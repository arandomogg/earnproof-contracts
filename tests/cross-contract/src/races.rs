//! What "a dependency update racing with a registration" means on this ledger.
//!
//! # The concurrency model
//!
//! Soroban applies the transactions in a ledger **sequentially**. There is no
//! concurrency within a ledger, and no interleaving within an invocation. Three
//! consequences settle every race question this issue raises, and none of them
//! involve timing:
//!
//! 1. A cross-contract read observes the state left by every transaction
//!    applied before the current one, and nothing that lands after. A
//!    registration cannot observe half of an update.
//! 2. `register_proof` reads each dependency exactly once and never re-reads.
//!    The values observed at boundaries 1-3 are the values that decide the
//!    write, and nothing can change between them.
//! 3. A failed invocation is rolled back in full, including any state a
//!    dependency changed while it ran.
//!
//! So a "race" is only ever an **ordering**: the last update applied before the
//! registration is the one it sees, and an update applied after it cannot reach
//! back. The tests below are written as orderings for that reason. There are no
//! sleeps here because there is nothing for a sleep to wait on.
//!
//! The one situation the ledger cannot produce — a dependency changing *during*
//! the invocation — is constructed artificially with
//! [`crate::mocks::SelfPausingConfig`], so that the third consequence above is
//! asserted rather than assumed.

use earnproof_shared::ProofError;

use crate::harness::{commitment, hash, outcome_of, Deployment, Rejection, APPROVED_SCHEMA};
use crate::mocks::{SelfPausingConfig, SelfPausingConfigClient};

/// An update an operator can apply to a dependency around a registration.
#[derive(Clone, Copy, Debug)]
enum Update {
    Pause,
    Unpause,
    DeprecateSchema,
    ApproveSchema,
    SuspendIssuer,
    ReactivateIssuer,
    RevokeIssuer,
}

const UPDATES: [Update; 7] = [
    Update::Pause,
    Update::Unpause,
    Update::DeprecateSchema,
    Update::ApproveSchema,
    Update::SuspendIssuer,
    Update::ReactivateIssuer,
    Update::RevokeIssuer,
];

fn apply(deployment: &Deployment, update: Update) {
    match update {
        Update::Pause => deployment.config.pause(),
        Update::Unpause => deployment.config.unpause(),
        Update::DeprecateSchema => deployment.config.deprecate_schema_version(&APPROVED_SCHEMA),
        Update::ApproveSchema => deployment.config.approve_schema_version(&APPROVED_SCHEMA),
        Update::SuspendIssuer => deployment.issuers.suspend_issuer(&deployment.issuer_id),
        Update::ReactivateIssuer => deployment.issuers.reactivate_issuer(&deployment.issuer_id),
        Update::RevokeIssuer => deployment.issuers.revoke_issuer(&deployment.issuer_id),
    }
}

/// Whether a registration is accepted once `update` is the most recent one
/// applied. Written from the documented registration rules rather than read off
/// the contract, so that the two can disagree.
fn permits_registration(update: Update) -> bool {
    match update {
        Update::Unpause | Update::ApproveSchema | Update::ReactivateIssuer => true,
        Update::Pause | Update::DeprecateSchema | Update::SuspendIssuer | Update::RevokeIssuer => {
            false
        }
    }
}

/// Attempts a registration and reports whether it was accepted.
fn attempt(deployment: &Deployment, discriminator: u8) -> bool {
    let rejection = outcome_of(|| {
        deployment.proofs.try_register_proof(
            &hash(&deployment.env, discriminator),
            &commitment(&deployment.env, discriminator),
            &deployment.issuer,
            &APPROVED_SCHEMA,
            &deployment.expiry(),
        )
    });
    rejection == Rejection::Accepted
}

// ---------------------------------------------------------------------------
// Ordering decides the outcome
// ---------------------------------------------------------------------------

#[test]
fn an_update_applied_before_registration_is_observed_by_it() {
    // Consequence 1: nothing applied before the registration can be missed by
    // it, whichever dependency the update touched.
    for update in UPDATES {
        let deployment = Deployment::new();
        apply(&deployment, update);

        assert_eq!(
            attempt(&deployment, 0xB1),
            permits_registration(update),
            "{update:?} applied before the registration was not observed by it"
        );
    }
}

#[test]
fn an_update_applied_after_registration_does_not_alter_the_stored_record() {
    // The mirror: a proof already committed is not retroactively rewritten by a
    // later pause, deprecation, or issuer transition. Revocation is the only
    // operation that changes a stored proof, and none of these is revocation.
    for update in UPDATES {
        let deployment = Deployment::new();
        let proof_id = deployment.register(0xB2);
        let before = deployment.footprint(&proof_id);

        apply(&deployment, update);

        let after = deployment.footprint(&proof_id);
        assert_eq!(
            before.proof, after.proof,
            "{update:?} applied after the registration rewrote the committed record"
        );
        assert_eq!(
            before.proof_ttl, after.proof_ttl,
            "{update:?} applied after the registration moved the committed record's TTL"
        );
    }
}

#[test]
fn the_last_update_applied_before_registration_is_the_one_that_decides() {
    // Two operators issuing conflicting updates during a handover. Whichever
    // transaction lands last is the one the registration observes, and the
    // earlier one leaves no residue that could tip the outcome.
    let conflicts = [
        (Update::Pause, Update::Unpause),
        (Update::DeprecateSchema, Update::ApproveSchema),
        (Update::SuspendIssuer, Update::ReactivateIssuer),
    ];

    for (one, other) in conflicts {
        for (first, last) in [(one, other), (other, one)] {
            let deployment = Deployment::new();
            apply(&deployment, first);
            apply(&deployment, last);

            assert_eq!(
                attempt(&deployment, 0xB3),
                permits_registration(last),
                "{first:?} then {last:?}: the earlier update decided the outcome"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// A change made *during* the invocation
// ---------------------------------------------------------------------------

#[test]
fn a_dependency_change_during_the_invocation_cannot_undo_the_committed_write() {
    // The ledger cannot produce this situation; the substitute dependency can.
    // Its first read reports "not paused" and pauses in the same call.
    //
    // The registration therefore decides from a value that is already stale by
    // the time the invocation ends. That is correct and is what consequence 2
    // states: the observed value is the deciding value, and a change visible
    // afterwards does not reach back into a committed record.
    let deployment = Deployment::with_dependency_addresses(|env, _config, issuers| {
        (env.register(SelfPausingConfig, ()), issuers)
    });
    let racing =
        SelfPausingConfigClient::new(&deployment.env, &deployment.proofs.get_protocol_config());

    let proof_id = deployment.register(0xB4);

    assert!(
        racing.pause_flag(),
        "the substitute dependency was supposed to change state during the read"
    );
    assert_eq!(
        deployment.proofs.get_proof(&proof_id).proof_id_hash,
        proof_id,
        "a committed registration must survive a dependency change that became \
         visible after it was decided"
    );

    // And the next registration observes the new state, with no carry-over from
    // the value the previous invocation read.
    let rejection = deployment.assert_rejected_and_atomic(&hash(&deployment.env, 0xB5));
    assert_eq!(rejection, Rejection::Typed(ProofError::ContractPaused));
}

#[test]
fn a_dependency_change_during_a_failing_invocation_is_discarded() {
    // Consequence 3. The substitute flips its flag at boundary 1; the
    // registration then fails at boundary 3. The flag must come back.
    //
    // Without this, a rejected registration could still shift the state that
    // decides every subsequent one — a failed call quietly changing the rules
    // for the next caller.
    let deployment = Deployment::with_dependency_addresses(|env, _config, issuers| {
        (env.register(SelfPausingConfig, ()), issuers)
    });
    let racing =
        SelfPausingConfigClient::new(&deployment.env, &deployment.proofs.get_protocol_config());
    deployment.issuers.suspend_issuer(&deployment.issuer_id);

    let rejection = deployment.assert_rejected_and_atomic(&hash(&deployment.env, 0xB6));

    assert_eq!(rejection, Rejection::Typed(ProofError::IssuerInactive));
    assert!(
        !racing.pause_flag(),
        "a dependency change made during a rejected registration survived it"
    );

    // The discarded change left nothing behind: once the issuer is active
    // again, registration works exactly as it would have before the failure.
    deployment.issuers.reactivate_issuer(&deployment.issuer_id);
    deployment.register(0xB7);
}
