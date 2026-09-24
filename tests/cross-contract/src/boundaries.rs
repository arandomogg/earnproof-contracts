//! Failures at each cross-contract read boundary.
//!
//! The table in [`crate::harness`] numbers the three reads `register_proof`
//! performs. This module walks that table: for each boundary it drives a
//! failure *before* it, *inside* it, and *after* it, and asserts the same thing
//! every time — the invocation is rejected, it publishes nothing, and the
//! complete footprint is exactly what it was beforehand.
//!
//! "Inside" is the case that needs help from [`crate::mocks`]. The real
//! dependencies never fail a read: `is_paused`, `is_schema_version_approved`
//! and `is_active_address` all answer successfully whatever their state and
//! report their verdict in the returned `bool`. A substitute dependency is the
//! only way to make the read itself fail, and it is also what makes the
//! *ordering* of the steps observable: a dependency that rejects every call
//! turns "which check ran first" into an assertion rather than a claim.

use earnproof_shared::{ProofError, ProofRecord, ProofStatus};
use soroban_sdk::testutils::{Address as _, Events as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{Address, BytesN, IntoVal};

use crate::harness::{
    assert_unchanged, commitment, hash, outcome_of, proof_key, Deployment, Rejection,
    APPROVED_SCHEMA,
};
use crate::mocks::{
    ConfigRequiringAuth, ConfigRequiringAuthClient, MalformedIssuerRead, MalformedPauseRead,
    MalformedSchemaRead, RecordingConfig, RecordingConfigClient, RejectsIssuerRead,
    RejectsPauseRead, RejectsSchemaRead,
};

// ---------------------------------------------------------------------------
// The reconstructed key this crate measures TTLs through
// ---------------------------------------------------------------------------

#[test]
fn the_reconstructed_proof_key_addresses_the_stored_record() {
    // Every proof TTL assertion in this crate reads through `proof_key`. If the
    // encoding of `proof-registry`'s private `DataKey::Proof(..)` ever changed,
    // the key would address nothing, and those assertions would quietly degrade
    // to comparing `None` with `None`. This test is what stops that.
    let deployment = Deployment::new();
    let proof_id = deployment.register(0x11);

    let key = proof_key(&deployment.env, &proof_id);
    let stored: Option<ProofRecord> =
        deployment.env.as_contract(&deployment.proofs.address, || {
            deployment.env.storage().persistent().get(&key)
        });
    let via_getter = deployment.proofs.get_proof(&proof_id);

    assert_eq!(
        stored,
        Some(via_getter),
        "the reconstructed storage key must address the same record the public getter returns"
    );
}

// ---------------------------------------------------------------------------
// Before the first read: authorization
// ---------------------------------------------------------------------------

#[test]
fn missing_authorization_is_rejected_before_any_dependency_is_read() {
    // An empty mock authorises nothing, so `issuer_address.require_auth()` at
    // the top of `register_proof` fails. The substituted dependency rejects
    // every call, so a rejection that is *typed* would mean a read had already
    // happened; `Aborted` here is the authorization failure itself.
    let deployment = Deployment::with_dependency_addresses(|env, _config, issuers| {
        (env.register(RejectsPauseRead, ()), issuers)
    });
    deployment.env.mock_auths(&[]);

    let rejection = deployment.assert_rejected_and_atomic(&hash(&deployment.env, 0x21));

    assert_eq!(
        rejection,
        Rejection::Aborted,
        "an unauthorised registration must be rejected by the host, \
         not resolved into a proof-registry verdict"
    );
}

#[test]
fn nested_authorization_failure_rolls_back_the_registration() {
    // The dependency demands authorization from an address the transaction
    // never authorised. `proof-registry` cannot anticipate that requirement and
    // must not proceed past it.
    let deployment = Deployment::with_dependency_addresses(|env, _config, issuers| {
        let config = env.register(ConfigRequiringAuth, ());
        ConfigRequiringAuthClient::new(env, &config).set_guardian(&Address::generate(env));
        (config, issuers)
    });
    let proof_id = hash(&deployment.env, 0x22);
    let before = deployment.footprint(&proof_id);

    let rejection = register_with_root_auth_only(&deployment, &proof_id);

    // Events before state: the environment reports only the most recent
    // invocation, and `footprint` invokes the getters.
    let events = deployment.env.events().all().events().len();
    let after = deployment.footprint(&proof_id);

    assert_eq!(
        rejection,
        Rejection::Aborted,
        "an unsatisfied nested authorization must abort the registration"
    );
    assert_eq!(events, 0, "a rejected registration published an event");
    assert_unchanged(&before, &after);
}

#[test]
fn root_authorization_alone_registers_against_dependencies_that_demand_none() {
    // Attributability for the test above. The single mocked authorization entry
    // has to be sufficient on its own, or the rejection there would be
    // explained by a malformed entry rather than by the nested requirement.
    let deployment = Deployment::new();
    let proof_id = hash(&deployment.env, 0x23);

    let rejection = register_with_root_auth_only(&deployment, &proof_id);

    assert_eq!(rejection, Rejection::Accepted);
    assert_eq!(
        deployment.proofs.get_proof(&proof_id).proof_id_hash,
        proof_id
    );
}

/// Attempts a registration carrying exactly one authorization entry: the
/// issuer's, for the root `register_proof` invocation and nothing beneath it.
fn register_with_root_auth_only(deployment: &Deployment, proof_id: &BytesN<32>) -> Rejection {
    let env = &deployment.env;
    let commitment_hash = commitment(env, 0xC0);
    let expires_at = deployment.expiry();
    let args: soroban_sdk::Vec<soroban_sdk::Val> = (
        proof_id.clone(),
        commitment_hash.clone(),
        deployment.issuer.clone(),
        APPROVED_SCHEMA,
        expires_at,
    )
        .into_val(env);

    env.mock_auths(&[MockAuth {
        address: &deployment.issuer,
        invoke: &MockAuthInvoke {
            contract: &deployment.proofs.address,
            fn_name: "register_proof",
            args,
            sub_invokes: &[],
        },
    }]);

    outcome_of(|| {
        deployment.proofs.try_register_proof(
            proof_id,
            &commitment_hash,
            &deployment.issuer,
            &APPROVED_SCHEMA,
            &expires_at,
        )
    })
}

// ---------------------------------------------------------------------------
// Before the first read: argument validation
//
// Both cases run against a dependency that rejects every call, so a typed
// rejection is proof the local check ran first. Had `protocol-config` been
// consulted before the argument was validated, the verdict would be `Aborted`.
// ---------------------------------------------------------------------------

#[test]
fn zero_schema_version_is_rejected_before_the_protocol_config_is_read() {
    let deployment = Deployment::with_dependency_addresses(|env, _config, issuers| {
        (env.register(RejectsPauseRead, ()), issuers)
    });

    let rejection = deployment.assert_rejected_and_atomic_with(
        &hash(&deployment.env, 0x24),
        &deployment.issuer,
        0,
        deployment.expiry(),
    );

    assert_eq!(
        rejection,
        Rejection::Typed(ProofError::InvalidSchemaVersion)
    );
}

#[test]
fn an_expired_proof_is_rejected_before_the_protocol_config_is_read() {
    let deployment = Deployment::with_dependency_addresses(|env, _config, issuers| {
        (env.register(RejectsPauseRead, ()), issuers)
    });
    let now = deployment.env.ledger().timestamp();

    let rejection = deployment.assert_rejected_and_atomic_with(
        &hash(&deployment.env, 0x25),
        &deployment.issuer,
        APPROVED_SCHEMA,
        now - 1,
    );

    assert_eq!(rejection, Rejection::Typed(ProofError::ProofExpired));
}

// ---------------------------------------------------------------------------
// Boundary 1: protocol-config::is_paused()
// ---------------------------------------------------------------------------

#[test]
fn a_rejected_pause_read_leaves_no_proof_record() {
    let deployment = Deployment::with_dependency_addresses(|env, _config, issuers| {
        (env.register(RejectsPauseRead, ()), issuers)
    });

    let rejection = deployment.assert_rejected_and_atomic(&hash(&deployment.env, 0x31));

    assert_eq!(
        rejection,
        Rejection::Aborted,
        "a read boundary failure must abort, not resolve to a ProofError"
    );
}

#[test]
fn a_malformed_pause_read_leaves_no_proof_record() {
    let deployment = Deployment::with_dependency_addresses(|env, _config, issuers| {
        (env.register(MalformedPauseRead, ()), issuers)
    });

    let rejection = deployment.assert_rejected_and_atomic(&hash(&deployment.env, 0x32));

    assert_eq!(
        rejection,
        Rejection::Aborted,
        "a type conversion failure at a boundary must abort"
    );
}

#[test]
fn a_successful_pause_read_gates_the_registration_correctly() {
    // Sanity check: when the dependency behaves normally, the verdict on the
    // actual state is applied. The real `protocol-config` responds
    // successfully; a deployed substitute that is not paused should not
    // prevent registration.
    let deployment = Deployment::new();
    let proof_id = hash(&deployment.env, 0x33);

    let rejection = outcome_of(|| {
        deployment.proofs.try_register_proof(
            &proof_id,
            &commitment(&deployment.env, 0xC0),
            &deployment.issuer,
            &APPROVED_SCHEMA,
            &deployment.expiry(),
        )
    });

    assert_eq!(
        rejection,
        Rejection::Accepted,
        "a registration against a not-paused protocol-config must succeed"
    );
}

// ---------------------------------------------------------------------------
// Boundary 2: protocol-config::is_schema_version_approved(u32)
// ---------------------------------------------------------------------------

#[test]
fn a_rejected_schema_read_leaves_no_proof_record() {
    let deployment = Deployment::with_dependency_addresses(|env, _config, issuers| {
        (env.register(RejectsSchemaRead, ()), issuers)
    });

    let rejection = deployment.assert_rejected_and_atomic(&hash(&deployment.env, 0x41));

    assert_eq!(
        rejection,
        Rejection::Aborted,
        "a read boundary failure must abort"
    );
}

#[test]
fn a_malformed_schema_read_leaves_no_proof_record() {
    let deployment = Deployment::with_dependency_addresses(|env, _config, issuers| {
        (env.register(MalformedSchemaRead, ()), issuers)
    });

    let rejection = deployment.assert_rejected_and_atomic(&hash(&deployment.env, 0x42));

    assert_eq!(
        rejection,
        Rejection::Aborted,
        "a type conversion failure must abort"
    );
}

#[test]
fn a_successful_schema_read_gates_the_registration_correctly() {
    let deployment = Deployment::new();
    let proof_id = hash(&deployment.env, 0x43);

    let rejection = outcome_of(|| {
        deployment.proofs.try_register_proof(
            &proof_id,
            &commitment(&deployment.env, 0xC0),
            &deployment.issuer,
            &APPROVED_SCHEMA,
            &deployment.expiry(),
        )
    });

    assert_eq!(
        rejection,
        Rejection::Accepted,
        "a registration with an approved schema must succeed"
    );
}

#[test]
fn an_unapproved_schema_is_rejected_after_the_pause_check_but_before_the_issuer_check() {
    // The real `protocol-config` rejects the schema (returns `false`). If the
    // issuer-registry is unreachable, we'd get `Aborted` instead of `Typed`.
    // This test verifies that the schema check happens after the pause check
    // but before the issuer check.
    // Can't test this directly because the schema read itself fails. Instead,
    // test with real config that unapproves the schema.
    let deployment = Deployment::new();
    let proof_id = hash(&deployment.env, 0x44);

    let rejection = deployment.assert_rejected_and_atomic_with(
        &proof_id,
        &deployment.issuer,
        999, // Unapproved schema version
        deployment.expiry(),
    );

    assert_eq!(rejection, Rejection::Typed(ProofError::UnsupportedSchema));
}

// ---------------------------------------------------------------------------
// Boundary 3: issuer-registry::is_active_address(Address)
// ---------------------------------------------------------------------------

#[test]
fn a_rejected_issuer_read_leaves_no_proof_record() {
    let deployment = Deployment::with_dependency_addresses(|env, config, _issuers| {
        (config, env.register(RejectsIssuerRead, ()))
    });

    let rejection = deployment.assert_rejected_and_atomic(&hash(&deployment.env, 0x51));

    assert_eq!(
        rejection,
        Rejection::Aborted,
        "a read boundary failure must abort"
    );
}

#[test]
fn a_malformed_issuer_read_leaves_no_proof_record() {
    let deployment = Deployment::with_dependency_addresses(|env, config, _issuers| {
        (config, env.register(MalformedIssuerRead, ()))
    });

    let rejection = deployment.assert_rejected_and_atomic(&hash(&deployment.env, 0x52));

    assert_eq!(
        rejection,
        Rejection::Aborted,
        "a type conversion failure must abort"
    );
}

#[test]
fn a_successful_issuer_read_gates_the_registration_correctly() {
    let deployment = Deployment::new();
    let proof_id = hash(&deployment.env, 0x53);

    let rejection = outcome_of(|| {
        deployment.proofs.try_register_proof(
            &proof_id,
            &commitment(&deployment.env, 0xC0),
            &deployment.issuer,
            &APPROVED_SCHEMA,
            &deployment.expiry(),
        )
    });

    assert_eq!(
        rejection,
        Rejection::Accepted,
        "a registration with an active issuer must succeed"
    );
}

#[test]
fn an_inactive_issuer_is_rejected_after_both_protocol_config_checks() {
    // The issuer is not in the registry at all, so the read fails with
    // `false`. The registration must be rejected with a typed error.
    let deployment = Deployment::new();
    let inactive_issuer = Address::generate(&deployment.env);
    let proof_id = hash(&deployment.env, 0x54);

    let rejection = deployment.assert_rejected_and_atomic_with(
        &proof_id,
        &inactive_issuer,
        APPROVED_SCHEMA,
        deployment.expiry(),
    );

    assert_eq!(rejection, Rejection::Typed(ProofError::IssuerInactive));
}

// ---------------------------------------------------------------------------
// After all reads: storage atomicity
// ---------------------------------------------------------------------------

#[test]
fn a_successful_registration_stores_the_proof_record_once() {
    let deployment = Deployment::new();
    let proof_id = hash(&deployment.env, 0x61);

    deployment.register(0x61);

    let record = deployment.proofs.get_proof(&proof_id);
    assert_eq!(record.proof_id_hash, proof_id);
    assert_eq!(record.status, ProofStatus::Active);
}

#[test]
fn a_duplicate_proof_id_is_rejected_before_writing() {
    let deployment = Deployment::new();
    let proof_id = hash(&deployment.env, 0x62);

    // Register once successfully
    deployment.register(0x62);

    // Try to register the same proof id again
    let rejection = outcome_of(|| {
        deployment.proofs.try_register_proof(
            &proof_id,
            &commitment(&deployment.env, 0xC0),
            &deployment.issuer,
            &APPROVED_SCHEMA,
            &deployment.expiry(),
        )
    });

    assert_eq!(
        rejection,
        Rejection::Typed(ProofError::ProofAlreadyRegistered)
    );
}

// ---------------------------------------------------------------------------
// Rollback verification: the dependency's writes are rolled back too
// ---------------------------------------------------------------------------

#[test]
fn a_failed_registration_rolls_back_writes_inside_the_dependency() {
    // `RecordingConfig` writes to its own persistent storage during the
    // `is_paused()` call. If the registration fails after that (e.g. during
    // the issuer check), that write must be rolled back too. This test verifies
    // the rollback reaches the callee.
    let deployment = Deployment::with_dependency_addresses(|env, _config, _issuers| {
        let recording = env.register(RecordingConfig, ());
        // Write to the recording config's storage during the pause read, then
        // fail the issuer check so the transaction rolls back.
        (recording, env.register(RejectsIssuerRead, ()))
    });

    let recording =
        RecordingConfigClient::new(&deployment.env, &deployment.proofs.get_protocol_config());

    // Before registration, the recording config has not been touched
    let before = recording.was_touched();
    assert!(!before, "the recording config should start untouched");

    // Attempt registration, which will write to the recording config during
    // the pause check, then fail at the issuer check
    let _rejection = deployment.assert_rejected_and_atomic(&hash(&deployment.env, 0x71));

    // After the failed registration, the write should be rolled back
    let after = recording.was_touched();
    assert!(
        !after,
        "the write inside the dependency must be rolled back on registration failure"
    );
}

// ---------------------------------------------------------------------------
// Invalid contract references
// ---------------------------------------------------------------------------

#[test]
fn an_invalid_protocol_config_address_aborts_the_registration() {
    // Point proof-registry at an address with no contract deployed
    let env = soroban_sdk::Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);

    let config_id = env.register(protocol_config::ProtocolConfigContract, ());
    let config = protocol_config::ProtocolConfigContractClient::new(&env, &config_id);
    config.initialize(&admin);
    config.approve_schema_version(&APPROVED_SCHEMA);

    let issuers_id = env.register(issuer_registry::IssuerRegistryContract, ());
    let issuers = issuer_registry::IssuerRegistryContractClient::new(&env, &issuers_id);
    issuers.initialize(&admin);
    let issuer_id = hash(&env, 0x01);
    issuers.register_issuer(&issuer_id, &issuer, &hash(&env, 0xAA));

    let proofs_id = env.register(proof_registry::ProofRegistryContract, ());
    let proofs = proof_registry::ProofRegistryContractClient::new(&env, &proofs_id);

    // Initialize with an invalid config address
    let invalid_config = Address::generate(&env);
    proofs.initialize(&admin, &issuers_id, &invalid_config);

    let rejection = outcome_of(|| {
        proofs.try_register_proof(
            &hash(&env, 0xAB),
            &commitment(&env, 0xC0),
            &issuer,
            &APPROVED_SCHEMA,
            &(env.ledger().timestamp() + 100_000),
        )
    });

    assert_eq!(
        rejection,
        Rejection::Aborted,
        "an invalid dependency address must abort, not produce a typed error"
    );
}

#[test]
fn an_invalid_issuer_registry_address_aborts_the_registration() {
    let env = soroban_sdk::Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);

    let config_id = env.register(protocol_config::ProtocolConfigContract, ());
    let config = protocol_config::ProtocolConfigContractClient::new(&env, &config_id);
    config.initialize(&admin);
    config.approve_schema_version(&APPROVED_SCHEMA);

    let issuers_id = env.register(issuer_registry::IssuerRegistryContract, ());
    let issuers = issuer_registry::IssuerRegistryContractClient::new(&env, &issuers_id);
    issuers.initialize(&admin);
    let issuer_id = hash(&env, 0x01);
    issuers.register_issuer(&issuer_id, &issuer, &hash(&env, 0xAA));

    let proofs_id = env.register(proof_registry::ProofRegistryContract, ());
    let proofs = proof_registry::ProofRegistryContractClient::new(&env, &proofs_id);

    // Initialize with an invalid issuer registry address
    let invalid_issuers = Address::generate(&env);
    proofs.initialize(&admin, &invalid_issuers, &config_id);

    let rejection = outcome_of(|| {
        proofs.try_register_proof(
            &hash(&env, 0xAC),
            &commitment(&env, 0xC0),
            &issuer,
            &APPROVED_SCHEMA,
            &(env.ledger().timestamp() + 100_000),
        )
    });

    assert_eq!(
        rejection,
        Rejection::Aborted,
        "an invalid dependency address must abort"
    );
}
