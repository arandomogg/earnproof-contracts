//! Invalid, stale, and version-incompatible dependency references.
//!
//! `proof-registry` fixes both dependency addresses at `initialize` and exposes
//! no way to change them. `initialize` does not check that anything is deployed
//! at either address, or that what *is* deployed answers the calls
//! `register_proof` will make. Every one of those mistakes therefore surfaces
//! for the first time inside a registration, which is the worst moment for it
//! to be ambiguous.
//!
//! The invariant this module protects is that all of them fail **closed**: a
//! reference that cannot be resolved, cannot be understood, or no longer
//! describes the caller must reject the registration, never wave it through.

use earnproof_shared::ProofError;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::Address;

use issuer_registry::IssuerRegistryContract;
use protocol_config::{ProtocolConfigContract, ProtocolConfigContractClient};

use crate::harness::{commitment, hash, Deployment, Rejection, APPROVED_SCHEMA};
use crate::mocks::{ConfigWithoutSchemaRead, IssuersWithChangedSignature};

// ---------------------------------------------------------------------------
// Unknown contract ids
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_protocol_config_id_fails_closed() {
    let unknown = Deployment::with_dependency_addresses(|env, _config, issuers| {
        (Address::generate(env), issuers)
    });

    // `initialize` accepted an address with nothing deployed at it, and stored
    // it unchanged. Nothing detects the mistake until the first registration.
    let reference = unknown.proofs.get_protocol_config();
    assert_ne!(reference, unknown.config.address);

    let rejection = unknown.assert_rejected_and_atomic(&hash(&unknown.env, 0xA1));

    assert_eq!(
        rejection,
        Rejection::Aborted,
        "a reference that resolves to no contract must reject the registration"
    );
}

#[test]
fn an_unknown_issuer_registry_id_fails_closed() {
    let unknown = Deployment::with_dependency_addresses(|env, config, _issuers| {
        (config, Address::generate(env))
    });

    // Both `protocol-config` reads succeed before this reference is touched, so
    // the failure happens with the invocation already part-way through.
    let rejection = unknown.assert_rejected_and_atomic(&hash(&unknown.env, 0xA2));

    assert_eq!(rejection, Rejection::Aborted);
}

// ---------------------------------------------------------------------------
// Version-incompatible references
//
// `docs/compatibility.md` classifies removing an entry point and changing a
// parameter type as **Breaking** ABI changes, and notes that a caller built
// against the old signature "does not fail to compile — it fails at invocation,
// in production". These two tests are that failure, pinned to fail closed.
// ---------------------------------------------------------------------------

#[test]
fn a_protocol_config_missing_the_schema_entry_point_fails_closed() {
    let deployment = Deployment::with_dependency_addresses(|env, _config, issuers| {
        (env.register(ConfigWithoutSchemaRead, ()), issuers)
    });

    let rejection = deployment.assert_rejected_and_atomic(&hash(&deployment.env, 0xA3));

    assert_eq!(
        rejection,
        Rejection::Aborted,
        "a dependency missing an entry point the caller needs must fail closed, \
         not be treated as an approval"
    );
}

#[test]
fn an_issuer_registry_with_a_changed_signature_fails_closed() {
    // The entry point still exists and still returns `true`; only its parameter
    // type moved. Failing closed here is what stops a version skew from turning
    // into an unconditional "issuer is active".
    let deployment = Deployment::with_dependency_addresses(|env, config, _issuers| {
        (config, env.register(IssuersWithChangedSignature, ()))
    });

    let rejection = deployment.assert_rejected_and_atomic(&hash(&deployment.env, 0xA4));

    assert_eq!(rejection, Rejection::Aborted);
}

// ---------------------------------------------------------------------------
// Uninitialized references
// ---------------------------------------------------------------------------

#[test]
fn an_uninitialized_protocol_config_fails_closed() {
    // The contract is deployed but was never initialised, so it holds no state.
    //
    // Worth being precise about *why* this fails. `is_paused` reads
    // `DataKey::Paused` with `unwrap_or(false)`, so an uninitialised config
    // reports "not paused" — boundary 1 fails open. It is boundary 2 that
    // closes the door: no schema version has been approved, so
    // `is_schema_version_approved` returns false and the registration is
    // rejected. The overall behaviour is fail-closed, but it rests on the
    // second read, not the first.
    let deployment = Deployment::with_dependency_addresses(|env, _config, issuers| {
        (env.register(ProtocolConfigContract, ()), issuers)
    });
    let bare = ProtocolConfigContractClient::new(
        &deployment.env,
        &deployment.proofs.get_protocol_config(),
    );
    assert!(
        !bare.is_paused(),
        "an uninitialised config reports unpaused"
    );

    let rejection = deployment.assert_rejected_and_atomic(&hash(&deployment.env, 0xA5));

    assert_eq!(rejection, Rejection::Typed(ProofError::UnsupportedSchema));
}

#[test]
fn an_uninitialized_issuer_registry_fails_closed() {
    // No issuer is registered, so the reverse-index lookup at boundary 3 finds
    // nothing and `is_active_address` returns false.
    let deployment = Deployment::with_dependency_addresses(|env, config, _issuers| {
        (config, env.register(IssuerRegistryContract, ()))
    });

    let rejection = deployment.assert_rejected_and_atomic(&hash(&deployment.env, 0xA6));

    assert_eq!(rejection, Rejection::Typed(ProofError::IssuerInactive));
}

// ---------------------------------------------------------------------------
// Stale references
// ---------------------------------------------------------------------------

#[test]
fn a_stale_issuer_address_fails_closed_after_rotation() {
    // A caller retrying a transaction built before the issuer rotated its
    // address. `rotate_issuer_address` removes the old `AddressIssuer` entry, so
    // boundary 3 no longer resolves the stale address to an issuer and the
    // registration is rejected. A rotation a stale caller could ignore would
    // defeat the point of rotating.
    let deployment = Deployment::new();
    let stale_address = deployment.issuer.clone();
    let rotated_to = Address::generate(&deployment.env);
    deployment
        .issuers
        .rotate_issuer_address(&deployment.issuer_id, &rotated_to);

    let rejection = deployment.assert_rejected_and_atomic_with(
        &hash(&deployment.env, 0xA7),
        &stale_address,
        APPROVED_SCHEMA,
        deployment.expiry(),
    );

    assert_eq!(rejection, Rejection::Typed(ProofError::IssuerInactive));

    // Attributability: the rotation moved the authority rather than breaking
    // registration outright.
    deployment.proofs.register_proof(
        &hash(&deployment.env, 0xA8),
        &commitment(&deployment.env, 0xA8),
        &rotated_to,
        &APPROVED_SCHEMA,
        &deployment.expiry(),
    );
}

#[test]
fn the_referenced_protocol_config_gates_registration_not_a_newer_deployment() {
    // Redeploying `protocol-config` does not re-point an existing
    // `proof-registry`: the reference is fixed at `initialize`. Pausing the
    // referenced contract must contain registration even while a newer, fully
    // configured, unpaused one exists on the same ledger.
    let deployment = Deployment::new();

    let newer_id = deployment.env.register(ProtocolConfigContract, ());
    let newer = ProtocolConfigContractClient::new(&deployment.env, &newer_id);
    newer.initialize(&deployment.admin);
    newer.approve_schema_version(&APPROVED_SCHEMA);

    deployment.config.pause();
    assert!(!newer.is_paused());

    let rejection = deployment.assert_rejected_and_atomic(&hash(&deployment.env, 0xA9));

    assert_eq!(rejection, Rejection::Typed(ProofError::ContractPaused));
    assert_eq!(
        deployment.proofs.get_protocol_config(),
        deployment.config.address,
        "the reference must still name the contract the registry was initialised with"
    );
}
