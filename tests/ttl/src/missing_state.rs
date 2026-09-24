//! Behaviour when registry or configuration state is absent.
//!
//! Archival is not the only way state can be missing: a contract can be called
//! before it is initialized, or asked about a record that was never written.
//! Those paths must fail with a deterministic error rather than fall back to a
//! permissive default, so that a backend can tell "not proven" apart from
//! "proven false".

use super::fixture::{bytes, deployment, FAR_FUTURE, SCHEMA_VERSION};
use earnproof_shared::{ContractError, IssuerError, ProofError};
use proof_registry::{ProofRegistryContract, ProofRegistryContractClient};
use protocol_config::{ProtocolConfigContract, ProtocolConfigContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

#[test]
fn an_uninitialized_proof_registry_reports_not_initialized() {
    let env = Env::default();
    let contract_id = env.register(ProofRegistryContract, ());
    let client = ProofRegistryContractClient::new(&env, &contract_id);

    assert_eq!(
        client.try_get_admin(),
        Err(Ok(ContractError::NotInitialized))
    );
    assert_eq!(
        client.try_get_issuer_registry(),
        Err(Ok(ContractError::NotInitialized))
    );
    assert_eq!(
        client.try_get_protocol_config(),
        Err(Ok(ContractError::NotInitialized))
    );
}

#[test]
fn registration_against_an_uninitialized_registry_fails_closed() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(ProofRegistryContract, ());
    let client = ProofRegistryContractClient::new(&env, &contract_id);
    let issuer = Address::generate(&env);

    // Without instance state there is no protocol config to consult, so the
    // call must not proceed to a write.
    let result = client.try_register_proof(
        &bytes(&env, 1),
        &bytes(&env, 2),
        &issuer,
        &SCHEMA_VERSION,
        &FAR_FUTURE,
    );

    assert_eq!(result, Err(Ok(ProofError::ProofNotFound)));
    assert!(!client.is_valid_proof(&bytes(&env, 1)));
}

#[test]
fn verification_of_an_unknown_proof_is_false_not_an_error() {
    let deployment = deployment();
    let unknown = bytes(&deployment.env, 42);

    assert!(!deployment.proofs.is_valid_proof(&unknown));
    assert!(!deployment.proofs.is_revoked(&unknown));
    assert_eq!(
        deployment.proofs.try_get_proof(&unknown),
        Err(Ok(ProofError::ProofNotFound))
    );
}

#[test]
fn revocation_of_an_unknown_proof_reports_proof_not_found() {
    let deployment = deployment();
    let unknown = bytes(&deployment.env, 42);

    assert_eq!(
        deployment.proofs.try_revoke_proof(&unknown),
        Err(Ok(ProofError::ProofNotFound))
    );
    assert_eq!(
        deployment.proofs.try_admin_revoke_proof(&unknown),
        Err(Ok(ProofError::ProofNotFound))
    );
}

#[test]
fn an_unapproved_schema_version_reads_as_unapproved_rather_than_failing() {
    let deployment = deployment();

    // A schema flag that was never written has no storage entry at all. The
    // read must report "not approved" and must not create one.
    assert!(!deployment.config.is_schema_version_approved(&7));
    assert!(!deployment.config.is_schema_version_approved(&0));

    let result = deployment.proofs.try_register_proof(
        &bytes(&deployment.env, 1),
        &bytes(&deployment.env, 2),
        &deployment.issuer,
        &7,
        &FAR_FUTURE,
    );
    assert_eq!(result, Err(Ok(ProofError::UnsupportedSchema)));
}

#[test]
fn an_unknown_issuer_address_is_inactive_rather_than_an_error() {
    let deployment = deployment();
    let stranger = Address::generate(&deployment.env);

    assert!(!deployment.issuers.is_active_address(&stranger));
    assert_eq!(
        deployment.issuers.try_get_issuer_by_address(&stranger),
        Err(Ok(IssuerError::IssuerAddressNotFound))
    );
    assert!(!deployment
        .issuers
        .is_active_issuer(&bytes(&deployment.env, 99)));
}

#[test]
fn an_uninitialized_protocol_config_reads_as_unpaused_and_unapproved() {
    let env = Env::default();
    let contract_id = env.register(ProtocolConfigContract, ());
    let client = ProtocolConfigContractClient::new(&env, &contract_id);

    // These defaults are deliberate and documented: `is_paused` is a safety
    // switch that defaults to "not engaged", while every schema version is
    // unapproved until an admin approves it. An uninitialized config therefore
    // blocks every registration through the schema check, not through the
    // pause check.
    assert!(!client.is_paused());
    assert!(!client.is_schema_version_approved(&SCHEMA_VERSION));
    assert_eq!(client.get_config_version(), 0);
    assert_eq!(
        client.try_get_admin(),
        Err(Ok(ContractError::NotInitialized))
    );
}

#[test]
fn a_registration_pointed_at_an_empty_protocol_config_is_rejected() {
    let deployment = deployment();
    let env = &deployment.env;

    // A second, never-initialized protocol config stands in for a
    // misconfigured or wiped deployment.
    let empty_config = env.register(ProtocolConfigContract, ());
    let proofs_id = env.register(ProofRegistryContract, ());
    let proofs = ProofRegistryContractClient::new(env, &proofs_id);
    proofs.initialize(&deployment.admin, &deployment.issuers_id, &empty_config);

    let result = proofs.try_register_proof(
        &bytes(env, 1),
        &bytes(env, 2),
        &deployment.issuer,
        &SCHEMA_VERSION,
        &FAR_FUTURE,
    );

    assert_eq!(result, Err(Ok(ProofError::UnsupportedSchema)));
    assert!(!proofs.is_valid_proof(&bytes(env, 1)));
}
