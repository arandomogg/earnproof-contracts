//! The codes the contracts actually return.
//!
//! A catalog that describes intended behaviour is worse than no catalog: a
//! backend written against it fails in production in ways nobody predicted.
//! Every entry marked `Returned` is driven here through a real failure path,
//! and the code that comes back is compared against the catalog. Every entry
//! marked `Reserved` is asserted to be absent from all of those paths.

use earnproof_shared::error_catalog::Status;
use earnproof_shared::{ContractError, InterfaceVersion, IssuerError, ProofError, ERROR_CATALOG};
use issuer_registry::{IssuerRegistryContract, IssuerRegistryContractClient};
use proof_registry::{ProofRegistryContract, ProofRegistryContractClient};
use protocol_config::{ProtocolConfigContract, ProtocolConfigContractClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};

const FAR_FUTURE: u64 = 10_000_000;

/// A stand-in issuer registry that reports an interface version the proof
/// registry cannot bind to. Used to drive the incompatible-dependency path.
#[contract]
pub struct BadVersionRegistry;

#[contractimpl]
impl BadVersionRegistry {
    pub fn is_active_address(_env: Env, _issuer_address: Address) -> bool {
        true
    }

    pub fn interface_version(_env: Env) -> InterfaceVersion {
        // A different major is a breaking-change boundary the consumer rejects.
        InterfaceVersion::new(99, 0, 0)
    }
}

fn bytes32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

struct Deployment {
    env: Env,
    config: ProtocolConfigContractClient<'static>,
    issuers: IssuerRegistryContractClient<'static>,
    proofs: ProofRegistryContractClient<'static>,
    issuers_id: Address,
    config_id: Address,
    admin: Address,
    issuer: Address,
}

fn deployment() -> Deployment {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);

    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);

    let config_id = env.register(ProtocolConfigContract, ());
    let config = ProtocolConfigContractClient::new(&env, &config_id);
    config.initialize(&admin);
    config.approve_schema_version(&1);

    let issuers_id = env.register(IssuerRegistryContract, ());
    let issuers = IssuerRegistryContractClient::new(&env, &issuers_id);
    issuers.initialize(&admin);
    issuers.register_issuer(&bytes32(&env, 1), &issuer, &bytes32(&env, 2));

    let proofs_id = env.register(ProofRegistryContract, ());
    let proofs = ProofRegistryContractClient::new(&env, &proofs_id);
    proofs.initialize(&admin, &issuers_id, &config_id);

    Deployment {
        env,
        config,
        issuers,
        proofs,
        issuers_id,
        config_id,
        admin,
        issuer,
    }
}

/// Records the code observed on one failure path, so that the full set can be
/// compared against the catalog at the end.
struct Observations {
    codes: std::vec::Vec<u32>,
}

impl Observations {
    fn new() -> Self {
        Self {
            codes: std::vec::Vec::new(),
        }
    }

    fn record(&mut self, path: &str, code: u32) {
        let entry = ERROR_CATALOG
            .into_iter()
            .find(|entry| entry.code == code)
            .unwrap_or_else(|| std::panic!("{path} returned uncatalogued code {code}"));
        assert_eq!(
            entry.status,
            Status::Returned,
            "{path} returned {}, which the catalog marks reserved",
            entry.name
        );
        self.codes.push(code);
    }
}

#[test]
fn every_returned_code_is_produced_by_a_real_failure_path() {
    let mut observed = Observations::new();

    // --- protocol-config -------------------------------------------------
    let deployment = deployment();
    let env = &deployment.env;

    let fresh_config = env.register(ProtocolConfigContract, ());
    let fresh_config = ProtocolConfigContractClient::new(env, &fresh_config);
    observed.record(
        "protocol-config get_admin uninitialized",
        code(fresh_config.try_get_admin()),
    );
    observed.record(
        "protocol-config pause uninitialized",
        code(fresh_config.try_pause()),
    );
    observed.record(
        "protocol-config initialize twice",
        code(deployment.config.try_initialize(&deployment.admin)),
    );
    observed.record(
        "protocol-config approve_schema_version(0)",
        code(deployment.config.try_approve_schema_version(&0)),
    );
    observed.record(
        "protocol-config deprecate_schema_version(0)",
        code(deployment.config.try_deprecate_schema_version(&0)),
    );

    // --- issuer-registry -------------------------------------------------
    observed.record(
        "issuer-registry initialize twice",
        code(deployment.issuers.try_initialize(&deployment.admin)),
    );
    observed.record(
        "issuer-registry duplicate issuer id",
        code(deployment.issuers.try_register_issuer(
            &bytes32(env, 1),
            &Address::generate(env),
            &bytes32(env, 3),
        )),
    );
    observed.record(
        "issuer-registry duplicate issuer address",
        code(deployment.issuers.try_register_issuer(
            &bytes32(env, 9),
            &deployment.issuer,
            &bytes32(env, 3),
        )),
    );
    observed.record(
        "issuer-registry update unknown issuer",
        code(
            deployment
                .issuers
                .try_update_issuer(&bytes32(env, 99), &bytes32(env, 3)),
        ),
    );
    observed.record(
        "issuer-registry get unknown issuer",
        code(deployment.issuers.try_get_issuer(&bytes32(env, 99))),
    );
    observed.record(
        "issuer-registry lookup unknown address",
        code(
            deployment
                .issuers
                .try_get_issuer_by_address(&Address::generate(env)),
        ),
    );

    let revoked_issuer = Address::generate(env);
    deployment
        .issuers
        .register_issuer(&bytes32(env, 20), &revoked_issuer, &bytes32(env, 21));
    deployment.issuers.revoke_issuer(&bytes32(env, 20));
    observed.record(
        "issuer-registry update revoked issuer",
        code(
            deployment
                .issuers
                .try_update_issuer(&bytes32(env, 20), &bytes32(env, 22)),
        ),
    );
    observed.record(
        "issuer-registry reactivate revoked issuer",
        code(deployment.issuers.try_reactivate_issuer(&bytes32(env, 20))),
    );

    // --- proof-registry --------------------------------------------------
    let fresh_proofs = env.register(ProofRegistryContract, ());
    let fresh_proofs = ProofRegistryContractClient::new(env, &fresh_proofs);
    observed.record(
        "proof-registry get_admin uninitialized",
        code(fresh_proofs.try_get_admin()),
    );
    observed.record(
        "proof-registry initialize twice",
        code(deployment.proofs.try_initialize(
            &deployment.admin,
            &deployment.issuers_id,
            &deployment.config_id,
        )),
    );

    let proof_id = bytes32(env, 5);
    deployment.proofs.register_proof(
        &proof_id,
        &bytes32(env, 6),
        &deployment.issuer,
        &1,
        &FAR_FUTURE,
    );
    observed.record(
        "proof-registry duplicate proof id",
        code(deployment.proofs.try_register_proof(
            &proof_id,
            &bytes32(env, 7),
            &deployment.issuer,
            &1,
            &FAR_FUTURE,
        )),
    );
    observed.record(
        "proof-registry get unknown proof",
        code(deployment.proofs.try_get_proof(&bytes32(env, 99))),
    );
    deployment.proofs.revoke_proof(&proof_id);
    observed.record(
        "proof-registry revoke twice",
        code(deployment.proofs.try_revoke_proof(&proof_id)),
    );
    observed.record(
        "proof-registry expiration in the past",
        code(deployment.proofs.try_register_proof(
            &bytes32(env, 30),
            &bytes32(env, 31),
            &deployment.issuer,
            &1,
            &0,
        )),
    );
    observed.record(
        "proof-registry schema version zero",
        code(deployment.proofs.try_register_proof(
            &bytes32(env, 32),
            &bytes32(env, 33),
            &deployment.issuer,
            &0,
            &FAR_FUTURE,
        )),
    );
    observed.record(
        "proof-registry unapproved schema version",
        code(deployment.proofs.try_register_proof(
            &bytes32(env, 34),
            &bytes32(env, 35),
            &deployment.issuer,
            &7,
            &FAR_FUTURE,
        )),
    );

    // --- issuer-registry capacity and cooldown --------------------------
    // A dedicated registry keeps the active-count accounting isolated from the
    // paths above.
    let cap_id = env.register(IssuerRegistryContract, ());
    let cap = IssuerRegistryContractClient::new(env, &cap_id);
    cap.initialize(&deployment.admin);
    let cap_issuer = Address::generate(env);
    cap.register_issuer(&bytes32(env, 50), &cap_issuer, &bytes32(env, 51));

    observed.record(
        "issuer-registry set_max below active usage",
        code(cap.try_set_max_active_issuers(&0, &false)),
    );

    cap.set_max_active_issuers(&1, &false);
    observed.record(
        "issuer-registry register beyond capacity",
        code(cap.try_register_issuer(
            &bytes32(env, 52),
            &Address::generate(env),
            &bytes32(env, 53),
        )),
    );

    cap.set_reactivation_cooldown(&1_000);
    cap.suspend_issuer(&bytes32(env, 50));
    observed.record(
        "issuer-registry reactivate before cooldown",
        code(cap.try_reactivate_issuer(&bytes32(env, 50))),
    );

    // --- proof-registry incompatible dependency -------------------------
    let bad_registry = env.register(BadVersionRegistry, ());
    observed.record(
        "proof-registry bind incompatible issuer registry",
        code(deployment.proofs.try_set_issuer_registry(&bad_registry)),
    );

    // Every catalogued `Returned` code must appear at least once above.
    for entry in ERROR_CATALOG {
        if entry.status == Status::Returned {
            assert!(
                observed.codes.contains(&entry.code),
                "{} ({}) is catalogued as returned but no failure path here produces it",
                entry.name,
                entry.code
            );
        } else {
            assert!(
                !observed.codes.contains(&entry.code),
                "{} ({}) is catalogued as reserved but a failure path produced it",
                entry.name,
                entry.code
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Individually named paths for the codes a backend is most likely to branch on
// ---------------------------------------------------------------------------

#[test]
fn a_paused_protocol_is_reported_as_invalid_schema_version() {
    // The overloaded code documented in the catalog. Asserting it means the
    // documentation stays honest, and means a future release that introduces a
    // distinct pause code has to update the catalog in the same change.
    let deployment = deployment();
    deployment.config.pause();

    let result = deployment.proofs.try_register_proof(
        &bytes32(&deployment.env, 1),
        &bytes32(&deployment.env, 2),
        &deployment.issuer,
        &1,
        &FAR_FUTURE,
    );

    assert_eq!(result, Err(Ok(ProofError::InvalidSchemaVersion)));
    assert_ne!(
        ProofError::InvalidSchemaVersion as u32,
        ContractError::ProtocolPaused as u32
    );
}

#[test]
fn a_suspended_issuer_is_reported_as_invalid_schema_version() {
    let deployment = deployment();
    let env = &deployment.env;
    let suspended = Address::generate(env);
    deployment
        .issuers
        .register_issuer(&bytes32(env, 40), &suspended, &bytes32(env, 41));
    deployment.issuers.suspend_issuer(&bytes32(env, 40));

    let result = deployment.proofs.try_register_proof(
        &bytes32(env, 42),
        &bytes32(env, 43),
        &suspended,
        &1,
        &FAR_FUTURE,
    );

    assert_eq!(result, Err(Ok(ProofError::InvalidSchemaVersion)));
    assert_ne!(
        ProofError::InvalidSchemaVersion as u32,
        IssuerError::IssuerInactive as u32
    );
}

#[test]
fn an_uninitialized_proof_registry_reports_proof_not_found_and_writes_nothing() {
    let env = Env::default();
    env.mock_all_auths();
    let contract = env.register(ProofRegistryContract, ());
    let proofs = ProofRegistryContractClient::new(&env, &contract);
    let issuer = Address::generate(&env);

    let result = proofs.try_register_proof(
        &bytes32(&env, 1),
        &bytes32(&env, 2),
        &issuer,
        &1,
        &FAR_FUTURE,
    );

    assert_eq!(result, Err(Ok(ProofError::ProofNotFound)));
    assert!(!proofs.is_valid_proof(&bytes32(&env, 1)));
}

#[test]
fn a_registry_pointed_at_an_empty_config_reports_schema_version_not_approved() {
    let deployment = deployment();
    let env = &deployment.env;
    let empty_config = env.register(ProtocolConfigContract, ());
    let proofs_id = env.register(ProofRegistryContract, ());
    let proofs = ProofRegistryContractClient::new(env, &proofs_id);
    proofs.initialize(&deployment.admin, &deployment.issuers_id, &empty_config);

    let result = proofs.try_register_proof(
        &bytes32(env, 1),
        &bytes32(env, 2),
        &deployment.issuer,
        &1,
        &FAR_FUTURE,
    );

    assert_eq!(result, Err(Ok(ProofError::SchemaVersionNotApproved)));
}

#[test]
fn a_returned_error_carries_a_code_and_nothing_else() {
    // Soroban contract errors are a type and a number. There is no message, no
    // payload, and therefore nothing for a failing call to disclose about the
    // record it touched. This is the structural reason the catalog can promise
    // that authorization and lookup failures reveal no protected state.
    let deployment = deployment();
    let unknown = bytes32(&deployment.env, 99);

    let error = deployment
        .proofs
        .try_get_proof(&unknown)
        .expect_err("unknown proof must fail")
        .expect("must be a contract error rather than a host error");

    assert_eq!(error, ProofError::ProofNotFound);
    assert_eq!(error as u32, 301);
}

/// Extracts the contract error code from a `try_` result, failing the test if
/// the call succeeded or aborted with a host error.
fn code<T, E>(result: Result<T, Result<E, soroban_sdk::InvokeError>>) -> u32
where
    E: Into<soroban_sdk::Error> + Clone,
    T: core::fmt::Debug,
{
    match result {
        Ok(value) => std::panic!("expected a failure, got {value:?}"),
        Err(Ok(error)) => {
            let error: soroban_sdk::Error = error.into();
            error.get_code()
        }
        Err(Err(invoke)) => std::panic!("expected a contract error, got {invoke:?}"),
    }
}
