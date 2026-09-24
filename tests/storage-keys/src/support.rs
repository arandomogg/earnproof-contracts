//! Key builders and contract-scoped storage scanning.
//!
//! ## Rebuilding the keys
//!
//! Each contract keeps its `DataKey` enum private, so the keys are rebuilt here
//! as tuples. A `#[contracttype]` enum variant and the equivalent Rust tuple
//! encode to the same host value, and
//! `encoding::reconstructed_keys_match_the_keys_the_contracts_write` proves it
//! byte for byte against real storage rather than taking it on faith.
//!
//! ## Scoping the scan
//!
//! `storage().persistent().all()` and `storage().temporary().all()` are not
//! scoped to the current contract: they return every entry of that durability
//! in the test ledger, whichever contract wrote it. Only `instance().all()`
//! filters by contract. The scan below therefore takes the unscoped set and
//! partitions it with `has()`, which is contract-scoped, so each contract is
//! measured against its own entries only.

use earnproof_shared::StorageClass;
use soroban_sdk::testutils::storage::{Instance as _, Persistent as _, Temporary as _};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{symbol_short, Address, Bytes, BytesN, Env, IntoVal, Map, Symbol, Val};

use issuer_registry::{IssuerRegistryContract, IssuerRegistryContractClient};
use proof_registry::{ProofRegistryContract, ProofRegistryContractClient};
use protocol_config::{ProtocolConfigContract, ProtocolConfigContractClient};

// ---------------------------------------------------------------------------
// Key construction
// ---------------------------------------------------------------------------

pub fn bytes32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

/// Serialized XDR form of a key, which is what the ledger stores.
pub fn encoded<K: IntoVal<Env, Val>>(env: &Env, key: K) -> std::vec::Vec<u8> {
    let bytes: Bytes = key.to_xdr(env);
    bytes.iter().collect()
}

pub fn admin_key() -> (Symbol,) {
    (symbol_short!("Admin"),)
}

pub fn paused_key() -> (Symbol,) {
    (symbol_short!("Paused"),)
}

pub fn config_version_key(env: &Env) -> (Symbol,) {
    (Symbol::new(env, "ConfigVersion"),)
}

pub fn contract_version_key(env: &Env) -> (Symbol,) {
    (Symbol::new(env, "ContractVersion"),)
}

pub fn schema_version_key(env: &Env, version: u32) -> (Symbol, u32) {
    (Symbol::new(env, "SchemaVersion"), version)
}

pub fn issuer_registry_key(env: &Env) -> (Symbol,) {
    (Symbol::new(env, "IssuerRegistry"),)
}

pub fn protocol_config_key(env: &Env) -> (Symbol,) {
    (Symbol::new(env, "ProtocolConfig"),)
}

pub fn issuer_key(id: &BytesN<32>) -> (Symbol, BytesN<32>) {
    (symbol_short!("Issuer"), id.clone())
}

pub fn address_issuer_key(env: &Env, address: &Address) -> (Symbol, Address) {
    (Symbol::new(env, "AddressIssuer"), address.clone())
}

pub fn proof_key(id: &BytesN<32>) -> (Symbol, BytesN<32>) {
    (symbol_short!("Proof"), id.clone())
}

pub fn active_issuer_count_key(env: &Env) -> (Symbol,) {
    (Symbol::new(env, "ActiveIssuerCount"),)
}

pub fn issuer_epoch_key(env: &Env) -> (Symbol,) {
    (Symbol::new(env, "IssuerEpoch"),)
}

pub fn max_active_issuers_key(env: &Env) -> (Symbol,) {
    (Symbol::new(env, "MaxActiveIssuers"),)
}

pub fn reactivation_cooldown_key(env: &Env) -> (Symbol,) {
    (Symbol::new(env, "ReactivationCooldown"),)
}

// ---------------------------------------------------------------------------
// Contract-scoped storage scanning
// ---------------------------------------------------------------------------

/// Every key the given contract holds in the given durability class.
pub fn keys_in(env: &Env, contract: &Address, class: StorageClass) -> std::vec::Vec<Val> {
    let all: Map<Val, Val> = env.as_contract(contract, || match class {
        StorageClass::Instance => env.storage().instance().all(),
        StorageClass::Persistent => env.storage().persistent().all(),
        StorageClass::Temporary => env.storage().temporary().all(),
    });

    all.keys()
        .iter()
        .filter(|key| owns(env, contract, class, key))
        .collect()
}

/// Same scan, reduced to sorted XDR encodings.
pub fn encoded_keys_in(
    env: &Env,
    contract: &Address,
    class: StorageClass,
) -> std::vec::Vec<std::vec::Vec<u8>> {
    let mut keys: std::vec::Vec<std::vec::Vec<u8>> = keys_in(env, contract, class)
        .into_iter()
        .map(|key| encoded(env, key))
        .collect();
    keys.sort();
    keys
}

fn owns(env: &Env, contract: &Address, class: StorageClass, key: &Val) -> bool {
    // `instance().all()` is already contract-scoped, and `instance().has()`
    // would answer about the instance entry rather than about this key.
    if class == StorageClass::Instance {
        return true;
    }
    env.as_contract(contract, || match class {
        StorageClass::Persistent => env.storage().persistent().has(key),
        StorageClass::Temporary => env.storage().temporary().has(key),
        StorageClass::Instance => true,
    })
}

// ---------------------------------------------------------------------------
// Deployments
// ---------------------------------------------------------------------------

pub struct Deployment {
    pub env: Env,
    pub config_id: Address,
    pub issuers_id: Address,
    pub proofs_id: Address,
    pub issuer: Address,
    pub issuer_id: BytesN<32>,
    pub proof_id: BytesN<32>,
}

/// The smallest deployment that writes one entry under every namespace.
pub fn deployment() -> Deployment {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);

    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    let issuer_id = bytes32(&env, 1);
    let proof_id = bytes32(&env, 5);

    let config_id = env.register(ProtocolConfigContract, ());
    let config = ProtocolConfigContractClient::new(&env, &config_id);
    config.initialize(&admin);
    config.approve_schema_version(&1);

    let issuers_id = env.register(IssuerRegistryContract, ());
    let issuers = IssuerRegistryContractClient::new(&env, &issuers_id);
    issuers.initialize(&admin);
    issuers.register_issuer(&issuer_id, &issuer, &bytes32(&env, 2));

    let proofs_id = env.register(ProofRegistryContract, ());
    let proofs = ProofRegistryContractClient::new(&env, &proofs_id);
    proofs.initialize(&admin, &issuers_id, &config_id);
    proofs.register_proof(&proof_id, &bytes32(&env, 6), &issuer, &1, &1_000_000);

    Deployment {
        env,
        config_id,
        issuers_id,
        proofs_id,
        issuer,
        issuer_id,
        proof_id,
    }
}

/// A deployment that has taken every state-mutating entry point, so that no
/// namespace can hide behind an untaken code path.
pub fn exercised_deployment() -> Deployment {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);

    let admin = Address::generate(&env);
    let rotated_admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    let rotated_issuer = Address::generate(&env);
    let suspended_issuer = Address::generate(&env);
    let revoked_issuer = Address::generate(&env);
    let held_suspended_issuer = Address::generate(&env);
    let issuer_id = bytes32(&env, 1);
    let proof_id = bytes32(&env, 5);

    let config_id = env.register(ProtocolConfigContract, ());
    let config = ProtocolConfigContractClient::new(&env, &config_id);
    config.initialize(&admin);
    config.approve_schema_version(&1);
    config.approve_schema_version(&2);
    config.deprecate_schema_version(&2);
    config.pause();
    config.unpause();
    config.set_admin(&rotated_admin);

    let issuers_id = env.register(IssuerRegistryContract, ());
    let issuers = IssuerRegistryContractClient::new(&env, &issuers_id);
    issuers.initialize(&admin);
    issuers.register_issuer(&issuer_id, &issuer, &bytes32(&env, 2));
    issuers.update_issuer(&issuer_id, &bytes32(&env, 3));
    issuers.rotate_issuer_address(&issuer_id, &rotated_issuer);
    issuers.register_issuer(&bytes32(&env, 10), &suspended_issuer, &bytes32(&env, 11));
    issuers.suspend_issuer(&bytes32(&env, 10));
    issuers.reactivate_issuer(&bytes32(&env, 10));
    issuers.register_issuer(&bytes32(&env, 20), &revoked_issuer, &bytes32(&env, 21));
    issuers.revoke_issuer(&bytes32(&env, 20));
    // Suspended and left suspended, so the ReactivatableAt namespace is present
    // for the durability-class inventory check. The reactivate path above proves
    // the entry is removed when a suspension is lifted.
    issuers.register_issuer(
        &bytes32(&env, 30),
        &held_suspended_issuer,
        &bytes32(&env, 31),
    );
    issuers.suspend_issuer(&bytes32(&env, 30));

    let proofs_id = env.register(ProofRegistryContract, ());
    let proofs = ProofRegistryContractClient::new(&env, &proofs_id);
    proofs.initialize(&admin, &issuers_id, &config_id);
    proofs.register_proof(
        &proof_id,
        &bytes32(&env, 6),
        &rotated_issuer,
        &1,
        &1_000_000,
    );
    proofs.register_proof(
        &bytes32(&env, 7),
        &bytes32(&env, 8),
        &rotated_issuer,
        &1,
        &1_000_000,
    );
    proofs.revoke_proof(&bytes32(&env, 7));

    Deployment {
        env,
        config_id,
        issuers_id,
        proofs_id,
        issuer: rotated_issuer,
        issuer_id,
        proof_id,
    }
}
