//! Durability-class compatibility gate.
//!
//! This module drives a full lifecycle across all three contracts, reads back
//! the namespaces that actually appear in each durability class, and compares
//! them against the inventory in `earnproof-shared`. It is the test that fails
//! when a `DataKey` variant is added, renamed, or written to a class the
//! inventory does not claim.

use super::support::{exercised_deployment, keys_in};
use earnproof_shared::storage_namespaces::namespaces_for;
use earnproof_shared::{StorageClass, STORAGE_NAMESPACES};
use soroban_sdk::{Address, Env, IntoVal, Symbol, Val, Vec as SorobanVec};

const CONTRACT_NAMES: [&str; 3] = ["protocol-config", "issuer-registry", "proof-registry"];

/// Namespaces present in one durability class of one contract, sorted and
/// de-duplicated.
///
/// The discriminant symbol is resolved back to a name by matching it against
/// the inventory. A key whose discriminant is not in the inventory is a new
/// namespace nobody documented, and it fails here by name.
fn observed(
    env: &Env,
    contract: &Address,
    class: StorageClass,
) -> std::vec::Vec<std::string::String> {
    let mut namespaces: std::vec::Vec<std::string::String> = keys_in(env, contract, class)
        .into_iter()
        .map(|key| {
            let parts: SorobanVec<Val> = key.into_val(env);
            let discriminant: Symbol = parts
                .get(0)
                .expect("storage key is not a discriminated vector")
                .into_val(env);
            let known = STORAGE_NAMESPACES
                .iter()
                .map(|entry| entry.namespace)
                .find(|name| Symbol::new(env, name) == discriminant)
                .expect("storage key uses a namespace missing from STORAGE_NAMESPACES");
            std::string::String::from(known)
        })
        .collect();
    namespaces.sort();
    namespaces.dedup();
    namespaces
}

fn expected(contract: &str, class: StorageClass) -> std::vec::Vec<std::string::String> {
    let mut namespaces: std::vec::Vec<std::string::String> = namespaces_for(contract, class)
        .map(std::string::String::from)
        .collect();
    namespaces.sort();
    namespaces
}

#[test]
fn observed_namespaces_match_the_inventory_exactly() {
    let deployment = exercised_deployment();
    let addresses = [
        &deployment.config_id,
        &deployment.issuers_id,
        &deployment.proofs_id,
    ];

    for (contract, address) in CONTRACT_NAMES.into_iter().zip(addresses) {
        for class in [
            StorageClass::Instance,
            StorageClass::Persistent,
            StorageClass::Temporary,
        ] {
            assert_eq!(
                observed(&deployment.env, address, class),
                expected(contract, class),
                "{contract} {} storage",
                class.as_str()
            );
        }
    }
}

#[test]
fn no_contract_writes_to_temporary_storage() {
    let deployment = exercised_deployment();

    for address in [
        &deployment.config_id,
        &deployment.issuers_id,
        &deployment.proofs_id,
    ] {
        assert!(
            keys_in(&deployment.env, address, StorageClass::Temporary).is_empty(),
            "temporary storage must stay empty"
        );
    }
}

#[test]
fn per_record_namespaces_hold_one_entry_per_record() {
    let deployment = exercised_deployment();
    let env = &deployment.env;

    // Four issuers, each with a record and a reverse-index entry. The rotated
    // address replaces the old index entry rather than adding to it, so those
    // two counts are eight and not nine. The issuer left suspended adds one
    // ReactivatableAt entry, for nine persistent keys in total.
    assert_eq!(
        keys_in(env, &deployment.issuers_id, StorageClass::Persistent).len(),
        9
    );

    // Two proofs, one of them revoked in place.
    assert_eq!(
        keys_in(env, &deployment.proofs_id, StorageClass::Persistent).len(),
        2
    );

    // Two schema versions, one approved and one deprecated. Deprecation keeps
    // the key so that "never seen" stays distinguishable from "withdrawn".
    assert_eq!(
        keys_in(env, &deployment.config_id, StorageClass::Persistent).len(),
        2
    );
}

#[test]
fn singleton_namespaces_hold_exactly_one_entry_each() {
    let deployment = exercised_deployment();
    let addresses = [
        &deployment.config_id,
        &deployment.issuers_id,
        &deployment.proofs_id,
    ];

    for (contract, address) in CONTRACT_NAMES.into_iter().zip(addresses) {
        assert_eq!(
            keys_in(&deployment.env, address, StorageClass::Instance).len(),
            expected(contract, StorageClass::Instance).len(),
            "{contract} instance storage should hold one entry per namespace"
        );
    }
}

#[test]
fn a_namespace_stays_in_one_durability_class() {
    let deployment = exercised_deployment();
    let addresses = [
        &deployment.config_id,
        &deployment.issuers_id,
        &deployment.proofs_id,
    ];

    // The same namespace must never appear in two classes within a contract.
    // A key that migrated class would otherwise leave a readable copy behind
    // under the old lifetime rules.
    for address in addresses {
        let instance = observed(&deployment.env, address, StorageClass::Instance);
        let persistent = observed(&deployment.env, address, StorageClass::Persistent);
        for namespace in &instance {
            assert!(
                !persistent.contains(namespace),
                "{namespace} appears in two durability classes"
            );
        }
    }
}
