//! Self-consistency of the namespace inventory.
//!
//! These tests do not touch a contract. They check that
//! [`earnproof_shared::STORAGE_NAMESPACES`] is a well-formed description: no
//! duplicated namespace within a contract, no namespace name a Soroban `Symbol`
//! could not carry, and no durability class chosen against the documented
//! lifecycle rules.

use earnproof_shared::storage_namespaces::{namespace, namespaces_for, CONTRACTS};
use earnproof_shared::{StorageClass, STORAGE_NAMESPACES};

/// Soroban symbols are limited to 32 characters drawn from `[a-zA-Z0-9_]`.
/// A namespace that violated this could not be used as an enum discriminant.
const SYMBOL_MAX_LEN: usize = 32;

#[test]
fn every_namespace_is_a_valid_symbol() {
    for entry in STORAGE_NAMESPACES {
        assert!(
            !entry.namespace.is_empty(),
            "{}: empty namespace",
            entry.contract
        );
        assert!(
            entry.namespace.len() <= SYMBOL_MAX_LEN,
            "{}::{} is {} characters, over the {SYMBOL_MAX_LEN}-character symbol limit",
            entry.contract,
            entry.namespace,
            entry.namespace.len()
        );
        assert!(
            entry
                .namespace
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_'),
            "{}::{} contains a character a symbol cannot carry",
            entry.contract,
            entry.namespace
        );
    }
}

#[test]
fn no_contract_declares_the_same_namespace_twice() {
    for (index, entry) in STORAGE_NAMESPACES.iter().enumerate() {
        for other in STORAGE_NAMESPACES.iter().skip(index + 1) {
            assert!(
                !(entry.contract == other.contract && entry.namespace == other.namespace),
                "{}::{} is declared twice",
                entry.contract,
                entry.namespace
            );
        }
    }
}

#[test]
fn the_inventory_is_sorted_and_covers_every_contract() {
    // A sorted inventory keeps diffs on this file readable and makes an
    // accidental duplicate obvious during review.
    let mut previous: Option<(&str, &str)> = None;
    for entry in STORAGE_NAMESPACES {
        let current = (entry.contract, entry.namespace);
        if let Some(previous) = previous {
            assert!(
                previous < current,
                "inventory is out of order at {}::{}",
                entry.contract,
                entry.namespace
            );
        }
        previous = Some(current);
    }

    for contract in CONTRACTS {
        assert!(
            STORAGE_NAMESPACES
                .iter()
                .any(|entry| entry.contract == contract),
            "{contract} has no namespaces declared"
        );
    }

    for entry in STORAGE_NAMESPACES {
        assert!(
            CONTRACTS.contains(&entry.contract),
            "{} is not a known contract",
            entry.contract
        );
    }
}

#[test]
fn durability_matches_the_documented_lifecycle_rules() {
    for entry in STORAGE_NAMESPACES {
        match entry.class {
            // Instance entries share one lifetime and one footprint slot with
            // the contract, so only fixed singletons belong there. A key that
            // carries a payload is per-record by construction and would grow
            // the instance entry without bound.
            StorageClass::Instance => assert_eq!(
                entry.arity, 0,
                "{}::{} is instance storage but carries a payload",
                entry.contract, entry.namespace
            ),
            // Persistent entries are the only class safe for records a
            // verifier may need after an idle period, because they are the
            // only class that can be restored once archived.
            StorageClass::Persistent => assert!(
                entry.arity > 0,
                "{}::{} is persistent but is a singleton; singletons belong in instance storage",
                entry.contract,
                entry.namespace
            ),
            // Temporary storage is unrecoverable after expiry. Nothing in this
            // deployment may use it, and a future key that does has to justify
            // itself by changing this assertion.
            StorageClass::Temporary => panic!(
                "{}::{} uses temporary storage, which cannot be restored after expiry",
                entry.contract, entry.namespace
            ),
        }
    }
}

#[test]
fn every_namespace_records_a_value_type_and_an_owner() {
    for entry in STORAGE_NAMESPACES {
        assert!(
            !entry.value.is_empty(),
            "{}::{} has no value type",
            entry.contract,
            entry.namespace
        );
        assert!(
            !entry.owner.is_empty(),
            "{}::{} has no documented owner",
            entry.contract,
            entry.namespace
        );
    }
}

#[test]
fn lookup_helpers_agree_with_the_inventory() {
    for entry in STORAGE_NAMESPACES {
        assert_eq!(namespace(entry.contract, entry.namespace), Some(entry));
    }

    assert_eq!(namespace("proof-registry", "Issuer"), None);
    assert_eq!(namespace("issuer-registry", "Proof"), None);

    let persistent: std::vec::Vec<&str> =
        namespaces_for("issuer-registry", StorageClass::Persistent).collect();
    assert_eq!(
        persistent,
        std::vec!["AddressIssuer", "Issuer", "ReactivatableAt"]
    );

    let instance: std::vec::Vec<&str> =
        namespaces_for("proof-registry", StorageClass::Instance).collect();
    assert_eq!(
        instance,
        std::vec![
            "Admin",
            "ContractVersion",
            "IssuerRegistry",
            "ProtocolConfig"
        ]
    );

    assert_eq!(
        namespaces_for("proof-registry", StorageClass::Temporary).count(),
        0
    );
}

#[test]
fn the_same_namespace_name_may_be_reused_across_contracts() {
    // `Admin` exists in all three contracts. This is safe because ledger keys
    // are scoped by contract address, and it is asserted here so that the
    // uniqueness test above is not misread as forbidding it.
    let admins = STORAGE_NAMESPACES
        .iter()
        .filter(|entry| entry.namespace == "Admin")
        .count();
    assert_eq!(admins, CONTRACTS.len());
}
