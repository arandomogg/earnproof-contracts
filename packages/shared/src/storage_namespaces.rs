//! The authoritative inventory of on-chain storage namespaces.
//!
//! Each contract keeps its own private `DataKey` enum, which is what actually
//! addresses ledger entries. This module is the reviewed description of those
//! enums: one entry per `DataKey` variant, recording which contract owns it,
//! how many payload fields it carries, which durability class it belongs to,
//! what it stores, and who is responsible for it.
//!
//! The inventory is not decorative. `tests/storage-keys/` drives a full
//! lifecycle across all three contracts and compares the namespaces that
//! actually appear in instance, persistent, and temporary storage against
//! [`STORAGE_NAMESPACES`]. A new `DataKey` variant, a renamed one, or one
//! written to the wrong durability class fails that comparison.
//!
//! ## Why namespaces cannot collide
//!
//! A `#[contracttype]` enum encodes as a vector whose first element is the
//! variant name as a `Symbol` and whose remaining elements are the payload
//! fields in declaration order. Two consequences follow, and both are asserted
//! in `tests/storage-keys/`:
//!
//! * Two variants with different names never produce the same key, whatever
//!   their payloads, because the discriminant symbol differs in the first
//!   position. There is no concatenation step in which a payload could be
//!   mistaken for a discriminant.
//! * Two variants with the same name and different arity never produce the
//!   same key, because the encoded vectors have different lengths.
//!
//! Ledger keys are additionally scoped by contract address, so the same
//! namespace name in two different contracts addresses two different entries.
//!
//! See [`docs/storage.md`](../../../docs/storage.md) for the prose version of
//! this inventory, including the rules for adding a namespace.

/// Durability class of a storage entry.
///
/// The three classes are not interchangeable. Instance entries share one
/// lifetime with the contract itself and are read on nearly every call, so
/// they suit small configuration values. Persistent entries carry an
/// independent per-key lifetime and suit records that must outlive any single
/// deployment concern. Temporary entries cannot be restored once they expire,
/// which makes them unsuitable for anything a verifier may need later.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StorageClass {
    /// Shares the contract instance lifetime.
    Instance,
    /// Independent per-key lifetime, restorable after archival.
    Persistent,
    /// Independent per-key lifetime, unrecoverable after expiry.
    Temporary,
}

impl StorageClass {
    /// Stable lower-case name, used in generated documentation and tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            StorageClass::Instance => "instance",
            StorageClass::Persistent => "persistent",
            StorageClass::Temporary => "temporary",
        }
    }
}

/// One `DataKey` variant.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct StorageNamespace {
    /// Crate name of the owning contract, as it appears under `contracts/`.
    pub contract: &'static str,
    /// The `DataKey` variant name, which is the discriminant symbol that
    /// appears first in the encoded key.
    pub namespace: &'static str,
    /// Number of payload fields the variant carries. The encoded key is a
    /// vector of `arity + 1` elements.
    pub arity: u32,
    /// Durability class the contract writes this key to.
    pub class: StorageClass,
    /// Rust type stored under the key.
    pub value: &'static str,
    /// Role accountable for the entry existing and staying live.
    pub owner: &'static str,
}

/// Every storage namespace in the deployment, ordered by contract and then by
/// namespace name.
///
/// Adding a row here is the second half of adding a storage key; the first is
/// adding the `DataKey` variant. Doing one without the other fails the tests in
/// `tests/storage-keys/`.
pub const STORAGE_NAMESPACES: [StorageNamespace; 19] = [
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "ActiveIssuerCount",
        arity: 0,
        class: StorageClass::Instance,
        value: "u32",
        owner: "registry operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "AddressIssuer",
        arity: 1,
        class: StorageClass::Persistent,
        value: "BytesN<32>",
        owner: "registry operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "Admin",
        arity: 0,
        class: StorageClass::Instance,
        value: "Address",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "ContractVersion",
        arity: 0,
        class: StorageClass::Instance,
        value: "u32",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "Issuer",
        arity: 1,
        class: StorageClass::Persistent,
        value: "IssuerRecord",
        owner: "registry operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "IssuerEpoch",
        arity: 0,
        class: StorageClass::Instance,
        value: "u64",
        owner: "registry operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "MaxActiveIssuers",
        arity: 0,
        class: StorageClass::Instance,
        value: "u32",
        owner: "registry operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "ReactivatableAt",
        arity: 1,
        class: StorageClass::Persistent,
        value: "u64",
        owner: "registry operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "ReactivationCooldown",
        arity: 0,
        class: StorageClass::Instance,
        value: "u64",
        owner: "registry operator",
    },
    StorageNamespace {
        contract: "proof-registry",
        namespace: "Admin",
        arity: 0,
        class: StorageClass::Instance,
        value: "Address",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "proof-registry",
        namespace: "ContractVersion",
        arity: 0,
        class: StorageClass::Instance,
        value: "u32",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "proof-registry",
        namespace: "IssuerRegistry",
        arity: 0,
        class: StorageClass::Instance,
        value: "Address",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "proof-registry",
        namespace: "Proof",
        arity: 1,
        class: StorageClass::Persistent,
        value: "ProofRecord",
        owner: "issuing party",
    },
    StorageNamespace {
        contract: "proof-registry",
        namespace: "ProtocolConfig",
        arity: 0,
        class: StorageClass::Instance,
        value: "Address",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "protocol-config",
        namespace: "Admin",
        arity: 0,
        class: StorageClass::Instance,
        value: "Address",
        owner: "protocol operator",
    },
    StorageNamespace {
        contract: "protocol-config",
        namespace: "ConfigVersion",
        arity: 0,
        class: StorageClass::Instance,
        value: "u32",
        owner: "protocol operator",
    },
    StorageNamespace {
        contract: "protocol-config",
        namespace: "ContractVersion",
        arity: 0,
        class: StorageClass::Instance,
        value: "u32",
        owner: "protocol operator",
    },
    StorageNamespace {
        contract: "protocol-config",
        namespace: "Paused",
        arity: 0,
        class: StorageClass::Instance,
        value: "bool",
        owner: "protocol operator",
    },
    StorageNamespace {
        contract: "protocol-config",
        namespace: "SchemaVersion",
        arity: 1,
        class: StorageClass::Persistent,
        value: "bool",
        owner: "protocol operator",
    },
];

/// The three contracts covered by [`STORAGE_NAMESPACES`].
pub const CONTRACTS: [&str; 3] = ["issuer-registry", "proof-registry", "protocol-config"];

/// Returns the namespaces owned by `contract` in the given durability class.
pub fn namespaces_for<'a>(
    contract: &'a str,
    class: StorageClass,
) -> impl Iterator<Item = &'static str> + 'a {
    STORAGE_NAMESPACES
        .into_iter()
        .filter(move |entry| entry.contract == contract && entry.class == class)
        .map(|entry| entry.namespace)
}

/// Looks up a single namespace.
pub fn namespace(contract: &str, name: &str) -> Option<StorageNamespace> {
    STORAGE_NAMESPACES
        .into_iter()
        .find(|entry| entry.contract == contract && entry.namespace == name)
}
