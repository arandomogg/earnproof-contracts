//! The catalog and the error enums describe the same set of errors.

use earnproof_shared::error_catalog::{domain_for, spec, Domain};
use earnproof_shared::{ContractError, IssuerError, ProofError, ERROR_CATALOG};

/// Every variant of every published error enum, paired with its code.
///
/// This list is written out by hand on purpose. Rust cannot enumerate the
/// variants of a `#[contracterror]` enum at runtime, so a new variant does not
/// appear here on its own; whoever adds one has to add it in three places, and
/// the tests below fail until all three agree.
fn declared_variants() -> std::vec::Vec<(&'static str, &'static str, u32)> {
    std::vec![
        (
            "ContractError",
            "AlreadyInitialized",
            ContractError::AlreadyInitialized as u32
        ),
        (
            "ContractError",
            "NotInitialized",
            ContractError::NotInitialized as u32
        ),
        (
            "ContractError",
            "Unauthorized",
            ContractError::Unauthorized as u32
        ),
        (
            "ContractError",
            "AlreadyExists",
            ContractError::AlreadyExists as u32
        ),
        ("ContractError", "NotFound", ContractError::NotFound as u32),
        (
            "ContractError",
            "InvalidState",
            ContractError::InvalidState as u32
        ),
        (
            "ContractError",
            "InvalidInput",
            ContractError::InvalidInput as u32
        ),
        (
            "ContractError",
            "ProtocolPaused",
            ContractError::ProtocolPaused as u32
        ),
        (
            "IssuerError",
            "IssuerAlreadyRegistered",
            IssuerError::IssuerAlreadyRegistered as u32
        ),
        (
            "IssuerError",
            "IssuerNotFound",
            IssuerError::IssuerNotFound as u32
        ),
        (
            "IssuerError",
            "IssuerAddressAlreadyRegistered",
            IssuerError::IssuerAddressAlreadyRegistered as u32,
        ),
        (
            "IssuerError",
            "IssuerAddressNotFound",
            IssuerError::IssuerAddressNotFound as u32
        ),
        (
            "IssuerError",
            "IssuerRevoked",
            IssuerError::IssuerRevoked as u32
        ),
        (
            "IssuerError",
            "IssuerInactive",
            IssuerError::IssuerInactive as u32
        ),
        (
            "IssuerError",
            "InvalidTransition",
            IssuerError::InvalidTransition as u32
        ),
        (
            "ProofError",
            "ProofAlreadyRegistered",
            ProofError::ProofAlreadyRegistered as u32
        ),
        (
            "ProofError",
            "ProofNotFound",
            ProofError::ProofNotFound as u32
        ),
        (
            "ProofError",
            "ProofAlreadyRevoked",
            ProofError::ProofAlreadyRevoked as u32
        ),
        (
            "ProofError",
            "ProofExpired",
            ProofError::ProofExpired as u32
        ),
        (
            "ProofError",
            "InvalidSchemaVersion",
            ProofError::InvalidSchemaVersion as u32
        ),
        (
            "ProofError",
            "SchemaVersionNotApproved",
            ProofError::SchemaVersionNotApproved as u32,
        ),
        (
            "ProofError",
            "ContractPaused",
            ProofError::ContractPaused as u32,
        ),
        (
            "ProofError",
            "IssuerInactive",
            ProofError::IssuerInactive as u32,
        ),
        (
            "ProofError",
            "UnsupportedSchema",
            ProofError::UnsupportedSchema as u32,
        ),
        (
            "ProofError",
            "MalformedInput",
            ProofError::MalformedInput as u32,
        ),
    ]
}

#[test]
fn every_declared_variant_has_a_catalog_entry() {
    for (enum_name, name, code) in declared_variants() {
        let entry = spec(code).unwrap_or_else(|| {
            std::panic!("{enum_name}::{name} has code {code} but no catalog entry")
        });
        assert_eq!(
            entry.name, name,
            "code {code} is catalogued under a different name"
        );
        assert_eq!(
            entry.enum_name, enum_name,
            "code {code} is catalogued under a different enum"
        );
    }
}

#[test]
fn every_catalog_entry_corresponds_to_a_declared_variant() {
    let declared = declared_variants();
    for entry in ERROR_CATALOG {
        assert!(
            declared
                .iter()
                .any(|(enum_name, name, code)| *code == entry.code
                    && *name == entry.name
                    && *enum_name == entry.enum_name),
            "catalog entry {} ({}) does not correspond to a declared variant",
            entry.name,
            entry.code
        );
    }
    assert_eq!(ERROR_CATALOG.len(), declared.len());
}

#[test]
fn codes_are_unique() {
    for (index, entry) in ERROR_CATALOG.iter().enumerate() {
        for other in ERROR_CATALOG.iter().skip(index + 1) {
            assert_ne!(
                entry.code, other.code,
                "{} and {} share code {}",
                entry.name, other.name, entry.code
            );
        }
    }
}

#[test]
fn the_catalog_is_ordered_by_code() {
    // Ordering keeps the golden fixture and the published tables comparable
    // line by line, and makes a renumbering obvious in review.
    let mut previous = 0_u32;
    for entry in ERROR_CATALOG {
        assert!(
            entry.code > previous,
            "{} breaks code ordering at {}",
            entry.name,
            entry.code
        );
        previous = entry.code;
    }
}

#[test]
fn every_code_sits_in_the_range_its_enum_owns() {
    for entry in ERROR_CATALOG {
        assert_eq!(
            domain_for(entry.code),
            entry.domain,
            "{} is catalogued in the wrong domain",
            entry.name
        );

        let (low, high) = entry
            .domain
            .range()
            .unwrap_or_else(|| std::panic!("{} has no allocated range", entry.name));
        assert!(
            (low..=high).contains(&entry.code),
            "{} at {} is outside {}..={}",
            entry.name,
            entry.code,
            low,
            high
        );

        let expected_enum = match entry.domain {
            Domain::Common => "ContractError",
            Domain::IssuerRegistry => "IssuerError",
            Domain::ProofRegistry => "ProofError",
            Domain::ProtocolConfig | Domain::Unallocated => {
                std::panic!("{} uses a domain with no enum", entry.name)
            }
        };
        assert_eq!(
            entry.enum_name, expected_enum,
            "{} is in the wrong enum",
            entry.name
        );
    }
}

#[test]
fn the_protocol_config_range_is_reserved_and_empty() {
    // 100-199 is allocated in the documented scheme but unused: protocol-config
    // returns common errors only. Asserting it here means the first code added
    // there is a deliberate act, not an accident.
    assert!(!ERROR_CATALOG
        .iter()
        .any(|entry| (100..=199).contains(&entry.code)));
    assert_eq!(domain_for(150), Domain::ProtocolConfig);
}

#[test]
fn every_entry_documents_a_cause_and_a_remediation() {
    for entry in ERROR_CATALOG {
        assert!(!entry.cause.is_empty(), "{} has no cause", entry.name);
        assert!(
            !entry.remediation.is_empty(),
            "{} has no remediation",
            entry.name
        );
        assert!(
            !entry.client_message.is_empty(),
            "{} has no client message",
            entry.name
        );
        assert!(
            (400..=599).contains(&entry.http_status),
            "{} maps to a non-error HTTP status",
            entry.name
        );
    }
}
