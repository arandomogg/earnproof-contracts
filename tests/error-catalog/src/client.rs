//! The mapping a backend is expected to perform.
//!
//! A client integrating these contracts has to answer three questions about
//! any code it receives: which contract produced it, whether retrying can
//! help, and what it may tell a user. The helpers in `earnproof-shared` answer
//! all three, including for codes that did not exist when the client was
//! compiled, and this module exercises them the way a backend would.

use earnproof_shared::error_catalog::{domain_for, retry_for, spec};
use earnproof_shared::{Domain, Retry, ERROR_CATALOG};

/// The decision a backend makes from a raw contract error code.
///
/// This mirrors what a real integration does: attribute, classify, and pick a
/// user-facing response, without ever branching on a variant name.
#[derive(Debug, Eq, PartialEq)]
struct Decision {
    domain: Domain,
    retry: Retry,
    http_status: u16,
    message: &'static str,
    recognised: bool,
}

fn decide(code: u32) -> Decision {
    match spec(code) {
        Some(entry) => Decision {
            domain: entry.domain,
            retry: entry.retry,
            http_status: entry.http_status,
            message: entry.client_message,
            recognised: true,
        },
        // The unknown-code rule. The client still attributes the failure to a
        // contract by range, but it refuses to guess what the code means: no
        // automatic retry, a generic message, and a status that says the
        // request was not completed rather than that it was rejected.
        None => Decision {
            domain: domain_for(code),
            retry: Retry::Never,
            http_status: 502,
            message: "Request could not be completed",
            recognised: false,
        },
    }
}

#[test]
fn every_published_code_is_recognised() {
    for entry in ERROR_CATALOG {
        let decision = decide(entry.code);
        assert!(decision.recognised, "{} was not recognised", entry.name);
        assert_eq!(decision.domain, entry.domain);
        assert_eq!(decision.retry, entry.retry);
        assert_eq!(decision.http_status, entry.http_status);
        assert_eq!(decision.message, entry.client_message);
    }
}

#[test]
fn an_unknown_code_inside_an_allocated_range_is_attributed_but_not_guessed() {
    // A future release adds proof-registry code 350. A client compiled today
    // must attribute it to the proof registry, refuse to retry it, and say
    // nothing specific about it.
    let decision = decide(350);

    assert_eq!(decision.domain, Domain::ProofRegistry);
    assert_eq!(decision.retry, Retry::Never);
    assert!(!decision.recognised);
    assert_eq!(decision.http_status, 502);
    assert_eq!(decision.message, "Request could not be completed");
}

#[test]
fn an_unknown_code_in_every_allocated_range_is_attributed_correctly() {
    for (code, domain) in [
        (50_u32, Domain::Common),
        (150, Domain::ProtocolConfig),
        (250, Domain::IssuerRegistry),
        (350, Domain::ProofRegistry),
    ] {
        let decision = decide(code);
        assert_eq!(decision.domain, domain, "code {code}");
        assert!(!decision.recognised, "code {code}");
    }
}

#[test]
fn a_code_outside_every_range_is_not_attributed_to_a_contract() {
    // Zero, the boundaries just outside the allocated ranges, and the top of
    // the u32 space. None of these came from these contracts, and a client
    // must not claim otherwise.
    for code in [0_u32, 400, 401, 100_000, u32::MAX] {
        let decision = decide(code);
        assert_eq!(decision.domain, Domain::Unallocated, "code {code}");
        assert_eq!(decision.retry, Retry::Never, "code {code}");
        assert!(!decision.recognised, "code {code}");
    }
}

#[test]
fn range_boundaries_are_inclusive_on_both_ends() {
    assert_eq!(domain_for(1), Domain::Common);
    assert_eq!(domain_for(99), Domain::Common);
    assert_eq!(domain_for(100), Domain::ProtocolConfig);
    assert_eq!(domain_for(199), Domain::ProtocolConfig);
    assert_eq!(domain_for(200), Domain::IssuerRegistry);
    assert_eq!(domain_for(299), Domain::IssuerRegistry);
    assert_eq!(domain_for(300), Domain::ProofRegistry);
    assert_eq!(domain_for(399), Domain::ProofRegistry);
    assert_eq!(domain_for(0), Domain::Unallocated);
    assert_eq!(domain_for(400), Domain::Unallocated);
}

#[test]
fn retry_for_never_invents_a_classification() {
    for entry in ERROR_CATALOG {
        assert_eq!(retry_for(entry.code), entry.retry);
    }
    for unknown in [0_u32, 50, 150, 250, 350, 400, u32::MAX] {
        assert_eq!(retry_for(unknown), Retry::Never, "code {unknown}");
    }
}

#[test]
fn an_automatic_retry_loop_only_repeats_operator_action_codes() {
    // The one decision that is dangerous to get wrong. A backend that retries
    // on its own must do so for exactly the codes an operator can clear, and
    // for nothing else, so that a rejected request is never replayed.
    let retryable: std::vec::Vec<&str> = ERROR_CATALOG
        .iter()
        .filter(|entry| retry_for(entry.code) == Retry::AfterOperatorAction)
        .map(|entry| entry.name)
        .collect();

    assert_eq!(
        retryable,
        std::vec![
            "NotInitialized",
            "ProtocolPaused",
            "IssuerInactive",
            "IssuerCapacityExceeded",
            "InvalidSchemaVersion",
            "SchemaVersionNotApproved",
        ]
    );
}
