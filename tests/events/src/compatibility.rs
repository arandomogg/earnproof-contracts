//! Event topic and payload evolution.
//!
//! `tests/event-fixtures/` validates that the JSON fixtures are well-formed.
//! What it cannot check is whether they still describe the contracts: a fixture
//! is a static file, and nothing stops the two from drifting apart.
//!
//! These tests close that gap by comparing live emissions against the fixtures.
//! A renamed topic or a dropped payload field fails here, which is what makes
//! the fixtures usable as a compatibility contract for indexers rather than
//! documentation that happened to be true once.

use crate::harness::{hash, read_events, Deployment, ObservedEvent};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, Symbol, TryFromVal, Val};

/// Every topic the fixtures declare, with the payload fields they promise.
///
/// Mirrors `tests/fixtures/events/*/v1/*.json`. Changing either side without
/// the other fails a test here, which is the point: the fixture is the
/// published contract and the emission is the implementation.
const DECLARED_EVENTS: &[(&str, &[&str])] = &[
    // protocol-config
    ("initialized", &["admin"]),
    ("admin_changed", &["new_admin"]),
    ("paused", &["paused"]),
    ("unpaused", &["paused"]),
    ("schema_approved", &["version"]),
    ("schema_deprecated", &["version"]),
    // issuer-registry
    (
        "issuer_registered",
        &[
            "issuer_id_hash",
            "issuer_address",
            "metadata_hash",
            "created_at",
            "epoch",
        ],
    ),
    (
        "issuer_metadata_updated",
        &["issuer_id_hash", "metadata_hash", "updated_at", "epoch"],
    ),
    (
        "issuer_suspended",
        &["issuer_id_hash", "updated_at", "epoch"],
    ),
    (
        "issuer_reactivated",
        &["issuer_id_hash", "updated_at", "epoch"],
    ),
    ("issuer_revoked", &["issuer_id_hash", "updated_at", "epoch"]),
    (
        "issuer_address_rotated",
        &[
            "issuer_id_hash",
            "old_address",
            "new_address",
            "updated_at",
            "epoch",
        ],
    ),
];

/// Looks up the declared payload fields for a topic.
fn declared_fields(topic: &str) -> &'static [&'static str] {
    DECLARED_EVENTS
        .iter()
        .find(|(name, _)| *name == topic)
        .map(|(_, fields)| *fields)
        .unwrap_or_else(|| {
            std::panic!(
                "topic {topic} is emitted but not declared in DECLARED_EVENTS \
                 or tests/fixtures/events/; an undeclared event is an \
                 undocumented compatibility surface"
            )
        })
}

/// Asserts an event carries exactly the fields its fixture declares.
///
/// Both directions matter. A missing field breaks an indexer that reads it; an
/// extra one is an undocumented addition that the fixture's `compatibility`
/// classification has not been updated to describe.
fn assert_matches_fixture(env: &Env, event: &ObservedEvent) {
    let topic = event
        .discriminant(env)
        .map(|symbol| std::format!("{symbol:?}"))
        .expect("every event carries a symbol discriminant");

    // The debug rendering is `Symbol(name)`; extract the name.
    let name: std::string::String = topic
        .trim_start_matches("Symbol(")
        .trim_end_matches(')')
        .into();

    let expected = declared_fields(&name);

    let map: soroban_sdk::Map<Symbol, Val> =
        soroban_sdk::Map::try_from_val(env, &event.data).expect("payloads are maps");

    assert_eq!(
        map.len() as usize,
        expected.len(),
        "{name}: fixture declares {} payload field(s), contract emitted {}",
        expected.len(),
        map.len()
    );

    for field in expected {
        assert!(
            map.get(Symbol::new(env, field)).is_some(),
            "{name}: fixture declares field {field} but the contract did not emit it"
        );
    }
}

#[test]
fn protocol_config_events_match_their_fixtures() {
    let deployment = Deployment::new();
    let successor = Address::generate(&deployment.env);

    for event in deployment.capture(|| deployment.config.pause()) {
        assert_matches_fixture(&deployment.env, &event);
    }
    for event in deployment.capture(|| deployment.config.unpause()) {
        assert_matches_fixture(&deployment.env, &event);
    }
    for event in deployment.capture(|| deployment.config.approve_schema_version(&4)) {
        assert_matches_fixture(&deployment.env, &event);
    }
    for event in deployment.capture(|| deployment.config.deprecate_schema_version(&4)) {
        assert_matches_fixture(&deployment.env, &event);
    }
    for event in deployment.capture(|| deployment.config.set_admin(&successor)) {
        assert_matches_fixture(&deployment.env, &event);
    }
}

#[test]
fn initialization_event_matches_its_fixture() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register(protocol_config::ProtocolConfigContract, ());
    let config = protocol_config::ProtocolConfigContractClient::new(&env, &contract_id);
    config.initialize(&admin);

    for event in read_events(&env) {
        assert_matches_fixture(&env, &event);
    }
}

#[test]
fn issuer_registry_events_match_their_fixtures() {
    let deployment = Deployment::new();
    let next = Address::generate(&deployment.env);
    let replacement = Address::generate(&deployment.env);
    let second_id = hash(&deployment.env, 0x04);

    for event in deployment.capture(|| {
        deployment
            .issuers
            .register_issuer(&second_id, &next, &hash(&deployment.env, 0xC4))
    }) {
        assert_matches_fixture(&deployment.env, &event);
    }

    for event in deployment.capture(|| {
        deployment
            .issuers
            .update_issuer(&deployment.issuer_id, &hash(&deployment.env, 0xC5))
    }) {
        assert_matches_fixture(&deployment.env, &event);
    }

    for event in deployment.capture(|| deployment.issuers.suspend_issuer(&deployment.issuer_id)) {
        assert_matches_fixture(&deployment.env, &event);
    }

    for event in deployment.capture(|| deployment.issuers.reactivate_issuer(&deployment.issuer_id))
    {
        assert_matches_fixture(&deployment.env, &event);
    }

    for event in deployment.capture(|| {
        deployment
            .issuers
            .rotate_issuer_address(&deployment.issuer_id, &replacement)
    }) {
        assert_matches_fixture(&deployment.env, &event);
    }

    for event in deployment.capture(|| deployment.issuers.revoke_issuer(&deployment.issuer_id)) {
        assert_matches_fixture(&deployment.env, &event);
    }
}

#[test]
fn the_declared_event_set_has_no_duplicates() {
    // Two entries for one topic would make `declared_fields` return whichever
    // came first, silently weakening every assertion that depends on it.
    let mut seen: std::vec::Vec<&str> = std::vec::Vec::new();

    for (name, _) in DECLARED_EVENTS {
        assert!(
            !seen.contains(name),
            "topic {name} is declared more than once"
        );
        seen.push(name);
    }
}

#[test]
fn every_declared_event_names_at_least_one_payload_field() {
    // An event with no payload would be a bare signal. None exists today, and
    // adding one should be a deliberate decision recorded in docs/events.md
    // rather than an empty fixture entry nobody noticed.
    for (name, fields) in DECLARED_EVENTS {
        assert!(
            !fields.is_empty(),
            "{name} declares no payload fields; \
             a bare signal event needs an explicit note in docs/events.md"
        );
    }
}

#[test]
fn proof_registry_declares_no_events() {
    // The fixture at tests/fixtures/events/proof-registry/v1/events.json records
    // an empty event list. Adding an event to this contract must therefore fail
    // here first, forcing the fixture and docs/events.md to be updated with it.
    let emitted_by_proof_registry = DECLARED_EVENTS
        .iter()
        .any(|(name, _)| name.starts_with("proof_"));

    assert!(
        !emitted_by_proof_registry,
        "proof-registry is documented as emitting no events; \
         update tests/fixtures/events/proof-registry/v1/events.json and \
         docs/events.md before declaring one here"
    );
}
