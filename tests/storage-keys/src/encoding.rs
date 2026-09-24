//! Key encoding and collision safety.
//!
//! A `#[contracttype]` enum encodes as a vector: the variant name as a
//! `Symbol` first, then the payload fields in declaration order. These tests
//! confirm that the keys reconstructed in `support` are byte-identical to the
//! ones the contracts write, and then use that encoding to show what cannot
//! collide.
//!
//! The comparisons are made on serialized XDR bytes rather than on host value
//! identity, because the ledger stores bytes and a compatibility break shows up
//! there first.

use super::support::{
    active_issuer_count_key, address_issuer_key, admin_key, bytes32, config_version_key,
    contract_version_key, deployment, encoded, encoded_keys_in, issuer_epoch_key, issuer_key,
    issuer_registry_key, max_active_issuers_key, paused_key, proof_key, protocol_config_key,
    reactivation_cooldown_key, schema_version_key,
};
use earnproof_shared::StorageClass;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{symbol_short, Address, BytesN, Env, IntoVal, Symbol, Val, Vec as SorobanVec};

fn sorted(mut keys: std::vec::Vec<std::vec::Vec<u8>>) -> std::vec::Vec<std::vec::Vec<u8>> {
    keys.sort();
    keys
}

// ---------------------------------------------------------------------------
// The reconstructed keys are the real keys
// ---------------------------------------------------------------------------

#[test]
fn reconstructed_keys_match_the_keys_the_contracts_write() {
    let deployment = deployment();
    let env = &deployment.env;

    assert_eq!(
        encoded_keys_in(env, &deployment.config_id, StorageClass::Instance),
        sorted(std::vec![
            encoded(env, admin_key()),
            encoded(env, paused_key()),
            encoded(env, config_version_key(env)),
            encoded(env, contract_version_key(env)),
        ]),
        "protocol-config instance keys"
    );

    assert_eq!(
        encoded_keys_in(env, &deployment.config_id, StorageClass::Persistent),
        sorted(std::vec![encoded(env, schema_version_key(env, 1))]),
        "protocol-config persistent keys"
    );

    assert_eq!(
        encoded_keys_in(env, &deployment.issuers_id, StorageClass::Instance),
        sorted(std::vec![
            encoded(env, admin_key()),
            encoded(env, contract_version_key(env)),
            encoded(env, active_issuer_count_key(env)),
            encoded(env, issuer_epoch_key(env)),
            encoded(env, max_active_issuers_key(env)),
            encoded(env, reactivation_cooldown_key(env)),
        ]),
        "issuer-registry instance keys"
    );

    assert_eq!(
        encoded_keys_in(env, &deployment.issuers_id, StorageClass::Persistent),
        sorted(std::vec![
            encoded(env, issuer_key(&deployment.issuer_id)),
            encoded(env, address_issuer_key(env, &deployment.issuer)),
        ]),
        "issuer-registry persistent keys"
    );

    assert_eq!(
        encoded_keys_in(env, &deployment.proofs_id, StorageClass::Instance),
        sorted(std::vec![
            encoded(env, admin_key()),
            encoded(env, contract_version_key(env)),
            encoded(env, issuer_registry_key(env)),
            encoded(env, protocol_config_key(env)),
        ]),
        "proof-registry instance keys"
    );

    assert_eq!(
        encoded_keys_in(env, &deployment.proofs_id, StorageClass::Persistent),
        sorted(std::vec![encoded(env, proof_key(&deployment.proof_id))]),
        "proof-registry persistent keys"
    );
}

#[test]
fn keys_encode_as_a_discriminant_followed_by_the_payload() {
    let env = Env::default();
    let identifier = bytes32(&env, 3);

    let singleton: SorobanVec<Val> = admin_key().into_val(&env);
    assert_eq!(singleton.len(), 1);
    let discriminant: Symbol = singleton.get(0).unwrap().into_val(&env);
    assert_eq!(discriminant, symbol_short!("Admin"));

    let composite: SorobanVec<Val> = proof_key(&identifier).into_val(&env);
    assert_eq!(composite.len(), 2);
    let discriminant: Symbol = composite.get(0).unwrap().into_val(&env);
    assert_eq!(discriminant, symbol_short!("Proof"));
    let payload: BytesN<32> = composite.get(1).unwrap().into_val(&env);
    assert_eq!(payload, identifier);
}

#[test]
fn key_encoding_is_deterministic() {
    let env = Env::default();
    let identifier = bytes32(&env, 9);

    assert_eq!(
        encoded(&env, proof_key(&identifier)),
        encoded(&env, proof_key(&identifier))
    );

    // A second environment must produce the same bytes: nothing in the
    // encoding depends on host object handles or allocation order.
    let other = Env::default();
    assert_eq!(
        encoded(&env, proof_key(&identifier)),
        encoded(&other, proof_key(&bytes32(&other, 9)))
    );
}

// ---------------------------------------------------------------------------
// Collision safety
// ---------------------------------------------------------------------------

#[test]
fn no_two_distinct_keys_share_an_encoding() {
    let env = Env::default();
    let first = Address::generate(&env);
    let second = Address::generate(&env);

    let mut keys: std::vec::Vec<(std::string::String, std::vec::Vec<u8>)> = std::vec![
        ("Admin".into(), encoded(&env, admin_key())),
        ("Paused".into(), encoded(&env, paused_key())),
        (
            "ConfigVersion".into(),
            encoded(&env, config_version_key(&env))
        ),
        (
            "ContractVersion".into(),
            encoded(&env, contract_version_key(&env))
        ),
        (
            "IssuerRegistry".into(),
            encoded(&env, issuer_registry_key(&env))
        ),
        (
            "ProtocolConfig".into(),
            encoded(&env, protocol_config_key(&env))
        ),
    ];
    for version in [0_u32, 1, 2, u32::MAX - 1, u32::MAX] {
        keys.push((
            std::format!("SchemaVersion({version})"),
            encoded(&env, schema_version_key(&env, version)),
        ));
    }
    for value in [0_u8, 1, 2, 254, 255] {
        let identifier = bytes32(&env, value);
        keys.push((
            std::format!("Issuer({value})"),
            encoded(&env, issuer_key(&identifier)),
        ));
        keys.push((
            std::format!("Proof({value})"),
            encoded(&env, proof_key(&identifier)),
        ));
    }
    for (index, address) in [&first, &second].into_iter().enumerate() {
        keys.push((
            std::format!("AddressIssuer({index})"),
            encoded(&env, address_issuer_key(&env, address)),
        ));
    }

    let total = keys.len();
    let mut seen: std::collections::BTreeMap<std::vec::Vec<u8>, std::string::String> =
        std::collections::BTreeMap::new();
    for (label, bytes) in keys {
        if let Some(previous) = seen.insert(bytes, label.clone()) {
            panic!("{previous} and {label} encode identically");
        }
    }
    assert_eq!(seen.len(), total);
}

#[test]
fn the_same_payload_under_two_namespaces_produces_two_keys() {
    let env = Env::default();
    let identifier = bytes32(&env, 7);

    // `Issuer(h)` and `Proof(h)` carry the same 32 bytes. They are different
    // keys, and they live in different contracts besides.
    assert_ne!(
        encoded(&env, issuer_key(&identifier)),
        encoded(&env, proof_key(&identifier))
    );
}

#[test]
fn adjacent_payloads_produce_distinct_keys() {
    let env = Env::default();

    // Identifiers that differ in a single trailing bit.
    let low = BytesN::from_array(&env, &[0_u8; 32]);
    let mut trailing = [0_u8; 32];
    trailing[31] = 1;
    let trailing = BytesN::from_array(&env, &trailing);
    assert_ne!(
        encoded(&env, proof_key(&low)),
        encoded(&env, proof_key(&trailing))
    );

    // A leading-bit difference, which a truncating scheme would lose.
    let mut leading = [0_u8; 32];
    leading[0] = 1;
    let leading = BytesN::from_array(&env, &leading);
    assert_ne!(
        encoded(&env, proof_key(&low)),
        encoded(&env, proof_key(&leading))
    );
    assert_ne!(
        encoded(&env, proof_key(&leading)),
        encoded(&env, proof_key(&trailing))
    );

    // Consecutive schema versions.
    for version in [0_u32, 1, 2, 100] {
        assert_ne!(
            encoded(&env, schema_version_key(&env, version)),
            encoded(&env, schema_version_key(&env, version + 1))
        );
    }
}

#[test]
fn composite_identifiers_cannot_collide_through_concatenation() {
    let env = Env::default();

    // The ambiguity a naive scheme has: a key built by concatenating the
    // namespace text with the payload text cannot tell "Ab" + "cd" apart from
    // "Abcd" + nothing. Both would reduce to the same string.
    let split: (Symbol, Symbol) = (Symbol::new(&env, "Ab"), Symbol::new(&env, "cd"));
    let joined: (Symbol,) = (Symbol::new(&env, "Abcd"),);
    assert_ne!(encoded(&env, split), encoded(&env, joined));

    // The same shape with namespaces this deployment actually uses: a
    // one-field key and a zero-field key whose names share a prefix.
    let composite = (symbol_short!("Issuer"), Symbol::new(&env, "Registry"));
    assert_ne!(
        encoded(&env, composite),
        encoded(&env, issuer_registry_key(&env))
    );

    // Arity alone keeps two keys apart even when the discriminant matches,
    // because the encoded vectors have different lengths.
    let unit = (symbol_short!("Proof"),);
    assert_ne!(
        encoded(&env, unit),
        encoded(&env, proof_key(&bytes32(&env, 0)))
    );
}

#[test]
fn identical_namespaces_in_different_contracts_address_different_entries() {
    let deployment = deployment();
    let env = &deployment.env;
    let admin = encoded(env, admin_key());

    // All three contracts store an `Admin` key under the same encoding.
    for contract in [
        &deployment.config_id,
        &deployment.issuers_id,
        &deployment.proofs_id,
    ] {
        assert!(encoded_keys_in(env, contract, StorageClass::Instance).contains(&admin));
    }

    // Sharing that namespace has not pulled one contract's instance keys into
    // another: the issuer registry still holds only its fixed instance keys.
    assert_eq!(
        encoded_keys_in(env, &deployment.issuers_id, StorageClass::Instance).len(),
        6
    );
}

#[test]
fn a_key_written_by_one_contract_is_invisible_to_another() {
    let deployment = deployment();
    let env = &deployment.env;
    let proof = proof_key(&deployment.proof_id);

    let in_proof_registry = env.as_contract(&deployment.proofs_id, || {
        env.storage().persistent().has(&proof)
    });
    let in_issuer_registry = env.as_contract(&deployment.issuers_id, || {
        env.storage().persistent().has(&proof)
    });

    assert!(in_proof_registry);
    assert!(!in_issuer_registry);
}
