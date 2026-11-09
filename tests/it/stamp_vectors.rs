//! Deterministic known-answer vectors of the confirmation stamp, executed
//! natively and in Chrome. A changed hash means a changed wire format, message
//! layout, generator derivation, transcript or upstream proof encoding; update
//! a value only together with a written reason in the commit.

use blake2::{Blake2b512, Digest};
use cpsd::*;
use rand::{SeedableRng, rngs::StdRng};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

fn receipt(name: &str, bytes: &[u8]) -> String {
    let hash = Blake2b512::digest(bytes);
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::console_log!("CPSD_VECTOR {name} {hex}");
    #[cfg(not(target_arch = "wasm32"))]
    println!("CPSD_VECTOR {name} {hex}");
    hex
}

const KEY: &str = concat!(
    "8edba8574dd7eab4c6c0107dfe0ac6e4b49bccf7c1baf00d9f34a7964cc58f96",
    "facd3600f023e61ba2c1ad602da0adc0ee65cffd50ab20ed4691b34616457571"
);
const ISSUANCE: &str = concat!(
    "3123fb4f6c9feab0e73ea9e4b46516a7b5eb7db10ee820cdb980fda683981621",
    "8bf98dcdb741557ec885560e12b470a8cad8906c0a8af38c7100acd08f344ce2"
);
const CONFIRMATION: &str = concat!(
    "8743bf962d98d76e658f94f897fadbc3c9075694d8fe2a820193971673149858",
    "3e70adc4fd89c8596a38b8a05f47c88d8e8fe4e9a7f86750aba5a013e5bb51d4"
);
const BLIND: &str = concat!(
    "e20548fa910653f4d9372720e099f99d6296652dbb3275eff2e80300a1e680db",
    "7f7ae351bf8ae6fb4903bb6ac289404222969822c42d62f58d7e1fdba8f83344"
);
const PRESENTATION: &str = concat!(
    "1b6627d37b2b441a1db0c31d7f8eff76b3ba287d9c6ff50c8f2b8976cde4998d",
    "903832d7fc4f2c35c9b8eaef641c5364ae48ebdce3075994acd1e6eb00298b9f"
);

/// 2026-10-15T00:03:20Z, in the rulebook-default one-day cohort: the stamp
/// expires at the end of the next UTC day, 2026-10-17T00:00:00Z.
const NOW: Timestamp = 1_792_022_600;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn stamp_v1_known_answers() {
    let mut rng = StdRng::seed_from_u64(0x5747_0001);
    let params = StampParams::new(86_400).unwrap();
    let key =
        StampIssuerKey::generate(&mut rng, KeyId::new("stamp-vectors").unwrap(), &params).unwrap();
    let mut holder = OpaqueHolder::from_seed(&mut [0x5a; 32]);
    let scope = StampScope::new(
        CommunityId::new(b"community-a").unwrap(),
        CommunityFingerprint::from_bytes([0x11; 32]),
    );
    let action = StampAction::new(
        ActionKind::new("lineage.pair").unwrap(),
        PayloadDigest::from_bytes([0x22; 32]),
        StampSalt::from_bytes([0x33; 32]),
    );
    let nonce = IssuanceChallenge::from_bytes([0x44; 32]);
    let request = holder
        .begin_stamp(
            &mut rng,
            key.public_key(),
            &nonce,
            &[(scope.clone(), action.clone())],
            NOW,
        )
        .unwrap();
    let blind = key.issue_blind(&mut rng, &request, &nonce, 3, NOW).unwrap();
    holder.finish_stamp(&blind, 3, NOW).unwrap();
    let presentation = holder
        .present_stamp(&mut rng, &scope, &action, NOW)
        .unwrap();

    let key_bytes = key.public_key().to_bytes();
    let request_bytes = request.to_bytes();
    let blind_bytes = blind.to_bytes();
    let presentation_bytes = presentation.to_bytes();
    for bytes in [
        &key_bytes,
        &request_bytes,
        &blind_bytes,
        &presentation_bytes,
    ] {
        assert_eq!(&bytes[..5], b"cpsd\x04", "stamp envelope version");
    }
    assert_eq!(blind.expires(), 1_792_022_400 + 2 * 86_400);
    assert_eq!(
        (key_bytes.len(), request_bytes.len(), blind_bytes.len()),
        (
            6 + 4 + 13 + 8 + 4 + 96,
            6 + 4 + 13 + 5 * 4 + 3 * 48 + (8 + 18 * 32) + 80,
            6 + 4 + 13 + 16 + 4 + 112
        )
    );
    assert_eq!(
        presentation_bytes.len(),
        6 + 4 + 13 + 16 + 2 + 48 + 4 + 890 + 4 + 80
    );
    let receipts = [
        receipt("stamp-key", &key_bytes),
        receipt("stamp-issuance", &request_bytes),
        receipt(
            "stamp-confirmation",
            &request.confirmation_challenge(&nonce),
        ),
        receipt("stamp-blind", &blind_bytes),
        receipt("stamp-presentation", &presentation_bytes),
    ];
    assert_eq!(receipts, [KEY, ISSUANCE, CONFIRMATION, BLIND, PRESENTATION]);

    let verified = verify_stamp(
        &[StampPublicKey::from_bytes(&key_bytes).unwrap()],
        &params,
        &scope,
        3,
        &action,
        &StampPresentation::from_bytes(&presentation_bytes).unwrap(),
        NOW,
    )
    .unwrap();
    assert_eq!(verified.pseudonym(), &holder.pseudonym(scope.community()));
    assert_eq!(
        verified.digest(),
        &action.digest(scope.fingerprint(), &holder.pseudonym(scope.community()))
    );
}
