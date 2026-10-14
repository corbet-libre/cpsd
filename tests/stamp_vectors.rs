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
    "5a9037786b9871e47656b02c1cb5c69c4eac144c3c2332a1ec4c4922938d4806",
    "ce8444c491dd1fce88c9622998d6814eb22cec42cecc5a11d33b54447573c45c"
);
const ISSUANCE: &str = concat!(
    "94eea2c20f66621744ea5cbb2de2ae267ac4d5eb8172813aa6d0b3772318e5a0",
    "6187110a86f75d53812ee93c9b410d2068b337adf61fab91b8d88b6a611cd967"
);
const BLIND: &str = concat!(
    "6a7a2dadef55d74022a0f188adf9300c6180cfaf6dd34aa5b8a158a4d0f23aa2",
    "1fc6cb1f39710a57680e74688e20ffbbc28ec292ceac9c26ca69e23d70e78fec"
);
const PRESENTATION: &str = concat!(
    "c895434923e9fb8d19f1252181745179a035ca6bde95472da7f27eb397e5db15",
    "e1c8d381f8704830f7b42aef0492cbdbec8648fe3aa352176dc47c523a33551e"
);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn stamp_v1_known_answers() {
    let mut rng = StdRng::seed_from_u64(0x5747_0001);
    let key =
        StampIssuerKey::generate(&mut rng, KeyId::new("stamp-vectors").unwrap(), 600).unwrap();
    let secret = HolderSecret::generate(&mut rng);
    let scope = StampScope::new(
        CommunityId::new(b"community-a").unwrap(),
        CommunityFingerprint::from_bytes([0x11; 32]),
    );
    let action = StampAction::new(
        ActionKind::new("lineage.pair").unwrap(),
        PayloadDigest::from_bytes([0x22; 32]),
        StampSalt::from_bytes([0x33; 32]),
    );
    let digest = action.digest(scope.fingerprint(), &secret.pseudonym(scope.community()));
    let nonce = IssuanceChallenge::from_bytes([0x44; 32]);
    let (request, pending) =
        request_stamp(&mut rng, &secret, key.public_key(), &nonce, &[digest]).unwrap();
    let blind = key
        .issue_blind(&mut rng, &request, &nonce, 3, 1_000_200)
        .unwrap();
    let stamp = pending.finish(&blind).unwrap();
    let presentation = stamp.present(&mut rng, &scope, &action).unwrap();

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
    assert_eq!(blind.expires(), 1_000_800);
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
        receipt("stamp-blind", &blind_bytes),
        receipt("stamp-presentation", &presentation_bytes),
    ];
    assert_eq!(receipts, [KEY, ISSUANCE, BLIND, PRESENTATION]);

    let verified = verify_stamp(
        &[StampPublicKey::from_bytes(&key_bytes).unwrap()],
        &scope,
        3,
        &action,
        &StampPresentation::from_bytes(&presentation_bytes).unwrap(),
        1_000_200,
    )
    .unwrap();
    assert_eq!(verified.pseudonym(), &secret.pseudonym(scope.community()));
    assert_eq!(verified.digest(), &digest);
}
