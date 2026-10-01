//! Actual identifier and secret-codec refusal boundaries on native and wasm.

use cpsd::rand::{SeedableRng, rngs::StdRng};
use cpsd::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn identifiers_preserve_exact_scope_and_refuse_log_control_characters() {
    for invalid in ["", "line\nbreak", "has space", "é"] {
        let key_error = KeyId::new(invalid).unwrap_err();
        let gate_error = GateId::new(invalid).unwrap_err();
        assert_eq!(key_error.to_string(), "invalid key id");
        assert_eq!(gate_error.to_string(), "invalid gate id");
    }
    assert!(KeyId::new("x".repeat(MAX_ID_LEN + 1)).is_err());
    assert!(GateId::new("x".repeat(MAX_ID_LEN + 1)).is_err());
    assert!(GateId::new("PHONE").is_err());
    let key = KeyId::new("X".repeat(MAX_ID_LEN)).unwrap();
    let gate = GateId::new("a0._-".repeat(12)).unwrap();
    assert_eq!(key.to_string(), key.as_str());
    assert_eq!(format!("{key:?}"), format!("KeyId({key})"));
    assert_eq!(gate.to_string(), gate.as_str());
    assert_eq!(format!("{gate:?}"), format!("GateId({gate})"));

    assert!(CommunityId::new([]).is_err());
    assert!(CommunityId::new(vec![0; MAX_COMMUNITY_ID_LEN + 1]).is_err());
    let binary = CommunityId::new(vec![0xff; MAX_COMMUNITY_ID_LEN]).unwrap();
    assert_eq!(binary.as_bytes(), &[0xff; MAX_COMMUNITY_ID_LEN]);
    assert_eq!(format!("{binary:?}"), format!("CommunityId({})", "ff".repeat(MAX_COMMUNITY_ID_LEN)));
    let text = CommunityId::new(b"line\nbreak").unwrap();
    assert!(!format!("{text:?}").contains('\n'));
    assert_ne!(text, CommunityId::new(b"line\\nbreak").unwrap());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn secret_restore_refuses_zero_scalar_and_debug_never_exports_it() {
    let mut rng = StdRng::seed_from_u64(52);
    let secret = HolderSecret::generate(&mut rng);
    assert_eq!(format!("{secret:?}"), "HolderSecret(<redacted>)");
    let bytes = secret.to_bytes();
    let restored = HolderSecret::from_bytes(&bytes).unwrap();
    assert_eq!(secret.issuer_tag(), restored.issuer_tag());
    let scope = CommunityId::new(b"scope").unwrap();
    assert_eq!(secret.pseudonym(&scope), restored.pseudonym(&scope));

    // The documented v2 holder wire ends with one canonical 32-byte Fr scalar.
    let mut zero = bytes.to_vec();
    let start = zero.len() - 32;
    zero[start..].fill(0);
    assert!(matches!(HolderSecret::from_bytes(&zero), Err(Error::InvalidKey)));
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(HolderSecret::from_bytes(&trailing).is_err());
    let context = AuthenticatedIssuance::new([11; 32], [12; 32]);
    assert_eq!(format!("{context:?}"), "AuthenticatedIssuance(<redacted>)");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn authentication_refuses_oversized_envelopes_before_decoding() {
    let signer = csgn::Signer::new(
        "cmty:fixture",
        csgn::SecretKey::from_seed(&mut [4; 32]),
        0,
        TIME_LIMIT,
    )
    .unwrap();
    let context = AuthenticatedCommunity::from_authenticated_origin(
        CommunityId::new(b"scope").unwrap(),
        signer.key_ring().clone(),
    );
    let oversized = vec![0; 256 * 1024 + 1];
    assert!(matches!(
        context.authenticate(&oversized, 100),
        Err(Error::InvalidPresentationRequest)
    ));
}
