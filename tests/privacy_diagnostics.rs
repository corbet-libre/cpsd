//! Real issuance objects keep private openings out of formatted diagnostics.

use cpsd::rand::{SeedableRng, rngs::StdRng};
use cpsd::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn real_issuance_diagnostics_omit_secret_openings_and_signature_material() {
    let mut rng = StdRng::seed_from_u64(81);
    let gate = GateId::new("phone").unwrap();
    let id = KeyId::new("diagnostics").unwrap();
    let issuer = IssuerKey::generate(&mut rng, id.clone(), vec![gate.clone()]).unwrap();
    let secret = HolderSecret::generate(&mut rng);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let (request, pending) =
        request_issue(&mut rng, &secret, issuer.public_key(), &challenge).unwrap();
    let mut invalid_key = issuer.to_secret_bytes().to_vec();
    let scalar_start = invalid_key.len() - 32;
    invalid_key[scalar_start..].fill(0);
    assert!(matches!(
        IssuerKey::from_secret_bytes(&invalid_key),
        Err(Error::InvalidKey)
    ));
    let mut invalid_opening = pending.to_bytes().to_vec();
    assert_eq!(&invalid_opening[6..10], &32_u32.to_be_bytes());
    invalid_opening[10..42].fill(0);
    assert!(matches!(
        PendingIssuance::from_bytes(&invalid_opening),
        Err(Error::InvalidKey)
    ));
    let public = IssuerPublicKey::from_bytes(&issuer.public_key().to_bytes()).unwrap();
    assert_eq!(&public, issuer.public_key());
    assert_eq!(public.key_id(), &id);
    assert_eq!(public.gates(), std::slice::from_ref(&gate));
    let attributes = PassportAttributes::new(1500, 7).with_gate(gate, 1500);
    let blind = issuer
        .issue_blind(&mut rng, &request, &challenge, &attributes)
        .unwrap();
    assert_eq!(blind.key_id(), &id);
    assert_eq!(blind.attributes(), &attributes);
    assert_ne!(blind.revocation_handle(), [0; 32]);
    let pending_debug = format!("{pending:?}");
    let passport = pending.finish(&blind).unwrap();
    assert_eq!(passport.key_id(), &id);
    assert_eq!(passport.issuer(), &public);
    assert_eq!(passport.attributes(), &attributes);
    let restored = Passport::from_bytes(&passport.to_bytes()).unwrap();
    let community = CommunityId::new(b"public-community").unwrap();
    assert_eq!(
        restored.pseudonym(&community),
        passport.pseudonym(&community)
    );
    let mut invalid_passport = passport.to_bytes().to_vec();
    assert_eq!(&invalid_passport[6..10], &32_u32.to_be_bytes());
    invalid_passport[10..42].fill(0);
    assert!(matches!(
        Passport::from_bytes(&invalid_passport),
        Err(Error::InvalidKey)
    ));
    for debug in [
        format!("{issuer:?}"),
        format!("{public:?}"),
        format!("{request:?}"),
        format!("{blind:?}"),
        format!("{passport:?}"),
        pending_debug,
    ] {
        for private_field in ["secret", "blinding", "signature", "revocation", "proof"] {
            assert!(!debug.contains(private_field), "{private_field}");
        }
        assert!(debug.contains(id.as_str()));
    }
    let nonce = IssuanceChallenge::from_bytes(challenge.to_bytes());
    assert_eq!(nonce, challenge);
    assert!(format!("{nonce:?}").starts_with("IssuanceChallenge("));
    let pseudonym = passport.pseudonym(&community);
    assert_eq!(
        format!("{pseudonym:?}"),
        format!("Pseudonym({})", pseudonym.to_hex())
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn public_errors_reveal_only_declared_identifiers_and_coarse_failure_reasons() {
    let gate = GateId::new("public-gate").unwrap();
    for error in [
        Error::InvalidIdentifier("key id"),
        Error::InvalidTimestamp,
        Error::InvalidGateCatalogue,
        Error::TooManyGates,
        Error::UnknownGate(gate.clone()),
        Error::KeyMismatch,
        Error::UnknownKey,
        Error::DuplicateKeyId,
        Error::InvalidKey,
        Error::InvalidIssuanceRequest,
        Error::IssuancePending,
        Error::NoPendingIssuance,
        Error::PassportUnavailable,
        Error::InvalidSignature,
        Error::PassportExpired,
        Error::WrongEpoch,
        Error::WrongExpiryCohort,
        Error::GateMissing(gate.clone()),
        Error::GateExpired(gate),
        Error::InvalidProof,
        Error::ProofGeneration,
        Error::Storage,
        Error::StorageCapacity,
        Error::ChallengeConflict,
        Error::InvalidChallenge,
        Error::InvalidPresentationRequest,
        Error::IssuerTagMismatch,
        Error::IssuerTagClaimed,
        Error::Decode("passport"),
    ] {
        let text = error.to_string();
        assert!(!text.is_empty());
        assert!(text.len() <= 100);
        assert!(!text.chars().any(char::is_control));
        assert!(std::error::Error::source(&error).is_none());
    }
}
