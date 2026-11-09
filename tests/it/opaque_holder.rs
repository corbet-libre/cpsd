//! Real nonexporting holder issuance, restoration and authenticated presentation.

use cpsd::rand::{SeedableRng, rngs::StdRng};
use cpsd::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn deterministic_identity_has_no_dependency_on_issuance_randomness() {
    let community = CommunityId::new(b"community-a").unwrap();
    let other = CommunityId::new(b"community-b").unwrap();
    let mut seed = [7; 32];
    let first = OpaqueHolder::from_seed(&mut seed);
    assert_eq!(seed, [0; 32]);
    let restored = OpaqueHolder::from_seed(&mut [7; 32]);
    let different = OpaqueHolder::from_seed(&mut [8; 32]);
    assert_eq!(first.pseudonym(&community), restored.pseudonym(&community));
    assert_eq!(first.issuer_tag(), restored.issuer_tag());
    assert_ne!(first.pseudonym(&community), first.pseudonym(&other));
    assert_ne!(first.pseudonym(&community), different.pseudonym(&community));
    assert!(first.attributes().is_none());
    assert_eq!(
        first.pseudonym(&community).to_hex(),
        "97322b8893bb653c820feb6b9915315da5e5f7716e15ad1ac521b18643b695dcb3a24b42ae422847f63d03efb782af60"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn opaque_issuance_and_refused_renewal_preserve_the_verified_identity() {
    let mut rng = StdRng::seed_from_u64(91);
    let gate = GateId::new("phone").unwrap();
    let issuer =
        IssuerKey::generate(&mut rng, KeyId::new("issuer").unwrap(), vec![gate.clone()]).unwrap();
    let other =
        IssuerKey::generate(&mut rng, KeyId::new("other").unwrap(), vec![gate.clone()]).unwrap();
    let mut holder =
        OpaqueHolder::from_seed_and_sealing_key(&mut [7; 32], &mut [8; 32], b"wallet-a").unwrap();
    let community = CommunityId::new(b"community-a").unwrap();
    let nym = holder.pseudonym(&community);
    let attributes = PassportAttributes::new(2000, 7).with_gate(gate.clone(), 2000);
    let request =
        PresentationRequest::for_epoch(&mut rng, community.clone(), 7, [gate], 1000, 2000).unwrap();
    let mut signer = csgn::Signer::new(
        "cmty:test",
        csgn::SecretKey::from_seed(&mut [4; 32]),
        0,
        TIME_LIMIT,
    )
    .unwrap();
    let signed = signer
        .sign(
            csgn::Kind::Credential,
            &request.to_bytes(),
            0,
            request.now() + 1,
        )
        .unwrap();
    let expected = AuthenticatedCommunity::from_authenticated_origin(
        community.clone(),
        signer.key_ring().clone(),
    );
    assert!(matches!(
        holder.present(&mut rng, &expected, &signed, 1000),
        Err(Error::PassportUnavailable)
    ));

    let challenge = IssuanceChallenge::generate(&mut rng);
    let issuance = holder
        .begin_issuance(&mut rng, issuer.public_key(), &challenge)
        .unwrap();
    assert!(matches!(
        holder.begin_issuance(&mut rng, issuer.public_key(), &challenge),
        Err(Error::IssuancePending)
    ));
    let issuance = IssuanceRequest::from_bytes(&issuance.to_bytes()).unwrap();
    let blind = issuer
        .issue_blind(&mut rng, &issuance, &challenge, &attributes)
        .unwrap();
    // A real pending blinding survives a page/process restart without leaving CPSD.
    let sealed = holder.seal(&mut rng).unwrap();
    let reopened =
        OpaqueHolder::from_seed_and_sealing_key(&mut [7; 32], &mut [8; 32], b"wallet-a").unwrap();
    holder = reopened
        .restored(&SealedHolder::from_bytes(sealed.as_bytes()).unwrap())
        .unwrap();
    holder.finish_issuance(&blind).unwrap();
    assert_eq!(holder.attributes(), Some(&attributes));
    assert_eq!(
        holder.finish_issuance(&blind),
        Err(Error::NoPendingIssuance)
    );
    // Restoring an installed credential rechecks the original BBS+ signature.
    let installed = holder.seal(&mut rng).unwrap();
    holder = reopened.restored(&installed).unwrap();
    let proof = holder.present(&mut rng, &expected, &signed, 1000).unwrap();
    assert_eq!(
        verify(&mut rng, &[issuer.public_key().clone()], &request, &proof).unwrap(),
        nym
    );
    assert!(holder.present(&mut rng, &expected, &signed, 1200).is_err());
    let wrong_scope = AuthenticatedCommunity::from_authenticated_origin(
        CommunityId::new(b"other-community").unwrap(),
        signer.key_ring().clone(),
    );
    assert!(
        holder
            .present(&mut rng, &wrong_scope, &signed, 1000)
            .is_err()
    );

    // A response signed for another issuer cannot replace a verified passport.
    let other_request = holder
        .begin_issuance(&mut rng, other.public_key(), &challenge)
        .unwrap();
    let wrong_blind = other
        .issue_blind(&mut rng, &other_request, &challenge, &attributes)
        .unwrap();
    holder.cancel_issuance();
    holder.cancel_issuance();
    holder
        .begin_issuance(&mut rng, issuer.public_key(), &challenge)
        .unwrap();
    // Renewal persists both the old credential and the new private opening.
    holder = reopened.restored(&holder.seal(&mut rng).unwrap()).unwrap();
    assert_eq!(
        holder.finish_issuance(&wrong_blind),
        Err(Error::KeyMismatch)
    );
    assert_eq!(holder.attributes(), Some(&attributes));
    assert_eq!(holder.pseudonym(&community), nym);
    let proof = holder.present(&mut rng, &expected, &signed, 1000).unwrap();
    assert_eq!(
        verify(&mut rng, &[issuer.public_key().clone()], &request, &proof).unwrap(),
        nym
    );
    for error in [
        Error::IssuancePending,
        Error::NoPendingIssuance,
        Error::PassportUnavailable,
        Error::HolderSealingUnavailable,
        Error::InvalidSealedHolder,
    ] {
        assert!(!error.to_string().is_empty());
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn sealed_holder_refuses_key_context_identity_and_ciphertext_substitution() {
    let mut rng = StdRng::seed_from_u64(104);
    let mut seed = [7; 32];
    let mut key = [8; 32];
    let holder = OpaqueHolder::from_seed_and_sealing_key(&mut seed, &mut key, b"wallet-a").unwrap();
    assert_eq!(seed, [0; 32]);
    assert_eq!(key, [0; 32]);
    let first = holder.seal(&mut rng).unwrap();
    let second = holder.seal(&mut rng).unwrap();
    assert_ne!(first.as_bytes(), second.as_bytes());
    assert_eq!(
        holder.restored(&first).unwrap().issuer_tag(),
        holder.issuer_tag()
    );
    for (seed, key, context) in [
        (7, 9, b"wallet-a"),
        (7, 8, b"wallet-b"),
        (9, 8, b"wallet-a"),
    ] {
        let wrong =
            OpaqueHolder::from_seed_and_sealing_key(&mut [seed; 32], &mut [key; 32], context)
                .unwrap();
        assert!(wrong.restored(&first).is_err());
    }
    for index in 0..first.as_bytes().len() {
        let mut bytes = first.as_bytes().to_vec();
        bytes[index] ^= 1;
        if let Ok(changed) = SealedHolder::from_bytes(&bytes) {
            assert!(holder.restored(&changed).is_err());
        }
    }
    for length in 0..first.as_bytes().len() {
        assert!(SealedHolder::from_bytes(&first.as_bytes()[..length]).is_err());
    }
    let mut appended = first.as_bytes().to_vec();
    appended.push(0);
    assert!(SealedHolder::from_bytes(&appended).is_err());
    assert!(SealedHolder::from_bytes(&vec![0; 256 * 1024 + 1]).is_err());
    let unbound = OpaqueHolder::from_seed(&mut [7; 32]);
    assert!(matches!(
        unbound.seal(&mut rng),
        Err(Error::HolderSealingUnavailable)
    ));
    assert!(matches!(
        unbound.restored(&first),
        Err(Error::HolderSealingUnavailable)
    ));
    for context in [vec![], vec![1; 4097]] {
        let mut seed = [7; 32];
        let mut key = [8; 32];
        assert!(OpaqueHolder::from_seed_and_sealing_key(&mut seed, &mut key, &context).is_err());
        assert_eq!(seed, [0; 32]);
        assert_eq!(key, [0; 32]);
    }
    assert!(holder.attributes().is_none());
}
