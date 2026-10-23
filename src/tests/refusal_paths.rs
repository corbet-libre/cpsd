//! Hostile transport values exercise the original decoders and cryptography.

use super::*;
use crate::wire::{Kind, Reader, Writer};
use ark_bls12_381::{G1Affine, G2Affine};
use ark_ec::AffineRepr;

#[test]
fn issuance_refuses_excess_attributes_before_signing() {
    let mut rng = rng();
    let issuer = key(&mut rng, "issuer");
    let secret = HolderSecret::generate(&mut rng);
    let nonce = IssuanceChallenge::generate(&mut rng);
    let (request, pending) = request_issue(&mut rng, &secret, issuer.public_key(), &nonce).unwrap();
    let mut excessive = attrs();
    for index in 0..MAX_GATES {
        excessive = excessive.with_gate(GateId::new(format!("extra-{index}")).unwrap(), 1500);
    }
    assert_eq!(
        issuer
            .issue_blind(&mut rng, &request, &nonce, &excessive)
            .err(),
        Some(Error::TooManyGates)
    );
    let blind = issuer
        .issue_blind(&mut rng, &request, &nonce, &attrs())
        .unwrap();
    let passport = pending.finish(&blind).unwrap();
    assert_eq!(
        passport.pseudonym(&community()),
        secret.pseudonym(&community())
    );
}

#[test]
fn transport_gate_lists_reject_duplicates_descending_order_and_excess_count() {
    for gates in [["phone", "phone"], ["phone", "human"]] {
        let mut blind = Writer::new(Kind::BlindPassport);
        blind.key_id(&KeyId::new("issuer").unwrap());
        blind.u64(7);
        blind.u64(2000);
        blind.u16(2);
        for name in gates {
            blind.gate(&GateId::new(name).unwrap());
            blind.u64(1500);
        }
        assert_eq!(
            BlindPassport::from_bytes(&blind.finish_public()).err(),
            Some(Error::Decode("gate order"))
        );
    }
    let mut request = Writer::new(Kind::PresentationRequest);
    request.bytes(community().as_bytes());
    request.u64(7);
    request.u64(1000);
    request.u64(0);
    request.u16((MAX_GATES + 1) as u16);
    assert_eq!(
        PresentationRequest::from_bytes(&request.finish_public()).err(),
        Some(Error::TooManyGates)
    );
}

#[test]
fn identity_public_keys_and_pseudonyms_are_never_accepted() {
    let mut public = Writer::new(Kind::IssuerPublicKey);
    public.key_id(&KeyId::new("identity").unwrap());
    public.u16(0);
    public.ark(&G2Affine::zero());
    assert_eq!(
        IssuerPublicKey::from_bytes(&public.finish_public()).err(),
        Some(Error::InvalidKey)
    );
    let identity = crate::issuer::point_bytes(&G1Affine::zero());
    assert_eq!(
        Pseudonym::from_bytes(&identity),
        Err(Error::Decode("pseudonym"))
    );
    let mut rng = rng();
    let valid = HolderSecret::generate(&mut rng).pseudonym(&community());
    let mut trailing = valid.to_bytes().to_vec();
    trailing.push(0);
    assert_eq!(
        Pseudonym::from_bytes(&trailing),
        Err(Error::Decode("pseudonym"))
    );
    assert_eq!(Pseudonym::from_bytes(&valid.to_bytes()), Ok(valid));
}

#[test]
fn identity_issuance_commitment_and_tag_refuse_decode_and_signing() {
    let mut rng = rng();
    let issuer = key(&mut rng, "issuer");
    let secret = HolderSecret::generate(&mut rng);
    let nonce = IssuanceChallenge::generate(&mut rng);
    let (request, pending) = request_issue(&mut rng, &secret, issuer.public_key(), &nonce).unwrap();
    for identity_commitment in [true, false] {
        let mut hostile = request.clone();
        if identity_commitment {
            hostile.commitment = G1Affine::zero();
        } else {
            hostile.issuer_tag = G1Affine::zero();
        }
        assert_eq!(
            IssuanceRequest::from_bytes(&hostile.to_bytes()).err(),
            Some(Error::Decode("identity element"))
        );
        assert_eq!(
            issuer
                .issue_blind(&mut rng, &hostile, &nonce, &attrs())
                .err(),
            Some(Error::InvalidIssuanceRequest)
        );
    }
    let blind = issuer
        .issue_blind(&mut rng, &request, &nonce, &attrs())
        .unwrap();
    pending.finish(&blind).unwrap();
}

#[test]
fn valid_cose_cannot_extend_a_presentation_deadline() {
    let mut rng = rng();
    let request = request(&mut rng);
    let mut signer = crate::test_support::signer(42);
    let anchor =
        AuthenticatedCommunity::from_authenticated_origin(community(), signer.key_ring().clone());
    let extended = signer
        .sign(
            csgn::Kind::Credential,
            &request.to_bytes(),
            0,
            request.now() + 2,
        )
        .unwrap();
    assert_eq!(
        anchor.authenticate(&extended, request.now()).err(),
        Some(Error::InvalidPresentationRequest)
    );
    assert_eq!(
        anchor.authenticate(&extended, request.now() + 1).err(),
        Some(Error::InvalidPresentationRequest)
    );
    let original = crate::test_support::signed(&mut signer, &request);
    assert_eq!(
        anchor.authenticate(&original, request.now()).unwrap(),
        request
    );
}

/// X2 M3: in the independent-expiry profile the deadline is also the lower
/// bound of the hidden expiry ranges. A community that signs a deadline far in
/// the future would turn the holder's accept or refuse answer into a range
/// oracle for the hidden expiries; the holder refuses it before it looks at the
/// passport.
#[test]
fn independent_profile_refuses_a_deadline_beyond_the_ahead_bound() {
    let mut rng = rng();
    let (_, passport, _) = fixture(&mut rng);
    let wallet_now = 1_000;
    let mut signer = crate::test_support::signer(42);
    let anchor =
        AuthenticatedCommunity::from_authenticated_origin(community(), signer.key_ring().clone());
    let ask = |rng: &mut StdRng, signer: &mut csgn::Signer, deadline: Timestamp| {
        let request = PresentationRequest::new(rng, community(), 7, [gate()], deadline).unwrap();
        crate::test_support::signed(signer, &request)
    };
    // The probe: the passport's validity ends at 2000 and its gate at 1500.
    // Without the bound, deadlines 1501 and 2001 would be answered with
    // "present" or "expired" and bracket the hidden values.
    for deadline in [
        wallet_now + MAX_REQUEST_AHEAD_SECONDS + 1,
        1_501,
        2_001,
        1_000_000,
    ] {
        let cose = ask(&mut rng, &mut signer, deadline);
        assert_eq!(
            anchor.authenticate(&cose, wallet_now).err(),
            Some(Error::InvalidPresentationRequest),
            "deadline {deadline}"
        );
        assert_eq!(
            passport.present(&mut rng, &anchor, &cose, wallet_now).err(),
            Some(Error::InvalidPresentationRequest),
            "deadline {deadline}"
        );
    }
    // The bound itself and everything below it is still answered.
    for deadline in [wallet_now, wallet_now + MAX_REQUEST_AHEAD_SECONDS] {
        let cose = ask(&mut rng, &mut signer, deadline);
        assert_eq!(
            anchor.authenticate(&cose, wallet_now).unwrap().now(),
            deadline
        );
        passport
            .present(&mut rng, &anchor, &cose, wallet_now)
            .unwrap();
    }
}

/// The shared-epoch profile reveals the expiry exactly, so a later deadline
/// teaches the community nothing and stays accepted.
#[test]
fn shared_epoch_profile_keeps_deadlines_beyond_the_ahead_bound() {
    let mut rng = rng();
    let mut signer = crate::test_support::signer(42);
    let anchor =
        AuthenticatedCommunity::from_authenticated_origin(community(), signer.key_ring().clone());
    let wallet_now = 1_000;
    let deadline = wallet_now + 10 * MAX_REQUEST_AHEAD_SECONDS;
    let request =
        PresentationRequest::for_epoch(&mut rng, community(), 7, [gate()], deadline, 5_000)
            .unwrap();
    let cose = crate::test_support::signed(&mut signer, &request);
    assert_eq!(anchor.authenticate(&cose, wallet_now).unwrap(), request);
}

#[test]
fn sealed_transport_requires_a_complete_authentication_tag() {
    for length in [0, 1, 15] {
        let mut encoded = Writer::new(Kind::SealedHolder);
        encoded.fixed(&[42; 24]);
        encoded.bytes(&vec![7; length]);
        assert_eq!(
            SealedHolder::from_bytes(&encoded.finish_public()).err(),
            Some(Error::InvalidSealedHolder)
        );
    }
}

#[test]
fn presentation_request_transport_requires_strict_gate_order() {
    for (gates, valid) in [
        (["phone", "phone"], false),
        (["phone", "human"], false),
        (["human", "phone"], true),
    ] {
        let mut encoded = Writer::new(Kind::PresentationRequest);
        encoded.bytes(community().as_bytes());
        encoded.u64(7);
        encoded.u64(1000);
        encoded.u64(0);
        encoded.u16(2);
        for name in gates {
            encoded.gate(&GateId::new(name).unwrap());
        }
        encoded.fixed(&[23; 32]);
        let decoded = PresentationRequest::from_bytes(&encoded.finish_public());
        if valid {
            assert_eq!(
                decoded.unwrap().required_gates(),
                &std::collections::BTreeSet::from([
                    GateId::new("human").unwrap(),
                    GateId::new("phone").unwrap(),
                ])
            );
        } else {
            assert_eq!(decoded.err(), Some(Error::Decode("gate order")));
        }
    }
}

#[test]
fn presentation_diagnostics_omit_nonce_proof_and_secret_material() {
    let mut rng = rng();
    let (issuer, passport, request) = fixture(&mut rng);
    let other_nonce =
        PresentationRequest::with_challenge(community(), 7, [gate()], 1000, [77; 32]).unwrap();
    assert_ne!(request.challenge(), other_nonce.challenge());
    assert_eq!(format!("{request:?}"), format!("{other_nonce:?}"));
    assert!(!format!("{request:?}").contains(&crate::wire::hex(&request.challenge())));
    assert!(format!("{request:?}").contains("community-a"));

    let first = passport.present_trusted(&mut rng, &request).unwrap();
    let second = passport.present_trusted(&mut rng, &request).unwrap();
    assert_ne!(first.to_bytes(), second.to_bytes());
    assert_eq!(format!("{first:?}"), format!("{second:?}"));
    assert_eq!(first.key_id(), issuer.public_key().key_id());
    let debug = format!("{first:?}");
    assert!(debug.contains("key-1"));
    assert!(debug.contains(&first.pseudonym().to_hex()));
    assert!(!debug.contains(&crate::wire::hex(&passport.secret().to_bytes())));
    for proof in [&first, &second] {
        assert_eq!(
            verify(&mut rng, &[issuer.public_key().clone()], &request, proof).unwrap(),
            passport.pseudonym(&community())
        );
    }
    let outstanding = ChallengeRecord {
        nonce: request.challenge(),
        binding: [19; 32],
        expires: request.now(),
    };
    let different = ChallengeRecord {
        nonce: other_nonce.challenge(),
        binding: [20; 32],
        expires: request.now() + 1,
    };
    assert_ne!(outstanding, different);
    assert_eq!(format!("{outstanding:?}"), "ChallengeRecord(<redacted>)");
    assert_eq!(format!("{outstanding:?}"), format!("{different:?}"));
}

// The fixture's known key opens genuine sealed state. These helpers alter only
// the encoded pending/passport fields and re-authenticate with the real AEAD;
// restoration must still run the original codecs and owner-binding checks.
fn sealed_fields(sealed: &SealedHolder) -> [zeroize::Zeroizing<Vec<u8>>; 3] {
    use chacha20poly1305::{
        KeyInit, XChaCha20Poly1305, XNonce,
        aead::{Aead, Payload},
    };
    let mut encoded = Reader::new(sealed.as_bytes(), Kind::SealedHolder).unwrap();
    let nonce = encoded.fixed::<24>().unwrap();
    let ciphertext = encoded.bytes().unwrap();
    encoded.finish().unwrap();
    let plaintext = zeroize::Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(&[8; 32])
            .unwrap()
            .decrypt(
                &XNonce::try_from(nonce.as_slice()).unwrap(),
                Payload {
                    msg: ciphertext,
                    aad: b"cpsd.opaque-holder.v1\0wallet-a",
                },
            )
            .unwrap(),
    );
    let mut original = Reader::new(&plaintext, Kind::OpaqueHolder).unwrap();
    let fields =
        std::array::from_fn(|_| zeroize::Zeroizing::new(original.bytes().unwrap().to_vec()));
    original.finish().unwrap();
    fields
}

fn reseal_fields(rng: &mut StdRng, fields: &[zeroize::Zeroizing<Vec<u8>>; 3]) -> SealedHolder {
    use chacha20poly1305::{
        KeyInit, XChaCha20Poly1305, XNonce,
        aead::{Aead, Payload},
    };
    use rand::RngCore;
    let mut encoded = Writer::new(Kind::OpaqueHolder);
    for field in fields {
        encoded.bytes(field);
    }
    let plaintext = encoded.finish_secret();
    let mut nonce = [0; 24];
    rng.fill_bytes(&mut nonce);
    let ciphertext = XChaCha20Poly1305::new_from_slice(&[8; 32])
        .unwrap()
        .encrypt(
            &XNonce::try_from(nonce.as_slice()).unwrap(),
            Payload {
                msg: &plaintext,
                aad: b"cpsd.opaque-holder.v1\0wallet-a",
            },
        )
        .unwrap();
    let mut sealed = Writer::new(Kind::SealedHolder);
    sealed.fixed(&nonce);
    sealed.bytes(&ciphertext);
    SealedHolder::from_bytes(&sealed.finish_public()).unwrap()
}

#[test]
fn authenticated_sealed_state_rejects_malformed_pending_and_passport() {
    let mut rng = rng();
    let issuer = key(&mut rng, "issuer");
    let mut holder =
        OpaqueHolder::from_seed_and_sealing_key(&mut [7; 32], &mut [8; 32], b"wallet-a").unwrap();
    let nonce = IssuanceChallenge::generate(&mut rng);
    let request = holder
        .begin_issuance(&mut rng, issuer.public_key(), &nonce)
        .unwrap();
    let blind = issuer
        .issue_blind(&mut rng, &request, &nonce, &attrs())
        .unwrap();
    for field in [1, 2] {
        let original = holder.seal(&mut rng).unwrap();
        let mut fields = sealed_fields(&original);
        assert!(!fields[field].is_empty());
        fields[field] = zeroize::Zeroizing::new(vec![9; 20]);
        let hostile = reseal_fields(&mut rng, &fields);
        assert_eq!(
            holder.restored(&hostile).err(),
            Some(Error::Decode("magic"))
        );
        holder = holder.restored(&original).unwrap();
        if field == 1 {
            holder.finish_issuance(&blind).unwrap();
        }
    }
    assert_eq!(holder.attributes().unwrap(), &attrs());
}

#[test]
fn authenticated_sealed_state_rejects_pending_and_passport_from_another_holder() {
    let mut rng = rng();
    let issuer = key(&mut rng, "issuer");
    let mut alice =
        OpaqueHolder::from_seed_and_sealing_key(&mut [7; 32], &mut [8; 32], b"wallet-a").unwrap();
    let mut bob =
        OpaqueHolder::from_seed_and_sealing_key(&mut [9; 32], &mut [8; 32], b"wallet-a").unwrap();
    assert_ne!(alice.pseudonym(&community()), bob.pseudonym(&community()));
    let nonce = IssuanceChallenge::generate(&mut rng);
    let alice_request = alice
        .begin_issuance(&mut rng, issuer.public_key(), &nonce)
        .unwrap();
    let bob_request = bob
        .begin_issuance(&mut rng, issuer.public_key(), &nonce)
        .unwrap();
    for field in [1, 2] {
        let original = alice.seal(&mut rng).unwrap();
        let mut fields = sealed_fields(&original);
        let other = sealed_fields(&bob.seal(&mut rng).unwrap());
        assert!(!fields[field].is_empty());
        assert!(!other[field].is_empty());
        fields[field] = other[field].clone();
        let hostile = reseal_fields(&mut rng, &fields);
        assert_eq!(
            alice.restored(&hostile).err(),
            Some(Error::InvalidSealedHolder)
        );
        alice = alice.restored(&original).unwrap();
        if field == 1 {
            for (holder, request) in [(&mut alice, &alice_request), (&mut bob, &bob_request)] {
                let blind = issuer
                    .issue_blind(&mut rng, request, &nonce, &attrs())
                    .unwrap();
                holder.finish_issuance(&blind).unwrap();
            }
        }
    }
    let request = request(&mut rng);
    let mut signer = crate::test_support::signer(42);
    let anchor =
        AuthenticatedCommunity::from_authenticated_origin(community(), signer.key_ring().clone());
    let signed = crate::test_support::signed(&mut signer, &request);
    let proof = alice
        .present(&mut rng, &anchor, &signed, request.now())
        .unwrap();
    assert_eq!(
        verify(&mut rng, &[issuer.public_key().clone()], &request, &proof).unwrap(),
        alice.pseudonym(&community())
    );
}
