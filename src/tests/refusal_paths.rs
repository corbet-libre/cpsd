//! Hostile transport values exercise the original decoders and cryptography.

use super::*;
use crate::wire::{Kind, Writer};
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
