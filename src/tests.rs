use crate::test_support::TestPresentation;
use std::{collections::BTreeSet, time::Instant};

use crate::*;
use rand::{SeedableRng, rngs::StdRng};

fn rng() -> StdRng {
    StdRng::seed_from_u64(71)
}
fn gate() -> GateId {
    GateId::new("phone").unwrap()
}
fn community() -> CommunityId {
    CommunityId::new(b"community-a").unwrap()
}
fn key(rng: &mut StdRng, name: &str) -> IssuerKey {
    IssuerKey::generate(
        rng,
        KeyId::new(name).unwrap(),
        vec![gate(), GateId::new("human").unwrap()],
    )
    .unwrap()
}
fn issue(
    rng: &mut StdRng,
    key: &IssuerKey,
    secret: &HolderSecret,
    attrs: PassportAttributes,
) -> Passport {
    let challenge = IssuanceChallenge::generate(rng);
    let (request, pending) = request_issue(rng, secret, key.public_key(), &challenge).unwrap();
    let request = IssuanceRequest::from_bytes(&request.to_bytes()).unwrap();
    let pending = PendingIssuance::from_bytes(&pending.to_bytes()).unwrap();
    let blind = key.issue_blind(rng, &request, &challenge, &attrs).unwrap();
    let blind = BlindPassport::from_bytes(&blind.to_bytes()).unwrap();
    let passport = pending.finish(&blind).unwrap();
    Passport::from_bytes(&passport.to_bytes()).unwrap()
}
fn attrs() -> PassportAttributes {
    PassportAttributes::new(2_000, 7).with_gate(gate(), 1_500)
}
fn request(rng: &mut StdRng) -> PresentationRequest {
    PresentationRequest::new(rng, community(), 7, [gate()], 1_000).unwrap()
}
fn fixture(rng: &mut StdRng) -> (IssuerKey, Passport, PresentationRequest) {
    let key = key(rng, "key-1");
    let secret = HolderSecret::generate(rng);
    let passport = issue(rng, &key, &secret, attrs());
    let request = request(rng);
    (key, passport, request)
}

#[test]
fn blind_issue_present_verify_and_all_transport_roundtrips() {
    let mut rng = rng();
    let (key, passport, request) = fixture(&mut rng);
    let restored = IssuerKey::from_secret_bytes(&key.to_secret_bytes()).unwrap();
    assert_eq!(restored.public_key(), key.public_key());
    let public = IssuerPublicKey::from_bytes(&key.public_key().to_bytes()).unwrap();
    let request = PresentationRequest::from_bytes(&request.to_bytes()).unwrap();
    let proof = passport.present_trusted(&mut rng, &request).unwrap();
    let decoded = Presentation::from_bytes(&proof.to_bytes()).unwrap();
    let nym = verify(&mut rng, &[public], &request, &decoded).unwrap();
    assert_eq!(nym, passport.pseudonym(&community()));
    assert_eq!(nym, Pseudonym::from_bytes(&nym.to_bytes()).unwrap());
    assert_eq!(nym.to_hex().len(), 96);
}

#[test]
fn proofs_bind_every_request_field_and_the_issuer_public_key() {
    let mut rng = rng();
    let (key, passport, req) = fixture(&mut rng);
    let proof = passport.present_trusted(&mut rng, &req).unwrap();
    let requests = [
        PresentationRequest::new(&mut rng, community(), 7, [gate()], 1000).unwrap(),
        PresentationRequest::with_challenge(
            CommunityId::new(b"other").unwrap(),
            7,
            [gate()],
            1000,
            req.challenge(),
        )
        .unwrap(),
        PresentationRequest::with_challenge(community(), 8, [gate()], 1000, req.challenge())
            .unwrap(),
        PresentationRequest::with_challenge(community(), 7, [], 1000, req.challenge()).unwrap(),
        PresentationRequest::with_challenge(community(), 7, [gate()], 1001, req.challenge())
            .unwrap(),
    ];
    for wrong in requests {
        assert!(verify(&mut rng, &[key.public_key().clone()], &wrong, &proof).is_err());
    }
    let impostor = self::key(&mut rng, "key-1");
    assert!(verify(&mut rng, &[impostor.public_key().clone()], &req, &proof).is_err());
    assert_eq!(verify(&mut rng, &[], &req, &proof), Err(Error::UnknownKey));
    assert_eq!(
        verify(
            &mut rng,
            &[key.public_key().clone(), key.public_key().clone()],
            &req,
            &proof
        ),
        Err(Error::DuplicateKeyId)
    );
}

#[test]
fn issuance_rejects_wrong_challenge_key_tag_commitment_and_response() {
    let mut rng = rng();
    let key = key(&mut rng, "a");
    let secret = HolderSecret::generate(&mut rng);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let (req, pending) = request_issue(&mut rng, &secret, key.public_key(), &challenge).unwrap();
    let wrong = IssuanceChallenge::generate(&mut rng);
    assert!(key.issue_blind(&mut rng, &req, &wrong, &attrs()).is_err());
    let other = self::key(&mut rng, "b");
    assert!(
        other
            .issue_blind(&mut rng, &req, &challenge, &attrs())
            .is_err()
    );
    let mut modified = req.clone();
    modified.issuer_tag = modified.commitment;
    assert!(
        key.issue_blind(&mut rng, &modified, &challenge, &attrs())
            .is_err()
    );
    modified = req.clone();
    modified.commitment = modified.issuer_tag;
    assert!(
        key.issue_blind(&mut rng, &modified, &challenge, &attrs())
            .is_err()
    );
    let mut blind = key
        .issue_blind(&mut rng, &req, &challenge, &attrs())
        .unwrap();
    blind.attributes.policy_epoch += 1;
    assert!(pending.finish(&blind).is_err());
}

#[test]
fn distinct_blind_requests_hide_one_secret_and_cannot_swap_responses() {
    let mut rng = rng();
    let key = key(&mut rng, "a");
    let secret = HolderSecret::generate(&mut rng);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let (a, _) = request_issue(&mut rng, &secret, key.public_key(), &challenge).unwrap();
    let (b, pending_b) = request_issue(&mut rng, &secret, key.public_key(), &challenge).unwrap();
    assert_ne!(a.commitment, b.commitment);
    assert_ne!(a.to_bytes(), b.to_bytes());
    assert_eq!(a.issuer_tag(), b.issuer_tag());
    let answer_a = key.issue_blind(&mut rng, &a, &challenge, &attrs()).unwrap();
    assert!(pending_b.finish(&answer_a).is_err());
}

#[test]
fn epoch_expiry_and_gate_checks_cannot_be_bypassed_by_a_hostile_holder() {
    let mut rng = rng();
    let key = key(&mut rng, "a");
    let secret = HolderSecret::generate(&mut rng);
    let req = request(&mut rng);
    for attributes in [
        PassportAttributes::new(2000, 6).with_gate(gate(), 1500),
        PassportAttributes::new(999, 7).with_gate(gate(), 1500),
        PassportAttributes::new(2000, 7),
        PassportAttributes::new(2000, 7).with_gate(gate(), 999),
    ] {
        let passport = issue(&mut rng, &key, &secret, attributes);
        assert!(passport.present_trusted(&mut rng, &req).is_err());
        // Bypass all client policy checks: security must reside in verification.
        if let Ok(proof) = crate::presentation::prove(&mut rng, &passport, &req) {
            assert!(verify(&mut rng, &[key.public_key().clone()], &req, &proof).is_err());
        }
    }
}

#[test]
fn hidden_signed_attributes_and_holder_secret_cannot_be_substituted() {
    let mut rng = rng();
    let (key, passport, req) = fixture(&mut rng);
    for field in 0..4 {
        let mut fake = passport.clone();
        match field {
            0 => fake.secret = HolderSecret::generate(&mut rng),
            1 => fake.attributes.valid_until += 100,
            2 => {
                fake.attributes.gates.insert(gate(), 1900);
            }
            _ => fake.revocation += ark_bls12_381::Fr::from(1u64),
        }
        assert!(Passport::from_bytes(&fake.to_bytes()).is_err());
        if let Ok(proof) = crate::presentation::prove(&mut rng, &fake, &req) {
            assert!(verify(&mut rng, &[key.public_key().clone()], &req, &proof).is_err());
        }
    }
}

#[test]
fn expiry_is_inclusive_and_zero_is_always_an_absent_gate() {
    let mut rng = rng();
    let key = key(&mut rng, "a");
    let secret = HolderSecret::generate(&mut rng);
    for t in [1, 1000, TIME_LIMIT - 1] {
        let passport = issue(
            &mut rng,
            &key,
            &secret,
            PassportAttributes::new(t, 7).with_gate(gate(), t),
        );
        let req = PresentationRequest::new(&mut rng, community(), 7, [gate()], t).unwrap();
        let proof = passport.present_trusted(&mut rng, &req).unwrap();
        verify(&mut rng, &[key.public_key().clone()], &req, &proof).unwrap();
    }
    for t in [0, TIME_LIMIT, u64::MAX] {
        assert!(PresentationRequest::new(&mut rng, community(), 7, [], t).is_err());
        assert!(
            PassportAttributes::new(t, 7)
                .validate(key.public_key().gates())
                .is_err()
        );
        assert!(
            attrs()
                .with_gate(gate(), t)
                .validate(key.public_key().gates())
                .is_err()
        );
    }
}

#[test]
fn renewal_and_key_rotation_preserve_pseudonyms() {
    let mut rng = rng();
    let secret = HolderSecret::generate(&mut rng);
    let restored = HolderSecret::from_bytes(&secret.to_bytes()).unwrap();
    let a = key(&mut rng, "a");
    let b = key(&mut rng, "b");
    let first = issue(&mut rng, &a, &secret, attrs());
    let second = issue(&mut rng, &b, &restored, attrs());
    assert_eq!(
        first.pseudonym(&community()),
        second.pseudonym(&community())
    );
    let req = request(&mut rng);
    for passport in [first, second] {
        let proof = passport.present_trusted(&mut rng, &req).unwrap();
        verify(
            &mut rng,
            &[a.public_key().clone(), b.public_key().clone()],
            &req,
            &proof,
        )
        .unwrap();
    }
}

#[test]
fn cross_community_collision_and_bit_distribution_regression() {
    let mut rng = rng();
    let mut seen = BTreeSet::new();
    let mut ones = 0usize;
    let mut bits = 0usize;
    for _ in 0..128 {
        let secret = HolderSecret::generate(&mut rng);
        let a = secret.pseudonym(&community()).to_bytes();
        let b = secret
            .pseudonym(&CommunityId::new(b"community-b").unwrap())
            .to_bytes();
        assert_eq!(a, secret.pseudonym(&community()).to_bytes());
        assert!(seen.insert(a));
        assert!(seen.insert(b));
        // Drop compression flags and the biased high field bits.
        for (a, b) in a[1..].iter().zip(&b[1..]) {
            ones += (a ^ b).count_ones() as usize;
            bits += 8;
        }
    }
    let fraction = ones as f64 / bits as f64;
    assert!(
        (0.47..0.53).contains(&fraction),
        "XOR bit fraction {fraction}"
    );
    // This catches implementation regressions; it is not a proof of DDH.
}

#[test]
fn presentations_randomize_even_for_an_identical_request() {
    let mut rng = rng();
    let (_, passport, req) = fixture(&mut rng);
    let a = passport.present_trusted(&mut rng, &req).unwrap();
    let b = passport.present_trusted(&mut rng, &req).unwrap();
    assert_eq!(a.pseudonym(), b.pseudonym());
    assert_ne!(a.to_bytes(), b.to_bytes());
}

#[test]
fn reject_invalid_identifiers_catalogues_and_untrusted_encodings() {
    let mut rng = rng();
    assert!(KeyId::new("").is_err());
    assert!(KeyId::new("with space").is_err());
    assert!(GateId::new("PHONE").is_err());
    assert!(CommunityId::new([]).is_err());
    assert!(CommunityId::new([1; 256]).is_err());
    assert!(IssuerKey::generate(&mut rng, KeyId::new("a").unwrap(), vec![gate(), gate()]).is_err());
    let (_, passport, req) = fixture(&mut rng);
    let proof = passport.present_trusted(&mut rng, &req).unwrap().to_bytes();
    for size in 0..proof.len() {
        assert!(Presentation::from_bytes(&proof[..size]).is_err());
    }
    let mut extra = proof.clone();
    extra.push(0);
    assert!(Presentation::from_bytes(&extra).is_err());
    for offset in [0, 4, 5] {
        let mut changed = proof.clone();
        changed[offset] ^= 255;
        assert!(Presentation::from_bytes(&changed).is_err());
    }
    assert!(Presentation::from_bytes(&vec![0; 256 * 1024 + 1]).is_err());
    assert!(Pseudonym::from_bytes(&[0; 48]).is_err());
    assert!(HolderSecret::from_bytes(&[0; 32]).is_err());
}

#[test]
fn malformed_proof_shapes_fail_before_upstream_verification() {
    use proof_system::statement_proof::StatementProof;
    let mut rng = rng();
    let (key, passport, req) = fixture(&mut rng);
    let good = passport.present_trusted(&mut rng, &req).unwrap();
    for case in 0..6 {
        let mut bad = good.clone();
        match case {
            0 => {
                bad.proof.statement_proofs.pop();
            }
            1 => {
                bad.proof
                    .statement_proofs
                    .push(bad.proof.statement_proofs[0].clone());
            }
            2 => {
                bad.proof.statement_proofs.swap(0, 1);
            }
            3 => {
                if let StatementProof::BoundCheckBpp(p) = &mut bad.proof.statement_proofs[2] {
                    p.bpp_proof.V.push(p.bpp_proof.V[0]);
                }
            }
            4 => {
                if let StatementProof::PedersenCommitmentPartial(p) =
                    &mut bad.proof.statement_proofs[1]
                {
                    p.response.total_responses = usize::MAX;
                }
            }
            _ => {
                bad.pseudonym = HolderSecret::generate(&mut rng).pseudonym(&community());
            }
        }
        assert!(verify(&mut rng, &[key.public_key().clone()], &req, &bad).is_err());
        // Removing a range statement leaves a decodable smaller proof; only
        // the verifier knows the requested gate count.
        if (1..=4).contains(&case) {
            assert!(Presentation::from_bytes(&bad.to_bytes()).is_err());
        }
    }
}

#[test]
fn print_native_performance() {
    let mut rng = rng();
    let start = Instant::now();
    let (key, passport, req) = fixture(&mut rng);
    let issuance = start.elapsed();
    let start = Instant::now();
    let proof = passport.present_trusted(&mut rng, &req).unwrap();
    let proving = start.elapsed();
    let start = Instant::now();
    verify(&mut rng, &[key.public_key().clone()], &req, &proof).unwrap();
    println!(
        "native setup/issuance/roundtrips={issuance:?}, present={proving:?}, verify={:?}, presentation_bytes={}",
        start.elapsed(),
        proof.to_bytes().len()
    );
}

#[test]
fn empty_and_maximum_gate_catalogues_and_unknown_gates() {
    let mut rng = rng();
    for count in [0, MAX_GATES] {
        let catalogue: Vec<_> = (0..count)
            .map(|i| GateId::new(format!("gate-{i:02}")).unwrap())
            .collect();
        let issuer =
            IssuerKey::generate(&mut rng, KeyId::new("limits").unwrap(), catalogue.clone())
                .unwrap();
        let secret = HolderSecret::generate(&mut rng);
        let mut attributes = PassportAttributes::new(2000, u64::MAX);
        for gate in &catalogue {
            attributes = attributes.with_gate(gate.clone(), 1500);
        }
        let passport = issue(&mut rng, &issuer, &secret, attributes);
        let request =
            PresentationRequest::new(&mut rng, community(), u64::MAX, catalogue, 1000).unwrap();
        let proof = passport.present_trusted(&mut rng, &request).unwrap();
        let decoded = Presentation::from_bytes(&proof.to_bytes()).unwrap();
        verify(&mut rng, &[issuer.public_key().clone()], &request, &decoded).unwrap();
    }
    let (issuer, passport, _) = fixture(&mut rng);
    let unknown = GateId::new("unknown").unwrap();
    assert!(
        attrs()
            .with_gate(unknown.clone(), 1500)
            .validate(issuer.public_key().gates())
            .is_err()
    );
    let request = PresentationRequest::new(&mut rng, community(), 7, [unknown], 1000).unwrap();
    assert!(matches!(
        passport.present_trusted(&mut rng, &request),
        Err(Error::UnknownGate(_))
    ));
    let too_many: Vec<_> = (0..=MAX_GATES)
        .map(|i| GateId::new(format!("g{i}")).unwrap())
        .collect();
    assert!(IssuerKey::generate(&mut rng, KeyId::new("over").unwrap(), too_many.clone()).is_err());
    assert!(PresentationRequest::new(&mut rng, community(), 7, too_many, 1000).is_err());
}

#[test]
fn tampered_serialized_proofs_never_authenticate_or_panic() {
    use rand::RngCore;
    let mut rng = rng();
    let (issuer, passport, request) = fixture(&mut rng);
    let proof = passport
        .present_trusted(&mut rng, &request)
        .unwrap()
        .to_bytes();
    for _ in 0..96 {
        let mut changed = proof.clone();
        let offset = rng.next_u32() as usize % changed.len();
        changed[offset] ^= 1 << (rng.next_u32() % 8);
        if let Ok(decoded) = Presentation::from_bytes(&changed) {
            assert!(verify(&mut rng, &[issuer.public_key().clone()], &request, &decoded).is_err());
        }
    }
    // Every variable-length integer is untrusted, including nested upstream
    // response counts. Shape checks must reject size bombs before allocation.
    let mut changed = proof;
    let key_len = u32::from_be_bytes(changed[6..10].try_into().unwrap()) as usize;
    let count_offset = 10 + key_len + 48;
    changed[count_offset..count_offset + 2].fill(255);
    assert!(Presentation::from_bytes(&changed).is_err());
}

#[test]
fn shared_epoch_proofs_bind_expiry_profile_and_all_requested_gates() {
    let mut rng = rng();
    let issuer = key(&mut rng, "shared-epoch");
    let secret = HolderSecret::generate(&mut rng);
    let passport = issue(
        &mut rng,
        &issuer,
        &secret,
        PassportAttributes::new(1500, 7).with_gate(gate(), 1500),
    );
    let request =
        PresentationRequest::for_epoch(&mut rng, community(), 7, [gate()], 1000, 1500).unwrap();
    let request = PresentationRequest::from_bytes(&request.to_bytes()).unwrap();
    assert_eq!(request.epoch_expiry(), Some(1500));
    let proof = passport.present_trusted(&mut rng, &request).unwrap();
    assert_eq!(proof.proof.statement_proofs.len(), 2);
    let proof = Presentation::from_bytes(&proof.to_bytes()).unwrap();
    assert_eq!(
        verify(&mut rng, &[issuer.public_key().clone()], &request, &proof).unwrap(),
        passport.pseudonym(request.community())
    );
    let hidden =
        PresentationRequest::with_challenge(community(), 7, [gate()], 1000, request.challenge())
            .unwrap();
    for wrong in [
        hidden.clone(),
        hidden.clone().with_epoch_expiry(1600).unwrap(),
        PresentationRequest::with_challenge(community(), 7, [], 1000, request.challenge())
            .unwrap()
            .with_epoch_expiry(1500)
            .unwrap(),
    ] {
        assert!(verify(&mut rng, &[issuer.public_key().clone()], &wrong, &proof).is_err());
    }
    let hidden_proof = passport.present_trusted(&mut rng, &hidden).unwrap();
    assert!(
        verify(
            &mut rng,
            &[issuer.public_key().clone()],
            &request,
            &hidden_proof
        )
        .is_err()
    );
    for attributes in [
        PassportAttributes::new(1600, 7).with_gate(gate(), 1500),
        PassportAttributes::new(1500, 7).with_gate(gate(), 1600),
        PassportAttributes::new(1500, 7),
        PassportAttributes::new(1500, 6).with_gate(gate(), 1500),
        PassportAttributes::new(999, 7).with_gate(gate(), 999),
    ] {
        let bad = issue(&mut rng, &issuer, &secret, attributes);
        assert!(bad.present_trusted(&mut rng, &request).is_err());
        // Revealed values must match signed messages, even without client checks.
        if let Ok(forgery) = crate::presentation::prove(&mut rng, &bad, &request) {
            assert!(verify(&mut rng, &[issuer.public_key().clone()], &request, &forgery).is_err());
        }
    }
    for expiry in [0, 999, TIME_LIMIT] {
        assert!(hidden.clone().with_epoch_expiry(expiry).is_err());
    }
    let bytes = proof.to_bytes();
    for end in 0..bytes.len() {
        assert!(Presentation::from_bytes(&bytes[..end]).is_err());
    }
    for offset in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        if let Ok(decoded) = Presentation::from_bytes(&changed) {
            assert!(verify(&mut rng, &[issuer.public_key().clone()], &request, &decoded).is_err());
        }
    }
}

#[test]
fn shared_epoch_handles_inclusive_boundaries_and_all_64_gates() {
    let mut rng = rng();
    for count in [0, MAX_GATES] {
        let catalogue: Vec<_> = (0..count)
            .map(|i| GateId::new(format!("g{i}")).unwrap())
            .collect();
        let issuer = IssuerKey::generate(
            &mut rng,
            KeyId::new("shared-limits").unwrap(),
            catalogue.clone(),
        )
        .unwrap();
        let secret = HolderSecret::generate(&mut rng);
        for expiry in [1, TIME_LIMIT - 1] {
            let mut attributes = PassportAttributes::new(expiry, u64::MAX);
            for gate in &catalogue {
                attributes = attributes.with_gate(gate.clone(), expiry);
            }
            let passport = issue(&mut rng, &issuer, &secret, attributes);
            let request = PresentationRequest::for_epoch(
                &mut rng,
                community(),
                u64::MAX,
                catalogue.clone(),
                expiry,
                expiry,
            )
            .unwrap();
            let proof = passport.present_trusted(&mut rng, &request).unwrap();
            let proof = Presentation::from_bytes(&proof.to_bytes()).unwrap();
            verify(&mut rng, &[issuer.public_key().clone()], &request, &proof).unwrap();
        }
    }
}

#[test]
fn signed_requests_require_the_origin_pinned_scope_key_kind_and_time() {
    use crate::test_support::{signed, signer};
    let mut rng = rng();
    let (issuer, passport, request) = fixture(&mut rng);
    let mut a = signer(42);
    let mut b = signer(43); // Same issuer label, different key: labels are not trust.
    let expected =
        AuthenticatedCommunity::from_authenticated_origin(community(), a.key_ring().clone());
    let valid = signed(&mut a, &request);
    let proof = passport
        .present(&mut rng, &expected, &valid, request.now())
        .unwrap();
    verify(&mut rng, &[issuer.public_key().clone()], &request, &proof).unwrap();
    let foreign = PresentationRequest::with_challenge(
        CommunityId::new("community-b").unwrap(),
        request.policy_epoch(),
        [gate()],
        request.now(),
        request.challenge(),
    )
    .unwrap();
    let mut changed = valid.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    for invalid in [
        signed(&mut b, &request),
        signed(&mut a, &foreign), // Even A's key cannot authorize B's scope.
        changed,
        request.to_bytes(),
        a.sign(
            csgn::Kind::SettingsSnapshot,
            &request.to_bytes(),
            0,
            request.now() + 1,
        )
        .unwrap(),
        a.sign(
            csgn::Kind::Credential,
            &request.to_bytes(),
            0,
            request.now() + 2,
        )
        .unwrap(),
        a.sign(
            csgn::Kind::Credential,
            b"different protocol",
            0,
            request.now() + 1,
        )
        .unwrap(),
    ] {
        assert!(matches!(
            passport.present(&mut rng, &expected, &invalid, request.now()),
            Err(Error::InvalidPresentationRequest)
        ));
    }
    assert!(matches!(
        passport.present(&mut rng, &expected, &valid, request.now() + 1),
        Err(Error::InvalidPresentationRequest)
    ));
    let future = a
        .sign(
            csgn::Kind::Credential,
            &request.to_bytes(),
            900,
            request.now() + 1,
        )
        .unwrap();
    assert!(matches!(
        passport.present(&mut rng, &expected, &future, 899),
        Err(Error::InvalidPresentationRequest)
    ));
}

#[test]
fn own_community_b_pseudonym_cannot_answer_community_a() {
    let mut rng = rng();
    let (issuer, passport, request) = fixture(&mut rng);
    let mut proof = passport.present_trusted(&mut rng, &request).unwrap();
    proof.pseudonym = passport.pseudonym(&CommunityId::new("community-b").unwrap());
    assert_eq!(
        verify(&mut rng, &[issuer.public_key().clone()], &request, &proof),
        Err(Error::InvalidProof)
    );
}

#[test]
fn all_ark_fields_require_decode_encode_identity() {
    use crate::wire::{Kind, Reader, Writer};
    use ark_bls12_381::{Fr, G1Affine, G2Affine};
    use ark_ff::{BigInteger, PrimeField};
    use ark_serialize::CanonicalSerialize;
    // Ark's point decoder accepts noncanonical identity coordinates/flags on
    // some curves. The cpsd boundary must reject every normalized encoding.
    fn point<T: CanonicalSerialize + ark_serialize::CanonicalDeserialize + ark_ec::AffineRepr>() {
        let mut w = Writer::new(Kind::BlindPassport);
        w.ark(&T::zero());
        let bytes = w.finish_public();
        assert!(
            Reader::new(&bytes, Kind::BlindPassport)
                .unwrap()
                .ark::<T>("test")
                .is_ok()
        );
        for index in 10..bytes.len() {
            for mask in [1, 32, 64, 128] {
                let mut changed = bytes.clone();
                changed[index] ^= mask;
                if let Ok(value) = Reader::new(&changed, Kind::BlindPassport)
                    .unwrap()
                    .ark::<T>("test")
                {
                    let mut out = Writer::new(Kind::BlindPassport);
                    out.ark(&value);
                    assert_eq!(changed, out.finish_public());
                }
            }
        }
    }
    point::<G1Affine>();
    point::<G2Affine>();
    let mut w = Writer::new(Kind::HolderSecret);
    w.ark(&Fr::from(1u64));
    let bytes = w.finish_public();
    for noncanonical in [Fr::MODULUS.to_bytes_le(), vec![255; 32]] {
        let mut changed = bytes.clone();
        changed[10..].copy_from_slice(&noncanonical);
        assert!(HolderSecret::from_bytes(&changed).is_err());
    }
    // Mutate complete nested encodings as well as primitive fields.
    let mut rng = rng();
    let (issuer, passport, request) = fixture(&mut rng);
    let nonce = IssuanceChallenge::generate(&mut rng);
    let (issue_request, pending) =
        request_issue(&mut rng, passport.secret(), issuer.public_key(), &nonce).unwrap();
    let blind = issuer
        .issue_blind(&mut rng, &issue_request, &nonce, &attrs())
        .unwrap();
    macro_rules! identity {
        ($bytes:expr, $decode:path, $encode:ident) => {{
            let bytes = $bytes.to_vec();
            for index in 0..bytes.len() {
                let mut changed = bytes.clone();
                changed[index] ^= 1;
                if let Ok(value) = $decode(&changed) {
                    assert_eq!(value.$encode().as_slice(), changed.as_slice());
                }
            }
        }};
    }
    identity!(
        issuer.public_key().to_bytes(),
        IssuerPublicKey::from_bytes,
        to_bytes
    );
    identity!(
        issuer.to_secret_bytes(),
        IssuerKey::from_secret_bytes,
        to_secret_bytes
    );
    identity!(pending.to_bytes(), PendingIssuance::from_bytes, to_bytes);
    identity!(blind.to_bytes(), BlindPassport::from_bytes, to_bytes);
    identity!(
        issue_request.to_bytes(),
        IssuanceRequest::from_bytes,
        to_bytes
    );
    identity!(
        request.to_bytes(),
        PresentationRequest::from_bytes,
        to_bytes
    );
    identity!(passport.to_bytes(), Passport::from_bytes, to_bytes);
}

#[test]
fn unrelated_pseudonym_secret_without_witness_equality_is_rejected() {
    use crate::presentation::{Side, presentation_spec, revealed_messages};
    use ark_ec::CurveGroup;
    use proof_system::{
        meta_statement::MetaStatements,
        proof::Proof,
        prover::ProverConfig,
        witness::{PoKBBSSignatureG1, Witness, Witnesses},
    };
    let mut rng = rng();
    let issuer = key(&mut rng, "equality");
    let holder = HolderSecret::generate(&mut rng);
    let passport = issue(&mut rng, &issuer, &holder, PassportAttributes::new(1500, 7));
    let request = PresentationRequest::for_epoch(&mut rng, community(), 7, [], 1000, 1500).unwrap();
    let unrelated = HolderSecret::generate(&mut rng);
    let point = (crate::params::community_base(request.community()) * unrelated.0).into_affine();
    let mut spec = presentation_spec(issuer.public_key(), &request, point, Side::Prover).unwrap();
    spec.meta_statements = MetaStatements::new();
    let revealed = revealed_messages(issuer.public_key(), &request).unwrap();
    let hidden = passport
        .messages()
        .iter()
        .enumerate()
        .filter(|(i, _)| !revealed.contains_key(i))
        .map(|(i, m)| (i, *m))
        .collect();
    let mut witnesses = Witnesses::new();
    witnesses.add(PoKBBSSignatureG1::new_as_witness(
        passport.signature.clone(),
        hidden,
    ));
    witnesses.add(Witness::PedersenCommitment(vec![unrelated.0]));
    let (proof, _) = Proof::new::<_, blake2::Blake2b512>(
        &mut rng,
        spec,
        witnesses,
        Some(request.challenge().to_vec()),
        ProverConfig::default(),
    )
    .unwrap();
    let mut forgery = passport.present_trusted(&mut rng, &request).unwrap();
    forgery.proof = proof;
    forgery.pseudonym = unrelated.pseudonym(request.community());
    assert_eq!(
        verify(&mut rng, &[issuer.public_key().clone()], &request, &forgery),
        Err(Error::InvalidProof)
    );
    assert!(Presentation::from_bytes(&forgery.to_bytes()).is_err());
}

#[test]
fn issuance_commitment_cannot_add_generators_for_issuer_owned_attributes() {
    use crate::params::{Curve, IDX_EPOCH, IDX_SECRET};
    use ark_bls12_381::Fr;
    use ark_ec::CurveGroup;
    use proof_system::{
        proof::Proof,
        prover::ProverConfig,
        statement::{Statements, ped_comm::PedersenCommitment},
        witness::{Witness, Witnesses},
    };
    let mut rng = rng();
    let issuer = key(&mut rng, "extra-generator");
    let secret = HolderSecret::generate(&mut rng);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let params = issuer.public_key().signature_params();
    let blind = Fr::from(11u64);
    let extra = Fr::from(7u64);
    let commitment =
        (params.h_0 * blind + params.h[IDX_SECRET] * secret.0 + params.h[IDX_EPOCH] * extra)
            .into_affine();
    let tag = (crate::params::issuer_tag_base() * secret.0).into_affine();
    let mut spec = crate::issuer::issuance_spec(issuer.public_key(), commitment, tag);
    let mut statements = Statements::<Curve>::new();
    statements.add(PedersenCommitment::new_statement_from_params::<Curve>(
        vec![params.h_0, params.h[IDX_SECRET], params.h[IDX_EPOCH]],
        commitment,
    ));
    statements.add(PedersenCommitment::new_statement_from_params::<Curve>(
        vec![crate::params::issuer_tag_base()],
        tag,
    ));
    spec.statements = statements;
    let mut witnesses = Witnesses::new();
    witnesses.add(Witness::PedersenCommitment(vec![blind, secret.0, extra]));
    witnesses.add(Witness::PedersenCommitment(vec![secret.0]));
    let (proof, _) = Proof::new::<_, blake2::Blake2b512>(
        &mut rng,
        spec,
        witnesses,
        Some(challenge.to_bytes().to_vec()),
        ProverConfig::default(),
    )
    .unwrap();
    let request = IssuanceRequest {
        key_id: issuer.public_key().key_id().clone(),
        commitment,
        issuer_tag: tag,
        proof,
    };
    assert!(matches!(
        issuer.issue_blind(&mut rng, &request, &challenge, &attrs()),
        Err(Error::InvalidIssuanceRequest)
    ));
    assert!(IssuanceRequest::from_bytes(&request.to_bytes()).is_err());
}

#[test]
fn write_fuzz_corpus() {
    let Ok(directory) = std::env::var("CPSD_FUZZ_CORPUS") else {
        return;
    };
    let dir = std::path::Path::new(&directory);
    std::fs::create_dir_all(dir).unwrap();
    let mut rng = rng();
    let (issuer, passport, request) = fixture(&mut rng);
    let nonce = IssuanceChallenge::generate(&mut rng);
    let (issuance, pending) =
        request_issue(&mut rng, passport.secret(), issuer.public_key(), &nonce).unwrap();
    let blind = issuer
        .issue_blind(&mut rng, &issuance, &nonce, &attrs())
        .unwrap();
    let proof = passport.present_trusted(&mut rng, &request).unwrap();
    let seeds = [
        issuer.public_key().to_bytes(),
        issuer.to_secret_bytes().to_vec(),
        passport.secret().to_bytes().to_vec(),
        pending.to_bytes().to_vec(),
        issuance.to_bytes(),
        blind.to_bytes(),
        passport.to_bytes().to_vec(),
        request.to_bytes(),
        proof.to_bytes(),
        proof.pseudonym().to_bytes().to_vec(),
    ];
    for (i, bytes) in seeds.into_iter().enumerate() {
        std::fs::write(dir.join(format!("valid-{i}")), bytes).unwrap();
    }
    // Explicit malformed scalar/infinity seeds keep canonicalization branches
    // reachable even during a short bounded CI fuzz run.
    use ark_ff::{BigInteger, PrimeField};
    let mut scalar = passport.secret().to_bytes().to_vec();
    scalar[10..].copy_from_slice(&ark_bls12_381::Fr::MODULUS.to_bytes_le());
    std::fs::write(dir.join("scalar-modulus"), scalar).unwrap();
    use ark_ec::AffineRepr;
    use ark_serialize::CanonicalSerialize;
    let mut infinity = Vec::new();
    ark_bls12_381::G1Affine::zero()
        .serialize_compressed(&mut infinity)
        .unwrap();
    infinity[0] |= 1;
    let mut malformed = blind.to_bytes();
    let signature_offset = malformed.len() - 112;
    malformed[signature_offset..signature_offset + 48].copy_from_slice(&infinity);
    std::fs::write(dir.join("noncanonical-infinity"), malformed).unwrap();
}
