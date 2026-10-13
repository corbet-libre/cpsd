mod refusal_paths;
mod proof_migration;

use crate::test_support::TestPresentation;
use std::{collections::BTreeSet, time::Instant};

use crate::*;
use ark_ec::AffineRepr;
use ark_ff::Zero;
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
    let mut rng = rng();
    let (key, passport, req) = fixture(&mut rng);
    let good = passport.present_trusted(&mut rng, &req).unwrap();
    for case in 0..7 {
        let mut bad = good.clone();
        match case {
            0 => {
                bad.proof.ranges.pop();
            }
            1 => {
                bad.proof.ranges.push(bad.proof.ranges[0].clone());
            }
            2 => {
                bad.proof.ranges.swap(0, 1);
            }
            3 => {
                let range = &mut bad.proof.ranges[0].range;
                range.V.push(range.V[0]);
            }
            4 => {
                bad.proof.signature.sc_resp_2 = None;
            }
            5 => {
                bad.proof.ranges[0].range.V.pop();
            }
            _ => {
                bad.pseudonym = HolderSecret::generate(&mut rng).pseudonym(&community());
            }
        }
        assert!(verify(&mut rng, &[key.public_key().clone()], &req, &bad).is_err());
        if (3..=5).contains(&case) {
            assert!(Presentation::from_bytes(&bad.to_bytes()).is_err());
        }
    }
    // Fields now have fixed roles, so swapping signature/pseudonym bytes must
    // fail decoding instead of supplying a general statement enum.
    let bytes = good.to_bytes();
    let key_len = u32::from_be_bytes(bytes[6..10].try_into().unwrap()) as usize;
    let first = 10 + key_len + 48;
    let sig_len = u32::from_be_bytes(bytes[first..first + 4].try_into().unwrap()) as usize;
    let second = first + 4 + sig_len;
    let third = second + 4 + 80;
    let swapped = [
        &bytes[..first],
        &bytes[second..third],
        &bytes[first..second],
        &bytes[third..],
    ]
    .concat();
    assert!(Presentation::from_bytes(&swapped).is_err());
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
    assert!(proof.proof.ranges.is_empty());
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
    use crate::params::IDX_SECRET;
    use ark_bls12_381::Fr;
    use ark_ec::CurveGroup;
    use ark_std::UniformRand;
    use bbs_plus::proof::PoKOfSignatureG1Protocol;
    use dock_crypto_utils::{signature::MessageOrBlinding, transcript::Transcript};
    use schnorr_pok::discrete_log::PokDiscreteLogProtocol;
    let mut rng = rng();
    let issuer = key(&mut rng, "equality");
    let holder = HolderSecret::generate(&mut rng);
    let passport = issue(&mut rng, &issuer, &holder, PassportAttributes::new(1500, 7));
    let request = PresentationRequest::for_epoch(&mut rng, community(), 7, [], 1000, 1500).unwrap();
    let unrelated = HolderSecret::generate(&mut rng);
    let base = crate::params::community_base(request.community());
    let point = (base * unrelated.0).into_affine();
    let revealed = crate::presentation::revealed_messages(issuer.public_key(), &request).unwrap();
    let messages = passport.messages();
    let shared = Fr::rand(&mut rng);
    let signature = PoKOfSignatureG1Protocol::init(
        &mut rng,
        &passport.signature,
        issuer.public_key().signature_params(),
        messages.iter().enumerate().map(|(i, m)| {
            if revealed.contains_key(&i) {
                MessageOrBlinding::RevealMessage(m)
            } else if i == IDX_SECRET {
                MessageOrBlinding::BlindMessageWithConcreteBlinding {
                    message: m,
                    blinding: shared,
                }
            } else {
                MessageOrBlinding::BlindMessageRandomly(m)
            }
        }),
    )
    .unwrap();
    let nym = PokDiscreteLogProtocol::init(unrelated.0, shared, &base);
    let mut transcript = crate::proof::presentation_transcript(issuer.public_key(), &request);
    let mut bytes = Vec::new();
    signature
        .challenge_contribution(
            &revealed,
            issuer.public_key().signature_params(),
            &mut bytes,
        )
        .unwrap();
    transcript.append_message(b"signature", &bytes);
    bytes.clear();
    nym.challenge_contribution(&base, &point, &mut bytes)
        .unwrap();
    transcript.append_message(b"pseudonym", &bytes);
    let challenge = transcript.challenge_scalar::<Fr>(b"challenge");
    let signature = signature.gen_proof(&challenge).unwrap();
    let nym = nym.gen_proof(&challenge);
    // Each maintained primitive is valid on its own. The only violated
    // relation is the original required equality of the two hidden secrets.
    signature
        .verify(
            &revealed,
            &challenge,
            issuer.public_key().bbs_public_key().clone(),
            issuer.public_key().signature_params().clone(),
        )
        .unwrap();
    assert!(nym.verify(&point, &base, &challenge));
    let mut forgery = passport.present_trusted(&mut rng, &request).unwrap();
    forgery.proof = crate::proof::PresentationProof {
        signature,
        pseudonym: nym,
        ranges: vec![],
    };
    forgery.pseudonym = unrelated.pseudonym(request.community());
    assert_eq!(
        verify(&mut rng, &[issuer.public_key().clone()], &request, &forgery),
        Err(Error::InvalidProof)
    );
    // V3 contains full responses: a structurally valid inequality is rejected
    // by verification, whereas the old partial-proof format rejected decoding.
    let decoded = Presentation::from_bytes(&forgery.to_bytes()).unwrap();
    assert_eq!(
        verify(&mut rng, &[issuer.public_key().clone()], &request, &decoded),
        Err(Error::InvalidProof)
    );
}

#[test]
fn issuance_commitment_cannot_add_generators_for_issuer_owned_attributes() {
    use crate::params::{IDX_EPOCH, IDX_SECRET};
    use ark_bls12_381::Fr;
    use ark_ec::CurveGroup;
    use ark_serialize::CanonicalSerialize;
    use dock_crypto_utils::transcript::Transcript;
    use schnorr_pok::{SchnorrChallengeContributor, SchnorrCommitment};
    let mut rng = rng();
    let issuer = key(&mut rng, "extra-generator");
    let secret = HolderSecret::generate(&mut rng);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let params = issuer.public_key().signature_params();
    let blind = Fr::from(11u64);
    let extra = Fr::from(7u64);
    let bases = [params.h_0, params.h[IDX_SECRET], params.h[IDX_EPOCH]];
    let commitment = (bases[0] * blind + bases[1] * secret.0 + bases[2] * extra).into_affine();
    let protocol = SchnorrCommitment::new(
        &bases,
        vec![Fr::from(13u64), Fr::from(17u64), Fr::from(19u64)],
    );
    let mut transcript = crate::proof::issuance_transcript(issuer.public_key(), &challenge);
    let mut contribution = Vec::new();
    bases.serialize_compressed(&mut contribution).unwrap();
    commitment.serialize_compressed(&mut contribution).unwrap();
    protocol.challenge_contribution(&mut contribution).unwrap();
    transcript.append_message(b"opening", &contribution);
    let scalar = transcript.challenge_scalar::<Fr>(b"challenge");
    let response = protocol
        .response(&[blind, secret.0, extra], &scalar)
        .unwrap();
    response
        .is_valid(&bases, &commitment, &protocol.t, &scalar)
        .unwrap();
    let (mut request, _) =
        request_issue(&mut rng, &secret, issuer.public_key(), &challenge).unwrap();
    request.commitment = commitment;
    assert!(matches!(
        issuer.issue_blind(&mut rng, &request, &challenge, &attrs()),
        Err(Error::InvalidIssuanceRequest)
    ));
    // A real three-generator proof cannot enter the fixed two-generator wire.
    let mut w = crate::wire::Writer::new(crate::wire::Kind::IssuanceRequest);
    w.key_id(issuer.public_key().key_id());
    w.ark(&commitment);
    w.ark(&request.issuer_tag);
    let mut extra_proof = Vec::new();
    protocol.t.serialize_compressed(&mut extra_proof).unwrap();
    response.serialize_compressed(&mut extra_proof).unwrap();
    request
        .proof
        .tag
        .serialize_compressed(&mut extra_proof)
        .unwrap();
    w.bytes(&extra_proof);
    assert!(IssuanceRequest::from_bytes(&w.finish_public()).is_err());
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

// --- Coverage batch: exact diagnostics, wire boundaries, session contracts.

#[test]
fn error_display_reports_exact_diagnostics() {
    let gate = GateId::new("phone").unwrap();
    let cases = [
        (Error::InvalidIdentifier("key id"), "invalid key id"),
        (Error::InvalidTimestamp, "timestamp out of range"),
        (Error::InvalidGateCatalogue, "invalid gate catalogue"),
        (Error::TooManyGates, "too many gates"),
        (
            Error::UnknownGate(gate.clone()),
            "gate phone is not in the issuer's catalogue",
        ),
        (
            Error::KeyMismatch,
            "object belongs to a different issuer key",
        ),
        (Error::UnknownKey, "unknown issuer key"),
        (Error::DuplicateKeyId, "duplicate key ID in key ring"),
        (Error::InvalidKey, "invalid key"),
        (Error::InvalidIssuanceRequest, "invalid issuance request"),
        (Error::IssuancePending, "issuance already pending"),
        (Error::NoPendingIssuance, "no pending issuance"),
        (Error::PassportUnavailable, "passport unavailable"),
        (Error::InvalidSignature, "invalid passport signature"),
        (Error::PassportExpired, "passport expired"),
        (Error::WrongEpoch, "wrong policy epoch"),
        (Error::WrongExpiryCohort, "wrong expiry cohort"),
        (
            Error::GateMissing(gate.clone()),
            "gate phone missing from passport",
        ),
        (Error::GateExpired(gate.clone()), "gate phone expired"),
        (Error::InvalidProof, "invalid proof"),
        (Error::ProofGeneration, "proof generation failed"),
        (Error::Storage, "challenge storage failed"),
        (
            Error::StorageCapacity,
            "challenge storage capacity exceeded",
        ),
        (Error::ChallengeConflict, "challenge collision"),
        (Error::InvalidChallenge, "invalid or consumed challenge"),
        (
            Error::InvalidPresentationRequest,
            "unauthenticated presentation request",
        ),
        (Error::IssuerTagMismatch, "issuer tag continuity failed"),
        (Error::IssuerTagClaimed, "issuer tag already claimed"),
        (Error::Decode("gate order"), "cannot decode gate order"),
    ];
    assert_eq!(cases.len(), 29);
    for (error, diagnostic) in cases {
        assert_eq!(error.to_string(), diagnostic);
    }
}

#[test]
fn debug_formats_redact_secrets_and_name_public_parts() {
    let mut rng = rng();
    let (key, passport, request) = fixture(&mut rng);
    let issuance_challenge = IssuanceChallenge::generate(&mut rng);
    let (issuance_request, pending) = request_issue(
        &mut rng,
        passport.secret(),
        key.public_key(),
        &issuance_challenge,
    )
    .unwrap();
    let proof = passport.present_trusted(&mut rng, &request).unwrap();
    assert_eq!(
        format!("{:?}", passport.secret()),
        "HolderSecret(<redacted>)"
    );
    let pending_debug = format!("{pending:?}");
    assert!(pending_debug.contains("PendingIssuance"));
    assert!(pending_debug.contains("key-1"));
    let passport_debug = format!("{passport:?}");
    assert!(passport_debug.contains("Passport"));
    assert!(passport_debug.contains("key-1"));
    let public_debug = format!("{:?}", key.public_key());
    assert!(public_debug.contains("IssuerPublicKey"));
    assert!(public_debug.contains("key-1"));
    let key_debug = format!("{key:?}");
    assert!(key_debug.contains("IssuerKey"));
    assert!(key_debug.contains("key-1"));
    let tag = passport.secret().issuer_tag();
    assert_eq!(
        format!("{tag:?}"),
        format!("IssuerTag({})", crate::wire::hex(&tag.to_bytes()))
    );
    let challenge = IssuanceChallenge::generate(&mut rng);
    assert_eq!(
        format!("{challenge:?}"),
        format!(
            "IssuanceChallenge({})",
            crate::wire::hex(&challenge.to_bytes())
        )
    );
    let request_debug = format!("{request:?}");
    assert!(request_debug.contains("PresentationRequest"));
    assert!(request_debug.contains("community-a"));
    let offering = key
        .issue_blind(
            &mut rng,
            &IssuanceRequest::from_bytes(&issuance_request.to_bytes()).unwrap(),
            &issuance_challenge,
            &attrs(),
        )
        .unwrap();
    let offering_debug = format!("{offering:?}");
    assert!(offering_debug.contains("BlindPassport"));
    assert!(offering_debug.contains("key-1"));
    let presentation_debug = format!("{proof:?}");
    assert!(presentation_debug.contains("Presentation"));
    assert!(presentation_debug.contains("key-1"));
    let record = ChallengeRecord {
        nonce: [1; 32],
        binding: [2; 32],
        expires: 10,
    };
    assert_eq!(format!("{record:?}"), "ChallengeRecord(<redacted>)");
    let auth = AuthenticatedIssuance::new([1; 32], [2; 32]);
    assert_eq!(format!("{auth:?}"), "AuthenticatedIssuance(<redacted>)");
    let nym = passport.pseudonym(&community());
    assert_eq!(format!("{nym:?}"), format!("Pseudonym({})", nym.to_hex()));
}

#[test]
fn public_accessors_report_committed_state() {
    let mut rng = rng();
    let (key, passport, request) = fixture(&mut rng);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let (issuance_request, _) =
        request_issue(&mut rng, passport.secret(), key.public_key(), &challenge).unwrap();
    assert_eq!(passport.key_id(), key.public_key().key_id());
    assert_eq!(passport.attributes(), &attrs());
    assert_eq!(passport.issuer(), key.public_key());
    assert_eq!(
        passport.secret().to_bytes().as_slice(),
        HolderSecret::from_bytes(passport.secret().to_bytes().as_slice())
            .unwrap()
            .to_bytes()
            .as_slice()
    );
    assert_eq!(
        passport.secret().issuer_tag(),
        issuance_request.issuer_tag()
    );
    assert_eq!(request.community(), &community());
    assert_eq!(request.policy_epoch(), 7);
    assert_eq!(request.now(), 1000);
    assert_eq!(request.epoch_expiry(), None);
    assert!(request.required_gates().contains(&gate()));
    assert_eq!(request.challenge().len(), 32);
    let proof = passport.present_trusted(&mut rng, &request).unwrap();
    assert_eq!(proof.key_id(), key.public_key().key_id());
    assert_eq!(proof.pseudonym(), &passport.pseudonym(&community()));
    assert_eq!(proof.pseudonym().to_hex().len(), 96);
    let handle = BlindPassport::from_bytes(
        &key.issue_blind(
            &mut rng,
            &IssuanceRequest::from_bytes(&issuance_request.to_bytes()).unwrap(),
            &challenge,
            &attrs(),
        )
        .unwrap()
        .to_bytes(),
    )
    .unwrap();
    assert_eq!(handle.key_id(), key.public_key().key_id());
    assert_eq!(handle.attributes(), &attrs());
    assert_eq!(handle.revocation_handle().len(), 32);
}

#[test]
fn attributes_reject_oversized_catalogues_and_unordered_wire_gates() {
    use crate::wire::{Kind, Reader, Writer};
    let too_many: Vec<_> = (0..=MAX_GATES)
        .map(|i| GateId::new(format!("g{i}")).unwrap())
        .collect();
    let mut oversized = PassportAttributes::new(2000, 7);
    for gate in &too_many {
        oversized = oversized.with_gate(gate.clone(), 1500);
    }
    assert_eq!(oversized.validate(&too_many), Err(Error::TooManyGates));
    for gates in [
        vec![GateId::new("b").unwrap(), GateId::new("a").unwrap()],
        vec![GateId::new("a").unwrap(), GateId::new("a").unwrap()],
    ] {
        let mut w = Writer::new(Kind::Passport);
        w.u64(7);
        w.u64(2000);
        w.u16(gates.len() as u16);
        for gate in &gates {
            w.gate(gate);
            w.u64(1500);
        }
        let bytes = w.finish_public();
        let mut r = Reader::new(&bytes, Kind::Passport).unwrap();
        assert_eq!(
            PassportAttributes::decode(&mut r),
            Err(Error::Decode("gate order"))
        );
    }
}

#[test]
fn presentation_request_rejects_unordered_wire_gates() {
    use crate::wire::{Kind, Writer};
    let mut w = Writer::new(Kind::PresentationRequest);
    w.bytes(community().as_bytes());
    w.u64(7);
    w.u64(1000);
    w.u64(0);
    w.u16(2);
    w.gate(&GateId::new("b").unwrap());
    w.gate(&GateId::new("a").unwrap());
    w.fixed(&[7u8; 32]);
    let bytes = w.finish_public();
    assert_eq!(
        PresentationRequest::from_bytes(&bytes),
        Err(Error::Decode("gate order"))
    );
}

#[test]
fn pseudonym_boundary_rejects_trailing_identity_and_noncanonical_encodings() {
    use ark_bls12_381::G1Affine;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    let mut rng = rng();
    let secret = HolderSecret::generate(&mut rng);
    let valid = secret.pseudonym(&community()).to_bytes().to_vec();
    let mut trailing = valid.clone();
    trailing.push(0);
    assert_eq!(
        Pseudonym::from_bytes(&trailing),
        Err(Error::Decode("pseudonym"))
    );
    let mut identity = Vec::new();
    G1Affine::zero()
        .serialize_compressed(&mut identity)
        .unwrap();
    assert_eq!(identity.len(), 48);
    assert!(
        G1Affine::deserialize_compressed(identity.as_slice())
            .unwrap()
            .is_zero()
    );
    assert_eq!(
        Pseudonym::from_bytes(&identity),
        Err(Error::Decode("pseudonym"))
    );
    let mut ambiguous = valid.clone();
    ambiguous[0] |= 0x40;
    assert_eq!(
        Pseudonym::from_bytes(&ambiguous),
        Err(Error::Decode("pseudonym"))
    );
}

#[test]
fn issuance_request_rejects_identity_commitment_and_tag() {
    use ark_bls12_381::G1Affine;
    use ark_serialize::CanonicalSerialize;
    let mut rng = rng();
    let key = key(&mut rng, "identity");
    let secret = HolderSecret::generate(&mut rng);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let (request, _) = request_issue(&mut rng, &secret, key.public_key(), &challenge).unwrap();
    let encoded = request.to_bytes();
    let mut point = Vec::new();
    G1Affine::zero().serialize_compressed(&mut point).unwrap();
    assert_eq!(point.len(), 48);
    // Layout: magic + version + kind, key id, then the 48-byte commitment.
    let key_len = u32::from_be_bytes(encoded[6..10].try_into().unwrap()) as usize;
    let commitment = 10 + key_len;
    for offset in [commitment, commitment + 4 + 48] {
        let mut changed = encoded.clone();
        changed[offset + 4..offset + 4 + 48].copy_from_slice(&point);
        assert_eq!(
            IssuanceRequest::from_bytes(&changed).err(),
            Some(Error::Decode("identity element"))
        );
    }
}

#[test]
fn zero_scalars_are_rejected_at_every_boundary() {
    let mut rng = rng();
    let (key, passport, _) = fixture(&mut rng);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let (_, pending) =
        request_issue(&mut rng, passport.secret(), key.public_key(), &challenge).unwrap();
    let mut pending_bytes = pending.to_bytes().to_vec();
    pending_bytes[10..42].fill(0);
    assert_eq!(
        PendingIssuance::from_bytes(&pending_bytes).err(),
        Some(Error::InvalidKey)
    );
    let mut passport_bytes = passport.to_bytes().to_vec();
    passport_bytes[10..42].fill(0);
    assert_eq!(
        Passport::from_bytes(&passport_bytes).err(),
        Some(Error::InvalidKey)
    );
    let mut secret_bytes = key.to_secret_bytes().to_vec();
    let key_len = u32::from_be_bytes(secret_bytes[6..10].try_into().unwrap()) as usize;
    let mut offset = 10 + key_len;
    let gates = u16::from_be_bytes(secret_bytes[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;
    for _ in 0..gates {
        let len = u32::from_be_bytes(secret_bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4 + len;
    }
    assert_eq!(&secret_bytes[offset..offset + 4], &32u32.to_be_bytes());
    assert_eq!(offset + 4 + 32, secret_bytes.len());
    secret_bytes[offset + 4..offset + 4 + 32].fill(0);
    assert_eq!(
        IssuerKey::from_secret_bytes(&secret_bytes).err(),
        Some(Error::InvalidKey)
    );
}

#[test]
fn tampered_issuer_key_with_identity_point_is_invalid() {
    use ark_bls12_381::G2Affine;
    use ark_serialize::CanonicalSerialize;
    let mut rng = rng();
    let key = key(&mut rng, "identity-key");
    let encoded = key.public_key().to_bytes();
    let mut point = Vec::new();
    G2Affine::zero().serialize_compressed(&mut point).unwrap();
    assert_eq!(point.len(), 96);
    let key_len = u32::from_be_bytes(encoded[6..10].try_into().unwrap()) as usize;
    let mut offset = 10 + key_len;
    let gates = u16::from_be_bytes(encoded[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;
    for _ in 0..gates {
        let len = u32::from_be_bytes(encoded[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4 + len;
    }
    assert_eq!(&encoded[offset..offset + 4], &96u32.to_be_bytes());
    assert_eq!(offset + 4 + 96, encoded.len());
    let mut changed = encoded.clone();
    changed[offset + 4..offset + 4 + 96].copy_from_slice(&point);
    assert_eq!(
        IssuerPublicKey::from_bytes(&changed),
        Err(Error::InvalidKey)
    );
}

#[test]
fn issuance_with_identity_commitment_is_rejected_before_signing() {
    use ark_bls12_381::G1Affine;
    let mut rng = rng();
    let key = key(&mut rng, "identity-check");
    let secret = HolderSecret::generate(&mut rng);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let (request, _) = request_issue(&mut rng, &secret, key.public_key(), &challenge).unwrap();
    for forged in [
        IssuanceRequest {
            commitment: G1Affine::zero(),
            ..request.clone()
        },
        IssuanceRequest {
            issuer_tag: G1Affine::zero(),
            ..request.clone()
        },
    ] {
        assert_eq!(
            key.issue_blind(&mut rng, &forged, &challenge, &attrs())
                .err(),
            Some(Error::InvalidIssuanceRequest)
        );
    }
}

#[test]
fn issuer_key_equality_compares_all_components() {
    let mut rng = rng();
    let first = key(&mut rng, "same");
    let second = key(&mut rng, "same");
    assert_ne!(first.public_key(), second.public_key());
    assert_ne!(key(&mut rng, "other").public_key(), first.public_key());
    let other_catalogue =
        IssuerKey::generate(&mut rng, KeyId::new("same").unwrap(), vec![gate()]).unwrap();
    assert_ne!(first.public_key(), other_catalogue.public_key());
}

#[test]
fn canonical_encoding_requires_full_consumption_and_byte_identity() {
    assert!(crate::wire::canonical_encoding(
        &[],
        b"canonical",
        b"canonical"
    ));
    assert!(!crate::wire::canonical_encoding(
        b"trailing",
        b"canonical",
        b"canonical"
    ));
    assert!(!crate::wire::canonical_encoding(
        &[],
        b"canonical",
        b"normalized"
    ));
    // Opaque backend errors must not be formatted or exposed by redaction.
    struct PrivateBackend;
    let result: std::result::Result<(), PrivateBackend> = Err(PrivateBackend);
    assert_eq!(
        result.map_err(crate::error::redact(Error::Storage)),
        Err(Error::Storage)
    );
}

#[test]
fn issuance_accessors_roundtrip_and_debug_omits_proof_material() {
    let mut rng = rng();
    let key = key(&mut rng, "transport");
    let secret = HolderSecret::generate(&mut rng);
    let bytes = [0xa5; 32];
    let from_bytes: fn([u8; 32]) -> IssuanceChallenge =
        std::hint::black_box(IssuanceChallenge::from_bytes);
    let challenge = from_bytes(bytes);
    assert_eq!(challenge.to_bytes(), bytes);
    let (request, _) = request_issue(&mut rng, &secret, key.public_key(), &challenge).unwrap();
    let key_id: fn(&IssuanceRequest) -> &KeyId = std::hint::black_box(IssuanceRequest::key_id);
    assert_eq!(key_id(&request), key.public_key().key_id());
    let debug = format!("{request:?}");
    assert!(debug.contains("transport"));
    assert!(debug.contains("issuer_tag"));
    assert!(!debug.contains("proof"));
    assert!(!debug.contains("commitment"));
}

#[test]
fn issuance_rejects_zero_secret_even_before_proof_construction() {
    use ark_bls12_381::Fr;
    use rand::{CryptoRng, RngCore};
    struct ZeroRng;
    impl RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, bytes: &mut [u8]) {
            bytes.fill(0);
        }
        fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(bytes);
            Ok(())
        }
    }
    impl CryptoRng for ZeroRng {}
    let mut rng = rng();
    let key = key(&mut rng, "zero-secret");
    let secret = HolderSecret(Fr::zero());
    let challenge = IssuanceChallenge::generate(&mut rng);
    // Zero blinding makes the commitment identity; random blinding leaves
    // a nonidentity commitment but the issuer tag remains identity.
    assert_eq!(
        request_issue(&mut ZeroRng, &secret, key.public_key(), &challenge).err(),
        Some(Error::ProofGeneration)
    );
    assert_eq!(
        request_issue(&mut rng, &secret, key.public_key(), &challenge).err(),
        Some(Error::ProofGeneration)
    );
}

#[tokio::test]
async fn memory_consumption_entrypoint_enforces_binding_time_and_replay() {
    let store = MemoryStore::new(community(), 4).unwrap();
    assert!(
        store
            .reserve(ChallengeRecord {
                nonce: [1; 32],
                binding: [2; 32],
                expires: 100
            })
            .await
            .unwrap()
    );
    let consume = std::hint::black_box(<MemoryStore as ChallengeStore>::consume);
    assert_eq!(
        consume(&store, [1; 32], [2; 32], 0).await,
        Err(Error::InvalidTimestamp)
    );
    assert!(!consume(&store, [1; 32], [3; 32], 100).await.unwrap());
    assert!(!consume(&store, [1; 32], [2; 32], 101).await.unwrap());
    assert!(consume(&store, [1; 32], [2; 32], 100).await.unwrap());
    assert!(!consume(&store, [1; 32], [2; 32], 100).await.unwrap());
}

#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
#[tokio::test]
async fn libsql_rechecks_verified_issuance_and_rolls_back_inexact_consumption() {
    use crate::storage::libsql::{
        ISSUANCE_SCHEMA, ISSUANCE_UNIQUENESS_SCHEMA, LibsqlStore, SCHEMA,
    };
    use crlt::{Config, Db, Migration};
    let directory = tempfile::tempdir().unwrap();
    let db = Db::open(Config::new(
        format!("file://{}", directory.path().join("ignored.db").display()),
        "",
    ))
    .await
    .unwrap();
    let migrations = vec![
        Migration::new(1, "challenges", SCHEMA),
        Migration::new(2, "continuity", ISSUANCE_SCHEMA),
        Migration::new(3, "uniqueness", ISSUANCE_UNIQUENESS_SCHEMA),
    ];
    db.migrate(&migrations).await.unwrap();
    let store = LibsqlStore::new(&db, community(), 4).unwrap();
    let store_community: fn(&LibsqlStore) -> &CommunityId =
        std::hint::black_box(<LibsqlStore as ChallengeStore>::community);
    assert_eq!(store_community(&store), &community());
    let tag = HolderSecret::generate(&mut rng()).issuer_tag();
    let verified = || VerifiedIssuance {
        nonce: [1; 32],
        binding: [2; 32],
        now: 100,
        person: [3; 32],
        tag,
    };
    assert!(!store.consume_issuance(verified()).await.unwrap());
    assert!(
        store
            .reserve(ChallengeRecord {
                nonce: [1; 32],
                binding: [2; 32],
                expires: 100
            })
            .await
            .unwrap()
    );
    let consume = std::hint::black_box(<LibsqlStore as ChallengeStore>::consume);
    assert!(!consume(&store, [1; 32], [9; 32], 100).await.unwrap());
    let scoped = db
        .community(format!("cpsd/{}", crate::wire::hex(community().as_bytes())))
        .unwrap();
    for count in [0, 2] {
        let mut tx = scoped.tx().await.unwrap();
        tx.execute(
            "INSERT INTO cpsd_issuer_tags (person, tag) VALUES (?1, ?2)",
            crlt::params![vec![3u8; 32], tag.to_bytes().to_vec()],
        )
        .await
        .unwrap();
        assert!(
            !crate::storage::libsql::finish_issuance_transaction(tx, count)
                .await
                .unwrap()
        );
        assert!(
            scoped
                .query(
                    "SELECT tag FROM cpsd_issuer_tags WHERE person = ?1",
                    crlt::params![vec![3u8; 32]]
                )
                .await
                .unwrap()
                .is_empty()
        );
        assert!(store.matches([1; 32], [2; 32], 100).await.unwrap());
    }
    // A different tag must succeed: inexact consumption rolled back the
    // first tag registration together with its transaction.
    let other_tag = HolderSecret::generate(&mut StdRng::seed_from_u64(99)).issuer_tag();
    let mut retry = verified();
    retry.tag = other_tag;
    assert!(store.consume_issuance(retry).await.unwrap());
    assert!(!store.consume_issuance(verified()).await.unwrap());
}

#[test]
fn rigged_rng_zero_is_rejected_by_nonzero_scalar() {
    use rand::RngCore;
    struct ZeroPrefixRng {
        zero_calls: usize,
        inner: StdRng,
    }
    impl RngCore for ZeroPrefixRng {
        fn next_u32(&mut self) -> u32 {
            if self.zero_calls > 0 {
                self.zero_calls -= 1;
                0
            } else {
                self.inner.next_u32()
            }
        }
        fn next_u64(&mut self) -> u64 {
            if self.zero_calls > 0 {
                self.zero_calls -= 1;
                0
            } else {
                self.inner.next_u64()
            }
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            if self.zero_calls > 0 {
                self.zero_calls -= 1;
                dest.fill(0);
            } else {
                self.inner.fill_bytes(dest);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            if self.zero_calls > 0 {
                self.zero_calls -= 1;
                dest.fill(0);
                Ok(())
            } else {
                self.inner.try_fill_bytes(dest)
            }
        }
    }
    let mut rigged = ZeroPrefixRng {
        zero_calls: 16,
        inner: StdRng::seed_from_u64(7),
    };
    let scalar = crate::issuer::nonzero_scalar(&mut rigged);
    assert!(!scalar.is_zero());
}

#[test]
fn opaque_holder_attributes_track_verified_passport() {
    let mut rng = rng();
    let gate = gate();
    let issuer = key(&mut rng, "opaque-attrs");
    let mut holder = OpaqueHolder::from_seed(&mut [9; 32]);
    assert_eq!(holder.attributes(), None);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let request = holder
        .begin_issuance(&mut rng, issuer.public_key(), &challenge)
        .unwrap();
    let attributes = PassportAttributes::new(2000, 7).with_gate(gate, 2000);
    let blind = issuer
        .issue_blind(&mut rng, &request, &challenge, &attributes)
        .unwrap();
    holder.finish_issuance(&blind).unwrap();
    assert_eq!(holder.attributes(), Some(&attributes));
}

#[test]
fn authentication_rejects_stale_but_signed_requests() {
    use crate::test_support::{signed, signer};
    let mut rng = rng();
    let (_, _, request) = fixture(&mut rng);
    let mut authority = signer(42);
    let expected = AuthenticatedCommunity::from_authenticated_origin(
        community(),
        authority.key_ring().clone(),
    );
    let stale = authority
        .sign(
            csgn::Kind::Credential,
            &request.to_bytes(),
            0,
            request.now() + 5,
        )
        .unwrap();
    assert_eq!(
        expected.authenticate(&stale, request.now() + 2),
        Err(Error::InvalidPresentationRequest)
    );
    let valid = signed(&mut authority, &request);
    assert_eq!(
        expected
            .authenticate(&valid, request.now())
            .unwrap()
            .to_bytes(),
        request.to_bytes()
    );
}

#[test]
fn trailing_statement_bytes_are_rejected_before_decoding() {
    use crate::wire::{Kind, Writer};
    use ark_serialize::CanonicalSerialize;
    let mut rng = rng();
    let (_, passport, request) = fixture(&mut rng);
    let proof = passport.present_trusted(&mut rng, &request).unwrap();
    let mut signature = Vec::new();
    proof
        .proof
        .signature
        .serialize_compressed(&mut signature)
        .unwrap();
    signature.push(0);
    let mut w = Writer::new(Kind::Presentation);
    w.key_id(proof.key_id());
    w.fixed(&proof.pseudonym().to_bytes());
    w.bytes(&signature);
    w.ark(&proof.proof.pseudonym);
    w.u16(proof.proof.ranges.len() as u16);
    for range in &proof.proof.ranges {
        w.ark(range);
    }
    assert_eq!(
        Presentation::from_bytes(&w.finish_public()).err(),
        Some(Error::Decode("proof shape"))
    );
}

#[test]
fn illformed_proofs_fail_shape_validation() {
    let mut rng = rng();
    let (_, passport, request) = fixture(&mut rng);
    let proof = passport.present_trusted(&mut rng, &request).unwrap();
    let count = proof.proof.ranges.len();
    assert!(crate::proof_wire::well_formed(&proof.proof, count));
    let mut short = proof.proof.clone();
    short.ranges.pop();
    assert!(!crate::proof_wire::well_formed(&short, count));
    let mut partial = proof.proof.clone();
    partial.signature.sc_resp_2 = None;
    assert!(!crate::proof_wire::well_formed(&partial, count));
    let mut oversized = proof.proof.clone();
    let point = oversized.ranges[0].range.V[0];
    oversized.ranges[0].range.V.push(point);
    assert!(!crate::proof_wire::well_formed(&oversized, count));
}

#[tokio::test]
async fn memory_store_reports_scope_and_direct_issuance_outcomes() {
    let store = MemoryStore::new(community(), 10).unwrap();
    assert_eq!(store.community(), &community());
    let tag = HolderSecret::generate(&mut rng()).issuer_tag();
    let absent = VerifiedIssuance {
        nonce: [9; 32],
        binding: [8; 32],
        now: 100,
        person: [1; 32],
        tag,
    };
    assert!(!store.consume_issuance(absent).await.unwrap());
    let present = ChallengeRecord {
        nonce: [9; 32],
        binding: [8; 32],
        expires: 200,
    };
    assert!(store.reserve(present).await.unwrap());
    let mismatched = VerifiedIssuance {
        nonce: [9; 32],
        binding: [7; 32],
        now: 100,
        person: [1; 32],
        tag,
    };
    assert!(!store.consume_issuance(mismatched).await.unwrap());
    let expired = VerifiedIssuance {
        nonce: [9; 32],
        binding: [8; 32],
        now: 201,
        person: [1; 32],
        tag,
    };
    assert!(!store.consume_issuance(expired).await.unwrap());
    let valid = VerifiedIssuance {
        nonce: [9; 32],
        binding: [8; 32],
        now: 100,
        person: [1; 32],
        tag,
    };
    assert!(store.consume_issuance(valid).await.unwrap());
    let consumed = VerifiedIssuance {
        nonce: [9; 32],
        binding: [8; 32],
        now: 100,
        person: [1; 32],
        tag,
    };
    assert!(!store.consume_issuance(consumed).await.unwrap());
}

#[test]
fn verified_issuance_fields_report_tuple() {
    let tag = HolderSecret::generate(&mut rng()).issuer_tag();
    let issuance = VerifiedIssuance {
        nonce: [9; 32],
        binding: [8; 32],
        now: 100,
        person: [1; 32],
        tag,
    };
    assert_eq!(issuance.fields(), ([9; 32], [8; 32], 100, [1; 32], tag));
}

#[tokio::test]
async fn verifier_rejects_duplicate_key_ids() {
    let mut rng = rng();
    let store = MemoryStore::new(community(), 10).unwrap();
    let key = key(&mut rng, "dup");
    assert!(matches!(
        Verifier::new(
            store,
            vec![key.public_key().clone(), key.public_key().clone()]
        ),
        Err(Error::DuplicateKeyId)
    ));
}

#[tokio::test]
async fn verifier_rejects_foreign_community_and_prunes() {
    let mut rng = rng();
    let store = MemoryStore::new(community(), 10).unwrap();
    let (issuer, passport, _) = fixture(&mut rng);
    let verifier = Verifier::new(store, vec![issuer.public_key().clone()]).unwrap();
    let foreign = PresentationRequest::new(
        &mut rng,
        CommunityId::new(b"community-b").unwrap(),
        7,
        [gate()],
        1000,
    )
    .unwrap();
    let proof = passport.present_trusted(&mut rng, &foreign).unwrap();
    assert_eq!(
        verifier.verify(&mut rng, &foreign, &proof, 7, 900).await,
        Err(Error::InvalidChallenge)
    );
    let registered = verifier.request(&mut rng, 7, [gate()], 200).await.unwrap();
    assert_eq!(verifier.prune(199).await.unwrap(), 0);
    assert_eq!(verifier.prune(200).await.unwrap(), 0);
    assert_eq!(verifier.prune(201).await.unwrap(), 1);
    let _ = registered;
}

#[tokio::test]
async fn verifier_request_collision_is_a_conflict() {
    let store = MemoryStore::new(community(), 10).unwrap();
    let verifier = Verifier::new(store, vec![]).unwrap();
    let mut first = StdRng::seed_from_u64(77);
    let mut second = StdRng::seed_from_u64(77);
    let request = verifier
        .request(&mut first, 7, [gate()], 200)
        .await
        .unwrap();
    assert_eq!(request.now(), 200);
    assert_eq!(
        verifier.request(&mut second, 7, [gate()], 200).await,
        Err(Error::ChallengeConflict)
    );
}

#[tokio::test]
async fn issuance_challenge_request_collisions_are_conflicts() {
    let mut rng = rng();
    let store = MemoryStore::new(community(), 10).unwrap();
    let issuer = key(&mut rng, "collision");
    let auth = AuthenticatedIssuance::new([1; 32], [2; 32]);
    let mut first = StdRng::seed_from_u64(78);
    let mut second = StdRng::seed_from_u64(78);
    let challenge = issuance_challenge(&mut first, &store, issuer.public_key(), &auth, 200)
        .await
        .unwrap();
    assert_eq!(
        issuance_challenge(&mut second, &store, issuer.public_key(), &auth, 200).await,
        Err(Error::ChallengeConflict)
    );
    let _ = challenge;
}

#[tokio::test]
async fn a_revoked_issuance_challenge_is_gone_and_foreign_ones_are_untouched() {
    let mut rng = rng();
    let store = MemoryStore::new(community(), 10).unwrap();
    let issuer = key(&mut rng, "revoke");
    let auth = AuthenticatedIssuance::new([1; 32], [2; 32]);
    let other = AuthenticatedIssuance::new([1; 32], [3; 32]);
    let challenge = issuance_challenge(&mut rng, &store, issuer.public_key(), &auth, 200)
        .await
        .unwrap();
    // Another session, a later time and a foreign challenge remove nothing.
    assert_eq!(
        revoke_issuance_challenge(&store, issuer.public_key(), &other, &challenge, 100).await,
        Ok(false)
    );
    assert_eq!(
        revoke_issuance_challenge(&store, issuer.public_key(), &auth, &challenge, 201).await,
        Ok(false)
    );
    let unknown = IssuanceChallenge::generate(&mut rng);
    assert_eq!(
        revoke_issuance_challenge(&store, issuer.public_key(), &auth, &unknown, 100).await,
        Ok(false)
    );
    assert_eq!(
        revoke_issuance_challenge(&store, issuer.public_key(), &auth, &challenge, 100).await,
        Ok(true)
    );
    assert_eq!(
        revoke_issuance_challenge(&store, issuer.public_key(), &auth, &challenge, 100).await,
        Ok(false)
    );
    // The slot is free again for a replacement.
    issuance_challenge(&mut rng, &store, issuer.public_key(), &auth, 200)
        .await
        .unwrap();
}

#[tokio::test]
async fn unreserved_issuance_challenge_is_invalid() {
    let mut rng = rng();
    let store = MemoryStore::new(community(), 10).unwrap();
    let issuer = key(&mut rng, "unreserved");
    let secret = HolderSecret::generate(&mut rng);
    let auth = AuthenticatedIssuance::new([1; 32], [2; 32]);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let (request, _) = request_issue(&mut rng, &secret, issuer.public_key(), &challenge).unwrap();
    assert_eq!(
        issue_blind_once(
            &mut rng,
            &store,
            &issuer,
            &auth,
            &request,
            &challenge,
            &attrs(),
            90
        )
        .await
        .err(),
        Some(Error::InvalidChallenge)
    );
}

struct StubStore {
    community: CommunityId,
    consume_ok: bool,
    issuance_ok: bool,
    consumption_attempts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl ChallengeStore for StubStore {
    fn community(&self) -> &CommunityId {
        &self.community
    }
    async fn reserve(&self, _: ChallengeRecord) -> Result<bool, Error> {
        Ok(true)
    }
    async fn matches(&self, _: [u8; 32], _: [u8; 32], _: Timestamp) -> Result<bool, Error> {
        Ok(true)
    }
    async fn consume(&self, _: [u8; 32], _: [u8; 32], _: Timestamp) -> Result<bool, Error> {
        self.consumption_attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(self.consume_ok)
    }
    async fn prune(&self, _: Timestamp) -> Result<u64, Error> {
        Ok(0)
    }
}

impl IssuanceStore for StubStore {
    async fn consume_issuance(&self, _: VerifiedIssuance) -> Result<bool, Error> {
        self.consumption_attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(self.issuance_ok)
    }
}

#[tokio::test]
async fn lost_consumption_race_fails_closed() {
    let mut rng = rng();
    let (issuer, passport, request) = fixture(&mut rng);
    let proof = passport.present_trusted(&mut rng, &request).unwrap();
    let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let stub = StubStore {
        community: community(),
        consume_ok: false,
        issuance_ok: true,
        consumption_attempts: attempts.clone(),
    };
    let verifier = Verifier::new(stub, vec![issuer.public_key().clone()]).unwrap();
    assert_eq!(
        verifier.verify(&mut rng, &request, &proof, 7, 900).await,
        Err(Error::InvalidChallenge)
    );
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn lost_issuance_consumption_fails_closed() {
    let mut rng = rng();
    let issuer = key(&mut rng, "stub-issuance");
    let secret = HolderSecret::generate(&mut rng);
    let auth = AuthenticatedIssuance::new([1; 32], [2; 32]);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let (request, _) = request_issue(&mut rng, &secret, issuer.public_key(), &challenge).unwrap();
    let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let stub = StubStore {
        community: community(),
        consume_ok: true,
        issuance_ok: false,
        consumption_attempts: attempts.clone(),
    };
    assert_eq!(
        issue_blind_once(
            &mut rng,
            &stub,
            &issuer,
            &auth,
            &request,
            &challenge,
            &attrs(),
            90
        )
        .await
        .err(),
        Some(Error::InvalidChallenge)
    );
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[path = "root_board/tests.rs"]
mod root_board;
