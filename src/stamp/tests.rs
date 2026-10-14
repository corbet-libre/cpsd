//! Stamp tests: real BBS+ issuance and presentations, seeded property loops,
//! hostile provers built from the crate's own building blocks, and refusals.

use std::collections::BTreeSet;

use ark_bls12_381::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use dock_crypto_utils::transcript::Transcript;
use rand::{Rng, SeedableRng, rngs::StdRng, seq::SliceRandom};
use schnorr_pok::{SchnorrCommitment, discrete_log::PokDiscreteLog};

use super::issuance::{
    ISSUANCE_WITNESSES, IssuanceProof, WITNESS_SECRET, bases, request_for_slots, statement,
    transcript,
};
use super::presentation::{StampRequest, prove};
use crate::*;

const COHORT: u64 = 600;
const EPOCH: u64 = 9;
/// 1_000_200 = 1667 * 600 + 0, so the cohort ends at 1_000_800 (a full cohort ahead).
const NOW: Timestamp = 1_000_200;
const EXPIRES: Timestamp = 1_000_800;

fn key(rng: &mut StdRng, name: &str) -> StampIssuerKey {
    StampIssuerKey::generate(rng, KeyId::new(name).unwrap(), COHORT).unwrap()
}

fn scope(n: usize) -> StampScope {
    StampScope::new(
        CommunityId::new(format!("community-{n}")).unwrap(),
        CommunityFingerprint::from_bytes([n as u8; 32]),
    )
}

fn action(rng: &mut StdRng, kind: &str) -> StampAction {
    let mut payload = [0u8; 32];
    rng.fill(&mut payload);
    StampAction::new(
        ActionKind::new(kind).unwrap(),
        PayloadDigest::from_bytes(payload),
        StampSalt::generate(rng),
    )
}

fn digest(secret: &HolderSecret, scope: &StampScope, action: &StampAction) -> StampDigest {
    action.digest(scope.fingerprint(), &secret.pseudonym(scope.community()))
}

/// Issues a stamp through every transport encoding.
fn issue(
    rng: &mut StdRng,
    key: &StampIssuerKey,
    secret: &HolderSecret,
    covered: &[(StampScope, StampAction)],
) -> Stamp {
    let digests: Vec<StampDigest> = covered.iter().map(|(s, a)| digest(secret, s, a)).collect();
    let nonce = IssuanceChallenge::generate(rng);
    let (request, pending) =
        request_stamp(rng, secret, key.public_key(), &nonce, &digests).unwrap();
    let request = StampIssuanceRequest::from_bytes(&request.to_bytes()).unwrap();
    let pending = PendingStamp::from_bytes(&pending.to_bytes()).unwrap();
    let blind = key.issue_blind(rng, &request, &nonce, EPOCH, NOW).unwrap();
    let blind = BlindStamp::from_bytes(&blind.to_bytes()).unwrap();
    assert_eq!((blind.epoch(), blind.expires()), (EPOCH, EXPIRES));
    assert_eq!(blind.key_id(), key.public_key().key_id());
    let stamp = pending.finish(&blind).unwrap();
    Stamp::from_bytes(&stamp.to_bytes()).unwrap()
}

fn covered(rng: &mut StdRng, count: usize) -> Vec<(StampScope, StampAction)> {
    (0..count)
        .map(|n| (scope(n), action(rng, "lineage.pair")))
        .collect()
}

fn verify_one(
    key: &StampIssuerKey,
    scope: &StampScope,
    action: &StampAction,
    presentation: &StampPresentation,
) -> Result<VerifiedStamp, Error> {
    verify_stamp(
        &[key.public_key().clone()],
        scope,
        EPOCH,
        action,
        presentation,
        NOW,
    )
}

fn roundtrip(presentation: &StampPresentation) -> StampPresentation {
    StampPresentation::from_bytes(&presentation.to_bytes()).unwrap()
}

#[test]
fn one_stamp_approves_one_action_in_each_of_sixteen_communities() {
    let mut rng = StdRng::seed_from_u64(1);
    let key = key(&mut rng, "stamp-1");
    let secret = HolderSecret::generate(&mut rng);
    let covered = covered(&mut rng, STAMP_SLOTS);
    let stamp = issue(&mut rng, &key, &secret, &covered);
    assert_eq!(
        (stamp.key_id(), stamp.epoch(), stamp.expires()),
        (key.public_key().key_id(), EPOCH, EXPIRES)
    );
    assert_eq!(stamp.issuer(), key.public_key());
    let mut slots = BTreeSet::new();
    for (scope, action) in &covered {
        assert!(stamp.covers(scope, action));
        let presentation = roundtrip(&stamp.present(&mut rng, scope, action).unwrap());
        assert_eq!(presentation.key_id(), key.public_key().key_id());
        assert_eq!(
            (presentation.epoch(), presentation.expires()),
            (EPOCH, EXPIRES)
        );
        assert_eq!(
            presentation.pseudonym(),
            &secret.pseudonym(scope.community())
        );
        slots.insert(presentation.slot());
        let verified = verify_one(&key, scope, action, &presentation).unwrap();
        assert_eq!(verified.pseudonym(), &secret.pseudonym(scope.community()));
        assert_eq!(verified.community(), scope.community());
        assert_eq!(verified.digest(), &digest(&secret, scope, action));
        assert_eq!(verified.action_kind(), action.kind());
        assert_eq!(verified.key_id(), key.public_key().key_id());
        assert_eq!((verified.epoch(), verified.expires()), (EPOCH, EXPIRES));
        assert!(format!("{verified:?}").contains("VerifiedStamp"));
        assert!(format!("{presentation:?}").contains("slot"));
    }
    // Sixteen digests occupy sixteen distinct slots.
    assert_eq!(slots.len(), STAMP_SLOTS);
}

/// Every proof element of a presentation as bytes, for overlap checks.
fn proof_elements(p: &StampPresentation) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut push = |value: &dyn Fn(&mut Vec<u8>)| {
        let mut bytes = Vec::new();
        value(&mut bytes);
        out.push(bytes);
    };
    let s = &p.proof.signature;
    push(&|b| s.A_prime.serialize_compressed(b).unwrap());
    push(&|b| s.A_bar.serialize_compressed(b).unwrap());
    push(&|b| s.d.serialize_compressed(b).unwrap());
    push(&|b| s.sc_resp_1.t.serialize_compressed(b).unwrap());
    push(&|b| s.sc_resp_1.response1.serialize_compressed(b).unwrap());
    push(&|b| s.sc_resp_1.response2.serialize_compressed(b).unwrap());
    push(&|b| s.T2.serialize_compressed(b).unwrap());
    for response in &s.sc_resp_2.as_ref().unwrap().0 {
        push(&|b| response.serialize_compressed(b).unwrap());
    }
    push(&|b| p.proof.pseudonym.t.serialize_compressed(b).unwrap());
    push(&|b| p.proof.pseudonym.response.serialize_compressed(b).unwrap());
    push(&|b| b.extend_from_slice(&p.pseudonym.to_bytes()));
    out
}

#[test]
fn presentations_of_one_stamp_share_only_key_epoch_and_cohort_across_communities() {
    for seed in 0..4u64 {
        let mut rng = StdRng::seed_from_u64(100 + seed);
        let key = key(&mut rng, "stamp-u");
        let secret = HolderSecret::generate(&mut rng);
        let count = rng.gen_range(2..=STAMP_SLOTS);
        let covered = covered(&mut rng, count);
        let stamp = issue(&mut rng, &key, &secret, &covered);
        let mut picks: Vec<usize> = (0..count).collect();
        picks.shuffle(&mut rng);
        let (a, b) = (&covered[picks[0]], &covered[picks[1]]);
        let pa = stamp.present(&mut rng, &a.0, &a.1).unwrap();
        let pb = stamp.present(&mut rng, &b.0, &b.1).unwrap();
        // Shared public metadata only.
        assert_eq!(
            (pa.key_id(), pa.epoch(), pa.expires()),
            (pb.key_id(), pb.epoch(), pb.expires())
        );
        assert_ne!(pa.pseudonym(), pb.pseudonym());
        assert_ne!(pa.slot(), pb.slot());
        let ea = proof_elements(&pa);
        let eb = proof_elements(&pb);
        let shared: Vec<_> = ea.iter().filter(|e| eb.contains(e)).collect();
        assert!(shared.is_empty(), "seed {seed}: proof elements repeat");
        // A different holder's stamp from the same key, epoch and cohort has
        // exactly the same observable shape.
        let other_secret = HolderSecret::generate(&mut rng);
        let other = issue(&mut rng, &key, &other_secret, &covered[..1]);
        let po = other
            .present(&mut rng, &covered[0].0, &covered[0].1)
            .unwrap();
        assert_eq!(po.to_bytes().len(), pa.to_bytes().len());
        assert_eq!(
            (po.key_id(), po.epoch(), po.expires()),
            (pa.key_id(), pa.epoch(), pa.expires())
        );
        // Presenting the same slot twice re-randomises everything but the
        // pseudonym, which is the community's stable member ID by design.
        let again = stamp.present(&mut rng, &a.0, &a.1).unwrap();
        assert_eq!(again.pseudonym(), pa.pseudonym());
        assert_eq!(again.slot(), pa.slot());
        let repeated: Vec<_> = proof_elements(&again)
            .into_iter()
            .filter(|e| ea.contains(e))
            .collect();
        assert_eq!(repeated, vec![pa.pseudonym().to_bytes().to_vec()]);
    }
}

fn forged_presentation(
    rng: &mut StdRng,
    stamp: &Stamp,
    scope: &StampScope,
    slot: usize,
    digest: StampDigest,
) -> StampPresentation {
    let pseudonym = stamp.secret.pseudonym(scope.community());
    let request = StampRequest::with_challenge(
        scope.community(),
        stamp.epoch(),
        stamp.expires(),
        slot,
        digest,
    );
    let proof = prove(rng, stamp, &request, &pseudonym.point().unwrap()).unwrap();
    StampPresentation {
        key_id: stamp.key_id().clone(),
        epoch: stamp.epoch(),
        expires: stamp.expires(),
        slot,
        pseudonym,
        proof,
    }
}

#[test]
fn a_presentation_for_one_slot_cannot_reveal_or_forge_another() {
    for seed in 0..4u64 {
        let mut rng = StdRng::seed_from_u64(200 + seed);
        let key = key(&mut rng, "stamp-s");
        let secret = HolderSecret::generate(&mut rng);
        let count = rng.gen_range(2..=STAMP_SLOTS);
        let covered = covered(&mut rng, count);
        let stamp = issue(&mut rng, &key, &secret, &covered);
        let i = rng.gen_range(0..count);
        let j = (i + rng.gen_range(1..count)) % count;
        let (si, ai) = &covered[i];
        let (sj, aj) = &covered[j];
        let honest = stamp.present(&mut rng, si, ai).unwrap();
        let slot_j = stamp.present(&mut rng, sj, aj).unwrap().slot();
        // The proof for slot i says nothing about action j, in any scope.
        assert_eq!(
            verify_one(&key, si, aj, &honest).err(),
            Some(Error::InvalidProof)
        );
        assert_eq!(
            verify_one(&key, sj, aj, &honest).err(),
            Some(Error::InvalidProof)
        );
        // Re-labelling the revealed index fails for both actions.
        let mut moved = honest.clone();
        moved.slot = slot_j;
        let moved = roundtrip(&moved);
        assert_eq!(
            verify_one(&key, si, ai, &moved).err(),
            Some(Error::InvalidProof)
        );
        assert_eq!(
            verify_one(&key, sj, aj, &moved).err(),
            Some(Error::InvalidProof)
        );
        // A cheating prover claiming digest i at slot j, or digest j at slot i,
        // or a digest the stamp never carried, is refused.
        let d_i = digest(&secret, si, ai);
        let d_j = digest(&secret, sj, aj);
        let forged = forged_presentation(&mut rng, &stamp, si, slot_j, d_i);
        assert_eq!(
            verify_one(&key, si, ai, &forged).err(),
            Some(Error::InvalidProof)
        );
        let forged = forged_presentation(&mut rng, &stamp, sj, honest.slot(), d_j);
        assert_eq!(
            verify_one(&key, sj, aj, &forged).err(),
            Some(Error::InvalidProof)
        );
        let foreign = action(&mut rng, "lineage.pair");
        assert!(!stamp.covers(si, &foreign));
        assert_eq!(
            stamp.present(&mut rng, si, &foreign).err(),
            Some(Error::StampDigestMissing)
        );
        let forged = forged_presentation(
            &mut rng,
            &stamp,
            si,
            honest.slot(),
            digest(&secret, si, &foreign),
        );
        assert_eq!(
            verify_one(&key, si, &foreign, &forged).err(),
            Some(Error::InvalidProof)
        );
        // The honest presentation still verifies after all of the above.
        verify_one(&key, si, ai, &honest).unwrap();
    }
}

#[test]
fn tampered_challenge_scope_epoch_key_or_proof_fails() {
    let mut rng = StdRng::seed_from_u64(3);
    let key = key(&mut rng, "stamp-t");
    let secret = HolderSecret::generate(&mut rng);
    let covered = covered(&mut rng, 2);
    let stamp = issue(&mut rng, &key, &secret, &covered);
    let (scope, act) = &covered[0];
    let p = stamp.present(&mut rng, scope, act).unwrap();
    let ring = [key.public_key().clone()];
    let check = |scope: &StampScope, act: &StampAction, p: &StampPresentation| {
        verify_stamp(&ring, scope, EPOCH, act, p, NOW).err()
    };
    // Every digest input is bound: kind, payload, salt, fingerprint, community.
    let tampered = [
        StampAction::new(
            ActionKind::new("device.revoke").unwrap(),
            *act.payload(),
            *act.salt(),
        ),
        StampAction::new(
            act.kind().clone(),
            PayloadDigest::from_bytes([1; 32]),
            *act.salt(),
        ),
        StampAction::new(
            act.kind().clone(),
            *act.payload(),
            StampSalt::from_bytes([2; 32]),
        ),
    ];
    for other in &tampered {
        assert_eq!(check(scope, other, &p), Some(Error::InvalidProof));
    }
    let wrong_fingerprint = StampScope::new(
        scope.community().clone(),
        CommunityFingerprint::from_bytes([0xee; 32]),
    );
    assert_eq!(
        check(&wrong_fingerprint, act, &p),
        Some(Error::InvalidProof)
    );
    let wrong_community =
        StampScope::new(CommunityId::new("elsewhere").unwrap(), *scope.fingerprint());
    assert_eq!(check(&wrong_community, act, &p), Some(Error::InvalidProof));
    // Epoch, key ring and expiry window.
    assert_eq!(
        verify_stamp(&ring, scope, EPOCH + 1, act, &p, NOW).err(),
        Some(Error::WrongEpoch)
    );
    assert_eq!(
        verify_stamp(&[], scope, EPOCH, act, &p, NOW).err(),
        Some(Error::UnknownKey)
    );
    let twice = [key.public_key().clone(), key.public_key().clone()];
    assert_eq!(
        verify_stamp(&twice, scope, EPOCH, act, &p, NOW).err(),
        Some(Error::DuplicateKeyId)
    );
    let other_key = self::key(&mut rng, "stamp-t");
    assert_eq!(
        verify_stamp(
            &[other_key.public_key().clone()],
            scope,
            EPOCH,
            act,
            &p,
            NOW
        )
        .err(),
        Some(Error::InvalidProof)
    );
    assert_eq!(
        verify_stamp(&ring, scope, EPOCH, act, &p, EXPIRES).err(),
        Some(Error::StampExpired)
    );
    assert_eq!(
        verify_stamp(&ring, scope, EPOCH, act, &p, EXPIRES - 2 * COHORT - 1).err(),
        Some(Error::WrongExpiryCohort)
    );
    verify_stamp(&ring, scope, EPOCH, act, &p, EXPIRES - 2 * COHORT).unwrap();
    verify_stamp(&ring, scope, EPOCH, act, &p, EXPIRES - 1).unwrap();
    assert_eq!(
        verify_stamp(&ring, scope, EPOCH, act, &p, 0).err(),
        Some(Error::InvalidTimestamp)
    );
    // Revealed metadata cannot be rewritten.
    let mut q = p.clone();
    q.epoch = EPOCH + 1;
    assert_eq!(
        verify_stamp(&ring, scope, EPOCH + 1, act, &q, NOW).err(),
        Some(Error::InvalidProof)
    );
    let mut q = p.clone();
    q.expires = EXPIRES + COHORT;
    assert_eq!(check(scope, act, &q), Some(Error::InvalidProof));
    let mut q = p.clone();
    q.pseudonym = secret.pseudonym(covered[1].0.community());
    assert_eq!(check(scope, act, &q), Some(Error::InvalidProof));
    // Each relation of the proof is checked on its own.
    let mut q = p.clone();
    q.proof.pseudonym.response += Fr::from(1u64);
    assert_eq!(check(scope, act, &q), Some(Error::InvalidProof));
    let mut q = p.clone();
    q.proof.pseudonym.t = (q.proof.pseudonym.t + G1Affine::generator()).into_affine();
    assert_eq!(check(scope, act, &q), Some(Error::InvalidProof));
    let mut q = p.clone();
    q.proof.signature.A_bar = (q.proof.signature.A_bar + G1Affine::generator()).into_affine();
    assert_eq!(check(scope, act, &q), Some(Error::InvalidProof));
    // Any single flipped bit in the encoding is refused (decode or proof).
    let bytes = p.to_bytes();
    for index in (6..bytes.len()).step_by(29) {
        let mut flipped = bytes.clone();
        flipped[index] ^= 0x10;
        let refused = StampPresentation::from_bytes(&flipped)
            .and_then(|q| verify_stamp(&ring, scope, EPOCH, act, &q, NOW));
        assert!(refused.is_err(), "bit flip at {index} accepted");
    }
    assert_eq!(check(scope, act, &p), None);
}

/// A hostile issuance request whose tag proof carries an arbitrary Schnorr
/// commitment but the honest shared response.
fn request_with_bogus_tag_commitment(
    rng: &mut StdRng,
    secret: &HolderSecret,
    key: &StampPublicKey,
    nonce: &IssuanceChallenge,
) -> StampIssuanceRequest {
    let params = key.signature_params();
    let slots: Vec<Fr> = (0..STAMP_SLOTS).map(|_| Fr::rand(rng)).collect();
    let blinding = Fr::rand(rng);
    let hidden = core::iter::once((crate::params::IDX_SECRET, &secret.0)).chain(
        slots
            .iter()
            .enumerate()
            .map(|(i, s)| (crate::params::STAMP_IDX_FIRST_SLOT + i, s)),
    );
    let commitment = params.commit_to_messages(hidden, &blinding).unwrap();
    let tag = (crate::params::issuer_tag_base() * secret.0).into_affine();
    let bases = bases(params);
    let mut witnesses = vec![blinding, secret.0];
    witnesses.extend_from_slice(&slots);
    let randomness: Vec<Fr> = (0..ISSUANCE_WITNESSES).map(|_| Fr::rand(rng)).collect();
    let opening = SchnorrCommitment::new(&bases, randomness);
    let bogus_t = (G1Affine::generator() * Fr::rand(rng)).into_affine();
    let mut t = transcript(key, nonce);
    statement(&mut t, &bases, &commitment, &opening.t, &tag, &bogus_t);
    let c = t.challenge_scalar::<Fr>(b"challenge");
    let responses = opening.response(&witnesses, &c).unwrap();
    let shared = responses.0[WITNESS_SECRET];
    StampIssuanceRequest {
        key_id: key.key_id().clone(),
        commitment,
        issuer_tag: tag,
        proof: IssuanceProof {
            t: opening.t,
            responses,
            tag: PokDiscreteLog {
                t: bogus_t,
                response: shared,
            },
        },
    }
}

#[test]
fn issuance_proof_binds_opening_tag_secret_key_and_nonce() {
    let mut rng = StdRng::seed_from_u64(4);
    let key = key(&mut rng, "stamp-i");
    let secret = HolderSecret::generate(&mut rng);
    let attacker = HolderSecret::generate(&mut rng);
    let nonce = IssuanceChallenge::generate(&mut rng);
    let d = [digest(
        &secret,
        &scope(0),
        &action(&mut rng, "lineage.pair"),
    )];
    let (honest, _) = request_stamp(&mut rng, &secret, key.public_key(), &nonce, &d).unwrap();
    assert_eq!(honest.key_id(), key.public_key().key_id());
    assert_eq!(honest.issuer_tag(), secret.issuer_tag());
    assert!(format!("{honest:?}").contains("issuer_tag"));
    let refuse = |request: &StampIssuanceRequest, nonce: &IssuanceChallenge| {
        key.issue_blind(&mut StdRng::seed_from_u64(0), request, nonce, EPOCH, NOW)
            .err()
    };
    // Bound to the wallet's nonce and the addressed key.
    let other_nonce = IssuanceChallenge::generate(&mut rng);
    assert_eq!(
        refuse(&honest, &other_nonce),
        Some(Error::InvalidIssuanceRequest)
    );
    let other_key = self::key(&mut rng, "stamp-other");
    assert_eq!(
        other_key
            .issue_blind(&mut rng, &honest, &nonce, EPOCH, NOW)
            .err(),
        Some(Error::KeyMismatch)
    );
    // The commitment's secret and the tag's secret must coincide.
    let slots = [Fr::from(3u64); STAMP_SLOTS];
    let (mixed, _) = request_for_slots(
        &mut rng,
        &attacker,
        &secret,
        key.public_key(),
        &nonce,
        &slots,
    )
    .unwrap();
    assert_eq!(mixed.issuer_tag(), secret.issuer_tag());
    assert_eq!(refuse(&mixed, &nonce), Some(Error::InvalidIssuanceRequest));
    // Swapping in another member's tag point breaks the proof.
    let mut swapped = honest.clone();
    swapped.issuer_tag = (crate::params::issuer_tag_base() * attacker.0).into_affine();
    assert_eq!(
        refuse(&swapped, &nonce),
        Some(Error::InvalidIssuanceRequest)
    );
    // Each relation is checked on its own: shared response, tag proof, opening.
    let mut q = honest.clone();
    q.proof.tag.response += Fr::from(1u64);
    assert_eq!(refuse(&q, &nonce), Some(Error::InvalidIssuanceRequest));
    let bogus = request_with_bogus_tag_commitment(&mut rng, &secret, key.public_key(), &nonce);
    assert_eq!(refuse(&bogus, &nonce), Some(Error::InvalidIssuanceRequest));
    let mut q = honest.clone();
    q.proof.responses.0[0] += Fr::from(1u64);
    assert_eq!(refuse(&q, &nonce), Some(Error::InvalidIssuanceRequest));
    let mut q = honest.clone();
    q.commitment = (q.commitment + G1Affine::generator()).into_affine();
    assert_eq!(refuse(&q, &nonce), Some(Error::InvalidIssuanceRequest));
    // The commitment cannot reach the issuer's attributes: a request that
    // adds the expiry generator verifies nowhere.
    let mut q = honest.clone();
    q.commitment = (q.commitment
        + key.public_key().signature_params().h[crate::params::STAMP_IDX_EXPIRY])
        .into_affine();
    assert_eq!(refuse(&q, &nonce), Some(Error::InvalidIssuanceRequest));
    // Unusable clock values are refused before any proof work.
    assert_eq!(
        key.issue_blind(&mut rng, &honest, &nonce, EPOCH, 0).err(),
        Some(Error::InvalidTimestamp)
    );
    key.issue_blind(&mut rng, &honest, &nonce, EPOCH, NOW)
        .unwrap();
}

#[test]
fn request_digest_lists_and_confirmation_challenge() {
    let mut rng = StdRng::seed_from_u64(5);
    let key = key(&mut rng, "stamp-r");
    let secret = HolderSecret::generate(&mut rng);
    let nonce = IssuanceChallenge::generate(&mut rng);
    let digests: Vec<StampDigest> = (0..=STAMP_SLOTS)
        .map(|n| digest(&secret, &scope(n), &action(&mut rng, "lineage.pair")))
        .collect();
    for bad in [
        &digests[..0],
        &digests[..],
        &[digests[0], digests[1], digests[0]][..],
    ] {
        assert_eq!(
            request_stamp(&mut rng, &secret, key.public_key(), &nonce, bad).err(),
            Some(Error::InvalidStamp)
        );
    }
    let (request, _) =
        request_stamp(&mut rng, &secret, key.public_key(), &nonce, &digests[..1]).unwrap();
    let (again, _) =
        request_stamp(&mut rng, &secret, key.public_key(), &nonce, &digests[..1]).unwrap();
    let challenge = request.confirmation_challenge(&nonce);
    assert_eq!(challenge, request.confirmation_challenge(&nonce));
    assert_ne!(challenge, again.confirmation_challenge(&nonce));
    assert_ne!(
        challenge,
        request.confirmation_challenge(&IssuanceChallenge::from_bytes([0; 32]))
    );
}

#[test]
fn unblinding_checks_key_grid_and_signature() {
    let mut rng = StdRng::seed_from_u64(6);
    let key = key(&mut rng, "stamp-b");
    let secret = HolderSecret::generate(&mut rng);
    let nonce = IssuanceChallenge::generate(&mut rng);
    let d = [digest(
        &secret,
        &scope(0),
        &action(&mut rng, "lineage.pair"),
    )];
    let pending = || {
        let (request, pending) = request_stamp(
            &mut StdRng::seed_from_u64(9),
            &secret,
            key.public_key(),
            &nonce,
            &d,
        )
        .unwrap();
        (request, pending)
    };
    let (request, _) = pending();
    let blind = key
        .issue_blind(&mut rng, &request, &nonce, EPOCH, NOW)
        .unwrap();
    assert!(format!("{blind:?}").contains("BlindStamp"));
    assert!(format!("{:?}", pending().1).contains("PendingStamp"));
    let mut wrong = blind.clone();
    wrong.key_id = KeyId::new("other").unwrap();
    assert_eq!(pending().1.finish(&wrong).err(), Some(Error::KeyMismatch));
    let mut off_grid = blind.clone();
    off_grid.expires += 1;
    assert_eq!(
        pending().1.finish(&off_grid).err(),
        Some(Error::InvalidStamp)
    );
    let mut later = blind.clone();
    later.expires += COHORT;
    assert_eq!(
        pending().1.finish(&later).err(),
        Some(Error::InvalidSignature)
    );
    let mut epoch = blind.clone();
    epoch.epoch += 1;
    assert_eq!(
        pending().1.finish(&epoch).err(),
        Some(Error::InvalidSignature)
    );
    let stamp = pending().1.finish(&blind).unwrap();
    assert!(format!("{stamp:?}").contains("Stamp"));
    assert!(!format!("{stamp:?}").contains("secret"));
}

#[test]
fn cohort_rule_for_issuer_holder_and_verifier() {
    let mut rng = StdRng::seed_from_u64(7);
    for bad in [
        0,
        MIN_STAMP_COHORT_SECONDS - 1,
        MAX_STAMP_COHORT_SECONDS + 1,
    ] {
        assert_eq!(
            StampIssuerKey::generate(&mut rng, KeyId::new("k").unwrap(), bad).err(),
            Some(Error::InvalidStamp)
        );
    }
    for good in [MIN_STAMP_COHORT_SECONDS, MAX_STAMP_COHORT_SECONDS] {
        let k = StampIssuerKey::generate(&mut rng, KeyId::new("k").unwrap(), good).unwrap();
        assert_eq!(k.public_key().cohort_seconds(), good);
    }
    let key = key(&mut rng, "stamp-c");
    let public = key.public_key();
    // At least half a cohort left: the current cohort's end.
    assert_eq!(public.expiry_for(1_000_200).unwrap(), 1_000_800);
    assert_eq!(public.expiry_for(1_000_500).unwrap(), 1_000_800);
    assert_eq!(public.expiry_for(1_000_800).unwrap(), 1_001_400);
    // Less than half left: the next cohort's end.
    assert_eq!(public.expiry_for(1_000_501).unwrap(), 1_001_400);
    assert_eq!(public.expiry_for(1_000_799).unwrap(), 1_001_400);
    assert_eq!(public.expiry_for(0).err(), Some(Error::InvalidTimestamp));
    assert_eq!(
        public.expiry_for(TIME_LIMIT - 1).err(),
        Some(Error::InvalidTimestamp)
    );
    // Every issuer choice is accepted by verifiers for its whole life.
    for now in [1_000_200, 1_000_501, 1_000_799, 1_000_800] {
        let expires = public.expiry_for(now).unwrap();
        for t in [now, expires - 1] {
            public.check_expiry(expires, t).unwrap();
        }
        assert_eq!(
            public.check_expiry(expires, expires),
            Err(Error::StampExpired)
        );
    }
    assert_eq!(
        public.check_expiry(1_000_801, 1_000_200),
        Err(Error::WrongExpiryCohort)
    );
    assert_eq!(
        public.check_expiry(1_002_000, 1_000_200),
        Err(Error::WrongExpiryCohort)
    );
    assert_eq!(
        public.check_expiry(1_000_800, 0),
        Err(Error::InvalidTimestamp)
    );
    public.check_alignment(1_000_800).unwrap();
    assert_eq!(public.check_alignment(1_000_801), Err(Error::InvalidStamp));
    assert_eq!(public.check_alignment(0), Err(Error::InvalidTimestamp));
}

#[test]
fn keys_encode_validate_and_stay_apart_from_passport_keys() {
    let mut rng = StdRng::seed_from_u64(8);
    let key = key(&mut rng, "stamp-k");
    let public = key.public_key();
    assert_eq!(
        &StampPublicKey::from_bytes(&public.to_bytes()).unwrap(),
        public
    );
    let restored = StampIssuerKey::from_secret_bytes(&key.to_secret_bytes()).unwrap();
    assert_eq!(restored.public_key(), public);
    assert!(format!("{key:?}").contains("cohort_seconds"));
    assert!(!format!("{key:?}").contains("secret"));
    let other = self::key(&mut rng, "stamp-k");
    assert_ne!(other.public_key(), public);
    let renamed = self::key(&mut rng, "stamp-k2");
    assert_ne!(renamed.public_key(), public);
    let longer =
        StampIssuerKey::generate(&mut rng, KeyId::new("stamp-k").unwrap(), COHORT + 60).unwrap();
    assert_ne!(longer.public_key(), public);
    // Zero secret and out-of-range cohort encodings are refused.
    let mut bytes = key.to_secret_bytes().to_vec();
    let at = bytes.len() - 32;
    bytes[at..].fill(0);
    assert_eq!(
        StampIssuerKey::from_secret_bytes(&bytes).err(),
        Some(Error::InvalidKey)
    );
    let mut bytes = public.to_bytes();
    let cohort_at = 6 + 4 + "stamp-k".len();
    bytes[cohort_at..cohort_at + 8].copy_from_slice(&59u64.to_be_bytes());
    assert_eq!(
        StampPublicKey::from_bytes(&bytes).err(),
        Some(Error::InvalidStamp)
    );
    // Same key ID and secret derivation domain never yield passport generators.
    let passport = IssuerKey::generate(&mut rng, KeyId::new("stamp-k").unwrap(), vec![]).unwrap();
    assert_ne!(
        passport.public_key().signature_params().h_0,
        public.signature_params().h_0
    );
    assert!(IssuerPublicKey::from_bytes(&public.to_bytes()).is_err());
    assert!(StampPublicKey::from_bytes(&passport.public_key().to_bytes()).is_err());
    assert!(StampIssuerKey::from_secret_bytes(&passport.to_secret_bytes()).is_err());
    assert_eq!(public.to_bytes()[4], 4, "stamp envelope version");
}

/// All strict prefixes fail, one trailing byte fails, and a foreign kind byte fails.
fn assert_strict<T>(bytes: &[u8], decode: impl Fn(&[u8]) -> Result<T, Error>) {
    assert!(decode(bytes).is_ok());
    for len in 0..bytes.len() {
        assert!(decode(&bytes[..len]).is_err(), "prefix {len} accepted");
    }
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert_eq!(decode(&longer).err(), Some(Error::Decode("trailing bytes")));
    let mut kind = bytes.to_vec();
    kind[5] = 9;
    assert_eq!(decode(&kind).err(), Some(Error::Decode("object kind")));
    let mut version = bytes.to_vec();
    version[4] = 3;
    assert_eq!(
        decode(&version).err(),
        Some(Error::Decode("format version"))
    );
}

#[test]
fn every_stamp_encoding_is_strict() {
    let mut rng = StdRng::seed_from_u64(10);
    let key = key(&mut rng, "stamp-w");
    let secret = HolderSecret::generate(&mut rng);
    let (s, a) = (scope(0), action(&mut rng, "lineage.pair"));
    let nonce = IssuanceChallenge::generate(&mut rng);
    let (request, pending) = request_stamp(
        &mut rng,
        &secret,
        key.public_key(),
        &nonce,
        &[digest(&secret, &s, &a)],
    )
    .unwrap();
    let blind = key
        .issue_blind(&mut rng, &request, &nonce, EPOCH, NOW)
        .unwrap();
    let pending_bytes = pending.to_bytes();
    let stamp = pending.finish(&blind).unwrap();
    let presentation = stamp.present(&mut rng, &s, &a).unwrap();
    assert_strict(&key.public_key().to_bytes(), StampPublicKey::from_bytes);
    assert_strict(&key.to_secret_bytes(), StampIssuerKey::from_secret_bytes);
    assert_strict(&request.to_bytes(), StampIssuanceRequest::from_bytes);
    assert_strict(&blind.to_bytes(), BlindStamp::from_bytes);
    assert_strict(&pending_bytes, PendingStamp::from_bytes);
    assert_strict(&stamp.to_bytes(), Stamp::from_bytes);
    assert_strict(&presentation.to_bytes(), StampPresentation::from_bytes);

    // Identity commitment or tag.
    for identity in [true, false] {
        let mut q = request.clone();
        if identity {
            q.commitment = G1Affine::zero();
        } else {
            q.issuer_tag = G1Affine::zero();
        }
        assert_eq!(
            StampIssuanceRequest::from_bytes(&q.to_bytes()).err(),
            Some(Error::Decode("identity element"))
        );
    }
    // Wrong issuance proof length.
    let mut q = request.clone();
    q.proof.responses.0.pop();
    assert_eq!(
        StampIssuanceRequest::from_bytes(&q.to_bytes()).err(),
        Some(Error::Decode("stamp issuance proof shape"))
    );
    // Slot index, signature response count and pseudonym proof length.
    let mut q = presentation.clone();
    q.slot = STAMP_SLOTS;
    assert_eq!(
        StampPresentation::from_bytes(&q.to_bytes()).err(),
        Some(Error::Decode("stamp slot"))
    );
    let mut q = presentation.clone();
    q.proof.signature.sc_resp_2.as_mut().unwrap().0.pop();
    assert_eq!(
        StampPresentation::from_bytes(&q.to_bytes()).err(),
        Some(Error::Decode("signature responses"))
    );
    let mut bytes = presentation.to_bytes();
    let tail = bytes.len() - 80;
    bytes.truncate(tail);
    bytes.truncate(bytes.len() - 4);
    bytes.extend_from_slice(&79u32.to_be_bytes());
    bytes.extend_from_slice(&[0; 79]);
    assert_eq!(
        StampPresentation::from_bytes(&bytes).err(),
        Some(Error::Decode("pseudonym proof shape"))
    );
    // A non-canonical point (identity flag with payload bits) is refused
    // even where upstream decoding accepts it.
    let mut bytes = presentation.to_bytes();
    let nym = bytes.len() - 80;
    bytes[nym..nym + 48].fill(0);
    bytes[nym] = 0xc0;
    bytes[nym + 47] = 1;
    assert_eq!(
        StampPresentation::from_bytes(&bytes).err(),
        Some(Error::Decode("noncanonical proof"))
    );
    // Zero holder secrets are refused on restore.
    let mut zero = pending_bytes.to_vec();
    zero[10..42].fill(0);
    assert_eq!(
        PendingStamp::from_bytes(&zero).err(),
        Some(Error::InvalidKey)
    );
    let mut zero = stamp.to_bytes().to_vec();
    zero[10..42].fill(0);
    assert_eq!(Stamp::from_bytes(&zero).err(), Some(Error::InvalidKey));
    // Passport objects never decode as stamp objects.
    assert!(StampPresentation::from_bytes(&request.to_bytes()).is_err());
}

#[test]
fn digest_known_answers_and_typed_inputs() {
    // Independently computed (Python hashlib.blake2s over the documented
    // length-prefixed encoding); the member is the G1 generator.
    let member =
        Pseudonym::from_bytes(&crate::issuer::point_bytes(&G1Affine::generator())).unwrap();
    let mut fingerprint = [0u8; 32];
    for (i, b) in fingerprint.iter_mut().enumerate() {
        *b = i as u8;
    }
    let fingerprint = CommunityFingerprint::from_bytes(fingerprint);
    let payload = PayloadDigest::from_bytes([0xaa; 32]);
    let salt = StampSalt::from_bytes([0x55; 32]);
    let hex = |d: StampDigest| crate::wire::hex(&d.to_bytes());
    let pair = ActionKind::new("lineage.pair").unwrap();
    assert_eq!(
        hex(StampDigest::compute(
            &fingerprint,
            &member,
            &pair,
            &payload,
            &salt
        )),
        "b85086223e7684c6b6c874a6fc2abae543c145927f5e0c403c95811c379bcc13"
    );
    let revoke = ActionKind::new("device.revoke").unwrap();
    let action = StampAction::new(revoke.clone(), payload, salt);
    assert_eq!(
        hex(action.digest(&fingerprint, &member)),
        "f66f9bbea233bd280c450840fe4af5f1856ed5b6fd6dd3d4861b96315e942f3f"
    );
    let d = action.digest(&fingerprint, &member);
    assert_eq!(StampDigest::from_bytes(d.to_bytes()), d);
    assert_eq!(fingerprint.to_bytes()[31], 31);
    assert_eq!(payload.to_bytes(), [0xaa; 32]);
    assert_eq!(salt.to_bytes(), [0x55; 32]);
    assert_eq!(action.kind(), &revoke);
    // Debug never shows the salt.
    assert_eq!(format!("{salt:?}"), "StampSalt(<redacted>)");
    assert!(!format!("{action:?}").contains("55555555"));
    assert!(format!("{d:?}").starts_with("StampDigest(f66f"));
    assert!(format!("{fingerprint:?}").starts_with("CommunityFingerprint(0001"));
    assert!(format!("{payload:?}").starts_with("PayloadDigest(aaaa"));
    assert_eq!(format!("{revoke:?}"), "ActionKind(device.revoke)");
    let scope = StampScope::new(CommunityId::new("c").unwrap(), fingerprint);
    assert!(format!("{scope:?}").contains("fingerprint"));
    // The action kind uses the gate alphabet.
    for good in [
        "a",
        "z9",
        "a.b",
        "a_b",
        "a-b",
        &"k".repeat(MAX_ACTION_KIND_LEN),
    ] {
        assert_eq!(ActionKind::new(good).unwrap().as_str(), good);
    }
    for bad in ["", "A", "a b", "a/b", &"k".repeat(MAX_ACTION_KIND_LEN + 1)] {
        assert_eq!(
            ActionKind::new(bad).err(),
            Some(Error::InvalidIdentifier("action kind"))
        );
    }
    // Fresh salts differ.
    let mut rng = StdRng::seed_from_u64(11);
    assert_ne!(StampSalt::generate(&mut rng), StampSalt::generate(&mut rng));
}

#[tokio::test]
async fn wallet_issuance_binds_member_tag_and_single_use_nonce() {
    let mut rng = StdRng::seed_from_u64(12);
    let store = MemoryStore::new(CommunityId::new("wallet").unwrap(), 20).unwrap();
    let key = key(&mut rng, "stamp-w");
    let secret = HolderSecret::generate(&mut rng);
    let auth = AuthenticatedStampIssuance::new([1; 32], [2; 32], secret.issuer_tag());
    assert_eq!(
        format!("{auth:?}"),
        "AuthenticatedStampIssuance(<redacted>)"
    );
    let d = [digest(
        &secret,
        &scope(0),
        &action(&mut rng, "lineage.pair"),
    )];
    assert_eq!(
        stamp_issuance_challenge(&mut rng, &store, key.public_key(), &auth, 0)
            .await
            .err(),
        Some(Error::InvalidTimestamp)
    );
    let nonce = stamp_issuance_challenge(&mut rng, &store, key.public_key(), &auth, 100)
        .await
        .unwrap();
    let once = |request: StampIssuanceRequest, auth: AuthenticatedStampIssuance, now| {
        let store = store.clone();
        let key = &key;
        async move {
            issue_stamp_once(
                &mut StdRng::seed_from_u64(1),
                &store,
                key,
                &auth,
                &request,
                &nonce,
                EPOCH,
                now,
            )
            .await
        }
    };
    let (request, pending) =
        request_stamp(&mut rng, &secret, key.public_key(), &nonce, &d).unwrap();
    // Wrong member, session or tag: the nonce binding does not match.
    for wrong in [
        AuthenticatedStampIssuance::new([3; 32], [2; 32], secret.issuer_tag()),
        AuthenticatedStampIssuance::new([1; 32], [3; 32], secret.issuer_tag()),
    ] {
        assert_eq!(
            once(request.clone(), wrong, 90).await.err(),
            Some(Error::InvalidChallenge)
        );
    }
    assert_eq!(
        once(request.clone(), auth.clone(), 101).await.err(),
        Some(Error::InvalidChallenge)
    );
    assert_eq!(
        once(request.clone(), auth.clone(), 0).await.err(),
        Some(Error::InvalidTimestamp)
    );
    // A request from another secret carries another tag.
    let other = HolderSecret::generate(&mut rng);
    let (foreign, _) = request_stamp(&mut rng, &other, key.public_key(), &nonce, &d).unwrap();
    assert_eq!(
        once(foreign, auth.clone(), 90).await.err(),
        Some(Error::IssuerTagMismatch)
    );
    // The member's tag on a commitment to another secret fails the proof.
    let slots = [Fr::from(5u64); STAMP_SLOTS];
    let (mixed, _) =
        request_for_slots(&mut rng, &other, &secret, key.public_key(), &nonce, &slots).unwrap();
    assert_eq!(
        once(mixed, auth.clone(), 90).await.err(),
        Some(Error::InvalidIssuanceRequest)
    );
    // Refusals consumed nothing; success consumes the nonce once.
    let blind = once(request.clone(), auth.clone(), 90).await.unwrap();
    pending.finish(&blind).unwrap();
    assert_eq!(
        once(request.clone(), auth.clone(), 90).await.err(),
        Some(Error::InvalidChallenge)
    );
    // Withdrawal of an outstanding nonce.
    let spare = stamp_issuance_challenge(&mut rng, &store, key.public_key(), &auth, 100)
        .await
        .unwrap();
    assert!(
        revoke_stamp_issuance_challenge(&store, key.public_key(), &auth, &spare, 90)
            .await
            .unwrap()
    );
    assert!(
        !revoke_stamp_issuance_challenge(&store, key.public_key(), &auth, &spare, 90)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn stamp_tag_registry_is_separate_and_immutable() {
    let mut rng = StdRng::seed_from_u64(13);
    let store = MemoryStore::new(CommunityId::new("wallet").unwrap(), 20).unwrap();
    let key = key(&mut rng, "stamp-g");
    let alice = HolderSecret::generate(&mut rng);
    let mallory = HolderSecret::generate(&mut rng);
    let d = [StampDigest::from_bytes([7; 32])];
    let issue = |secret: &HolderSecret, auth: &AuthenticatedStampIssuance, seed| {
        let store = store.clone();
        let key = &key;
        let secret = secret.clone();
        let auth = auth.clone();
        async move {
            let mut rng = StdRng::seed_from_u64(seed);
            let nonce = stamp_issuance_challenge(&mut rng, &store, key.public_key(), &auth, 100)
                .await
                .unwrap();
            let (request, _) =
                request_stamp(&mut rng, &secret, key.public_key(), &nonce, &d).unwrap();
            issue_stamp_once(&mut rng, &store, key, &auth, &request, &nonce, EPOCH, 90).await
        }
    };
    let member = |id: u8, secret: &HolderSecret| {
        AuthenticatedStampIssuance::new([id; 32], [id; 32], secret.issuer_tag())
    };
    issue(&alice, &member(1, &alice), 1).await.unwrap();
    issue(&alice, &member(1, &alice), 2).await.unwrap();
    // Another member presenting alice's tag (even with alice's secret) is refused.
    assert_eq!(
        issue(&alice, &member(2, &alice), 3).await.err(),
        Some(Error::IssuerTagClaimed)
    );
    // Member 1 with a different passport tag is refused by the registry.
    assert_eq!(
        issue(&mallory, &member(1, &mallory), 4).await.err(),
        Some(Error::IssuerTagMismatch)
    );
    // The passport registry of the same store is untouched by stamps.
    let passport_key = IssuerKey::generate(&mut rng, KeyId::new("p").unwrap(), vec![]).unwrap();
    let passport_auth = AuthenticatedIssuance::new([2; 32], [9; 32]);
    let nonce = issuance_challenge(
        &mut rng,
        &store,
        passport_key.public_key(),
        &passport_auth,
        100,
    )
    .await
    .unwrap();
    let (request, _) = request_issue(&mut rng, &alice, passport_key.public_key(), &nonce).unwrap();
    issue_blind_once(
        &mut rng,
        &store,
        &passport_key,
        &passport_auth,
        &request,
        &nonce,
        &PassportAttributes::new(300, 1),
        90,
    )
    .await
    .unwrap();
    let (nonce, binding, now, member_id, tag) = VerifiedStampIssuance {
        nonce: [1; 32],
        binding: [2; 32],
        now: 3,
        member: [4; 32],
        tag: alice.issuer_tag(),
    }
    .fields();
    assert_eq!(
        (nonce, binding, now, member_id, tag),
        ([1; 32], [2; 32], 3, [4; 32], alice.issuer_tag())
    );
}

#[tokio::test]
async fn ledger_records_each_digest_once_until_the_cohort_ends() {
    let mut rng = StdRng::seed_from_u64(14);
    let key = key(&mut rng, "stamp-l");
    let secret = HolderSecret::generate(&mut rng);
    let covered = covered(&mut rng, 2);
    let stamp = issue(&mut rng, &key, &secret, &covered);
    let (scope, act) = &covered[0];
    let store = MemoryStore::new(scope.community().clone(), 10).unwrap();
    assert_eq!(
        StampLedger::new(
            store.clone(),
            *scope.fingerprint(),
            vec![key.public_key().clone(), key.public_key().clone()]
        )
        .err()
        .map(|e| e.to_string()),
        Some("duplicate key ID in key ring".into())
    );
    let ledger = StampLedger::new(
        store.clone(),
        *scope.fingerprint(),
        vec![key.public_key().clone()],
    )
    .unwrap();
    assert_eq!(&ledger.scope(), scope);
    let p = roundtrip(&stamp.present(&mut rng, scope, act).unwrap());
    let verified = ledger.accept(act, &p, EPOCH, NOW).await.unwrap();
    assert!(ledger.recorded(&verified, NOW).await.unwrap());
    // A replayed presentation, or a fresh presentation of the same slot.
    assert_eq!(
        ledger.accept(act, &p, EPOCH, NOW).await.err(),
        Some(Error::StampReplayed)
    );
    let fresh = stamp.present(&mut rng, scope, act).unwrap();
    assert_eq!(
        ledger.accept(act, &fresh, EPOCH, NOW + 1).await.err(),
        Some(Error::StampReplayed)
    );
    assert_eq!(
        ledger.record(&verified, NOW).await.err(),
        Some(Error::StampReplayed)
    );
    // An invalid presentation records nothing.
    let other = action(&mut rng, "lineage.pair");
    assert_eq!(
        ledger.accept(&other, &p, EPOCH, NOW).await.err(),
        Some(Error::InvalidProof)
    );
    // Release only for an action that was not applied; then it can be retried.
    assert!(ledger.release(&verified, NOW).await.unwrap());
    assert!(!ledger.recorded(&verified, NOW).await.unwrap());
    assert!(!ledger.release(&verified, NOW).await.unwrap());
    ledger.accept(act, &fresh, EPOCH, NOW).await.unwrap();
    // Foreign community, expired stamp and invalid time.
    let (other_scope, other_act) = &covered[1];
    let foreign = verify_stamp(
        &[key.public_key().clone()],
        other_scope,
        EPOCH,
        other_act,
        &stamp.present(&mut rng, other_scope, other_act).unwrap(),
        NOW,
    )
    .unwrap();
    assert_eq!(
        ledger.record(&foreign, NOW).await.err(),
        Some(Error::InvalidStamp)
    );
    assert!(!ledger.recorded(&foreign, NOW).await.unwrap());
    assert_eq!(
        ledger.record(&verified, EXPIRES).await.err(),
        Some(Error::StampExpired)
    );
    assert_eq!(
        ledger.record(&verified, 0).await.err(),
        Some(Error::InvalidTimestamp)
    );
    // The record outlives the stamp; pruning after expiry removes it.
    assert_eq!(ledger.prune(EXPIRES).await.unwrap(), 0);
    assert_eq!(ledger.prune(EXPIRES + 1).await.unwrap(), 1);
}

#[test]
fn new_errors_and_issuer_tags_have_stable_text_and_validation() {
    for (error, text) in [
        (Error::InvalidStamp, "invalid confirmation stamp"),
        (
            Error::StampDigestMissing,
            "stamp does not cover this action",
        ),
        (Error::StampExpired, "confirmation stamp expired"),
        (
            Error::StampReplayed,
            "confirmation stamp digest already used",
        ),
    ] {
        assert_eq!(error.to_string(), text);
    }
    let mut rng = StdRng::seed_from_u64(15);
    let tag = HolderSecret::generate(&mut rng).issuer_tag();
    assert_eq!(IssuerTag::from_bytes(&tag.to_bytes()).unwrap(), tag);
    assert_eq!(
        IssuerTag::from_bytes(&[0; 48]).err(),
        Some(Error::Decode("issuer tag"))
    );
    let mut identity = [0u8; 48];
    identity[0] = 0xc0;
    assert_eq!(
        IssuerTag::from_bytes(&identity).err(),
        Some(Error::Decode("issuer tag"))
    );
}
