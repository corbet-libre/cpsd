//! Stamp tests: real BBS+ issuance and presentations, seeded property loops,
//! requests and proofs built from the crate's own building blocks with wrong
//! witnesses or claims (they show the code fails closed; soundness itself
//! rests on Dock's proofs of knowledge), and refusals.

use std::collections::BTreeSet;

use ark_bls12_381::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use dock_crypto_utils::transcript::Transcript;
use rand::{Rng, SeedableRng, rngs::StdRng, seq::SliceRandom};
use schnorr_pok::{SchnorrCommitment, discrete_log::PokDiscreteLog};

use super::issuance::{
    ISSUANCE_WITNESSES, IssuanceProof, WITNESS_SECRET, bases, request_for_slots, shuffled_slots,
    statement, transcript,
};
use super::presentation::{StampRequest, prove};
use super::state::{MAX_HELD_STAMPS, StampState};
use super::{PendingStamp, Stamp, request_stamp};
use crate::*;

/// The finest accepted cohort (one hour); the rulebook default is one day.
const COHORT: u64 = 3_600;
const EPOCH: u64 = 9;
/// 3_600_200 lies 200 s into cohort 1000, so the stamp expires at the end of
/// cohort 1001: 3_607_200.
const NOW: Timestamp = 3_600_200;
const EXPIRES: Timestamp = 3_607_200;

fn params() -> StampParams {
    StampParams::new(COHORT).unwrap()
}

fn key(rng: &mut StdRng, name: &str) -> StampIssuerKey {
    StampIssuerKey::generate(rng, KeyId::new(name).unwrap(), &params()).unwrap()
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

/// A holder secret with one stamp: what the opaque holder retains, opened up
/// for tests of the crate-private building blocks.
struct Held {
    secret: HolderSecret,
    stamp: Stamp,
}

impl Held {
    fn present(
        &self,
        rng: &mut StdRng,
        scope: &StampScope,
        action: &StampAction,
    ) -> Result<StampPresentation, Error> {
        self.stamp.present(rng, &self.secret, scope, action)
    }

    fn covers(&self, scope: &StampScope, action: &StampAction) -> bool {
        self.stamp.covers(&self.secret, scope, action)
    }

    fn key_id(&self) -> &KeyId {
        self.stamp.key_id()
    }

    fn epoch(&self) -> u64 {
        self.stamp.epoch
    }

    fn expires(&self) -> Timestamp {
        self.stamp.expires
    }
}

/// Issues a stamp through every transport and storage encoding.
fn issue(
    rng: &mut StdRng,
    key: &StampIssuerKey,
    secret: &HolderSecret,
    covered: &[(StampScope, StampAction)],
) -> Held {
    let digests: Vec<StampDigest> = covered.iter().map(|(s, a)| digest(secret, s, a)).collect();
    let nonce = IssuanceChallenge::generate(rng);
    let (request, pending) =
        request_stamp(rng, secret, key.public_key(), &nonce, &digests, NOW).unwrap();
    let request = StampIssuanceRequest::from_bytes(&request.to_bytes()).unwrap();
    let pending = PendingStamp::from_bytes(&pending.to_bytes()).unwrap();
    let blind = key.issue_blind(rng, &request, &nonce, EPOCH, NOW).unwrap();
    let blind = BlindStamp::from_bytes(&blind.to_bytes()).unwrap();
    assert_eq!((blind.epoch(), blind.expires()), (EPOCH, EXPIRES));
    assert_eq!(blind.key_id(), key.public_key().key_id());
    let stamp = pending.finish(secret, &blind, NOW).unwrap();
    Held {
        secret: secret.clone(),
        stamp: Stamp::from_bytes(&stamp.to_bytes(), secret).unwrap(),
    }
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
        &params(),
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
    assert_eq!(stamp.stamp.issuer(), key.public_key());
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
    stamp: &Held,
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
    let proof = prove(
        rng,
        &stamp.secret,
        &stamp.stamp,
        &request,
        &pseudonym.point().unwrap(),
    )
    .unwrap();
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
        verify_stamp(&ring, &params(), scope, EPOCH, act, p, NOW).err()
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
        verify_stamp(&ring, &params(), scope, EPOCH + 1, act, &p, NOW).err(),
        Some(Error::WrongEpoch)
    );
    assert_eq!(
        verify_stamp(&[], &params(), scope, EPOCH, act, &p, NOW).err(),
        Some(Error::UnknownKey)
    );
    let twice = [key.public_key().clone(), key.public_key().clone()];
    assert_eq!(
        verify_stamp(&twice, &params(), scope, EPOCH, act, &p, NOW).err(),
        Some(Error::DuplicateKeyId)
    );
    let other_key = self::key(&mut rng, "stamp-t");
    assert_eq!(
        verify_stamp(
            &[other_key.public_key().clone()],
            &params(),
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
        verify_stamp(&ring, &params(), scope, EPOCH, act, &p, EXPIRES).err(),
        Some(Error::StampExpired)
    );
    // Issued at most two cohorts plus the clock tolerance in the verifier's future.
    let earliest = EXPIRES - 2 * COHORT - STAMP_CLOCK_SKEW_SECONDS;
    assert_eq!(
        verify_stamp(&ring, &params(), scope, EPOCH, act, &p, earliest - 1).err(),
        Some(Error::WrongExpiryCohort)
    );
    verify_stamp(&ring, &params(), scope, EPOCH, act, &p, earliest).unwrap();
    verify_stamp(&ring, &params(), scope, EPOCH, act, &p, EXPIRES - 1).unwrap();
    // The verifier's configured cohort must be the key's.
    for other in [2 * COHORT, MAX_STAMP_COHORT_SECONDS] {
        let other = StampParams::new(other).unwrap();
        assert_eq!(
            verify_stamp(&ring, &other, scope, EPOCH, act, &p, NOW).err(),
            Some(Error::WrongExpiryCohort)
        );
    }
    assert_eq!(
        verify_stamp(&ring, &params(), scope, EPOCH, act, &p, 0).err(),
        Some(Error::InvalidTimestamp)
    );
    // Revealed metadata cannot be rewritten.
    let mut q = p.clone();
    q.epoch = EPOCH + 1;
    assert_eq!(
        verify_stamp(&ring, &params(), scope, EPOCH + 1, act, &q, NOW).err(),
        Some(Error::InvalidProof)
    );
    let mut q = p.clone();
    q.expires = EXPIRES - COHORT;
    assert_eq!(check(scope, act, &q), Some(Error::InvalidProof));
    q.expires = EXPIRES + COHORT;
    assert_eq!(check(scope, act, &q), Some(Error::WrongExpiryCohort));
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
            .and_then(|q| verify_stamp(&ring, &params(), scope, EPOCH, act, &q, NOW));
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
    let (honest, _) = request_stamp(&mut rng, &secret, key.public_key(), &nonce, &d, NOW).unwrap();
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
        NOW,
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
            request_stamp(&mut rng, &secret, key.public_key(), &nonce, bad, NOW).err(),
            Some(Error::InvalidStamp)
        );
    }
    let (request, _) = request_stamp(
        &mut rng,
        &secret,
        key.public_key(),
        &nonce,
        &digests[..1],
        NOW,
    )
    .unwrap();
    let (again, _) = request_stamp(
        &mut rng,
        &secret,
        key.public_key(),
        &nonce,
        &digests[..1],
        NOW,
    )
    .unwrap();
    let challenge = request.confirmation_challenge(&nonce);
    assert_eq!(challenge, request.confirmation_challenge(&nonce));
    assert_ne!(challenge, again.confirmation_challenge(&nonce));
    assert_ne!(
        challenge,
        request.confirmation_challenge(&IssuanceChallenge::from_bytes([0; 32]))
    );
}

#[test]
fn unblinding_checks_key_window_and_signature() {
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
        request_stamp(
            &mut StdRng::seed_from_u64(9),
            &secret,
            key.public_key(),
            &nonce,
            &d,
            NOW,
        )
        .unwrap()
    };
    let (request, _) = pending();
    let blind = key
        .issue_blind(&mut rng, &request, &nonce, EPOCH, NOW)
        .unwrap();
    assert!(format!("{blind:?}").contains("BlindStamp"));
    assert!(format!("{:?}", pending().1).contains("PendingStamp"));
    assert_eq!(pending().1.issuer(), key.public_key());
    let finish = |blind: &BlindStamp, now| pending().1.finish(&secret, blind, now).err();
    let mut wrong = blind.clone();
    wrong.key_id = KeyId::new("other").unwrap();
    assert_eq!(finish(&wrong, NOW), Some(Error::KeyMismatch));
    let mut off_grid = blind.clone();
    off_grid.expires += 1;
    assert_eq!(finish(&off_grid, NOW), Some(Error::InvalidStamp));
    // A grid value outside the issuance window (request to answer, widened by
    // the clock tolerance) is refused before the signature check: a
    // dishonest wallet cannot pick among grid values to tag one holder.
    let mut later = blind.clone();
    later.expires += COHORT;
    assert_eq!(finish(&later, NOW), Some(Error::InvalidStamp));
    let mut earlier = blind.clone();
    earlier.expires -= 2 * COHORT;
    assert_eq!(finish(&earlier, NOW), Some(Error::InvalidStamp));
    // NOW is 200 s into its cohort, so a wallet clock up to the tolerance
    // behind may still sign the previous value; the signature decides.
    earlier.expires += COHORT;
    assert_eq!(finish(&earlier, NOW), Some(Error::InvalidSignature));
    // Answered a cohort later (for example after a restart), the next grid
    // value lies inside the window and only the signature decides.
    assert_eq!(finish(&later, NOW + COHORT), Some(Error::InvalidSignature));
    // The tolerance covers a wallet clock just across the next cohort boundary.
    let boundary = (NOW / COHORT + 1) * COHORT;
    let skewed = key.public_key().expiry_for(boundary).unwrap();
    assert_eq!(skewed, EXPIRES + COHORT);
    let near = boundary - STAMP_CLOCK_SKEW_SECONDS;
    let (request, pending_near) =
        request_stamp(&mut rng, &secret, key.public_key(), &nonce, &d, near).unwrap();
    let blind_near = key
        .issue_blind(&mut rng, &request, &nonce, EPOCH, boundary)
        .unwrap();
    assert_eq!(blind_near.expires(), skewed);
    pending_near.finish(&secret, &blind_near, near).unwrap();
    let (request, pending_far) =
        request_stamp(&mut rng, &secret, key.public_key(), &nonce, &d, near - 1).unwrap();
    let blind_far = key
        .issue_blind(&mut rng, &request, &nonce, EPOCH, boundary)
        .unwrap();
    assert_eq!(
        pending_far.finish(&secret, &blind_far, near - 1).err(),
        Some(Error::InvalidStamp)
    );
    let mut epoch = blind.clone();
    epoch.epoch += 1;
    assert_eq!(finish(&epoch, NOW), Some(Error::InvalidSignature));
    // An answer that arrives after the stamp expired is useless and refused.
    assert_eq!(finish(&blind, EXPIRES), Some(Error::StampExpired));
    assert_eq!(finish(&blind, 0), Some(Error::InvalidTimestamp));
    // Another secret never unblinds into a valid stamp.
    let other = HolderSecret::generate(&mut rng);
    assert_eq!(
        pending().1.finish(&other, &blind, NOW).err(),
        Some(Error::InvalidSignature)
    );
    let stamp = pending().1.finish(&secret, &blind, NOW).unwrap();
    assert!(format!("{stamp:?}").contains("Stamp"));
    assert!(!format!("{stamp:?}").contains("secret"));
    assert_eq!(
        request_stamp(&mut rng, &secret, key.public_key(), &nonce, &d, 0).err(),
        Some(Error::InvalidTimestamp)
    );
}

#[test]
fn cohort_params_rule_for_issuer_holder_and_verifier() {
    let mut rng = StdRng::seed_from_u64(7);
    // Whole hours that divide one UTC day; nothing finer than an hour.
    for bad in [
        0,
        60,
        MIN_STAMP_COHORT_SECONDS - 1,
        MIN_STAMP_COHORT_SECONDS + 1,
        5 * 3_600,
        7 * 3_600,
        MAX_STAMP_COHORT_SECONDS + 3_600,
        2 * MAX_STAMP_COHORT_SECONDS,
    ] {
        assert_eq!(
            StampParams::new(bad).err(),
            Some(Error::InvalidStamp),
            "{bad}"
        );
    }
    for hours in [1, 2, 3, 4, 6, 8, 12, 24] {
        let params = StampParams::new(hours * 3_600).unwrap();
        assert_eq!(params.cohort_seconds(), hours * 3_600);
        let k = StampIssuerKey::generate(&mut rng, KeyId::new("k").unwrap(), &params).unwrap();
        assert_eq!(k.public_key().cohort_seconds(), hours * 3_600);
        assert_eq!(k.public_key().params(), params);
    }
    assert_eq!(
        (MIN_STAMP_COHORT_SECONDS, MAX_STAMP_COHORT_SECONDS),
        (3_600, 86_400)
    );
    // The rulebook default, one UTC day: a stamp expires at the end of the
    // UTC day after issuance, whatever the time of day.
    let day = StampParams::new(86_400).unwrap();
    let daily = StampIssuerKey::generate(&mut rng, KeyId::new("day").unwrap(), &day).unwrap();
    // 2026-10-15T00:00:00Z = 1_792_022_400.
    let midnight = 1_792_022_400;
    for now in [midnight, midnight + 1, midnight + 43_200, midnight + 86_399] {
        assert_eq!(
            daily.public_key().expiry_for(now).unwrap(),
            midnight + 2 * 86_400
        );
    }
    assert_eq!(
        daily.public_key().expiry_for(midnight + 86_400).unwrap(),
        midnight + 3 * 86_400
    );
    let key = key(&mut rng, "stamp-c");
    let public = key.public_key();
    // Every issuance in one cohort gets the same expiry: the end of the next.
    assert_eq!(public.expiry_for(3_600_000).unwrap(), EXPIRES);
    assert_eq!(public.expiry_for(NOW).unwrap(), EXPIRES);
    assert_eq!(public.expiry_for(3_603_599).unwrap(), EXPIRES);
    assert_eq!(public.expiry_for(3_603_600).unwrap(), EXPIRES + COHORT);
    assert_eq!(public.expiry_for(0).err(), Some(Error::InvalidTimestamp));
    assert_eq!(
        public.expiry_for(TIME_LIMIT - 1).err(),
        Some(Error::InvalidTimestamp)
    );
    // Every issuer choice is accepted by verifiers for its whole life.
    for now in [3_600_000, NOW, 3_603_599, 3_603_600] {
        let expires = public.expiry_for(now).unwrap();
        assert!(expires - now > COHORT);
        assert!(expires - now <= 2 * COHORT);
        for t in [now, expires - 1] {
            public.check_expiry(expires, t).unwrap();
        }
        assert_eq!(
            public.check_expiry(expires, expires),
            Err(Error::StampExpired)
        );
    }
    assert_eq!(
        public.check_expiry(EXPIRES + 1, NOW),
        Err(Error::WrongExpiryCohort)
    );
    assert_eq!(
        public.check_expiry(EXPIRES + COHORT, NOW),
        Err(Error::WrongExpiryCohort)
    );
    assert_eq!(
        public.check_expiry(EXPIRES, 0),
        Err(Error::InvalidTimestamp)
    );
    public.check_alignment(EXPIRES).unwrap();
    assert_eq!(
        public.check_alignment(EXPIRES + 1),
        Err(Error::InvalidStamp)
    );
    assert_eq!(public.check_alignment(0), Err(Error::InvalidTimestamp));
    // Holder window: grid values from the request time to the answer time,
    // each widened by the clock tolerance.
    public.check_signed_expiry(EXPIRES, NOW, NOW).unwrap();
    assert_eq!(
        public.check_signed_expiry(EXPIRES + COHORT, NOW, NOW),
        Err(Error::InvalidStamp)
    );
    public
        .check_signed_expiry(EXPIRES + COHORT, NOW, NOW + COHORT)
        .unwrap();
    // A clock that stepped back between request and answer keeps the window.
    public.check_signed_expiry(EXPIRES, NOW, NOW - 100).unwrap();
    assert_eq!(
        public.check_signed_expiry(EXPIRES, 1, 1),
        Err(Error::InvalidStamp)
    );
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
    let longer = StampIssuerKey::generate(
        &mut rng,
        KeyId::new("stamp-k").unwrap(),
        &StampParams::new(2 * COHORT).unwrap(),
    )
    .unwrap();
    assert_ne!(longer.public_key(), public);
    // Zero secret and out-of-range cohort encodings are refused.
    let mut bytes = key.to_secret_bytes().to_vec();
    let at = bytes.len() - 32;
    bytes[at..].fill(0);
    assert_eq!(
        StampIssuerKey::from_secret_bytes(&bytes).err(),
        Some(Error::InvalidKey)
    );
    // Published keys and stored issuer keys finer than an hour, off the
    // hour grid or longer than a day are refused.
    let cohort_at = 6 + 4 + "stamp-k".len();
    for bad in [59u64, 60, 3_599, 5_400, 5 * 3_600, 2 * 86_400] {
        let mut bytes = public.to_bytes();
        bytes[cohort_at..cohort_at + 8].copy_from_slice(&bad.to_be_bytes());
        assert_eq!(
            StampPublicKey::from_bytes(&bytes).err(),
            Some(Error::InvalidStamp)
        );
        let mut bytes = key.to_secret_bytes().to_vec();
        bytes[cohort_at..cohort_at + 8].copy_from_slice(&bad.to_be_bytes());
        assert_eq!(
            StampIssuerKey::from_secret_bytes(&bytes).err(),
            Some(Error::InvalidStamp)
        );
    }
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
        NOW,
    )
    .unwrap();
    let blind = key
        .issue_blind(&mut rng, &request, &nonce, EPOCH, NOW)
        .unwrap();
    let pending_bytes = pending.to_bytes();
    let stamp = pending.finish(&secret, &blind, NOW).unwrap();
    let presentation = stamp.present(&mut rng, &secret, &s, &a).unwrap();
    let mut state = StampState {
        pending: Some(PendingStamp::from_bytes(&pending_bytes).unwrap()),
        ..StampState::default()
    };
    state.stamps.push(stamp.clone());
    let state_bytes = state.to_bytes();
    assert_strict(&key.public_key().to_bytes(), StampPublicKey::from_bytes);
    assert_strict(&key.to_secret_bytes(), StampIssuerKey::from_secret_bytes);
    assert_strict(&request.to_bytes(), StampIssuanceRequest::from_bytes);
    assert_strict(&blind.to_bytes(), BlindStamp::from_bytes);
    assert_strict(&pending_bytes, PendingStamp::from_bytes);
    assert_strict(&stamp.to_bytes(), |b| Stamp::from_bytes(b, &secret));
    assert_strict(&state_bytes, |b| StampState::from_bytes(b, &secret));
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
    // A stamp restores only for its own holder: the signature covers the
    // secret, which the encoding does not carry.
    let other = HolderSecret::generate(&mut rng);
    assert_eq!(
        Stamp::from_bytes(&stamp.to_bytes(), &other).err(),
        Some(Error::InvalidSignature)
    );
    assert_eq!(
        StampState::from_bytes(&state_bytes, &other).err(),
        Some(Error::InvalidSignature)
    );
    assert_eq!(
        Stamp::from_bytes(&stamp.to_bytes(), &HolderSecret(Fr::from(0u64))).err(),
        Some(Error::InvalidKey)
    );
    // A pending request with an invalid start time, an empty state, or more
    // stamps than a holder retains are refused.
    let mut zero_time = pending_bytes.to_vec();
    let at = zero_time.len() - 8;
    zero_time[at..].fill(0);
    assert_eq!(
        PendingStamp::from_bytes(&zero_time).err(),
        Some(Error::InvalidTimestamp)
    );
    assert_eq!(
        StampState::from_bytes(&StampState::default().to_bytes(), &secret).err(),
        Some(Error::InvalidSealedHolder)
    );
    let mut full = StampState::default();
    for _ in 0..=MAX_HELD_STAMPS {
        full.stamps.push(stamp.clone());
    }
    assert_eq!(
        StampState::from_bytes(&full.to_bytes(), &secret).err(),
        Some(Error::InvalidSealedHolder)
    );
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
async fn wallet_issuance_binds_member_tag_confirmation_and_single_use_nonce() {
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
    // The wallet's verified user verification must cover this request.
    let confirmed = |auth: &AuthenticatedStampIssuance, request: &StampIssuanceRequest| {
        auth.clone()
            .with_user_verification(request.confirmation_challenge(&nonce))
    };
    let (request, pending) =
        request_stamp(&mut rng, &secret, key.public_key(), &nonce, &d, 90).unwrap();
    // Wrong member or session: the nonce binding does not match.
    for wrong in [
        AuthenticatedStampIssuance::new([3; 32], [2; 32], secret.issuer_tag()),
        AuthenticatedStampIssuance::new([1; 32], [3; 32], secret.issuer_tag()),
    ] {
        assert_eq!(
            once(request.clone(), confirmed(&wrong, &request), 90)
                .await
                .err(),
            Some(Error::InvalidChallenge)
        );
    }
    let ok = confirmed(&auth, &request);
    assert_eq!(
        once(request.clone(), ok.clone(), 101).await.err(),
        Some(Error::InvalidChallenge)
    );
    assert_eq!(
        once(request.clone(), ok.clone(), 0).await.err(),
        Some(Error::InvalidTimestamp)
    );
    // A request from another secret carries another tag.
    let other = HolderSecret::generate(&mut rng);
    let (foreign, _) = request_stamp(&mut rng, &other, key.public_key(), &nonce, &d, 90).unwrap();
    assert_eq!(
        once(foreign.clone(), confirmed(&auth, &foreign), 90)
            .await
            .err(),
        Some(Error::IssuerTagMismatch)
    );
    // No user verification, one over another request, over another nonce, or
    // a device-chosen value: refused before any proof work.
    let (again, _) = request_stamp(&mut rng, &secret, key.public_key(), &nonce, &d, 90).unwrap();
    for unconfirmed in [
        auth.clone(),
        confirmed(&auth, &again),
        auth.clone().with_user_verification(
            request.confirmation_challenge(&IssuanceChallenge::from_bytes([0; 32])),
        ),
        auth.clone().with_user_verification([0; 32]),
    ] {
        assert_eq!(
            once(request.clone(), unconfirmed, 90).await.err(),
            Some(Error::UnconfirmedStampRequest)
        );
    }
    // The member's tag on a commitment to another secret fails the proof.
    let slots = [Fr::from(5u64); STAMP_SLOTS];
    let (mixed, _) = request_for_slots(
        &mut rng,
        &other,
        &secret,
        key.public_key(),
        &nonce,
        &slots,
        90,
    )
    .unwrap();
    assert_eq!(
        once(mixed.clone(), confirmed(&auth, &mixed), 90)
            .await
            .err(),
        Some(Error::InvalidIssuanceRequest)
    );
    // Refusals consumed nothing; success consumes the nonce once.
    let blind = once(request.clone(), ok.clone(), 90).await.unwrap();
    pending.finish(&secret, &blind, 90).unwrap();
    assert_eq!(
        once(request.clone(), ok.clone(), 90).await.err(),
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
    assert_eq!(
        Error::UnconfirmedStampRequest.to_string(),
        "stamp request not covered by the user verification"
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
                request_stamp(&mut rng, &secret, key.public_key(), &nonce, &d, 90).unwrap();
            let auth = auth.with_user_verification(request.confirmation_challenge(&nonce));
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
            vec![key.public_key().clone(), key.public_key().clone()],
            params(),
        )
        .err()
        .map(|e| e.to_string()),
        Some("duplicate key ID in key ring".into())
    );
    // A key whose cohort is not the rulebook's is refused for the ring.
    let hourly_ring = vec![key.public_key().clone()];
    assert_eq!(
        StampLedger::new(
            store.clone(),
            *scope.fingerprint(),
            hourly_ring,
            StampParams::new(86_400).unwrap(),
        )
        .err(),
        Some(Error::WrongExpiryCohort)
    );
    let ledger = StampLedger::new(
        store.clone(),
        *scope.fingerprint(),
        vec![key.public_key().clone()],
        params(),
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
        &params(),
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
    // The record outlives the stamp by the prune margin: a node whose clock
    // is up to that far behind still finds it, so it cannot apply the action
    // twice; once the margin has passed, every such node refuses the stamp as
    // expired anyway.
    assert_eq!(ledger.prune(EXPIRES).await.unwrap(), 0);
    assert_eq!(ledger.prune(EXPIRES + 1).await.unwrap(), 0);
    assert_eq!(
        ledger
            .prune(EXPIRES + STAMP_PRUNE_MARGIN_SECONDS)
            .await
            .unwrap(),
        0
    );
    assert!(ledger.recorded(&verified, EXPIRES).await.unwrap());
    assert_eq!(
        ledger.accept(act, &fresh, EPOCH, EXPIRES).await.err(),
        Some(Error::StampExpired)
    );
    assert_eq!(
        ledger
            .prune(EXPIRES + STAMP_PRUNE_MARGIN_SECONDS + 1)
            .await
            .unwrap(),
        1
    );
    // Early clock values prune nothing and invalid ones are refused.
    assert_eq!(ledger.prune(STAMP_PRUNE_MARGIN_SECONDS).await.unwrap(), 0);
    assert_eq!(ledger.prune(1).await.unwrap(), 0);
    assert_eq!(ledger.prune(0).await.err(), Some(Error::InvalidTimestamp));
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

/// Every encoding of `secret` the codecs could plausibly leak: the canonical
/// little-endian scalar, its big-endian form and the legacy secret encoding.
fn secret_forms(secret: &HolderSecret) -> Vec<Vec<u8>> {
    let mut le = Vec::new();
    secret.0.serialize_compressed(&mut le).unwrap();
    let be: Vec<u8> = le.iter().rev().copied().collect();
    vec![le, be, secret.to_bytes().to_vec()]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn pending_stamp_stamp_and_state_encodings_carry_no_secret_bytes() {
    for seed in 0..4u64 {
        let mut rng = StdRng::seed_from_u64(300 + seed);
        let key = key(&mut rng, "stamp-n");
        let secret = HolderSecret::generate(&mut rng);
        let covered = covered(&mut rng, 3);
        let digests: Vec<StampDigest> =
            covered.iter().map(|(s, a)| digest(&secret, s, a)).collect();
        let nonce = IssuanceChallenge::generate(&mut rng);
        let (request, pending) =
            request_stamp(&mut rng, &secret, key.public_key(), &nonce, &digests, NOW).unwrap();
        let pending_bytes = pending.to_bytes();
        let blind = key
            .issue_blind(&mut rng, &request, &nonce, EPOCH, NOW)
            .unwrap();
        let stamp = pending.finish(&secret, &blind, NOW).unwrap();
        let (_, second) =
            request_stamp(&mut rng, &secret, key.public_key(), &nonce, &digests, NOW).unwrap();
        let mut state = StampState {
            pending: Some(second),
            ..StampState::default()
        };
        state.stamps.push(stamp.clone());
        let blobs = [
            pending_bytes.to_vec(),
            stamp.to_bytes().to_vec(),
            state.to_bytes().to_vec(),
            request.to_bytes(),
            blind.to_bytes(),
        ];
        for form in secret_forms(&secret) {
            for blob in &blobs {
                assert!(
                    !contains(blob, &form),
                    "seed {seed}: secret bytes in a stamp blob"
                );
            }
        }
        // What is stored suffices: the holder's secret restores and presents.
        let restored = StampState::from_bytes(&state.to_bytes(), &secret).unwrap();
        let (scope, act) = &covered[0];
        let presentation = restored
            .covering(&secret, scope, act, NOW)
            .unwrap()
            .present(&mut rng, &secret, scope, act)
            .unwrap();
        verify_one(&key, scope, act, &presentation).unwrap();
        assert!(restored.pending.is_some());
    }
}

#[test]
fn slot_positions_are_uniform_and_fillers_fresh() {
    // Chi-square over the position of each real digest among sixteen slots.
    // 15 degrees of freedom: 37.70 is the 0.1 % critical value. The seeded
    // RNG makes the run deterministic.
    let mut rng = StdRng::seed_from_u64(16);
    let digests: Vec<StampDigest> = (0..3u8).map(|n| StampDigest::from_bytes([n; 32])).collect();
    let draws = 3_200;
    let mut counts = [[0u32; STAMP_SLOTS]; 3];
    let mut fillers = BTreeSet::new();
    for _ in 0..draws {
        let slots = shuffled_slots(&mut rng, &digests).unwrap();
        for (d, digest) in digests.iter().enumerate() {
            let at = slots.iter().position(|s| *s == digest.scalar()).unwrap();
            counts[d][at] += 1;
        }
        for slot in slots.iter() {
            if !digests.iter().any(|d| d.scalar() == *slot) {
                let mut bytes = Vec::new();
                slot.serialize_compressed(&mut bytes).unwrap();
                assert!(fillers.insert(bytes), "filler repeated");
            }
        }
    }
    let expected = f64::from(draws) / STAMP_SLOTS as f64;
    for per_digest in &counts {
        let chi: f64 = per_digest
            .iter()
            .map(|&c| (f64::from(c) - expected).powi(2) / expected)
            .sum();
        assert!(chi < 37.70, "slot positions not uniform: chi-square {chi}");
    }
    assert_eq!(
        fillers.len(),
        draws as usize * (STAMP_SLOTS - digests.len())
    );
}

#[test]
fn stamp_and_passport_prove_the_same_pseudonym() {
    let mut rng = StdRng::seed_from_u64(17);
    let passport_key =
        IssuerKey::generate(&mut rng, KeyId::new("passport").unwrap(), vec![]).unwrap();
    let secret = HolderSecret::generate(&mut rng);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let (request, pending) =
        request_issue(&mut rng, &secret, passport_key.public_key(), &challenge).unwrap();
    let blind = passport_key
        .issue_blind(
            &mut rng,
            &request,
            &challenge,
            &PassportAttributes::new(NOW + 1_000, 7),
        )
        .unwrap();
    let passport = pending.finish(&blind).unwrap();
    let stamp_key = key(&mut rng, "stamp-p");
    let covered = covered(&mut rng, 2);
    let stamp = issue(&mut rng, &stamp_key, &secret, &covered);
    for (scope, act) in &covered {
        let request =
            PresentationRequest::new(&mut rng, scope.community().clone(), 7, [], NOW).unwrap();
        let shown = crate::presentation::present_checked(&mut rng, &passport, &request).unwrap();
        let from_passport = verify(
            &mut rng,
            &[passport_key.public_key().clone()],
            &request,
            &shown,
        )
        .unwrap();
        let from_stamp = verify_one(
            &stamp_key,
            scope,
            act,
            &stamp.present(&mut rng, scope, act).unwrap(),
        )
        .unwrap();
        assert_eq!(from_stamp.pseudonym(), &from_passport);
    }
}
