//! Hostile root-board compositions against the real BBS+/Schnorr protocols.
//!
//! The public flow is covered by `tests/root_board.rs`. These tests need crate
//! internals to build proofs that no honest holder API can produce.

use super::*;
use crate::root_board::{
    self,
    state::{RootBoardCredential, RootBoardState},
};
use crate::wire::{Kind, Writer};

const EXPIRY: Timestamp = 2_000_000;
const NOW: Timestamp = 1_000;

fn root_gate() -> GateId {
    GateId::new("root-board").unwrap()
}
fn root_community() -> CommunityId {
    CommunityId::new(b"root").unwrap()
}
fn root_issuer(rng: &mut StdRng, key_id: &str) -> IssuerKey {
    IssuerKey::generate(rng, KeyId::new(key_id).unwrap(), vec![root_gate()]).unwrap()
}
fn descriptor(issuer: &IssuerKey, epoch: u64) -> RootBoardPublicKey {
    RootBoardPublicKey::from_authenticated_beacon(
        issuer.public_key().clone(),
        root_community(),
        epoch,
        0,
    )
    .unwrap()
}
fn global_attrs() -> PassportAttributes {
    PassportAttributes::new(EXPIRY, 7).with_gate(gate(), EXPIRY)
}
fn context(rng: &mut StdRng, root: &RootBoardPublicKey) -> RootBoardIssuanceContext {
    let source = PresentationRequest::for_epoch(rng, community(), 7, [gate()], NOW, EXPIRY).unwrap();
    RootBoardIssuanceContext::new(rng, source, root.clone()).unwrap()
}
fn holder(rng: &mut StdRng, global: &IssuerKey) -> Passport {
    let secret = HolderSecret::generate(rng);
    issue(rng, global, &secret, global_attrs())
}

/// Complete honest issuance through the same internal steps the holder uses.
fn mint(
    rng: &mut StdRng,
    global: &IssuerKey,
    root_key: &IssuerKey,
    root: &RootBoardPublicKey,
    passport: &Passport,
) -> RootBoardCredential {
    let context = context(rng, root);
    let (request, pending) = root_board::begin_issuance(rng, passport, &context).unwrap();
    let request = RootBoardIssuanceRequest::from_bytes(&request.to_bytes()).unwrap();
    let verified = verify_root_board_issuance(
        &[global.public_key().clone()],
        &context,
        &request,
        NOW,
    )
    .unwrap();
    assert_eq!(verified.source_pseudonym(), passport.pseudonym(&community()));
    assert_eq!(verified.source_community(), &community());
    assert_eq!(verified.nonce(), context.nonce());
    assert_eq!(verified.deadline(), NOW);
    assert!(verified.root() == root);
    let blind = issue_blind_root_board(rng, root_key, root, verified, NOW).unwrap();
    let blind = BlindRootBoardCredential::from_bytes(&blind.to_bytes()).unwrap();
    let mut state = RootBoardState {
        pending: Some(pending),
        credential: None,
    };
    state.finish(&blind).unwrap();
    state.credential.unwrap()
}

fn root_request(rng: &mut StdRng, root: &RootBoardPublicKey) -> RootBoardRequest {
    let global =
        PresentationRequest::for_epoch(rng, root_community(), 7, [gate()], NOW, EXPIRY).unwrap();
    RootBoardRequest::new(global, root.clone()).unwrap()
}

#[test]
fn honest_root_board_roundtrip_binds_one_holder_secret() {
    let mut rng = rng();
    let global = key(&mut rng, "global");
    let root_key = root_issuer(&mut rng, "root-board-1");
    let root = descriptor(&root_key, 3);
    let passport = holder(&mut rng, &global);
    let credential = mint(&mut rng, &global, &root_key, &root, &passport);
    let request = root_request(&mut rng, &root);
    let request = RootBoardRequest::from_bytes(&request.to_bytes()).unwrap();
    let proof = root_board::present(&mut rng, &passport, &credential, &request).unwrap();
    let proof = RootBoardPresentation::from_bytes(&proof.to_bytes()).unwrap();
    let nym = verify_root_board(&[global.public_key().clone()], &request, &proof, NOW).unwrap();
    assert_eq!(nym, passport.pseudonym(&root_community()));
    // Nothing in the public presentation names the source community or the
    // issuance tag: the pseudonym differs from the one shown to the issuer.
    assert_ne!(nym, passport.pseudonym(&community()));
    // The common expiry is public and exclusive; the request deadline is inclusive.
    assert!(verify_root_board(&[global.public_key().clone()], &request, &proof, NOW + 1).is_err());
    assert!(
        verify_root_board(
            &[global.public_key().clone()],
            &request,
            &proof,
            crate::root_board::ROOT_BOARD_COHORT_SECONDS,
        )
        .is_err()
    );
}

#[test]
fn independently_valid_passport_and_root_credential_of_two_holders_are_rejected() {
    let mut rng = rng();
    let global = key(&mut rng, "global");
    let root_key = root_issuer(&mut rng, "root-board-1");
    let root = descriptor(&root_key, 3);
    let alice = holder(&mut rng, &global);
    let bob = holder(&mut rng, &global);
    let alice_root = mint(&mut rng, &global, &root_key, &root, &alice);
    let bob_root = mint(&mut rng, &global, &root_key, &root, &bob);
    let request = root_request(&mut rng, &root);
    let issuers = [global.public_key().clone()];
    // Both halves verify alone: each holder's own credential pair is honest.
    for (passport, credential) in [(&alice, &alice_root), (&bob, &bob_root)] {
        let proof = root_board::present(&mut rng, passport, credential, &request).unwrap();
        verify_root_board(&issuers, &request, &proof, NOW).unwrap();
    }
    // The honest API refuses to mix; the hostile construction fails verification.
    assert_eq!(
        root_board::present(&mut rng, &alice, &bob_root, &request).err(),
        Some(Error::InvalidRootBoard)
    );
    let mixed = root_board::build_presentation(&mut rng, &alice, &bob_root, &request).unwrap();
    let mixed = RootBoardPresentation::from_bytes(&mixed.to_bytes()).unwrap();
    assert!(verify_root_board(&issuers, &request, &mixed, NOW).is_err());
}

#[test]
fn issuance_proof_cannot_commit_to_a_secret_other_than_the_passports() {
    let mut rng = rng();
    let global = key(&mut rng, "global");
    let root_key = root_issuer(&mut rng, "root-board-1");
    let root = descriptor(&root_key, 3);
    let alice = holder(&mut rng, &global);
    let other = HolderSecret::generate(&mut rng);
    let context = context(&mut rng, &root);
    let issuers = [global.public_key().clone()];
    let (hostile, _pending) =
        root_board::request_for_opening(&mut rng, &alice, &other, &context).unwrap();
    assert_eq!(
        verify_root_board_issuance(&issuers, &context, &hostile, NOW).err(),
        Some(Error::InvalidRootBoard)
    );
    // The same function with the passport's own secret verifies.
    let (honest, _pending) =
        root_board::request_for_opening(&mut rng, &alice, alice.secret(), &context).unwrap();
    verify_root_board_issuance(&issuers, &context, &honest, NOW).unwrap();
}

#[test]
fn issuance_is_bound_to_context_cohort_scope_issuer_and_time() {
    let mut rng = rng();
    let global = key(&mut rng, "global");
    let root_key = root_issuer(&mut rng, "root-board-1");
    let root = descriptor(&root_key, 3);
    let alice = holder(&mut rng, &global);
    let issuers = [global.public_key().clone()];
    let first = context(&mut rng, &root);
    let (request, _pending) = root_board::begin_issuance(&mut rng, &alice, &first).unwrap();
    verify_root_board_issuance(&issuers, &first, &request, NOW).unwrap();
    // Another nonce, descriptor epoch, root issuer or deadline is another
    // transcript; the proof does not transfer.
    let second = context(&mut rng, &root);
    assert!(verify_root_board_issuance(&issuers, &second, &request, NOW).is_err());
    let other_epoch = context(&mut rng, &descriptor(&root_key, 4));
    assert!(verify_root_board_issuance(&issuers, &other_epoch, &request, NOW).is_err());
    let other_key = root_issuer(&mut rng, "root-board-2");
    let other_issuer = context(&mut rng, &descriptor(&other_key, 3));
    assert!(verify_root_board_issuance(&issuers, &other_issuer, &request, NOW).is_err());
    // Past the source request's inclusive deadline and past the cohort.
    assert_eq!(
        verify_root_board_issuance(&issuers, &first, &request, NOW + 1).err(),
        Some(Error::InvalidChallenge)
    );
    assert!(
        verify_root_board_issuance(
            &issuers,
            &first,
            &request,
            crate::root_board::ROOT_BOARD_COHORT_SECONDS,
        )
        .is_err()
    );
    // An untrusted or duplicated global key ring never verifies.
    assert_eq!(
        verify_root_board_issuance(&[], &first, &request, NOW).err(),
        Some(Error::UnknownKey)
    );
    assert_eq!(
        verify_root_board_issuance(&[issuers[0].clone(), issuers[0].clone()], &first, &request, NOW)
            .err(),
        Some(Error::DuplicateKeyId)
    );
    // The root key must differ from every global key the verifier trusts.
    let same_id = root_issuer(&mut rng, "global");
    let sneaky = descriptor(&same_id, 3);
    let sneaky_context = context(&mut rng, &sneaky);
    assert_eq!(
        root_board::begin_issuance(&mut rng, &alice, &sneaky_context).err(),
        Some(Error::InvalidRootBoard)
    );
}

#[test]
fn signature_release_requires_the_exact_context_issuer_and_open_cohort() {
    let mut rng = rng();
    let global = key(&mut rng, "global");
    let root_key = root_issuer(&mut rng, "root-board-1");
    let root = descriptor(&root_key, 3);
    let alice = holder(&mut rng, &global);
    let issuers = [global.public_key().clone()];
    let context = context(&mut rng, &root);
    let (request, _pending) = root_board::begin_issuance(&mut rng, &alice, &context).unwrap();
    let verify = || verify_root_board_issuance(&issuers, &context, &request, NOW).unwrap();
    // Wrong signing key, wrong expected descriptor, late clock.
    let other_key = root_issuer(&mut rng, "root-board-2");
    assert_eq!(
        issue_blind_root_board(&mut rng, &other_key, &root, verify(), NOW).err(),
        Some(Error::InvalidRootBoard)
    );
    let other = descriptor(&root_key, 4);
    assert_eq!(
        issue_blind_root_board(&mut rng, &root_key, &other, verify(), NOW).err(),
        Some(Error::InvalidRootBoard)
    );
    assert_eq!(
        issue_blind_root_board(&mut rng, &root_key, &root, verify(), NOW + 1).err(),
        Some(Error::InvalidChallenge)
    );
    let blind = issue_blind_root_board(&mut rng, &root_key, &root, verify(), NOW).unwrap();
    // The signed attributes are exactly the common cohort: a public, issuer-
    // independent value that carries no issuance time and no per-holder datum.
    assert!(blind.descriptor == root);
}

#[test]
fn answers_for_other_descriptors_or_attributes_never_install() {
    let mut rng = rng();
    let global = key(&mut rng, "global");
    let root_key = root_issuer(&mut rng, "root-board-1");
    let root = descriptor(&root_key, 3);
    let alice = holder(&mut rng, &global);
    let context = context(&mut rng, &root);
    let (request, pending) = root_board::begin_issuance(&mut rng, &alice, &context).unwrap();
    let verified = verify_root_board_issuance(
        &[global.public_key().clone()],
        &context,
        &request,
        NOW,
    )
    .unwrap();
    let blind = issue_blind_root_board(&mut rng, &root_key, &root, verified, NOW).unwrap();
    // An answer carrying another descriptor is refused and consumes the attempt.
    let mut state = RootBoardState {
        pending: Some(pending),
        credential: None,
    };
    let wrong = BlindRootBoardCredential {
        descriptor: descriptor(&root_key, 4),
        blind: BlindPassport::from_bytes(&blind.blind.to_bytes()).unwrap(),
    };
    assert_eq!(state.finish(&wrong).err(), Some(Error::InvalidRootBoard));
    assert!(state.is_empty());
    assert_eq!(state.finish(&blind).err(), Some(Error::NoPendingIssuance));
    // Decoding refuses an answer whose signed attributes are not the common
    // cohort, even when the issuer's original signing path produced it.
    let challenge = IssuanceChallenge::generate(&mut rng);
    let secret = HolderSecret::generate(&mut rng);
    let (issuance, _opening) =
        request_issue(&mut rng, &secret, root_key.public_key(), &challenge).unwrap();
    let off_cohort = root_key
        .issue_blind(
            &mut rng,
            &issuance,
            &challenge,
            &PassportAttributes::new(EXPIRY, 3).with_gate(root_gate(), EXPIRY),
        )
        .unwrap();
    let mut forged = Writer::new(Kind::BlindRootBoardCredential);
    forged.bytes(&root.to_bytes());
    forged.bytes(&off_cohort.to_bytes());
    assert_eq!(
        BlindRootBoardCredential::from_bytes(&forged.finish_public()).err(),
        Some(Error::InvalidRootBoard)
    );
    let mut genuine = Writer::new(Kind::BlindRootBoardCredential);
    genuine.bytes(&root.to_bytes());
    genuine.bytes(&blind.blind.to_bytes());
    let mut bytes = genuine.finish_public();
    assert!(BlindRootBoardCredential::from_bytes(&bytes).is_ok());
    bytes.push(0);
    assert!(BlindRootBoardCredential::from_bytes(&bytes).is_err());
}

#[test]
fn state_codec_rejects_every_inconsistent_extension() {
    let mut rng = rng();
    let global = key(&mut rng, "global");
    let root_key = root_issuer(&mut rng, "root-board-1");
    let root = descriptor(&root_key, 3);
    let alice = holder(&mut rng, &global);
    let credential = mint(&mut rng, &global, &root_key, &root, &alice);
    let context = context(&mut rng, &root);
    let (_request, pending) = root_board::begin_issuance(&mut rng, &alice, &context).unwrap();
    let state = RootBoardState {
        pending: Some(pending),
        credential: Some(credential),
    };
    let bytes = state.to_bytes();
    let restored = RootBoardState::from_bytes(&bytes, alice.secret()).unwrap();
    assert!(restored.pending.is_some() && restored.credential.is_some());
    // The same bytes under another holder secret never restore.
    let other = HolderSecret::generate(&mut rng);
    assert_eq!(
        RootBoardState::from_bytes(&bytes, &other).err(),
        Some(Error::InvalidSealedHolder)
    );
    // Every truncation and trailing byte is refused.
    for length in 0..bytes.len() {
        assert!(RootBoardState::from_bytes(&bytes[..length], alice.secret()).is_err());
    }
    let mut appended = bytes.to_vec();
    appended.push(0);
    assert!(RootBoardState::from_bytes(&appended, alice.secret()).is_err());
    // An entirely empty extension has no canonical encoding.
    let empty = RootBoardState::default().to_bytes();
    assert_eq!(
        RootBoardState::from_bytes(&empty, alice.secret()).err(),
        Some(Error::InvalidSealedHolder)
    );
}

#[test]
fn descriptor_and_wire_objects_refuse_noncanonical_input() {
    let mut rng = rng();
    let root_key = root_issuer(&mut rng, "root-board-1");
    let root = descriptor(&root_key, 3);
    assert!(RootBoardPublicKey::from_bytes(&root.to_bytes()).unwrap() == root);
    assert_eq!(root.cohort_start(), 0);
    assert_eq!(root.expires_at(), crate::root_board::ROOT_BOARD_COHORT_SECONDS);
    assert_eq!(root.policy_epoch(), 3);
    assert_eq!(root.community(), &root_community());
    assert_eq!(root.issuer(), root_key.public_key());
    // The cohort is a fixed Unix-aligned period and the catalogue is fixed.
    for start in [1, crate::root_board::ROOT_BOARD_COHORT_SECONDS - 1] {
        assert_eq!(
            RootBoardPublicKey::from_authenticated_beacon(
                root_key.public_key().clone(),
                root_community(),
                3,
                start,
            )
            .err(),
            Some(Error::InvalidRootBoard)
        );
    }
    let global = key(&mut rng, "global");
    assert_eq!(
        RootBoardPublicKey::from_authenticated_beacon(
            global.public_key().clone(),
            root_community(),
            3,
            0,
        )
        .err(),
        Some(Error::InvalidRootBoard)
    );
    assert!(RootBoardPublicKey::from_bytes(&[]).is_err());
    let mut bytes = root.to_bytes();
    bytes.push(0);
    assert!(RootBoardPublicKey::from_bytes(&bytes).is_err());
    // A context cannot share its source and root scope, nor start outside the cohort.
    let source =
        PresentationRequest::for_epoch(&mut rng, root_community(), 7, [gate()], NOW, EXPIRY).unwrap();
    assert_eq!(
        RootBoardIssuanceContext::new(&mut rng, source, root.clone()).err(),
        Some(Error::InvalidRootBoard)
    );
    let late = PresentationRequest::for_epoch(
        &mut rng,
        community(),
        7,
        [gate()],
        crate::root_board::ROOT_BOARD_COHORT_SECONDS,
        crate::root_board::ROOT_BOARD_COHORT_SECONDS,
    )
    .unwrap();
    assert_eq!(
        RootBoardIssuanceContext::new(&mut rng, late, root.clone()).err(),
        Some(Error::InvalidRootBoard)
    );
    let context = context(&mut rng, &root);
    let decoded = RootBoardIssuanceContext::from_bytes(&context.to_bytes()).unwrap();
    assert!(decoded == context);
    assert_eq!(decoded.source_request(), context.source_request());
    assert!(decoded.root() == context.root());
    assert!(RootBoardIssuanceContext::from_bytes(&[]).is_err());
    let global_request =
        PresentationRequest::for_epoch(&mut rng, community(), 7, [gate()], NOW, EXPIRY).unwrap();
    // A root request must be issued for the root scope itself.
    assert_eq!(
        RootBoardRequest::new(global_request, root).err(),
        Some(Error::InvalidRootBoard)
    );
}
