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

#[test]
fn root_v3_request_framing_is_exact_and_does_not_upgrade_normal_v2() {
    let mut rng = rng();
    let root_key = root_issuer(&mut rng, "root-board-wire");
    let root = descriptor(&root_key, 3);
    let source =
        PresentationRequest::for_epoch(&mut rng, community(), 7, [gate()], NOW, EXPIRY).unwrap();
    let ordinary = source.to_bytes();
    assert_eq!(&ordinary[..6], b"cpsd\x02\x08");
    let nested = root_board::request_bytes(&source);
    assert_eq!(&nested[..6], b"cpsd\x03\x08");
    assert_eq!(&ordinary[6..], &nested[6..]);
    assert!(PresentationRequest::from_bytes(&nested).is_err());
    assert!(root_board::request_from_bytes(&ordinary).is_err());
    assert!(root_board::request_from_bytes(&nested).unwrap() == source);

    let context = RootBoardIssuanceContext::new(&mut rng, source, root.clone()).unwrap();
    let bytes = context.to_bytes();
    assert_eq!(&bytes[..6], b"cpsd\x03\x0f");
    let mut reader = crate::wire::Reader::new(&bytes, Kind::RootBoardIssuanceContext).unwrap();
    assert_eq!(reader.bytes().unwrap(), nested);
    assert_eq!(reader.bytes().unwrap(), root.to_bytes());
    assert_eq!(reader.fixed::<32>().unwrap(), context.nonce());
    reader.finish().unwrap();
    assert!(RootBoardIssuanceContext::from_bytes(&bytes).unwrap() == context);

    let mut root_signer = crate::test_support::signer(91);
    let expected_root = AuthenticatedCommunity::from_authenticated_origin(
        root_community(),
        root_signer.key_ring().clone(),
    );
    let mut source_signer = crate::test_support::signer(92);
    let expected_source = AuthenticatedCommunity::from_authenticated_origin(
        community(),
        source_signer.key_ring().clone(),
    );
    let signed_root = root_signer
        .sign(csgn::Kind::Credential, &bytes, 0, NOW + 1)
        .unwrap();
    let legacy_source = source_signer
        .sign(csgn::Kind::Credential, &nested, 0, NOW + 1)
        .unwrap();
    assert!(expected_source.authenticate(&legacy_source, NOW).is_err());
    assert!(
        expected_root
            .authenticate_root_board_issuance(&signed_root, &expected_source, &legacy_source, NOW,)
            .unwrap()
            == context
    );

    let mut old_nested = bytes.clone();
    old_nested[14] = 2; // Six-byte outer header + four-byte field length + version.
    assert!(RootBoardIssuanceContext::from_bytes(&old_nested).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(RootBoardIssuanceContext::from_bytes(&trailing).is_err());

    let holder = HolderSecret::generate(&mut rng);
    let global = key(&mut rng, "ordinary-v2");
    let challenge = IssuanceChallenge::generate(&mut rng);
    let (issuance, _) = request_issue(&mut rng, &holder, global.public_key(), &challenge).unwrap();
    let mut issuance_wire = issuance.to_bytes();
    assert_eq!(issuance_wire[4], 2);
    issuance_wire[4] = 3;
    assert!(IssuanceRequest::from_bytes(&issuance_wire).is_err());
}

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
    let source =
        PresentationRequest::for_epoch(rng, community(), 7, [gate()], NOW, EXPIRY).unwrap();
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
    let verified =
        verify_root_board_issuance(&[global.public_key().clone()], &context, &request, NOW)
            .unwrap();
    assert_eq!(
        verified.source_pseudonym(),
        passport.pseudonym(&community())
    );
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
        verify_root_board_issuance(
            &[issuers[0].clone(), issuers[0].clone()],
            &first,
            &request,
            NOW
        )
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
    let verified =
        verify_root_board_issuance(&[global.public_key().clone()], &context, &request, NOW)
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
    assert_eq!(
        root.expires_at(),
        crate::root_board::ROOT_BOARD_COHORT_SECONDS
    );
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
        PresentationRequest::for_epoch(&mut rng, root_community(), 7, [gate()], NOW, EXPIRY)
            .unwrap();
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

#[test]
fn restored_root_state_binds_each_opening_and_credential_independently() {
    let mut rng = rng();
    let global = key(&mut rng, "global");
    let root_key = root_issuer(&mut rng, "root-board-1");
    let other_key = root_issuer(&mut rng, "root-board-2");
    let root = descriptor(&root_key, 3);
    let other_root = descriptor(&other_key, 3);
    let alice = holder(&mut rng, &global);
    let bob = holder(&mut rng, &global);
    let credential = mint(&mut rng, &global, &root_key, &root, &alice);
    let context = context(&mut rng, &root);
    let (_, pending) = root_board::begin_issuance(&mut rng, &alice, &context).unwrap();

    // These encodings are individually valid; their associations are hostile.
    let encode = |pending_descriptor: &[u8], opening: &[u8], descriptor: &[u8], passport: &[u8]| {
        let mut w = Writer::new(Kind::RootBoardState);
        w.bytes(pending_descriptor);
        w.bytes(opening);
        w.bytes(descriptor);
        w.bytes(passport);
        w.finish_secret()
    };
    let opening = pending.opening.to_bytes();
    let root_bytes = root.to_bytes();
    let other_bytes = other_root.to_bytes();
    let passport = credential.passport.to_bytes();
    for bytes in [
        encode(&other_bytes, &opening, &[], &[]),
        encode(&[], &[], &other_bytes, &passport),
        encode(&[], &[], &descriptor(&root_key, 4).to_bytes(), &passport),
    ] {
        assert_eq!(
            RootBoardState::from_bytes(&bytes, alice.secret()).err(),
            Some(Error::InvalidSealedHolder)
        );
    }
    let valid = encode(&[], &[], &root_bytes, &passport);
    assert_eq!(
        RootBoardState::from_bytes(&valid, bob.secret()).err(),
        Some(Error::InvalidSealedHolder)
    );
    let restored = RootBoardState::from_bytes(&valid, alice.secret()).unwrap();
    let request = root_request(&mut rng, &root);
    let proof = root_board::present(
        &mut rng,
        &alice,
        restored.credential.as_ref().unwrap(),
        &request,
    )
    .unwrap();
    assert_eq!(
        verify_root_board(&[global.public_key().clone()], &request, &proof, NOW).unwrap(),
        alice.pseudonym(&root_community())
    );

    // A missing half is malformed, rather than silently treated as absent.
    for bytes in [
        encode(&[], &opening, &[], &[]),
        encode(&root_bytes, &[], &[], &[]),
        encode(&[], &[], &[], &passport),
        encode(&[], &[], &root_bytes, &[]),
    ] {
        assert!(RootBoardState::from_bytes(&bytes, alice.secret()).is_err());
    }
}

#[test]
fn root_presentation_codec_rejects_independent_expiry_proofs_for_root_credential() {
    let mut rng = rng();
    let global = key(&mut rng, "global");
    let root_key = root_issuer(&mut rng, "root-board-1");
    let root = descriptor(&root_key, 3);
    let alice = holder(&mut rng, &global);
    let credential = mint(&mut rng, &global, &root_key, &root, &alice);
    let global_request =
        PresentationRequest::for_epoch(&mut rng, root_community(), 7, [gate()], NOW, EXPIRY)
            .unwrap();
    let global_proof = alice.present_trusted(&mut rng, &global_request).unwrap();
    let independent = PresentationRequest::new(
        &mut rng,
        root_community(),
        root.policy_epoch(),
        [root_gate()],
        NOW,
    )
    .unwrap();
    let root_proof = credential
        .passport
        .present_trusted(&mut rng, &independent)
        .unwrap();
    // The original independent proof is valid for its original request.
    verify(
        &mut rng,
        &[root_key.public_key().clone()],
        &independent,
        &root_proof,
    )
    .unwrap();
    let mut w = Writer::new(Kind::RootBoardPresentation);
    w.key_id(global.public_key().key_id());
    w.fixed(&global_proof.pseudonym().to_bytes());
    // Use the original root-only maintained protocol to build its genuine
    // independent-expiry proof shape. The ordinary v2 proof above remains valid.
    let global_direct = root_board::TestRootProof::new(
        &mut rng,
        &alice,
        &global_request,
        &global_proof.pseudonym().point().unwrap(),
    )
    .unwrap();
    let root_direct = root_board::TestRootProof::new(
        &mut rng,
        &credential.passport,
        &independent,
        &root_proof.pseudonym().point().unwrap(),
    )
    .unwrap();
    root_direct
        .verify(
            root_key.public_key(),
            &independent,
            &root_proof.pseudonym().point().unwrap(),
        )
        .unwrap();
    w.root_board_proof(&global_direct);
    w.root_board_proof(&root_direct);
    assert_eq!(
        RootBoardPresentation::from_bytes(&w.finish_public()).err(),
        Some(Error::InvalidRootBoard)
    );
}

#[test]
fn root_cohort_cannot_authorize_a_request_before_its_start() {
    let mut rng = rng();
    let root_key = root_issuer(&mut rng, "root-board-1");
    let start = crate::root_board::ROOT_BOARD_COHORT_SECONDS;
    let root = RootBoardPublicKey::from_authenticated_beacon(
        root_key.public_key().clone(),
        root_community(),
        3,
        start,
    )
    .unwrap();
    let early_source = PresentationRequest::new(&mut rng, community(), 7, [], start - 1).unwrap();
    assert_eq!(
        RootBoardIssuanceContext::new(&mut rng, early_source, root.clone()).err(),
        Some(Error::InvalidRootBoard)
    );
    let current_source = PresentationRequest::new(&mut rng, community(), 7, [], start).unwrap();
    RootBoardIssuanceContext::new(&mut rng, current_source, root).unwrap();
}

#[test]
fn root_issuance_wire_rejects_identity_commitments_and_foreign_blind_issuers() {
    use crate::wire::Reader;
    use ark_bls12_381::G1Affine;
    use ark_ec::AffineRepr;

    let mut rng = rng();
    let global = key(&mut rng, "global");
    let root_key = root_issuer(&mut rng, "root-board-1");
    let root = descriptor(&root_key, 3);
    let alice = holder(&mut rng, &global);
    let context = context(&mut rng, &root);
    let (request, pending) = root_board::begin_issuance(&mut rng, &alice, &context).unwrap();

    // Preserve the genuine proof fields while replacing only the commitment.
    let bytes = request.to_bytes();
    let mut r = Reader::new(&bytes, Kind::RootBoardIssuanceRequest).unwrap();
    let key_id = r.key_id().unwrap();
    let pseudonym = r.fixed::<48>().unwrap();
    let _: G1Affine = r.ark("root commitment").unwrap();
    let proof = r.root_board_proof().unwrap();
    let opening = r.bytes().unwrap();
    r.finish().unwrap();
    let mut w = Writer::new(Kind::RootBoardIssuanceRequest);
    w.key_id(&key_id);
    w.fixed(&pseudonym);
    w.ark(&G1Affine::zero());
    w.root_board_proof(&proof);
    w.bytes(opening);
    assert_eq!(
        RootBoardIssuanceRequest::from_bytes(&w.finish_public()).err(),
        Some(Error::InvalidRootBoard)
    );
    let verified =
        verify_root_board_issuance(&[global.public_key().clone()], &context, &request, NOW)
            .unwrap();
    let blind = issue_blind_root_board(&mut rng, &root_key, &root, verified, NOW).unwrap();
    let bytes = blind.to_bytes();
    let mut r = Reader::new(&bytes, Kind::BlindRootBoardCredential).unwrap();
    let _original_descriptor = r.bytes().unwrap();
    let blind_passport = r.bytes().unwrap();
    r.finish().unwrap();
    let other_key = root_issuer(&mut rng, "root-board-2");
    let other_root = descriptor(&other_key, 3);
    assert_eq!(root.attributes(), other_root.attributes());
    let mut w = Writer::new(Kind::BlindRootBoardCredential);
    w.bytes(&other_root.to_bytes());
    w.bytes(blind_passport);
    assert_eq!(
        BlindRootBoardCredential::from_bytes(&w.finish_public()).err(),
        Some(Error::InvalidRootBoard)
    );
    let original = BlindRootBoardCredential::from_bytes(&bytes).unwrap();
    let mut state = RootBoardState {
        pending: Some(pending),
        credential: None,
    };
    state.finish(&original).unwrap();
    let changed = root_request(&mut rng, &descriptor(&root_key, 4));
    assert_eq!(
        root_board::present(
            &mut rng,
            &alice,
            state.credential.as_ref().unwrap(),
            &changed
        )
        .err(),
        Some(Error::InvalidRootBoard)
    );
    let valid = root_request(&mut rng, &root);
    let proof =
        root_board::present(&mut rng, &alice, state.credential.as_ref().unwrap(), &valid).unwrap();
    verify_root_board(&[global.public_key().clone()], &valid, &proof, NOW).unwrap();
}
