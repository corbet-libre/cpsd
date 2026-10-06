//! Same-holder root-board credential through the nonexporting holder: issuance,
//! sealed restart, renewal, joint presentation and every authentication refusal.

use cpsd::rand::{SeedableRng, rngs::StdRng};
use cpsd::*;

#[path = "root_board/issuance_nonce.rs"]
mod issuance_nonce;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const EXPIRY: Timestamp = 2_000_000;
const NOW: Timestamp = 1_000;

fn signer(seed: u8) -> csgn::Signer {
    csgn::Signer::new(
        "cmty:test",
        csgn::SecretKey::from_seed(&mut [seed; 32]),
        0,
        TIME_LIMIT,
    )
    .unwrap()
}

fn sign(signer: &mut csgn::Signer, payload: &[u8], deadline: Timestamp) -> Vec<u8> {
    signer
        .sign(csgn::Kind::Credential, payload, 0, deadline + 1)
        .unwrap()
}

struct World {
    rng: StdRng,
    phone: GateId,
    global: IssuerKey,
    root_key: IssuerKey,
    root_community: CommunityId,
    source: CommunityId,
    descriptor: RootBoardPublicKey,
    signer: csgn::Signer,
    expected: AuthenticatedCommunity,
    source_signer: csgn::Signer,
    expected_source: AuthenticatedCommunity,
}

fn world() -> World {
    let mut rng = StdRng::seed_from_u64(311);
    let phone = GateId::new("phone").unwrap();
    let global =
        IssuerKey::generate(&mut rng, KeyId::new("global").unwrap(), vec![phone.clone()]).unwrap();
    let root_key = IssuerKey::generate(
        &mut rng,
        KeyId::new("root-board-1").unwrap(),
        vec![GateId::new("root-board").unwrap()],
    )
    .unwrap();
    let root_community = CommunityId::new(b"root").unwrap();
    let descriptor = RootBoardPublicKey::from_authenticated_beacon(
        root_key.public_key().clone(),
        root_community.clone(),
        3,
        0,
    )
    .unwrap();
    let source = CommunityId::new(b"community-a").unwrap();
    let source_signer = signer(7);
    let expected_source = AuthenticatedCommunity::from_authenticated_origin(
        source.clone(),
        source_signer.key_ring().clone(),
    );
    let signer = signer(5);
    let expected = AuthenticatedCommunity::from_authenticated_origin(
        root_community.clone(),
        signer.key_ring().clone(),
    );
    World {
        rng,
        phone,
        global,
        root_key,
        root_community,
        source,
        descriptor,
        signer,
        expected,
        source_signer,
        expected_source,
    }
}

impl World {
    fn holder(&self) -> OpaqueHolder {
        OpaqueHolder::from_seed_and_sealing_key(&mut [7; 32], &mut [8; 32], b"wallet-a").unwrap()
    }

    fn passport(&mut self, holder: &mut OpaqueHolder) {
        let challenge = IssuanceChallenge::generate(&mut self.rng);
        let request = holder
            .begin_issuance(&mut self.rng, self.global.public_key(), &challenge)
            .unwrap();
        let attributes = PassportAttributes::new(EXPIRY, 7).with_gate(self.phone.clone(), EXPIRY);
        let blind = self
            .global
            .issue_blind(&mut self.rng, &request, &challenge, &attributes)
            .unwrap();
        holder.finish_issuance(&blind).unwrap();
    }

    fn context(&mut self) -> RootBoardIssuanceContext {
        let source = PresentationRequest::for_epoch(
            &mut self.rng,
            self.source.clone(),
            7,
            [self.phone.clone()],
            NOW,
            EXPIRY,
        )
        .unwrap();
        RootBoardIssuanceContext::new(&mut self.rng, source, self.descriptor.clone()).unwrap()
    }

    fn signed_context(&mut self, context: &RootBoardIssuanceContext) -> (Vec<u8>, Vec<u8>) {
        let root = sign(&mut self.signer, &context.to_bytes(), context.deadline());
        let source = sign(
            &mut self.source_signer,
            &context.source_request().to_bytes(),
            context.deadline(),
        );
        (root, source)
    }

    /// Run one complete honest issuance, returning the answer for inspection.
    fn issue(&mut self, holder: &mut OpaqueHolder) -> BlindRootBoardCredential {
        let context = self.context();
        let (signed, signed_source) = self.signed_context(&context);
        let request = holder
            .begin_root_board_issuance(
                &mut self.rng,
                &self.expected,
                &signed,
                &self.expected_source,
                &signed_source,
                NOW,
            )
            .unwrap();
        let request = RootBoardIssuanceRequest::from_bytes(&request.to_bytes()).unwrap();
        let verified = verify_root_board_issuance(
            &[self.global.public_key().clone()],
            &context,
            &request,
            NOW,
        )
        .unwrap();
        // Only the source pseudonym and the shared common cohort reach the issuer.
        assert_eq!(verified.source_pseudonym(), holder.pseudonym(&self.source));
        assert_ne!(
            verified.source_pseudonym(),
            holder.pseudonym(&self.root_community)
        );
        let blind = issue_blind_root_board(
            &mut self.rng,
            &self.root_key,
            &self.descriptor,
            verified,
            NOW,
        )
        .unwrap();
        BlindRootBoardCredential::from_bytes(&blind.to_bytes()).unwrap()
    }

    fn request(&mut self) -> (RootBoardRequest, Vec<u8>) {
        let global = PresentationRequest::for_epoch(
            &mut self.rng,
            self.root_community.clone(),
            7,
            [self.phone.clone()],
            NOW,
            EXPIRY,
        )
        .unwrap();
        let request = RootBoardRequest::new(global, self.descriptor.clone()).unwrap();
        let signed = sign(&mut self.signer, &request.to_bytes(), request.deadline());
        (request, signed)
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn joint_request_replay_slot_binds_the_complete_root_descriptor() {
    let mut w = world();
    let mut holder = w.holder();
    w.passport(&mut holder);
    let blind = w.issue(&mut holder);
    holder.finish_root_board_issuance(&blind).unwrap();
    let (request, signed) = w.request();
    let proof = holder
        .present_root_board(&mut w.rng, &w.expected, &signed, NOW)
        .unwrap();
    let store = MemoryStore::new(w.root_community.clone(), 4).unwrap();
    let verifier = Verifier::new(store, vec![w.global.public_key().clone()]).unwrap();
    let wrong_scope = Verifier::new(
        MemoryStore::new(w.source.clone(), 4).unwrap(),
        vec![w.global.public_key().clone()],
    )
    .unwrap();
    assert!(matches!(
        wrong_scope
            .register_root_board_request(request.clone())
            .await,
        Err(Error::InvalidChallenge)
    ));
    assert!(matches!(
        wrong_scope
            .verify_root_board(&request, &proof, 7, NOW)
            .await,
        Err(Error::InvalidChallenge)
    ));
    assert!(matches!(
        verifier.verify_root_board(&request, &proof, 7, NOW).await,
        Err(Error::InvalidChallenge)
    ));
    verifier
        .register_root_board_request(request.clone())
        .await
        .unwrap();
    assert!(matches!(
        verifier.register_root_board_request(request.clone()).await,
        Err(Error::ChallengeConflict)
    ));
    assert!(matches!(
        verifier.verify_root_board(&request, &proof, 8, NOW).await,
        Err(Error::WrongEpoch)
    ));
    assert!(matches!(
        verifier
            .verify_root_board(&request, &proof, 7, NOW + 1)
            .await,
        Err(Error::InvalidChallenge)
    ));
    let altered = RootBoardRequest::new(
        request.global_request().clone(),
        RootBoardPublicKey::from_authenticated_beacon(
            w.root_key.public_key().clone(),
            w.root_community.clone(),
            4,
            0,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        verifier.verify_root_board(&altered, &proof, 7, NOW).await,
        Err(Error::InvalidChallenge)
    ));
    // A separately valid joint proof cannot consume this request's challenge.
    let (_, other_signed) = w.request();
    let other = holder
        .present_root_board(&mut w.rng, &w.expected, &other_signed, NOW)
        .unwrap();
    assert!(
        verifier
            .verify_root_board(&request, &other, 7, NOW)
            .await
            .is_err()
    );
    assert_eq!(
        verifier
            .verify_root_board(&request, &proof, 7, NOW)
            .await
            .unwrap(),
        holder.pseudonym(&w.root_community),
    );
    assert!(matches!(
        verifier.verify_root_board(&request, &proof, 7, NOW).await,
        Err(Error::InvalidChallenge)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn ordinary_passport_and_joint_root_challenges_cannot_be_interchanged() {
    let mut w = world();
    let mut holder = w.holder();
    w.passport(&mut holder);
    let blind = w.issue(&mut holder);
    holder.finish_root_board_issuance(&blind).unwrap();
    let store = MemoryStore::new(w.root_community.clone(), 4).unwrap();
    let verifier = Verifier::new(store, vec![w.global.public_key().clone()]).unwrap();
    let global = verifier
        .request_for_epoch(&mut w.rng, 7, [w.phone.clone()], NOW, EXPIRY)
        .await
        .unwrap();
    let request = RootBoardRequest::new(global.clone(), w.descriptor.clone()).unwrap();
    let signed = sign(&mut w.signer, &request.to_bytes(), NOW);
    let proof = holder
        .present_root_board(&mut w.rng, &w.expected, &signed, NOW)
        .unwrap();
    assert!(matches!(
        verifier.verify_root_board(&request, &proof, 7, NOW).await,
        Err(Error::InvalidChallenge)
    ));
    assert!(matches!(
        verifier.register_root_board_request(request).await,
        Err(Error::ChallengeConflict)
    ));
    let (joint, _) = w.request();
    verifier
        .register_root_board_request(joint.clone())
        .await
        .unwrap();
    let signed_global = sign(&mut w.signer, &joint.global_request().to_bytes(), NOW);
    let ordinary = holder
        .present(&mut w.rng, &w.expected, &signed_global, NOW)
        .unwrap();
    assert!(matches!(
        verifier
            .verify(&mut w.rng, joint.global_request(), &ordinary, 7, NOW)
            .await,
        Err(Error::InvalidChallenge)
    ));
}

#[cfg(all(not(target_arch = "wasm32"), feature = "storage"))]
#[tokio::test]
async fn joint_root_challenge_is_consumed_once_across_sql_handles_and_reopen() {
    let mut w = world();
    let mut holder = w.holder();
    w.passport(&mut holder);
    let blind = w.issue(&mut holder);
    holder.finish_root_board_issuance(&blind).unwrap();
    let (request, signed) = w.request();
    let proof = holder
        .present_root_board(&mut w.rng, &w.expected, &signed, NOW)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let file = format!("file://{}", dir.path().join("root.db").display());
    let db = crlt::Db::open(crlt::Config::new(&file, "")).await.unwrap();
    db.migrate(&[crlt::Migration::new(1, "cpsd", storage::libsql::SCHEMA)])
        .await
        .unwrap();
    let make = |db: &crlt::Db| {
        Verifier::new(
            storage::libsql::LibsqlStore::new(db, w.root_community.clone(), 4).unwrap(),
            vec![w.global.public_key().clone()],
        )
        .unwrap()
    };
    let first = make(&db);
    let second = make(&db);
    first
        .register_root_board_request(request.clone())
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        first.verify_root_board(&request, &proof, 7, NOW),
        second.verify_root_board(&request, &proof, 7, NOW),
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let success = a.or(b).unwrap();
    assert_eq!(success, holder.pseudonym(&w.root_community));
    drop(first);
    drop(second);
    drop(db);
    let reopened = crlt::Db::open(crlt::Config::new(&file, "")).await.unwrap();
    assert!(matches!(
        make(&reopened)
            .verify_root_board(&request, &proof, 7, NOW)
            .await,
        Err(Error::InvalidChallenge)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn valid_root_signatures_do_not_make_other_payload_types_authoritative() {
    let mut w = world();
    let mut holder = w.holder();
    w.passport(&mut holder);
    let blind = w.issue(&mut holder);
    holder.finish_root_board_issuance(&blind).unwrap();
    let context = w.context();
    let (_, signed_source) = w.signed_context(&context);
    let (request, signed_request) = w.request();

    // Each envelope has the expected signer, kind and exclusive expiry, but
    // the typed payload belongs to a different operation.
    assert_eq!(
        w.expected
            .authenticate_root_board_issuance(
                &signed_request,
                &w.expected_source,
                &signed_source,
                NOW,
            )
            .err(),
        Some(Error::InvalidPresentationRequest)
    );
    assert!(matches!(
        holder.begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &signed_request,
            &w.expected_source,
            &signed_source,
            NOW,
        ),
        Err(Error::InvalidPresentationRequest)
    ));
    for payload in [context.to_bytes(), context.source_request().to_bytes()] {
        let signed = sign(&mut w.signer, &payload, request.deadline());
        assert_eq!(
            w.expected
                .authenticate_root_board_request(&signed, NOW)
                .err(),
            Some(Error::InvalidPresentationRequest)
        );
        assert!(matches!(
            holder.present_root_board(&mut w.rng, &w.expected, &signed, NOW,),
            Err(Error::InvalidPresentationRequest)
        ));
    }
    let proof = holder
        .present_root_board(&mut w.rng, &w.expected, &signed_request, NOW)
        .unwrap();
    verify_root_board(&[w.global.public_key().clone()], &request, &proof, NOW).unwrap();
    // Failed authentication did not install a pending opening or remove the
    // existing credential: a full honest renewal still completes.
    let renewed = w.issue(&mut holder);
    holder.finish_root_board_issuance(&renewed).unwrap();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn root_payload_deadlines_cannot_be_extended_by_live_cose_envelopes() {
    let mut w = world();
    let mut holder = w.holder();
    w.passport(&mut holder);
    let blind = w.issue(&mut holder);
    holder.finish_root_board_issuance(&blind).unwrap();
    let context = w.context();
    let (_, signed_source) = w.signed_context(&context);
    let (request, original) = w.request();
    let extended_context = sign(&mut w.signer, &context.to_bytes(), context.deadline() + 5);
    let extended_request = sign(&mut w.signer, &request.to_bytes(), request.deadline() + 5);
    let late = NOW + 1;
    // Verify the envelopes really are live at the tested instant; refusal must
    // enforce the inner deadline before the independently signed source request.
    for signed in [&extended_context, &extended_request] {
        w.signer
            .key_ring()
            .verify(signed, csgn::Kind::Credential, late)
            .unwrap();
    }
    assert_eq!(
        w.expected
            .authenticate_root_board_issuance(
                &extended_context,
                &w.expected_source,
                &signed_source,
                late,
            )
            .err(),
        Some(Error::InvalidPresentationRequest)
    );
    assert!(matches!(
        holder.begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &extended_context,
            &w.expected_source,
            &signed_source,
            late,
        ),
        Err(Error::InvalidPresentationRequest)
    ));
    assert_eq!(
        w.expected
            .authenticate_root_board_request(&extended_request, late)
            .err(),
        Some(Error::InvalidPresentationRequest)
    );
    assert!(matches!(
        holder.present_root_board(&mut w.rng, &w.expected, &extended_request, late,),
        Err(Error::InvalidPresentationRequest)
    ));
    let proof = holder
        .present_root_board(&mut w.rng, &w.expected, &original, NOW)
        .unwrap();
    verify_root_board(&[w.global.public_key().clone()], &request, &proof, NOW).unwrap();
    let renewed = w.issue(&mut holder);
    holder.finish_root_board_issuance(&renewed).unwrap();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn issuance_seal_restore_and_joint_presentation_use_one_hidden_secret() {
    let mut w = world();
    let mut holder = w.holder();
    let reopened = w.holder();
    // No passport, no root issuance and no root presentation.
    let context = w.context();
    let (signed, signed_source) = w.signed_context(&context);
    assert!(matches!(
        holder.begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &signed,
            &w.expected_source,
            &signed_source,
            NOW
        ),
        Err(Error::PassportUnavailable)
    ));
    let (request, signed_request) = w.request();
    assert!(matches!(
        holder.present_root_board(&mut w.rng, &w.expected, &signed_request, NOW),
        Err(Error::PassportUnavailable)
    ));
    w.passport(&mut holder);
    assert!(!holder.has_root_board());
    assert!(matches!(
        holder.present_root_board(&mut w.rng, &w.expected, &signed_request, NOW),
        Err(Error::PassportUnavailable)
    ));

    // The pending root opening survives a sealed restart and a second begin is
    // refused until it finishes or is cancelled.
    let context = w.context();
    let (signed, signed_source) = w.signed_context(&context);
    let issuance = holder
        .begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &signed,
            &w.expected_source,
            &signed_source,
            NOW,
        )
        .unwrap();
    assert!(matches!(
        holder.begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &signed,
            &w.expected_source,
            &signed_source,
            NOW
        ),
        Err(Error::IssuancePending)
    ));
    let verified =
        verify_root_board_issuance(&[w.global.public_key().clone()], &context, &issuance, NOW)
            .unwrap();
    let blind =
        issue_blind_root_board(&mut w.rng, &w.root_key, &w.descriptor, verified, NOW).unwrap();
    let sealed = holder.seal(&mut w.rng).unwrap();
    holder = reopened
        .restored(&SealedHolder::from_bytes(sealed.as_bytes()).unwrap())
        .unwrap();
    holder.finish_root_board_issuance(&blind).unwrap();
    assert!(holder.has_root_board());
    assert!(matches!(
        holder.finish_root_board_issuance(&blind),
        Err(Error::NoPendingIssuance)
    ));
    // The global passport attributes are untouched and show no root state.
    assert_eq!(holder.attributes().unwrap().policy_epoch, 7);

    // Both credentials restore from the sealed extension and present jointly.
    let installed = holder.seal(&mut w.rng).unwrap();
    holder = reopened.restored(&installed).unwrap();
    assert!(holder.has_root_board());
    let proof = holder
        .present_root_board(&mut w.rng, &w.expected, &signed_request, NOW)
        .unwrap();
    let proof = RootBoardPresentation::from_bytes(&proof.to_bytes()).unwrap();
    let nym = verify_root_board(&[w.global.public_key().clone()], &request, &proof, NOW).unwrap();
    assert_eq!(nym, holder.pseudonym(&w.root_community));
    assert_ne!(nym, holder.pseudonym(&w.source));

    // The old global presentation API is unaffected by the extension.
    let plain = PresentationRequest::for_epoch(
        &mut w.rng,
        w.source.clone(),
        7,
        [w.phone.clone()],
        NOW,
        EXPIRY,
    )
    .unwrap();
    let source_signer_cose = sign(&mut signer(6), &plain.to_bytes(), plain.now());
    let source_expected = AuthenticatedCommunity::from_authenticated_origin(
        w.source.clone(),
        signer(6).key_ring().clone(),
    );
    let shown = holder
        .present(&mut w.rng, &source_expected, &source_signer_cose, NOW)
        .unwrap();
    assert_eq!(
        verify(&mut w.rng, &[w.global.public_key().clone()], &plain, &shown).unwrap(),
        holder.pseudonym(&w.source)
    );

    // Holders with another seed or sealing context never restore this state.
    for (seed, key, context) in [
        (9, 8, b"wallet-a"),
        (7, 9, b"wallet-a"),
        (7, 8, b"wallet-b"),
    ] {
        let wrong =
            OpaqueHolder::from_seed_and_sealing_key(&mut [seed; 32], &mut [key; 32], context)
                .unwrap();
        assert!(wrong.restored(&installed).is_err());
    }
    for index in (0..installed.as_bytes().len()).step_by(7) {
        let mut bytes = installed.as_bytes().to_vec();
        bytes[index] ^= 1;
        if let Ok(changed) = SealedHolder::from_bytes(&bytes) {
            assert!(reopened.restored(&changed).is_err());
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn failed_renewal_keeps_the_previous_credential_and_success_replaces_it() {
    let mut w = world();
    let mut holder = w.holder();
    w.passport(&mut holder);
    let first = w.issue(&mut holder);
    holder.finish_root_board_issuance(&first).unwrap();
    let (request, signed_request) = w.request();
    let issuers = [w.global.public_key().clone()];
    let before = holder
        .present_root_board(&mut w.rng, &w.expected, &signed_request, NOW)
        .unwrap();
    verify_root_board(&issuers, &request, &before, NOW).unwrap();

    // A renewal answered for another descriptor consumes the attempt, fails,
    // and leaves the credential that already verified.
    let renewal = w.issue(&mut holder);
    holder.cancel_root_board_issuance();
    let other_key = IssuerKey::generate(
        &mut w.rng,
        KeyId::new("root-board-2").unwrap(),
        vec![GateId::new("root-board").unwrap()],
    )
    .unwrap();
    let other = RootBoardPublicKey::from_authenticated_beacon(
        other_key.public_key().clone(),
        w.root_community.clone(),
        3,
        0,
    )
    .unwrap();
    let other_source = PresentationRequest::for_epoch(
        &mut w.rng,
        w.source.clone(),
        7,
        [w.phone.clone()],
        NOW,
        EXPIRY,
    )
    .unwrap();
    let other_context = RootBoardIssuanceContext::new(&mut w.rng, other_source, other).unwrap();
    let (signed, signed_source) = w.signed_context(&other_context);
    holder
        .begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &signed,
            &w.expected_source,
            &signed_source,
            NOW,
        )
        .unwrap();
    assert!(matches!(
        holder.finish_root_board_issuance(&renewal),
        Err(Error::InvalidRootBoard)
    ));
    assert!(matches!(
        holder.finish_root_board_issuance(&renewal),
        Err(Error::NoPendingIssuance)
    ));
    assert!(holder.has_root_board());
    let (request, signed_request) = w.request();
    let after = holder
        .present_root_board(&mut w.rng, &w.expected, &signed_request, NOW)
        .unwrap();
    verify_root_board(&issuers, &request, &after, NOW).unwrap();

    // Cancelling drops only the pending opening.
    let context = w.context();
    let (signed, signed_source) = w.signed_context(&context);
    holder
        .begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &signed,
            &w.expected_source,
            &signed_source,
            NOW,
        )
        .unwrap();
    holder.cancel_root_board_issuance();
    holder.cancel_root_board_issuance();
    assert!(holder.has_root_board());
    let second = w.issue(&mut holder);
    holder.finish_root_board_issuance(&second).unwrap();
    let (request, signed_request) = w.request();
    let renewed = holder
        .present_root_board(&mut w.rng, &w.expected, &signed_request, NOW)
        .unwrap();
    verify_root_board(&issuers, &request, &renewed, NOW).unwrap();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn only_the_root_scope_authenticates_issuance_contexts_and_requests() {
    let mut w = world();
    let mut holder = w.holder();
    w.passport(&mut holder);
    let context = w.context();
    let (good, signed_source) = w.signed_context(&context);
    let wrong_ring = AuthenticatedCommunity::from_authenticated_origin(
        w.root_community.clone(),
        signer(6).key_ring().clone(),
    );
    let wrong_scope = AuthenticatedCommunity::from_authenticated_origin(
        w.source.clone(),
        w.signer.key_ring().clone(),
    );
    for expected in [&wrong_ring, &wrong_scope] {
        assert!(matches!(
            holder.begin_root_board_issuance(
                &mut w.rng,
                expected,
                &good,
                &w.expected_source,
                &signed_source,
                NOW
            ),
            Err(Error::InvalidPresentationRequest)
        ));
    }
    // Exclusive COSE expiry must equal the inclusive deadline plus one second.
    let skewed = sign(&mut w.signer, &context.to_bytes(), context.deadline() + 5);
    assert!(matches!(
        holder.begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &skewed,
            &w.expected_source,
            &signed_source,
            NOW
        ),
        Err(Error::InvalidPresentationRequest)
    ));
    // Past the deadline, unknown payloads and oversized input all refuse.
    assert!(matches!(
        holder.begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &good,
            &w.expected_source,
            &signed_source,
            NOW + 1
        ),
        Err(Error::InvalidPresentationRequest)
    ));
    let (request, signed_request) = w.request();
    let plain = sign(
        &mut w.signer,
        &request.global_request().to_bytes(),
        request.deadline(),
    );
    assert!(matches!(
        holder.begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &plain,
            &w.expected_source,
            &signed_source,
            NOW
        ),
        Err(Error::InvalidPresentationRequest)
    ));
    assert!(matches!(
        holder.begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &vec![0; 256 * 1024 + 1],
            &w.expected_source,
            &signed_source,
            NOW
        ),
        Err(Error::InvalidPresentationRequest)
    ));
    // A root request needs a retained root credential and the matching ring.
    let first = w.issue(&mut holder);
    holder.finish_root_board_issuance(&first).unwrap();
    for expected in [&wrong_ring, &wrong_scope] {
        assert!(matches!(
            holder.present_root_board(&mut w.rng, expected, &signed_request, NOW),
            Err(Error::InvalidPresentationRequest)
        ));
    }
    let skewed = sign(&mut w.signer, &request.to_bytes(), request.deadline() + 5);
    assert!(matches!(
        holder.present_root_board(&mut w.rng, &w.expected, &skewed, NOW),
        Err(Error::InvalidPresentationRequest)
    ));
    assert!(matches!(
        holder.present_root_board(&mut w.rng, &w.expected, &signed_request, NOW + 1),
        Err(Error::InvalidPresentationRequest)
    ));
    // The verifier rejects a stale deadline, a foreign request and wrong keys.
    let proof = holder
        .present_root_board(&mut w.rng, &w.expected, &signed_request, NOW)
        .unwrap();
    let issuers = [w.global.public_key().clone()];
    verify_root_board(&issuers, &request, &proof, NOW).unwrap();
    let (other_request, _) = w.request();
    assert!(verify_root_board(&issuers, &other_request, &proof, NOW).is_err());
    assert!(verify_root_board(&[], &request, &proof, NOW).is_err());
    assert!(verify_root_board(&issuers, &request, &proof, NOW + 1).is_err());
    let decoded_error = RootBoardPresentation::from_bytes(&[]);
    assert!(decoded_error.is_err());
    assert!(!Error::InvalidRootBoard.to_string().is_empty());
}

fn assert_source_refused(
    w: &mut World,
    holder: &mut OpaqueHolder,
    root: &[u8],
    source: &[u8],
    now: Timestamp,
) {
    // The public authenticator must enforce the same boundary as the holder.
    assert!(matches!(
        w.expected
            .authenticate_root_board_issuance(root, &w.expected_source, source, now),
        Err(Error::InvalidPresentationRequest)
    ));
    assert!(matches!(
        holder.begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            root,
            &w.expected_source,
            source,
            now
        ),
        Err(Error::InvalidPresentationRequest)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn root_authority_cannot_substitute_any_part_of_the_source_request() {
    let mut w = world();
    let mut holder = w.holder();
    w.passport(&mut holder);
    let context = w.context();
    let (root, source) = w.signed_context(&context);
    let original = w.expected_source.authenticate(&source, NOW).unwrap();
    assert!(original == *context.source_request());
    let mut other_challenge = original.challenge();
    other_challenge[0] ^= 1;
    // Each root context has a genuine root signature, but changes exactly one
    // source field. Even a trusted root cannot choose an unrelated source Y or
    // replace a nonce/profile inside an otherwise matching source-X request.
    for (community, epoch, gates, deadline, expiry, challenge) in [
        (
            CommunityId::new(b"community-b").unwrap(),
            7,
            vec![w.phone.clone()],
            NOW,
            Some(EXPIRY),
            original.challenge(),
        ),
        (
            w.source.clone(),
            8,
            vec![w.phone.clone()],
            NOW,
            Some(EXPIRY),
            original.challenge(),
        ),
        (
            w.source.clone(),
            7,
            vec![],
            NOW,
            Some(EXPIRY),
            original.challenge(),
        ),
        (
            w.source.clone(),
            7,
            vec![w.phone.clone()],
            NOW + 1,
            Some(EXPIRY),
            original.challenge(),
        ),
        (
            w.source.clone(),
            7,
            vec![w.phone.clone()],
            NOW,
            None,
            original.challenge(),
        ),
        (
            w.source.clone(),
            7,
            vec![w.phone.clone()],
            NOW,
            Some(EXPIRY + 1),
            original.challenge(),
        ),
        (
            w.source.clone(),
            7,
            vec![w.phone.clone()],
            NOW,
            Some(EXPIRY),
            other_challenge,
        ),
    ] {
        let mut substituted =
            PresentationRequest::with_challenge(community, epoch, gates, deadline, challenge)
                .unwrap();
        if let Some(expiry) = expiry {
            substituted = substituted.with_epoch_expiry(expiry).unwrap();
        }
        assert!(substituted != original);
        let changed =
            RootBoardIssuanceContext::new(&mut w.rng, substituted, w.descriptor.clone()).unwrap();
        let signed = sign(&mut w.signer, &changed.to_bytes(), changed.deadline());
        assert_source_refused(&mut w, &mut holder, &signed, &source, NOW);
    }
    // Refusals installed no pending opening; the original dual authorization
    // still authenticates and produces a proof for the original source scope.
    assert!(
        w.expected
            .authenticate_root_board_issuance(&root, &w.expected_source, &source, NOW)
            .unwrap()
            == context
    );
    let request = holder
        .begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &root,
            &w.expected_source,
            &source,
            NOW,
        )
        .unwrap();
    let verified =
        verify_root_board_issuance(&[w.global.public_key().clone()], &context, &request, NOW)
            .unwrap();
    assert_eq!(verified.source_pseudonym(), holder.pseudonym(&w.source));
    let blind =
        issue_blind_root_board(&mut w.rng, &w.root_key, &w.descriptor, verified, NOW).unwrap();
    holder.finish_root_board_issuance(&blind).unwrap();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn source_authentication_refusals_preserve_renewal_and_pending_state() {
    let mut w = world();
    let mut holder = w.holder();
    w.passport(&mut holder);
    let first = w.issue(&mut holder);
    holder.finish_root_board_issuance(&first).unwrap();
    let context = w.context();
    let (root, source) = w.signed_context(&context);
    let payload = context.source_request().to_bytes();
    // Missing/unsigned input, a root signature substituted for the source,
    // a foreign source key, and both expired and incorrectly bounded COSE.
    for rejected in [
        vec![],
        payload.clone(),
        sign(&mut w.signer, &payload, NOW),
        sign(&mut signer(9), &payload, NOW),
        sign(&mut w.source_signer, &payload, NOW - 1),
        sign(&mut w.source_signer, &payload, NOW + 1),
    ] {
        assert!(w.expected_source.authenticate(&rejected, NOW).is_err());
        assert_source_refused(&mut w, &mut holder, &root, &rejected, NOW);
    }
    assert_source_refused(&mut w, &mut holder, &root, &source, NOW + 1);
    let wrong_scope = AuthenticatedCommunity::from_authenticated_origin(
        CommunityId::new(b"community-b").unwrap(),
        w.source_signer.key_ring().clone(),
    );
    let wrong_ring = AuthenticatedCommunity::from_authenticated_origin(
        w.source.clone(),
        signer(9).key_ring().clone(),
    );
    for expected_source in [&wrong_scope, &wrong_ring, &w.expected] {
        assert!(matches!(
            w.expected
                .authenticate_root_board_issuance(&root, expected_source, &source, NOW),
            Err(Error::InvalidPresentationRequest)
        ));
        assert!(matches!(
            holder.begin_root_board_issuance(
                &mut w.rng,
                &w.expected,
                &root,
                expected_source,
                &source,
                NOW
            ),
            Err(Error::InvalidPresentationRequest)
        ));
    }
    let (request, signed_request) = w.request();
    let proof = holder
        .present_root_board(&mut w.rng, &w.expected, &signed_request, NOW)
        .unwrap();
    verify_root_board(&[w.global.public_key().clone()], &request, &proof, NOW).unwrap();
    // Honest renewal can still start. An intervening rejected begin must not
    // consume that pending opening or remove the already installed credential.
    let renewal = w.issue(&mut holder);
    assert!(matches!(
        holder.begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &root,
            &w.expected_source,
            &[],
            NOW
        ),
        Err(Error::IssuancePending)
    ));
    let proof = holder
        .present_root_board(&mut w.rng, &w.expected, &signed_request, NOW)
        .unwrap();
    verify_root_board(&[w.global.public_key().clone()], &request, &proof, NOW).unwrap();
    holder.finish_root_board_issuance(&renewal).unwrap();
    let proof = holder
        .present_root_board(&mut w.rng, &w.expected, &signed_request, NOW)
        .unwrap();
    verify_root_board(&[w.global.public_key().clone()], &request, &proof, NOW).unwrap();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn independent_expiry_root_issuance_and_joint_presentation() {
    let mut w = world();
    let mut holder = w.holder();
    // Different actual passport/gate expiries require the independent profile.
    let challenge = IssuanceChallenge::generate(&mut w.rng);
    let issuance = holder
        .begin_issuance(&mut w.rng, w.global.public_key(), &challenge)
        .unwrap();
    let attributes = PassportAttributes::new(EXPIRY, 7).with_gate(w.phone.clone(), EXPIRY - 100);
    let blind = w
        .global
        .issue_blind(&mut w.rng, &issuance, &challenge, &attributes)
        .unwrap();
    holder.finish_issuance(&blind).unwrap();
    let source =
        PresentationRequest::new(&mut w.rng, w.source.clone(), 7, [w.phone.clone()], NOW).unwrap();
    assert_eq!(source.epoch_expiry(), None);
    let context = RootBoardIssuanceContext::new(&mut w.rng, source, w.descriptor.clone()).unwrap();
    let (root, source) = w.signed_context(&context);
    let issuance = holder
        .begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &root,
            &w.expected_source,
            &source,
            NOW,
        )
        .unwrap();
    let verified =
        verify_root_board_issuance(&[w.global.public_key().clone()], &context, &issuance, NOW)
            .unwrap();
    assert_eq!(verified.source_pseudonym(), holder.pseudonym(&w.source));
    let blind =
        issue_blind_root_board(&mut w.rng, &w.root_key, &w.descriptor, verified, NOW).unwrap();
    holder.finish_root_board_issuance(&blind).unwrap();
    let global = PresentationRequest::new(
        &mut w.rng,
        w.root_community.clone(),
        7,
        [w.phone.clone()],
        NOW,
    )
    .unwrap();
    assert_eq!(global.epoch_expiry(), None);
    let request = RootBoardRequest::new(global, w.descriptor.clone()).unwrap();
    let signed = sign(&mut w.signer, &request.to_bytes(), request.deadline());
    let proof = holder
        .present_root_board(&mut w.rng, &w.expected, &signed, NOW)
        .unwrap();
    let nym = verify_root_board(&[w.global.public_key().clone()], &request, &proof, NOW).unwrap();
    assert_eq!(nym, holder.pseudonym(&w.root_community));
    assert_ne!(nym, holder.pseudonym(&w.source));

    // Seed the original all-codecs fuzz target with real PUBLIC root objects.
    // No credential opening, holder secret or retained credential is exported.
    #[cfg(not(target_arch = "wasm32"))]
    if let Ok(directory) = std::env::var("CPSD_FUZZ_CORPUS") {
        let dir = std::path::Path::new(&directory);
        std::fs::create_dir_all(dir).unwrap();
        for (i, bytes) in [
            w.descriptor.to_bytes(),
            context.to_bytes(),
            issuance.to_bytes(),
            blind.to_bytes(),
            request.to_bytes(),
            proof.to_bytes(),
        ]
        .into_iter()
        .enumerate()
        {
            std::fs::write(dir.join(format!("root-board-independent-{i}")), bytes).unwrap();
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn root_key_must_be_distinct_from_unselected_global_ring_entries() {
    let mut w = world();
    let mut holder = w.holder();
    w.passport(&mut holder);
    let context = w.context();
    let (root, source) = w.signed_context(&context);
    let issuance = holder
        .begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &root,
            &w.expected_source,
            &source,
            NOW,
        )
        .unwrap();
    let global = w.global.public_key().clone();
    let verified =
        verify_root_board_issuance(std::slice::from_ref(&global), &context, &issuance, NOW)
            .unwrap();
    let blind =
        issue_blind_root_board(&mut w.rng, &w.root_key, &w.descriptor, verified, NOW).unwrap();
    holder.finish_root_board_issuance(&blind).unwrap();
    let (request, signed_request) = w.request();
    let proof = holder
        .present_root_board(&mut w.rng, &w.expected, &signed_request, NOW)
        .unwrap();
    verify_root_board(std::slice::from_ref(&global), &request, &proof, NOW).unwrap();

    let same_id_different_key = IssuerKey::generate(
        &mut w.rng,
        w.root_key.public_key().key_id().clone(),
        vec![w.phone.clone()],
    )
    .unwrap();
    // A published key can carry a fresh label while retaining the exact BBS
    // key bytes. Root/global separation must compare the key material too.
    let original = w.root_key.public_key().to_bytes();
    let mut relabeled = original.clone();
    let label_length = u32::from_be_bytes(original[6..10].try_into().unwrap()) as usize;
    let alias_label = b"root-board-2";
    assert_eq!(label_length, alias_label.len());
    assert_eq!(
        &original[10..10 + label_length],
        w.root_key.public_key().key_id().as_str().as_bytes()
    );
    relabeled[10..10 + label_length].copy_from_slice(alias_label);
    assert_eq!(
        &relabeled[10 + label_length..],
        &original[10 + label_length..]
    );
    let same_key_different_id = IssuerPublicKey::from_bytes(&relabeled).unwrap();
    assert_ne!(
        same_key_different_id.key_id(),
        w.root_key.public_key().key_id()
    );
    // Both proofs genuinely select global, which is distinct from the root.
    // Adding an unused ring entry must still enforce the root/global boundary.
    for unused in [
        w.root_key.public_key(),
        same_id_different_key.public_key(),
        &same_key_different_id,
    ] {
        let ring = [global.clone(), unused.clone()];
        assert_eq!(
            verify_root_board_issuance(&ring, &context, &issuance, NOW).err(),
            Some(Error::InvalidRootBoard)
        );
        assert_eq!(
            verify_root_board(&ring, &request, &proof, NOW).err(),
            Some(Error::InvalidRootBoard)
        );
    }
    // An unrelated rotation key in the ring remains valid.
    let other = IssuerKey::generate(
        &mut w.rng,
        KeyId::new("global-next").unwrap(),
        vec![w.phone.clone()],
    )
    .unwrap();
    let ring = [global, other.public_key().clone()];
    verify_root_board_issuance(&ring, &context, &issuance, NOW).unwrap();
    verify_root_board(&ring, &request, &proof, NOW).unwrap();
}
