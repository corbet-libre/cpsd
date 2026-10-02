//! Same-holder root-board credential through the nonexporting holder: issuance,
//! sealed restart, renewal, joint presentation and every authentication refusal.

use cpsd::rand::{SeedableRng, rngs::StdRng};
use cpsd::*;

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
}

fn world() -> World {
    let mut rng = StdRng::seed_from_u64(311);
    let phone = GateId::new("phone").unwrap();
    let global = IssuerKey::generate(&mut rng, KeyId::new("global").unwrap(), vec![phone.clone()])
        .unwrap();
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
        source: CommunityId::new(b"community-a").unwrap(),
        descriptor,
        signer,
        expected,
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

    fn signed_context(&mut self, context: &RootBoardIssuanceContext) -> Vec<u8> {
        sign(&mut self.signer, &context.to_bytes(), context.deadline())
    }

    /// Run one complete honest issuance, returning the answer for inspection.
    fn issue(&mut self, holder: &mut OpaqueHolder) -> BlindRootBoardCredential {
        let context = self.context();
        let signed = self.signed_context(&context);
        let request = holder
            .begin_root_board_issuance(&mut self.rng, &self.expected, &signed, NOW)
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
        assert_ne!(verified.source_pseudonym(), holder.pseudonym(&self.root_community));
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
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn issuance_seal_restore_and_joint_presentation_use_one_hidden_secret() {
    let mut w = world();
    let mut holder = w.holder();
    let reopened = w.holder();
    // No passport, no root issuance and no root presentation.
    let context = w.context();
    let signed = w.signed_context(&context);
    assert!(matches!(
        holder.begin_root_board_issuance(&mut w.rng, &w.expected, &signed, NOW),
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
    let signed = w.signed_context(&context);
    let issuance = holder
        .begin_root_board_issuance(&mut w.rng, &w.expected, &signed, NOW)
        .unwrap();
    assert!(matches!(
        holder.begin_root_board_issuance(&mut w.rng, &w.expected, &signed, NOW),
        Err(Error::IssuancePending)
    ));
    let verified = verify_root_board_issuance(
        &[w.global.public_key().clone()],
        &context,
        &issuance,
        NOW,
    )
    .unwrap();
    let blind = issue_blind_root_board(&mut w.rng, &w.root_key, &w.descriptor, verified, NOW)
        .unwrap();
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
    let plain =
        PresentationRequest::for_epoch(&mut w.rng, w.source.clone(), 7, [w.phone.clone()], NOW, EXPIRY)
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
    for (seed, key, context) in [(9, 8, b"wallet-a"), (7, 9, b"wallet-a"), (7, 8, b"wallet-b")] {
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
    let signed = w.signed_context(&other_context);
    holder
        .begin_root_board_issuance(&mut w.rng, &w.expected, &signed, NOW)
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
    let signed = w.signed_context(&context);
    holder
        .begin_root_board_issuance(&mut w.rng, &w.expected, &signed, NOW)
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
    let good = w.signed_context(&context);
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
            holder.begin_root_board_issuance(&mut w.rng, expected, &good, NOW),
            Err(Error::InvalidPresentationRequest)
        ));
    }
    // Exclusive COSE expiry must equal the inclusive deadline plus one second.
    let skewed = sign(&mut w.signer, &context.to_bytes(), context.deadline() + 5);
    assert!(matches!(
        holder.begin_root_board_issuance(&mut w.rng, &w.expected, &skewed, NOW),
        Err(Error::InvalidPresentationRequest)
    ));
    // Past the deadline, unknown payloads and oversized input all refuse.
    assert!(matches!(
        holder.begin_root_board_issuance(&mut w.rng, &w.expected, &good, NOW + 1),
        Err(Error::InvalidPresentationRequest)
    ));
    let (request, signed_request) = w.request();
    let plain = sign(&mut w.signer, &request.global_request().to_bytes(), request.deadline());
    assert!(matches!(
        holder.begin_root_board_issuance(&mut w.rng, &w.expected, &plain, NOW),
        Err(Error::InvalidPresentationRequest)
    ));
    assert!(matches!(
        holder.begin_root_board_issuance(&mut w.rng, &w.expected, &vec![0; 256 * 1024 + 1], NOW),
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
