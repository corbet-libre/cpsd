//! A holder engine whose public outputs never contain its scalar or passport.

use crate::rand::{CryptoRng, RngCore, SeedableRng};
use crate::{
    AuthenticatedCommunity, BlindPassport, BlindStamp, CommunityId, Error, HolderSecret,
    IssuanceChallenge, IssuanceRequest, IssuerPublicKey, IssuerTag, Passport, PassportAttributes,
    PendingIssuance, Presentation, Pseudonym, RootBoardIssuanceRequest, RootBoardPresentation,
    StampAction, StampDigest, StampIssuanceRequest, StampPresentation, StampPublicKey, StampScope,
    Timestamp,
    root_board::{self, BlindRootBoardCredential, state::RootBoardState},
    stamp::{self, StampState},
};
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroize;

mod sealing;
pub use sealing::SealedHolder;

/// Nonexporting deterministic holder and its current issuance state.
///
/// Wallet retains this engine and lends access through current authorization.
/// Keys only derives its purpose-separated seed. No secret, RNG, pending opening,
/// passport or stamp accessor exists; there is
/// no Clone, Debug or serialization implementation. Public issuance messages and
/// presentations still use the original upstream BBS+ implementation.
/// Confirmation stamps are requested, unblinded, retained and presented only
/// here; the stamp API never accepts or returns a holder secret.
///
/// ```compile_fail
/// let holder = cpsd::OpaqueHolder::from_seed(&mut [7; 32]);
/// let secret = holder.secret();
/// ```
/// ```compile_fail
/// let holder = cpsd::OpaqueHolder::from_seed(&mut [7; 32]);
/// let bytes = holder.to_bytes();
/// ```
/// ```compile_fail
/// let holder = cpsd::OpaqueHolder::from_seed(&mut [7; 32]);
/// let copy = holder.clone();
/// ```
/// ```compile_fail
/// let holder = cpsd::OpaqueHolder::from_seed(&mut [7; 32]);
/// let diagnostic = format!("{holder:?}");
/// ```
/// No stamp operation takes a raw secret, and no stamp state is exported:
/// ```compile_fail
/// let request = cpsd::request_stamp;
/// ```
/// ```compile_fail
/// fn stamp(pending: cpsd::PendingStamp) {}
/// ```
/// ```compile_fail
/// fn stamp(stamp: cpsd::Stamp) {}
/// ```
/// ```compile_fail
/// let holder = cpsd::OpaqueHolder::from_seed(&mut [7; 32]);
/// let stamps = holder.stamps();
/// ```
pub struct OpaqueHolder {
    secret: HolderSecret,
    pending: Option<PendingIssuance>,
    passport: Option<Passport>,
    // Private extension, retained and sealed only beside the original state.
    root_board: RootBoardState,
    // Confirmation stamps; encoded without the secret and sealed beside it.
    stamps: StampState,
    sealing: Option<std::sync::Arc<sealing::HolderSeal>>,
}

impl OpaqueHolder {
    /// Restore the stable holder identity from a dedicated 256-bit secret seed.
    ///
    /// Uses upstream ChaCha20 (zero stream/position) and the existing nonzero
    /// arkworks scalar sampler. This is a versioned identity recipe: changing
    /// the RNG or sampler would change identities. The input buffer is wiped.
    /// The seed must already be purpose-separated by the embedding key manager;
    /// this function neither accepts a passkey root nor performs a KDF.
    pub fn from_seed(seed: &mut [u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        seed.zeroize();
        Self {
            secret: HolderSecret::generate(&mut rng),
            pending: None,
            passport: None,
            root_board: RootBoardState::default(),
            stamps: StampState::default(),
            sealing: None,
        }
    }

    /// Derive the existing per-community public pseudonym.
    pub fn pseudonym(&self, community: &CommunityId) -> Pseudonym {
        self.secret.pseudonym(community)
    }

    /// Public continuity tag sent only to the global issuer.
    pub fn issuer_tag(&self) -> IssuerTag {
        self.secret.issuer_tag()
    }

    /// Start issuance or renewal, retaining the private opening internally.
    ///
    /// Use fresh cryptographic randomness, never the deterministic identity RNG.
    /// A pending attempt must finish or be explicitly cancelled first. A failed
    /// renewal leaves the previous verified passport usable.
    pub fn begin_issuance<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        issuer: &IssuerPublicKey,
        challenge: &IssuanceChallenge,
    ) -> Result<IssuanceRequest, Error> {
        if self.pending.is_some() {
            return Err(Error::IssuancePending);
        }
        let (request, pending) = crate::request_issue(rng, &self.secret, issuer, challenge)?;
        self.pending = Some(pending);
        Ok(request)
    }

    /// Consume the pending opening and install only a signature-verified answer.
    ///
    /// Even an invalid answer consumes the attempt. Start a new challenge after
    /// failure; the old verified passport remains unchanged.
    pub fn finish_issuance(&mut self, blind: &BlindPassport) -> Result<(), Error> {
        let pending = self.pending.take().ok_or(Error::NoPendingIssuance)?;
        let passport = pending.finish(blind)?;
        self.passport = Some(passport);
        Ok(())
    }

    /// Drop a pending opening without affecting the verified passport.
    pub fn cancel_issuance(&mut self) {
        self.pending = None;
    }

    /// Read only the signed public attributes of the current passport.
    pub fn attributes(&self) -> Option<&PassportAttributes> {
        self.passport.as_ref().map(Passport::attributes)
    }

    /// Prove the existing credential against an authenticated community request.
    pub fn present<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        expected: &AuthenticatedCommunity,
        signed_request: &[u8],
        now: Timestamp,
    ) -> Result<Presentation, Error> {
        self.passport
            .as_ref()
            .ok_or(Error::PassportUnavailable)?
            .present(rng, expected, signed_request, now)
    }

    /// Start the same-holder root-board issuance with the retained passport.
    ///
    /// `expected_root` is the ROOT community's authenticated origin mapping and
    /// `signed_context` the root service's csgn Credential over the exact
    /// context. `expected_source` independently pins the initiating SOURCE
    /// community; `signed_source_request` is its original signed presentation
    /// request and must exactly match the context. Both are authenticated before
    /// producing a proof or storing a pending opening.
    /// The commitment, source-pseudonym proof and secret equality are
    /// produced from the retained passport; no secret or opening is returned.
    /// A pending root attempt must finish or be cancelled first. A failed
    /// renewal leaves the previous verified root credential and the global
    /// passport usable.
    pub fn begin_root_board_issuance<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        expected_root: &AuthenticatedCommunity,
        signed_context: &[u8],
        expected_source: &AuthenticatedCommunity,
        signed_source_request: &[u8],
        now: Timestamp,
    ) -> Result<RootBoardIssuanceRequest, Error> {
        if self.root_board.pending.is_some() {
            return Err(Error::IssuancePending);
        }
        let passport = self.passport.as_ref().ok_or(Error::PassportUnavailable)?;
        let context = expected_root.authenticate_root_board_issuance(
            signed_context,
            expected_source,
            signed_source_request,
            now,
        )?;
        let (request, pending) = root_board::begin_issuance(rng, passport, &context)?;
        self.root_board.pending = Some(pending);
        Ok(request)
    }

    /// Consume the pending root opening and install only a signature-verified
    /// answer. Even an invalid answer consumes the attempt; the previous root
    /// credential and global passport remain unchanged.
    pub fn finish_root_board_issuance(
        &mut self,
        blind: &BlindRootBoardCredential,
    ) -> Result<(), Error> {
        self.root_board.finish(blind)
    }

    /// Drop a pending root opening without affecting any verified credential.
    pub fn cancel_root_board_issuance(&mut self) {
        self.root_board.pending = None;
    }

    /// Whether a verified root credential is retained (no attributes or bytes).
    pub fn has_root_board(&self) -> bool {
        self.root_board.credential.is_some()
    }

    /// Prove both retained credentials against one authenticated root request.
    /// The two proofs share the hidden holder secret; the result carries only
    /// the root-community pseudonym and no source community, role or tag.
    pub fn present_root_board<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        expected: &AuthenticatedCommunity,
        signed_request: &[u8],
        now: Timestamp,
    ) -> Result<RootBoardPresentation, Error> {
        let passport = self.passport.as_ref().ok_or(Error::PassportUnavailable)?;
        let credential = self
            .root_board
            .credential
            .as_ref()
            .ok_or(Error::PassportUnavailable)?;
        let request = expected.authenticate_root_board_request(signed_request, now)?;
        root_board::present(rng, passport, credential, &request)
    }

    /// Start one confirmation stamp for up to [`crate::STAMP_SLOTS`] distinct
    /// actions (typically one per community), keeping the opening internally.
    ///
    /// Each digest is computed here with this holder's own pseudonym in its
    /// scope; digests fill shuffled slots and the rest are random. `challenge`
    /// is the wallet's single-use stamp nonce and `now` starts the window the
    /// signed expiry is checked against. Confirm the request with one user
    /// verification over [`StampIssuanceRequest::confirmation_challenge`].
    /// A pending stamp request must finish or be cancelled first.
    pub fn begin_stamp<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        issuer: &StampPublicKey,
        challenge: &IssuanceChallenge,
        actions: &[(StampScope, StampAction)],
        now: Timestamp,
    ) -> Result<StampIssuanceRequest, Error> {
        if self.stamps.pending.is_some() {
            return Err(Error::IssuancePending);
        }
        let digests: Vec<StampDigest> = actions
            .iter()
            .map(|(scope, action)| {
                action.digest(scope.fingerprint(), &self.pseudonym(scope.community()))
            })
            .collect();
        let (request, pending) =
            stamp::request_stamp(rng, &self.secret, issuer, challenge, &digests, now)?;
        self.stamps.pending = Some(pending);
        Ok(request)
    }

    /// Consume the pending stamp request and retain only a verified stamp
    /// whose signed epoch is `expected_epoch` and whose signed expiry fits the
    /// issuance window ending at `now`.
    ///
    /// `expected_epoch` is the stamp epoch of the authenticated global
    /// publication (the signed global status the device verifies, identical for
    /// every member; the epoch verifiers pass to [`crate::verify_stamp`]). Never
    /// take it from the wallet's answer or reply: every presentation reveals the
    /// epoch, so a wallet that chose it per member would tag the member for a
    /// colluding community. Another signed epoch fails with [`Error::WrongEpoch`].
    ///
    /// Even an invalid answer consumes the attempt; retained stamps are kept.
    /// At most eight stamps are retained: a new one first drops expired ones,
    /// then the one that expires first.
    pub fn finish_stamp(
        &mut self,
        blind: &BlindStamp,
        expected_epoch: u64,
        now: Timestamp,
    ) -> Result<(), Error> {
        self.stamps.finish(&self.secret, blind, expected_epoch, now)
    }

    /// Drop a pending stamp request without affecting retained stamps.
    pub fn cancel_stamp(&mut self) {
        self.stamps.pending = None;
    }

    /// The stamp key of the pending stamp request, if any.
    pub fn pending_stamp_key(&self) -> Option<&StampPublicKey> {
        self.stamps
            .pending
            .as_ref()
            .map(stamp::PendingStamp::issuer)
    }

    /// The exact bytes of the pending stamp request when it carries every
    /// action of `actions` (with this holder's own pseudonyms, as
    /// [`begin_stamp`](Self::begin_stamp) computed them).
    ///
    /// A device interrupted after it sent the request sends these SAME bytes
    /// again: the wallet answers the same request with the same blind stamp,
    /// without a second confirmation, and [`finish_stamp`](Self::finish_stamp)
    /// completes the kept request against the stamp key it was addressed to.
    /// `None` when nothing is pending or the request was made for other actions.
    pub fn pending_stamp_request(&self, actions: &[(StampScope, StampAction)]) -> Option<Vec<u8>> {
        let digests: Vec<StampDigest> = actions
            .iter()
            .map(|(scope, action)| {
                action.digest(scope.fingerprint(), &self.pseudonym(scope.community()))
            })
            .collect();
        self.stamps
            .pending
            .as_ref()?
            .request_covering(&digests)
            .map(<[u8]>::to_vec)
    }

    /// Whether an unexpired retained stamp approves `action` in `scope`.
    pub fn stamp_covers(&self, scope: &StampScope, action: &StampAction, now: Timestamp) -> bool {
        self.stamps
            .covering(&self.secret, scope, action, now)
            .is_ok()
    }

    /// Present the retained stamp that approves `action` in `scope`: reveals
    /// the key ID, epoch, expiry and exactly that action's slot, and proves
    /// this holder's pseudonym in `scope`. Fails with
    /// [`Error::StampDigestMissing`] when no retained stamp carries the action
    /// and with [`Error::StampExpired`] when only expired ones do. The result
    /// verifies offline ([`crate::verify_stamp`]); presenting again is allowed
    /// (the community records each digest once).
    pub fn present_stamp<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        scope: &StampScope,
        action: &StampAction,
        now: Timestamp,
    ) -> Result<StampPresentation, Error> {
        crate::attributes::check_timestamp(now)?;
        self.stamps
            .covering(&self.secret, scope, action, now)?
            .present(rng, &self.secret, scope, action)
    }
}
