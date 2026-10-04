//! A holder engine whose public outputs never contain its scalar or passport.

use crate::rand::{CryptoRng, RngCore, SeedableRng};
use crate::{
    AuthenticatedCommunity, BlindPassport, CommunityId, Error, HolderSecret, IssuanceChallenge,
    IssuanceRequest, IssuerPublicKey, IssuerTag, Passport, PassportAttributes, PendingIssuance,
    Presentation, Pseudonym, RootBoardIssuanceRequest, RootBoardPresentation, Timestamp,
    root_board::{self, BlindRootBoardCredential, state::RootBoardState},
};
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroize;

mod sealing;
pub use sealing::SealedHolder;

/// Nonexporting deterministic holder and its current issuance state.
///
/// Wallet retains this engine and lends access through current authorization.
/// Keys only derives its purpose-separated seed. No secret, RNG, pending opening
/// or passport accessor exists; there is
/// no Clone, Debug or serialization implementation. Public issuance messages and
/// presentations still use the original upstream BBS+ implementation.
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
pub struct OpaqueHolder {
    secret: HolderSecret,
    pending: Option<PendingIssuance>,
    passport: Option<Passport>,
    // Private extension, retained and sealed only beside the original state.
    root_board: RootBoardState,
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
}
