//! A holder engine whose public outputs never contain its scalar or passport.

use crate::rand::{CryptoRng, RngCore, SeedableRng};
use crate::{
    AuthenticatedCommunity, BlindPassport, CommunityId, Error, HolderSecret, IssuanceChallenge,
    IssuanceRequest, IssuerPublicKey, IssuerTag, Passport, PassportAttributes, PendingIssuance,
    Presentation, Pseudonym, Timestamp,
};
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroize;

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
}
