//! Caller-supplied authentication context; never derived from holder input.

use crate::{
    CommunityId, Error, PresentationRequest, RootBoardIssuanceContext, RootBoardRequest, Timestamp,
    attributes::check_timestamp,
};

/// How far ahead of the wallet's own clock an independent-expiry request's
/// deadline (`request.now()`) may lie, in seconds. Equal to the stamp clock
/// skew ([`crate::STAMP_CLOCK_SKEW_SECONDS`]).
///
/// In the independent-expiry profile the deadline is also the lower bound of
/// the hidden expiry ranges, and the holder refuses without answering when its
/// passport or a requested gate expires before it. A community that signs
/// deadlines far in the future could therefore binary-search a hidden expiry
/// from the holder's accept or refuse answers. With this bound the answer says
/// only that an expiry lies within the next five minutes, which passes
/// anyway. The bound is a constant of this crate, independent of the
/// community's key ring and its `max_validity`.
pub const MAX_REQUEST_AHEAD_SECONDS: u64 = 5 * 60;

/// Wallet trust anchor pinned to the initiating origin by authenticated discovery.
///
/// The caller must authenticate BOTH the community ID and its csgn key ring.
/// Never construct this from the presentation request or an untrusted redirect.
/// The ring's issuer is part of that authenticated mapping. Wallet code and its
/// delivery origin are trusted: malicious code can read the holder secret.
pub struct AuthenticatedCommunity {
    community: CommunityId,
    ring: csgn::KeyRing,
}

impl AuthenticatedCommunity {
    /// Import a community/ring association already authenticated by the wallet.
    pub fn from_authenticated_origin(community: CommunityId, ring: csgn::KeyRing) -> Self {
        Self { community, ring }
    }

    /// Verify a csgn COSE Credential whose payload is exactly a versioned cpsd
    /// PresentationRequest. The cpsd magic/version/kind domain-separates this
    /// authorization from other credentials; other csgn kinds are rejected.
    /// Sign with an exclusive COSE expiry equal to `request.now() + 1`, so the
    /// inclusive challenge deadline remains usable. No dates are persisted here.
    /// An independent-expiry request whose deadline lies more than
    /// [`MAX_REQUEST_AHEAD_SECONDS`] after `now` is refused.
    pub fn authenticate(&self, cose: &[u8], now: Timestamp) -> Result<PresentationRequest, Error> {
        let (payload, valid_until) = self.verified_payload(cose, now)?;
        let request = PresentationRequest::from_bytes(&payload)
            .map_err(|_| Error::InvalidPresentationRequest)?;
        if request.community() != &self.community
            || now > request.now()
            || valid_until != request.now() + 1
        {
            return Err(Error::InvalidPresentationRequest);
        }
        check_deadline_ahead(&request, now)?;
        Ok(request)
    }

    /// Verify a csgn COSE Credential whose payload is exactly a root-board
    /// issuance context, signed by the ROOT community's key ring this value
    /// was imported for. The same exclusive-expiry rule applies: the COSE expiry
    /// is the context deadline plus one second. Independently authenticate the
    /// original source request against its caller-pinned source mapping, then
    /// require the entire request to equal the one inside the root context.
    /// Root authority cannot select a different source pseudonym scope.
    pub fn authenticate_root_board_issuance(
        &self,
        cose: &[u8],
        expected_source: &AuthenticatedCommunity,
        signed_source_request: &[u8],
        now: Timestamp,
    ) -> Result<RootBoardIssuanceContext, Error> {
        let (payload, valid_until) = self.verified_payload(cose, now)?;
        let context = RootBoardIssuanceContext::from_bytes(&payload)
            .map_err(|_| Error::InvalidPresentationRequest)?;
        if context.root().community() != &self.community
            || now > context.deadline()
            || valid_until != context.deadline() + 1
        {
            return Err(Error::InvalidPresentationRequest);
        }
        let source = expected_source.authenticate_root_source(signed_source_request, now)?;
        if context.source_request() != &source {
            return Err(Error::InvalidPresentationRequest);
        }
        Ok(context)
    }

    // Accept only the original canonical v3 request inside this authenticated
    // complete root context, then compare the exact original typed request.
    // The ordinary request decoder also refuses legacy v2 framing.
    fn authenticate_root_source(
        &self,
        cose: &[u8],
        now: Timestamp,
    ) -> Result<PresentationRequest, Error> {
        let (payload, valid_until) = self.verified_payload(cose, now)?;
        let request = if payload.starts_with(b"cpsd\x03\x08") {
            crate::root_board::request_from_bytes(&payload)
        } else {
            PresentationRequest::from_bytes(&payload)
        }
        .map_err(|_| Error::InvalidPresentationRequest)?;
        if request.community() != &self.community
            || now > request.now()
            || valid_until != request.now() + 1
        {
            return Err(Error::InvalidPresentationRequest);
        }
        check_deadline_ahead(&request, now)?;
        Ok(request)
    }

    /// Verify a csgn COSE Credential whose payload is exactly a root-board
    /// presentation request, signed by the root community's key ring. This is
    /// the only way a device accepts the second (root credential) requirement.
    pub fn authenticate_root_board_request(
        &self,
        cose: &[u8],
        now: Timestamp,
    ) -> Result<RootBoardRequest, Error> {
        let (payload, valid_until) = self.verified_payload(cose, now)?;
        let request = RootBoardRequest::from_bytes(&payload)
            .map_err(|_| Error::InvalidPresentationRequest)?;
        if request.root().community() != &self.community
            || now > request.deadline()
            || valid_until != request.deadline() + 1
        {
            return Err(Error::InvalidPresentationRequest);
        }
        check_deadline_ahead(request.global_request(), now)?;
        Ok(request)
    }

    fn verified_payload(&self, cose: &[u8], now: Timestamp) -> Result<(Vec<u8>, Timestamp), Error> {
        check_timestamp(now)?;
        if cose.len() > crate::wire::MAX_ENCODED_LEN {
            return Err(Error::InvalidPresentationRequest);
        }
        let verified = self
            .ring
            .verify(cose, csgn::Kind::Credential, now)
            .map_err(|_| Error::InvalidPresentationRequest)?;
        Ok((verified.payload().to_vec(), verified.valid_until()))
    }
}

/// Refuses an independent-expiry request whose deadline lies more than
/// [`MAX_REQUEST_AHEAD_SECONDS`] after the wallet's `now`. The shared-epoch
/// profile reveals the expiry exactly, so a deadline there teaches nothing.
fn check_deadline_ahead(request: &PresentationRequest, now: Timestamp) -> Result<(), Error> {
    if request.epoch_expiry().is_none()
        && request.now() > now.saturating_add(MAX_REQUEST_AHEAD_SECONDS)
    {
        return Err(Error::InvalidPresentationRequest);
    }
    Ok(())
}

/// Opaque global person and session IDs obtained from successful authentication.
/// No provider identifier, raw gate data, or community pseudonym belongs here.
/// The service must use a stable person ID across sessions and key rotation.
#[derive(Clone)]
pub struct AuthenticatedIssuance {
    pub(crate) person: [u8; 32],
    pub(crate) session: [u8; 32],
}

impl AuthenticatedIssuance {
    /// Import the authenticated service context, never IDs supplied by a holder.
    pub fn new(person: [u8; 32], session: [u8; 32]) -> Self {
        Self { person, session }
    }
}

impl core::fmt::Debug for AuthenticatedIssuance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AuthenticatedIssuance(<redacted>)")
    }
}
