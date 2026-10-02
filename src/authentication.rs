//! Caller-supplied authentication context; never derived from holder input.

use crate::{
    CommunityId, Error, PresentationRequest, RootBoardIssuanceContext, RootBoardRequest, Timestamp,
    attributes::check_timestamp,
};

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
        Ok(request)
    }

    /// Verify a csgn COSE Credential whose payload is exactly a root-board
    /// issuance context, signed by the ROOT community's key ring this value
    /// was imported for. The same exclusive-expiry rule applies: the COSE expiry
    /// is the context deadline plus one second. The source community inside the
    /// context is only a request scope; authority comes from this root ring.
    pub fn authenticate_root_board_issuance(
        &self,
        cose: &[u8],
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
        Ok(context)
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
