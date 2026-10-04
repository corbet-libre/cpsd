//! Non-transferable root admission, composed from the original Dock protocols.
//!
//! The authenticated common issuer/cohort comes from Beacon. Proof verification
//! does not establish an admin role: the service must hold the original source
//! role lease and atomically consume its nonce before releasing a signature.

use crate::{
    CommunityId, Error, GateId, IssuerPublicKey, PassportAttributes, PresentationRequest,
    Timestamp,
    attributes::check_timestamp,
    wire::{Kind, Reader, Writer},
};

mod issuance;
mod presentation;
pub(crate) mod state;
pub(crate) use issuance::request as begin_issuance;
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) use issuance::request_for_opening;
pub use issuance::{
    BlindRootBoardCredential, RootBoardIssuanceContext, RootBoardIssuanceRequest,
    VerifiedRootBoardIssuance, issue_blind_root_board, verify_root_board_issuance,
};
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) use presentation::build as build_presentation;
pub(crate) use presentation::present;
pub use presentation::{RootBoardPresentation, RootBoardRequest, verify_root_board};

/// Common fixed cohort duration; individual issuance times are never attributes.
pub const ROOT_BOARD_COHORT_SECONDS: u64 = 30 * 24 * 60 * 60;

fn gate() -> GateId {
    GateId::new("root-board").expect("fixed gate identifier")
}

/// Purpose-specific public descriptor obtained from authenticated common Beacon.
/// No per-member key or expiry is accepted. Construction does not authenticate
/// a Beacon: that remains the original Beacon/Policy owner's responsibility.
#[derive(Clone, PartialEq, Eq)]
pub struct RootBoardPublicKey {
    issuer: IssuerPublicKey,
    community: CommunityId,
    policy_epoch: u64,
    cohort_start: Timestamp,
    expires_at: Timestamp,
}

impl RootBoardPublicKey {
    /// Import the authenticated common descriptor. The catalogue must be exactly
    /// `[root-board]`. Cohorts are aligned to Unix epoch in fixed 30-day periods;
    /// `expires_at` is exclusive and cannot be selected independently.
    pub fn from_authenticated_beacon(
        issuer: IssuerPublicKey,
        community: CommunityId,
        policy_epoch: u64,
        cohort_start: Timestamp,
    ) -> Result<Self, Error> {
        if issuer.gates() != [gate()] || !cohort_start.is_multiple_of(ROOT_BOARD_COHORT_SECONDS) {
            return Err(Error::InvalidRootBoard);
        }
        let expires_at = cohort_start
            .checked_add(ROOT_BOARD_COHORT_SECONDS)
            .ok_or(Error::InvalidRootBoard)?;
        check_timestamp(expires_at)?;
        Ok(Self {
            issuer,
            community,
            policy_epoch,
            cohort_start,
            expires_at,
        })
    }

    /// Common published BBS+ issuer, distinct from global passport keys.
    pub fn issuer(&self) -> &IssuerPublicKey {
        &self.issuer
    }
    /// Root pseudonym scope.
    pub fn community(&self) -> &CommunityId {
        &self.community
    }
    /// Common policy epoch.
    pub fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }
    /// Common exclusive expiry.
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
    /// Beginning of the common 30-day cohort.
    pub fn cohort_start(&self) -> Timestamp {
        self.cohort_start
    }

    pub(crate) fn current(&self, now: Timestamp) -> Result<(), Error> {
        check_timestamp(now)?;
        if now < self.cohort_start || now >= self.expires_at {
            return Err(Error::InvalidRootBoard);
        }
        Ok(())
    }

    pub(crate) fn distinct_from(&self, global: &IssuerPublicKey) -> Result<(), Error> {
        if self.issuer.key_id() == global.key_id()
            || self.issuer.bbs_public_key() == global.bbs_public_key()
        {
            return Err(Error::InvalidRootBoard);
        }
        Ok(())
    }

    pub(crate) fn attributes(&self) -> PassportAttributes {
        // Original PassportAttributes has inclusive expiry; preserve that codec
        // and map this explicitly exclusive root expiry to its final valid second.
        PassportAttributes::new(self.expires_at - 1, self.policy_epoch)
            .with_gate(gate(), self.expires_at - 1)
    }

    pub(crate) fn request(
        &self,
        global: &PresentationRequest,
    ) -> Result<PresentationRequest, Error> {
        self.current(global.now())?;
        PresentationRequest::with_challenge(
            self.community.clone(),
            self.policy_epoch,
            [gate()],
            global.now(),
            global.challenge(),
        )?
        .with_epoch_expiry(self.expires_at - 1)
    }

    /// Canonical public descriptor. Decoding alone does not authenticate Beacon.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Kind::RootBoardPublicKey);
        w.bytes(&self.issuer.to_bytes());
        w.bytes(self.community.as_bytes());
        w.u64(self.policy_epoch);
        w.u64(self.cohort_start);
        w.finish_public()
    }

    /// Strictly decode the common descriptor; authenticate it before use.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::RootBoardPublicKey)?;
        let issuer = IssuerPublicKey::from_bytes(r.bytes()?)?;
        let community = CommunityId::new(r.bytes()?)?;
        let policy_epoch = r.u64()?;
        let cohort_start = r.u64()?;
        r.finish()?;
        Self::from_authenticated_beacon(issuer, community, policy_epoch, cohort_start)
    }
}

pub(crate) fn global_issuer<'a>(
    issuers: &'a [IssuerPublicKey],
    key_id: &crate::KeyId,
    root: &RootBoardPublicKey,
) -> Result<&'a IssuerPublicKey, Error> {
    let mut matching = issuers.iter().filter(|key| key.key_id() == key_id);
    let issuer = matching.next().ok_or(Error::UnknownKey)?;
    if matching.next().is_some() {
        return Err(Error::DuplicateKeyId);
    }
    root.distinct_from(issuer)?;
    Ok(issuer)
}
