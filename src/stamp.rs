//! Confirmation stamps: one blind, short-lived credential that carries up to
//! [`STAMP_SLOTS`] hidden action digests, presented one digest per community.
//!
//! A device obtains ONE stamp after one user verification at the wallet and
//! uses it to approve one action in each of up to sixteen communities:
//!
//! - **Own issuer key.** Stamps are signed by a [`StampIssuerKey`], never by a
//!   passport key; generators, wire kinds and envelope version are separate.
//!   The key fixes the expiry cohort length ([`StampPublicKey::cohort_seconds`]).
//! - **Blind issuance.** [`request_stamp`] commits the holder secret and all
//!   sixteen digest slots (Pedersen, multi-base Schnorr proof) and carries the
//!   passport's [`IssuerTag`](crate::IssuerTag) with a proof that the tag and
//!   the commitment hide the same secret. Unused slots are random scalars and
//!   the slot order is shuffled, so the wallet learns neither digests nor how
//!   many communities are involved. [`issue_stamp_once`] signs the commitment
//!   with the key ID, the stamp epoch and the expiry cohort.
//! - **Presentation.** [`Stamp::present`] reveals the key ID, epoch, expiry
//!   cohort and exactly one digest slot (index and value) and proves the
//!   member's community pseudonym (the passport's `secret * H(community)`).
//!   The proof's challenge is the action digest itself, so [`verify_stamp`] is
//!   pure and offline over the stamp key ring.
//! - **One use.** [`StampLedger`] records each accepted digest in the
//!   community's [`ChallengeStore`](crate::ChallengeStore) until the cohort ends.
//!
//! The written security argument is `docs/STAMP-SECURITY.md`.

mod digest;
mod issuance;
mod key;
mod presentation;
mod session;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

pub use digest::{
    ActionKind, CommunityFingerprint, MAX_ACTION_KIND_LEN, PayloadDigest, StampAction, StampDigest,
    StampSalt, StampScope,
};
pub use issuance::{BlindStamp, PendingStamp, Stamp, StampIssuanceRequest, request_stamp};
pub use key::{MAX_STAMP_COHORT_SECONDS, MIN_STAMP_COHORT_SECONDS, StampIssuerKey, StampPublicKey};
pub use presentation::{StampPresentation, VerifiedStamp, verify_stamp};
pub use session::{
    AuthenticatedStampIssuance, StampLedger, issue_stamp_once, revoke_stamp_issuance_challenge,
    stamp_issuance_challenge,
};

/// Number of digest slots in every stamp, used or not.
pub const STAMP_SLOTS: usize = crate::params::STAMP_SLOTS;
