//! Pseudonyms: blind credential issuance and unlinkable per-community pseudonyms.
//!
//! `cpsd` is a thin facade over docknetwork's
//! [`crypto`](https://github.com/docknetwork/crypto) crates (`bbs_plus`,
//! `schnorr_pok`, `bulletproofs_plus_plus`) for the `cvld` passport:
//!
//! - **Blind issuance.** The holder commits to a random secret
//!   ([`HolderSecret`]) and proves knowledge of it ([`request_issue`]); the
//!   issuer ([`IssuerKey::issue_blind`]) signs a BBS+ credential over the
//!   committed secret plus attributes it knows (passed global gates with
//!   expiries, valid-until, policy epoch, key ID) without learning the secret;
//!   the holder unblinds it ([`PendingIssuance::finish`]) into a [`Passport`].
//! - **Per-community pseudonyms.** `pseudonym = secret * H(community)` in G1
//!   ([`Pseudonym`]): deterministic per holder and community, unlinkable across
//!   communities (DDH in G1).
//! - **Presentation.** [`present`] proves in zero knowledge: a valid passport
//!   signed by key K, the requested gates present and unexpired, the requested
//!   policy epoch, and that the pseudonym derives from the signed secret; bound
//!   to the verifier's [`PresentationRequest`] (community, time, challenge).
//!   [`verify`] checks it and returns the pseudonym.
//! - **Revocation (v1).** Validity period and policy epoch inside the
//!   passport; see the crate README for the accumulator extension point (v2).
//!
//! Randomness is always supplied by the caller (`RngCore + CryptoRng`, the
//! `rand` 0.8 traits re-exported as [`rand`]); in a browser seed a CSPRNG from
//! `crypto.getRandomValues`.
//!
//! See `docs/CONTRACT.md` for the contract and the README for the design.
#![forbid(unsafe_code)]

mod attributes;
mod authentication;
mod error;
mod holder;
mod ids;
mod issuer;
mod opaque_holder;
mod params;
mod presentation;
mod proof;
mod proof_wire;
mod root_board;
mod session;
pub mod storage;
mod wire;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod test_support;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

pub use ark_std::rand;

pub use attributes::{MAX_GATES, PassportAttributes, TIME_LIMIT, Timestamp};
pub use authentication::{AuthenticatedCommunity, AuthenticatedIssuance};
pub use error::Error;
pub use holder::{HolderSecret, Passport, PendingIssuance, request_issue};
pub use ids::{CommunityId, GateId, KeyId, MAX_COMMUNITY_ID_LEN, MAX_ID_LEN};
pub use issuer::{
    BlindPassport, IssuanceChallenge, IssuanceRequest, IssuerKey, IssuerPublicKey, IssuerTag,
};
pub use opaque_holder::{OpaqueHolder, SealedHolder};
pub use presentation::{Presentation, PresentationRequest, Pseudonym, present, verify};
pub use root_board::{
    BlindRootBoardCredential, ROOT_BOARD_COHORT_SECONDS, RootBoardIssuanceContext,
    RootBoardIssuanceRequest, RootBoardPresentation, RootBoardPublicKey, RootBoardRequest,
    VerifiedRootBoardIssuance, issue_blind_root_board, verify_root_board,
    verify_root_board_issuance,
};

pub use session::{
    ConsumedRootBoardIssuance, Verifier, consume_root_board_issuance, issuance_challenge,
    issue_blind_once, register_root_board_issuance, verify_stored_root_board_issuance,
};
pub use storage::{ChallengeRecord, ChallengeStore, IssuanceStore, MemoryStore, VerifiedIssuance};
