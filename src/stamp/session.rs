//! Stateful wrappers: single-use issuance at the wallet and one use per
//! digest in each community.

use ark_std::rand::{CryptoRng, RngCore};

use super::{
    BlindStamp, StampAction, StampIssuanceRequest, StampIssuerKey, StampPresentation,
    StampPublicKey, StampScope, VerifiedStamp, verify_stamp,
};
use crate::{
    ChallengeRecord, ChallengeStore, CommunityFingerprint, Error, IssuanceChallenge, IssuerTag,
    Timestamp,
    attributes::check_timestamp,
    error::ensure,
    session::binding,
    storage::{StampIssuanceStore, VerifiedStampIssuance},
};

/// The wallet's authenticated context of one stamp issuance: the wallet
/// member, the member's wallet session and the passport issuer tag that the
/// passport issuer's tag store holds for that member. Never built from
/// device input.
///
/// The wallet obtains one fresh user verification of `member` whose WebAuthn
/// challenge is [`StampIssuanceRequest::confirmation_challenge`] before it
/// calls [`issue_stamp_once`]; this crate does not see WebAuthn. The wallet
/// also rate-limits stamps per member and period (rulebook setting).
#[derive(Clone)]
pub struct AuthenticatedStampIssuance {
    member: [u8; 32],
    session: [u8; 32],
    tag: IssuerTag,
}

impl AuthenticatedStampIssuance {
    /// Imports the wallet's authenticated member, session and passport tag.
    pub fn new(member: [u8; 32], session: [u8; 32], passport_tag: IssuerTag) -> Self {
        Self {
            member,
            session,
            tag: passport_tag,
        }
    }
}

impl core::fmt::Debug for AuthenticatedStampIssuance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AuthenticatedStampIssuance(<redacted>)")
    }
}

fn issuance_binding(
    issuer: &StampPublicKey,
    authenticated: &AuthenticatedStampIssuance,
) -> [u8; 32] {
    binding(
        b"cpsd/stamp/v1/issuance-slot",
        &[
            &issuer.to_bytes(),
            &authenticated.member,
            &authenticated.session,
            &authenticated.tag.to_bytes(),
        ],
    )
}

/// Reserves a single-use stamp issuance nonce in the wallet's challenge store,
/// bound to the stamp key, the member, the session and the passport tag.
pub async fn stamp_issuance_challenge<R: RngCore + CryptoRng, S: ChallengeStore>(
    rng: &mut R,
    store: &S,
    issuer: &StampPublicKey,
    authenticated: &AuthenticatedStampIssuance,
    deadline: Timestamp,
) -> Result<IssuanceChallenge, Error> {
    check_timestamp(deadline)?;
    let nonce = IssuanceChallenge::generate(rng);
    let record = ChallengeRecord {
        nonce: nonce.to_bytes(),
        binding: issuance_binding(issuer, authenticated),
        expires: deadline,
    };
    ensure(store.reserve(record).await?, Error::ChallengeConflict)?;
    Ok(nonce)
}

/// Withdraws an outstanding stamp issuance nonce so a retry can replace it.
/// Returns whether a live nonce for exactly this key, member, session and tag
/// was removed.
pub async fn revoke_stamp_issuance_challenge<S: ChallengeStore>(
    store: &S,
    issuer: &StampPublicKey,
    authenticated: &AuthenticatedStampIssuance,
    challenge: &IssuanceChallenge,
    now: Timestamp,
) -> Result<bool, Error> {
    store
        .consume(
            challenge.to_bytes(),
            issuance_binding(issuer, authenticated),
            now,
        )
        .await
}

/// Signs at most one stamp for a stored issuance nonce.
///
/// Requires the request's tag to equal the authenticated member's passport tag
/// ([`Error::IssuerTagMismatch`] otherwise), verifies the request's proof
/// (so the committed secret is the passport's secret), signs `epoch` and the
/// key's cohort expiry for `now`, and then consumes the nonce together with the
/// stamp tag registry ([`StampIssuanceStore`]) in one transaction before
/// releasing the answer. A refused request consumes nothing. On an uncertain
/// storage outcome, obtain a new nonce instead of assuming success.
#[allow(clippy::too_many_arguments)]
pub async fn issue_stamp_once<R: RngCore + CryptoRng, S: StampIssuanceStore>(
    rng: &mut R,
    store: &S,
    issuer: &StampIssuerKey,
    authenticated: &AuthenticatedStampIssuance,
    request: &StampIssuanceRequest,
    challenge: &IssuanceChallenge,
    epoch: u64,
    now: Timestamp,
) -> Result<BlindStamp, Error> {
    check_timestamp(now)?;
    let binding = issuance_binding(issuer.public_key(), authenticated);
    ensure(
        store.matches(challenge.to_bytes(), binding, now).await?,
        Error::InvalidChallenge,
    )?;
    ensure(
        request.issuer_tag() == authenticated.tag,
        Error::IssuerTagMismatch,
    )?;
    let blind = issuer.issue_blind(rng, request, challenge, epoch, now)?;
    let consumed = store
        .consume_stamp_issuance(VerifiedStampIssuance {
            nonce: challenge.to_bytes(),
            binding,
            now,
            member: authenticated.member,
            tag: authenticated.tag,
        })
        .await?;
    // A concurrent issuance consumed the nonce first: release nothing.
    ensure(consumed, Error::InvalidChallenge)?;
    Ok(blind)
}

/// One community's one-use record of stamped actions, over the community's
/// own [`ChallengeStore`]: the key is the action digest, the binding is the
/// community and action kind, the record lives until the stamp's expiry.
///
/// The same digest is the same action by the same member, so replicas that
/// record it converge; a second presentation of a recorded digest is refused
/// with [`Error::StampReplayed`].
pub struct StampLedger<S> {
    store: S,
    fingerprint: CommunityFingerprint,
    keys: Vec<StampPublicKey>,
}

impl<S: ChallengeStore> StampLedger<S> {
    /// A ledger for the store's community, its pinned fingerprint and the
    /// authenticated stamp key ring.
    pub fn new(
        store: S,
        fingerprint: CommunityFingerprint,
        keys: Vec<StampPublicKey>,
    ) -> Result<Self, Error> {
        let mut ids = std::collections::BTreeSet::new();
        ensure(
            keys.iter().all(|key| ids.insert(key.key_id().clone())),
            Error::DuplicateKeyId,
        )?;
        Ok(Self {
            store,
            fingerprint,
            keys,
        })
    }

    /// This ledger's community as a stamp scope.
    pub fn scope(&self) -> StampScope {
        StampScope::new(self.store.community().clone(), self.fingerprint)
    }

    /// Verifies a presentation ([`verify_stamp`]) and records its digest in
    /// one step. Apply the action only after this succeeded; if applying it
    /// fails definitively, [`release`](Self::release) the digest.
    pub async fn accept(
        &self,
        action: &StampAction,
        presentation: &StampPresentation,
        epoch: u64,
        now: Timestamp,
    ) -> Result<VerifiedStamp, Error> {
        let verified = verify_stamp(&self.keys, &self.scope(), epoch, action, presentation, now)?;
        self.record(&verified, now).await?;
        Ok(verified)
    }

    /// Records the digest of a stamp verified for this community (for example
    /// by a peer that verified offline). Insert-if-absent: a digest already
    /// recorded is refused with [`Error::StampReplayed`]; an expired stamp with
    /// [`Error::StampExpired`]; a stamp of another community with
    /// [`Error::InvalidStamp`].
    pub async fn record(&self, stamp: &VerifiedStamp, now: Timestamp) -> Result<(), Error> {
        check_timestamp(now)?;
        ensure(
            stamp.community == *self.store.community(),
            Error::InvalidStamp,
        )?;
        ensure(now < stamp.expires, Error::StampExpired)?;
        let record = ChallengeRecord {
            nonce: stamp.digest.to_bytes(),
            binding: one_use_binding(stamp),
            expires: stamp.expires,
        };
        ensure(self.store.reserve(record).await?, Error::StampReplayed)
    }

    /// Whether this exact stamped action is recorded and its stamp unexpired.
    pub async fn recorded(&self, stamp: &VerifiedStamp, now: Timestamp) -> Result<bool, Error> {
        self.store
            .matches(stamp.digest.to_bytes(), one_use_binding(stamp), now)
            .await
    }

    /// Removes the record of an action that was NOT applied, so the member can
    /// retry with the same stamp. Never call it for an applied action.
    pub async fn release(&self, stamp: &VerifiedStamp, now: Timestamp) -> Result<bool, Error> {
        self.store
            .consume(stamp.digest.to_bytes(), one_use_binding(stamp), now)
            .await
    }

    /// Deletes records whose stamps expired before `now`.
    pub async fn prune(&self, now: Timestamp) -> Result<u64, Error> {
        self.store.prune(now).await
    }
}

fn one_use_binding(stamp: &VerifiedStamp) -> [u8; 32] {
    binding(
        b"cpsd/stamp/v1/one-use",
        &[stamp.community.as_bytes(), stamp.kind.as_str().as_bytes()],
    )
}
