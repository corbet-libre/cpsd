//! Stateful wrappers: single-use issuance at the wallet and one use per
//! digest in each community.

use ark_std::rand::{CryptoRng, RngCore};

use super::{
    BlindStamp, STAMP_PRUNE_MARGIN_SECONDS, StampAction, StampIssuanceRequest, StampIssuerKey,
    StampParams, StampPresentation, StampPublicKey, StampScope, VerifiedStamp, verify_stamp,
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
/// Before [`issue_stamp_once`], the wallet verifies one fresh user
/// verification of `member` and records the WebAuthn challenge it covered with
/// [`with_user_verification`](Self::with_user_verification); issuance refuses
/// unless that challenge is the request's
/// [`StampIssuanceRequest::confirmation_challenge`]. This crate does not see
/// WebAuthn. The wallet also rate-limits stamps per member and period
/// (rulebook setting).
#[derive(Clone)]
pub struct AuthenticatedStampIssuance {
    member: [u8; 32],
    session: [u8; 32],
    tag: IssuerTag,
    confirmation: Option<[u8; 32]>,
}

impl AuthenticatedStampIssuance {
    /// Imports the wallet's authenticated member, session and passport tag.
    /// Enough to reserve a nonce; issuance also needs the user verification.
    pub fn new(member: [u8; 32], session: [u8; 32], passport_tag: IssuerTag) -> Self {
        Self {
            member,
            session,
            tag: passport_tag,
            confirmation: None,
        }
    }

    /// Records the challenge of the WebAuthn assertion with user verification
    /// that the wallet verified for this member. Pass only the challenge
    /// taken from a verified assertion, never a value the device supplied.
    pub fn with_user_verification(mut self, verified_challenge: [u8; 32]) -> Self {
        self.confirmation = Some(verified_challenge);
        self
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
/// ([`Error::IssuerTagMismatch`] otherwise) and the verified user verification
/// to cover exactly this request and nonce ([`Error::UnconfirmedStampRequest`]
/// otherwise), verifies the request's proof
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
    ensure(
        authenticated.confirmation == Some(request.confirmation_challenge(challenge)),
        Error::UnconfirmedStampRequest,
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
/// community and action kind, the record lives until the stamp's expiry plus
/// [`STAMP_PRUNE_MARGIN_SECONDS`].
///
/// The same digest is the same action by the same member, so replicas that
/// record it converge; a second presentation of a recorded digest is refused
/// with [`Error::StampReplayed`].
pub struct StampLedger<S> {
    store: S,
    fingerprint: CommunityFingerprint,
    keys: Vec<StampPublicKey>,
    params: StampParams,
}

impl<S: ChallengeStore> StampLedger<S> {
    /// A ledger for the store's community, its pinned fingerprint, the
    /// authenticated stamp key ring and the rulebook's stamp settings. A key
    /// whose cohort differs from `params` is refused ([`Error::WrongExpiryCohort`]).
    pub fn new(
        store: S,
        fingerprint: CommunityFingerprint,
        keys: Vec<StampPublicKey>,
        params: StampParams,
    ) -> Result<Self, Error> {
        let mut ids = std::collections::BTreeSet::new();
        ensure(
            keys.iter().all(|key| ids.insert(key.key_id().clone())),
            Error::DuplicateKeyId,
        )?;
        ensure(
            keys.iter().all(|key| key.params() == params),
            Error::WrongExpiryCohort,
        )?;
        Ok(Self {
            store,
            fingerprint,
            keys,
            params,
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
        let verified = verify_stamp(
            &self.keys,
            &self.params,
            &self.scope(),
            epoch,
            action,
            presentation,
            now,
        )?;
        self.record(&verified, now).await?;
        Ok(verified)
    }

    /// Records the digest of a stamp verified for this community (for example
    /// by a peer that verified offline). Insert-if-absent: a digest already
    /// recorded is refused with [`Error::StampReplayed`]; an expired stamp with
    /// [`Error::StampExpired`]; a stamp of another community with
    /// [`Error::InvalidStamp`].
    ///
    /// The record is stored with the deadline `X + `[`STAMP_PRUNE_MARGIN_SECONDS`],
    /// not `X`: the store's own `prune` (also the verifier's `Verifier::prune`
    /// on the shared community store) deletes everything past its deadline, so
    /// the margin lives in the record itself and no pruning path can remove it
    /// early. Every live check keeps comparing with `X`.
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
            expires: retention_deadline(stamp.expires)?,
        };
        ensure(self.store.reserve(record).await?, Error::StampReplayed)
    }

    /// Whether this exact stamped action is recorded and its stamp unexpired.
    /// Past the stamp's expiry `X` the answer is false even while the record
    /// still exists for the prune margin.
    pub async fn recorded(&self, stamp: &VerifiedStamp, now: Timestamp) -> Result<bool, Error> {
        if now > stamp.expires {
            return Ok(false);
        }
        self.store
            .matches(stamp.digest.to_bytes(), one_use_binding(stamp), now)
            .await
    }

    /// Removes the record of an action that was NOT applied, so the member can
    /// retry with the same stamp. Never call it for an applied action. Nothing
    /// is removed once the stamp's expiry `X` has passed.
    pub async fn release(&self, stamp: &VerifiedStamp, now: Timestamp) -> Result<bool, Error> {
        if now > stamp.expires {
            return Ok(false);
        }
        self.store
            .consume(stamp.digest.to_bytes(), one_use_binding(stamp), now)
            .await
    }

    /// Deletes the records whose stamps expired more than
    /// [`STAMP_PRUNE_MARGIN_SECONDS`] before `now`. The margin keeps a record
    /// alive while a node with a clock up to that far behind (or a clock that
    /// stepped back) could still accept its stamp; deleting at `X` itself would
    /// let such a node apply the same action again. The margin is part of the
    /// stored deadline ([`record`](Self::record)), so this is the store's plain
    /// `prune(now)` and any other pruning of the same store, such as
    /// `Verifier::prune`, keeps the same margin.
    pub async fn prune(&self, now: Timestamp) -> Result<u64, Error> {
        check_timestamp(now)?;
        self.store.prune(now).await
    }
}

/// The stored deadline of a one-use record: the stamp's expiry plus the prune
/// margin. Refuses a deadline beyond the timestamp range.
fn retention_deadline(expires: Timestamp) -> Result<Timestamp, Error> {
    let deadline = expires
        .checked_add(STAMP_PRUNE_MARGIN_SECONDS)
        .ok_or(Error::InvalidTimestamp)?;
    check_timestamp(deadline)?;
    Ok(deadline)
}

fn one_use_binding(stamp: &VerifiedStamp) -> [u8; 32] {
    binding(
        b"cpsd/stamp/v1/one-use",
        &[stamp.community.as_bytes(), stamp.kind.as_str().as_bytes()],
    )
}
