//! Stateful replay protection around the pure cryptographic operations.

use crate::{attributes::check_timestamp, params::Label, *};
use blake2::{Blake2s256, Digest};
use rand::{CryptoRng, RngCore};

fn binding(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut label = Label::new(domain);
    for field in fields {
        label.bytes(field);
    }
    Blake2s256::digest(label.finish()).into()
}

/// Verifier with one community's challenge store and an authenticated key ring.
/// Policy/time remain caller inputs so no login dates or clock reads are needed.
pub struct Verifier<S> {
    store: S,
    keys: Vec<IssuerPublicKey>,
}

impl<S: ChallengeStore> Verifier<S> {
    /// Construct from a service-selected scope and trusted shared issuer keys.
    pub fn new(store: S, keys: Vec<IssuerPublicKey>) -> Result<Self, Error> {
        let mut ids = std::collections::BTreeSet::new();
        if keys.iter().any(|key| !ids.insert(key.key_id().clone())) {
            return Err(Error::DuplicateKeyId);
        }
        Ok(Self { store, keys })
    }

    /// Reserve an unpredictable, single-use challenge.
    ///
    /// Prove validity through `deadline`, not merely through challenge creation.
    /// This closes the time-of-check gap while the holder is generating its proof.
    /// The service chooses a short deadline and rate-limits this operation.
    pub async fn request<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        epoch: u64,
        gates: impl IntoIterator<Item = GateId>,
        deadline: Timestamp,
    ) -> Result<PresentationRequest, Error> {
        let request =
            PresentationRequest::new(rng, self.store.community().clone(), epoch, gates, deadline)?;
        self.register(request).await
    }

    /// Reserve a request for the recommended shared-epoch profile.
    /// Both the passport and requested gates must be signed with `epoch_expiry`.
    /// The service selects this value from authenticated epoch policy, shared
    /// by all holders; it must be no earlier than the challenge deadline.
    pub async fn request_for_epoch<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        epoch: u64,
        gates: impl IntoIterator<Item = GateId>,
        deadline: Timestamp,
        epoch_expiry: Timestamp,
    ) -> Result<PresentationRequest, Error> {
        let request = PresentationRequest::for_epoch(
            rng,
            self.store.community().clone(),
            epoch,
            gates,
            deadline,
            epoch_expiry,
        )?;
        self.register(request).await
    }

    async fn register(&self, request: PresentationRequest) -> Result<PresentationRequest, Error> {
        let record = ChallengeRecord {
            nonce: request.challenge(),
            binding: presentation_binding(&request),
            expires: request.now(),
        };
        if !self.store.reserve(record).await? {
            return Err(Error::ChallengeConflict);
        }
        Ok(request)
    }

    /// Reserve the complete service-created joint request in the same bounded
    /// replay store. The descriptor is supplied by authenticated root policy.
    /// A passport-only request cannot occupy or consume this purpose's slot.
    pub async fn register_root_board_request(
        &self,
        request: RootBoardRequest,
    ) -> Result<RootBoardRequest, Error> {
        if request.global_request().community() != self.store.community() {
            return Err(Error::InvalidChallenge);
        }
        let record = ChallengeRecord {
            nonce: request.global_request().challenge(),
            binding: root_board_binding(&request),
            expires: request.deadline(),
        };
        if !self.store.reserve(record).await? {
            return Err(Error::ChallengeConflict);
        }
        Ok(request)
    }

    /// Verify both credentials and consume their exact joint challenge once.
    /// Current descriptor/policy selection stays with the service; this method
    /// checks the configured community, current global epoch and original keys.
    /// Invalid proofs leave the challenge available for its legitimate holder.
    pub async fn verify_root_board(
        &self,
        request: &RootBoardRequest,
        proof: &RootBoardPresentation,
        epoch: u64,
        now: Timestamp,
    ) -> Result<Pseudonym, Error> {
        check_timestamp(now)?;
        let global = request.global_request();
        if global.community() != self.store.community() || now > request.deadline() {
            return Err(Error::InvalidChallenge);
        }
        if global.policy_epoch() != epoch {
            return Err(Error::WrongEpoch);
        }
        let binding = root_board_binding(request);
        if !self.store.matches(global.challenge(), binding, now).await? {
            return Err(Error::InvalidChallenge);
        }
        let pseudonym = crate::verify_root_board(&self.keys, request, proof, now)?;
        if !self.store.consume(global.challenge(), binding, now).await? {
            return Err(Error::InvalidChallenge);
        }
        Ok(pseudonym)
    }

    /// Verify, then atomically consume the challenge before returning a pseudonym.
    /// Invalid proofs do not consume a challenge. Concurrent valid submissions
    /// yield at most one success. `epoch`/`now` are authoritative service values.
    pub async fn verify<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        request: &PresentationRequest,
        proof: &Presentation,
        epoch: u64,
        now: Timestamp,
    ) -> Result<Pseudonym, Error> {
        check_timestamp(now)?;
        if request.community() != self.store.community() {
            return Err(Error::InvalidChallenge);
        }
        if request.policy_epoch() != epoch {
            return Err(Error::WrongEpoch);
        }
        if now > request.now() {
            return Err(Error::InvalidChallenge);
        }
        if !self
            .store
            .matches(request.challenge(), presentation_binding(request), now)
            .await?
        {
            return Err(Error::InvalidChallenge);
        }
        let pseudonym = verify(rng, &self.keys, request, proof)?;
        if !self
            .store
            .consume(request.challenge(), presentation_binding(request), now)
            .await?
        {
            return Err(Error::InvalidChallenge);
        }
        Ok(pseudonym)
    }

    /// Remove expired outstanding challenges; successful ones were already deleted.
    pub async fn prune(&self, now: Timestamp) -> Result<u64, Error> {
        self.store.prune(now).await
    }
}

fn presentation_binding(request: &PresentationRequest) -> [u8; 32] {
    binding(b"cpsd/v1/presentation-slot", &[&request.to_bytes()])
}

fn root_board_binding(request: &RootBoardRequest) -> [u8; 32] {
    binding(b"cpsd/v3/root-board-slot", &[&request.to_bytes()])
}

fn root_board_issuance_binding(context: &RootBoardIssuanceContext) -> [u8; 32] {
    binding(b"cpsd/v3/root-board-issuance-slot", &[&context.to_bytes()])
}

fn root_board_issuance_scope<S: ChallengeStore>(
    store: &S,
    context: &RootBoardIssuanceContext,
) -> Result<(), Error> {
    if store.community() != context.root().community() {
        return Err(Error::InvalidChallenge);
    }
    Ok(())
}

/// Reserve a service-created root issuance context in the root scope's original
/// bounded challenge store. Only a purpose-separated digest, nonce and deadline
/// are stored; no source pseudonym, proof or role history is retained.
///
/// The service authenticates the source request and current common descriptor,
/// chooses a short deadline, rate-limits and prunes. This does not authorize an
/// admin role or sign the context; those remain the original service's duties.
/// Every attempt must use a fresh [`RootBoardIssuanceContext::new`] nonce. Never
/// re-register a retired context: the store intentionally keeps no tombstones.
pub async fn register_root_board_issuance<S: ChallengeStore>(
    store: &S,
    context: &RootBoardIssuanceContext,
) -> Result<(), Error> {
    root_board_issuance_scope(store, context)?;
    if !store
        .reserve(ChallengeRecord {
            nonce: context.nonce(),
            binding: root_board_issuance_binding(context),
            expires: context.deadline(),
        })
        .await?
    {
        return Err(Error::ChallengeConflict);
    }
    Ok(())
}

/// Verify genuine holder binding only after matching the retained complete
/// context. The full authenticated global ring is required. Failed proofs leave
/// the nonce usable. Success is neither nonce consumption nor role authority.
///
/// The service must compare the result with its original live source role lease
/// and retain that lease through consumption and signature release.
pub async fn verify_stored_root_board_issuance<S: ChallengeStore>(
    store: &S,
    issuers: &[IssuerPublicKey],
    context: &RootBoardIssuanceContext,
    request: &RootBoardIssuanceRequest,
    now: Timestamp,
) -> Result<VerifiedRootBoardIssuance, Error> {
    root_board_issuance_scope(store, context)?;
    context.current(now)?;
    if !store
        .matches(context.nonce(), root_board_issuance_binding(context), now)
        .await?
    {
        return Err(Error::InvalidChallenge);
    }
    crate::verify_root_board_issuance(issuers, context, request, now)
}

/// One successful nonce consumption, not admin or session authority. The value
/// has no public constructor, clone or serializer; dropping it burns the nonce.
/// Its only signing path consumes it and delegates the original cryptography.
pub struct ConsumedRootBoardIssuance {
    verified: VerifiedRootBoardIssuance,
    consumed_at: Timestamp,
}

impl ConsumedRootBoardIssuance {
    /// Release at most one blind signature for the consumed context. Before
    /// calling, the service must still hold the matching live source role lease,
    /// recheck its session and current policy, and read its real clock again
    /// after the nonce-store await. No role assertion is accepted by this port.
    ///
    /// Recheck time again before emitting the result; discard it if a lease or
    /// deadline expired during signing. Any failure leaves the nonce consumed.
    pub fn issue<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        issuer: &IssuerKey,
        expected: &RootBoardPublicKey,
        now: Timestamp,
    ) -> Result<BlindRootBoardCredential, Error> {
        if now < self.consumed_at {
            return Err(Error::InvalidChallenge);
        }
        crate::issue_blind_root_board(rng, issuer, expected, self.verified, now)
    }
}

/// Atomically consume the exact context proved by the owned proof capability.
/// The service calls this only while retaining the matching original source
/// role lease and after checking role, session, policy and current time.
///
/// Only an acknowledged compare-and-delete yields a release capability. On
/// cancellation or an uncertain storage result, release nothing and obtain a
/// fresh challenge. Never retry the old request as if no consumption occurred.
pub async fn consume_root_board_issuance<S: ChallengeStore>(
    store: &S,
    verified: VerifiedRootBoardIssuance,
    now: Timestamp,
) -> Result<ConsumedRootBoardIssuance, Error> {
    let context = verified.context();
    root_board_issuance_scope(store, context)?;
    context.current(now)?;
    if !store
        .consume(context.nonce(), root_board_issuance_binding(context), now)
        .await?
    {
        return Err(Error::InvalidChallenge);
    }
    Ok(ConsumedRootBoardIssuance {
        verified,
        consumed_at: now,
    })
}

/// Reserve an issuance nonce in the global issuer's separate challenge store.
/// Attributes and uniqueness checks are still authorized by the issuer service.
pub async fn issuance_challenge<R: RngCore + CryptoRng, S: ChallengeStore>(
    rng: &mut R,
    store: &S,
    issuer: &IssuerPublicKey,
    authenticated: &AuthenticatedIssuance,
    deadline: Timestamp,
) -> Result<IssuanceChallenge, Error> {
    check_timestamp(deadline)?;
    let nonce = IssuanceChallenge::generate(rng);
    let record = ChallengeRecord {
        nonce: nonce.to_bytes(),
        binding: issuance_binding(issuer, authenticated),
        expires: deadline,
    };
    if !store.reserve(record).await? {
        return Err(Error::ChallengeConflict);
    }
    Ok(nonce)
}

fn issuance_binding(issuer: &IssuerPublicKey, authenticated: &AuthenticatedIssuance) -> [u8; 32] {
    binding(
        b"cpsd/v2/issuance-slot",
        &[
            &issuer.to_bytes(),
            &authenticated.person,
            &authenticated.session,
        ],
    )
}

/// Sign only once for a stored issuance challenge. The caller must authenticate
/// the person and session and authorize the attributes. Tag continuity and nonce
/// consumption are committed together, after proof validation, before release.
/// A storage failure never releases a signed response; outcomes can be uncertain
/// on remote timeouts, so obtain a new challenge instead of assuming success.
#[allow(clippy::too_many_arguments)]
pub async fn issue_blind_once<R: RngCore + CryptoRng, S: crate::storage::IssuanceStore>(
    rng: &mut R,
    store: &S,
    issuer: &IssuerKey,
    authenticated: &AuthenticatedIssuance,
    request: &IssuanceRequest,
    challenge: &IssuanceChallenge,
    attributes: &PassportAttributes,
    now: Timestamp,
) -> Result<BlindPassport, Error> {
    check_timestamp(now)?;
    let binding = issuance_binding(issuer.public_key(), authenticated);
    if !store.matches(challenge.to_bytes(), binding, now).await? {
        return Err(Error::InvalidChallenge);
    }
    let blind = issuer.issue_blind(rng, request, challenge, attributes)?;
    if !store
        .consume_issuance(crate::storage::VerifiedIssuance {
            nonce: challenge.to_bytes(),
            binding,
            now,
            person: authenticated.person,
            tag: request.issuer_tag(),
        })
        .await?
    {
        return Err(Error::InvalidChallenge);
    }
    Ok(blind)
}
