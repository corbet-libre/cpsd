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
