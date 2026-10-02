//! Presentation: zero-knowledge proof of a valid passport plus the community
//! pseudonym, and its verification.

use std::collections::{BTreeMap, BTreeSet};

use ark_bls12_381::{Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_std::rand::{CryptoRng, RngCore};

use crate::{
    CommunityId, Error, GateId, IssuerPublicKey, KeyId, MAX_GATES, Passport, Timestamp,
    attributes::check_timestamp,
    issuer::point_bytes,
    params::{self, IDX_EPOCH, IDX_FIRST_GATE, IDX_KEY_ID, IDX_VALID_UNTIL},
    proof::PresentationProof,
    wire::{Kind, Reader, Writer, hex},
};

/// A holder's pseudonym in one community: `secret * H(community)` in G1.
///
/// Same holder and community give the same pseudonym (also across passport
/// renewals); pseudonyms of one holder in different communities are
/// unlinkable under the decisional Diffie-Hellman assumption in G1. This is
/// the member ID of the community register.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pseudonym([u8; 48]);

impl Pseudonym {
    pub(crate) fn from_point(p: G1Affine) -> Self {
        Self(point_bytes(&p))
    }

    pub(crate) fn point(&self) -> Result<G1Affine, Error> {
        decode_point(&self.0)
    }

    /// Compressed G1 encoding (48 bytes).
    pub fn to_bytes(&self) -> [u8; 48] {
        self.0
    }

    /// Validates a 48-byte pseudonym (canonical, in the prime-order subgroup,
    /// not the identity).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let p = decode_point(bytes)?;
        Ok(Self::from_point(p))
    }

    /// Lower-case hexadecimal of [`to_bytes`](Self::to_bytes) (96 characters).
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }
}

impl core::fmt::Debug for Pseudonym {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Pseudonym({})", self.to_hex())
    }
}

fn decode_point(bytes: &[u8]) -> Result<G1Affine, Error> {
    use ark_serialize::CanonicalDeserialize;
    let mut slice = bytes;
    let p = G1Affine::deserialize_compressed(&mut slice).map_err(|_| Error::Decode("pseudonym"))?;
    if !slice.is_empty() || p.is_zero() || point_bytes(&p).as_slice() != bytes {
        return Err(Error::Decode("pseudonym"));
    }
    Ok(p)
}

/// What a verifier (community level, `cmty`) asks for, created fresh for every
/// admission attempt.
///
/// The challenge is random; the verifier must store the request, accept at
/// most one presentation for it and discard it afterwards (that, together with
/// the proof's binding to the challenge, is the replay protection).
#[derive(Clone, PartialEq, Eq)]
pub struct PresentationRequest {
    community: CommunityId,
    policy_epoch: u64,
    required_gates: BTreeSet<GateId>,
    now: Timestamp,
    epoch_expiry: Option<Timestamp>,
    challenge: [u8; 32],
}

impl PresentationRequest {
    /// Creates a request with a fresh random challenge.
    ///
    /// `now` is the verifier's current time; the proof shows that the
    /// passport's validity and every required gate's expiry are not before it.
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        community: CommunityId,
        policy_epoch: u64,
        required_gates: impl IntoIterator<Item = GateId>,
        now: Timestamp,
    ) -> Result<Self, Error> {
        let mut challenge = [0u8; 32];
        rng.fill_bytes(&mut challenge);
        Self::with_challenge(community, policy_epoch, required_gates, now, challenge)
    }

    /// Request the fast shared-epoch profile. Passport and requested gate
    /// expiries must equal the verifier-selected `epoch_expiry` exactly.
    /// This public cohort value is already known to the verifier; ordinary
    /// BBS+ selective disclosure replaces expensive hidden range predicates.
    /// Use one authenticated expiry for the entire epoch, never per holder.
    pub fn for_epoch<R: RngCore + CryptoRng>(
        rng: &mut R,
        community: CommunityId,
        policy_epoch: u64,
        required_gates: impl IntoIterator<Item = GateId>,
        now: Timestamp,
        epoch_expiry: Timestamp,
    ) -> Result<Self, Error> {
        Self::new(rng, community, policy_epoch, required_gates, now)?
            .with_epoch_expiry(epoch_expiry)
    }

    /// Select the shared-epoch profile without changing this request's nonce.
    /// Call before registering the request in a service's challenge store.
    pub fn with_epoch_expiry(mut self, expiry: Timestamp) -> Result<Self, Error> {
        check_timestamp(expiry)?;
        if expiry < self.now {
            return Err(Error::PassportExpired);
        }
        self.epoch_expiry = Some(expiry);
        Ok(self)
    }

    /// Creates a request with a caller-supplied challenge (which must be
    /// unpredictable and single-use).
    pub fn with_challenge(
        community: CommunityId,
        policy_epoch: u64,
        required_gates: impl IntoIterator<Item = GateId>,
        now: Timestamp,
        challenge: [u8; 32],
    ) -> Result<Self, Error> {
        check_timestamp(now)?;
        let required_gates: BTreeSet<GateId> = required_gates.into_iter().collect();
        if required_gates.len() > MAX_GATES {
            return Err(Error::TooManyGates);
        }
        Ok(Self {
            community,
            policy_epoch,
            required_gates,
            now,
            epoch_expiry: None,
            challenge,
        })
    }

    /// The community (pseudonym scope).
    pub fn community(&self) -> &CommunityId {
        &self.community
    }

    /// Required policy epoch.
    pub fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }

    /// Gates that must be present and unexpired.
    pub fn required_gates(&self) -> &BTreeSet<GateId> {
        &self.required_gates
    }

    /// The verifier's time.
    pub fn now(&self) -> Timestamp {
        self.now
    }

    /// Shared expiry required by the fast profile, or hidden independent expiries.
    pub fn epoch_expiry(&self) -> Option<Timestamp> {
        self.epoch_expiry
    }

    /// The challenge.
    pub fn challenge(&self) -> [u8; 32] {
        self.challenge
    }

    /// Encoding for transport to the holder.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Kind::PresentationRequest);
        w.bytes(self.community.as_bytes());
        w.u64(self.policy_epoch);
        w.u64(self.now);
        // Zero is reserved for the independent hidden-expiry profile.
        w.u64(self.epoch_expiry.unwrap_or(0));
        w.u16(self.required_gates.len() as u16);
        for gate in &self.required_gates {
            w.gate(gate);
        }
        w.fixed(&self.challenge);
        w.finish_public()
    }

    /// Decodes a request received from a verifier.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::PresentationRequest)?;
        let community = CommunityId::new(r.bytes()?)?;
        let policy_epoch = r.u64()?;
        let now = r.u64()?;
        let epoch_expiry = r.u64()?;
        let count = r.u16()? as usize;
        if count > MAX_GATES {
            return Err(Error::TooManyGates);
        }
        let mut gates = Vec::with_capacity(count);
        for _ in 0..count {
            let gate = r.gate()?;
            if gates.last().is_some_and(|last: &GateId| *last >= gate) {
                return Err(Error::Decode("gate order"));
            }
            gates.push(gate);
        }
        let challenge = r.fixed::<32>()?;
        r.finish()?;
        let request = Self::with_challenge(community, policy_epoch, gates, now, challenge)?;
        if epoch_expiry == 0 {
            Ok(request)
        } else {
            request.with_epoch_expiry(epoch_expiry)
        }
    }
}

impl core::fmt::Debug for PresentationRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PresentationRequest")
            .field("community", &self.community)
            .field("policy_epoch", &self.policy_epoch)
            .field("required_gates", &self.required_gates)
            .field("now", &self.now)
            .field("epoch_expiry", &self.epoch_expiry)
            .finish_non_exhaustive()
    }
}

/// A holder's answer to a [`PresentationRequest`]: the community pseudonym
/// and a zero-knowledge proof of
///
/// - a valid BBS+ signature by the key `key_id` over hidden messages,
/// - revealed: the key ID and the requested policy epoch,
/// - the pseudonym is `secret * H(community)` for the signed holder secret,
/// - `now <= valid_until` and `now <= expiry` of every requested gate,
/// - all bound to the request (community, epoch, gates, time, challenge).
///
/// Independent expiries stay hidden. In the shared-epoch profile, requested
/// expiries equal the verifier's already-known cohort value. Other gates,
/// the revocation handle and signature stay hidden. Two presentations are
/// unlinkable apart from the pseudonym and shared public policy metadata.
#[derive(Clone)]
pub struct Presentation {
    key_id: KeyId,
    pub(crate) pseudonym: Pseudonym,
    pub(crate) proof: PresentationProof,
}

impl Presentation {
    /// Key that signed the presented passport.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The claimed pseudonym. Only meaningful after [`verify`] succeeded;
    /// `verify` returns it.
    pub fn pseudonym(&self) -> &Pseudonym {
        &self.pseudonym
    }

    /// Encoding for transport to the verifier.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Kind::Presentation);
        w.key_id(&self.key_id);
        w.fixed(&self.pseudonym.0);
        w.proof(&self.proof);
        w.finish_public()
    }

    /// Decodes a presentation received from a holder.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::Presentation)?;
        let key_id = r.key_id()?;
        let pseudonym = Pseudonym::from_bytes(&r.fixed::<48>()?)?;
        let proof = r.proof()?;
        r.finish()?;
        Ok(Self {
            key_id,
            pseudonym,
            proof,
        })
    }
}

impl core::fmt::Debug for Presentation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Presentation")
            .field("key_id", &self.key_id)
            .field("pseudonym", &self.pseudonym)
            .finish_non_exhaustive()
    }
}

pub(crate) fn revealed_messages(
    issuer: &IssuerPublicKey,
    request: &PresentationRequest,
) -> Result<BTreeMap<usize, Fr>, Error> {
    let mut revealed = BTreeMap::from([
        (IDX_KEY_ID, params::key_id_scalar(issuer.key_id())),
        (IDX_EPOCH, Fr::from(request.policy_epoch)),
    ]);
    if let Some(expiry) = request.epoch_expiry {
        revealed.insert(IDX_VALID_UNTIL, Fr::from(expiry));
        for gate in &request.required_gates {
            revealed.insert(IDX_FIRST_GATE + issuer.gate_slot(gate)?, Fr::from(expiry));
        }
    }
    Ok(revealed)
}

/// Exact signed message indices required by the independent-expiry profile.
pub(crate) fn ranged_messages(
    issuer: &IssuerPublicKey,
    request: &PresentationRequest,
) -> Result<Vec<usize>, Error> {
    if request.epoch_expiry.is_some() {
        return Ok(Vec::new());
    }
    let mut ranged = vec![IDX_VALID_UNTIL];
    for gate in &request.required_gates {
        ranged.push(IDX_FIRST_GATE + issuer.gate_slot(gate)?);
    }
    Ok(ranged)
}

/// Authenticate a community-signed request against the wallet's origin-pinned
/// expected community, then create a presentation. `now` is trusted wallet time.
/// The csgn Credential payload must be the exact versioned PresentationRequest;
/// see [`crate::AuthenticatedCommunity::authenticate`] for signing requirements.
///
/// Fails without producing a proof if authentication fails or the passport cannot satisfy the request
/// (wrong epoch, expired, gate missing or expired, gate unknown to the key).
pub fn present<R: RngCore + CryptoRng>(
    rng: &mut R,
    passport: &Passport,
    expected: &crate::AuthenticatedCommunity,
    signed_request: &[u8],
    now: Timestamp,
) -> Result<Presentation, Error> {
    let request = expected.authenticate(signed_request, now)?;
    present_checked(rng, passport, &request)
}

pub(crate) fn present_checked<R: RngCore + CryptoRng>(
    rng: &mut R,
    passport: &Passport,
    request: &PresentationRequest,
) -> Result<Presentation, Error> {
    check_request(passport, request)?;
    prove(rng, passport, request)
}

pub(crate) fn check_request(passport: &Passport, request: &PresentationRequest) -> Result<(), Error> {
    let attributes = passport.attributes();
    let issuer = passport.issuer();
    if attributes.policy_epoch != request.policy_epoch {
        return Err(Error::WrongEpoch);
    }
    if attributes.valid_until < request.now {
        return Err(Error::PassportExpired);
    }
    for gate in &request.required_gates {
        issuer.gate_slot(gate)?;
        match attributes.gates.get(gate) {
            None => return Err(Error::GateMissing(gate.clone())),
            Some(expires) if *expires < request.now => {
                return Err(Error::GateExpired(gate.clone()));
            }
            Some(_) => {}
        }
    }
    if let Some(expiry) = request.epoch_expiry
        && (attributes.valid_until != expiry
            || request
                .required_gates
                .iter()
                .any(|gate| attributes.gates.get(gate) != Some(&expiry)))
    {
        return Err(Error::WrongExpiryCohort);
    }
    Ok(())
}

/// Builds the proof without the holder-side checks of [`present`]. For a
/// passport that does not satisfy the request this either fails or yields a
/// proof that does not verify.
pub(crate) fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    passport: &Passport,
    request: &PresentationRequest,
) -> Result<Presentation, Error> {
    let issuer = passport.issuer();
    let pseudonym = passport.pseudonym(&request.community);
    let proof = PresentationProof::new(rng, passport, request, &pseudonym.point()?)?;
    Ok(Presentation {
        key_id: issuer.key_id().clone(),
        pseudonym,
        proof,
    })
}

/// Verifies `presentation` against the verifier's own `request` and returns
/// the holder's pseudonym for the request's community.
///
/// `issuers` is the verifier's key ring (all accepted issuer keys, including
/// old keys whose passports have not expired yet). The verifier must use the
/// request it created and stored, never one received from the holder.
pub fn verify<R: RngCore + CryptoRng>(
    _rng: &mut R,
    issuers: &[IssuerPublicKey],
    request: &PresentationRequest,
    presentation: &Presentation,
) -> Result<Pseudonym, Error> {
    let mut matching = issuers
        .iter()
        .filter(|k| *k.key_id() == presentation.key_id);
    let issuer = matching.next().ok_or(Error::UnknownKey)?;
    if matching.next().is_some() {
        return Err(Error::DuplicateKeyId);
    }
    for gate in &request.required_gates {
        issuer.gate_slot(gate)?;
    }

    presentation
        .proof
        .verify(issuer, request, &presentation.pseudonym.point()?)?;
    Ok(presentation.pseudonym)
}
