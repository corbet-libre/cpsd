use ark_bls12_381::{Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_std::{
    UniformRand,
    rand::{CryptoRng, RngCore},
};
use dock_crypto_utils::transcript::{MerlinTranscript, Transcript};
use schnorr_pok::discrete_log::{PokPedersenCommitment, PokPedersenCommitmentProtocol};

use super::{RootBoardPublicKey, global_issuer, state::RootBoardPending};
use crate::{
    BlindPassport, CommunityId, Error, IssuanceChallenge, IssuerKey, IssuerPublicKey, KeyId,
    Passport, PendingIssuance, PresentationRequest, Pseudonym, Timestamp,
    params::IDX_SECRET,
    root_board::check_request,
    root_board::proof::{PresentationProof, PresentationProtocol},
    wire::{Kind, Reader, Writer},
};

/// Verifier-owned source request, authenticated common root descriptor and fresh
/// one-use root nonce. The source request's time is the inclusive deadline.
#[derive(Clone, PartialEq, Eq)]
pub struct RootBoardIssuanceContext {
    source: PresentationRequest,
    root: RootBoardPublicKey,
    nonce: IssuanceChallenge,
}

impl RootBoardIssuanceContext {
    /// Create and store before sending to the holder. The root issuer's service
    /// retains this exact context through its original nonce/role transaction.
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        source: PresentationRequest,
        root: RootBoardPublicKey,
    ) -> Result<Self, Error> {
        Self::assemble(source, root, IssuanceChallenge::generate(rng))
    }

    fn assemble(
        source: PresentationRequest,
        root: RootBoardPublicKey,
        nonce: IssuanceChallenge,
    ) -> Result<Self, Error> {
        root.current(source.now())?;
        if source.community() == root.community() {
            return Err(Error::InvalidRootBoard);
        }
        Ok(Self {
            source,
            root,
            nonce,
        })
    }

    /// Original source request; it must also be authenticated on the device.
    pub fn source_request(&self) -> &PresentationRequest {
        &self.source
    }
    /// Common root key and cohort.
    pub fn root(&self) -> &RootBoardPublicKey {
        &self.root
    }
    /// Original service's one-use nonce key.
    pub fn nonce(&self) -> [u8; 32] {
        self.nonce.to_bytes()
    }
    /// Inclusive deadline, strictly before the root cohort's exclusive expiry.
    pub fn deadline(&self) -> Timestamp {
        self.source.now()
    }

    pub(crate) fn current(&self, now: Timestamp) -> Result<(), Error> {
        self.root.current(now)?;
        if now > self.deadline() {
            return Err(Error::InvalidChallenge);
        }
        Ok(())
    }

    /// Canonical public context; decode is not authentication or nonce storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Kind::RootBoardIssuanceContext);
        w.bytes(&super::request_bytes(&self.source));
        w.bytes(&self.root.to_bytes());
        w.fixed(&self.nonce.to_bytes());
        w.finish_public()
    }

    /// Strict bounded context decoder.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::RootBoardIssuanceContext)?;
        let source = super::request_from_bytes(r.bytes()?)?;
        let root = RootBoardPublicKey::from_bytes(r.bytes()?)?;
        let nonce = IssuanceChallenge::from_bytes(r.fixed()?);
        r.finish()?;
        Self::assemble(source, root, nonce)
    }
}

/// Joint proof of an original passport, its source pseudonym and the blinded
/// root holder secret. Contains no root pseudonym or global continuity tag.
pub struct RootBoardIssuanceRequest {
    pub(super) global_key: KeyId,
    pub(super) source_pseudonym: Pseudonym,
    pub(super) commitment: G1Affine,
    pub(super) passport: PresentationProof,
    pub(super) opening: PokPedersenCommitment<G1Affine>,
}

impl RootBoardIssuanceRequest {
    /// Public bounded proof encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Kind::RootBoardIssuanceRequest);
        w.key_id(&self.global_key);
        w.fixed(&self.source_pseudonym.to_bytes());
        w.ark(&self.commitment);
        w.proof(&self.passport);
        w.ark(&self.opening);
        w.finish_public()
    }

    /// Decode and validate all curve encodings and bounded proof shapes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::RootBoardIssuanceRequest)?;
        let global_key = r.key_id()?;
        let source_pseudonym = Pseudonym::from_bytes(&r.fixed::<48>()?)?;
        let commitment: G1Affine = r.ark("root commitment")?;
        let passport = r.proof()?;
        let opening = r.ark("root opening proof")?;
        r.finish()?;
        if commitment.is_zero() {
            return Err(Error::InvalidRootBoard);
        }
        Ok(Self {
            global_key,
            source_pseudonym,
            commitment,
            passport,
            opening,
        })
    }
}

fn transcript(issuer: &IssuerPublicKey, context: &RootBoardIssuanceContext) -> MerlinTranscript {
    let mut t = MerlinTranscript::new(b"cpsd/v3/root-board-issuance");
    t.append_message(b"global-issuer", &issuer.to_bytes());
    t.append_message(b"context", &context.to_bytes());
    t
}

fn opening_contribution(
    root: &RootBoardPublicKey,
    commitment: &G1Affine,
    t: &G1Affine,
    transcript: &mut MerlinTranscript,
) -> Result<(), Error> {
    let params = root.issuer.signature_params();
    let mut bytes = Vec::new();
    PokPedersenCommitmentProtocol::compute_challenge_contribution(
        &params.h_0,
        &params.h[IDX_SECRET],
        commitment,
        t,
        &mut bytes,
    )
    .map_err(|_| Error::InvalidRootBoard)?;
    transcript.append_message(b"root-opening", &bytes);
    Ok(())
}

pub(crate) fn request<R: RngCore + CryptoRng>(
    rng: &mut R,
    passport: &Passport,
    context: &RootBoardIssuanceContext,
) -> Result<(RootBoardIssuanceRequest, RootBoardPending), Error> {
    request_for_opening(rng, passport, &passport.secret, context)
}

/// The commitment's opening secret is a separate parameter ONLY so tests can
/// build a hostile request that commits to another secret; production callers
/// always pass the passport's own secret through [`request`].
pub(crate) fn request_for_opening<R: RngCore + CryptoRng>(
    rng: &mut R,
    passport: &Passport,
    opening_secret: &crate::HolderSecret,
    context: &RootBoardIssuanceContext,
) -> Result<(RootBoardIssuanceRequest, RootBoardPending), Error> {
    context.root.distinct_from(passport.issuer())?;
    check_request(passport, &context.source)?;
    let blinding = Fr::rand(rng);
    let shared = Fr::rand(rng);
    let params = context.root.issuer.signature_params();
    let commitment = params
        .commit_to_messages([(IDX_SECRET, &opening_secret.0)], &blinding)
        .map_err(|_| Error::ProofGeneration)?;
    if commitment.is_zero() {
        return Err(Error::ProofGeneration);
    }
    let source_pseudonym = passport.pseudonym(context.source.community());
    let protocol = PresentationProtocol::new(
        rng,
        passport,
        &context.source,
        &source_pseudonym.point()?,
        shared,
    )?;
    let opening = PokPedersenCommitmentProtocol::init(
        blinding,
        Fr::rand(rng),
        &params.h_0,
        opening_secret.0,
        shared,
        &params.h[IDX_SECRET],
    );
    let mut t = transcript(passport.issuer(), context);
    protocol.contribute(&mut t)?;
    opening_contribution(&context.root, &commitment, &opening.t, &mut t)?;
    let challenge = t.challenge_scalar::<Fr>(b"challenge");
    let request = RootBoardIssuanceRequest {
        global_key: passport.key_id().clone(),
        source_pseudonym,
        commitment,
        passport: protocol.finish(&challenge)?,
        opening: opening.gen_proof(&challenge),
    };
    let pending = RootBoardPending {
        descriptor: context.root.clone(),
        opening: PendingIssuance::from_opening(opening_secret, blinding, &context.root.issuer),
    };
    Ok((request, pending))
}

/// Verified holder binding, not admin authority. No public constructor, Clone or
/// serializer exists. Hold the matching original source role lease, recheck its
/// deadline and atomically consume this nonce before signature release.
pub struct VerifiedRootBoardIssuance {
    context: RootBoardIssuanceContext,
    source_pseudonym: Pseudonym,
    commitment: G1Affine,
}

impl VerifiedRootBoardIssuance {
    pub(crate) fn context(&self) -> &RootBoardIssuanceContext {
        &self.context
    }

    /// Compare with the original current admin/root lease's source community.
    pub fn source_community(&self) -> &CommunityId {
        self.context.source.community()
    }
    /// Compare with that same lease's member; never pair with a root pseudonym.
    pub fn source_pseudonym(&self) -> Pseudonym {
        self.source_pseudonym
    }
    /// Consume through the issuer service's original one-use nonce transaction.
    pub fn nonce(&self) -> [u8; 32] {
        self.context.nonce()
    }
    /// Recheck with the source lease after awaits and before signing.
    pub fn deadline(&self) -> Timestamp {
        self.context.deadline()
    }
    /// Exact authenticated common descriptor whose issuance was proved.
    pub fn root(&self) -> &RootBoardPublicKey {
        &self.context.root
    }
}

/// Verify against the service's OWN stored context and trusted global key ring.
/// This function establishes only cryptographic holder binding, never a role.
pub fn verify_root_board_issuance(
    issuers: &[IssuerPublicKey],
    context: &RootBoardIssuanceContext,
    request: &RootBoardIssuanceRequest,
    now: Timestamp,
) -> Result<VerifiedRootBoardIssuance, Error> {
    context.current(now)?;
    let issuer = global_issuer(issuers, &request.global_key, &context.root)?;
    if request.commitment.is_zero() {
        return Err(Error::InvalidRootBoard);
    }
    let mut t = transcript(issuer, context);
    let nym = request.source_pseudonym.point()?;
    request
        .passport
        .contribute(issuer, &context.source, &nym, &mut t)?;
    opening_contribution(
        &context.root,
        &request.commitment,
        &request.opening.t,
        &mut t,
    )?;
    let challenge = t.challenge_scalar::<Fr>(b"challenge");
    let params = context.root.issuer.signature_params();
    if request.opening.response2 != request.passport.pseudonym.response
        || !request.opening.verify(
            &request.commitment,
            &params.h_0,
            &params.h[IDX_SECRET],
            &challenge,
        )
    {
        return Err(Error::InvalidRootBoard);
    }
    request
        .passport
        .verify_challenge(issuer, &context.source, &nym, &challenge)?;
    Ok(VerifiedRootBoardIssuance {
        context: context.clone(),
        source_pseudonym: request.source_pseudonym,
        commitment: request.commitment,
    })
}

/// Blinded root credential, usable only with the actual retained holder opening.
pub struct BlindRootBoardCredential {
    pub(crate) descriptor: RootBoardPublicKey,
    pub(crate) blind: BlindPassport,
}

impl BlindRootBoardCredential {
    /// Public answer encoding; contains no holder opening or plaintext secret.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Kind::BlindRootBoardCredential);
        w.bytes(&self.descriptor.to_bytes());
        w.bytes(&self.blind.to_bytes());
        w.finish_public()
    }
    /// Strict bounded answer decoder. The holder still verifies the signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::BlindRootBoardCredential)?;
        let descriptor = RootBoardPublicKey::from_bytes(r.bytes()?)?;
        let blind = BlindPassport::from_bytes(r.bytes()?)?;
        r.finish()?;
        if blind.key_id() != descriptor.issuer.key_id()
            || blind.attributes() != &descriptor.attributes()
        {
            return Err(Error::InvalidRootBoard);
        }
        Ok(Self { descriptor, blind })
    }
}

/// Sign only a verified commitment with the exact authenticated common cohort.
/// The enclosing original service owns admin-lease/current-clock/nonce CAS.
/// Consumes the proof capability and accepts no caller-selected attributes.
pub fn issue_blind_root_board<R: RngCore + CryptoRng>(
    rng: &mut R,
    issuer: &IssuerKey,
    expected: &RootBoardPublicKey,
    verified: VerifiedRootBoardIssuance,
    now: Timestamp,
) -> Result<BlindRootBoardCredential, Error> {
    verified.context.current(now)?;
    if &verified.context.root != expected || issuer.public_key() != &expected.issuer {
        return Err(Error::InvalidRootBoard);
    }
    let blind = issuer.issue_commitment(rng, &verified.commitment, &expected.attributes())?;
    Ok(BlindRootBoardCredential {
        descriptor: expected.clone(),
        blind,
    })
}
