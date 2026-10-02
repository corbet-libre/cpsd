use ark_bls12_381::Fr;
use ark_std::{UniformRand, rand::{CryptoRng, RngCore}};
use dock_crypto_utils::transcript::{MerlinTranscript, Transcript};

use super::{RootBoardPublicKey, global_issuer, state::RootBoardCredential};
use crate::{
    Error, IssuerPublicKey, KeyId, Passport, PresentationRequest, Pseudonym, Timestamp,
    presentation::check_request, proof::{PresentationProof, PresentationProtocol},
    wire::{Kind, Reader, Writer},
};

/// One authenticated root request binding both credential requirements. Sign
/// this complete canonical payload as a csgn Credential, with exclusive COSE
/// expiry equal to the global request deadline plus one second.
#[derive(Clone, PartialEq, Eq)]
pub struct RootBoardRequest {
    global: PresentationRequest,
    root: RootBoardPublicKey,
}

impl RootBoardRequest {
    /// Create/store the root service's request using its authenticated common
    /// descriptor. Both original global presentation profiles are supported.
    pub fn new(global: PresentationRequest, root: RootBoardPublicKey) -> Result<Self, Error> {
        root.current(global.now())?;
        if global.community() != root.community() { return Err(Error::InvalidRootBoard); }
        Ok(Self { global, root })
    }
    /// Original global passport requirements and one-use challenge.
    pub fn global_request(&self) -> &PresentationRequest { &self.global }
    /// Authenticated common root issuer/cohort.
    pub fn root(&self) -> &RootBoardPublicKey { &self.root }
    /// Inclusive request deadline.
    pub fn deadline(&self) -> Timestamp { self.global.now() }

    pub(crate) fn current(&self, now: Timestamp) -> Result<(), Error> {
        self.root.current(now)?;
        if now > self.deadline() { return Err(Error::InvalidChallenge); }
        Ok(())
    }

    /// Complete canonical payload for the authenticated root request.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Kind::RootBoardRequest);
        w.bytes(&self.global.to_bytes());
        w.bytes(&self.root.to_bytes());
        w.finish_public()
    }
    /// Bounded canonical decoder. Authentication remains mandatory on device.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::RootBoardRequest)?;
        let global = PresentationRequest::from_bytes(r.bytes()?)?;
        let root = RootBoardPublicKey::from_bytes(r.bytes()?)?;
        r.finish()?;
        Self::new(global, root)
    }
}

/// Joint original passport/root credential proof over the same secret. No
/// source community, source pseudonym, role or issuance tag is included.
pub struct RootBoardPresentation {
    pub(super) global_key: KeyId,
    pub(super) pseudonym: Pseudonym,
    pub(super) global: PresentationProof,
    pub(super) root: PresentationProof,
}

impl RootBoardPresentation {
    /// Public bounded proof encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Kind::RootBoardPresentation);
        w.key_id(&self.global_key);
        w.fixed(&self.pseudonym.to_bytes());
        w.proof(&self.global);
        w.proof(&self.root);
        w.finish_public()
    }
    /// Strict bounded proof decoder. The claimed pseudonym remains untrusted.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::RootBoardPresentation)?;
        let global_key = r.key_id()?;
        let pseudonym = Pseudonym::from_bytes(&r.fixed::<48>()?)?;
        let global = r.proof()?;
        let root = r.proof()?;
        r.finish()?;
        if !root.ranges.is_empty() { return Err(Error::InvalidRootBoard); }
        Ok(Self { global_key, pseudonym, global, root })
    }
}

fn transcript(global: &IssuerPublicKey, request: &RootBoardRequest) -> MerlinTranscript {
    let mut t = MerlinTranscript::new(b"cpsd/v3/root-board-presentation");
    t.append_message(b"global-issuer", &global.to_bytes());
    t.append_message(b"request", &request.to_bytes());
    t
}

pub(crate) fn present<R: RngCore + CryptoRng>(
    rng: &mut R, passport: &Passport, credential: &RootBoardCredential, request: &RootBoardRequest,
) -> Result<RootBoardPresentation, Error> {
    if credential.descriptor != request.root || passport.secret.0 != credential.passport.secret.0 {
        return Err(Error::InvalidRootBoard);
    }
    build(rng, passport, credential, request)
}

/// Joint proof construction after the holder-side checks. Separate from
/// [`present`] ONLY so tests can build a hostile proof that mixes credentials of
/// two holders; production callers always go through [`present`].
pub(crate) fn build<R: RngCore + CryptoRng>(
    rng: &mut R, passport: &Passport, credential: &RootBoardCredential, request: &RootBoardRequest,
) -> Result<RootBoardPresentation, Error> {
    request.root.distinct_from(passport.issuer())?;
    check_request(passport, &request.global)?;
    let root_request = request.root.request(&request.global)?;
    check_request(&credential.passport, &root_request)?;
    let pseudonym = passport.pseudonym(request.root.community());
    let point = pseudonym.point()?;
    let shared = Fr::rand(rng);
    let global = PresentationProtocol::new(rng, passport, &request.global, &point, shared)?;
    let root = PresentationProtocol::new(rng, &credential.passport, &root_request, &point, shared)?;
    let mut t = transcript(passport.issuer(), request);
    t.append_message(b"credential", b"global");
    global.contribute(&mut t)?;
    t.append_message(b"credential", b"root-board");
    root.contribute(&mut t)?;
    let challenge = t.challenge_scalar::<Fr>(b"challenge");
    Ok(RootBoardPresentation {
        global_key: passport.key_id().clone(), pseudonym,
        global: global.finish(&challenge)?, root: root.finish(&challenge)?,
    })
}

/// Verify both actual signatures, expiry profiles and holder equality against
/// the verifier's OWN stored request and trusted keys. The original service
/// must consume that request's challenge exactly once on successful admission.
pub fn verify_root_board(
    issuers: &[IssuerPublicKey], request: &RootBoardRequest,
    presentation: &RootBoardPresentation, now: Timestamp,
) -> Result<Pseudonym, Error> {
    request.current(now)?;
    let issuer = global_issuer(issuers, &presentation.global_key, &request.root)?;
    let root_request = request.root.request(&request.global)?;
    let point = presentation.pseudonym.point()?;
    let mut t = transcript(issuer, request);
    t.append_message(b"credential", b"global");
    presentation.global.contribute(issuer, &request.global, &point, &mut t)?;
    t.append_message(b"credential", b"root-board");
    presentation.root.contribute(&request.root.issuer, &root_request, &point, &mut t)?;
    let challenge = t.challenge_scalar::<Fr>(b"challenge");
    if presentation.global.pseudonym.response != presentation.root.pseudonym.response {
        return Err(Error::InvalidRootBoard);
    }
    presentation.global.verify_challenge(issuer, &request.global, &point, &challenge)?;
    presentation.root.verify_challenge(&request.root.issuer, &root_request, &point, &challenge)?;
    Ok(presentation.pseudonym)
}
