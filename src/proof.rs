//! Fixed v3 statement composition using Dock's public protocol APIs.
//!
//! Equality follows Dock BBS+'s shared-blinding/shared-challenge examples.
//! Range commitments are converted by Dock's arbitrary-range API, as in its
//! BoundCheckBpp protocol. All responses, verification equations, range proofs,
//! and Fiat–Shamir challenges are computed by the maintained libraries.

use std::collections::{BTreeMap, BTreeSet};

use ark_bls12_381::{Fr, G1Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    UniformRand,
    rand::{CryptoRng, RngCore},
};
use bbs_plus::proof::{PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol};
use bulletproofs_plus_plus::prelude::ProofArbitraryRange;
use dock_crypto_utils::{
    signature::MessageOrBlinding,
    transcript::{MerlinTranscript, Transcript},
};
use schnorr_pok::discrete_log::{
    PokDiscreteLog, PokDiscreteLogProtocol, PokPedersenCommitment, PokPedersenCommitmentProtocol,
};
use zeroize::Zeroizing;

use crate::{
    Error, IssuanceChallenge, IssuerPublicKey, Passport, PresentationRequest, TIME_LIMIT,
    params::{self, Curve, IDX_SECRET},
    presentation::{ranged_messages, revealed_messages},
};

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct IssuanceProof {
    pub(crate) opening: PokPedersenCommitment<G1Affine>,
    pub(crate) tag: PokDiscreteLog<G1Affine>,
}

#[derive(Clone)]
pub(crate) struct PresentationProof {
    pub(crate) signature: PoKOfSignatureG1Proof<Curve>,
    pub(crate) pseudonym: PokDiscreteLog<G1Affine>,
    pub(crate) ranges: Vec<RangeProof>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct RangeProof {
    pub(crate) range: ProofArbitraryRange<G1Affine>,
    pub(crate) lower: PokPedersenCommitment<G1Affine>,
    pub(crate) upper: PokPedersenCommitment<G1Affine>,
}

pub(crate) fn issuance_transcript(
    issuer: &IssuerPublicKey,
    nonce: &IssuanceChallenge,
) -> MerlinTranscript {
    let mut transcript = MerlinTranscript::new(b"cpsd/v3/issuance");
    transcript.append_message(b"issuer", &issuer.to_bytes());
    transcript.append_message(b"nonce", &nonce.to_bytes());
    transcript
}

impl IssuanceProof {
    pub(crate) fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        issuer: &IssuerPublicKey,
        nonce: &IssuanceChallenge,
        commitment: &G1Affine,
        tag: &G1Affine,
        secret: Fr,
        blinding: Fr,
    ) -> Result<Self, Error> {
        let params = issuer.signature_params();
        let shared = Fr::rand(rng);
        let opening = PokPedersenCommitmentProtocol::init(
            blinding,
            Fr::rand(rng),
            &params.h_0,
            secret,
            shared,
            &params.h[IDX_SECRET],
        );
        let tag_protocol = PokDiscreteLogProtocol::init(secret, shared, &params::issuer_tag_base());
        let mut transcript = issuance_transcript(issuer, nonce);
        let mut bytes = Vec::new();
        opening
            .challenge_contribution(&params.h_0, &params.h[IDX_SECRET], commitment, &mut bytes)
            .map_err(|_| Error::ProofGeneration)?;
        transcript.append_message(b"opening", &bytes);
        bytes.clear();
        tag_protocol
            .challenge_contribution(&params::issuer_tag_base(), tag, &mut bytes)
            .map_err(|_| Error::ProofGeneration)?;
        transcript.append_message(b"tag", &bytes);
        let challenge = transcript.challenge_scalar::<Fr>(b"challenge");
        Ok(Self {
            opening: opening.gen_proof(&challenge),
            tag: tag_protocol.gen_proof(&challenge),
        })
    }

    pub(crate) fn verify(
        &self,
        issuer: &IssuerPublicKey,
        nonce: &IssuanceChallenge,
        commitment: &G1Affine,
        tag: &G1Affine,
    ) -> Result<(), Error> {
        let params = issuer.signature_params();
        let mut transcript = issuance_transcript(issuer, nonce);
        let mut bytes = Vec::new();
        self.opening
            .challenge_contribution(&params.h_0, &params.h[IDX_SECRET], commitment, &mut bytes)
            .map_err(|_| Error::InvalidIssuanceRequest)?;
        transcript.append_message(b"opening", &bytes);
        bytes.clear();
        self.tag
            .challenge_contribution(&params::issuer_tag_base(), tag, &mut bytes)
            .map_err(|_| Error::InvalidIssuanceRequest)?;
        transcript.append_message(b"tag", &bytes);
        let challenge = transcript.challenge_scalar::<Fr>(b"challenge");
        if self.opening.response2 != self.tag.response
            || !self
                .opening
                .verify(commitment, &params.h_0, &params.h[IDX_SECRET], &challenge)
            || !self.tag.verify(tag, &params::issuer_tag_base(), &challenge)
        {
            return Err(Error::InvalidIssuanceRequest);
        }
        Ok(())
    }
}

pub(crate) fn presentation_transcript(
    issuer: &IssuerPublicKey,
    request: &PresentationRequest,
) -> MerlinTranscript {
    let mut transcript = MerlinTranscript::new(b"cpsd/v3/presentation");
    transcript.append_message(b"issuer", &issuer.to_bytes());
    transcript.append_message(b"request", &request.to_bytes());
    transcript
}

fn range_transcript(
    issuer: &IssuerPublicKey,
    request: &PresentationRequest,
    index: usize,
) -> MerlinTranscript {
    let mut transcript = MerlinTranscript::new(b"cpsd/v3/range");
    transcript.append_message(b"issuer", &issuer.to_bytes());
    transcript.append_message(b"request", &request.to_bytes());
    transcript.append_message(b"message-index", &(index as u64).to_be_bytes());
    transcript
}

struct RangeProtocol {
    range: ProofArbitraryRange<G1Affine>,
    lower: PokPedersenCommitmentProtocol<G1Affine>,
    upper: PokPedersenCommitmentProtocol<G1Affine>,
}

impl RangeProtocol {
    fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        issuer: &IssuerPublicKey,
        request: &PresentationRequest,
        index: usize,
        value: u64,
        blinding: Fr,
    ) -> Result<Self, Error> {
        let params = params::range_proof_params();
        let randomness = Zeroizing::new(vec![Fr::rand(rng), Fr::rand(rng)]);
        let range = ProofArbitraryRange::new(
            rng,
            64,
            vec![(value, request.now(), TIME_LIMIT)],
            randomness.to_vec(),
            params.clone(),
            &mut range_transcript(issuer, request, index),
        )
        .map_err(|_| Error::ProofGeneration)?;
        let (g, h) = params.get_pedersen_commitment_key();
        let lower = PokPedersenCommitmentProtocol::init(
            Fr::from(value),
            blinding,
            &g,
            randomness[0],
            Fr::rand(rng),
            &h,
        );
        let upper = PokPedersenCommitmentProtocol::init(
            Fr::from(value),
            blinding,
            &g,
            -randomness[1],
            Fr::rand(rng),
            &h,
        );
        Ok(Self {
            range,
            lower,
            upper,
        })
    }

    fn contribute(
        &self,
        request: &PresentationRequest,
        index: usize,
        transcript: &mut MerlinTranscript,
    ) -> Result<(), Error> {
        range_contribution(
            &self.range,
            &self.lower.t,
            &self.upper.t,
            request,
            index,
            transcript,
        )
    }

    fn finish(self, challenge: &Fr) -> RangeProof {
        RangeProof {
            range: self.range,
            lower: self.lower.gen_proof(challenge),
            upper: self.upper.gen_proof(challenge),
        }
    }
}

fn range_commitments(
    range: &ProofArbitraryRange<G1Affine>,
    request: &PresentationRequest,
) -> Result<(G1Affine, G1Affine), Error> {
    // Shape is checked before calling Dock, whose split function indexes pairs.
    if range.V.len() != 2 {
        return Err(Error::InvalidProof);
    }
    range
        .get_commitments_to_values(
            vec![(request.now(), TIME_LIMIT)],
            params::range_proof_params(),
        )
        .map_err(|_| Error::InvalidProof)?
        .into_iter()
        .next()
        .ok_or(Error::InvalidProof)
}

pub(crate) fn range_contribution(
    range: &ProofArbitraryRange<G1Affine>,
    lower_t: &G1Affine,
    upper_t: &G1Affine,
    request: &PresentationRequest,
    index: usize,
    transcript: &mut MerlinTranscript,
) -> Result<(), Error> {
    let (lower, upper) = range_commitments(range, request)?;
    let (g, h) = params::range_proof_params().get_pedersen_commitment_key();
    let mut bytes = Vec::new();
    range
        .serialize_compressed(&mut bytes)
        .map_err(|_| Error::InvalidProof)?;
    transcript.append_message(b"range-index", &(index as u64).to_be_bytes());
    transcript.append_message(b"range-proof", &bytes);
    bytes.clear();
    PokPedersenCommitmentProtocol::compute_challenge_contribution(
        &g, &h, &lower, lower_t, &mut bytes,
    )
    .map_err(|_| Error::InvalidProof)?;
    transcript.append_message(b"range-lower", &bytes);
    bytes.clear();
    PokPedersenCommitmentProtocol::compute_challenge_contribution(
        &g, &h, &upper, upper_t, &mut bytes,
    )
    .map_err(|_| Error::InvalidProof)?;
    transcript.append_message(b"range-upper", &bytes);
    Ok(())
}

impl PresentationProof {
    pub(crate) fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        passport: &Passport,
        request: &PresentationRequest,
        pseudonym: &G1Affine,
    ) -> Result<Self, Error> {
        let issuer = passport.issuer();
        let messages = passport.messages();
        let revealed = revealed_messages(issuer, request)?;
        let ranged = ranged_messages(issuer, request)?;
        let mut blindings = BTreeMap::from([(IDX_SECRET, Fr::rand(rng))]);
        for index in &ranged {
            blindings.insert(*index, Fr::rand(rng));
        }
        let signature = PoKOfSignatureG1Protocol::init(
            rng,
            &passport.signature,
            issuer.signature_params(),
            messages.iter().enumerate().map(|(index, message)| {
                if revealed.contains_key(&index) {
                    MessageOrBlinding::RevealMessage(message)
                } else if let Some(blinding) = blindings.get(&index) {
                    MessageOrBlinding::BlindMessageWithConcreteBlinding {
                        message,
                        blinding: *blinding,
                    }
                } else {
                    MessageOrBlinding::BlindMessageRandomly(message)
                }
            }),
        )
        .map_err(|_| Error::ProofGeneration)?;
        let nym = PokDiscreteLogProtocol::init(
            passport.secret.0,
            blindings[&IDX_SECRET],
            &params::community_base(request.community()),
        );
        let mut transcript = presentation_transcript(issuer, request);
        let mut bytes = Vec::new();
        signature
            .challenge_contribution(&revealed, issuer.signature_params(), &mut bytes)
            .map_err(|_| Error::ProofGeneration)?;
        transcript.append_message(b"signature", &bytes);
        bytes.clear();
        nym.challenge_contribution(
            &params::community_base(request.community()),
            pseudonym,
            &mut bytes,
        )
        .map_err(|_| Error::ProofGeneration)?;
        transcript.append_message(b"pseudonym", &bytes);
        let mut ranges = Vec::with_capacity(ranged.len());
        for index in ranged {
            // Original attributes supply the integer; equality below binds it to
            // this exact signed message, including hostile mismatching passports.
            let value = if index == params::IDX_VALID_UNTIL {
                passport.attributes.valid_until
            } else {
                passport
                    .attributes
                    .gates
                    .get(&issuer.gates()[index - params::IDX_FIRST_GATE])
                    .copied()
                    .unwrap_or(0)
            };
            let range = RangeProtocol::new(rng, issuer, request, index, value, blindings[&index])?;
            range.contribute(request, index, &mut transcript)?;
            ranges.push(range);
        }
        let challenge = transcript.challenge_scalar::<Fr>(b"challenge");
        Ok(Self {
            signature: signature
                .gen_proof(&challenge)
                .map_err(|_| Error::ProofGeneration)?,
            pseudonym: nym.gen_proof(&challenge),
            ranges: ranges.into_iter().map(|r| r.finish(&challenge)).collect(),
        })
    }

    pub(crate) fn verify(
        &self,
        issuer: &IssuerPublicKey,
        request: &PresentationRequest,
        pseudonym: &G1Affine,
    ) -> Result<(), Error> {
        let revealed = revealed_messages(issuer, request)?;
        let ranged = ranged_messages(issuer, request)?;
        if !crate::proof_wire::well_formed(self, ranged.len()) {
            return Err(Error::InvalidProof);
        }
        let mut transcript = presentation_transcript(issuer, request);
        let mut bytes = Vec::new();
        self.signature
            .challenge_contribution(&revealed, issuer.signature_params(), &mut bytes)
            .map_err(|_| Error::InvalidProof)?;
        transcript.append_message(b"signature", &bytes);
        bytes.clear();
        self.pseudonym
            .challenge_contribution(
                &params::community_base(request.community()),
                pseudonym,
                &mut bytes,
            )
            .map_err(|_| Error::InvalidProof)?;
        transcript.append_message(b"pseudonym", &bytes);
        for (index, range) in ranged.iter().zip(&self.ranges) {
            range_contribution(
                &range.range,
                &range.lower.t,
                &range.upper.t,
                request,
                *index,
                &mut transcript,
            )?;
        }
        let challenge = transcript.challenge_scalar::<Fr>(b"challenge");
        let revealed_indices: BTreeSet<usize> = revealed.keys().copied().collect();
        let response = |index| {
            self.signature
                .get_resp_for_message(index, &revealed_indices)
                .copied()
                .map_err(|_| Error::InvalidProof)
        };
        if response(IDX_SECRET)? != self.pseudonym.response
            || !self.pseudonym.verify(
                pseudonym,
                &params::community_base(request.community()),
                &challenge,
            )
        {
            return Err(Error::InvalidProof);
        }
        self.signature
            .verify(
                &revealed,
                &challenge,
                issuer.bbs_public_key().clone(),
                issuer.signature_params().clone(),
            )
            .map_err(|_| Error::InvalidProof)?;
        let (g, h) = params::range_proof_params().get_pedersen_commitment_key();
        for (index, range) in ranged.into_iter().zip(&self.ranges) {
            let signed_response = response(index)?;
            let (lower, upper) = range_commitments(&range.range, request)?;
            if range.lower.response1 != signed_response
                || range.upper.response1 != signed_response
                || !range.lower.verify(&lower, &g, &h, &challenge)
                || !range.upper.verify(&upper, &g, &h, &challenge)
            {
                return Err(Error::InvalidProof);
            }
            range
                .range
                .verify(
                    64,
                    params::range_proof_params(),
                    &mut range_transcript(issuer, request, index),
                )
                .map_err(|_| Error::InvalidProof)?;
        }
        Ok(())
    }
}
