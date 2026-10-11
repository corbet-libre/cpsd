//! Root-board statement composition. The presentation proof, its range proofs
//! and the single verifier live in `crate::proof`; this module only prepares
//! the prover half so a second proof can share the transcript and the secret
//! blinding.

use std::collections::BTreeMap;

use ark_bls12_381::{Fr, G1Affine};
use ark_std::{
    UniformRand,
    rand::{CryptoRng, RngCore},
};
use bbs_plus::proof::PoKOfSignatureG1Protocol;
use dock_crypto_utils::{
    signature::MessageOrBlinding,
    transcript::{MerlinTranscript, Transcript},
};
use schnorr_pok::discrete_log::PokDiscreteLogProtocol;

pub(crate) use crate::proof::PresentationProof;
use crate::{
    Error, IssuerPublicKey, Passport, PresentationRequest,
    params::{self, Curve, IDX_SECRET},
    presentation::{ranged_messages, revealed_messages},
    proof::RangeProtocol,
};

/// Prepared maintained protocols; the enclosing statement owns the transcript.
pub(crate) struct PresentationProtocol<'a> {
    issuer: &'a IssuerPublicKey,
    request: &'a PresentationRequest,
    pseudonym: G1Affine,
    signature: PoKOfSignatureG1Protocol<Curve>,
    nym: PokDiscreteLogProtocol<G1Affine>,
    ranges: Vec<RangeProtocol>,
}

impl<'a> PresentationProtocol<'a> {
    pub(crate) fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        passport: &'a Passport,
        request: &'a PresentationRequest,
        pseudonym: &G1Affine,
        secret_blinding: Fr,
    ) -> Result<Self, Error> {
        let issuer = passport.issuer();
        let messages = passport.messages();
        let revealed = revealed_messages(issuer, request)?;
        let ranged = ranged_messages(issuer, request)?;
        let mut blindings = BTreeMap::from([(IDX_SECRET, secret_blinding)]);
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
            ranges.push(range);
        }
        Ok(Self {
            issuer,
            request,
            pseudonym: *pseudonym,
            signature,
            nym,
            ranges,
        })
    }

    pub(crate) fn contribute(&self, transcript: &mut MerlinTranscript) -> Result<(), Error> {
        let issuer = self.issuer;
        let request = self.request;
        let pseudonym = &self.pseudonym;
        let revealed = revealed_messages(issuer, request)?;
        let mut bytes = Vec::new();
        self.signature
            .challenge_contribution(&revealed, issuer.signature_params(), &mut bytes)
            .map_err(|_| Error::ProofGeneration)?;
        transcript.append_message(b"signature", &bytes);
        bytes.clear();
        self.nym
            .challenge_contribution(
                &params::community_base(request.community()),
                pseudonym,
                &mut bytes,
            )
            .map_err(|_| Error::ProofGeneration)?;
        transcript.append_message(b"pseudonym", &bytes);
        for (index, range) in ranged_messages(issuer, request)?
            .into_iter()
            .zip(&self.ranges)
        {
            range.contribute(request, index, transcript)?;
        }
        Ok(())
    }

    pub(crate) fn finish(self, challenge: &Fr) -> Result<PresentationProof, Error> {
        Ok(PresentationProof {
            signature: self
                .signature
                .gen_proof(challenge)
                .map_err(|_| Error::ProofGeneration)?,
            pseudonym: self.nym.gen_proof(challenge),
            ranges: self
                .ranges
                .into_iter()
                .map(|r| r.finish(challenge))
                .collect(),
        })
    }
}
