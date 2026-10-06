//! Hostile compositions made with real upstream proofs, not forged verdicts.

use super::*;
use ark_bls12_381::Fr;
use ark_ec::CurveGroup;
use ark_std::UniformRand;
use bbs_plus::proof::PoKOfSignatureG1Protocol;
use bulletproofs_plus_plus::prelude::ProofArbitraryRange;
use dock_crypto_utils::{
    signature::MessageOrBlinding,
    transcript::{MerlinTranscript, Transcript},
};
use schnorr_pok::discrete_log::{PokDiscreteLogProtocol, PokPedersenCommitmentProtocol};

#[test]
fn valid_range_for_different_signed_expiry_cannot_be_substituted() {
    use crate::params::{IDX_SECRET, IDX_VALID_UNTIL};
    let mut rng = rng();
    let issuer = key(&mut rng, "range-equality");
    let secret = HolderSecret::generate(&mut rng);
    let expired = issue(&mut rng, &issuer, &secret, PassportAttributes::new(900, 7));
    let request = PresentationRequest::with_challenge(community(), 7, [], 1000, [23; 32]).unwrap();
    let messages = expired.messages();
    let revealed = crate::presentation::revealed_messages(issuer.public_key(), &request).unwrap();
    let blind_secret = Fr::rand(&mut rng);
    let blind_expiry = Fr::rand(&mut rng);
    let signature = PoKOfSignatureG1Protocol::init(
        &mut rng,
        &expired.signature,
        issuer.public_key().signature_params(),
        messages.iter().enumerate().map(|(i, m)| {
            if revealed.contains_key(&i) {
                MessageOrBlinding::RevealMessage(m)
            } else if i == IDX_SECRET || i == IDX_VALID_UNTIL {
                MessageOrBlinding::BlindMessageWithConcreteBlinding {
                    message: m,
                    blinding: if i == IDX_SECRET {
                        blind_secret
                    } else {
                        blind_expiry
                    },
                }
            } else {
                MessageOrBlinding::BlindMessageRandomly(m)
            }
        }),
    )
    .unwrap();
    let base = crate::params::community_base(request.community());
    let point = (base * secret.0).into_affine();
    let nym = PokDiscreteLogProtocol::init(secret.0, blind_secret, &base);
    let params = crate::params::range_proof_params();
    let randomness = [Fr::rand(&mut rng), Fr::rand(&mut rng)];
    let mut inner = MerlinTranscript::new(b"cpsd/v3/range");
    inner.append_message(b"issuer", &issuer.public_key().to_bytes());
    inner.append_message(b"request", &request.to_bytes());
    inner.append_message(b"message-index", &(IDX_VALID_UNTIL as u64).to_be_bytes());
    let mut inner_verify = inner.clone();
    // This range really proves 1200 is valid, but the passport signed 900.
    let range = ProofArbitraryRange::new(
        &mut rng,
        64,
        vec![(1200, 1000, TIME_LIMIT)],
        randomness.to_vec(),
        params.clone(),
        &mut inner,
    )
    .unwrap();
    range.verify(64, params, &mut inner_verify).unwrap();
    let (g, h) = params.get_pedersen_commitment_key();
    let lower = PokPedersenCommitmentProtocol::init(
        Fr::from(1200u64),
        blind_expiry,
        &g,
        randomness[0],
        Fr::rand(&mut rng),
        &h,
    );
    let upper = PokPedersenCommitmentProtocol::init(
        Fr::from(1200u64),
        blind_expiry,
        &g,
        -randomness[1],
        Fr::rand(&mut rng),
        &h,
    );
    let mut transcript = crate::proof::presentation_transcript(issuer.public_key(), &request);
    let mut bytes = Vec::new();
    signature
        .challenge_contribution(
            &revealed,
            issuer.public_key().signature_params(),
            &mut bytes,
        )
        .unwrap();
    transcript.append_message(b"signature", &bytes);
    bytes.clear();
    nym.challenge_contribution(&base, &point, &mut bytes)
        .unwrap();
    transcript.append_message(b"pseudonym", &bytes);
    crate::proof::range_contribution(
        &range,
        &lower.t,
        &upper.t,
        &request,
        IDX_VALID_UNTIL,
        &mut transcript,
    )
    .unwrap();
    let challenge = transcript.challenge_scalar::<Fr>(b"challenge");
    let proof = crate::proof::PresentationProof {
        signature: signature.gen_proof(&challenge).unwrap(),
        pseudonym: nym.gen_proof(&challenge),
        ranges: vec![crate::proof::RangeProof {
            range,
            lower: lower.gen_proof(&challenge),
            upper: upper.gen_proof(&challenge),
        }],
    };
    proof
        .signature
        .verify(
            &revealed,
            &challenge,
            issuer.public_key().bbs_public_key().clone(),
            issuer.public_key().signature_params().clone(),
        )
        .unwrap();
    assert!(proof.pseudonym.verify(&point, &base, &challenge));
    let (lo, hi) = proof.ranges[0]
        .range
        .get_commitments_to_values(vec![(1000, TIME_LIMIT)], params)
        .unwrap()[0];
    assert!(proof.ranges[0].lower.verify(&lo, &g, &h, &challenge));
    assert!(proof.ranges[0].upper.verify(&hi, &g, &h, &challenge));
    assert!(crate::proof_wire::well_formed(&proof, 1));
    assert_eq!(
        proof.verify(issuer.public_key(), &request, &point),
        Err(Error::InvalidProof)
    );
}

#[test]
fn v3_issuance_tag_cannot_use_an_unrelated_secret() {
    let mut rng = rng();
    let issuer = key(&mut rng, "tag-equality");
    let holder = HolderSecret::generate(&mut rng);
    let unrelated = HolderSecret::generate(&mut rng);
    let nonce = IssuanceChallenge::generate(&mut rng);
    let params = issuer.public_key().signature_params();
    let blinding = Fr::rand(&mut rng);
    let commitment = params
        .commit_to_messages([(crate::params::IDX_SECRET, &holder.0)], &blinding)
        .unwrap();
    let base = crate::params::issuer_tag_base();
    let tag = (base * unrelated.0).into_affine();
    let shared = Fr::rand(&mut rng);
    let opening = PokPedersenCommitmentProtocol::init(
        blinding,
        Fr::rand(&mut rng),
        &params.h_0,
        holder.0,
        shared,
        &params.h[crate::params::IDX_SECRET],
    );
    let tag_protocol = PokDiscreteLogProtocol::init(unrelated.0, shared, &base);
    let mut transcript = crate::proof::issuance_transcript(issuer.public_key(), &nonce);
    let mut bytes = Vec::new();
    opening
        .challenge_contribution(&params.h_0, &params.h[0], &commitment, &mut bytes)
        .unwrap();
    transcript.append_message(b"opening", &bytes);
    bytes.clear();
    tag_protocol
        .challenge_contribution(&base, &tag, &mut bytes)
        .unwrap();
    transcript.append_message(b"tag", &bytes);
    let challenge = transcript.challenge_scalar::<Fr>(b"challenge");
    let proof = crate::proof::IssuanceProof {
        opening: opening.gen_proof(&challenge),
        tag: tag_protocol.gen_proof(&challenge),
    };
    assert!(
        proof
            .opening
            .verify(&commitment, &params.h_0, &params.h[0], &challenge)
    );
    assert!(proof.tag.verify(&tag, &base, &challenge));
    assert_eq!(
        proof.verify(issuer.public_key(), &nonce, &commitment, &tag),
        Err(Error::InvalidIssuanceRequest)
    );
}
