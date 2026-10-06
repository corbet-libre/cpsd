//! Narrow wire boundary for the exact Dock proof shapes used by cpsd.
//!
//! Dock's general proof decoder accepts many unrelated protocols. Its range
//! verifier also assumes particular vector dimensions. Check those dimensions
//! before decoding; leave all scalar/group validation and crypto to Dock/ark.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use proof_system::{proof::Proof, statement_proof::StatementProof};

use crate::{
    Error, MAX_GATES,
    params::Curve,
    wire::{Reader, Writer},
};

impl Writer {
    pub(crate) fn proof(&mut self, proof: &Proof<Curve>) {
        self.u16(proof.statement_proofs.len() as u16);
        for statement in &proof.statement_proofs {
            self.ark(statement);
        }
    }
}

impl Reader<'_> {
    pub(crate) fn proof(&mut self, presentation: bool) -> Result<Proof<Curve>, Error> {
        let count = self.u16()? as usize;
        if (presentation && !(2..=3 + MAX_GATES).contains(&count)) || (!presentation && count != 2)
        {
            return Err(Error::Decode("proof count"));
        }
        let mut statements = Vec::with_capacity(count);
        for index in 0..count {
            let raw = self.bytes()?;
            check_shape(raw, presentation, index)?;
            let mut field = raw;
            let statement = StatementProof::<Curve>::deserialize_compressed(&mut field)
                .map_err(crate::error::redact(Error::Decode("proof")))?;
            // Also reject duplicate or out-of-order map entries, which ark's
            // generic BTreeMap decoder otherwise normalizes silently.
            let mut canonical = Vec::new();
            statement
                .serialize_compressed(&mut canonical)
                .map_err(crate::error::redact(Error::Decode("proof")))?;
            crate::error::ensure(
                crate::wire::canonical_encoding(field, &canonical, raw),
                Error::Decode("noncanonical proof"),
            )?;
            statements.push(statement);
        }
        Ok(Proof {
            statement_proofs: statements,
            aggregated_groth16: None,
            aggregated_legogroth16: None,
        })
    }
}

/// Validate in-memory proofs too, including adversarial tests bypassing the wire.
pub(crate) fn well_formed(proof: &Proof<Curve>, count: usize, presentation: bool) -> bool {
    proof.statement_proofs.len() == count
        && proof.aggregated_groth16.is_none()
        && proof.aggregated_legogroth16.is_none()
        && proof
            .statement_proofs
            .iter()
            .enumerate()
            .all(|(i, statement)| {
                let mut raw = Vec::new();
                statement
                    .serialize_compressed(&mut raw)
                    .is_ok_and(|()| check_shape(&raw, presentation, i).is_ok())
            })
}

fn check_shape(raw: &[u8], presentation: bool, index: usize) -> Result<(), Error> {
    let mut c = Shape(raw);
    if index == 0 && presentation {
        c.literal(&[0])?; // PoKBBSSignatureG1
        c.skip(5 * 48 + 2 * 32)?;
        c.literal(&[1])?; // full Schnorr responses; no partial alternative
        let count = c.length()?;
        if !(4..=5 + MAX_GATES).contains(&count) {
            return Err(Error::Decode("signature responses"));
        }
        c.skip(count * 32)?;
        c.literal(&[0])?;
    } else if index == 0 {
        c.literal(&[3])?; // PedersenCommitment, blinding and secret
        c.skip(48)?;
        c.vector(2, 32)?;
    } else if index == 1 {
        c.literal(&[32])?; // PedersenCommitmentPartial, response supplied by statement 0
        c.skip(48)?;
        c.integer(0)?;
        c.integer(1)?;
    } else {
        c.literal(&[12])?; // BoundCheckBpp
        c.vector(2, 48)?; // transformed lower/upper commitments
        c.literal(&2u16.to_le_bytes())?; // base 2, fixed 64-bit setup
        c.skip(4 * 48)?;
        // log2(128 generators) folds; one final scalar per argument.
        c.vector(7, 48)?;
        c.vector(7, 48)?;
        c.vector(1, 32)?;
        c.vector(1, 32)?;
        for _ in 0..2 {
            c.skip(48)?;
            c.integer(1)?; // response map has only blinding at index 1
            c.integer(1)?;
            c.skip(32)?;
            c.integer(2)?;
        }
    }
    if !c.0.is_empty() {
        return Err(Error::Decode("proof shape"));
    }
    Ok(())
}

struct Shape<'a>(&'a [u8]);
impl Shape<'_> {
    fn skip(&mut self, n: usize) -> Result<(), Error> {
        self.0 = self.0.get(n..).ok_or(Error::Decode("proof shape"))?;
        Ok(())
    }
    fn literal(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if !self.0.starts_with(bytes) {
            return Err(Error::Decode("proof shape"));
        }
        self.skip(bytes.len())
    }
    fn integer(&mut self, n: u64) -> Result<(), Error> {
        self.literal(&n.to_le_bytes())
    }
    fn length(&mut self) -> Result<usize, Error> {
        let bytes: [u8; 8] = self
            .0
            .first_chunk::<8>()
            .copied()
            .ok_or(Error::Decode("proof shape"))?;
        self.skip(8)?;
        usize::try_from(u64::from_le_bytes(bytes))
            .map_err(crate::error::redact(Error::Decode("proof shape")))
    }
    fn vector(&mut self, count: usize, size: usize) -> Result<(), Error> {
        self.integer(count as u64)?;
        self.skip(count * size)
    }
}
