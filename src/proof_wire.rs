//! Bounded v3 wire shapes, checked before upstream vector allocation.
//! Scalar and group validation and exact canonical encoding remain upstream.

use crate::{
    Error, MAX_GATES,
    proof::{IssuanceProof, PresentationProof, RangeProof},
    wire::{Reader, Writer},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

impl Writer {
    pub(crate) fn proof(&mut self, proof: &PresentationProof) {
        self.ark(&proof.signature);
        self.ark(&proof.pseudonym);
        self.u16(proof.ranges.len() as u16);
        for range in &proof.ranges {
            self.ark(range);
        }
    }
}

impl Reader<'_> {
    pub(crate) fn issuance_proof(&mut self) -> Result<IssuanceProof, Error> {
        let raw = self.bytes()?;
        if raw.len() != 192 {
            return Err(Error::Decode("issuance proof shape"));
        }
        decode(raw)
    }

    pub(crate) fn proof(&mut self) -> Result<PresentationProof, Error> {
        let raw = self.bytes()?;
        signature_shape(raw)?;
        let signature = decode(raw)?;
        let raw = self.bytes()?;
        if raw.len() != 80 {
            return Err(Error::Decode("pseudonym proof shape"));
        }
        let pseudonym = decode(raw)?;
        let count = self.u16()? as usize;
        if count > 1 + MAX_GATES {
            return Err(Error::Decode("proof count"));
        }
        let mut ranges = Vec::with_capacity(count);
        for _ in 0..count {
            let raw = self.bytes()?;
            range_shape(raw)?;
            ranges.push(decode::<RangeProof>(raw)?);
        }
        Ok(PresentationProof {
            signature,
            pseudonym,
            ranges,
        })
    }
}

pub(crate) fn decode<T: CanonicalDeserialize + CanonicalSerialize>(raw: &[u8]) -> Result<T, Error> {
    let mut field = raw;
    let value = T::deserialize_compressed(&mut field).map_err(|_| Error::Decode("proof"))?;
    let mut canonical = Vec::with_capacity(raw.len());
    value
        .serialize_compressed(&mut canonical)
        .map_err(|_| Error::Decode("proof"))?;
    if !field.is_empty() || canonical != raw {
        return Err(Error::Decode("noncanonical proof"));
    }
    Ok(value)
}

/// Check hostile in-memory values as strictly as the untrusted decoder.
pub(crate) fn well_formed(proof: &PresentationProof, ranges: usize) -> bool {
    if proof.ranges.len() != ranges || ranges > 1 + MAX_GATES {
        return false;
    }
    let mut raw = Vec::new();
    if proof.signature.serialize_compressed(&mut raw).is_err() || signature_shape(&raw).is_err() {
        return false;
    }
    proof.ranges.iter().all(|range| {
        raw.clear();
        range.serialize_compressed(&mut raw).is_ok() && range_shape(&raw).is_ok()
    })
}

fn signature_shape(raw: &[u8]) -> Result<(), Error> {
    signature_shape_with(raw, 4..=5 + MAX_GATES)
}

/// A complete BBS+ proof of knowledge whose second Schnorr response count lies
/// in `responses` (hidden messages plus two).
pub(crate) fn signature_shape_with(
    raw: &[u8],
    responses: core::ops::RangeInclusive<usize>,
) -> Result<(), Error> {
    let mut c = Shape(raw);
    c.skip(5 * 48 + 2 * 32)?;
    c.literal(&[1])?; // Only complete responses; no optional partial map.
    let count = c.length()?;
    if !responses.contains(&count) {
        return Err(Error::Decode("signature responses"));
    }
    c.skip(count * 32)?;
    c.literal(&[0])?;
    c.finish()
}

fn range_shape(raw: &[u8]) -> Result<(), Error> {
    let mut c = Shape(raw);
    c.vector(2, 48)?;
    c.literal(&2u16.to_le_bytes())?; // Fixed base 2 and 64-bit setup.
    c.skip(4 * 48)?;
    c.vector(7, 48)?;
    c.vector(7, 48)?;
    c.vector(1, 32)?;
    c.vector(1, 32)?;
    c.skip(2 * (48 + 2 * 32))?; // Two full Pedersen proofs.
    c.finish()
}

struct Shape<'a>(&'a [u8]);
impl Shape<'_> {
    fn finish(self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Decode("proof shape"))
        }
    }
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
