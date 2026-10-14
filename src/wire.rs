//! Byte encoding of all cpsd objects.
//!
//! Every encoding starts with the 4-byte magic `cpsd`, a format version byte
//! and a kind byte, so an object of one kind can never be decoded as another.
//! Integers are big-endian; variable-length fields carry a `u32` length prefix;
//! curve points, scalars and proofs use arkworks' compressed canonical encoding
//! and are validated on decoding (on-curve, prime-order subgroup, canonical
//! scalars). Trailing bytes are rejected.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use zeroize::Zeroizing;

use crate::{Error, GateId, KeyId};

const MAGIC: &[u8; 4] = b"cpsd";

/// Upper bound for any encoded object; bounds allocation and verification work
/// for untrusted input.
pub(crate) const MAX_ENCODED_LEN: usize = 256 * 1024;

#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum Kind {
    IssuerPublicKey = 1,
    IssuerKey = 2,
    IssuanceRequest = 3,
    BlindPassport = 4,
    PendingIssuance = 5,
    Passport = 6,
    HolderSecret = 7,
    PresentationRequest = 8,
    Presentation = 9,
    OpaqueHolder = 10,
    SealedHolder = 11,
    OpaqueHolderWithRootBoard = 12,
    RootBoardState = 13,
    RootBoardPublicKey = 14,
    RootBoardIssuanceContext = 15,
    RootBoardIssuanceRequest = 16,
    BlindRootBoardCredential = 17,
    RootBoardRequest = 18,
    RootBoardPresentation = 19,
    StampPublicKey = 20,
    StampIssuerKey = 21,
    StampIssuanceRequest = 22,
    BlindStamp = 23,
    PendingStamp = 24,
    Stamp = 25,
    StampPresentation = 26,
    OpaqueHolderWithStamps = 27,
    StampState = 28,
}

impl Kind {
    fn version(self) -> u8 {
        match self {
            Self::IssuanceRequest
            | Self::PresentationRequest
            | Self::Presentation
            | Self::OpaqueHolderWithRootBoard
            | Self::RootBoardState
            | Self::RootBoardPublicKey
            | Self::RootBoardIssuanceContext
            | Self::RootBoardIssuanceRequest
            | Self::BlindRootBoardCredential
            | Self::RootBoardRequest
            | Self::RootBoardPresentation => 3,
            // Confirmation stamps are a separate credential family: their own
            // envelope version and kinds, so no passport object ever decodes
            // as a stamp object or the reverse.
            Self::StampPublicKey
            | Self::StampIssuerKey
            | Self::StampIssuanceRequest
            | Self::BlindStamp
            | Self::PendingStamp
            | Self::Stamp
            | Self::StampPresentation
            | Self::OpaqueHolderWithStamps
            | Self::StampState => 4,
            _ => 2,
        }
    }
}

/// Encoder. The buffer is wiped on drop because some kinds contain secrets.
pub(crate) struct Writer {
    buf: Zeroizing<Vec<u8>>,
}

impl Writer {
    pub(crate) fn new(kind: Kind) -> Self {
        // Reserve generously so that secret bytes are not left behind in
        // reallocated (unwiped) buffers for the small secret-bearing kinds.
        Self::with_capacity(kind, 16 * 1024)
    }

    pub(crate) fn with_capacity(kind: Kind, capacity: usize) -> Self {
        let mut buf = Zeroizing::new(Vec::with_capacity(capacity));
        buf.extend_from_slice(MAGIC);
        buf.push(kind.version());
        buf.push(kind as u8);
        Self { buf }
    }

    pub(crate) fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn fixed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub(crate) fn bytes(&mut self, bytes: &[u8]) {
        let len = u32::try_from(bytes.len()).expect("encoded field below 4 GiB");
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(bytes);
    }

    pub(crate) fn ark<T: CanonicalSerialize>(&mut self, value: &T) {
        let len = u32::try_from(value.compressed_size()).expect("encoded field below 4 GiB");
        self.buf.extend_from_slice(&len.to_be_bytes());
        value
            .serialize_compressed(&mut *self.buf)
            .expect("serialising into a Vec cannot fail");
    }

    pub(crate) fn key_id(&mut self, key_id: &KeyId) {
        self.bytes(key_id.as_str().as_bytes());
    }

    pub(crate) fn gate(&mut self, gate: &GateId) {
        self.bytes(gate.as_str().as_bytes());
    }

    /// Finishes an encoding without secret content.
    pub(crate) fn finish_public(mut self) -> Vec<u8> {
        core::mem::take(&mut *self.buf)
    }

    /// Finishes an encoding with secret content; the result wipes itself.
    pub(crate) fn finish_secret(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }
}

/// Decoder over untrusted bytes.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8], kind: Kind) -> Result<Self, Error> {
        if data.len() > MAX_ENCODED_LEN {
            return Err(Error::Decode("oversized input"));
        }
        let mut r = Self { data };
        if r.take(4)? != MAGIC {
            return Err(Error::Decode("magic"));
        }
        if r.take(1)?[0] != kind.version() {
            return Err(Error::Decode("format version"));
        }
        if r.take(1)?[0] != kind as u8 {
            return Err(Error::Decode("object kind"));
        }
        Ok(r)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.data.len() < n {
            return Err(Error::Decode("truncated input"));
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Ok(head)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let b = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(b);
        Ok(a)
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let b = self.take(4)?;
        let len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        self.take(len)
    }

    pub(crate) fn ark<T: CanonicalDeserialize + CanonicalSerialize>(
        &mut self,
        what: &'static str,
    ) -> Result<T, Error> {
        let raw = self.bytes()?;
        let mut field = raw;
        let value = T::deserialize_compressed(&mut field)
            .map_err(crate::error::redact(Error::Decode(what)))?;
        let mut canonical = Zeroizing::new(Vec::with_capacity(raw.len()));
        value
            .serialize_compressed(&mut *canonical)
            .map_err(crate::error::redact(Error::Decode(what)))?;
        crate::error::ensure(
            canonical_encoding(field, &canonical, raw),
            Error::Decode(what),
        )?;
        Ok(value)
    }

    pub(crate) fn key_id(&mut self) -> Result<KeyId, Error> {
        let raw = core::str::from_utf8(self.bytes()?)
            .map_err(crate::error::redact(Error::Decode("key id")))?;
        KeyId::new(raw)
    }

    pub(crate) fn gate(&mut self) -> Result<GateId, Error> {
        let raw = core::str::from_utf8(self.bytes()?)
            .map_err(crate::error::redact(Error::Decode("gate id")))?;
        GateId::new(raw)
    }

    pub(crate) fn finish(self) -> Result<(), Error> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(Error::Decode("trailing bytes"))
        }
    }
}

pub(crate) fn canonical_encoding(remaining: &[u8], canonical: &[u8], raw: &[u8]) -> bool {
    remaining.is_empty() && canonical == raw
}

/// Lower-case hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}
