//! Private holder encoding and maintained AEAD; no storage or key derivation.
use super::OpaqueHolder;
use crate::rand::{CryptoRng, RngCore};
use crate::wire::{Kind, MAX_ENCODED_LEN, Reader, Writer};
use crate::{Error, HolderSecret, Passport, PendingIssuance};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

pub(super) struct HolderSeal {
    cipher: XChaCha20Poly1305,
    aad: Vec<u8>,
}

#[cfg(test)]
mod tests;

/// Bounded authenticated ciphertext suitable for the original wallet Store.
/// Decoding this container proves no authenticity; only an existing holder's
/// immutable private sealing capability can open it. No private codec is exposed.
pub struct SealedHolder(Vec<u8>);

impl SealedHolder {
    /// Parse the bounded versioned ciphertext container, without decrypting it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_ENCODED_LEN {
            return Err(Error::InvalidSealedHolder);
        }
        let sealed = Self(bytes.to_vec());
        sealed.parts()?;
        Ok(sealed)
    }

    /// Original sealed bytes. These contain ciphertext, never an unwrapped holder.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn parts(&self) -> Result<([u8; 24], &[u8]), Error> {
        let mut reader = Reader::new(&self.0, Kind::SealedHolder)?;
        let nonce = reader.fixed()?;
        let ciphertext = reader.bytes()?;
        if ciphertext.len() < 16 {
            return Err(Error::InvalidSealedHolder);
        }
        reader.finish()?;
        Ok((nonce, ciphertext))
    }
}

impl OpaqueHolder {
    /// Consume a dedicated identity seed and wallet sealing key inside Keys.
    /// Both inputs are wiped on every return. The original deterministic identity
    /// recipe is unchanged. Keys owns purpose derivation and the canonical wallet
    /// context; CPSD never accepts a root/passkey key or derives a new purpose.
    ///
    /// The binding is immutable: this engine exposes no key getter or rekey API.
    /// A holder created with `from_seed` cannot later acquire a caller-chosen key.
    ///
    /// ```compile_fail
    /// # let holder = cpsd::OpaqueHolder::from_seed(&mut [7; 32]);
    /// holder.rekey(&mut [0; 32]);
    /// ```
    pub fn from_seed_and_sealing_key(
        seed: &mut [u8; 32],
        key: &mut [u8; 32],
        wallet_context: &[u8],
    ) -> Result<Self, Error> {
        let seed_copy = Zeroizing::new(*seed);
        let key_copy = Zeroizing::new(*key);
        seed.zeroize();
        key.zeroize();
        if wallet_context.is_empty() || wallet_context.len() > 4096 {
            return Err(Error::InvalidSealedHolder);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(key_copy.as_slice())
            .map_err(|_| Error::InvalidSealedHolder)?;
        let mut aad = b"cpsd.opaque-holder.v1\0".to_vec();
        aad.extend_from_slice(wallet_context);
        let mut seed_copy = seed_copy;
        let mut holder = Self::from_seed(&mut seed_copy);
        holder.sealing = Some(Arc::new(HolderSeal { cipher, aad }));
        Ok(holder)
    }

    /// Seal the current original codecs with the key bound at construction.
    /// There is deliberately no key or context parameter. This proves no durable
    /// commit; Wallet must use the original Store transaction and matching receipt.
    pub fn seal<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<SealedHolder, Error> {
        let sealing = self
            .sealing
            .as_ref()
            .ok_or(Error::HolderSealingUnavailable)?;
        let secret = self.secret.to_bytes();
        let pending = self.pending.as_ref().map(PendingIssuance::to_bytes);
        let passport = self.passport.as_ref().map(Passport::to_bytes);
        let pending = pending.as_deref().map(Vec::as_slice).unwrap_or_default();
        let passport = passport.as_deref().map(Vec::as_slice).unwrap_or_default();
        let length = 6 + 12 + secret.len() + pending.len() + passport.len();
        if length > MAX_ENCODED_LEN - 50 {
            return Err(Error::InvalidSealedHolder);
        }
        // The original non-root aggregate and all nested owner codecs remain v2.
        // Allocate exactly once so secret bytes do not survive reallocation.
        let mut writer = Writer::with_capacity(Kind::OpaqueHolder, length);
        writer.bytes(&secret);
        writer.bytes(pending);
        writer.bytes(passport);
        let plaintext = writer.finish_secret();
        let mut nonce = [0; 24];
        rng.fill_bytes(&mut nonce);
        let ciphertext = sealing
            .cipher
            .encrypt(
                &XNonce::try_from(nonce.as_slice()).map_err(|_| Error::InvalidSealedHolder)?,
                Payload {
                    msg: &plaintext,
                    aad: &sealing.aad,
                },
            )
            .map_err(|_| Error::InvalidSealedHolder)?;
        let mut writer = Writer::new(Kind::SealedHolder);
        writer.fixed(&nonce);
        writer.bytes(&ciphertext);
        Ok(SealedHolder(writer.finish_public()))
    }

    /// Restore into a separate nonexporting candidate under this exact private
    /// key, context and seeded identity. The existing engine remains unchanged
    /// on every error. Wallet alone adopts a durable candidate; authentic old
    /// ciphertext is not an anti-rollback receipt or current authority.
    pub fn restored(&self, sealed: &SealedHolder) -> Result<Self, Error> {
        let sealing = self
            .sealing
            .as_ref()
            .ok_or(Error::HolderSealingUnavailable)?;
        let (nonce, ciphertext) = sealed.parts()?;
        let plaintext = Zeroizing::new(
            sealing
                .cipher
                .decrypt(
                    &XNonce::try_from(nonce.as_slice()).map_err(|_| Error::InvalidSealedHolder)?,
                    Payload {
                        msg: ciphertext,
                        aad: &sealing.aad,
                    },
                )
                .map_err(|_| Error::InvalidSealedHolder)?,
        );
        // This owner implements only the original non-root v2 codec. An
        // authenticated extended/root-board frame is refused, never stripped.
        let mut reader = Reader::new(&plaintext, Kind::OpaqueHolder)?;
        let secret = HolderSecret::from_bytes(reader.bytes()?)?;
        let pending = reader.bytes()?;
        let passport = reader.bytes()?;
        reader.finish()?;
        let pending = (!pending.is_empty())
            .then(|| PendingIssuance::from_bytes(pending))
            .transpose()?;
        let passport = (!passport.is_empty())
            .then(|| Passport::from_bytes(passport))
            .transpose()?;
        if secret.0 != self.secret.0
            || pending
                .as_ref()
                .is_some_and(|value| !value.belongs_to(&secret))
            || passport
                .as_ref()
                .is_some_and(|value| value.secret.0 != secret.0)
        {
            return Err(Error::InvalidSealedHolder);
        }
        Ok(Self {
            secret,
            pending,
            passport,
            sealing: Some(Arc::clone(sealing)),
        })
    }
}
