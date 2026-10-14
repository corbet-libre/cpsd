//! Private holder encoding and maintained AEAD; no storage or key derivation.
use super::OpaqueHolder;
use crate::rand::{CryptoRng, RngCore};
use crate::root_board::state::RootBoardState;
use crate::stamp::StampState;
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
        // Without root-board or stamp state the original kind-10 plaintext
        // stays byte-identical, so older readers and stored blobs keep working.
        // Root-board state alone keeps the kind-12 layout. Any stamp state
        // selects kind 27, which always carries the root field (possibly
        // empty) and then the stamp state; no reader guesses a format. The
        // stamp state never contains the secret, which is stored once, first.
        let root = (!self.root_board.is_empty()).then(|| self.root_board.to_bytes());
        let stamps = (!self.stamps.is_empty()).then(|| self.stamps.to_bytes());
        let root_field = match (&root, &stamps) {
            (Some(root), _) => Some(root.as_slice()),
            (None, Some(_)) => Some(&[][..]),
            (None, None) => None,
        };
        let stamps = stamps.as_deref().map(Vec::as_slice);
        let length = 6
            + 12
            + secret.len()
            + pending.len()
            + passport.len()
            + root_field.map_or(0, |root| 4 + root.len())
            + stamps.map_or(0, |stamps| 4 + stamps.len());
        if length > MAX_ENCODED_LEN - 50 {
            return Err(Error::InvalidSealedHolder);
        }
        // Allocate once at its exact final size; secret bytes never survive a
        // Vec reallocation. Each original codec and this aggregate wipe on drop.
        let kind = match (root_field, stamps) {
            (_, Some(_)) => Kind::OpaqueHolderWithStamps,
            (Some(_), None) => Kind::OpaqueHolderWithRootBoard,
            (None, None) => Kind::OpaqueHolder,
        };
        let mut writer = Writer::with_capacity(kind, length);
        writer.bytes(&secret);
        writer.bytes(pending);
        writer.bytes(passport);
        if let Some(root) = root_field {
            writer.bytes(root);
        }
        if let Some(stamps) = stamps {
            writer.bytes(stamps);
        }
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
        // The explicit kind byte selects the declared codec; anything else is
        // handed to the original reader, which rejects unknown kinds.
        let kind = match plaintext.get(5) {
            Some(&byte) if byte == Kind::OpaqueHolderWithRootBoard as u8 => {
                Kind::OpaqueHolderWithRootBoard
            }
            Some(&byte) if byte == Kind::OpaqueHolderWithStamps as u8 => {
                Kind::OpaqueHolderWithStamps
            }
            _ => Kind::OpaqueHolder,
        };
        let mut reader = Reader::new(&plaintext, kind)?;
        let secret = HolderSecret::from_bytes(reader.bytes()?)?;
        let pending = reader.bytes()?;
        let passport = reader.bytes()?;
        let (root, stamps) = match kind {
            Kind::OpaqueHolderWithRootBoard => (Some(reader.bytes()?), None),
            Kind::OpaqueHolderWithStamps => {
                let root = reader.bytes()?;
                ((!root.is_empty()).then_some(root), Some(reader.bytes()?))
            }
            _ => (None, None),
        };
        reader.finish()?;
        let pending = (!pending.is_empty())
            .then(|| PendingIssuance::from_bytes(pending))
            .transpose()?;
        let passport = (!passport.is_empty())
            .then(|| Passport::from_bytes(passport))
            .transpose()?;
        let root_board = match root {
            Some(root) => RootBoardState::from_bytes(root, &secret)?,
            None => RootBoardState::default(),
        };
        // Every retained stamp must verify under this exact secret.
        let stamps = match stamps {
            Some(stamps) => StampState::from_bytes(stamps, &secret)?,
            None => StampState::default(),
        };
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
            root_board,
            stamps,
            sealing: Some(Arc::clone(sealing)),
        })
    }
}
