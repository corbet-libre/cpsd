//! Maintained authenticated encryption around original owner state, not an
//! accepting verifier. Extended state stays unsupported and cannot be dropped.
use super::*;
use crate::rand::{SeedableRng, rngs::StdRng};
use crate::{IssuanceChallenge, IssuerKey, KeyId};

fn holder(seed: u8) -> OpaqueHolder {
    OpaqueHolder::from_seed_and_sealing_key(&mut [seed; 32], &mut [8; 32], b"wallet-a").unwrap()
}

fn encrypted(holder: &OpaqueHolder, plaintext: &[u8]) -> SealedHolder {
    let sealing = holder.sealing.as_ref().unwrap();
    let nonce = [19; 24];
    let ciphertext = sealing
        .cipher
        .encrypt(
            &XNonce::try_from(nonce.as_slice()).unwrap(),
            Payload {
                msg: plaintext,
                aad: &sealing.aad,
            },
        )
        .unwrap();
    // Confirm the refusal input actually authenticates under the original
    // immutable key/context. This is not a corrupt-ciphertext scenario.
    assert_eq!(
        sealing
            .cipher
            .decrypt(
                &XNonce::try_from(nonce.as_slice()).unwrap(),
                Payload {
                    msg: &ciphertext,
                    aad: &sealing.aad
                },
            )
            .unwrap(),
        plaintext
    );
    let mut writer = Writer::new(Kind::SealedHolder);
    writer.fixed(&nonce);
    writer.bytes(&ciphertext);
    SealedHolder::from_bytes(&writer.finish_public()).unwrap()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn authenticated_malformed_root_state_refuses_without_replacing_the_original_holder() {
    let holder = holder(7);
    let original = holder.issuer_tag();
    let mut writer = Writer::new(Kind::OpaqueHolder);
    writer.bytes(&holder.secret.to_bytes());
    writer.bytes(&[]);
    writer.bytes(&[]);
    let mut plaintext = writer.finish_secret();
    // The original extended owner declares format3/kind12 and an additional
    // root-board state field. Authentication alone cannot make its deliberately
    // malformed contents a valid original root credential or pending opening.
    plaintext[4] = 3;
    plaintext[5] = 12;
    let root_state = b"retained malformed root-board state";
    plaintext.extend_from_slice(&(root_state.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(root_state);
    let extended = encrypted(&holder, &plaintext);
    assert!(holder.restored(&extended).is_err());
    assert_eq!(holder.issuer_tag(), original);
    assert!(holder.attributes().is_none());
    // Even an attempted format downgrade must not make an extra owner field
    // disappear: the original complete-input decoder still refuses it.
    plaintext[4] = 2;
    plaintext[5] = Kind::OpaqueHolder as u8;
    assert!(holder.restored(&encrypted(&holder, &plaintext)).is_err());
    assert_eq!(holder.issuer_tag(), original);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn authenticated_foreign_pending_opening_cannot_replace_the_seeded_identity() {
    let mut rng = StdRng::seed_from_u64(506);
    let issuer = IssuerKey::generate(&mut rng, KeyId::new("issuer").unwrap(), vec![]).unwrap();
    let challenge = IssuanceChallenge::generate(&mut rng);
    let original = holder(7);
    let mut foreign = holder(9);
    foreign
        .begin_issuance(&mut rng, issuer.public_key(), &challenge)
        .unwrap();
    let mut writer = Writer::new(Kind::OpaqueHolder);
    writer.bytes(&original.secret.to_bytes());
    writer.bytes(&foreign.pending.as_ref().unwrap().to_bytes());
    writer.bytes(&[]);
    let sealed = encrypted(&original, &writer.finish_secret());
    assert!(matches!(
        original.restored(&sealed),
        Err(Error::InvalidSealedHolder)
    ));
    assert!(original.pending.is_none());
    assert!(original.attributes().is_none());
}
