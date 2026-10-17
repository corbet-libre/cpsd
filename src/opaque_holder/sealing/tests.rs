//! Maintained authenticated encryption around original owner state, not an
//! accepting verifier. Extended state stays unsupported and cannot be dropped.
use super::*;
use crate::rand::{SeedableRng, rngs::StdRng};
use crate::{
    ActionKind, CommunityFingerprint, CommunityId, IssuanceChallenge, IssuerKey, KeyId,
    PayloadDigest, StampAction, StampIssuerKey, StampParams, StampSalt, StampScope, verify_stamp,
};

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

fn decrypted(holder: &OpaqueHolder, sealed: &SealedHolder) -> Zeroizing<Vec<u8>> {
    let sealing = holder.sealing.as_ref().unwrap();
    let (nonce, ciphertext) = sealed.parts().unwrap();
    Zeroizing::new(
        sealing
            .cipher
            .decrypt(
                &XNonce::try_from(nonce.as_slice()).unwrap(),
                Payload {
                    msg: ciphertext,
                    aad: &sealing.aad,
                },
            )
            .unwrap(),
    )
}

fn approval(n: u8) -> (StampScope, StampAction) {
    (
        StampScope::new(
            CommunityId::new(format!("community-{n}")).unwrap(),
            CommunityFingerprint::from_bytes([n; 32]),
        ),
        StampAction::new(
            ActionKind::new("lineage.pair").unwrap(),
            PayloadDigest::from_bytes([n; 32]),
            StampSalt::from_bytes([n; 32]),
        ),
    )
}

fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn stamp_state_survives_a_restart_and_never_repeats_the_secret() {
    let mut rng = StdRng::seed_from_u64(507);
    let params = StampParams::new(3_600).unwrap();
    let key = StampIssuerKey::generate(&mut rng, KeyId::new("stamp").unwrap(), &params).unwrap();
    let now = 3_600_200;
    let mut original = holder(7);
    let plain = decrypted(&original, &original.seal(&mut rng).unwrap());
    assert_eq!(
        plain[5],
        Kind::OpaqueHolder as u8,
        "no stamp state: kind 10"
    );
    let nonce = IssuanceChallenge::generate(&mut rng);
    let request = original
        .begin_stamp(&mut rng, key.public_key(), &nonce, &[approval(1)], now)
        .unwrap();
    // Restart after the user verification, before the wallet's answer.
    let sealed = original.seal(&mut rng).unwrap();
    let plain = decrypted(&original, &sealed);
    assert_eq!(plain[5], Kind::OpaqueHolderWithStamps as u8);
    let mut restored = original.restored(&sealed).unwrap();
    assert_eq!(restored.pending_stamp_key(), Some(key.public_key()));
    // The restarted device sends the SAME request bytes again (the wallet answers them
    // again without a second confirmation); only for the actions they carry.
    assert_eq!(
        restored.pending_stamp_request(&[approval(1)]),
        Some(request.to_bytes())
    );
    assert_eq!(restored.pending_stamp_request(&[approval(2)]), None);
    assert_eq!(restored.pending_stamp_request(&[approval(1), approval(2)]), None);
    assert_eq!(restored.pending_stamp_request(&[]), None);
    let blind = key.issue_blind(&mut rng, &request, &nonce, 1, now).unwrap();
    restored.finish_stamp(&blind, now).unwrap();
    assert_eq!(restored.pending_stamp_key(), None);
    assert_eq!(restored.pending_stamp_request(&[approval(1)]), None);
    let second = IssuanceChallenge::generate(&mut rng);
    restored
        .begin_stamp(&mut rng, key.public_key(), &second, &[approval(2)], now)
        .unwrap();
    // The sealed plaintext holds the secret exactly once, in its own field;
    // the pending request and the stamp carry none of it.
    let sealed = restored.seal(&mut rng).unwrap();
    let plain = decrypted(&restored, &sealed);
    let mut secret = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&restored.secret.0, &mut secret)
        .unwrap();
    assert_eq!(occurrences(&plain, &secret), 1);
    let stamps = restored.stamps.to_bytes();
    assert_eq!(occurrences(&stamps, &secret), 0);
    assert!(occurrences(&plain, &stamps) == 1);
    // After the restart the stamp still presents, the second request is still
    // pending, and both verify under this holder only.
    let again = restored.restored(&sealed).unwrap();
    assert_eq!(again.pending_stamp_key(), Some(key.public_key()));
    let (scope, action) = approval(1);
    assert!(again.stamp_covers(&scope, &action, now));
    let shown = again.present_stamp(&mut rng, &scope, &action, now).unwrap();
    let verified = verify_stamp(
        &[key.public_key().clone()],
        &params,
        &scope,
        1,
        &action,
        &shown,
        now,
    )
    .unwrap();
    assert_eq!(verified.pseudonym(), &original.pseudonym(scope.community()));
    // Another identity under the same sealing key cannot adopt it.
    assert!(matches!(
        holder(9).restored(&sealed),
        Err(Error::InvalidSealedHolder)
    ));
    // A cancelled request and no stamps fall back to the original kind 10.
    let mut empty = holder(7);
    empty
        .begin_stamp(&mut rng, key.public_key(), &nonce, &[approval(3)], now)
        .unwrap();
    empty.cancel_stamp();
    let plain = decrypted(&empty, &empty.seal(&mut rng).unwrap());
    assert_eq!(plain[5], Kind::OpaqueHolder as u8);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn authenticated_foreign_or_empty_stamp_state_is_refused() {
    let mut rng = StdRng::seed_from_u64(508);
    let params = StampParams::new(3_600).unwrap();
    let key = StampIssuerKey::generate(&mut rng, KeyId::new("stamp").unwrap(), &params).unwrap();
    let now = 3_600_200;
    let original = holder(7);
    let mut foreign = holder(9);
    let nonce = IssuanceChallenge::generate(&mut rng);
    let request = foreign
        .begin_stamp(&mut rng, key.public_key(), &nonce, &[approval(1)], now)
        .unwrap();
    let blind = key.issue_blind(&mut rng, &request, &nonce, 1, now).unwrap();
    foreign.finish_stamp(&blind, now).unwrap();
    let with_stamps = |stamps: &[u8], root: &[u8]| {
        let mut writer = Writer::new(Kind::OpaqueHolderWithStamps);
        writer.bytes(&original.secret.to_bytes());
        writer.bytes(&[]);
        writer.bytes(&[]);
        writer.bytes(root);
        writer.bytes(stamps);
        encrypted(&original, &writer.finish_secret())
    };
    // Another holder's stamp never verifies under this secret.
    assert!(matches!(
        original.restored(&with_stamps(&foreign.stamps.to_bytes(), &[])),
        Err(Error::InvalidSignature)
    ));
    // An empty stamp section or a malformed root field is not canonical.
    let empty = crate::stamp::StampState::default().to_bytes();
    assert!(original.restored(&with_stamps(&empty, &[])).is_err());
    assert!(
        original
            .restored(&with_stamps(&foreign.stamps.to_bytes(), b"root"))
            .is_err()
    );
    assert!(original.stamps.is_empty());
}
