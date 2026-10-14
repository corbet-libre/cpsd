//! Confirmation stamps through the public custody path only: the opaque
//! holder requests, unblinds, retains and presents; the wallet issues once;
//! the community verifies and records. No raw secret appears anywhere.

#![cfg(not(target_arch = "wasm32"))]

use cpsd::*;
use rand::{SeedableRng, rngs::StdRng};

/// 200 s into hour cohort 1000; stamps issued now expire at 3_607_200.
const NOW: Timestamp = 3_600_200;
const EXPIRES: Timestamp = 3_607_200;
const EPOCH: u64 = 4;

fn params() -> StampParams {
    StampParams::new(3_600).unwrap()
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

/// Requests and installs one stamp covering `approvals`, issued at `now`.
fn stamp(
    rng: &mut StdRng,
    holder: &mut OpaqueHolder,
    key: &StampIssuerKey,
    approvals: &[(StampScope, StampAction)],
    now: Timestamp,
) {
    let nonce = IssuanceChallenge::generate(rng);
    let request = holder
        .begin_stamp(rng, key.public_key(), &nonce, approvals, now)
        .unwrap();
    let blind = key.issue_blind(rng, &request, &nonce, EPOCH, now).unwrap();
    holder.finish_stamp(&blind, now).unwrap();
}

#[tokio::test]
async fn one_confirmation_approves_sixteen_communities_through_the_opaque_holder() {
    let mut rng = StdRng::seed_from_u64(40);
    let key = StampIssuerKey::generate(&mut rng, KeyId::new("stamp").unwrap(), &params()).unwrap();
    let mut holder = OpaqueHolder::from_seed(&mut [40; 32]);
    let wallet = MemoryStore::new(CommunityId::new("wallet").unwrap(), 10).unwrap();
    let member = AuthenticatedStampIssuance::new([1; 32], [2; 32], holder.issuer_tag());
    let approvals: Vec<_> = (0..STAMP_SLOTS as u8).map(approval).collect();
    let nonce = stamp_issuance_challenge(&mut rng, &wallet, key.public_key(), &member, NOW + 60)
        .await
        .unwrap();
    let request = holder
        .begin_stamp(&mut rng, key.public_key(), &nonce, &approvals, NOW)
        .unwrap();
    // The device confirms exactly this request; the wallet checks it.
    let confirmed = member
        .clone()
        .with_user_verification(request.confirmation_challenge(&nonce));
    let blind = issue_stamp_once(
        &mut rng, &wallet, &key, &confirmed, &request, &nonce, EPOCH, NOW,
    )
    .await
    .unwrap();
    assert_eq!(blind.expires(), EXPIRES);
    holder.finish_stamp(&blind, NOW).unwrap();
    for (scope, action) in &approvals {
        assert!(holder.stamp_covers(scope, action, NOW));
        let shown = holder.present_stamp(&mut rng, scope, action, NOW).unwrap();
        let store = MemoryStore::new(scope.community().clone(), 10).unwrap();
        let ledger = StampLedger::new(
            store,
            *scope.fingerprint(),
            vec![key.public_key().clone()],
            params(),
        )
        .unwrap();
        let verified = ledger.accept(action, &shown, EPOCH, NOW).await.unwrap();
        assert_eq!(verified.pseudonym(), &holder.pseudonym(scope.community()));
        // Presenting again yields a fresh proof of the same, recorded digest.
        let again = holder.present_stamp(&mut rng, scope, action, NOW).unwrap();
        assert_ne!(again.to_bytes(), shown.to_bytes());
        assert_eq!(
            ledger.accept(action, &again, EPOCH, NOW).await.err(),
            Some(Error::StampReplayed)
        );
    }
}

#[test]
fn holder_refuses_concurrent_missing_foreign_and_expired_stamp_operations() {
    let mut rng = StdRng::seed_from_u64(41);
    let key = StampIssuerKey::generate(&mut rng, KeyId::new("stamp").unwrap(), &params()).unwrap();
    let other_key =
        StampIssuerKey::generate(&mut rng, KeyId::new("other").unwrap(), &params()).unwrap();
    let mut holder = OpaqueHolder::from_seed(&mut [41; 32]);
    let (scope, action) = approval(1);
    let nonce = IssuanceChallenge::generate(&mut rng);
    // Nothing pending, nothing retained.
    let elsewhere = OpaqueHolder::from_seed(&mut [9; 32])
        .begin_stamp(&mut rng, key.public_key(), &nonce, &[approval(1)], NOW)
        .unwrap();
    let unrequested = key
        .issue_blind(&mut rng, &elsewhere, &nonce, EPOCH, NOW)
        .unwrap();
    assert_eq!(
        holder.finish_stamp(&unrequested, NOW).err(),
        Some(Error::NoPendingIssuance)
    );
    assert_eq!(
        holder.present_stamp(&mut rng, &scope, &action, NOW).err(),
        Some(Error::StampDigestMissing)
    );
    assert!(!holder.stamp_covers(&scope, &action, NOW));
    // Digest list bounds: none, more than sixteen, or one action twice.
    let seventeen: Vec<_> = (0..=STAMP_SLOTS as u8).map(approval).collect();
    for bad in [&[][..], &seventeen[..], &[approval(2), approval(2)][..]] {
        assert_eq!(
            holder
                .begin_stamp(&mut rng, key.public_key(), &nonce, bad, NOW)
                .err(),
            Some(Error::InvalidStamp)
        );
    }
    assert_eq!(holder.pending_stamp_key(), None);
    // One pending request at a time; cancel replaces it.
    let request = holder
        .begin_stamp(
            &mut rng,
            other_key.public_key(),
            &nonce,
            &[approval(1)],
            NOW,
        )
        .unwrap();
    assert_eq!(
        holder
            .begin_stamp(&mut rng, key.public_key(), &nonce, &[approval(1)], NOW)
            .err(),
        Some(Error::IssuancePending)
    );
    assert_eq!(holder.pending_stamp_key(), Some(other_key.public_key()));
    holder.cancel_stamp();
    assert_eq!(holder.pending_stamp_key(), None);
    // An answer from another key consumes the attempt and installs nothing.
    let request_again = holder
        .begin_stamp(&mut rng, key.public_key(), &nonce, &[approval(1)], NOW)
        .unwrap();
    let foreign = other_key
        .issue_blind(&mut rng, &request, &nonce, EPOCH, NOW)
        .unwrap();
    assert_eq!(
        holder.finish_stamp(&foreign, NOW).err(),
        Some(Error::KeyMismatch)
    );
    assert_eq!(holder.pending_stamp_key(), None);
    assert!(!holder.stamp_covers(&scope, &action, NOW));
    // The real answer to the earlier request no longer has an opening.
    let late = key
        .issue_blind(&mut rng, &request_again, &nonce, EPOCH, NOW)
        .unwrap();
    assert_eq!(
        holder.finish_stamp(&late, NOW).err(),
        Some(Error::NoPendingIssuance)
    );
    // A retained stamp expires with its cohort.
    stamp(&mut rng, &mut holder, &key, &[approval(1)], NOW);
    assert!(holder.stamp_covers(&scope, &action, EXPIRES - 1));
    holder
        .present_stamp(&mut rng, &scope, &action, EXPIRES - 1)
        .unwrap();
    assert!(!holder.stamp_covers(&scope, &action, EXPIRES));
    assert_eq!(
        holder
            .present_stamp(&mut rng, &scope, &action, EXPIRES)
            .err(),
        Some(Error::StampExpired)
    );
    assert_eq!(
        holder.present_stamp(&mut rng, &scope, &action, 0).err(),
        Some(Error::InvalidTimestamp)
    );
    // A foreign action is not covered even in the right community.
    let (_, unrelated) = approval(7);
    assert_eq!(
        holder
            .present_stamp(&mut rng, &scope, &unrelated, NOW)
            .err(),
        Some(Error::StampDigestMissing)
    );
}

#[test]
fn holder_retains_at_most_eight_stamps_and_drops_expired_ones_first() {
    let mut rng = StdRng::seed_from_u64(42);
    let key = StampIssuerKey::generate(&mut rng, KeyId::new("stamp").unwrap(), &params()).unwrap();
    let mut holder = OpaqueHolder::from_seed(&mut [42; 32]);
    // An early stamp from the previous cohort (expires at EXPIRES - 3600).
    let early = NOW - 3_600;
    stamp(&mut rng, &mut holder, &key, &[approval(100)], early);
    for n in 0..8u8 {
        stamp(&mut rng, &mut holder, &key, &[approval(n)], NOW);
    }
    // Nine issued, eight kept: the one that expires first went.
    let (scope, action) = approval(100);
    assert!(!holder.stamp_covers(&scope, &action, NOW));
    for n in 0..8u8 {
        let (scope, action) = approval(n);
        assert!(holder.stamp_covers(&scope, &action, NOW), "stamp {n} kept");
    }
    // Once a cohort has passed, a new stamp drops every expired one.
    let next = EXPIRES + 10;
    stamp(&mut rng, &mut holder, &key, &[approval(50)], next);
    for n in 0..8u8 {
        let (scope, action) = approval(n);
        assert_eq!(
            holder.present_stamp(&mut rng, &scope, &action, next).err(),
            Some(Error::StampDigestMissing)
        );
    }
    let (scope, action) = approval(50);
    holder
        .present_stamp(&mut rng, &scope, &action, next)
        .unwrap();
}
