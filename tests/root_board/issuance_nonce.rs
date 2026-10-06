//! Replay protection uses the original signed holder flow and original stores.
//! These tests establish nonce authority only, never a source admin role.
use super::*;

fn attempt(
    w: &mut World,
    holder: &mut OpaqueHolder,
    context: &RootBoardIssuanceContext,
) -> RootBoardIssuanceRequest {
    holder.cancel_root_board_issuance();
    let (root, source) = w.signed_context(context);
    holder
        .begin_root_board_issuance(
            &mut w.rng,
            &w.expected,
            &root,
            &w.expected_source,
            &source,
            NOW,
        )
        .unwrap()
}

// The original public codec ends in the fixed 32-byte nonce. Keep that nonce
// while substituting a separately canonical source request or root descriptor.
fn same_nonce(context: RootBoardIssuanceContext, nonce: [u8; 32]) -> RootBoardIssuanceContext {
    let mut bytes = context.to_bytes();
    let tail = bytes.len() - 32;
    bytes[tail..].copy_from_slice(&nonce);
    RootBoardIssuanceContext::from_bytes(&bytes).unwrap()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn complete_context_and_live_nonce_are_both_required_before_release() {
    let mut w = world();
    let mut holder = w.holder();
    w.passport(&mut holder);
    let context = w.context();
    let request = attempt(&mut w, &mut holder, &context);
    let keys = [w.global.public_key().clone()];
    let store = MemoryStore::new(w.root_community.clone(), 2).unwrap();
    assert!(matches!(
        verify_stored_root_board_issuance(&store, &keys, &context, &request, NOW).await,
        Err(Error::InvalidChallenge)
    ));
    register_root_board_issuance(&store, &context)
        .await
        .unwrap();
    assert_eq!(
        register_root_board_issuance(&store, &context).await,
        Err(Error::ChallengeConflict)
    );
    let changed_source = same_nonce(w.context(), context.nonce());
    let changed_root = RootBoardPublicKey::from_authenticated_beacon(
        w.root_key.public_key().clone(),
        w.root_community.clone(),
        w.descriptor.policy_epoch() + 1,
        0,
    )
    .unwrap();
    let changed_root = same_nonce(
        RootBoardIssuanceContext::new(&mut w.rng, context.source_request().clone(), changed_root)
            .unwrap(),
        context.nonce(),
    );
    for changed in [&changed_source, &changed_root] {
        assert!(matches!(
            verify_stored_root_board_issuance(&store, &keys, changed, &request, NOW).await,
            Err(Error::InvalidChallenge)
        ));
        // Even genuine proofs for another context cannot consume this slot.
        let other = attempt(&mut w, &mut holder, changed);
        assert!(
            verify_stored_root_board_issuance(&store, &keys, &context, &other, NOW)
                .await
                .is_err()
        );
        let verified = verify_root_board_issuance(&keys, changed, &other, NOW).unwrap();
        assert!(matches!(
            consume_root_board_issuance(&store, verified, NOW).await,
            Err(Error::InvalidChallenge)
        ));
    }
    assert!(matches!(
        verify_stored_root_board_issuance(&store, &[], &context, &request, NOW).await,
        Err(Error::UnknownKey)
    ));
    assert!(matches!(
        verify_stored_root_board_issuance(
            &store,
            &[keys[0].clone(), w.root_key.public_key().clone()],
            &context,
            &request,
            NOW,
        )
        .await,
        Err(Error::InvalidRootBoard)
    ));
    let request = attempt(&mut w, &mut holder, &context);
    // Holding or dropping a proof capability performs no nonce mutation: a
    // service refusing a source role here leaves the actual slot available.
    drop(
        verify_stored_root_board_issuance(&store, &keys, &context, &request, NOW)
            .await
            .unwrap(),
    );
    let verified = verify_stored_root_board_issuance(&store, &keys, &context, &request, NOW)
        .await
        .unwrap();
    assert_eq!(verified.source_pseudonym(), holder.pseudonym(&w.source));
    let consumed = consume_root_board_issuance(&store, verified, NOW)
        .await
        .unwrap();
    let blind = consumed
        .issue(&mut w.rng, &w.root_key, &w.descriptor, NOW)
        .unwrap();
    holder.finish_root_board_issuance(&blind).unwrap();
    let (joint, signed) = w.request();
    let proof = holder
        .present_root_board(&mut w.rng, &w.expected, &signed, NOW)
        .unwrap();
    assert_eq!(
        verify_root_board(&keys, &joint, &proof, NOW).unwrap(),
        holder.pseudonym(&w.root_community)
    );
    let duplicate = verify_root_board_issuance(&keys, &context, &request, NOW).unwrap();
    assert!(matches!(
        consume_root_board_issuance(&store, duplicate, NOW).await,
        Err(Error::InvalidChallenge)
    ));
    assert!(matches!(
        verify_stored_root_board_issuance(&store, &keys, &context, &request, NOW).await,
        Err(Error::InvalidChallenge)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn scope_capacity_expiry_and_failed_signing_do_not_restore_a_consumed_slot() {
    let mut w = world();
    let mut holder = w.holder();
    w.passport(&mut holder);
    let keys = [w.global.public_key().clone()];
    let store = MemoryStore::new(w.root_community.clone(), 1).unwrap();
    let foreign = MemoryStore::new(w.source.clone(), 1).unwrap();
    let context = w.context();
    let request = attempt(&mut w, &mut holder, &context);
    assert_eq!(
        register_root_board_issuance(&foreign, &context).await,
        Err(Error::InvalidChallenge)
    );
    assert!(matches!(
        verify_stored_root_board_issuance(&foreign, &keys, &context, &request, NOW).await,
        Err(Error::InvalidChallenge)
    ));
    let verified = verify_root_board_issuance(&keys, &context, &request, NOW).unwrap();
    assert!(matches!(
        consume_root_board_issuance(&foreign, verified, NOW).await,
        Err(Error::InvalidChallenge)
    ));
    register_root_board_issuance(&store, &context)
        .await
        .unwrap();
    let next = w.context();
    assert_eq!(
        register_root_board_issuance(&store, &next).await,
        Err(Error::StorageCapacity)
    );
    assert!(matches!(
        verify_stored_root_board_issuance(&store, &keys, &context, &request, NOW + 1).await,
        Err(Error::InvalidChallenge)
    ));
    let verified = verify_root_board_issuance(&keys, &context, &request, NOW).unwrap();
    assert!(matches!(
        consume_root_board_issuance(&store, verified, NOW + 1).await,
        Err(Error::InvalidChallenge)
    ));
    assert_eq!(store.prune(NOW).await.unwrap(), 0);
    assert_eq!(store.prune(NOW + 1).await.unwrap(), 1);
    // A new service-created context is needed after consumption or pruning.
    for failure in 0..4 {
        let context = w.context();
        let request = attempt(&mut w, &mut holder, &context);
        register_root_board_issuance(&store, &context)
            .await
            .unwrap();
        let verified = verify_stored_root_board_issuance(&store, &keys, &context, &request, NOW)
            .await
            .unwrap();
        let consumed = consume_root_board_issuance(&store, verified, NOW)
            .await
            .unwrap();
        if failure == 3 {
            drop(consumed);
        } else {
            let (issuer, now) = match failure {
                0 => (&w.global, NOW),
                1 => (&w.root_key, NOW + 1),
                _ => (&w.root_key, NOW - 1),
            };
            assert!(
                consumed
                    .issue(&mut w.rng, issuer, &w.descriptor, now)
                    .is_err()
            );
        }
        assert!(matches!(
            verify_stored_root_board_issuance(&store, &keys, &context, &request, NOW).await,
            Err(Error::InvalidChallenge)
        ));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn admission_and_global_issuance_slots_cannot_authorize_root_issuance() {
    let mut w = world();
    let mut holder = w.holder();
    w.passport(&mut holder);
    let blind = w.issue(&mut holder);
    holder.finish_root_board_issuance(&blind).unwrap();
    let keys = [w.global.public_key().clone()];
    let store = MemoryStore::new(w.root_community.clone(), 4).unwrap();
    let verifier = Verifier::new(store.clone(), keys.to_vec()).unwrap();
    // Ordinary presentation: the exact nonce exists under its original purpose.
    let plain = verifier
        .request_for_epoch(&mut w.rng, 7, [w.phone.clone()], NOW, EXPIRY)
        .await
        .unwrap();
    let context = same_nonce(w.context(), plain.challenge());
    let request = attempt(&mut w, &mut holder, &context);
    assert!(matches!(
        verify_stored_root_board_issuance(&store, &keys, &context, &request, NOW).await,
        Err(Error::InvalidChallenge)
    ));
    let signed = sign(&mut w.signer, &plain.to_bytes(), NOW);
    let proof = holder
        .present(&mut w.rng, &w.expected, &signed, NOW)
        .unwrap();
    verifier
        .verify(&mut w.rng, &plain, &proof, 7, NOW)
        .await
        .unwrap();
    // Root admission uses its own complete joint request digest.
    let (joint, signed) = w.request();
    verifier
        .register_root_board_request(joint.clone())
        .await
        .unwrap();
    let context = same_nonce(w.context(), joint.global_request().challenge());
    let request = attempt(&mut w, &mut holder, &context);
    let verified = verify_root_board_issuance(&keys, &context, &request, NOW).unwrap();
    assert!(matches!(
        consume_root_board_issuance(&store, verified, NOW).await,
        Err(Error::InvalidChallenge)
    ));
    let proof = holder
        .present_root_board(&mut w.rng, &w.expected, &signed, NOW)
        .unwrap();
    verifier
        .verify_root_board(&joint, &proof, 7, NOW)
        .await
        .unwrap();
    // The separate global-issuance purpose cannot authorize a root signature.
    let auth = AuthenticatedIssuance::new([1; 32], [2; 32]);
    let nonce = issuance_challenge(&mut w.rng, &store, w.global.public_key(), &auth, NOW)
        .await
        .unwrap();
    let context = same_nonce(w.context(), nonce.to_bytes());
    let request = attempt(&mut w, &mut holder, &context);
    let verified = verify_root_board_issuance(&keys, &context, &request, NOW).unwrap();
    assert!(matches!(
        consume_root_board_issuance(&store, verified, NOW).await,
        Err(Error::InvalidChallenge)
    ));
    let secret = HolderSecret::generate(&mut w.rng);
    let (request, pending) =
        request_issue(&mut w.rng, &secret, w.global.public_key(), &nonce).unwrap();
    let attributes = PassportAttributes::new(EXPIRY, 7).with_gate(w.phone.clone(), EXPIRY);
    let blind = issue_blind_once(
        &mut w.rng,
        &store,
        &w.global,
        &auth,
        &request,
        &nonce,
        &attributes,
        NOW,
    )
    .await
    .unwrap();
    pending.finish(&blind).unwrap();
}

#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_sql_consumption_races_once_and_survives_reopen() {
    let mut w = world();
    let mut holder = w.holder();
    w.passport(&mut holder);
    let context = w.context();
    let request = attempt(&mut w, &mut holder, &context);
    let keys = [w.global.public_key().clone()];
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "file://{}",
        directory.path().join("root-issuance.db").display()
    );
    let first = crlt::Db::open(crlt::Config::new(&url, "")).await.unwrap();
    first
        .migrate(&[crlt::Migration::new(
            1,
            "challenges only",
            storage::libsql::SCHEMA,
        )])
        .await
        .unwrap();
    let second = crlt::Db::open(crlt::Config::new(&url, "")).await.unwrap();
    let make =
        |db: &crlt::Db| storage::libsql::LibsqlStore::new(db, w.root_community.clone(), 2).unwrap();
    let a = make(&first);
    let b = make(&second);
    register_root_board_issuance(&a, &context).await.unwrap();
    let scoped = first.community("cpsd/726f6f74").unwrap();
    let rows = scoped
        .query(
            "SELECT nonce, binding, expires FROM cpsd_challenges",
            crlt::params![],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get_value(0).unwrap(),
        &crlt::Value::Blob(context.nonce().to_vec())
    );
    let crlt::Value::Blob(digest) = rows[0].get_value(1).unwrap() else {
        panic!("only a digest belongs in challenge binding");
    };
    assert_eq!(digest.len(), 32);
    assert_eq!(
        rows[0].get_value(2).unwrap(),
        &crlt::Value::Integer(NOW as i64)
    );
    drop((rows, scoped));
    // Both independent handles verify before either competes to consume.
    let proof_a = verify_stored_root_board_issuance(&a, &keys, &context, &request, NOW)
        .await
        .unwrap();
    let proof_b = verify_stored_root_board_issuance(&b, &keys, &context, &request, NOW)
        .await
        .unwrap();
    let (x, y) = tokio::join!(
        consume_root_board_issuance(&a, proof_a, NOW),
        consume_root_board_issuance(&b, proof_b, NOW),
    );
    assert_eq!(usize::from(x.is_ok()) + usize::from(y.is_ok()), 1);
    assert!(matches!(
        x.as_ref().err().or(y.as_ref().err()),
        Some(Error::InvalidChallenge)
    ));
    let consumed = x.or(y).unwrap();
    let blind = consumed
        .issue(&mut w.rng, &w.root_key, &w.descriptor, NOW)
        .unwrap();
    holder.finish_root_board_issuance(&blind).unwrap();
    drop((a, b, first, second));
    let reopened = crlt::Db::open(crlt::Config::new(&url, "")).await.unwrap();
    let store = make(&reopened);
    assert!(matches!(
        verify_stored_root_board_issuance(&store, &keys, &context, &request, NOW).await,
        Err(Error::InvalidChallenge)
    ));
    let verified = verify_root_board_issuance(&keys, &context, &request, NOW).unwrap();
    assert!(matches!(
        consume_root_board_issuance(&store, verified, NOW).await,
        Err(Error::InvalidChallenge)
    ));
    // No issuer continuity schema or source identity table was needed.
    store.check_indexes().await.unwrap();
}

#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
mod interrupted {
    use super::*;
    use std::sync::Arc;

    // Only the return transport is faulted, after the original SQL mutation.
    // No proof, signature, role or consumed capability is fabricated.
    struct AfterCommit {
        store: storage::libsql::LibsqlStore,
        observed: Arc<tokio::sync::Notify>,
        lose_reply: bool,
    }

    impl ChallengeStore for AfterCommit {
        fn community(&self) -> &CommunityId {
            self.store.community()
        }
        async fn reserve(&self, record: ChallengeRecord) -> Result<bool, Error> {
            self.store.reserve(record).await
        }
        async fn matches(
            &self,
            nonce: [u8; 32],
            binding: [u8; 32],
            now: Timestamp,
        ) -> Result<bool, Error> {
            self.store.matches(nonce, binding, now).await
        }
        async fn consume(
            &self,
            nonce: [u8; 32],
            binding: [u8; 32],
            now: Timestamp,
        ) -> Result<bool, Error> {
            assert!(self.store.consume(nonce, binding, now).await?);
            self.observed.notify_one();
            if self.lose_reply {
                Err(Error::Storage)
            } else {
                std::future::pending().await
            }
        }
        async fn prune(&self, now: Timestamp) -> Result<u64, Error> {
            self.store.prune(now).await
        }
    }

    #[tokio::test]
    async fn lost_or_cancelled_sql_acknowledgement_never_releases_a_capability() {
        let mut w = world();
        let mut holder = w.holder();
        w.passport(&mut holder);
        let keys = [w.global.public_key().clone()];
        let directory = tempfile::tempdir().unwrap();
        let url = format!("file://{}", directory.path().join("fault.db").display());
        let db = crlt::Db::open(crlt::Config::new(&url, "")).await.unwrap();
        let store = storage::libsql::LibsqlStore::new(&db, w.root_community.clone(), 2).unwrap();
        let context = w.context();
        let request = attempt(&mut w, &mut holder, &context);
        assert_eq!(
            register_root_board_issuance(&store, &context).await,
            Err(Error::Storage)
        );
        assert!(matches!(
            verify_stored_root_board_issuance(&store, &keys, &context, &request, NOW).await,
            Err(Error::Storage)
        ));
        let verified = verify_root_board_issuance(&keys, &context, &request, NOW).unwrap();
        assert!(matches!(
            consume_root_board_issuance(&store, verified, NOW).await,
            Err(Error::Storage)
        ));
        db.migrate(&[crlt::Migration::new(
            1,
            "challenges only",
            storage::libsql::SCHEMA,
        )])
        .await
        .unwrap();
        for lose_reply in [true, false] {
            let context = w.context();
            let request = attempt(&mut w, &mut holder, &context);
            register_root_board_issuance(&store, &context)
                .await
                .unwrap();
            let verified =
                verify_stored_root_board_issuance(&store, &keys, &context, &request, NOW)
                    .await
                    .unwrap();
            let fault = AfterCommit {
                store: store.clone(),
                observed: Arc::default(),
                lose_reply,
            };
            if lose_reply {
                assert!(matches!(
                    consume_root_board_issuance(&fault, verified, NOW).await,
                    Err(Error::Storage)
                ));
            } else {
                let future = consume_root_board_issuance(&fault, verified, NOW);
                tokio::pin!(future);
                tokio::select! {
                    result = &mut future => panic!("withheld acknowledgement returned: {}", result.is_ok()),
                    () = fault.observed.notified() => {}
                }
                // Scope exit drops the real pending consumer and its proof.
            }
            assert!(matches!(
                verify_stored_root_board_issuance(&store, &keys, &context, &request, NOW).await,
                Err(Error::InvalidChallenge)
            ));
        }
    }
}
