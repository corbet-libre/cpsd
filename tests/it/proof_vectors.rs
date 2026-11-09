//! Identical deterministic public proof vectors executed natively and in Chrome.

use crate::common::TestPresentation;
use blake2::{Blake2b512, Digest};
use cpsd::*;
use rand::{SeedableRng, rngs::StdRng};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

fn receipt(name: &str, bytes: &[u8]) {
    let hash = Blake2b512::digest(bytes);
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::console_log!("CPSD_VECTOR {name} {hex}");
    #[cfg(not(target_arch = "wasm32"))]
    println!("CPSD_VECTOR {name} {hex}");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn v3_proofs_preserve_identity_and_explicitly_reject_v2_exchange() {
    let mut rng = StdRng::seed_from_u64(0xc053_0003);
    let gate = GateId::new("phone").unwrap();
    let issuer =
        IssuerKey::generate(&mut rng, KeyId::new("vectors").unwrap(), vec![gate.clone()]).unwrap();
    let holder = HolderSecret::generate(&mut rng);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let (request, pending) =
        request_issue(&mut rng, &holder, issuer.public_key(), &challenge).unwrap();
    let issuance = request.to_bytes();
    assert_eq!(issuance[4], 3);
    receipt("issuance-v3", &issuance);
    let mut legacy = issuance.clone();
    legacy[4] = 2;
    assert!(IssuanceRequest::from_bytes(&legacy).is_err());
    let blind = issuer
        .issue_blind(
            &mut rng,
            &IssuanceRequest::from_bytes(&issuance).unwrap(),
            &challenge,
            &PassportAttributes::new(1500, 7).with_gate(gate.clone(), 1500),
        )
        .unwrap();
    assert_eq!(blind.to_bytes()[4], 2);
    assert_eq!(pending.to_bytes()[4], 2);
    let passport = pending.finish(&blind).unwrap();
    assert_eq!(passport.to_bytes()[4], 2);
    for shared in [false, true] {
        let request = PresentationRequest::with_challenge(
            CommunityId::new(b"community-a").unwrap(),
            7,
            [gate.clone()],
            1000,
            [31; 32],
        )
        .unwrap();
        let request = if shared {
            request.with_epoch_expiry(1500).unwrap()
        } else {
            request
        };
        let mut legacy = request.to_bytes();
        assert_eq!(legacy[4], 3);
        legacy[4] = 2;
        assert!(PresentationRequest::from_bytes(&legacy).is_err());
        let proof = passport.present_trusted(&mut rng, &request).unwrap();
        let bytes = proof.to_bytes();
        receipt(
            if shared {
                "shared-v3"
            } else {
                "independent-v3"
            },
            &bytes,
        );
        let decoded = Presentation::from_bytes(&bytes).unwrap();
        assert_eq!(
            verify(&mut rng, &[issuer.public_key().clone()], &request, &decoded).unwrap(),
            holder.pseudonym(request.community())
        );
        let mut legacy = bytes;
        legacy[4] = 2;
        assert!(Presentation::from_bytes(&legacy).is_err());
    }
}
