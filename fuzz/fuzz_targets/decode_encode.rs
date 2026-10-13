#![no_main]
use cpsd::*;
use libfuzzer_sys::fuzz_target;

// A successful decode must preserve the exact input, including nested ark
// points, scalars, maps and signatures. This also asserts no decoder panics.
fuzz_target!(|data: &[u8]| {
    macro_rules! identity {
        ($decode:path, $encode:ident) => {
            if let Ok(value) = $decode(data) {
                assert_eq!(value.$encode().as_slice(), data);
            }
        };
    }
    if let Ok(nonce) = <[u8; 32]>::try_from(data) {
        assert_eq!(IssuanceChallenge::from_bytes(nonce).to_bytes(), nonce);
    }
    identity!(IssuerPublicKey::from_bytes, to_bytes);
    identity!(IssuerKey::from_secret_bytes, to_secret_bytes);
    identity!(HolderSecret::from_bytes, to_bytes);
    identity!(PendingIssuance::from_bytes, to_bytes);
    identity!(IssuanceRequest::from_bytes, to_bytes);
    identity!(BlindPassport::from_bytes, to_bytes);
    identity!(Passport::from_bytes, to_bytes);
    identity!(PresentationRequest::from_bytes, to_bytes);
    identity!(Presentation::from_bytes, to_bytes);
    identity!(Pseudonym::from_bytes, to_bytes);
    identity!(RootBoardPublicKey::from_bytes, to_bytes);
    identity!(RootBoardIssuanceContext::from_bytes, to_bytes);
    identity!(RootBoardIssuanceRequest::from_bytes, to_bytes);
    identity!(BlindRootBoardCredential::from_bytes, to_bytes);
    identity!(RootBoardRequest::from_bytes, to_bytes);
    identity!(RootBoardPresentation::from_bytes, to_bytes);
});
