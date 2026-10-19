//! HKDF-SHA256 and HKDF-SHA512 against Project Wycheproof.
//!
//! The vector files are `testvectors_v1/hkdf_sha256_test.json` (86 tests) and
//! `testvectors_v1/hkdf_sha512_test.json` (83 tests) of C2SP/wycheproof at
//! commit e0df04e0c033f2d25c5051dd06230336c7822358 (Apache-2.0), copied byte
//! for byte under `tests/vectors/wycheproof/`; their sha256 is pinned below so
//! an edited file fails here. Every `valid` test's OKM is checked; every
//! `invalid` test (`SizeTooLarge`, L = 255 * HashLen + 1) must be refused.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::hash::{hkdf_sha256, hkdf_sha512, sha256};
use bsv_rs::Result;
use std::path::Path;

type Hkdf = fn(&[u8], &[u8], &[u8], &mut [u8]) -> Result<()>;

/// Runs every test of one file; returns (valid checked, invalid refused).
fn run(file: &str, pinned_sha256: &str, total: usize, hkdf: Hkdf) -> (usize, usize) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/wycheproof")
        .join(file);
    let bytes = std::fs::read(&path).expect("the Wycheproof file");
    assert_eq!(
        hex::encode(sha256(&bytes)),
        pinned_sha256,
        "{file} is the pinned copy"
    );
    let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(doc["numberOfTests"].as_u64().unwrap() as usize, total);
    let (mut valid, mut invalid) = (0, 0);
    for group in doc["testGroups"].as_array().unwrap() {
        for t in group["tests"].as_array().unwrap() {
            let id = t["tcId"].as_u64().unwrap();
            let field = |k: &str| hex::decode(t[k].as_str().unwrap()).unwrap();
            let size = t["size"].as_u64().unwrap() as usize;
            let mut okm = vec![0u8; size];
            let got = hkdf(&field("salt"), &field("ikm"), &field("info"), &mut okm);
            match t["result"].as_str().unwrap() {
                "valid" => {
                    got.unwrap_or_else(|e| panic!("{file} tcId {id}: {e}"));
                    assert_eq!(
                        hex::encode(&okm),
                        t["okm"].as_str().unwrap(),
                        "{file} tcId {id}"
                    );
                    valid += 1;
                }
                "invalid" => {
                    assert!(got.is_err(), "{file} tcId {id} must be refused");
                    invalid += 1;
                }
                other => panic!("{file} tcId {id}: result {other}"),
            }
        }
    }
    assert_eq!(valid + invalid, total, "{file}: every test ran");
    (valid, invalid)
}

#[test]
fn hkdf_sha256_passes_every_wycheproof_test() {
    let counts = run(
        "hkdf_sha256_test.json",
        "bb2b462a38b251cb52a2aede706d6d4b62b26864f4e80c95497507ddb07c5f1e",
        86,
        hkdf_sha256,
    );
    assert_eq!(counts, (83, 3));
}

#[test]
fn hkdf_sha512_passes_every_wycheproof_test() {
    let counts = run(
        "hkdf_sha512_test.json",
        "bb9a21f4e86041caf5d7792b030349f8ff289087f195b2fbc0fc0afc39deca6f",
        83,
        hkdf_sha512,
    );
    assert_eq!(counts, (80, 3));
}
