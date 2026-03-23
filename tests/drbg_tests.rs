//! DRBG test vectors from NIST SP 800-90A

use bsv_rs::primitives::drbg::HmacDrbg;
use serde::Deserialize;

#[derive(Deserialize)]
struct DrbgVector {
    name: String,
    entropy: String,
    nonce: String,
    pers: Option<String>,
    add: Vec<Option<String>>,
    expected: String,
}

fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

#[test]
fn test_drbg_nist_vectors() {
    let vectors_json = include_str!("vectors/drbg.json");
    let vectors: Vec<DrbgVector> = serde_json::from_str(vectors_json).expect("valid JSON");

    assert_eq!(vectors.len(), 15, "Expected 15 DRBG vectors");

    for v in &vectors {
        let entropy = from_hex(&v.entropy);
        let nonce = from_hex(&v.nonce);
        let personalization = v.pers.as_ref().map(|s| from_hex(s)).unwrap_or_default();

        let mut drbg = HmacDrbg::new(&entropy, &nonce, &personalization);

        let expected = from_hex(&v.expected);
        let output_len = expected.len();

        // Generate add.len() times (current vectors have [null, null], so generate twice)
        // Each generate call consumes one entry in the add array
        // The expected output is the result of the LAST generate call
        let mut output = Vec::new();
        for _ in &v.add {
            // Note: additional input is always null in current vectors
            output = drbg.generate(output_len);
        }

        assert_eq!(
            output,
            expected,
            "DRBG vector {} failed\nExpected: {}\nGot: {}",
            v.name,
            v.expected,
            hex::encode(&output)
        );
    }
}

#[test]
fn test_drbg_sha512_variant() {
    let entropy = b"entropy for sha512 test";
    let nonce = b"nonce";

    let mut drbg_256 = HmacDrbg::new(entropy, nonce, &[]);
    let mut drbg_512 = HmacDrbg::new_with_hash(entropy, nonce, &[], true);

    // Different hash should produce different output
    assert_ne!(drbg_256.generate(32), drbg_512.generate(32));
}

#[test]
fn test_drbg_empty_personalization() {
    let entropy = b"test entropy";
    let nonce = b"nonce";

    // Empty personalization should work
    let mut drbg1 = HmacDrbg::new(entropy, nonce, &[]);
    let mut drbg2 = HmacDrbg::new(entropy, nonce, b"");

    // Both should produce the same output since empty slice == empty vec
    assert_eq!(drbg1.generate(32), drbg2.generate(32));
}

#[test]
fn test_drbg_reseed_changes_output() {
    let entropy = b"initial entropy";
    let nonce = b"nonce";

    let mut drbg1 = HmacDrbg::new(entropy, nonce, &[]);
    let mut drbg2 = HmacDrbg::new(entropy, nonce, &[]);

    // Generate once to advance state
    let _ = drbg1.generate(32);
    let _ = drbg2.generate(32);

    // Reseed one of them
    drbg1.reseed(b"new entropy", &[]);

    // Now they should produce different outputs
    assert_ne!(drbg1.generate(32), drbg2.generate(32));
}

#[test]
fn test_drbg_output_length() {
    let mut drbg = HmacDrbg::new(b"entropy", b"nonce", &[]);

    // Test various output lengths
    assert_eq!(drbg.generate(1).len(), 1);
    assert_eq!(drbg.generate(16).len(), 16);
    assert_eq!(drbg.generate(32).len(), 32);
    assert_eq!(drbg.generate(64).len(), 64);
    assert_eq!(drbg.generate(128).len(), 128);
    assert_eq!(drbg.generate(256).len(), 256);
}

#[test]
fn test_drbg_determinism() {
    // Same inputs should always produce same outputs
    let mut outputs = Vec::new();
    for _ in 0..3 {
        let mut drbg = HmacDrbg::new(b"fixed entropy", b"fixed nonce", b"fixed pers");
        let output = drbg.generate(32);
        assert_eq!(output.len(), 32);
        outputs.push(output);
    }
    // All outputs should be identical (deterministic)
    assert_eq!(outputs[0], outputs[1]);
    assert_eq!(outputs[1], outputs[2]);
}
