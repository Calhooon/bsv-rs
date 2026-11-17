//! `core.rs`'s unit tests, moved beside it for the file's line ceiling (#843d9); the module is still `tests`.
#![cfg(test)]

use super::*;

// RFC 6238 Appendix B test vectors
// Secret keys for different algorithms (from the RFC)
const SHA1_SECRET: &[u8] = b"12345678901234567890";
const SHA256_SECRET: &[u8] = b"12345678901234567890123456789012";
const SHA512_SECRET: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

// RFC 6238 test vectors (8-digit codes)
#[test]
fn test_rfc6238_sha1_time_59() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha1,
        timestamp: Some(59),
        ..Default::default()
    };
    let code = Totp::generate(SHA1_SECRET, Some(options));
    assert_eq!(code, "94287082");
}

#[test]
fn test_rfc6238_sha256_time_59() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha256,
        timestamp: Some(59),
        ..Default::default()
    };
    let code = Totp::generate(SHA256_SECRET, Some(options));
    assert_eq!(code, "46119246");
}

#[test]
fn test_rfc6238_sha512_time_59() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha512,
        timestamp: Some(59),
        ..Default::default()
    };
    let code = Totp::generate(SHA512_SECRET, Some(options));
    assert_eq!(code, "90693936");
}

#[test]
fn test_rfc6238_sha1_time_1111111109() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha1,
        timestamp: Some(1111111109),
        ..Default::default()
    };
    let code = Totp::generate(SHA1_SECRET, Some(options));
    assert_eq!(code, "07081804");
}

#[test]
fn test_rfc6238_sha256_time_1111111109() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha256,
        timestamp: Some(1111111109),
        ..Default::default()
    };
    let code = Totp::generate(SHA256_SECRET, Some(options));
    assert_eq!(code, "68084774");
}

#[test]
fn test_rfc6238_sha512_time_1111111109() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha512,
        timestamp: Some(1111111109),
        ..Default::default()
    };
    let code = Totp::generate(SHA512_SECRET, Some(options));
    assert_eq!(code, "25091201");
}

#[test]
fn test_rfc6238_sha1_time_1111111111() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha1,
        timestamp: Some(1111111111),
        ..Default::default()
    };
    let code = Totp::generate(SHA1_SECRET, Some(options));
    assert_eq!(code, "14050471");
}

#[test]
fn test_rfc6238_sha256_time_1111111111() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha256,
        timestamp: Some(1111111111),
        ..Default::default()
    };
    let code = Totp::generate(SHA256_SECRET, Some(options));
    assert_eq!(code, "67062674");
}

#[test]
fn test_rfc6238_sha512_time_1111111111() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha512,
        timestamp: Some(1111111111),
        ..Default::default()
    };
    let code = Totp::generate(SHA512_SECRET, Some(options));
    assert_eq!(code, "99943326");
}

#[test]
fn test_rfc6238_sha1_time_1234567890() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha1,
        timestamp: Some(1234567890),
        ..Default::default()
    };
    let code = Totp::generate(SHA1_SECRET, Some(options));
    assert_eq!(code, "89005924");
}

#[test]
fn test_rfc6238_sha256_time_1234567890() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha256,
        timestamp: Some(1234567890),
        ..Default::default()
    };
    let code = Totp::generate(SHA256_SECRET, Some(options));
    assert_eq!(code, "91819424");
}

#[test]
fn test_rfc6238_sha512_time_1234567890() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha512,
        timestamp: Some(1234567890),
        ..Default::default()
    };
    let code = Totp::generate(SHA512_SECRET, Some(options));
    assert_eq!(code, "93441116");
}

#[test]
fn test_rfc6238_sha1_time_2000000000() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha1,
        timestamp: Some(2000000000),
        ..Default::default()
    };
    let code = Totp::generate(SHA1_SECRET, Some(options));
    assert_eq!(code, "69279037");
}

#[test]
fn test_rfc6238_sha256_time_2000000000() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha256,
        timestamp: Some(2000000000),
        ..Default::default()
    };
    let code = Totp::generate(SHA256_SECRET, Some(options));
    assert_eq!(code, "90698825");
}

#[test]
fn test_rfc6238_sha512_time_2000000000() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha512,
        timestamp: Some(2000000000),
        ..Default::default()
    };
    let code = Totp::generate(SHA512_SECRET, Some(options));
    assert_eq!(code, "38618901");
}

#[test]
fn test_rfc6238_sha1_time_20000000000() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha1,
        timestamp: Some(20000000000),
        ..Default::default()
    };
    let code = Totp::generate(SHA1_SECRET, Some(options));
    assert_eq!(code, "65353130");
}

#[test]
fn test_rfc6238_sha256_time_20000000000() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha256,
        timestamp: Some(20000000000),
        ..Default::default()
    };
    let code = Totp::generate(SHA256_SECRET, Some(options));
    assert_eq!(code, "77737706");
}

#[test]
fn test_rfc6238_sha512_time_20000000000() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha512,
        timestamp: Some(20000000000),
        ..Default::default()
    };
    let code = Totp::generate(SHA512_SECRET, Some(options));
    assert_eq!(code, "47863826");
}

// 6-digit tests (common use case)
#[test]
fn test_6_digit_sha1_time_59() {
    let options = TotpOptions {
        digits: 6,
        algorithm: Algorithm::Sha1,
        timestamp: Some(59),
        ..Default::default()
    };
    let code = Totp::generate(SHA1_SECRET, Some(options));
    // Last 6 digits of 94287082
    assert_eq!(code, "287082");
}

#[test]
fn test_6_digit_sha256_time_59() {
    let options = TotpOptions {
        digits: 6,
        algorithm: Algorithm::Sha256,
        timestamp: Some(59),
        ..Default::default()
    };
    let code = Totp::generate(SHA256_SECRET, Some(options));
    // Last 6 digits of 46119246
    assert_eq!(code, "119246");
}

#[test]
fn test_6_digit_sha512_time_59() {
    let options = TotpOptions {
        digits: 6,
        algorithm: Algorithm::Sha512,
        timestamp: Some(59),
        ..Default::default()
    };
    let code = Totp::generate(SHA512_SECRET, Some(options));
    // Last 6 digits of 90693936
    assert_eq!(code, "693936");
}

// Validation tests
#[test]
fn test_validate_current_code() {
    let options = TotpOptions {
        digits: 6,
        timestamp: Some(59),
        ..Default::default()
    };
    let code = Totp::generate(SHA1_SECRET, Some(options.clone()));

    let validate_options = TotpValidateOptions { options, skew: 1 };
    assert!(Totp::validate(SHA1_SECRET, &code, Some(validate_options)));
}

#[test]
fn test_validate_rejects_invalid_code() {
    let options = TotpOptions {
        digits: 6,
        timestamp: Some(59),
        ..Default::default()
    };
    let validate_options = TotpValidateOptions { options, skew: 1 };
    assert!(!Totp::validate(
        SHA1_SECRET,
        "000000",
        Some(validate_options)
    ));
}

#[test]
fn test_validate_with_skew_previous_period() {
    // Generate code for time 59 (counter 1)
    let gen_options = TotpOptions {
        digits: 6,
        timestamp: Some(59),
        ..Default::default()
    };
    let code = Totp::generate(SHA1_SECRET, Some(gen_options));

    // Validate at time 89 (counter 2, but skew=1 should accept counter 1)
    let validate_options = TotpValidateOptions {
        options: TotpOptions {
            digits: 6,
            timestamp: Some(89),
            ..Default::default()
        },
        skew: 1,
    };
    assert!(Totp::validate(SHA1_SECRET, &code, Some(validate_options)));
}

#[test]
fn test_validate_with_skew_next_period() {
    // Generate code for time 59 (counter 1)
    let gen_options = TotpOptions {
        digits: 6,
        timestamp: Some(59),
        ..Default::default()
    };
    let code = Totp::generate(SHA1_SECRET, Some(gen_options));

    // Validate at time 29 (counter 0, but skew=1 should accept counter 1)
    let validate_options = TotpValidateOptions {
        options: TotpOptions {
            digits: 6,
            timestamp: Some(29),
            ..Default::default()
        },
        skew: 1,
    };
    assert!(Totp::validate(SHA1_SECRET, &code, Some(validate_options)));
}

#[test]
fn test_validate_rejects_outside_skew() {
    // Generate code for time 59 (counter 1)
    let gen_options = TotpOptions {
        digits: 6,
        timestamp: Some(59),
        ..Default::default()
    };
    let code = Totp::generate(SHA1_SECRET, Some(gen_options));

    // Validate at time 119 (counter 3, skew=1 only accepts counters 2,3,4)
    let validate_options = TotpValidateOptions {
        options: TotpOptions {
            digits: 6,
            timestamp: Some(119),
            ..Default::default()
        },
        skew: 1,
    };
    assert!(!Totp::validate(SHA1_SECRET, &code, Some(validate_options)));
}

#[test]
fn test_validate_rejects_wrong_length() {
    let validate_options = TotpValidateOptions {
        options: TotpOptions {
            digits: 6,
            timestamp: Some(59),
            ..Default::default()
        },
        skew: 1,
    };

    // Too short
    assert!(!Totp::validate(
        SHA1_SECRET,
        "12345",
        Some(validate_options.clone())
    ));

    // Too long
    assert!(!Totp::validate(
        SHA1_SECRET,
        "1234567",
        Some(validate_options)
    ));
}

#[test]
fn test_validate_trims_whitespace() {
    let options = TotpOptions {
        digits: 6,
        timestamp: Some(59),
        ..Default::default()
    };
    let code = Totp::generate(SHA1_SECRET, Some(options.clone()));

    let validate_options = TotpValidateOptions { options, skew: 1 };

    // Should accept code with leading/trailing whitespace
    let padded_code = format!("  {}  ", code);
    assert!(Totp::validate(
        SHA1_SECRET,
        &padded_code,
        Some(validate_options)
    ));
}

#[test]
fn test_60_second_period() {
    let options_30 = TotpOptions {
        digits: 6,
        timestamp: Some(59),
        period: 30,
        ..Default::default()
    };
    let options_60 = TotpOptions {
        digits: 6,
        timestamp: Some(59),
        period: 60,
        ..Default::default()
    };

    let code_30 = Totp::generate(SHA1_SECRET, Some(options_30));
    let code_60 = Totp::generate(SHA1_SECRET, Some(options_60));

    // Different periods should produce different codes (same counter value)
    // At time 59: 30-second period has counter 1, 60-second period has counter 0
    assert_ne!(code_30, code_60);
}

// Cross-SDK compatibility tests (TypeScript SDK vectors)
#[test]
fn test_ts_sdk_compat_unix_epoch() {
    // TypeScript SDK test vector: time=0, secret=0x48656c6c6f21deadbeef
    let secret = hex::decode("48656c6c6f21deadbeef").unwrap();
    let options = TotpOptions {
        digits: 6,
        algorithm: Algorithm::Sha1,
        period: 30,
        timestamp: Some(0),
    };
    let code = Totp::generate(&secret, Some(options));
    assert_eq!(code, "282760");
}

#[test]
fn test_ts_sdk_compat_2016_timestamp() {
    // TypeScript SDK test vector: time=1465324707000ms = 1465324707s
    let secret = hex::decode("48656c6c6f21deadbeef").unwrap();
    let options = TotpOptions {
        digits: 6,
        algorithm: Algorithm::Sha1,
        period: 30,
        timestamp: Some(1465324707),
    };
    let code = Totp::generate(&secret, Some(options));
    assert_eq!(code, "341128");
}

#[test]
fn test_ts_sdk_compat_leading_zero() {
    // TypeScript SDK test vector with leading zero: time=1365324707000ms = 1365324707s
    let secret = hex::decode("48656c6c6f21deadbeef").unwrap();
    let options = TotpOptions {
        digits: 6,
        algorithm: Algorithm::Sha1,
        period: 30,
        timestamp: Some(1365324707),
    };
    let code = Totp::generate(&secret, Some(options));
    assert_eq!(code, "089029");
}

#[test]
fn test_ts_sdk_compat_cycle_boundary_start() {
    // TypeScript SDK: time=(1665644340000 + 1)ms = 1665644340s (counter 55521478)
    let secret = hex::decode("48656c6c6f21deadbeef").unwrap();
    let options = TotpOptions {
        digits: 6,
        algorithm: Algorithm::Sha1,
        period: 30,
        timestamp: Some(1665644340),
    };
    let code = Totp::generate(&secret, Some(options));
    assert_eq!(code, "886842");
}

#[test]
fn test_ts_sdk_compat_cycle_boundary_end() {
    // TypeScript SDK: time=(1665644340000 - 1)ms = 1665644339s (counter 55521477)
    let secret = hex::decode("48656c6c6f21deadbeef").unwrap();
    let options = TotpOptions {
        digits: 6,
        algorithm: Algorithm::Sha1,
        period: 30,
        timestamp: Some(1665644339),
    };
    let code = Totp::generate(&secret, Some(options));
    assert_eq!(code, "134996");
}

// Edge cases
#[test]
fn test_default_options() {
    // Ensure defaults work without panicking
    let code = Totp::generate(SHA1_SECRET, None);
    assert_eq!(code.len(), 6);
}

#[test]
fn test_validate_with_none_options() {
    let code = Totp::generate(SHA1_SECRET, None);
    assert!(Totp::validate(SHA1_SECRET, &code, None));
}

#[test]
fn test_constant_time_eq() {
    assert!(constant_time_eq("123456", "123456"));
    assert!(!constant_time_eq("123456", "654321"));
    assert!(!constant_time_eq("123", "123456"));
    assert!(!constant_time_eq("123456", "123"));
}

#[test]
fn test_constant_time_eq_empty() {
    // Both empty - they are equal
    assert!(constant_time_eq("", ""));
}

#[test]
fn test_counter_near_zero() {
    // Test validation when counter is 0 (edge case for skew subtraction)
    let options = TotpOptions {
        digits: 6,
        timestamp: Some(0), // counter = 0
        ..Default::default()
    };
    let code = Totp::generate(SHA1_SECRET, Some(options.clone()));

    let validate_options = TotpValidateOptions { options, skew: 1 };
    assert!(Totp::validate(SHA1_SECRET, &code, Some(validate_options)));
}

#[test]
fn test_algorithm_enum_default() {
    let algo: Algorithm = Default::default();
    assert_eq!(algo, Algorithm::Sha1);
}

#[test]
fn test_algorithm_enum_clone_eq() {
    let algo1 = Algorithm::Sha256;
    let algo2 = algo1;
    assert_eq!(algo1, algo2);
}

#[test]
fn test_totp_options_clone() {
    let options = TotpOptions {
        digits: 8,
        algorithm: Algorithm::Sha512,
        period: 60,
        timestamp: Some(12345),
    };
    let cloned = options.clone();
    assert_eq!(cloned.digits, 8);
    assert_eq!(cloned.algorithm, Algorithm::Sha512);
    assert_eq!(cloned.period, 60);
    assert_eq!(cloned.timestamp, Some(12345));
}

// Unusual digit count tests
#[test]
fn test_digits_1() {
    let options = TotpOptions {
        digits: 1,
        timestamp: Some(59),
        ..Default::default()
    };
    let code = Totp::generate(SHA1_SECRET, Some(options.clone()));
    assert_eq!(code.len(), 1);

    // Should still validate
    let validate_options = TotpValidateOptions { options, skew: 0 };
    assert!(Totp::validate(SHA1_SECRET, &code, Some(validate_options)));
}

#[test]
fn test_digits_9() {
    // 9 digits is the max that fits in u32 (10^9 = 1_000_000_000 < u32::MAX)
    let options = TotpOptions {
        digits: 9,
        timestamp: Some(59),
        ..Default::default()
    };
    let code = Totp::generate(SHA1_SECRET, Some(options.clone()));
    assert_eq!(code.len(), 9);

    // Should still validate
    let validate_options = TotpValidateOptions { options, skew: 0 };
    assert!(Totp::validate(SHA1_SECRET, &code, Some(validate_options)));
}

// RFC 4226 Appendix D HOTP test vectors
// Secret: "12345678901234567890" (ASCII), 6-digit codes
// These verify the underlying HOTP algorithm by using period=1 and timestamp=counter
#[test]
fn test_rfc4226_hotp_vectors() {
    let expected = [
        "755224", // counter 0
        "287082", // counter 1
        "359152", // counter 2
        "969429", // counter 3
        "338314", // counter 4
        "254676", // counter 5
        "287922", // counter 6
        "162583", // counter 7
        "399871", // counter 8
        "520489", // counter 9
    ];

    for (counter, expected_code) in expected.iter().enumerate() {
        let options = TotpOptions {
            digits: 6,
            algorithm: Algorithm::Sha1,
            period: 1,                       // 1-second period so timestamp == counter
            timestamp: Some(counter as u64), // counter value
        };
        let code = Totp::generate(SHA1_SECRET, Some(options));
        assert_eq!(
            &code, expected_code,
            "RFC 4226 HOTP vector failed for counter {}",
            counter
        );
    }
}
