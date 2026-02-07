#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz Base58 decoding - should never panic
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = bsv_sdk::primitives::from_base58(s);
        let _ = bsv_sdk::primitives::from_base58_check(s);
        let _ = bsv_sdk::primitives::from_hex(s);
        let _ = bsv_sdk::primitives::from_base64(s);
    }

    // Fuzz encoding roundtrips
    let encoded = bsv_sdk::primitives::to_base58(data);
    if let Ok(decoded) = bsv_sdk::primitives::from_base58(&encoded) {
        assert_eq!(decoded, data);
    }

    let hex = bsv_sdk::primitives::to_hex(data);
    if let Ok(decoded) = bsv_sdk::primitives::from_hex(&hex) {
        assert_eq!(decoded, data);
    }
});
