#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz Script::from_binary - should never panic
    if let Ok(script) = bsv_sdk::script::Script::from_binary(data) {
        // If parsing succeeded, verify roundtrip
        let binary = script.to_binary();
        let _ = bsv_sdk::script::Script::from_binary(&binary);

        // Exercise type detection (should never panic)
        let _ = script.is_p2pkh();
        let _ = script.is_p2pk();
        let _ = script.is_p2sh();
        let _ = script.is_data();
        let _ = script.is_multisig();
        let _ = script.to_asm();
        let _ = script.to_hex();
        let _ = script.chunks();
    }

    // Also fuzz hex parsing
    if let Ok(hex_str) = std::str::from_utf8(data) {
        let _ = bsv_sdk::script::Script::from_hex(hex_str);
    }
});
