#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The deprecated KVStore verdict never panics, and answers `true` only
    // for a token of five or six fields whose controller field is the key
    // it is checked against (the token's own lock key, and its controller).
    if let Ok(locking) = bsv_rs::script::LockingScript::from_binary(data) {
        if let Ok(token) = bsv_rs::script::templates::PushDrop::decode(&locking) {
            let controller = token
                .fields
                .get(3)
                .and_then(|field| bsv_rs::primitives::PublicKey::from_bytes(field).ok());
            for key in std::iter::once(token.locking_public_key.clone()).chain(controller) {
                #[allow(deprecated)]
                let verdict =
                    bsv_rs::kvstore::KVStoreInterpreter::verify_signature_legacy(&token, &key);
                assert!(
                    !verdict
                        || (matches!(token.fields.len(), 5 | 6)
                            && token.fields[3].as_slice() == key.to_compressed().as_slice()),
                    "a legacy verdict of true for a token its key does not control"
                );
            }
        }
    }

    // Fuzz Script::from_binary - should never panic
    if let Ok(script) = bsv_rs::script::Script::from_binary(data) {
        // If parsing succeeded, verify roundtrip
        let binary = script.to_binary();
        let _ = bsv_rs::script::Script::from_binary(&binary);

        // Exercise type detection (should never panic)
        let _ = script.is_p2pkh();
        let _ = script.is_p2pk();
        let _ = script.is_p2sh();
        let _ = script.is_data();
        let _ = script.is_multisig();
        let _ = script.to_asm();
        let _ = script.to_hex();
        let _ = script.chunks();

        // A template classifier says yes only to the template's bytes: each
        // push the template holds made by the opcode that is its length.
        if script.is_p2pkh() {
            assert!(
                binary.len() == 25 && binary[2] == 0x14,
                "is_p2pkh on {binary:02x?}"
            );
        }
        if script.is_p2sh() {
            assert!(
                binary.len() == 23 && binary[1] == 0x14,
                "is_p2sh on {binary:02x?}"
            );
        }
        if script.is_p2pk() {
            assert!(
                matches!((binary.len(), binary[0]), (35, 0x21) | (67, 0x41)),
                "is_p2pk on {binary:02x?}"
            );
        }
        if let Some((_, n)) = script.is_multisig() {
            let chunks = script.chunks();
            for key in &chunks[1..=usize::from(n)] {
                let len = key.data.as_ref().map_or(0, Vec::len);
                assert!(
                    usize::from(key.op) == len && (len == 33 || len == 65),
                    "is_multisig on {binary:02x?}"
                );
            }
        }
    }

    // Also fuzz hex parsing
    if let Ok(hex_str) = std::str::from_utf8(data) {
        let _ = bsv_rs::script::Script::from_hex(hex_str);
    }
});
