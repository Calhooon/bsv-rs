#![no_main]
//! BIP-32 (`compat::bip32`) on arbitrary input: `ExtendedKey::from_string` on
//! the input as text, `new_master` on it as a seed, `derive_path` with it as
//! a path, and every accessor of a key that parsed. The assertion is that
//! each returns; the target also checks a round trip: a parsed key prints the
//! string it parsed from, and a key's printed form parses back to it.
use bsv_rs::compat::bip32::{derive_public_keys_for_path, ExtendedKey, Network};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn master() -> &'static ExtendedKey {
    static MASTER: OnceLock<ExtendedKey> = OnceLock::new();
    MASTER.get_or_init(|| ExtendedKey::new_master(&[7; 32], Network::Mainnet).expect("a master"))
}

fn exercise(key: &ExtendedKey, index: u32) {
    let printed = key.to_string();
    let reparsed = ExtendedKey::from_string(&printed).expect("a key's printed form parses");
    assert_eq!(reparsed.to_string(), printed);
    let _ = key.depth();
    let _ = key.child_number();
    let _ = key.parent_fingerprint();
    let _ = key.chain_code();
    let _ = key.fingerprint();
    let _ = key.network();
    let _ = key.is_private();
    let _ = key.public_key();
    let _ = key.private_key();
    let _ = key.address(true);
    let _ = key.address(false);
    if let Ok(public) = key.neuter() {
        assert!(!public.is_private());
        let _ = public.derive_child(index);
        let _ = public.derive_child(index & 0x7fff_ffff);
    }
    let _ = key.derive_child(index);
}

fuzz_target!(|data: &[u8]| {
    let index = data
        .get(..4)
        .map(|w| u32::from_le_bytes(w.try_into().expect("four bytes")))
        .unwrap_or(0);

    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(key) = ExtendedKey::from_string(text) {
            assert_eq!(key.to_string(), text, "a parsed key prints another string");
            exercise(&key, index);
        }
        if let Ok(child) = master().derive_path(text) {
            exercise(&child, index);
        }
        let _ = derive_public_keys_for_path(master(), text, index, 2);
    }

    for network in [Network::Mainnet, Network::Testnet] {
        if let Ok(key) = ExtendedKey::new_master(data, network) {
            exercise(&key, index);
        }
    }
});
