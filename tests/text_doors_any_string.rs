//! A public door that reads text answers every string: the BIP-276 decoder
//! refuses a string that is not ASCII where it must be cut, an identity key
//! that is not ASCII is abbreviated at a character's edge, and every public
//! text door of the crate answers (an `Ok` or an `Err`) on strings carrying a
//! multi-byte character at every position. Every string an earlier version
//! answered is answered the same.
//!
//! Run with: `cargo test --all-features --test text_doors_any_string`

#![cfg(feature = "script")]

use bsv_rs::primitives::{sha256, to_hex};
use bsv_rs::script::{decode_bip276, encode_bip276};
use bsv_rs::Error;

const PREFIX: &str = "bitcoin-script:";

fn not_ascii() -> bsv_rs::Result<(u8, u8, Vec<u8>)> {
    Err(Error::Bip276Error(
        "invalid encoding: not ASCII".to_string(),
    ))
}

#[test]
fn a_bip276_string_not_ascii_in_its_network_is_refused() {
    assert_eq!(
        decode_bip276(&format!("{PREFIX}{}", "\u{20ac}".repeat(6))),
        not_ascii()
    );
}

#[test]
fn a_bip276_string_not_ascii_in_its_script_type_is_refused() {
    assert_eq!(
        decode_bip276(&format!("{PREFIX}00{}", "\u{20ac}".repeat(4))),
        not_ascii()
    );
}

#[test]
fn a_bip276_string_not_ascii_across_its_checksum_is_refused() {
    assert_eq!(
        decode_bip276(&format!("{PREFIX}0101\u{20ac}1234567")),
        not_ascii()
    );
}

#[test]
fn a_bip276_string_not_ascii_at_its_type_boundary_is_refused() {
    assert_eq!(
        decode_bip276(&format!("{PREFIX}000\u{e9}12345678")),
        not_ascii()
    );
}

/// Strings an earlier version answered (each cut on a character's edge)
/// keep their answers, words and all.
#[test]
fn a_bip276_string_answered_before_is_answered_the_same() {
    let honest = encode_bip276(1, 1, &[0x76, 0xa9]);
    assert_eq!(decode_bip276(&honest), Ok((1, 1, vec![0x76, 0xa9])));
    assert_eq!(
        decode_bip276(&format!("{PREFIX}0101\u{e9}\u{e9}12345678")),
        Err(Error::Bip276Error(
            "invalid script hex: '\u{e9}\u{e9}'".to_string()
        ))
    );
    assert_eq!(
        decode_bip276(&format!("{PREFIX}\u{e9}0112345678")),
        Err(Error::Bip276Error(
            "invalid network hex: '\u{e9}'".to_string()
        ))
    );
    assert_eq!(
        decode_bip276(&format!("{PREFIX}zzzzzzzzzzzz")),
        Err(Error::Bip276Error("invalid network hex: 'zz'".to_string()))
    );
    assert_eq!(
        decode_bip276("bitcoin-script:01"),
        Err(Error::Bip276Error("input too short".to_string()))
    );
}

#[cfg(feature = "identity")]
mod identity {
    use bsv_rs::identity::{Contact, DisplayableIdentity};

    #[test]
    fn an_identity_key_not_ascii_is_abbreviated_at_a_character_edge() {
        // 12 bytes: the head's cut (6) is an edge, the tail's (8) is not
        let key = "\u{20ac}".repeat(4);
        let identity = DisplayableIdentity::from_key(&key);
        assert_eq!(identity.abbreviated_key, "\u{20ac}\u{20ac}...\u{20ac}");
        assert_eq!(identity.name, "\u{20ac}\u{20ac}...\u{20ac}");
        assert_eq!(identity.identity_key, key);
        // 16 bytes of 4-byte characters: neither cut is an edge
        let key = "\u{1f600}".repeat(4);
        assert_eq!(
            DisplayableIdentity::from_key(&key).abbreviated_key,
            "\u{1f600}...\u{1f600}"
        );
    }

    #[test]
    fn a_contact_whose_key_is_not_ascii_displays_at_a_character_edge() {
        let contact = Contact::new("n", "\u{20ac}".repeat(4));
        assert_eq!(
            contact.to_displayable_identity().abbreviated_key,
            "\u{20ac}\u{20ac}...\u{20ac}"
        );
    }

    /// A key of 10 bytes is its own abbreviation; one of 11 is cut.
    #[test]
    fn an_identity_key_of_ten_bytes_is_kept_and_of_eleven_is_abbreviated() {
        assert_eq!(
            DisplayableIdentity::from_key("0123456789").abbreviated_key,
            "0123456789"
        );
        assert_eq!(
            DisplayableIdentity::from_key("0123456789a").abbreviated_key,
            "012345...789a"
        );
        assert_eq!(
            Contact::new("n", "0123456789")
                .to_displayable_identity()
                .abbreviated_key,
            "0123456789"
        );
        assert_eq!(
            Contact::new("n", "0123456789a")
                .to_displayable_identity()
                .abbreviated_key,
            "012345...789a"
        );
    }

    #[test]
    fn an_identity_key_abbreviated_before_is_abbreviated_the_same() {
        // a compressed key's 66 hex characters, built so no scanner reads a secret
        let key = format!("02{}", "a1".repeat(32));
        assert_eq!(
            DisplayableIdentity::from_key(&key).abbreviated_key,
            "02a1a1...a1a1"
        );
        assert_eq!(
            DisplayableIdentity::from_key("02abc").abbreviated_key,
            "02abc"
        );
        // 12 bytes of 2-byte characters: both cuts on an edge
        let key = "\u{e9}".repeat(6);
        assert_eq!(
            DisplayableIdentity::from_key(&key).abbreviated_key,
            "\u{e9}\u{e9}\u{e9}...\u{e9}\u{e9}"
        );
        assert_eq!(
            Contact::new("n", key)
                .to_displayable_identity()
                .abbreviated_key,
            "\u{e9}\u{e9}\u{e9}...\u{e9}\u{e9}"
        );
    }
}

/// A deterministic xorshift, so the differential's digest is one constant.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The `i`th honest text: an encoding of random bytes, the same with one
/// character changed or cut short, or a random ASCII string, a hex key now
/// and then.
fn honest_text(rng: &mut Rng) -> String {
    const ASCII: &[u8] = b"0123456789abcdefABCDEF:-xyz bitcoin-script";
    match rng.below(4) {
        0 | 1 => {
            let data: Vec<u8> = (0..rng.below(40)).map(|_| rng.below(256) as u8).collect();
            let mut text = encode_bip276(rng.below(4) as u8, rng.below(4) as u8, &data);
            if rng.below(2) == 0 {
                let at = rng.below(text.len() as u64) as usize;
                let with = ASCII[rng.below(ASCII.len() as u64) as usize] as char;
                text.replace_range(at..at + 1, &with.to_string());
            }
            if rng.below(4) == 0 {
                text.truncate(rng.below(text.len() as u64 + 1) as usize);
            }
            text
        }
        2 => (0..66)
            .map(|_| b"0123456789abcdef"[rng.below(16) as usize] as char)
            .collect(),
        _ => {
            let mut text = String::new();
            if rng.below(2) == 0 {
                text.push_str(PREFIX);
            }
            for _ in 0..rng.below(40) {
                text.push(ASCII[rng.below(ASCII.len() as u64) as usize] as char);
            }
            text
        }
    }
}

/// The differential: 20,000 honest texts through every door this change
/// touches; the answers' digest equals the one the code before it gives.
#[test]
fn twenty_thousand_honest_texts_answer_as_before() {
    let mut rng = Rng(0x5eed_0276_0bad_cafe);
    let mut transcript = String::new();
    for i in 0..20_000 {
        let text = honest_text(&mut rng);
        transcript.push_str(&format!("{i}:{:?};", decode_bip276(&text)));
        #[cfg(feature = "identity")]
        {
            use bsv_rs::identity::{Contact, DisplayableIdentity};
            transcript.push_str(&DisplayableIdentity::from_key(&text).abbreviated_key);
            transcript.push('|');
            transcript.push_str(
                &Contact::new("n", text.clone())
                    .to_displayable_identity()
                    .abbreviated_key,
            );
            transcript.push(';');
        }
    }
    #[cfg(feature = "identity")]
    let expected = "a657b6a340ba72a282775ea16cf244a4f5d4178cbec267647130aed4549dcee3";
    #[cfg(not(feature = "identity"))]
    let expected = "c88096bea8b058511053254159ac93aa1b7b2c09ba6ba0ee8a4876390c8818a0";
    assert_eq!(
        to_hex(&sha256(transcript.as_bytes())),
        expected,
        "an honest text answers otherwise than before"
    );
}

/// The strings of the family property: a multi-byte character (2, 3 and 4
/// bytes, and two that are invisible) at every position up to 24 after each
/// door's own prefixes, with ASCII tails of every length up to 10.
#[cfg(all(
    feature = "block",
    feature = "compat",
    feature = "storage",
    feature = "registry",
    feature = "identity",
    feature = "socketio",
    feature = "totp"
))]
fn family_strings() -> Vec<String> {
    let prefixes = [
        "",
        "bitcoin-script:",
        "bitcoin-script:00",
        "bitcoin-script:0001",
        "uhrp://",
        "web+uhrp://",
        "uhrp:",
        "https://",
        "xprv",
        "xpub",
        "m/",
        "m/0/",
        "m/0'/",
        "0x",
        "02",
        "03",
        "OP_",
        "tm_",
        "ls_",
        "[1,\"",
        "[\"",
        "aaaa.bbbb",
        "aaaa.bbbb.2.cccc",
        "SHIP",
        "SLAP",
        "1",
        "2",
        "40/",
        "0123456789",
        "localhost:",
    ];
    let chars = ["\u{e9}", "\u{20ac}", "\u{1f600}", "\u{85}", "\u{feff}"];
    let mut strings = Vec::new();
    for p in prefixes {
        for c in chars {
            for k in 0..24 {
                for tail in 0usize..=10 {
                    strings.push(format!("{p}{}{c}{}", "a".repeat(k), "0".repeat(tail)));
                    strings.push(format!("{p}{}{c}{}", "0".repeat(k), "1".repeat(tail)));
                }
            }
            strings.push(format!("{p}{}", c.repeat(12)));
        }
    }
    strings
}

/// The family property: every public door of the crate that reads a string
/// answers each of the family's 79,350 strings without stopping. A row's
/// label is the door's file under `src/` and its name: `arch_text_doors.rs`
/// reads these labels, and fails on a public door that takes text which is
/// in neither this table nor its list of doors that do not cut text.
#[cfg(all(
    feature = "block",
    feature = "compat",
    feature = "storage",
    feature = "registry",
    feature = "identity",
    feature = "socketio",
    feature = "totp"
))]
#[test]
#[allow(clippy::redundant_closure)] // one closure form for every door's table row
fn every_public_text_door_answers_every_string_of_the_family() {
    use bsv_rs::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let strings = family_strings();
    assert_eq!(strings.len(), 79_350);
    let master =
        compat::bip32::ExtendedKey::new_master(&[7u8; 32], compat::bip32::Network::Mainnet)
            .unwrap();
    let master = &master;
    let key = primitives::PrivateKey::from_bytes(&[3u8; 32]).unwrap();
    let key = &key;
    let public = key.public_key();
    let public = &public;
    let beef = transaction::Beef::new();
    let beef = &beef;
    let path = transaction::MerklePath::from_coinbase_txid(&"11".repeat(32), 1);
    let path = &path;
    type Door<'a> = (&'static str, Box<dyn Fn(&str) + 'a>);
    macro_rules! door {
        ($name:expr, $f:expr) => {
            (
                $name,
                Box::new(move |s: &str| {
                    let _ = $f(s);
                }) as Box<dyn Fn(&str)>,
            )
        };
    }
    let doors: Vec<Door> = vec![
        door!("script/bip276.rs decode_bip276", |s| script::decode_bip276(
            s
        )),
        door!("script/script.rs from_hex", |s| script::Script::from_hex(s)),
        door!("script/script_asm.rs from_asm", |s| {
            script::Script::from_asm(s)
        }),
        door!("script/locking_script.rs from_asm", |s| {
            script::LockingScript::from_asm(s)
        }),
        door!("script/locking_script.rs from_hex", |s| {
            script::LockingScript::from_hex(s)
        }),
        door!("script/unlocking_script.rs from_asm", |s| {
            script::UnlockingScript::from_asm(s)
        }),
        door!("script/unlocking_script.rs from_hex", |s| {
            script::UnlockingScript::from_hex(s)
        }),
        door!("script/address.rs new_from_string", |s| {
            script::Address::new_from_string(s)
        }),
        door!("script/address.rs is_valid_address", |s| {
            script::Address::is_valid_address(s)
        }),
        door!("script/op.rs name_to_opcode", |s| {
            script::op::name_to_opcode(s)
        }),
        door!("script/flags.rs from_names", |s| {
            script::ScriptFlags::from_names([s])
        }),
        door!("script/templates/p2pkh.rs lock_from_address", |s| {
            script::templates::P2PKH::lock_from_address(s)
        }),
        door!("transaction/transaction.rs from_hex", |s| {
            transaction::Transaction::from_hex(s)
        }),
        door!("transaction/transaction.rs from_hex_ef", |s| {
            transaction::Transaction::from_hex_ef(s)
        }),
        door!(
            "transaction/transaction/ef_reader.rs from_hex_ef_bounded",
            |s| { transaction::Transaction::from_hex_ef_bounded(s, 1) }
        ),
        door!("transaction/transaction.rs add_p2pkh_output", |s| {
            transaction::Transaction::new().add_p2pkh_output(s, Some(1))
        }),
        door!("transaction/tx_json.rs from_json", |s| {
            transaction::Transaction::from_json(s)
        }),
        door!("transaction/merkle_path.rs from_hex", |s| {
            transaction::MerklePath::from_hex(s)
        }),
        door!("transaction/merkle_path.rs from_coinbase_txid", |s| {
            transaction::MerklePath::from_coinbase_txid(s, 1)
        }),
        door!("transaction/merkle_path.rs contains", |s| path.contains(s)),
        door!("transaction/beef.rs from_hex", |s| {
            transaction::Beef::from_hex(s)
        }),
        door!("transaction/beef.rs find_bump", |s| beef
            .find_bump(s)
            .is_some()),
        door!("transaction/beef/index.rs find_txid", |s| {
            beef.find_txid(s).is_some()
        }),
        door!("primitives/encoding.rs from_hex", |s| primitives::from_hex(
            s
        )),
        door!("primitives/encoding.rs from_base58", |s| {
            primitives::from_base58(s)
        }),
        door!("primitives/encoding.rs from_base58_check", |s| {
            primitives::from_base58_check(s)
        }),
        door!(
            "primitives/encoding.rs from_base58_check_with_prefix_length",
            |s| primitives::encoding::from_base58_check_with_prefix_length(s, 1)
        ),
        door!("primitives/encoding.rs from_base64", |s| {
            primitives::from_base64(s)
        }),
        door!("primitives/ec/private_key.rs from_hex", |s| {
            primitives::PrivateKey::from_hex(s)
        }),
        door!("primitives/ec/private_key.rs from_wif", |s| {
            primitives::PrivateKey::from_wif(s)
        }),
        door!("primitives/ec/public_key.rs from_hex", |s| {
            primitives::PublicKey::from_hex(s)
        }),
        door!("primitives/bignum.rs from_hex", |s| {
            primitives::BigNumber::from_hex(s)
        }),
        door!("primitives/bignum.rs from_dec_str", |s| {
            primitives::BigNumber::from_dec_str(s)
        }),
        door!("primitives/bsv/shamir.rs from_backup_format", |s: &str| {
            primitives::bsv::KeyShares::from_backup_format(&[s.to_string(), s.to_string()])
        }),
        door!(
            "primitives/bsv/shamir_legacy.rs recover_private_key_from_legacy_backup",
            |s: &str| {
                primitives::bsv::recover_private_key_from_legacy_backup(&[
                    s.to_string(),
                    s.to_string(),
                ])
            }
        ),
        door!("compat/base58.rs decode", |s| compat::base58::decode(s)),
        door!("compat/bip32.rs from_string", |s| {
            compat::bip32::ExtendedKey::from_string(s)
        }),
        door!("compat/bip32.rs derive_path", |s| master.derive_path(s)),
        door!("compat/bip32.rs derive_addresses_for_path", |s| {
            compat::bip32::derive_addresses_for_path(master, s, 0, 1, true)
        }),
        door!("compat/bip32.rs derive_public_keys_for_path", |s| {
            compat::bip32::derive_public_keys_for_path(master, s, 0, 1)
        }),
        door!("compat/bip39/mnemonic.rs from_phrase", |s| {
            compat::Mnemonic::from_phrase(s)
        }),
        door!("compat/bip39/mnemonic.rs from_phrase_with_language", |s| {
            compat::Mnemonic::from_phrase_with_language(s, compat::Language::English)
        }),
        door!("compat/bsm.rs verify_message", |s| {
            compat::bsm::verify_message(s, &[0u8; 65], b"m")
        }),
        door!("compat/ecies.rs decrypt_single_base64", |s| {
            compat::ecies::decrypt_single_base64(s, key)
        }),
        door!(
            "storage/utils.rs normalize_url",
            |s| storage::normalize_url(s)
        ),
        door!("storage/utils.rs get_hash_from_url", |s| {
            storage::get_hash_from_url(s)
        }),
        door!("storage/utils.rs get_hash_hex_from_url", |s| {
            storage::get_hash_hex_from_url(s)
        }),
        door!("storage/utils.rs is_valid_url", |s| storage::is_valid_url(
            s
        )),
        door!("wallet/validation.rs parse_wallet_outpoint", |s| {
            wallet::validation::parse_wallet_outpoint(s)
        }),
        door!("wallet/validation.rs validate_outpoint_string", |s| {
            wallet::validation::validate_outpoint_string(s, "o")
        }),
        door!("wallet/validation.rs is_hex_string", |s| {
            wallet::validation::is_hex_string(s)
        }),
        door!("wallet/validation.rs validate_basket", |s| {
            wallet::validation::validate_basket(s)
        }),
        door!("wallet/validation.rs validate_label", |s| {
            wallet::validation::validate_label(s)
        }),
        door!("wallet/validation.rs validate_tag", |s| {
            wallet::validation::validate_tag(s)
        }),
        door!("wallet/validation.rs validate_description_5_2000", |s| {
            wallet::validation::validate_description_5_2000(s, "d")
        }),
        door!("wallet/validation.rs validate_description_5_50", |s| {
            wallet::validation::validate_description_5_50(s, "d")
        }),
        door!("wallet/validation.rs validate_query_mode", |s| {
            wallet::validation::validate_query_mode(Some(s), "q")
        }),
        door!("wallet/validation.rs validate_keyring_revealer", |s| {
            wallet::validation::validate_keyring_revealer(s, "k")
        }),
        door!("wallet/validation/originator.rs validate_originator", |s| {
            wallet::validation::validate_originator(Some(s))
        }),
        door!("wallet/types.rs from_string", |s| {
            wallet::Outpoint::from_string(s)
        }),
        door!("wallet/types.rs validate_description", |s| {
            wallet::validate_description(s, "d")
        }),
        door!("wallet/types.rs validate_key_id", |s| {
            wallet::validate_key_id(s)
        }),
        door!("wallet/types.rs validate_protocol_name", |s| {
            wallet::validate_protocol_name(s)
        }),
        door!("wallet/wire/encoding.rs write_outpoint_string", |s| {
            wallet::wire::WireWriter::new()
                .write_outpoint_string(s)
                .is_ok()
        }),
        door!("wallet/wire/encoding.rs write_txid_hex", |s| {
            wallet::wire::WireWriter::new().write_txid_hex(s).is_ok()
        }),
        door!("wallet/validation.rs validate_hex_string", |s| {
            wallet::validation::validate_hex_string(s, "h", None, None)
        }),
        door!("wallet/validation.rs validate_optional_hex_string", |s| {
            wallet::validation::validate_optional_hex_string(Some(s), "h", Some(2), Some(8))
        }),
        door!("wallet/validation.rs validate_base64_string", |s| {
            wallet::validation::validate_base64_string(s, "b", None, None)
        }),
        door!(
            "wallet/validation.rs validate_optional_base64_string",
            |s| {
                wallet::validation::validate_optional_base64_string(Some(s), "b", Some(1), Some(8))
            }
        ),
        door!("wallet/validation.rs validate_string_length", |s| {
            wallet::validation::validate_string_length(s, "n", Some(1), Some(10))
        }),
        door!(
            "wallet/validation.rs validate_optional_string_length",
            |s| {
                wallet::validation::validate_optional_string_length(Some(s), "n", Some(1), Some(10))
            }
        ),
        door!(
            "wallet/validation.rs validate_optional_outpoint_string",
            |s| { wallet::validation::validate_optional_outpoint_string(Some(s), "o") }
        ),
        door!("wallet/validation.rs validate_optional_basket", |s| {
            wallet::validation::validate_optional_basket(Some(s))
        }),
        door!("wallet/validation.rs validate_protocol_tuple", |s| {
            wallet::validation::validate_protocol_tuple((1, s))
        }),
        door!("wallet/types.rs from_tuple", |s| {
            wallet::Protocol::from_tuple((1, s))
        }),
        door!("wallet/types.rs from_hex", |s| {
            wallet::Counterparty::from_hex(s)
        }),
        door!("primitives/encoding.rs to_utf8_bytes", |s| {
            primitives::to_utf8_bytes(s)
        }),
        door!("primitives/p256.rs from_hex", |s| {
            primitives::p256::P256PrivateKey::from_hex(s)
        }),
        door!("primitives/p256.rs from_hex", |s| {
            primitives::p256::P256PublicKey::from_hex(s)
        }),
        door!("primitives/u256.rs from_hex", |s| {
            primitives::U256::from_hex(s)
        }),
        door!("primitives/bsv/polynomial.rs from_string", |s| {
            primitives::bsv::PointInFiniteField::from_string(s)
        }),
        door!("block/work.rs from_hex", |s| block::ChainWork::from_hex(s)),
        door!("auth/types.rs from_str", |s| auth::MessageType::from_str(s)),
        door!("overlay/types.rs parse", |s| overlay::Protocol::parse(s)),
        door!("overlay/host_reputation_tracker.rs from_json", |s| {
            overlay::HostReputationTracker::new().from_json(s)
        }),
        door!("error/wallet_refusal.rs from_name", |s| {
            WalletRefusalClass::from_name(s)
        }),
        door!("registry/types.rs try_from_str", |s| {
            registry::DefinitionType::try_from_str(s)
        }),
        door!("wallet/validation/crypto.rs validate_public_key", |s| {
            wallet::validation::validate_public_key(s, "k")
        }),
        door!("primitives/p256.rs public_key_from_private", |s| {
            primitives::p256::public_key_from_private(s)
        }),
        door!("primitives/p256.rs sign", |s| primitives::p256::sign(
            b"m", s
        )),
        door!(
            "auth/certificates/to_binary_key.rs certificate_key_bytes",
            |s| { auth::certificates::certificate_key_bytes(s, "f") }
        ),
        door!("auth/utils/identity_key.rs assert_auth_identity_key", |s| {
            auth::utils::assert_auth_identity_key(s)
        }),
        door!("compat/ecies.rs decrypt_shared_base64", |s| {
            compat::ecies::decrypt_shared_base64(s, key, public)
        }),
        door!("transaction/merkle_path.rs compute_root", |s| {
            path.compute_root(Some(s))
        }),
        door!("transaction/transaction.rs add_hash_puzzle_output", |s| {
            transaction::Transaction::new().add_hash_puzzle_output(s, s, 1)
        }),
        door!("wallet/wire/encoding.rs write_string", |s| {
            wallet::wire::WireWriter::new()
                .write_string(s)
                .as_bytes()
                .len()
        }),
        door!("wallet/wire/encoding.rs write_optional_string", |s| {
            wallet::wire::WireWriter::new()
                .write_optional_string(Some(s))
                .as_bytes()
                .len()
        }),
        door!("registry/types.rs deserialize_wallet_protocol", |s| {
            registry::types::deserialize_wallet_protocol(s)
        }),
        door!("auth/utils/nonce.rs validate_nonce_format", |s| {
            auth::utils::validate_nonce_format(s)
        }),
        door!("auth/utils/nonce.rs get_nonce_random", |s| {
            auth::utils::get_nonce_random(s)
        }),
        door!(
            "auth/certificates/certificate.rs get_field_encryption_key_id_master",
            |s| auth::certificates::Certificate::get_field_encryption_key_id_master(s)
        ),
        door!("auth/clients/payment.rs parse_known_txids_header", |s| {
            auth::clients::parse_known_txids_header(Some(s))
        }),
        door!("auth/transports/socketio/codec.rs decode", |s| {
            auth::transports::socketio::codec::EngineIoPacket::decode(s)
        }),
        door!("auth/transports/socketio/codec.rs decode", |s| {
            auth::transports::socketio::codec::SocketIoPacket::decode(s)
        }),
        door!(
            "auth/transports/socketio/codec.rs decode_polling_batch",
            |s| { auth::transports::socketio::codec::decode_polling_batch(s) }
        ),
        door!(
            "auth/transports/socketio/codec.rs decode_event_args_text",
            |s| auth::transports::socketio::codec::decode_event_args_text(s)
        ),
        door!(
            "block/header.rs from_hex",
            |s| block::BlockHeader::from_hex(s)
        ),
        door!("totp/core.rs validate", |s| totp::Totp::validate(
            &[1u8; 20], s, None
        )),
        door!("identity/types.rs from_key", |s| {
            identity::DisplayableIdentity::from_key(s)
        }),
        door!("identity/types.rs from_type_id", |s| {
            identity::KnownCertificateType::from_type_id(s)
        }),
        door!("identity/types.rs to_displayable_identity", |s: &str| {
            identity::Contact::new("n", s).to_displayable_identity()
        }),
    ];
    assert_eq!(doors.len(), DOORS);

    // Silence this thread's stops alone: another test's message still prints
    let me = std::thread::current().id();
    let hook = std::sync::Arc::new(std::panic::take_hook());
    let other = hook.clone();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().id() != me {
            other(info)
        }
    }));
    let mut stopped = Vec::new();
    for (name, door) in &doors {
        let count = strings
            .iter()
            .filter(|s| catch_unwind(AssertUnwindSafe(|| door(s))).is_err())
            .count();
        if count > 0 {
            stopped.push(format!("{name}: {count} of {}", strings.len()));
        }
    }
    let _ = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| hook(info)));
    assert!(stopped.is_empty(), "doors that stopped: {stopped:#?}");
}

/// The rows of the family table on this line.
#[cfg(all(
    feature = "block",
    feature = "compat",
    feature = "storage",
    feature = "registry",
    feature = "identity",
    feature = "socketio",
    feature = "totp"
))]
const DOORS: usize = 111;
