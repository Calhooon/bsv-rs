//! BRC-56's HMAC key vectors and the minimal-length-key refusal (#148).
//!
//! The vectors are `bsv-blockchain/BRCs` at `5119a9b` (the line's pin since
//! #154), `wallet/0056.md`, read with `git -C ~/bsv/brcs show 5119a9b:wallet/0056.md`: the key is the
//! shared point's X coordinate as exactly 32 bytes (line 66); a sender that
//! drops its leading zero bytes makes another tag (line 73); the inputs at
//! lines 81-85 and the six rows at lines 91-96.
//!
//! `verify_hmac` accepts the 32-byte-key tag only. A tag under the
//! minimal-length key is refused as `Error::HmacMinimalLengthKey`, naming the
//! sender's encoding, and is never accepted; a tag matching neither key is
//! the `WalletError("HMAC is not valid")` it always was.

#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::{from_hex, sha256, to_hex, PrivateKey, PublicKey};
use bsv_rs::wallet::{
    Counterparty, CreateHmacArgs, KeyDeriver, ProtoWallet, Protocol, SecurityLevel, VerifyHmacArgs,
};
use bsv_rs::Error;

/// `wallet/0056.md:81` at `5119a9b`: the root private key, SHA-256 of the
/// label below.
const ROOT_KEY: &str = "f0efba88c117ca2614554bb676d743f413822a31e3c8d70cfcc5fff119d20a07";
const ROOT_LABEL: &str = "BRC-56 HMAC key test vectors: root";
/// `wallet/0056.md:82`: the root public key.
const ROOT_PUB: &str = "035818cd7cc614fea816c8b39eebe6e43cafc635451ec5a873f8757b418aaae91a";
/// `wallet/0056.md:83`: the counterparty public key, its private key SHA-256
/// of the label below.
const COUNTERPARTY_PUB: &str = "03458d551018414b8fe1adbcef2d0afc17e1074bfab3fdde3e1b0750bdde58a9a7";
const COUNTERPARTY_LABEL: &str = "BRC-56 HMAC key test vectors: counterparty";
/// `wallet/0056.md:84`: the protocol, `[2, "hmac key vectors"]`.
const PROTOCOL_NAME: &str = "hmac key vectors";
/// `wallet/0056.md:85`: the data, `4252432d353620484d41432074657374`.
const DATA: &[u8] = b"BRC-56 HMAC test";

/// One row of `wallet/0056.md:91-96`.
struct Row {
    line: u32,
    counterparty_key: bool,
    key_id: &'static str,
    leading_zero_bytes: usize,
    hmac_key: &'static str,
    tag: &'static str,
    /// `None` where the table says `same`.
    minimal_tag: Option<&'static str>,
}

const ROWS: [Row; 6] = [
    Row {
        line: 91,
        counterparty_key: false,
        key_id: "k0",
        leading_zero_bytes: 0,
        hmac_key: "b1273850ff41cee365a4d590e3c323822129f66c5a9b2eacb8b9e790e000e396",
        tag: "99455edf49ea2156f6109466fb344c3027d4c14485581a50bf5ff0850328a269",
        minimal_tag: None,
    },
    Row {
        line: 92,
        counterparty_key: false,
        key_id: "k95",
        leading_zero_bytes: 1,
        hmac_key: "000c82ac78dc853158f24883ccfda332be6ba34f821765357cc4ef2a190a28fd",
        tag: "054a0fc6a3b0e21b31dc627fb1d645f2eea4127dff71eac95b1f71b7cb13c787",
        minimal_tag: Some("3a968ebaa25eaa4b1cfad138f96105bb1eb738defc066d01e37b32595900d48b"),
    },
    Row {
        line: 93,
        counterparty_key: false,
        key_id: "k91538",
        leading_zero_bytes: 2,
        hmac_key: "00009dc11102cc72eca3c6e4e232460eac581e9b2cee1bb35c395b635d3f6393",
        tag: "ff43127cb1ddfbd19776d01ce34b8c3e83916b51fa55ac045a355b731e6999f5",
        minimal_tag: Some("5a8b84fb2a7d9ce7b12feb8319f14dc6169e0be005a1a8e58d9b9b2d1ac29d47"),
    },
    Row {
        line: 94,
        counterparty_key: true,
        key_id: "k0",
        leading_zero_bytes: 0,
        hmac_key: "1896e0210afac8dbb4ca3bd4ea25c8377d0352ab83e62fe6ffabeca78c1a6113",
        tag: "986af579272261acf3e890bb1650124b0dfbc0b1edacda202f8ed0c3b876c072",
        minimal_tag: None,
    },
    Row {
        line: 95,
        counterparty_key: true,
        key_id: "k497",
        leading_zero_bytes: 1,
        hmac_key: "001829e1dd58fc2c45b6edcbb277eecdecbab1c884b42fd779e131fea5881b45",
        tag: "aa39467c48a116ffb00fd7b56ff158bd9af37d1298df2f031c0125458c30f574",
        minimal_tag: Some("3a5ea2bf5bcc9bc1461041737384bf258b0a3e5a475fb281a19c2972cdb1cff6"),
    },
    Row {
        line: 96,
        counterparty_key: true,
        key_id: "k29510",
        leading_zero_bytes: 2,
        hmac_key: "0000a52a35523175d6c181e90f463a27cdbf70f4ecf055e912d6fc24ac7d0e3c",
        tag: "2677674035f1aaac3219b3405cf8569ec07922a3ceffbd4f7c8a7948b2d3c553",
        minimal_tag: Some("ecca769bb17b1775ce8ae4326fe721ba0f7ba272300741bf4a5b068cf0cebd60"),
    },
];

fn protocol() -> Protocol {
    Protocol::new(SecurityLevel::Counterparty, PROTOCOL_NAME)
}

fn root_key() -> PrivateKey {
    PrivateKey::from_hex(ROOT_KEY).unwrap()
}

fn counterparty(row: &Row) -> Counterparty {
    if row.counterparty_key {
        Counterparty::Other(PublicKey::from_hex(COUNTERPARTY_PUB).unwrap())
    } else {
        Counterparty::Self_
    }
}

fn tag(hex: &str) -> [u8; 32] {
    from_hex(hex).unwrap().try_into().unwrap()
}

fn verify(wallet: &ProtoWallet, row: &Row, hmac: [u8; 32]) -> bsv_rs::Result<bool> {
    wallet
        .verify_hmac(VerifyHmacArgs {
            data: DATA.to_vec(),
            hmac,
            protocol_id: protocol(),
            key_id: row.key_id.to_string(),
            counterparty: Some(counterparty(row)),
            ..Default::default()
        })
        .map(|r| r.valid)
}

#[test]
fn the_brc56_inputs_derive_from_their_labels() {
    assert_eq!(to_hex(&sha256(ROOT_LABEL.as_bytes())), ROOT_KEY);
    assert_eq!(root_key().public_key().to_hex(), ROOT_PUB);
    let counterparty = PrivateKey::from_bytes(&sha256(COUNTERPARTY_LABEL.as_bytes())).unwrap();
    assert_eq!(counterparty.public_key().to_hex(), COUNTERPARTY_PUB);
    assert_eq!(to_hex(DATA), "4252432d353620484d41432074657374");
}

#[test]
fn the_six_hmac_keys_are_the_32_byte_x_coordinate_with_its_leading_zeros() {
    let deriver = KeyDeriver::new(Some(root_key()));
    for row in &ROWS {
        let key = deriver
            .derive_symmetric_key(&protocol(), row.key_id, &counterparty(row))
            .unwrap();
        assert_eq!(to_hex(key.as_bytes()), row.hmac_key, "line {}", row.line);
        let zeros = key.as_bytes().iter().take_while(|b| **b == 0).count();
        assert_eq!(zeros, row.leading_zero_bytes, "line {}", row.line);
    }
}

#[test]
fn create_hmac_reproduces_the_six_brc56_tags() {
    let wallet = ProtoWallet::new(Some(root_key()));
    for row in &ROWS {
        let created = wallet
            .create_hmac(CreateHmacArgs {
                data: DATA.to_vec(),
                protocol_id: protocol(),
                key_id: row.key_id.to_string(),
                counterparty: Some(counterparty(row)),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(to_hex(&created.hmac), row.tag, "line {}", row.line);
    }
}

#[test]
fn verify_hmac_accepts_the_six_32_byte_key_tags() {
    let wallet = ProtoWallet::new(Some(root_key()));
    for row in &ROWS {
        assert_eq!(
            verify(&wallet, row, tag(row.tag)),
            Ok(true),
            "line {}",
            row.line
        );
    }
    // The counterparty, verifying under the root's identity key, agrees.
    let other = PrivateKey::from_bytes(&sha256(COUNTERPARTY_LABEL.as_bytes())).unwrap();
    let other = ProtoWallet::new(Some(other));
    for row in ROWS.iter().filter(|r| r.counterparty_key) {
        let valid = other
            .verify_hmac(VerifyHmacArgs {
                data: DATA.to_vec(),
                hmac: tag(row.tag),
                protocol_id: protocol(),
                key_id: row.key_id.to_string(),
                counterparty: Some(Counterparty::Other(root_key().public_key())),
                ..Default::default()
            })
            .map(|r| r.valid);
        assert_eq!(valid, Ok(true), "line {}", row.line);
    }
}

#[test]
fn a_minimal_length_key_tag_is_refused_naming_the_senders_encoding() {
    let wallet = ProtoWallet::new(Some(root_key()));
    let mut refused = 0;
    for row in ROWS.iter().filter(|r| r.leading_zero_bytes > 0) {
        let minimal = tag(row.minimal_tag.unwrap());
        let err = verify(&wallet, row, minimal).unwrap_err();
        assert_eq!(
            err,
            Error::HmacMinimalLengthKey {
                leading_zero_bytes: row.leading_zero_bytes
            },
            "line {}",
            row.line
        );
        let text = err.to_string();
        assert!(text.contains("minimal-length key"), "{text}");
        assert!(text.starts_with("HMAC is not valid"), "{text}");
        refused += 1;
    }
    assert_eq!(refused, 4);
}

#[test]
fn a_minimal_length_key_tag_is_refused_through_the_async_interface() {
    use bsv_rs::wallet::WalletInterface;
    let wallet = ProtoWallet::new(Some(root_key()));
    let row = &ROWS[5];
    let args = VerifyHmacArgs {
        data: DATA.to_vec(),
        hmac: tag(row.minimal_tag.unwrap()),
        protocol_id: protocol(),
        key_id: row.key_id.to_string(),
        counterparty: Some(counterparty(row)),
        ..Default::default()
    };
    let result = futures::executor::block_on(WalletInterface::verify_hmac(
        &wallet,
        args,
        Some("brc56.test"),
    ));
    assert_eq!(
        result.unwrap_err(),
        Error::HmacMinimalLengthKey {
            leading_zero_bytes: 2
        }
    );
}

#[test]
fn a_key_with_no_leading_zero_has_one_encoding_and_no_refusal_path() {
    // The table reads `same` for k0 and counterparty k0 (lines 91 and 94):
    // the minimal-length key is the 32-byte key, so its tag is the accepted
    // one and there is nothing to refuse.
    let wallet = ProtoWallet::new(Some(root_key()));
    for row in ROWS.iter().filter(|r| r.leading_zero_bytes == 0) {
        assert_eq!(row.minimal_tag, None, "line {}", row.line);
        assert_eq!(
            verify(&wallet, row, tag(row.tag)),
            Ok(true),
            "line {}",
            row.line
        );
    }
}

#[test]
fn a_tag_matching_neither_key_stays_hmac_is_not_valid() {
    let wallet = ProtoWallet::new(Some(root_key()));
    let not_valid = Err(Error::WalletError("HMAC is not valid".to_string()));
    for row in &ROWS {
        let mut wrong = tag(row.tag);
        wrong[31] ^= 1;
        assert_eq!(verify(&wallet, row, wrong), not_valid, "line {}", row.line);
        // A row's minimal tag under another row's key is no refusal either.
        let other = &ROWS[(ROWS.iter().position(|r| r.line == row.line).unwrap() + 1) % 6];
        if let Some(minimal) = other.minimal_tag {
            assert_eq!(
                verify(&wallet, row, tag(minimal)),
                not_valid,
                "line {}",
                row.line
            );
        }
    }
}
