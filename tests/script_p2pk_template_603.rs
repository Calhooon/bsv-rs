//! #603: the P2PK template (`src/script/templates/p2pk.rs`) and the template
//! helpers (`src/script/template.rs`) on the sibling's vectors.
//!
//! The rule source is the sibling `bsv-script-lean` at `5dc337e1`: a P2PK
//! lock is `<pubkey> OP_CHECKSIG`, its key read by `decodePubKey`
//! (`lean/BsvScript/Crypto/Secp256k1.lean:151-175`: tags `02`/`03` with 32
//! bytes after them, `04`/`06`/`07` with 64, nothing else) and judged under
//! STRICTENC by `isCompressedOrUncompressedPubKey`
//! (`lean/BsvScript/Ops/Crypto.lean:77-84`: `02`/`03` at 33 bytes, `04` at
//! 65) in `checkSigOp` (`:133-156`). The vectors are the sibling's
//! `corpus/crypto/cases.jsonl` entries (sha256 `1159327d…`), copied by id with
//! their recorded verdicts (every column `valid`); their signer key is
//! `key("a")`, sha256 of the label (`harness/src/bin/crypto_cases.rs:100-103`),
//! and their signatures are deterministic (RFC 6979), so the template signing
//! the unsigned transaction must write the recorded unlocking script byte for
//! byte. The reference has no P2PK template at `ts-stack@edf6e03`
//! (`packages/sdk/src/script/templates/`: P2PKH, PushDrop, RPuzzle), nor
//! go-sdk at `2ca481c` (`transaction/template/`: p2pkh, pushdrop).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxOutput};
use bsv_rs::primitives::ec::PrivateKey;
use bsv_rs::primitives::from_hex;
use bsv_rs::primitives::hash::sha256;
use bsv_rs::script::template::{
    build_p2pkh_unlocking_script, create_transaction_signature, ScriptTemplate, SignOutputs,
    SigningContext,
};
use bsv_rs::script::templates::P2PK;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};
use bsv_rs::Error;

/// `corpus/crypto/cases.jsonl` `crypto-00001` (`crypto/p2pk`, "P2PK
/// compressed, ALL|FORKID"; post-Chronicle, consensus, version 2): valid.
const CRYPTO_00001_TX: &str = "0200000001f726794d4e752e6687628380ae0cb41cda2f6e6310a4d0251a5f751c70c7240c0000000048473044022007b3983e3a8fba529c9652227847c03360424703b98d8ce25c240ccfaf2a1c07022044bb823327ba9a79745b32b59f354d9ef3aa347dd26dcde07d7d41f01aad5ca141ffffffff010100000000000000015100000000";
const CRYPTO_00001_LOCK: &str =
    "21035935f55855afd8c999bdb5a8d08ae8e73b7618e200d4ef7687cd55d3c2e4c9d7ac";

/// `crypto-00002` (`crypto/p2pk`, "P2PK uncompressed key"): valid.
const CRYPTO_00002_TX: &str = "02000000016c41fc1df7867594677fcf5e2b37264bdc0fe186b0ed99caa5a4ef426d2ac2680000000049483045022100f900b9ff5c1014b80a00259332c242c16c8a0ee8e778a95ba6e2a7685462cf6a02206f1f781389c566514c851e5e7b414af9f174f2e0fde8b0f032e644757236d3cc41ffffffff010100000000000000015100000000";
const CRYPTO_00002_LOCK: &str = "41045935f55855afd8c999bdb5a8d08ae8e73b7618e200d4ef7687cd55d3c2e4c9d795cdf9ba5e4bbd35ab8e601fdbe36930344b1ac41c4acb7daa187334d5bc1723ac";

/// `crypto-00015` (`crypto/p2pkh`, "P2PKH"): valid.
const CRYPTO_00015_TX: &str = "0200000001582bf0aac761cb6184ec00de1150eb30f06d53855abe8c8465cb54cc4a2c267f000000006a473044022060bfbe55131913e2d7cc47d0ea2c0072620ba751e45d64136dbff53d30f8cfab02205dd613fcf8a4bb1d5265f319559d0f43c18fda6a19dba2813b080764f216a7464121035935f55855afd8c999bdb5a8d08ae8e73b7618e200d4ef7687cd55d3c2e4c9d7ffffffff010100000000000000015100000000";
const CRYPTO_00015_LOCK: &str = "76a914801e4d614345b36e18ecd0676f86a3bf2d100e6b88ac";

/// Every corpus coin carries 1000 satoshis.
const SATOSHIS: u64 = 1000;

/// The corpus's signer, `key("a")` (`crypto_cases.rs:100-103`).
fn key_a() -> PrivateKey {
    PrivateKey::from_bytes(&sha256(b"bsv-script-lean/corpus/crypto/key/a")).unwrap()
}

/// The corpus transaction with its one input's unlocking script emptied: the
/// transaction the corpus signed (`crypto_cases.rs:155-158`, `spend_tx` with
/// no unlock). Version (4), the input count (1), the outpoint (36), then the
/// script's length byte (below `0xfd` in every entry here) and the script.
fn unsigned(tx_hex: &str) -> Vec<u8> {
    let tx = from_hex(tx_hex).unwrap();
    assert_eq!(tx[4], 1, "one input");
    let len = tx[41] as usize;
    assert!(len < 0xfd);
    let mut out = tx[..41].to_vec();
    out.push(0);
    out.extend_from_slice(&tx[42 + len..]);
    out
}

/// The recorded unlocking script of input 0.
fn recorded_unlock(tx_hex: &str) -> Vec<u8> {
    parse_transaction(&from_hex(tx_hex).unwrap())
        .unwrap()
        .inputs[0]
        .script
        .clone()
}

/// The verdict of input 0 of `tx` spending `lock` under the block word of the
/// entry's era (post-Chronicle, consensus), as the corpus's `spec` column
/// judges it.
fn verdict(tx_hex: &str, lock: &LockingScript, unlock: &UnlockingScript) -> Result<bool, String> {
    let tx = parse_transaction(&from_hex(tx_hex).unwrap()).unwrap();
    let input = &tx.inputs[0];
    let outputs: Vec<TxOutput> = tx
        .outputs
        .iter()
        .map(|o| TxOutput {
            satoshis: o.satoshis,
            script: o.script.clone(),
        })
        .collect();
    let mut spend = Spend::new(SpendParams {
        source_txid: input.txid,
        source_output_index: input.output_index,
        source_satoshis: SATOSHIS,
        locking_script: lock.clone(),
        transaction_version: tx.version,
        other_inputs: vec![],
        outputs,
        input_index: 0,
        unlocking_script: unlock.clone(),
        input_sequence: input.sequence,
        lock_time: tx.locktime,
        memory_limit: None,
        work_limit: None,
    });
    spend.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
    spend.validate().map_err(|e| e.message)
}

/// The key a P2PK lock pushes: the bytes after its push opcode, before
/// `OP_CHECKSIG`.
fn key_of(lock_hex: &str) -> Vec<u8> {
    let lock = from_hex(lock_hex).unwrap();
    lock[1..lock.len() - 1].to_vec()
}

/// `decodePubKey` reads `02`/`03` with 32 bytes and `04` with 64
/// (`Secp256k1.lean:156-175`): the template locks both forms of the corpus key
/// as the corpus wrote them, `<pubkey> OP_CHECKSIG` with a direct push of 33 or
/// 65 bytes (`crypto_cases.rs:174-178`). Kills `p2pk.rs:116:47` (`!=` to `==`:
/// the 65-byte key refused), `p2pk.rs:126:35` (the guard `false`) and
/// `p2pk.rs:126:48` (`==` to `!=`): each refuses `crypto-00002`'s key.
#[test]
fn the_lock_writes_both_key_forms_as_the_corpus_crypto_p2pk_crypto_00001_00002() {
    for (id, lock_hex) in [
        ("crypto-00001", CRYPTO_00001_LOCK),
        ("crypto-00002", CRYPTO_00002_LOCK),
    ] {
        let lock = P2PK::new()
            .lock(&key_of(lock_hex))
            .unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(lock.to_hex(), lock_hex, "{id}");
    }
}

/// The template signs the corpus's unsigned spend with `key("a")` under
/// ALL|FORKID and writes the recorded unlocking script byte for byte (a minimal
/// push of the DER signature and the scope byte, `crypto_cases.rs:111-124`,
/// `:182-185`, `:190-193`), and the template's own lock and unlock spend valid,
/// as every column of the corpus records for both entries (`checkSigOp`,
/// `Ops/Crypto.lean:133-156`). Kills `template.rs:286:9`
/// (`ScriptTemplateUnlock::sign` answering an empty script: the sibling's
/// `corpus/signer` moved 97 template rows under it, `signer-p2pk-00001` the
/// first), and the three lock mutants above on `crypto-00002`.
#[test]
fn the_unlock_signs_the_corpus_spend_and_it_verifies_crypto_p2pk_crypto_00001_00002() {
    let a = key_a();
    for (id, tx_hex, lock_hex) in [
        ("crypto-00001", CRYPTO_00001_TX, CRYPTO_00001_LOCK),
        ("crypto-00002", CRYPTO_00002_TX, CRYPTO_00002_LOCK),
    ] {
        let lock = P2PK::new().lock(&key_of(lock_hex)).unwrap();
        let raw = unsigned(tx_hex);
        let unlock = P2PK::unlock(&a, SignOutputs::All, false)
            .sign(&SigningContext::new(&raw, 0, SATOSHIS, lock.as_script()))
            .unwrap();
        assert_eq!(unlock.to_binary(), recorded_unlock(tx_hex), "{id}");
        assert_eq!(verdict(tx_hex, &lock, &unlock), Ok(true), "{id}");
    }
}

/// `decodePubKey` pairs each tag with one length (`Secp256k1.lean:156-175`),
/// and under STRICTENC `isCompressedOrUncompressedPubKey`
/// (`Ops/Crypto.lean:77-84`) refuses `02`/`03` at 65 bytes and `04` at 33
/// (`SCRIPT_ERR_PUBKEYTYPE`, `:93`): the template refuses a key whose tag its
/// length does not carry. The keys are the corpus's, retagged as the corpus
/// builds its hybrid key from the same bytes (`crypto_cases.rs:260-263`); each
/// as a raw lock, spent by the entry's recorded unlock, is refused under the
/// block word as the corpus records `crypto-00014`'s retagged key (every column
/// `invalid`, `SCRIPT_ERR_PUBKEYTYPE`), in the words of this crate's branch of
/// that predicate (`src/script/spend/crypto.rs:397-407`, its three arms the
/// predicate's three: `04`, `02`/`03`, any other tag). Kills
/// `p2pk.rs:125:28` (the guard `true`: `02`/`03` at 65 accepted) and
/// `p2pk.rs:126:35` (the guard `true`: `04`/`06`/`07` at 33 accepted).
#[test]
fn the_lock_refuses_a_tag_its_length_does_not_carry_crypto_p2pk_crypto_00001_00002() {
    let compressed = key_of(CRYPTO_00001_LOCK);
    let uncompressed = key_of(CRYPTO_00002_LOCK);
    let mut cases = Vec::new();
    for tag in [0x02u8, 0x03] {
        let mut k = uncompressed.clone();
        k[0] = tag;
        cases.push((
            "crypto-00002",
            CRYPTO_00002_TX,
            k,
            "The compressed public key must be 33 bytes.",
        ));
    }
    for (tag, words) in [
        (0x04u8, "The non-compressed public key must be 65 bytes."),
        (0x06, "The public key is in an unknown format."),
        (0x07, "The public key is in an unknown format."),
    ] {
        let mut k = compressed.clone();
        k[0] = tag;
        cases.push(("crypto-00001", CRYPTO_00001_TX, k, words));
    }
    for (id, tx_hex, k, words) in cases {
        assert_eq!(
            P2PK::new().lock(&k).map(|l| l.to_hex()),
            Err(Error::InvalidPublicKey(
                "Invalid public key prefix".to_string()
            )),
            "{id} retagged {:02x} at {} bytes",
            k[0],
            k.len()
        );
        let mut raw = vec![k.len() as u8];
        raw.extend_from_slice(&k);
        raw.push(0xac);
        let lock = LockingScript::from_binary(&raw).unwrap();
        let unlock = UnlockingScript::from_binary(&recorded_unlock(tx_hex)).unwrap();
        assert_eq!(
            verdict(tx_hex, &lock, &unlock),
            Err(words.to_string()),
            "{id} retagged {:02x} at {} bytes",
            k[0],
            k.len()
        );
    }
}

/// `build_p2pkh_unlocking_script` writes `<sig> <compressed pubkey>`, the
/// unlock the corpus writes for its P2PKH entry (`crypto_cases.rs:272-291`:
/// the signature's minimal push, then `key("a")`'s compressed key), over the
/// digest the context computes for the lock under ALL|FORKID; the spend is
/// valid as every column records. Kills `template.rs:325:5` (the helper
/// answering an empty script).
#[test]
fn the_p2pkh_helper_writes_the_corpus_unlock_crypto_p2pkh_crypto_00015() {
    let a = key_a();
    let lock = LockingScript::from_hex(CRYPTO_00015_LOCK).unwrap();
    let raw = unsigned(CRYPTO_00015_TX);
    let sighash = SigningContext::new(&raw, 0, SATOSHIS, lock.as_script())
        .compute_sighash(0x41)
        .unwrap();
    let tx_sig = create_transaction_signature(&a, &sighash, 0x41).unwrap();
    let unlock = build_p2pkh_unlocking_script(&tx_sig, &a);
    assert_eq!(unlock.to_binary(), recorded_unlock(CRYPTO_00015_TX));
    assert_eq!(verdict(CRYPTO_00015_TX, &lock, &unlock), Ok(true));
}
