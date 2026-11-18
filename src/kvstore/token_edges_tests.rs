//! Every refusal of `decode_and_verify`, at its edge, against the
//! reference's recorded answers (#843's third fold): `tests/vectors/
//! kvstore_token_edges.json`, written by `tests/support/
//! kvstore_token_edges.mjs` from the tokens `record_the_edge_tokens` writes
//! (this crate's writer: `PushDrop`'s script, `KeyDeriver`'s lock,
//! `ProtoWallet`'s signature), each cell's script named by its SHA-256 and
//! judged by `decodeAndVerifyKVStoreToken` at `ts-stack@edf6e03` (the pin)
//! and at the reference's head. The table of the checks, their edges and
//! their parameters is `docs/lanes/fix-843-removals.md`, "The third fold".
#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::primitives::{sha256, PrivateKey};
use crate::script::op::{OP_1, OP_CHECKSIG, OP_DROP, OP_PUSHDATA1};
use crate::script::ScriptChunk;
use crate::wallet::CreateSignatureArgs;

/// The reference's figures as literals (`kvStoreTokenValidation.ts:11`,
/// `:89-90`), never this crate's constants, so a moved bound is a verdict
/// the replay reads and not a script that drifts.
const MIB: usize = 1_048_576;
const PAYLOAD: usize = 1_114_112;

fn controller() -> PrivateKey {
    PrivateKey::from_bytes(&sha256(b"controller")).unwrap()
}

fn other() -> PrivateKey {
    PrivateKey::from_bytes(&sha256(b"other")).unwrap()
}

/// How the last field is written.
#[derive(Clone)]
enum Sig {
    /// The controller's signature over the data fields.
    Honest,
    /// Another key's signature over the same data.
    OtherSigner,
    /// The controller's signature over other data.
    OtherData,
    /// The honest signature with S replaced by n - S.
    HighS,
    /// The honest signature with one byte after it.
    Trailing,
    /// The bytes given.
    Bytes(Vec<u8>),
}

/// The key the script locks with.
#[derive(Clone)]
enum Lock {
    /// The controller's derived key for the signing protocol and key ID.
    Honest,
    /// The derived key for another key ID.
    OtherKeyId,
    /// The derived key at another security level.
    OtherLevel,
    /// The controller's derived key with `for_self` false.
    NotForSelf,
    /// Another controller's derived key.
    OtherController,
}

/// What is done to the canonical script.
#[derive(Clone)]
enum Shape {
    Canonical,
    /// One `OP_DROP` per field in place of the `OP_2DROP`s.
    AllDrops,
    /// One opcode after the drops.
    TrailingOp(u8),
    /// The data field at the index pushed with `OP_PUSHDATA1`.
    PushData1(usize),
    /// The data field at the index pushed directly, never as a small opcode.
    DirectPush(usize),
    /// The lock key pushed as these bytes.
    KeyBytes(Vec<u8>),
}

#[derive(Clone)]
struct Spec {
    data: Vec<Vec<u8>>,
    level: u8,
    name: String,
    key_id: String,
    sig: Sig,
    lock: Lock,
    shape: Shape,
}

fn base() -> Spec {
    Spec {
        data: vec![
            br#"[1,"kvstore"]"#.to_vec(),
            b"k".to_vec(),
            b"v".to_vec(),
            controller().public_key().to_compressed().to_vec(),
        ],
        level: 1,
        name: "kvstore".into(),
        key_id: "k".into(),
        sig: Sig::Honest,
        lock: Lock::Honest,
        shape: Shape::Canonical,
    }
}

impl Spec {
    fn field(mut self, index: usize, bytes: impl Into<Vec<u8>>) -> Self {
        self.data[index] = bytes.into();
        self
    }
    fn protocol(self, text: impl Into<Vec<u8>>) -> Self {
        self.field(0, text)
    }
    /// The protocol text `[level,"name"]`, signed and locked for it.
    fn at(mut self, level: u8, name: &str) -> Self {
        self.level = level;
        self.name = name.into();
        self.protocol(format!("[{level},\"{name}\"]"))
    }
    /// The key field, signed and locked for `id`.
    fn key(mut self, bytes: impl Into<Vec<u8>>, id: &str) -> Self {
        self.key_id = id.into();
        self.field(1, bytes)
    }
    fn tags(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.data.push(bytes.into());
        self
    }
    fn sig(mut self, sig: Sig) -> Self {
        self.sig = sig;
        self
    }
    fn lock(mut self, lock: Lock) -> Self {
        self.lock = lock;
        self
    }
    fn shape(mut self, shape: Shape) -> Self {
        self.shape = shape;
        self
    }

    fn protocol_at(&self, level: u8) -> Protocol {
        Protocol::from_tuple((level, &self.name)).unwrap()
    }

    /// A name the derivation refuses is signed and locked as `[1,"kvstore"]`
    /// would be: every such cell is refused before the lock is judged.
    fn derivable(&self) -> Self {
        let mut spec = self.clone();
        if crate::wallet::validate_protocol_name(&self.name).is_err() {
            spec.level = 1;
            spec.name = "kvstore".into();
        }
        spec
    }

    fn signature(&self, data: &[u8]) -> Vec<u8> {
        let sign = |key: PrivateKey, data: &[u8]| {
            ProtoWallet::new(Some(key))
                .create_signature(CreateSignatureArgs {
                    data: Some(data.to_vec()),
                    protocol_id: self.protocol_at(self.level),
                    key_id: self.key_id.clone(),
                    counterparty: Some(Counterparty::Anyone),
                    ..Default::default()
                })
                .unwrap()
                .signature
        };
        match &self.sig {
            Sig::Honest => sign(controller(), data),
            Sig::OtherSigner => sign(other(), data),
            Sig::OtherData => sign(controller(), &[data, b"w"].concat()),
            Sig::HighS => high_s(&sign(controller(), data)),
            Sig::Trailing => [sign(controller(), data), vec![0]].concat(),
            Sig::Bytes(bytes) => bytes.clone(),
        }
    }

    fn lock_key(&self) -> PublicKey {
        let derive = |key: PrivateKey, level: u8, id: &str, for_self: bool| {
            KeyDeriver::new(Some(key))
                .derive_public_key(
                    &self.protocol_at(level),
                    id,
                    &Counterparty::Anyone,
                    for_self,
                )
                .unwrap()
        };
        let (level, id) = (self.level, self.key_id.as_str());
        match self.lock {
            Lock::Honest => derive(controller(), level, id, true),
            Lock::OtherKeyId => derive(controller(), level, "other", true),
            Lock::OtherLevel => derive(controller(), (level + 1) % 3, id, true),
            Lock::NotForSelf => derive(controller(), level, id, false),
            Lock::OtherController => derive(other(), level, id, true),
        }
    }

    fn script(&self) -> LockingScript {
        let signer = self.derivable();
        let mut fields = self.data.clone();
        fields.push(signer.signature(&self.data.concat()));
        let token = PushDrop::new(signer.lock_key(), fields.clone());
        let canonical = token.lock();
        let mut chunks = canonical.chunks();
        match &self.shape {
            Shape::Canonical => return canonical,
            Shape::AllDrops => {
                chunks.truncate(2 + fields.len());
                chunks.extend(fields.iter().map(|_| ScriptChunk::new_opcode(OP_DROP)));
            }
            Shape::TrailingOp(op) => chunks.push(ScriptChunk::new_opcode(*op)),
            Shape::PushData1(index) => {
                chunks[2 + index] = ScriptChunk::new(OP_PUSHDATA1, Some(fields[*index].clone()));
            }
            Shape::DirectPush(index) => {
                let data = fields[*index].clone();
                chunks[2 + index] = ScriptChunk::new(data.len() as u8, Some(data));
            }
            Shape::KeyBytes(bytes) => return token.lock_with_key_bytes(bytes),
        }
        LockingScript::from_chunks(chunks)
    }
}

/// The DER signature with S replaced by n - S, written as given.
fn high_s(der: &[u8]) -> Vec<u8> {
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    let signature = crate::primitives::Signature::from_der(der).unwrap();
    let s = signature.s();
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = N[i] as i16 - s[i] as i16 - borrow;
        borrow = i16::from(d < 0);
        out[i] = (d + 256 * borrow) as u8;
    }
    let int = |bytes: &[u8]| {
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(31);
        let mut value = bytes[start..].to_vec();
        if value[0] & 0x80 != 0 {
            value.insert(0, 0);
        }
        [vec![0x02, value.len() as u8], value].concat()
    };
    let body = [int(signature.r()), int(&out)].concat();
    [vec![0x30, body.len() as u8], body].concat()
}

/// The secp256k1 field prime plus `k` (k < 2^32), as 32 bytes.
fn p_plus(k: u32) -> Vec<u8> {
    let mut p = vec![0xff; 32];
    p[27] = 0xfe;
    let low = u64::from(u32::from_be_bytes([p[28], p[29], p[30], p[31]])) - 0x3d1 + u64::from(k);
    p[28..32].copy_from_slice(&(low as u32).to_be_bytes());
    assert!(low < 1 << 32);
    p
}

/// `[level,"kvstore"]` written with `spelling` for the level.
fn spelled(spelling: &str) -> Vec<u8> {
    format!("[{spelling},\"kvstore\"]").into_bytes()
}

#[path = "token_edges_cells.rs"]
mod cells;
use cells::cells;

fn hex_sha256(bytes: &[u8]) -> String {
    to_hex(&sha256(bytes))
}

/// This crate's answer, in the vector's form.
fn answer(script: &LockingScript) -> serde_json::Value {
    match decode_and_verify(script) {
        Ok(token) => serde_json::json!({
            "accepted": true,
            "protocol_id_text": token.protocol_id_text,
            "name_sha256": hex_sha256(token.key.as_bytes()),
            "value_sha256": hex_sha256(token.value.as_bytes()),
            "controller": token.controller,
            "tags": token.tags,
        }),
        Err(Error::KvStoreError(words)) => serde_json::json!({ "accepted": false, "words": words }),
        Err(other) => serde_json::json!({ "accepted": false, "native": format!("{other:?}") }),
    }
}

/// Writes every cell's script, hex, to `KVSTORE_EDGES_OUT` for the recorder.
#[test]
#[ignore = "a recorder: KVSTORE_EDGES_OUT=<file>"]
fn record_the_edge_tokens() {
    let out = std::env::var("KVSTORE_EDGES_OUT").unwrap();
    let cells: Vec<serde_json::Value> = cells()
        .into_iter()
        .map(|(row, name, spec)| {
            let script = spec.script();
            serde_json::json!({
                "row": row, "name": name, "hex": script.to_hex(), "this_crate": answer(&script)
            })
        })
        .collect();
    std::fs::write(out, serde_json::to_vec(&cells).unwrap()).unwrap();
}

/// The cells this crate answers otherwise than the pin, each by name with
/// its reason (the stated rows of the lane record's table): both sides
/// refuse every one of them.
const STATED: &[(&str, &str)] = &[
    ("lock_key_hybrid_07", STRICT_KEY),
    ("lock_key_x_p_plus_2", STRICT_KEY),
    ("lock_key_x_all_ff", STRICT_KEY),
    ("controller_x_p_plus_2", STRICT_KEY),
    ("controller_x_all_ff", STRICT_KEY),
    ("protocol_bom_twice", JSON_WORDS),
    ("protocol_no_json", JSON_WORDS),
    ("protocol_truncated", JSON_WORDS),
    ("protocol_trailing_comma", JSON_WORDS),
    ("protocol_level_1e400", JSON_WORDS),
    ("tags_no_json", JSON_WORDS),
    ("lone_surrogate_escape", JSON_WORDS),
    ("tags_bom_twice", JSON_WORDS),
    ("tag_number_1e400", JSON_WORDS),
    ("protocol_depth_128", JSON_DEPTH),
    ("protocol_depth_129", JSON_DEPTH),
    ("tags_depth_128", JSON_DEPTH),
    ("tags_depth_129", JSON_DEPTH),
    ("name_hyphen", DERIVER_WORDS),
    ("name_double_space", DERIVER_WORDS),
    ("name_ends_protocol", DERIVER_WORDS),
    ("name_three_chars_six_bytes", DERIVER_WORDS),
    ("name_short_after_trim", DERIVER_WORDS),
];

/// A key the reference reads (a hybrid key, an x at or above p reduced) is
/// refused at its parse here, the byte path strict (#498's row): the
/// reference refuses the token later, at the envelope or the lock.
const STRICT_KEY: &str = "the byte path's key parse is strict (#498)";
/// A text that is no JSON for `JSON.parse` (and `1e400`, which it reads as
/// `Infinity`) is refused by `serde_json` in its own words.
const JSON_WORDS: &str = "a JSON reader's own words (V8's there, serde_json's here)";
/// A text nested 128 deep or more is refused at `serde_json`'s recursion
/// bound, held so that no text can exhaust the stack (root rule 5), where
/// `JSON.parse` reads it and the reference refuses the value after.
const JSON_DEPTH: &str = "serde_json's recursion bound of 128 (no stack exhausted)";
/// A protocol name the key derivation refuses is refused in the shared
/// deriver's words (`validate_protocol_name`), the words of every door that
/// derives, where the reference's `computeInvoiceNumber` has its own; a
/// three-character name of six bytes is refused for its length there (UTF-16
/// units) and its characters here (bytes).
const DERIVER_WORDS: &str = "the shared key deriver's words";

/// The cells the reference reads and this crate refuses, each with its
/// reason (#843's fourth fold): a tag written with a lone surrogate escape
/// is a string `JSON.parse` holds and `serde_json`'s `String` cannot (the
/// #566 representation residue), refused here in `serde_json`'s words.
const STATED_READ_THERE: &[(&str, &str)] = &[("tag_lone_surrogate_escape", LONE_SURROGATE)];
const LONE_SURROGATE: &str = "a lone surrogate no Rust string holds (#566's residue)";

/// The cells the reference's head answers otherwise than its pin: the head
/// dropped `MAX_TAGS` (`ts-stack@c0453b58`, "Remove fixed GlobalKVStore
/// tag-count caps"), so 33 tags are read there; this crate keeps the pin's.
const HEAD_MOVED: &[&str] = &["tags_33"];

/// Every cell of the vector: its script rebuilt by this crate's writer (its
/// SHA-256 the recorded one) and judged by `decode_and_verify`, the
/// reference pin's verdict and words, or a stated row.
#[test]
fn every_refusal_edge_is_the_reference_answer() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/vectors/kvstore_token_edges.json")).unwrap();
    let recorded = v["cells"].as_array().unwrap();
    let built = cells();
    assert_eq!(recorded.len(), built.len());
    let mut stated = 0;
    let mut read_there = 0;
    for ((row, name, spec), cell) in built.into_iter().zip(recorded) {
        assert_eq!(
            (row, name.as_str()),
            (
                cell["row"].as_str().unwrap(),
                cell["name"].as_str().unwrap()
            )
        );
        let script = spec.script();
        assert_eq!(
            hex_sha256(&script.to_binary()),
            cell["sha256"],
            "{name}: the script drifted"
        );
        let ours = answer(&script);
        let pin = &cell["pin"];
        if let Some((_, reason)) = STATED.iter().find(|(stated, _)| *stated == name) {
            assert_eq!(pin["accepted"], false, "{name}: stated, {reason}");
            assert_eq!(ours["accepted"], false, "{name}: stated, {reason}");
            assert_ne!(ours["words"], pin["words"], "{name}: stated, {reason}");
            stated += 1;
            continue;
        }
        if let Some((_, reason)) = STATED_READ_THERE.iter().find(|(s, _)| *s == name) {
            assert_eq!(pin["accepted"], true, "{name}: stated, {reason}");
            assert_eq!(ours["accepted"], false, "{name}: stated, {reason}");
            read_there += 1;
            continue;
        }
        if pin["accepted"] == true {
            for member in [
                "protocol_id_text",
                "name_sha256",
                "value_sha256",
                "controller",
                "tags",
            ] {
                assert_eq!(ours[member], pin[member], "{name}: {member}");
            }
            assert_eq!(ours["accepted"], true, "{name}");
        } else {
            assert_eq!(
                ours,
                serde_json::json!({ "accepted": false, "words": pin["words"] }),
                "{name}"
            );
        }
    }
    assert_eq!(stated, STATED.len());
    assert_eq!(read_there, STATED_READ_THERE.len());
    let moved: Vec<&str> = recorded
        .iter()
        .filter(|cell| cell.get("head").is_some())
        .map(|cell| cell["name"].as_str().unwrap())
        .collect();
    assert_eq!(moved, HEAD_MOVED);
}
