//! #634, the adversarial door read and its fold: the answers beyond the
//! chunk count that the IF depth decides. Until the fold this crate clamped
//! the depth at 0 and, after a stray `OP_ENDIF`, folded an `OP_RETURN` and the
//! rest of the script into one chunk; the reference (`ts-stack@edf6e03`
//! `Script.ts:608,616`) reads the depth as -1 and the rest as chunks, as the
//! node's `GetOp` (bitcoin-sv v1.2.3 `6504a3a` `script.h:165-198`), which
//! counts no depth, reads them. The chunker now reads as the reference does,
//! and four answers are the reference's recording
//! (`tests/vectors/script_if_depth_consequences_634.json`, written by
//! `tests/support/script_if_depth_consequences_634.mjs` under Node 22):
//! `PushDrop::decode`'s fields, the registry reader's refusal words, the ASM
//! round trip, and the work charged for a CHECKSIG's scriptCode (a work
//! budget the clamp made decline now reaches the node's verdict).
#![cfg(feature = "registry")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::{to_hex, PrivateKey};
use bsv_rs::registry::{decode_and_verify_registry_token, DefinitionType};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::{LockingScript, Script, Spend, SpendParams, UnlockingScript};
use serde_json::Value;

fn recorded() -> Value {
    let recorded: Value = serde_json::from_str(include_str!(
        "vectors/script_if_depth_consequences_634.json"
    ))
    .unwrap();
    assert_eq!(recorded["runtime"].as_str().unwrap(), "node v22.18.0");
    recorded
}

fn shape(id: &str) -> Value {
    recorded()["shapes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == id)
        .unwrap_or_else(|| panic!("unrecorded shape {id}"))
        .clone()
}

const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn push(data: &[u8]) -> Script {
    let mut s = Script::new();
    s.write_bin(data);
    s
}

/// `<G> OP_CHECKSIG "abcd" OP_ENDIF OP_RETURN "hello" OP_2DROP`, by this
/// crate's writer.
fn pushdrop_shape() -> String {
    let mut s = Script::new();
    s.write_bin(&bsv_rs::primitives::from_hex(G).unwrap());
    s.write_opcode(0xac);
    s.write_bin(b"abcd");
    s.write_opcode(0x68);
    s.write_opcode(0x6a);
    s.write_bin(b"hello");
    s.write_opcode(0x6d);
    s.to_hex()
}

/// Four fields, as the reference reads them (the stray `OP_ENDIF` and the
/// `OP_RETURN` as empty ones, then `hello`, `PushDrop.ts:96-115`); with the
/// clamp this crate read three, the last the folded rest, `OP_2DROP` included.
#[test]
fn pushdrop_decode_reads_the_references_four_fields_after_a_stray_endif_634() {
    let s = shape("pushdrop-field-endif-return-field-2drop");
    assert_eq!(s["hex"].as_str().unwrap(), pushdrop_shape());
    let decoded = PushDrop::decode(&LockingScript::from_hex(&pushdrop_shape()).unwrap()).unwrap();
    let ours: Vec<String> = decoded.fields.iter().map(|f| to_hex(f)).collect();
    assert_eq!(ours, ["61626364", "", "", "68656c6c6f"]);
    let theirs: Vec<&str> = s["ts"]["pushdrop"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert_eq!(theirs, ["61626364", "", "", "68656c6c6f"]);
}

/// A basket token with four data fields, `OP_ENDIF OP_RETURN`, a signature
/// field and the drops: seven fields (the count asked), the envelope refused
/// in the reference's words (`decodeCanonicalPushDrop`); with the clamp this
/// crate counted six and refused the count.
#[test]
fn the_registry_reader_refuses_the_envelope_in_the_references_words_634() {
    let mut s = Script::new();
    s.write_bin(&bsv_rs::primitives::from_hex(G).unwrap());
    s.write_opcode(0xac);
    for field in [b"a", b"b", b"c", b"d"] {
        s.write_bin(field);
    }
    s.write_opcode(0x68);
    s.write_opcode(0x6a);
    s.write_bin(b"sigsigsig");
    for op in [0x6d, 0x6d, 0x6d, 0x75] {
        s.write_opcode(op);
    }
    let recorded = recorded();
    assert_eq!(
        recorded["registry_basket"]["hex"].as_str().unwrap(),
        s.to_hex()
    );
    let ours = decode_and_verify_registry_token(
        DefinitionType::Basket,
        &LockingScript::from_hex(&s.to_hex()).unwrap(),
    )
    .unwrap_err()
    .to_string();
    assert_eq!(
        ours,
        "registry error: PushDrop token must use the canonical PushDrop envelope"
    );
    assert_eq!(
        recorded["registry_basket"]["ts"]["error"].as_str().unwrap(),
        "PushDrop token must use the canonical PushDrop envelope"
    );
}

/// After a stray `OP_ENDIF` the `OP_RETURN` is an opcode and the ASM is the
/// reference's, reading back to the same bytes; with the clamp `to_asm` wrote
/// the folded rest's hex alone (`OP_ENDIF 51`), which read back as a push
/// (`680151`).
#[test]
fn the_asm_after_a_stray_endif_is_the_references_and_reads_back_634() {
    for id in [
        "endif-return-op1",
        "endif-return-push",
        "p2pkh-then-endif-return-op1",
        "pushdrop-field-endif-return-field-2drop",
    ] {
        let s = shape(id);
        let hex = s["hex"].as_str().unwrap();
        let asm = Script::from_hex(hex).unwrap().to_asm();
        assert_eq!(asm, s["ts"]["asm"].as_str().unwrap(), "{id}");
        assert_eq!(Script::from_asm(&asm).unwrap().to_hex(), hex, "{id}");
        assert_eq!(s["ts"]["asm_back_to_hex"].as_str().unwrap(), hex, "{id}");
    }
}

fn spend(lock: &Script, unlock: &Script, work_limit: Option<u64>) -> Result<bool, (bool, String)> {
    let mut s = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_hex(&lock.to_hex()).unwrap(),
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_hex(&unlock.to_hex()).unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit,
    });
    s.validate()
        .map_err(|e| (e.resource_limit.is_some(), e.message))
}

/// `<pk> OP_CHECKSIG OP_ENDIF OP_RETURN <sig>x200` under `<sig>`, a sighash
/// type without FORKID (the default mode's original digest): the CHECKSIG
/// runs before the stray `OP_ENDIF`, and its scriptCode is cleaned of the
/// signature's push (`CleanupScriptCode`, `interpreter.cpp:255-263`). The
/// node's `FindAndDelete` walks `GetOp` with no depth (`script.h:202-224`)
/// and deletes all two hundred pushes; this crate's `find_and_delete` walks
/// the chunks, which after the stray `OP_ENDIF` are the pushes, and deletes
/// them too. With the clamp they were the folded `OP_RETURN`'s data and were
/// kept, and the longer scriptCode's hashing made a work budget of 1000
/// decline (`ScriptResourceLimit`); now the script is judged unbalanced.
#[test]
fn a_work_budget_reaches_the_unbalanced_verdict_the_nodes_scriptcode_gives_634() {
    let key = PrivateKey::from_hex(&"11".repeat(32)).unwrap();
    let mut sig = key.sign(&[7u8; 32]).unwrap().to_low_s().to_der();
    sig.push(0x01);
    let pk = key.public_key().to_compressed();
    let tail = |copies: usize| {
        let mut s = Script::new();
        s.write_bin(&pk);
        s.write_opcode(0xac);
        s.write_opcode(0x68);
        s.write_opcode(0x6a);
        for _ in 0..copies {
            s.write_script(&push(&sig));
        }
        s
    };
    let lock = tail(200);
    let unlock = push(&sig);

    let mut code = Script::from_hex(&lock.to_hex()).unwrap();
    code.find_and_delete(&push(&sig));
    assert_eq!(code.to_hex(), tail(0).to_hex(), "the pushes are deleted");

    let unbalanced = "OP_ENDIF requires a preceeding OP_IF.".to_string();
    assert_eq!(
        spend(&lock, &unlock, None),
        Err((false, unbalanced.clone()))
    );
    assert_eq!(
        spend(&tail(0), &unlock, Some(1000)),
        Err((false, unbalanced.clone()))
    );
    assert_eq!(spend(&lock, &unlock, Some(1000)), Err((false, unbalanced)));
}
