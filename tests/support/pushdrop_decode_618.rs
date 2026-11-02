//! The #618 vector's site cases (`tests/vectors/pushdrop_decode_618.json`'s
//! `sites`, written by `tests/support/pushdrop_decode_618.mjs`): a key alone
//! and a token without CHECKSIG second at each #537 site, the public
//! `PushDrop::decode` reading each as the reference does, the site refusing
//! it as its reference counterpart does.
#![allow(dead_code)]

use bsv_rs::primitives::to_hex;
use bsv_rs::script::templates::{LockPosition, PushDrop};
use bsv_rs::script::{op, LockingScript, ScriptChunk};
use serde_json::Value;

/// The site's cases, each #537 not-a-point case's two shapes in turn.
pub fn cases(site: &str) -> Vec<Value> {
    let recorded: Value =
        serde_json::from_str(include_str!("../vectors/pushdrop_decode_618.json")).unwrap();
    let site = recorded["sites"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["site"] == site)
        .unwrap();
    site["cases"].as_array().unwrap().clone()
}

/// The case's shape built by this crate's writer from its #537 token (the
/// fields locked before, then the first chunk alone or the second replaced
/// by `OP_1`), asserted to be the script the reference was given; and the
/// public door's reading of it asserted to be the reference's.
pub fn script(case: &Value, from_537: &Value) -> LockingScript {
    assert_eq!(case["from_537"], from_537["name"]);
    let locked =
        PushDrop::decode(&LockingScript::from_hex(from_537["script"].as_str().unwrap()).unwrap())
            .unwrap();
    let before = PushDrop::new(locked.locking_public_key, locked.fields).lock();
    let chunks = before.chunks();
    let shape: Vec<ScriptChunk> = match case["shape"].as_str().unwrap() {
        "key_only" => vec![chunks[0].clone()],
        "no_checksig" => {
            let mut changed = chunks.to_vec();
            changed[1] = ScriptChunk::new_opcode(op::OP_1);
            changed
        }
        shape => panic!("unrecorded shape {shape}"),
    };
    let script = LockingScript::from_chunks(shape);
    assert_eq!(
        script.to_hex(),
        case["locking_script"].as_str().unwrap(),
        "{}",
        case["name"]
    );
    let token = PushDrop::decode(&script).unwrap();
    assert_eq!(token.lock_position, LockPosition::Before);
    let fields: Vec<String> = token.fields.iter().map(|field| to_hex(field)).collect();
    let recorded: Vec<String> = case["decode"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap().to_string())
        .collect();
    assert_eq!(fields, recorded, "{}", case["name"]);
    assert_eq!(
        token.locking_public_key.to_hex(),
        case["decode"]["locking_public_key"].as_str().unwrap()
    );
    script
}
