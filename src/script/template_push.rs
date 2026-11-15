//! The push a standard template holds, read by its bytes.
//!
//! A template's writer pushes 1 to 75 bytes by the one opcode that IS the
//! length (`Script::write_bin`, `ScriptChunk::new_push`), so a template's
//! bytes are fixed by its data: P2PKH is 25 bytes with `0x14` at offset 2,
//! P2SH 23 with `0x14` at offset 1, P2PK a `0x21` or `0x41` push then
//! `OP_CHECKSIG`, and a multisig's keys each a `0x21` or `0x41` push. The
//! classifiers (`Script::is_p2pkh`, `is_p2pk`, `is_p2sh`, `is_multisig`) and
//! the readers built on them (`extract_pubkey_hash`, `get_public_key`,
//! `LockingScript::to_address`) ask this one function for every push they
//! read, so a script that frames the same data by another push opcode is not
//! the template (`tests/script_template_bytes.rs`).

use super::ScriptChunk;

/// The data of `chunk` when it is a push of one of `lens` bytes by the
/// opcode that is its length; `None` for any other chunk.
pub(crate) fn template_push<'a>(chunk: &'a ScriptChunk, lens: &[usize]) -> Option<&'a [u8]> {
    let data = chunk.data.as_deref()?;
    (usize::from(chunk.op) == data.len() && lens.contains(&data.len())).then_some(data)
}
