//! The canonical signed two-field PushDrop the reference's identity token
//! and contact token are (#327, #544): `assertCanonicalIdentityTokenScript`
//! (`ts-stack@edf6e03` `IdentityClient.ts:123-147`) and
//! `assertCanonicalSignedPushDrop` (`ContactsManager.ts:218-241`), the same
//! five chunks.

use crate::script::LockingScript;

/// The opcode a canonical push of `len` bytes opens with
/// (`identityPushOpcode`, `IdentityClient.ts:123-128`; `pushOpcode`,
/// `ContactsManager.ts:218-223`).
fn push_opcode(len: usize) -> u8 {
    match len {
        0..=75 => len as u8,
        76..=0xff => 0x4c,
        0x100..=0xffff => 0x4d,
        _ => 0x4e,
    }
}

/// The key pushed, `OP_CHECKSIG`, the two fields each pushed by its
/// canonical opcode, `OP_2DROP`, and nothing else; `fields` are the two the
/// decode read.
pub(super) fn is_canonical_signed_pushdrop(script: &LockingScript, fields: &[Vec<u8>]) -> bool {
    let chunks = script.chunks();
    fields.len() == 2
        && chunks.len() == 5
        && chunks[0].op == 33
        && chunks[0].data.as_ref().is_some_and(|d| d.len() == 33)
        && chunks[1].op == 0xac
        && chunks[2].op == push_opcode(fields[0].len())
        && chunks[3].op == push_opcode(fields[1].len())
        && chunks[4].op == 0x6d
}
