//! The PushDrop lock with the key's bytes as given (#545).
//!
//! The reference's `lock` pushes the wallet's `getPublicKey` answer as the
//! wallet returned it, `toArray(publicKey, 'hex')` under the opcode
//! `publicKey.length / 2` (`ts-stack@edf6e03`
//! `packages/sdk/src/script/templates/PushDrop.ts:158-175`): a compressed key
//! as 33 bytes, an uncompressed (`04`) or hybrid (`06`/`07`) key as 65, never
//! re-encoded. The wallet sites lock through [`wallet_key_lock`]. One residue,
//! stated: for an odd-length key text the reference's opcode is
//! `length / 2` truncated by its writer (`0x20` before 33 bytes, a script
//! whose first push is cut), where this crate writes the 33 bytes' own push.

use super::pushdrop::{LockPosition, PushDrop};
use crate::script::op::OP_CHECKSIG;
use crate::script::{LockingScript, ScriptChunk};

impl PushDrop {
    /// Creates the locking script with `key_bytes` pushed as the key, as
    /// given, where [`lock`](Self::lock) pushes `locking_public_key`
    /// compressed: the reference's `lock` pushes the wallet's key as the
    /// wallet returned it (`PushDrop.ts:168-169`, #545). The fields, the drops
    /// and the lock position are [`lock`](Self::lock)'s. Crate-visible: the
    /// reference has one `lock`, taking the key as text, so this is a port
    /// helper for the wallet sites, not a second public constructor.
    pub(crate) fn lock_with_key_bytes(&self, key_bytes: &[u8]) -> LockingScript {
        let mut lock = vec![
            ScriptChunk::new_push(key_bytes.to_vec()),
            ScriptChunk::new_opcode(OP_CHECKSIG),
        ];
        let mut fields: Vec<ScriptChunk> = self
            .fields
            .iter()
            .map(|field| Self::create_minimally_encoded_chunk(field))
            .collect();
        Self::add_drop_operations(&mut fields, self.fields.len());
        let chunks = match self.lock_position {
            LockPosition::Before => {
                lock.extend(fields);
                lock
            }
            LockPosition::After => {
                fields.extend(lock);
                fields
            }
        };
        LockingScript::from_chunks(chunks)
    }
}

/// The lock-before PushDrop of a wallet's `getPublicKey` answer: the key read
/// by `PublicKey::from_hex` (its refusal unchanged) and pushed as the bytes
/// the text decodes to by the reference's `toArray(_, 'hex')` (#545).
#[cfg(any(feature = "kvstore", feature = "identity", feature = "registry"))]
pub(crate) fn wallet_key_lock(key_hex: &str, fields: Vec<Vec<u8>>) -> crate::Result<LockingScript> {
    let key = crate::primitives::PublicKey::from_hex(key_hex)?;
    let bytes = crate::primitives::ec::public_key_forms::reference_hex(key_hex)?;
    Ok(PushDrop::new(key, fields).lock_with_key_bytes(&bytes))
}

#[cfg(test)]
#[path = "pushdrop_key_bytes_545_tests.rs"]
mod key_bytes_545_tests;
