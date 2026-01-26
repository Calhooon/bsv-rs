//! # BSV Script
//!
//! Bitcoin Script construction, parsing, execution, and validation.
//!
//! This module provides:
//! - Opcode constants (`op` module)
//! - Script chunks (`ScriptChunk`)
//! - Script parsing and serialization (`Script`)
//! - Locking and unlocking script types (`LockingScript`, `UnlockingScript`)
//!
//! # Example
//!
//! ```rust
//! use bsv_sdk::script::{Script, LockingScript, op};
//!
//! // Create a P2PKH locking script from ASM
//! let script = Script::from_asm("OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG").unwrap();
//!
//! // Build a script programmatically
//! let mut script = Script::new();
//! script
//!     .write_opcode(op::OP_DUP)
//!     .write_opcode(op::OP_HASH160)
//!     .write_bin(&[0u8; 20])
//!     .write_opcode(op::OP_EQUALVERIFY)
//!     .write_opcode(op::OP_CHECKSIG);
//!
//! // Serialize to hex
//! let hex = script.to_hex();
//!
//! // Convert to a locking script
//! let locking = LockingScript::from_script(script);
//! assert!(locking.is_locking_script());
//! ```

pub mod chunk;
pub mod locking_script;
pub mod op;
#[allow(clippy::module_inception)]
pub mod script;
pub mod unlocking_script;

// Re-exports for convenience
pub use chunk::ScriptChunk;
pub use locking_script::LockingScript;
pub use script::Script;
pub use unlocking_script::UnlockingScript;
