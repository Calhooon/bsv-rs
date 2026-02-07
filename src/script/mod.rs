//! # BSV Script
//!
//! Bitcoin Script construction, parsing, execution, validation, and templates.
//!
//! This module provides:
//! - Opcode constants (`op` module)
//! - Script chunks (`ScriptChunk`)
//! - Script parsing and serialization (`Script`)
//! - Locking and unlocking script types (`LockingScript`, `UnlockingScript`)
//! - Script number encoding (`script_num` module)
//! - Script evaluation errors (`evaluation_error` module)
//! - Spend validation (`Spend`)
//! - Script templates (`template` module, `templates` module)
//!
//! # Example: Building Scripts
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
//!
//! # Example: Using Templates
//!
//! ```rust,ignore
//! use bsv_sdk::script::templates::P2PKH;
//! use bsv_sdk::script::template::{ScriptTemplate, SignOutputs};
//! use bsv_sdk::primitives::ec::PrivateKey;
//!
//! let private_key = PrivateKey::random();
//! let pubkey_hash = private_key.public_key().hash160();
//!
//! // Create locking script
//! let template = P2PKH::new();
//! let locking = template.lock(&pubkey_hash)?;
//!
//! // Or from an address
//! let locking = P2PKH::lock_from_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")?;
//! ```

pub mod address;
pub mod bip276;
pub mod chunk;
pub mod evaluation_error;
pub mod locking_script;
pub mod op;
#[allow(clippy::module_inception)]
pub mod script;
pub mod script_num;
pub mod spend;
pub mod template;
pub mod templates;
pub mod transaction;
pub mod unlocking_script;

// Re-exports for convenience
pub use address::Address;
pub use bip276::*;
pub use chunk::ScriptChunk;
pub use evaluation_error::{ExecutionContext, ScriptEvaluationError};
pub use locking_script::LockingScript;
pub use script::Script;
pub use script_num::ScriptNum;
pub use spend::{Spend, SpendParams};
pub use template::{ScriptTemplate, ScriptTemplateUnlock, SignOutputs, SigningContext};
pub use transaction::{
    SimpleUtxo, SpendValidation, TransactionContext, TransactionInputContext,
    TransactionOutputContext, UtxoProvider,
};
pub use unlocking_script::UnlockingScript;
