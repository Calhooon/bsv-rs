# BSV Script Module
> Bitcoin Script construction, parsing, execution, validation, and templates for BSV transactions

## Overview

This module provides complete Bitcoin Script functionality for the BSV SDK:
- Opcode definitions and lookup utilities
- Script parsing, serialization, and construction
- Specialized types for locking (output) and unlocking (input) scripts
- Script number encoding for stack operations
- Full script interpreter with spend validation
- Script templates for common transaction types (P2PKH, R-Puzzle)
- Transaction interface traits for Script/Transaction module integration

Compatible with the TypeScript and Go SDKs through shared opcode values, serialization formats, and execution semantics.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; submodule declarations and public re-exports |
| `op.rs` | Opcode constants and name/value lookup functions |
| `chunk.rs` | `ScriptChunk` type representing individual script elements |
| `script.rs` | Core `Script` class with parsing, serialization, and builder methods |
| `locking_script.rs` | `LockingScript` newtype wrapper for output scripts (scriptPubKey) |
| `unlocking_script.rs` | `UnlockingScript` newtype wrapper for input scripts (scriptSig) |
| `script_num.rs` | `ScriptNum` utilities for Bitcoin script number encoding |
| `evaluation_error.rs` | `ScriptEvaluationError` with full execution context for debugging |
| `spend.rs` | `Spend` interpreter for validating transaction spends |
| `template.rs` | `ScriptTemplate` trait, `SigningContext`, and signing utilities |
| `transaction.rs` | Transaction interface traits for future Transaction module |
| `templates/mod.rs` | Templates module declarations |
| `templates/p2pkh.rs` | P2PKH (Pay-to-Public-Key-Hash) template |
| `templates/rpuzzle.rs` | R-Puzzle template for knowledge-based locking |

## Key Exports

```rust
// Core script types
pub use chunk::ScriptChunk;
pub use script::Script;
pub use locking_script::LockingScript;
pub use unlocking_script::UnlockingScript;
pub use script_num::ScriptNum;

// Evaluation types
pub use evaluation_error::{ExecutionContext, ScriptEvaluationError};
pub use spend::{Spend, SpendParams};

// Template types
pub use template::{ScriptTemplate, ScriptTemplateUnlock, SignOutputs, SigningContext};

// Transaction interface types
pub use transaction::{
    SimpleUtxo, SpendValidation, TransactionContext, TransactionInputContext,
    TransactionOutputContext, UtxoProvider,
};
```

## Core Types

### Opcodes (`op` module)

All Bitcoin Script opcodes defined as `u8` constants. Key opcodes:

```rust
// Push values: OP_0, OP_1..OP_16, OP_1NEGATE, OP_PUSHDATA1/2/4
// Control: OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_VERIFY, OP_RETURN
// Stack: OP_DUP, OP_DROP, OP_SWAP, OP_OVER, OP_NIP, etc.
// BSV re-enabled: OP_CAT, OP_SPLIT, OP_NUM2BIN, OP_BIN2NUM, OP_MUL, OP_DIV, OP_MOD
// Crypto: OP_HASH160, OP_HASH256, OP_CHECKSIG, OP_CHECKMULTISIG

pub fn name_to_opcode(name: &str) -> Option<u8>      // "OP_DUP" -> Some(0x76)
pub fn opcode_to_name(op: u8) -> Option<&'static str>   // 0x76 -> Some("OP_DUP")
```

### ScriptChunk

```rust
pub struct ScriptChunk { pub op: u8, pub data: Option<Vec<u8>> }
impl ScriptChunk {
    pub fn new_opcode(op: u8) -> Self
    pub fn new_push(data: Vec<u8>) -> Self      // Auto-selects push opcode
    pub fn is_push_data(&self) -> bool
    pub fn to_asm(&self) -> String
}
```

### Script

Core script type with lazy parsing and caching:

```rust
impl Script {
    // Constructors
    pub fn new() -> Self
    pub fn from_chunks(chunks: Vec<ScriptChunk>) -> Self
    pub fn from_asm(asm: &str) -> Result<Self>      // "OP_DUP OP_HASH160 <hex>..."
    pub fn from_hex(hex: &str) -> Result<Self>
    pub fn from_binary(bin: &[u8]) -> Result<Self>

    // Serialization
    pub fn to_asm(&self) -> String
    pub fn to_hex(&self) -> String
    pub fn to_binary(&self) -> Vec<u8>

    // Builder methods (chainable)
    pub fn write_opcode(&mut self, op: u8) -> &mut Self
    pub fn write_bin(&mut self, bin: &[u8]) -> &mut Self
    pub fn write_number(&mut self, num: i64) -> &mut Self
    pub fn write_script(&mut self, script: &Script) -> &mut Self

    // Manipulation
    pub fn remove_codeseparators(&mut self) -> &mut Self
    pub fn find_and_delete(&mut self, script: &Script) -> &mut Self

    // Inspection
    pub fn chunks(&self) -> Vec<ScriptChunk>
    pub fn len(&self) -> usize
    pub fn is_push_only(&self) -> bool
}
```

### LockingScript / UnlockingScript

Newtype wrappers for output scripts (scriptPubKey) and input scripts (scriptSig):

```rust
pub struct LockingScript(Script);
pub struct UnlockingScript(Script);

// Both provide: new(), from_chunks(), from_asm(), from_hex(), from_binary(),
// from_script(), as_script(), into_script(), and delegate serialization methods
// LockingScript::is_locking_script() -> true
// UnlockingScript::is_unlocking_script() -> true
```

### ScriptNum

Utilities for Bitcoin Script number encoding (little-endian sign-magnitude):

```rust
impl ScriptNum {
    pub fn from_bytes(bytes: &[u8], require_minimal: bool) -> Result<BigNumber>
    pub fn to_bytes(value: &BigNumber) -> Vec<u8>
    pub fn is_minimally_encoded(bytes: &[u8]) -> bool
    pub fn cast_to_bool(bytes: &[u8]) -> bool
}
```

### ScriptEvaluationError

Rich error type capturing full execution state at failure:

```rust
pub struct ScriptEvaluationError {
    pub message: String,
    pub source_txid: String,
    pub source_output_index: u32,
    pub context: ExecutionContext,  // UnlockingScript or LockingScript
    pub program_counter: usize,
    pub stack: Vec<Vec<u8>>,
    pub alt_stack: Vec<Vec<u8>>,
    pub if_stack: Vec<bool>,
}
```

### Spend

Full script interpreter for validating transaction spends:

```rust
pub struct SpendParams {
    pub source_txid: [u8; 32],
    pub source_output_index: u32,
    pub source_satoshis: u64,
    pub locking_script: LockingScript,
    pub transaction_version: i32,
    pub other_inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub input_index: usize,
    pub unlocking_script: UnlockingScript,
    pub input_sequence: u32,
    pub lock_time: u32,
    pub memory_limit: Option<usize>,  // Default: 32MB
}

impl Spend {
    pub fn new(params: SpendParams) -> Self
    pub fn validate(&mut self) -> Result<bool, ScriptEvaluationError>
    pub fn step(&mut self) -> Result<bool, ScriptEvaluationError>
}
```

## Script Templates

### ScriptTemplate Trait & Types

```rust
pub trait ScriptTemplate {
    fn lock(&self, params: &[u8]) -> Result<LockingScript>;
}

pub enum SignOutputs { All, None, Single }  // SIGHASH flags

pub struct SigningContext<'a> {
    pub raw_tx: &'a [u8],
    pub input_index: usize,
    pub source_satoshis: u64,
    pub locking_script: &'a Script,
}
impl SigningContext {
    pub fn compute_sighash(&self, scope: u32) -> Result<[u8; 32]>
}

pub struct ScriptTemplateUnlock {
    pub fn sign(&self, context: &SigningContext) -> Result<UnlockingScript>
    pub fn estimate_length(&self) -> usize
}
```

### P2PKH (Pay-to-Public-Key-Hash)

The most common Bitcoin transaction type. Locking script: `OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG`

```rust
impl P2PKH {
    pub fn new() -> Self
    pub fn lock_from_address(address: &str) -> Result<LockingScript>
    pub fn unlock(private_key: &PrivateKey, sign_outputs: SignOutputs, anyone_can_pay: bool) -> ScriptTemplateUnlock
    pub fn sign_with_sighash(private_key: &PrivateKey, sighash: &[u8; 32], sign_outputs: SignOutputs, anyone_can_pay: bool) -> Result<UnlockingScript>
}
impl ScriptTemplate for P2PKH {
    fn lock(&self, params: &[u8]) -> Result<LockingScript>  // params = 20-byte pubkey hash
}
```

### RPuzzle

Knowledge-based locking using ECDSA R-value. Anyone who knows the K-value can spend:

```rust
pub enum RPuzzleType { Raw, Sha1, Sha256, Hash256, Ripemd160, Hash160 }

impl RPuzzle {
    pub fn new(puzzle_type: RPuzzleType) -> Self
    pub fn compute_r_from_k(k: &BigNumber) -> Result<[u8; 32]>
    pub fn unlock(k: &BigNumber, private_key: &PrivateKey, sign_outputs: SignOutputs, anyone_can_pay: bool) -> ScriptTemplateUnlock
    pub fn sign_with_sighash(k: &BigNumber, private_key: &PrivateKey, sighash: &[u8; 32], sign_outputs: SignOutputs, anyone_can_pay: bool) -> Result<UnlockingScript>
}
impl ScriptTemplate for RPuzzle {
    fn lock(&self, params: &[u8]) -> Result<LockingScript>  // params = R value or hash
}
```

## Transaction Interface Traits

Traits for future Transaction module integration:

```rust
pub trait TransactionInputContext {
    fn source_txid(&self) -> &[u8; 32];
    fn source_output_index(&self) -> u32;
    fn sequence(&self) -> u32;
    fn source_satoshis(&self) -> Option<u64>;
    fn source_locking_script(&self) -> Option<&LockingScript>;
    fn unlocking_script(&self) -> &UnlockingScript;
}

pub trait TransactionOutputContext {
    fn satoshis(&self) -> u64;
    fn locking_script(&self) -> &LockingScript;
}

pub trait TransactionContext {
    type Input: TransactionInputContext;
    type Output: TransactionOutputContext;
    fn version(&self) -> i32;
    fn inputs(&self) -> &[Self::Input];
    fn outputs(&self) -> &[Self::Output];
    fn lock_time(&self) -> u32;
}

pub trait SpendValidation: TransactionContext {
    fn validate_input(&self, index: usize) -> Result<bool, ScriptEvaluationError>;
    fn validate_all_inputs(&self) -> Result<(), ScriptEvaluationError>;
}

pub trait UtxoProvider {
    fn get_utxo(&self, txid: &[u8; 32], output_index: u32) -> Option<(u64, LockingScript)>;
}
```

## Usage Examples

### Building Scripts

```rust
use bsv_sdk::script::{Script, LockingScript, op};

// From ASM or hex
let script = Script::from_asm("OP_DUP OP_HASH160 <20-byte-hex> OP_EQUALVERIFY OP_CHECKSIG")?;
let script = Script::from_hex("76a914...")?;

// Builder pattern
let mut script = Script::new();
script.write_opcode(op::OP_DUP)
    .write_opcode(op::OP_HASH160)
    .write_bin(&pubkey_hash)
    .write_opcode(op::OP_EQUALVERIFY)
    .write_opcode(op::OP_CHECKSIG);
```

### Using Templates

```rust
use bsv_sdk::script::templates::P2PKH;
use bsv_sdk::script::{ScriptTemplate, SignOutputs, SigningContext};

// Create locking script
let locking = P2PKH::lock_from_address("1BvBMSEY...")?;

// Create unlock and sign
let unlock = P2PKH::unlock(&private_key, SignOutputs::All, false);
let context = SigningContext::new(&raw_tx, 0, 100_000, locking.as_script());
let unlocking = unlock.sign(&context)?;
```

## Implementation Notes

- **Lazy Parsing**: Scripts cache raw bytes; chunks parsed on demand
- **PUSHDATA**: Uses smallest encoding (direct push, PUSHDATA1/2/4)
- **BSV Opcodes**: Supports re-enabled opcodes (CAT, SPLIT, MUL, DIV, MOD, etc.)
- **Disabled Opcodes**: OP_2MUL, OP_2DIV, OP_VER, OP_VERIF, OP_VERNOTIF

### Script Interpreter Rules

- **Memory Limit**: 32MB default for stack usage
- **Minimal Push**: Required for data pushes
- **Push-Only Unlocking**: Unlocking scripts can only contain pushes
- **Low-S Signatures**: Required for all signatures
- **Clean Stack**: Exactly one true item after execution
- **SIGHASH_FORKID**: Required for all BSV signatures

## Test Vectors

| Vector File | Count | Purpose |
|-------------|-------|---------|
| `spend_valid.json` | 458 | Valid spend executions (all pass) |
| `script_valid.json` | 598 | Valid script parsing |
| `script_invalid.json` | 432 | Invalid scripts that should fail |

## Related Documentation

- `../CLAUDE.md` - Root SDK documentation
- `../primitives/CLAUDE.md` - Primitives module (encoding, hashing)
- `../primitives/bsv/CLAUDE.md` - BSV primitives (sighash, transaction signatures)
