# BSV Script Module
> Bitcoin Script construction, parsing, execution, validation, and templates for BSV transactions

## Overview

This module provides complete Bitcoin Script functionality for the BSV SDK:
- Opcode definitions and lookup utilities
- Script parsing, serialization, and construction
- Specialized types for locking (output) and unlocking (input) scripts
- Script number encoding for stack operations
- Full script interpreter with spend validation
- Script templates for common transaction types (P2PKH, P2PK, Multisig, R-Puzzle, PushDrop)
- Script type detection (P2PKH, P2PK, P2SH, multisig, data, safe data carrier)
- Bitcoin P2PKH address encoding/decoding (Base58Check)
- BIP-276 typed script encoding
- Transaction interface traits for Script/Transaction module integration

Compatible with the TypeScript and Go SDKs through shared opcode values, serialization formats, and execution semantics.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; submodule declarations and public re-exports |
| `op.rs` | Opcode constants (u8) and name/value lookup functions via `LazyLock` HashMaps |
| `chunk.rs` | `ScriptChunk` type representing individual script elements |
| `script.rs` | Core `Script` class with parsing, serialization, builder methods, and type detection |
| `locking_script.rs` | `LockingScript` newtype wrapper for output scripts (scriptPubKey) with `to_address()` |
| `unlocking_script.rs` | `UnlockingScript` newtype wrapper for input scripts (scriptSig) |
| `address.rs` | `Address` type for P2PKH address parsing, creation, and Base58Check encoding |
| `bip276.rs` | BIP-276 typed script encoding (`encode_bip276` / `decode_bip276`) |
| `script_num.rs` | `ScriptNum` utilities for Bitcoin script number encoding |
| `evaluation_error.rs` | `ScriptEvaluationError` with full execution context for debugging |
| `spend.rs` | `Spend` interpreter for validating transaction spends |
| `template.rs` | `ScriptTemplate` trait, `SigningContext`, and signing utilities |
| `transaction.rs` | Transaction interface traits for Transaction module integration |
| `templates/mod.rs` | Templates module declarations and re-exports |
| `templates/p2pkh.rs` | P2PKH (Pay-to-Public-Key-Hash) template |
| `templates/p2pk.rs` | P2PK (Pay-to-Public-Key) template |
| `templates/multisig.rs` | Multisig (M-of-N) template using OP_CHECKMULTISIG |
| `templates/rpuzzle.rs` | R-Puzzle template for knowledge-based locking |
| `templates/pushdrop.rs` | PushDrop template for data envelope scripts with P2PK lock |

## Key Exports

```rust
// Core script types
pub use chunk::ScriptChunk;
pub use script::Script;
pub use locking_script::LockingScript;
pub use unlocking_script::UnlockingScript;
pub use script_num::ScriptNum;

// Address and BIP-276
pub use address::Address;
pub use bip276::*;  // encode_bip276, decode_bip276, BIP276_PREFIX, NETWORK_MAINNET, NETWORK_TESTNET

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

// Templates (via templates module)
pub use templates::{P2PKH, P2PK, Multisig, RPuzzle, RPuzzleType, PushDrop, LockPosition};
```

## Core Types

### Opcodes (`op` module)

All Bitcoin Script opcodes defined as `u8` constants with `LazyLock` HashMaps for lookup:

```rust
// Push values: OP_0, OP_1..OP_16, OP_1NEGATE, OP_PUSHDATA1/2/4
// Control: OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_VERIFY, OP_RETURN
// Stack: OP_DUP, OP_DROP, OP_SWAP, OP_OVER, OP_NIP, OP_PICK, OP_ROLL, etc.
// BSV re-enabled: OP_CAT, OP_SPLIT, OP_NUM2BIN, OP_BIN2NUM, OP_MUL, OP_DIV, OP_MOD
// Bitwise: OP_INVERT, OP_AND, OP_OR, OP_XOR, OP_LSHIFT, OP_RSHIFT
// Crypto: OP_HASH160, OP_HASH256, OP_SHA256, OP_RIPEMD160, OP_SHA1
// Signature: OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
// Expansion NOPs: OP_NOP1..OP_NOP77 (0xb0-0xfc range)

pub fn name_to_opcode(name: &str) -> Option<u8>      // "OP_DUP" -> Some(0x76)
pub fn opcode_to_name(op: u8) -> Option<&'static str>   // 0x76 -> Some("OP_DUP")
```

### ScriptChunk

Represents a single script element (opcode or data push):

```rust
pub struct ScriptChunk { pub op: u8, pub data: Option<Vec<u8>> }

impl ScriptChunk {
    pub fn new_opcode(op: u8) -> Self
    pub fn new_push(data: Vec<u8>) -> Self      // Auto-selects optimal push opcode
    pub fn new(op: u8, data: Option<Vec<u8>>) -> Self
    pub fn is_push_data(&self) -> bool          // True if op <= OP_16
    pub fn to_asm(&self) -> String
}
```

### Script

Core script type with lazy parsing and serialization caching using `RefCell`:

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
    pub fn set_chunk_opcode(&mut self, index: usize, op: u8) -> &mut Self

    // Inspection
    pub fn chunks(&self) -> Vec<ScriptChunk>
    pub fn len(&self) -> usize
    pub fn is_empty(&self) -> bool
    pub fn is_push_only(&self) -> bool
    pub fn is_locking_script(&self) -> bool   // Always false for base Script
    pub fn is_unlocking_script(&self) -> bool // Always false for base Script

    // Script Type Detection
    pub fn is_p2pkh(&self) -> bool             // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    pub fn is_p2pk(&self) -> bool              // <33|65 bytes> OP_CHECKSIG
    pub fn is_p2sh(&self) -> bool              // OP_HASH160 <20> OP_EQUAL
    pub fn is_data(&self) -> bool              // OP_RETURN or OP_FALSE OP_RETURN
    pub fn is_safe_data_carrier(&self) -> bool // OP_FALSE OP_RETURN only (prunable, unspendable)
    pub fn is_multisig(&self) -> Option<(u8, u8)>  // Returns (M, N) if multisig
    pub fn opcode_to_small_int(op: u8) -> Option<u8>  // OP_1..OP_16 -> 1..16
    pub fn extract_pubkey_hash(&self) -> Option<[u8; 20]>  // From P2PKH scripts
    pub fn get_public_key(&self) -> Option<Vec<u8>>        // From P2PK scripts (matches Go PubKey())
    pub fn get_public_key_hex(&self) -> Option<String>     // Hex-encoded (matches Go PubKeyHex())
}
```

### LockingScript / UnlockingScript

Newtype wrappers for output scripts (scriptPubKey) and input scripts (scriptSig):

```rust
pub struct LockingScript(Script);
pub struct UnlockingScript(Script);

// Both provide: new(), from_chunks(), from_asm(), from_hex(), from_binary(),
// from_script(), as_script(), into_script(), to_asm(), to_hex(), to_binary(),
// chunks(), len(), is_empty(), is_push_only()

// Type identification:
// LockingScript::is_locking_script() -> true
// UnlockingScript::is_unlocking_script() -> true

// LockingScript-specific:
impl LockingScript {
    pub fn to_address(&self) -> Option<Address>  // Extracts P2PKH address (mainnet), None for non-P2PKH
}

// Conversions via From trait:
impl From<Script> for LockingScript
impl From<LockingScript> for Script
impl From<Script> for UnlockingScript
impl From<UnlockingScript> for Script
```

### Address

Bitcoin P2PKH address representation with Base58Check encoding:

```rust
pub struct Address {
    pub_key_hash: [u8; 20],  // RIPEMD160(SHA256(compressed_pubkey))
    prefix: u8,               // 0x00 mainnet, 0x6f testnet
}

impl Address {
    pub fn new_from_string(address: &str) -> Result<Self>           // Parse Base58Check address
    pub fn new_from_public_key_hash(hash: &[u8], mainnet: bool) -> Result<Self>
    pub fn new_from_public_key(public_key: &PublicKey, mainnet: bool) -> Result<Self>
    pub fn public_key_hash(&self) -> &[u8]
    pub fn prefix(&self) -> u8
    pub fn is_mainnet(&self) -> bool
    pub fn is_valid_address(address: &str) -> bool                  // Static validation
}

impl Display for Address { ... }   // Base58Check encoding
impl FromStr for Address { ... }   // "1BgGZ9...".parse::<Address>()
```

### BIP-276

Typed bitcoin script encoding (`bitcoin-script:<network><type><script><checksum>`):

```rust
pub const BIP276_PREFIX: &str = "bitcoin-script";
pub const NETWORK_MAINNET: u8 = 1;
pub const NETWORK_TESTNET: u8 = 2;

pub fn encode_bip276(network: u8, script_type: u8, script: &[u8]) -> String
pub fn decode_bip276(encoded: &str) -> Result<(u8, u8, Vec<u8>)>  // -> (network, type, data)
```

Checksum is the first 4 bytes of SHA256d of the payload (everything before the checksum).

### ScriptNum

Utilities for Bitcoin Script number encoding (little-endian sign-magnitude):

```rust
impl ScriptNum {
    pub fn from_bytes(bytes: &[u8], require_minimal: bool) -> Result<BigNumber>
    pub fn to_bytes(value: &BigNumber) -> Vec<u8>
    pub fn is_minimally_encoded(bytes: &[u8]) -> bool
    pub fn cast_to_bool(bytes: &[u8]) -> bool
    pub fn minimally_encode(bytes: &[u8]) -> Vec<u8>
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
    pub stack_mem: usize,
    pub alt_stack_mem: usize,
}

pub enum ExecutionContext { UnlockingScript, LockingScript }
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
    pub fn reset(&mut self)                           // Reset for re-execution
    pub fn validate(&mut self) -> Result<bool, ScriptEvaluationError>
    pub fn step(&mut self) -> Result<bool, ScriptEvaluationError>  // Single instruction
}
```

## Script Templates

### ScriptTemplate Trait & Types

```rust
pub trait ScriptTemplate {
    fn lock(&self, params: &[u8]) -> Result<LockingScript>;
}

pub enum SignOutputs { All, None, Single }  // SIGHASH output flags

pub struct SigningContext<'a> {
    pub raw_tx: &'a [u8],
    pub input_index: usize,
    pub source_satoshis: u64,
    pub locking_script: &'a Script,
}
impl SigningContext<'_> {
    pub fn new(...) -> Self
    pub fn compute_sighash(&self, scope: u32) -> Result<[u8; 32]>
}

pub struct ScriptTemplateUnlock { ... }
impl ScriptTemplateUnlock {
    pub fn sign(&self, context: &SigningContext) -> Result<UnlockingScript>
    pub fn estimate_length(&self) -> usize
}

pub fn compute_sighash_scope(sign_outputs: SignOutputs, anyone_can_pay: bool) -> u32
```

### P2PKH (Pay-to-Public-Key-Hash)

The most common Bitcoin transaction type. Locking script: `OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG`

```rust
impl P2PKH {
    pub fn new() -> Self
    pub fn lock_from_address(address: &str) -> Result<LockingScript>  // Mainnet or testnet
    pub fn unlock(private_key: &PrivateKey, sign_outputs: SignOutputs, anyone_can_pay: bool) -> ScriptTemplateUnlock
    pub fn sign_with_sighash(private_key: &PrivateKey, sighash: &[u8; 32], sign_outputs: SignOutputs, anyone_can_pay: bool) -> Result<UnlockingScript>
}
impl ScriptTemplate for P2PKH {
    fn lock(&self, params: &[u8]) -> Result<LockingScript>  // params = 20-byte pubkey hash
}
```

### P2PK (Pay-to-Public-Key)

Simpler than P2PKH - locks directly to a public key. Locking script: `<pubkey> OP_CHECKSIG`

```rust
impl P2PK {
    pub fn new() -> Self
    pub fn unlock(private_key: &PrivateKey, sign_outputs: SignOutputs, anyone_can_pay: bool) -> ScriptTemplateUnlock
    pub fn sign_with_sighash(private_key: &PrivateKey, sighash: &[u8; 32], sign_outputs: SignOutputs, anyone_can_pay: bool) -> Result<UnlockingScript>
}
impl ScriptTemplate for P2PK {
    fn lock(&self, params: &[u8]) -> Result<LockingScript>  // params = 33-byte compressed or 65-byte uncompressed key
}
```

### Multisig (M-of-N)

Requires M signatures from N public keys. Locking: `OP_M <pubkey1>...<pubkeyN> OP_N OP_CHECKMULTISIG`

```rust
impl Multisig {
    pub fn new(threshold: u8) -> Self
    pub fn lock_from_keys(&self, pubkeys: &[PublicKey]) -> Result<LockingScript>  // Recommended API
    pub fn unlock(signers: &[PrivateKey], sign_outputs: SignOutputs, anyone_can_pay: bool) -> ScriptTemplateUnlock
    pub fn sign_with_sighash(signers: &[PrivateKey], sighash: &[u8; 32], sign_outputs: SignOutputs, anyone_can_pay: bool) -> Result<UnlockingScript>
}
impl ScriptTemplate for Multisig {
    fn lock(&self, params: &[u8]) -> Result<LockingScript>  // params = concatenated 33-byte compressed keys
}
```

Signatures in the unlock must appear in the same order as their corresponding public keys in the lock. The leading `OP_0` in the unlocking script is required by a historical off-by-one bug in OP_CHECKMULTISIG.

### RPuzzle

Knowledge-based locking using ECDSA R-value. Anyone who knows the K-value can spend:

```rust
pub enum RPuzzleType { Raw, Sha1, Sha256, Hash256, Ripemd160, Hash160 }

impl RPuzzleType {
    pub fn hash(self, data: &[u8]) -> Vec<u8>  // Hash data with this type
}

impl RPuzzle {
    pub fn new(puzzle_type: RPuzzleType) -> Self
    pub fn compute_r_from_k(k: &BigNumber) -> Result<[u8; 32]>  // R = (k*G).x
    pub fn unlock(k: &BigNumber, private_key: &PrivateKey, sign_outputs: SignOutputs, anyone_can_pay: bool) -> ScriptTemplateUnlock
    pub fn sign_with_sighash(k: &BigNumber, private_key: &PrivateKey, sighash: &[u8; 32], sign_outputs: SignOutputs, anyone_can_pay: bool) -> Result<UnlockingScript>
}
impl ScriptTemplate for RPuzzle {
    fn lock(&self, params: &[u8]) -> Result<LockingScript>  // params = R value or hash
}
```

### PushDrop

Data envelope template with embedded fields and P2PK lock. Used by token protocols like BSV-20:

```rust
pub enum LockPosition { Before, After }  // Pubkey position relative to data

impl PushDrop {
    pub fn new(locking_public_key: PublicKey, fields: Vec<Vec<u8>>) -> Self
    pub fn with_position(self, position: LockPosition) -> Self
    pub fn lock(&self) -> LockingScript
    pub fn decode(script: &LockingScript) -> Result<Self>  // Parse existing script
    pub fn unlock(private_key: &PrivateKey, sign_outputs: SignOutputs, anyone_can_pay: bool) -> ScriptTemplateUnlock
    pub fn sign_with_sighash(private_key: &PrivateKey, sighash: &[u8; 32], sign_outputs: SignOutputs, anyone_can_pay: bool) -> Result<UnlockingScript>
    pub fn estimate_unlocking_length(&self) -> usize  // 73 bytes (signature only)
}

// Lock-Before pattern: <pubkey> OP_CHECKSIG <field1> <field2> ... OP_2DROP... OP_DROP
// Lock-After pattern:  <field1> <field2> ... OP_2DROP... OP_DROP <pubkey> OP_CHECKSIG
// Unlock pattern: <signature> (no pubkey needed, already in locking script)
```

## Transaction Interface Traits

Traits for Transaction module integration:

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
    fn input(&self, index: usize) -> Option<&Self::Input>;    // Default impl
    fn output(&self, index: usize) -> Option<&Self::Output>;  // Default impl
    fn input_count(&self) -> usize;                           // Default impl
    fn output_count(&self) -> usize;                          // Default impl
}

pub trait SpendValidation: TransactionContext {
    fn validate_input(&self, index: usize) -> Result<bool, Box<ScriptEvaluationError>>;
    fn validate_all_inputs(&self) -> Result<(), Box<ScriptEvaluationError>>;  // Default impl
}

pub trait UtxoProvider {
    fn get_utxo(&self, txid: &[u8; 32], output_index: u32) -> Option<(u64, LockingScript)>;
}

// Simple test implementation
pub struct SimpleUtxo { pub satoshis: u64, pub locking_script: LockingScript }
impl TransactionOutputContext for SimpleUtxo { ... }
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

// Script type detection
if script.is_p2pkh() {
    let hash = script.extract_pubkey_hash();
}
```

### Working with Addresses

```rust
use bsv_sdk::script::Address;

// Parse from string
let addr = Address::new_from_string("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")?;
let addr: Address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH".parse()?;

// Create from public key
let addr = Address::new_from_public_key(&public_key, true)?;  // mainnet
let addr = Address::new_from_public_key_hash(&hash, false)?;  // testnet

// Extract from locking script
let locking = P2PKH::lock_from_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")?;
if let Some(addr) = locking.to_address() {
    println!("Address: {}", addr);
}
```

### BIP-276 Encoding

```rust
use bsv_sdk::script::bip276::{encode_bip276, decode_bip276, NETWORK_MAINNET};

let encoded = encode_bip276(NETWORK_MAINNET, 1, &script_bytes);
// -> "bitcoin-script:0101<hex><checksum>"

let (network, script_type, data) = decode_bip276(&encoded)?;
```

### Using Templates

```rust
use bsv_sdk::script::templates::{P2PKH, P2PK, Multisig, PushDrop, LockPosition};
use bsv_sdk::script::{ScriptTemplate, SignOutputs, SigningContext};

// P2PKH from address
let locking = P2PKH::lock_from_address("1BvBMSEY...")?;

// P2PK from public key
let template = P2PK::new();
let locking = template.lock(&pubkey_compressed)?;

// 2-of-3 Multisig
let template = Multisig::new(2);
let locking = template.lock_from_keys(&[pk1, pk2, pk3])?;

// PushDrop for token data
let fields = vec![b"BSV20".to_vec(), b"transfer".to_vec()];
let pushdrop = PushDrop::new(public_key, fields)
    .with_position(LockPosition::Before);
let locking = pushdrop.lock();
```

### Validating Spends

```rust
use bsv_sdk::script::{Spend, SpendParams, LockingScript, UnlockingScript};

let mut spend = Spend::new(SpendParams {
    source_txid: txid,
    source_output_index: 0,
    source_satoshis: 100_000,
    locking_script: LockingScript::from_asm("OP_DUP OP_HASH160...")?,
    transaction_version: 1,
    other_inputs: vec![],
    outputs: vec![...],
    input_index: 0,
    unlocking_script: UnlockingScript::from_asm("<sig> <pubkey>")?,
    input_sequence: 0xffffffff,
    lock_time: 0,
    memory_limit: None,
});

let valid = spend.validate()?;  // Returns Ok(true) if valid
```

## Implementation Notes

- **Lazy Parsing**: Scripts cache raw bytes; chunks parsed on demand via `ensure_parsed()`
- **Caching**: Raw bytes and hex strings are cached and invalidated on mutation
- **PUSHDATA**: Uses smallest encoding (direct push 0x01-0x4b, PUSHDATA1/2/4)
- **BSV Opcodes**: All BSV re-enabled opcodes supported (CAT, SPLIT, MUL, DIV, MOD, etc.)
- **Disabled Opcodes**: OP_2MUL, OP_2DIV, OP_VER, OP_VERIF, OP_VERNOTIF

### Script Interpreter Rules

- **Memory Limit**: 32MB default for stack usage
- **Element Size**: 1GB max for BSV (unlimited mode)
- **Minimal Push**: Required for data pushes
- **Push-Only Unlocking**: Unlocking scripts can only contain pushes
- **Low-S Signatures**: Required for all signatures (BIP 62)
- **Clean Stack**: Exactly one true item after execution
- **SIGHASH_FORKID**: Required for all BSV signatures

### Configuration Constants (spend.rs)

```rust
const MAX_SCRIPT_ELEMENT_SIZE: usize = 1024 * 1024 * 1024;  // 1GB
const DEFAULT_MEMORY_LIMIT: usize = 32_000_000;              // 32MB
const MAX_MULTISIG_KEY_COUNT: i64 = i32::MAX as i64;
const REQUIRE_MINIMAL_PUSH: bool = true;
const REQUIRE_PUSH_ONLY_UNLOCKING: bool = true;
const REQUIRE_LOW_S_SIGNATURES: bool = true;
const REQUIRE_CLEAN_STACK: bool = true;
```

## Related Documentation

- `../CLAUDE.md` - Root SDK documentation
- `../primitives/CLAUDE.md` - Primitives module (encoding, hashing)
- `../primitives/bsv/CLAUDE.md` - BSV primitives (sighash, transaction signatures)
- `templates/CLAUDE.md` - Templates module documentation
