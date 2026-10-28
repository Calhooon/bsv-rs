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
| `script_num.rs` | `ScriptNum` utilities for Bitcoin script number encoding (one buffer per encoding, exactly one byte reserved for the sign; the decode reads the sign with the magnitude, no negated copy: #348) |
| `evaluation_error.rs` | `ScriptEvaluationError` with full execution context for debugging; `ScriptResource`, `ScriptResourceLimit` and its `Display`, the one place the resource sentences live (#228) |
| `spend/` | `Spend` interpreter for validating transaction spends, one module per opcode group (the map: "The interpreter's layout" below) |
| `flags.rs` | `ScriptFlags` (the node's 32-bit verification flag word, bitcoin-sv v1.2.2's bit values and names; `block(era)` the consensus word, `standard(era)` the mempool word), `ProtocolEra`, `ScriptFlagsError` |
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
pub use evaluation_error::{ExecutionContext, ScriptEvaluationError, ScriptResource, ScriptResourceLimit};
pub use flags::{ProtocolEra, ScriptFlags, ScriptFlagsError};
pub use spend::{Spend, SpendParams, TxSpendParams};

// Template types
pub use template::{chronicle_unlocking_script_code, ScriptTemplate, ScriptTemplateUnlock, SignOutputs, SigningContext};

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
// Push values: OP_0/OP_FALSE, OP_1..OP_16, OP_1NEGATE, OP_PUSHDATA1/2/4
// Direct push: OP_DATA_1..OP_DATA_75 (push exactly N bytes)
// Control: OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_VERIFY, OP_RETURN
// Stack: OP_DUP, OP_DROP, OP_SWAP, OP_OVER, OP_NIP, OP_PICK, OP_ROLL, etc.
// BSV re-enabled: OP_CAT, OP_SPLIT, OP_NUM2BIN, OP_BIN2NUM, OP_MUL, OP_DIV, OP_MOD
// Bitwise: OP_INVERT, OP_AND, OP_OR, OP_XOR, OP_LSHIFT, OP_RSHIFT
// Crypto: OP_HASH160, OP_HASH256, OP_SHA256, OP_RIPEMD160, OP_SHA1
// Signature: OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
// Expansion NOPs: OP_NOP1..OP_NOP77 (0xb0-0xfc range)
// Template matching: OP_SMALLDATA, OP_SMALLINTEGER, OP_PUBKEYS, OP_PUBKEYHASH, OP_PUBKEY

pub fn name_to_opcode(name: &str) -> Option<u8>        // "OP_DUP" -> Some(0x76)
pub fn opcode_to_name(op: u8) -> Option<&'static str>  // 0x76 -> Some("OP_DUP")
```

Note: `OP_FALSE`/`OP_0` renders as `"0"` in ASM output, `OP_1NEGATE` renders as `"-1"`. The value-to-name map uses BSV names for dual-named opcodes (e.g., `OP_SPLIT` not `OP_SUBSTR`).

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
// Implements Default (OP_0), Debug, Clone, PartialEq, Eq
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
    pub fn truncated_push(&self) -> Option<usize>   // the first push cut short of its declared bytes (BAD_OPCODE when reached)
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
// Implements Default, Debug, Clone, PartialEq (by binary), Eq
```

### LockingScript / UnlockingScript

Newtype wrappers providing type safety for output scripts (scriptPubKey) and input scripts (scriptSig):

```rust
pub struct LockingScript(Script);   // is_locking_script() -> true
pub struct UnlockingScript(Script); // is_unlocking_script() -> true

// Both provide: new(), from_chunks(), from_asm(), from_hex(), from_binary(),
// from_script(), as_script(), into_script(), to_asm(), to_hex(), to_binary(),
// chunks(), len(), is_empty(), is_push_only()
// Both implement: Default, Debug, Clone, PartialEq, Eq, From<Script>

// LockingScript-specific:
impl LockingScript {
    pub fn to_address(&self) -> Option<Address>  // Extracts P2PKH address (mainnet), None for non-P2PKH
}
```

### Address

Bitcoin P2PKH address with Base58Check encoding (mainnet `0x00`, testnet `0x6f`):

```rust
impl Address {
    pub fn new_from_string(address: &str) -> Result<Self>
    pub fn new_from_public_key_hash(hash: &[u8], mainnet: bool) -> Result<Self>
    pub fn new_from_public_key(public_key: &PublicKey, mainnet: bool) -> Result<Self>
    pub fn public_key_hash(&self) -> &[u8]
    pub fn prefix(&self) -> u8
    pub fn is_mainnet(&self) -> bool
    pub fn is_valid_address(address: &str) -> bool
}
// Implements Display (Base58Check), FromStr, Debug, Clone, PartialEq, Eq
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

`from_bytes` reads the element in place (no copy of the operand, the sign bit cleared in the
digits) and `to_bytes` sizes its one allocation up front, the sign byte's room included;
`try_to_bytes` (crate-internal) is its fallible form, the interpreter's (#374).

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
    pub memory_limit: Option<usize>,  // the LOCAL budget: None = uncapped (default mode, the reference's Spend, #331) or 100 MB on the node's count (under a word); Some(n) the caller's
}

// 0.4.4: one transaction shared by the spends of all its inputs (bsv-low #591)
pub struct TxSpendParams {
    pub transaction: Arc<TxSighashCache>,  // inputs, outputs, version, lock time, the BIP-143 midstates once per transaction
    pub input_index: usize,
    pub source_satoshis: u64,
    pub locking_script: LockingScript,
    pub unlocking_script: UnlockingScript,
    pub memory_limit: Option<usize>,
}

impl Spend {
    pub fn new(params: SpendParams) -> Self          // the TypeScript SDK's default mode
    pub fn with_transaction(params: TxSpendParams) -> Result<Self>  // nothing copied per input; Err if the index names no input
    pub fn set_flags(&mut self, flags: ScriptFlags)  // the node's word: every rule re-derived at the reference's site under its version gate
    pub fn flags(&self) -> Option<ScriptFlags>
    pub fn set_require_minimal(&mut self, require: bool)    // overrides, also after set_flags
    pub fn set_require_push_only(&mut self, require: bool)  // overrides, also after set_flags
    pub fn set_utxo_after_chronicle(&mut self, after: bool)  // the coin's era: all ten opcodes and a word's number length; hash gate independent (#397)
    pub fn memory_limit(&self) -> usize                      // the local budget in force (0.3.30)
    pub fn stack_memory_policy(&self) -> Option<usize>       // the mempool path's verdict figure in force (0.3.30)
    pub fn set_stack_memory_policy(&mut self, bytes: usize)  // the node's -maxstackmemoryusagepolicy, 0 = none (0.3.30)
    pub fn stack_memory_consensus(&self) -> Option<usize>    // the block path's verdict figure in force (#38)
    pub fn set_stack_memory_consensus(&mut self, bytes: usize)  // the node's -maxstackmemoryusageconsensus, 0 = none (#38)
    pub fn reset(&mut self)
    pub fn validate(&mut self) -> Result<bool, ScriptEvaluationError>  // refuses a word `check` refuses first
    pub fn step(&mut self) -> Result<bool, ScriptEvaluationError>  // Single instruction
}
```

Two ways to run it. Without a word: strict for version ≤ 1 (MINIMALDATA, LOW_S,
CLEANSTACK, NULLDUMMY), relaxed for version ≥ 2, push-only unlocking scripts at
every version, no NULLFAIL (ts-sdk `isRelaxed()`). With a word: `ScriptFlags::block(era)`
is what a mining node applies, `ScriptFlags::standard(era)` what a relaying node with
default policy applies; NULLFAIL, MINIMALIF, DISCOURAGE_UPGRADABLE_NOPS and
COMPRESSED_PUBKEYTYPE exist only under a word. A consensus oracle selects the block
word. The gates, their sites in bitcoin-sv v1.2.2 and what is not modeled are the
table on `ScriptFlags` in `flags.rs`; the seven witness transactions are
`tests/script_flags_witnesses.rs`.

The memory budget (0.3.30, bsv-rs#30). `memory_limit` is LOCAL: exhausting it is a
`ScriptResourceLimit`, never a verdict, and `Some(n)` wins in every mode. In the default
mode `None` is uncapped, as the reference's `Spend` is (`Spend.ts:295-296` at `edf6e03`;
#331, the keeper's ruling of 2026-10-27; 32 MB until then), and `Some(n)` is `n` bytes for
each stack apart, the bytes alone (`Transaction::verify` passes the caller's budget, its
third parameter). Uncapped, an element the allocator refuses is a decline, its limit the
bytes both stacks held and those the step holds off them (its popped operands), every element allocated fallibly; the 1 GiB element bound holds at
a push, `OP_CAT`, `OP_NUM2BIN` and the numeric left shift, and at an arithmetic result as a
decline (#374, `arithmetic_room.rs`): `BigNumber` allocates infallibly, so before an operand
is decoded a result whose least length passes the bound (only `OP_MUL`'s can pass its
operands by more than a byte) is declined from the operands' bytes, the others' exact length
judged after; in every mode the step's peak, when 64 KiB or more, is asked of the allocator
first (`try_reserve_exact`, released), its refusal a decline: 6 times the operands' bytes for
`OP_MUL`, 12 for `OP_DIV` and `OP_MOD`, 2 for the rest (measured at most 5.12, 10.0 and 1.0:
the decode reads the element without a copy, the arithmetic is owned, the encoding sized up
front); a number's read (1.5 times its bytes) and the numeric shifts' results are asked the
same way, and every encoded number is allocated fallibly. The default mode reads a number as
the reference does (`reference_read.rs`, the keeper's word of 2026-10-27): an operand whose
magnitude passes 536,870,888 bits, V8's longest string at `ts-stack@edf6e03` under Node 22
(`BigNumber.ts:450`), is invalid at its read, `Invalid string length`, a verdict, after the
minimal-encoding check, and a result past the figure is invalid at its push in the same words
where the reference builds it through `toString(2)`: `OP_ADD`, `OP_SUB`, `OP_1ADD`, `OP_1SUB`
(`BigNumber.ts:771-781`) and `OP_LSHIFTNUM` (`Spend.ts:1066`, judged before the shift
allocates; past 2^30 bits in the words of V8's `BigInt` cap, `Maximum BigInt size exceeded`,
the reference's shift throwing before its string), a caller's budget declining
the push first (the keeper's word of 21:5xZ;
`OP_MUL`'s and `OP_2MUL`'s pushed, as the reference's `mul` writes no string); under a word
the node's number length decides. A memory budget bounds memory, never time: `work_limit` does. Under a word the count is the
node's (`LimitedStack`: one budget over both stacks, `STACK_ELEMENT_OVERHEAD` = 32
bytes per element, every growth charged before it happens, an unlocking script's alt
stack left charged) and `None` selects 100 MB (`WORD_MEMORY_LIMIT`, the node's policy
default); on the mempool path the node's stack memory policy is a verdict besides
(`Stack size limit exceeded: …`, `SCRIPT_ERR_STACK_SIZE`), and `OP_NUM2BIN`'s size is
bounded by `INT32_MAX` (`SCRIPT_ERR_PUSH_SIZE`). On the block path a node's budget
is its operator's mandatory `-maxstackmemoryusageconsensus` (bitcoin-sv v1.2.3 does not
start without it, `src/bitcoind.cpp:140-157`; 0 = `INT64_MAX`,
`src/configscriptpolicy.cpp:280-287`), no constant, so the local budget declines above
100 MB; `memory_limit: Some(X)` models a node set to `X` only as a decline above `X`,
`Some(usize::MAX)` a node run with 0. `set_stack_memory_consensus(X)` (#38) is that
node's verdict on the block path (`Stack size limit exceeded: N bytes, the stack memory
consensus limit is M bytes.`, `limitedstack.cpp:202-205` at v1.2.3), 0 none; the mempool
word and the default mode ignore it, and a policy above it is not clamped (the node
refuses that pair at start). A decline is an `Err`
whose `resource_limit` is `Some`: never read it as invalid. The witnesses are
`tests/script_stack_memory_witness.rs`.

### ScriptFlags / ProtocolEra (`flags.rs`)

```rust
pub enum ProtocolEra { PostGenesis, PostChronicle }   // mainnet 620,538 / 943,816; ProtocolEra::mainnet(height)
pub struct ScriptFlags(u32);                          // the reference's bit values (script_flags.h)
impl ScriptFlags {
    pub const P2SH, STRICTENC, DERSIG, LOW_S, NULLDUMMY, SIGPUSHONLY, MINIMALDATA, DISCOURAGE_UPGRADABLE_NOPS,
              CLEANSTACK, CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY, MINIMALIF, NULLFAIL, COMPRESSED_PUBKEYTYPE,
              SIGHASH_FORKID, GENESIS, UTXO_AFTER_GENESIS, CHRONICLE, UTXO_AFTER_CHRONICLE: Self;
    pub fn block(era: ProtocolEra) -> Self             // 0x3D462F post-Chronicle
    pub fn standard(era: ProtocolEra) -> Self          // 0x3D47FF post-Chronicle
    pub fn bits(self) -> u32
    pub fn from_bits(bits: u32) -> Result<Self, ScriptFlagsError>          // unknown bits refused
    pub fn from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Self, ScriptFlagsError>
    pub fn names(self) -> Vec<&'static str>
    pub fn contains / union / without
    pub fn check(self) -> Result<(), ScriptFlagsError>  // what the interpreter cannot honor, what the reference refuses
    pub fn enforce_non_malleability(self, tx_version: i32) -> bool  // interpreter.cpp:40-44
    pub fn requires_push_only(self, tx_version: i32) -> bool        // interpreter.cpp:2321-2334
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
// Implements Display, Error, Debug, Clone
```

## Script Templates

### ScriptTemplate Trait & Types

```rust
pub trait ScriptTemplate {
    fn lock(&self, params: &[u8]) -> Result<LockingScript>;
}

pub enum SignOutputs { All, None, Single }

pub struct SigningContext<'a> { pub raw_tx, pub input_index, pub source_satoshis, pub locking_script, pub script_code: Option<&'a Script> }
impl<'a> SigningContext<'a> {
    pub fn new(...) -> Self                                        // script_code None: the locking script
    pub fn with_script_code(self, script_code: &'a Script) -> Self // the scriptCode where the CHECKSIG executes
    pub fn compute_sighash(&self, scope: u32) -> Result<[u8; 32]>  // the node's dispatch (0.7.0)
}

// a CHECKSIG inside a post-Chronicle unlocking script: the unlock after its last
// OP_CODESEPARATOR, then the lock (interpreter.cpp:1471-1481)
pub fn chronicle_unlocking_script_code(unlocking_script: &Script, locking_script: &Script) -> Script

pub struct ScriptTemplateUnlock { sign_fn, estimate_length_fn }
impl ScriptTemplateUnlock {
    pub fn sign(&self, context: &SigningContext) -> Result<UnlockingScript>
    pub fn estimate_length(&self) -> usize
}

pub fn compute_sighash_scope(sign_outputs: SignOutputs, anyone_can_pay: bool) -> u32
```

### P2PKH / P2PK / Multisig / RPuzzle / PushDrop

See `templates/CLAUDE.md` for detailed template documentation.

Summary: each template provides `lock()` (via `ScriptTemplate` trait or direct), `unlock()` (returns `ScriptTemplateUnlock`), and `sign_with_sighash()` (direct signing). PushDrop also provides `decode()` and `estimate_unlocking_length()`.

## Transaction Interface Traits

Traits for Transaction module integration (implemented by the `transaction` module):

```rust
pub trait TransactionInputContext   // source_txid, output_index, sequence, satoshis, locking_script, unlocking_script
pub trait TransactionOutputContext  // satoshis, locking_script
pub trait TransactionContext        // version, inputs, outputs, lock_time + default impls
pub trait SpendValidation           // validate_input, validate_all_inputs
pub trait UtxoProvider              // get_utxo(txid, index) -> Option<(u64, LockingScript)>
pub struct SimpleUtxo               // Test implementation of TransactionOutputContext
```

## Implementation Notes

- **Lazy Parsing**: Scripts cache raw bytes; chunks parsed on demand via `ensure_parsed()`
- **Caching**: Raw bytes and hex strings are cached and invalidated on mutation
- **PUSHDATA**: Uses smallest encoding (direct push 0x01-0x4b, PUSHDATA1/2/4)
- **BSV Opcodes**: All BSV re-enabled opcodes supported (CAT, SPLIT, MUL, DIV, MOD, etc.)
- **Default-mode gates (#397, #429)**: without a word all ten opcodes (`OP_2MUL`, `OP_2DIV`, `OP_VER`, `OP_VERIF`, `OP_VERNOTIF`, `0xb3`–`0xb7`) run at every version (`chronicle_opcodes`, `Spend.ts:792-803`, `:827-858`); there is no number-length bound (`:393-401`, the V8 read bound above still applies), while `SIGHASH_CHRONICLE` requires version > 1 (`:586-591`), refused at version 1 in the reference's visible words, `The signature format is invalid.` (the DER wrapper's catch, `:622-625`). The fourth switch is the fork-ID gate: absent without a word, so `0x01` signatures at versions 1 and 2 verify over the original digest; under a word SIGHASH_FORKID is mandatory and implies STRICTENC. Under a word, `UTXO_AFTER_CHRONICLE` gates the opcodes and number length; `CHRONICLE` independently gates the hash type, with the existing refusals. `set_utxo_after_chronicle` overrides only the opcode and number-length gates. Undefined opcodes `0xba`–`0xff` executed, a truncated push reached, a second `OP_ELSE`: failures in every mode.
- **ASM Rendering**: `OP_FALSE`/`OP_0` renders as `"0"`, not `"OP_0"` in `to_asm()`

### The interpreter's layout (`spend/`, #85)

`spend.rs` was one file of 4,419 lines until #85; it is a directory now, split
by the node's opcode groups. A refactor: no verdict, error text, budget or flag
site moved, and every public path is the same (`bsv_rs::script::Spend`,
`bsv_rs::script::spend::{Spend, SpendParams, TxSpendParams}`); the sibling's
harness (`bsv-script-lean` `harness/run --impl bsv-rs --corpus all`) reads the
same before and after. Every handler is an `impl Spend` method in its group's
module, `pub(super)`; the dispatcher is one static `match` in `mod.rs`, each arm a
direct call (no trait object, no table of function pointers, no clone added).

| Module | What lives there |
|--------|------------------|
| `mod.rs` | The crate docs of the two modes and the budgets; `SpendParams`, `TxSpendParams`, the `Spend` struct and its constructors (`new`, `with_transaction`); `reset`, `validate` (the word's `check`, push-only, the balance, CLEANSTACK, the truthy top), `step` (the walk: the work charge, the truncated push, the disabled opcodes, the minimal push of an executed push) and `execute_opcode`, the dispatcher; `error`, the one constructor of `ScriptEvaluationError`; the default mode's `REQUIRE_*` switches |
| `word.rs` | `set_flags` (every switch re-derived from `ScriptFlags::gates`), `flags`, and the setters that override a derived rule (`set_require_minimal`, `set_require_push_only`, `set_utxo_after_chronicle`) |
| `push.rs` | The precomputed `OP_1NEGATE`/`OP_0`-`OP_16` encodings and their handlers, the data pushes, `is_chunk_minimal_push` (MINIMALDATA on a push) |
| `flow.rs` | The NOPs and DISCOURAGE_UPGRADABLE_NOPS, all ten Chronicle opcodes under `chronicle_opcodes` (always on by default, the UTXO bit under a word), `OP_VER` (four raw little-endian bytes), the conditionals (VERIF/VERNOTIF compare exactly four bytes), MINIMALIF and the one-ELSE rule, `OP_VERIFY`, `OP_RETURN`, `is_opcode_disabled`. No CLTV/CSV module: they are NOPs for a post-Genesis UTXO |
| `stack_ops.rs` | The alt-stack moves and the stack opcodes (`OP_2DROP` to `OP_TUCK`, `OP_PICK`/`OP_ROLL`) |
| `splice.rs` | `OP_SIZE`, `OP_CAT`, `OP_SPLIT` (`split_position`, the `INT32_MAX` bound under a word), `OP_NUM2BIN` (`num2bin_size`, the bound before the allocation; `padded`), `OP_BIN2NUM`, the Chronicle `OP_SUBSTR`/`OP_LEFT`/`OP_RIGHT`/`OP_LSHIFTNUM`/`OP_RSHIFTNUM` (`op_chronicle_splice`, the shift counts' two bounds under a word, the default mode's `INT_MAX` refusal in the reference's words before the value is read, #383) and `read_splice_operand` (the `int64` operand under a word) |
| `splice.rs` | `OP_SIZE`, `OP_CAT`, `OP_SPLIT` (`split_position`, the `INT32_MAX` bound under a word), `OP_NUM2BIN` (`num2bin_size`, the bound before the allocation; `padded`), `OP_BIN2NUM`, the Chronicle `OP_SUBSTR`/`OP_LEFT`/`OP_RIGHT`/`OP_LSHIFTNUM`/`OP_RSHIFTNUM` (`op_chronicle_splice`, the shift counts' two bounds) and `read_splice_operand` (the `int64` operand under a word; in the default mode the reference's `#readSpliceOperand`, the first 8 bytes of a longer operand and the `int` clamp, #382) |
| `bitwise.rs` | `OP_INVERT`, `OP_AND`/`OP_OR`/`OP_XOR`, `OP_EQUAL`/`OP_EQUALVERIFY`, the width-preserving `OP_LSHIFT`/`OP_RSHIFT` (`shifted`) |
| `arithmetic.rs` | The unary and binary number opcodes (`truth` for a comparison's 1 or 0), `OP_WITHIN` |
| `arithmetic_room.rs` | The room an arithmetic result needs, judged before it is allocated (#374): `arithmetic_room` (the operands' encodings as the read judges them, then in the default mode the element bound on the result's least length from the operands' bytes, then in every mode `try_reserve_exact` of the step's peak when 64 KiB or more, `step_peak`'s multiple of the operands' bytes, `STEP_PEAK_*`), `number_room` (the same probe for a number's read and a numeric shift), `push_arithmetic_result` (takes the result and frees it once encoded, #348; the encoding fallible, then the default mode's bound on the exact length); its unit tests, `arithmetic_room_tests.rs`, model the bound and the allocator's ceiling at a small scale |
| `crypto.rs` | The hashes (each charged to the work budget before it runs), `OP_CODESEPARATOR`, `OP_CHECKSIG` and `OP_CHECKMULTISIG` with NULLFAIL and NULLDUMMY, the public key encoding (COMPRESSED_PUBKEYTYPE), the scriptCode (`build_subscript`, a FORKID signature's push kept) and `verify_signature` (the CHRONICLE-bit dispatch through `TxSighashCache`) |
| `signature_encoding.rs` | Signature encoding (DER, LOW_S at the order, hash type delegated to `hash_type.rs`, FORKID); at version 1 without a word, hash type before low-S and the reference catch's `The signature format is invalid.` for either refusal (#417); under a word low-S before hash type with distinct node messages. Without a word, no fork-ID gate at either version: a signature lacking the bit uses the original digest and its verification result (#429); under a word the mandatory bit and refusal text are unchanged. DER-off requires an explicit word in TypeScript; this crate refuses that word for lacking SIGHASH_FORKID. Its unit test pins the order before wrapping |
| `hash_type.rs` | STRICTENC's defined base type and the Chronicle hash-type gate: version > 1 without a word, refused in the reference's visible words (the DER wrapper's `The signature format is invalid.`, `Spend.ts:622-625`, over the gate's at `:586-591`), `CHRONICLE` under a word (#22, #397); the version-1 default caller wraps undefined-type errors too (#417), while version-2 words stay as pinned by #23 |
| `stack.rs` | The main and alt stacks: push, pop, peek, `require_two_items` (the two-operand guard), and the memory each element is charged: per stack in the default mode, the node's one count with `STACK_ELEMENT_OVERHEAD` under a word (`charge`, `release`) |
| `limits.rs` | The budgets and their declines: `MAX_SCRIPT_ELEMENT_SIZE`, `WORD_MEMORY_LIMIT`, `MAX_MULTISIG_KEY_COUNT`; `memory_limit`, `stack_memory_policy` (the mempool path's verdict), `stack_memory_consensus` (the block path's, #38), `check_node_budget`, `resource_error` (every `ScriptResourceLimit` the memory budget raises), the work budget (`work_spent`, `charge_work`, `work_error`); both errors' messages are the limit's `Display` |
| `reference_read.rs` | The default mode's read limit, the reference's (#331, the keeper's word of 2026-10-27): `refusal` (`Invalid string length` for a magnitude past 536,870,888 bits, V8's longest string, `toString(2)` at `BigNumber.ts:450`), `result_refusal` (the same figure on a result's bits: `push_arithmetic_result`'s sum or difference), `shift_refusal` (the numeric left shift's: `Maximum BigInt size exceeded` past 2^30 bits, V8's `BigInt` cap, thrown by the reference's `value << bits` before its string, else `result_refusal`), `magnitude_bits` (the magnitude's bits from the bytes, padding none); `num.rs`'s `check_reference_read` applies it at every read in the default mode, after the minimal-encoding check |
| `num.rs` | Script numbers under the length limit in force: `max_script_num_length`, `set_script_num_length_policy`, `read_number` (its digits asked of the allocator first, #374), `check_number` (the read's verdicts without the decode, #374), `read_count` (CHECKMULTISIG's 4-byte counts), `push_number` (takes the number and frees it before its bytes are pushed, #348) and `push_encoded_number`, the overflow error, `number_text` (a number in an error's text: decimal up to 64 bytes, `a N-byte number` above, #349). The encoding is `ScriptNum`'s (`script_num.rs`), not repeated here |
| `tests.rs`, `flag_tests.rs`, `chronicle_tests.rs`, `low_s_order_tests.rs`, `script_num_length_tests.rs`, `fixed_width_operand_tests.rs` | The unit tests, one file per former inline module; their paths (`script::spend::flag_tests::...`) are unchanged |

A new opcode handler goes in its group's module as a `pub(super) fn` on `Spend`
and gets one arm in `execute_opcode`. A module stays under 800 lines and a
handler under 60 (`docs/RATCHETS.md`); a guard several handlers share is one
helper (`require_two_items`), not a copy per module.

### Script Interpreter Configuration (`spend/`)

```rust
// limits.rs
const MAX_SCRIPT_ELEMENT_SIZE: usize = 1024 * 1024 * 1024;  // 1GB (BSV unlimited)
const WORD_MEMORY_LIMIT: usize = DEFAULT_STACK_MEMORY_USAGE_POLICY;  // 100MB, under a word
const MAX_MULTISIG_KEY_COUNT: i64 = i32::MAX as i64;
// mod.rs
const REQUIRE_MINIMAL_PUSH: bool = true;        // the default mode, version <= 1 only
const REQUIRE_PUSH_ONLY_UNLOCKING: bool = true;  // the default mode, every version
const REQUIRE_LOW_S_SIGNATURES: bool = true;     // the default mode, version <= 1 only
const REQUIRE_CLEAN_STACK: bool = true;          // the default mode, version <= 1 only
// NULLDUMMY: the default mode, version <= 1 only. NULLFAIL, MINIMALIF, DISCOURAGE_UPGRADABLE_NOPS,
// COMPRESSED_PUBKEYTYPE: only under a word (`set_flags`, word.rs), derived by `ScriptFlags::gates`.
```

## Related Documentation

- `../CLAUDE.md` - Root SDK documentation
- `../primitives/CLAUDE.md` - Primitives module (encoding, hashing)
- `../primitives/bsv/CLAUDE.md` - BSV primitives (sighash, transaction signatures)
- `templates/CLAUDE.md` - Templates module documentation
