# bsv-rs

[![CI](https://github.com/Calhooon/bsv-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Calhooon/bsv-rs/actions/workflows/ci.yml?query=branch%3Amain)
[![Bench](https://github.com/Calhooon/bsv-rs/actions/workflows/bench.yml/badge.svg)](https://github.com/Calhooon/bsv-rs/actions/workflows/bench.yml)
[![MSRV](https://github.com/Calhooon/bsv-rs/actions/workflows/msrv.yml/badge.svg)](https://github.com/Calhooon/bsv-rs/actions/workflows/msrv.yml)
[![Features](https://github.com/Calhooon/bsv-rs/actions/workflows/features.yml/badge.svg)](https://github.com/Calhooon/bsv-rs/actions/workflows/features.yml)
[![Unused dependencies](https://github.com/Calhooon/bsv-rs/actions/workflows/machete.yml/badge.svg)](https://github.com/Calhooon/bsv-rs/actions/workflows/machete.yml)
[![Docs](https://github.com/Calhooon/bsv-rs/actions/workflows/docs.yml/badge.svg)](https://github.com/Calhooon/bsv-rs/actions/workflows/docs.yml)

The programme, measured scoreboard and research queue are in [docs/NORTH-STAR.md](docs/NORTH-STAR.md).
The module map, the invariants and the test that pins each are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

**0.7.1**, a Rust SDK for BSV: keys and cryptography, Script, transactions,
BEEF and SPV, block headers and proof of work, wallets, authentication and
overlay clients. Optional features support native applications and wasm hosts.
Compatibility is tested against shared vectors; the crate also has explicit
local evaluator contracts and documented differences from other SDKs.

The release of record is the tag `v0.7.1`; the version on crates.io is 0.7.1,
the same release. [CHANGELOG.md](CHANGELOG.md) says what each release changed.

## Install

```toml
[dependencies]
bsv-rs = { version = "=0.7.1", features = ["transaction", "wallet"] }
```

Defaults enable `primitives` and `script`. [Cargo.toml](Cargo.toml) lists the
module features (`block`, `transaction`, `wallet`, `messages`, `compat`,
`totp`, `auth`, `overlay`, `storage`, `registry`, `kvstore`, `identity`,
`socketio`), `full` (all of those), the native transports `http` and
`websocket` (neither in `full`), `wasm`, `tracing` (not in `full`: one `warn`
event at the wallet wire processor carrying a wallet's error words that the
frame replaces with `Wallet operation failed`, and one naming a wallet refusal's class (#137)), and `dhat-profiling` for the
heap profiling tests. `transaction` enables `block`. A Worker should select the
features it needs and enable `wasm`; native HTTP transports are separate:
`http` is native-only, and a wasm32 build with it stops at `build.rs` with one
message (#152). `WalletClient` and its `WalletInterface` implementation need
only `wallet`: `WalletClient::with_substrate` wraps an in-process wallet,
including another client. The named HTTP substrates and automatic discovery
require `http`. The declared minimum Rust is 1.88 (`rust-version`).

## Authenticated HTTP

With `auth` and native `http`, `auth::AuthFetch` wraps a `Peer` and the BRC-104
transport, correlates responses, exchanges certificates, and handles bounded
BRC-105 payments using the supplied wallet. `AuthFetchOptions` carries method,
headers, body bytes, retry limits and payment labels; the returned `Response`
owns its status, headers and body. The wallet's `create_action` policy authorizes
payments. Wasm embedders use `auth` with their own transport factory and `wasm`.
The [#423 entry in the changelog](CHANGELOG.md) records the exact reference
behavior, including the certificate-request intake limitation.

## The signing digest (0.7.0)

`SigningContext::compute_sighash`, the digest every template's `unlock` and
`Transaction::sign` sign, computes through
`compute_sighash_dispatched_for_signing`: the BIP143 digest for a hash type
that carries `SIGHASH_FORKID` and not `SIGHASH_CHRONICLE`, the original digest
for every other type, and under the original digest the constant `one` for
`SIGHASH_SINGLE` with the input index at or beyond the outputs. The scriptCode
is the locking script unless `SigningContext::with_script_code` names another;
`script::chronicle_unlocking_script_code` forms the one a CHECKSIG in a
post-Chronicle unlocking script signs. An input index the transaction does not
have is an `Err`. `SigningContext` gained the public field `script_code`, so a
struct literal of it adds `script_code: None` (or uses `SigningContext::new`).
The templates sign FORKID types without CHRONICLE, so their signatures are
unchanged from 0.6.1. The identity paths
`IdentityClient::revoke_certificate_revelation` and the contact update and
removal of `ContactsManager` now sign the same dispatched digest.
[tests/sighash_tests.rs](tests/sighash_tests.rs) and
[tests/identity_spend_witness.rs](tests/identity_spend_witness.rs) pin these;
the CHANGELOG's 0.7.0 entry names each test.

## Proof and evaluator contracts

A one-level merkle path with one hashed leaf is accepted only at offset 0,
representing a one-transaction block. A nonzero lone-leaf offset is refused
with `MissingSibling`, both when parsing and computing the root. Obtain a
valid proof; do not rewrite an offset on trust.
[tests/merkle_path_lone_leaf.rs](tests/merkle_path_lone_leaf.rs) pins this rule.

`SpendParams` and `TxSpendParams` accept `work_limit: Option<u64>`.
`Transaction::verify_with_work_budget` adds the same per-input bound beside the
memory budget; live doors use `verify_with_chain_params_and_work_budget`.
The default `None` leaves work accounting off, matching the reference's
`verify`, which has no work bound. With a bound, reached opcodes and bytes fed
to hashes are charged before that work. The interpreter reports
`ScriptResource::Work`; transaction and stream verifiers carry
`NotJudgedCause::WorkBudgetExceeded { input, budget, work_done }` on their
`NotJudged` class. A spend inside the budget retains its verdict. Each door
names its policy value in its brief beside its memory budget. This is not a
wall-clock or total computation bound.
[tests/script_work_budget.rs](tests/script_work_budget.rs) pins the accounting;
[tests/transaction_work_budget_378.rs](tests/transaction_work_budget_378.rs)
pins the verification paths.

For a transaction-wide work bound, `transaction::WorkBudget` carries
readable `per_input` and `per_transaction` fields, both optional. It is
`#[non_exhaustive]`: start with `WorkBudget::new()` (both bounds `None`) and use
`with_per_input` and `with_per_transaction` to configure the policy passed to
`Transaction::verify_with_work_budgets` or the chain-parameter counterpart.
Stream verifiers add `with_transaction_work_budget` beside `with_work_budget`.
Inputs are charged in verification order; a total above the bound returns
`NotJudgedCause::TransactionWorkBudgetExceeded { input, limit, total }`.
The crossing input runs under its per-input bound alone: the work done is at
most the limit plus one input's charge, so a door passes both bounds.
`work_spent()` on either stream verifier reports the running transaction total;
on a transaction-budget refusal verdict it returns `Some(total)`.
The toolbox can delete its input-work sum and pass that limit directly.

The streaming BEEF reader verifies element by element, checks proof roots
through supplied headers and executes unproven inputs. It holds an ancestry
index and needed outputs, so streaming does not mean constant memory.
`StreamVerifier::set_work_limit` / `with_work_budget` and their async equivalents
apply the local work bound per input. Reapply it after resuming a cursor.
Pausing is between elements or inputs; a work decline cannot resume within a
script. The implementation is [src/transaction/beef_stream.rs](src/transaction/beef_stream.rs).

Script defaults follow SDK evaluation mode; callers modelling node validation
select explicit `ScriptFlags` and interpret resource limits separately from
validity. `Transaction::verify` keeps the two apart: an invalid script is
`TransactionError`, an input whose evaluation stopped at a memory budget is
`Error::ScriptEvaluationDeclined`. Work exhaustion through a budgeted verifier
is `Error::TransactionNotJudged`. Its third parameter is that budget, the
reference's `memoryLimit`: `None` runs uncapped, as the reference does, and
`Some(n)` is `n` bytes per stack, the figure a door judging untrusted
transactions passes. `SpendParams::memory_limit: None` is uncapped in the
default mode too (the reference's `Spend`); a memory budget bounds memory,
while the budgeted transaction methods, `SpendParams::work_limit` and the
stream's `set_work_limit` share one counter for charged work. Neither can interrupt an arithmetic opcode or bound its elapsed time. On the block path
`Spend::set_stack_memory_consensus` is a node's
`-maxstackmemoryusageconsensus`, a verdict; `memory_limit` only declines. The flag and resource witnesses live in [tests](./tests).

## The node's mining checks

From 0.5.0 the streaming reader refuses an unproven transaction that
bitcoin-sv refuses when mining it: an unproven coinbase, a null outpoint, a
repeated input, an output value or running total outside the money range, an
input total outside it, a P2SH-shaped output after Genesis, an immature
coinbase spend, and a time-locked transaction that is not final for the next
block. Each byte refusal names its offset and kind. A finality verdict needs a
tip: `Headers::mining_tip` and the async `ChainTracker::mining_tip` supply a
`ChainTip`, and without one the reader declines the transaction as
unverifiable instead of guessing. The new kinds and refusals extend public
exhaustive enums; [CHANGELOG.md](CHANGELOG.md) carries the 0.5.0 migration
notes and cites the node's rules through the pins of a separate repository,
bsv-script-lean (`~/bsv/bsv-script-lean`), which measures this crate against
its specification of the node; this README states none of its results.

## Build, gate and records

```sh
cargo build --examples --all-features
cargo test --test readme_examples --test merkle_path_lone_leaf --test script_work_budget --all-features
cargo fmt --all -- --check
```

[.github/workflows/ci.yml](.github/workflows/ci.yml) is the required set and
the only workflow a push or a pull request starts: the tests, formatting,
clippy, Documentation, vectors, deny, the ratchet, the fixtures, the secrets scan, the
combined wasm32 slice and the line checks, exactly the contexts the line's
protection requires. The checks that judge something other than the commit
run on dispatch and before every tag, each in its own workflow with its own
badge above: [bench.yml](.github/workflows/bench.yml) (the benchmark
build and the scoreboard on tags; regression comparisons on branch dispatches),
[msrv.yml](.github/workflows/msrv.yml),
[features.yml](.github/workflows/features.yml) (each feature alone and the
other wasm32 slices), [machete.yml](.github/workflows/machete.yml) (unused
dependencies) and [docs.yml](.github/workflows/docs.yml) (workflow lint).
`Documentation` runs `cargo doc --no-deps --all-features` with warnings denied;
the captain adds it to each line's protection once that line's `ci.yml` runs it (#515).
The CI badge reads `ci.yml` on `main`; a run cancelled because
a newer push superseded it is never a red.
`ci.yml` checks out the pinned external conformance corpus for the vector job;
a local run without that corpus can skip those tests and is not conformance
evidence.
[RELEASING.md](RELEASING.md) defines the machine gate and trusted publication
from tags. [CHANGELOG.md](CHANGELOG.md) holds release and API migration notes.

## Examples

The blocks below are the files in [examples](./examples), checked byte for byte
by [tests/readme_examples.rs](tests/readme_examples.rs). Building them does not
run their network or signing operations. Network examples require a host's
own configuration and authorization.

### Keys, hashes, signatures


```rust
// examples/keys.rs
use bsv_rs::primitives::{sha256, to_hex, PrivateKey};

fn main() {
    // A fresh secp256k1 key pair. `PrivateKey::random()` draws from the platform
    // RNG (`getrandom`; on wasm32 with the `wasm` feature, the JS host's).
    let private_key = PrivateKey::random();
    let public_key = private_key.public_key();

    // The P2PKH address and the WIF export round-trip.
    let address = public_key.to_address();
    let wif = private_key.to_wif();
    assert_eq!(PrivateKey::from_wif(&wif).unwrap().to_wif(), wif);

    // ECDSA over a SHA-256 digest: RFC 6979 deterministic nonces, so the same
    // key and digest always give the same DER bytes.
    let digest = sha256(b"Hello, BSV!");
    let signature = private_key.sign(&digest).unwrap();
    assert!(public_key.verify(&digest, &signature));
    assert_eq!(
        private_key.sign(&digest).unwrap().to_der(),
        signature.to_der()
    );

    println!("address   {address}");
    println!("pubkey    {}", to_hex(&public_key.to_compressed()));
    println!("signature {}", to_hex(&signature.to_der()));
}
```

### Scripts, and the interpreter


```rust
// examples/script.rs
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

fn main() {
    // A P2PKH locking script from an address, and the same script parsed
    // back from hex and from ASM.
    let locking = P2PKH::lock_from_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").unwrap();
    let from_hex = Script::from_hex(&locking.to_hex()).unwrap();
    assert_eq!(from_hex.to_asm(), locking.to_asm());
    assert!(from_hex.is_p2pkh());
    println!("p2pkh  {}", locking.to_asm());

    // The interpreter is `Spend`: it executes an unlocking script against a
    // locking script inside its transaction context, exactly as the TypeScript
    // SDK's default evaluation mode does. Here the context is synthetic: one
    // input, no outputs, transaction version 1 (the strict mode: minimal
    // pushes, low-S, a clean stack).
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: LockingScript::from_asm("OP_1 OP_EQUAL").unwrap(),
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_asm("OP_1").unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    assert!(spend.validate().unwrap());

    // A refusal is an error that names the failing step; a script that only
    // exhausts the interpreter's memory budget is a DIFFERENT class
    // (`is_resource_limit()`), so a caller judging on the network's behalf can
    // tell "invalid" from "too big for this evaluator".
    let mut refused = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: LockingScript::from_asm("OP_1 OP_EQUAL").unwrap(),
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_asm("OP_2").unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    let err = refused.validate().unwrap_err();
    assert!(!err.is_resource_limit());
    println!("refused {}", err.message);

    // A node validates under a FLAG WORD and derives two of them: the block
    // word (what a mining node applies when it connects a block) and the
    // standard word (the block word plus the relay-only restrictions of its
    // mempool policy). Without a word `Spend` is the TypeScript SDK's default
    // mode, which is neither; a consensus oracle selects the block word. Here
    // a version-1 spend leaves two elements on the stack: refused by the
    // default mode and by the standard word (CLEANSTACK, a relay rule), valid
    // under the block word, exactly as it is in a block.
    let untidy = || {
        Spend::new(SpendParams {
            source_txid: [0u8; 32],
            source_output_index: 0,
            source_satoshis: 1,
            locking_script: LockingScript::from_asm("OP_1 OP_1").unwrap(),
            transaction_version: 1,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: UnlockingScript::new(),
            input_sequence: 0xffff_ffff,
            lock_time: 0,
            memory_limit: None,
            work_limit: None,
        })
    };
    assert!(untidy().validate().is_err());
    let mut consensus = untidy();
    consensus.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
    assert!(consensus.validate().unwrap());
    let mut relay = untidy();
    relay.set_flags(ScriptFlags::standard(ProtocolEra::PostChronicle));
    println!("relay   {}", relay.validate().unwrap_err().message);
}
```

### A transaction: build, sign, verify


```rust
// examples/transaction.rs
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::{SignOutputs, UnlockingScript};
use bsv_rs::transaction::{
    MerklePath, MockChainTracker, Transaction, TransactionInput, TransactionOutput,
};

fn main() {
    let key = PrivateKey::random();
    let address = key.public_key().to_address();

    // A funding transaction that pays our address. It spends a coin this
    // program does not carry, which its merkle path vouches for (here it is
    // the one transaction of its block, so the block's root is its txid). A
    // transaction with no input, or with no output, is no transaction, and
    // `verify` refuses one.
    let mut funding = Transaction::new();
    let mut mined = TransactionInput::new("11".repeat(32), 0);
    mined.unlocking_script = Some(UnlockingScript::new());
    funding.add_input(mined).unwrap();
    funding
        .add_output(TransactionOutput::new(
            10_000,
            P2PKH::lock_from_address(&address).unwrap(),
        ))
        .unwrap();
    let funding_txid = funding.id();
    funding.merkle_path = Some(MerklePath::from_coinbase_txid(&funding_txid, 800_000));

    // The spend: one input sourcing the funding output (the whole source
    // transaction rides along, which is what SPV-style verification needs),
    // one P2PKH output, and the unlocking script produced by the P2PKH
    // template's signer at `sign()` time.
    let mut spend = Transaction::new();
    let mut input = TransactionInput::with_source_transaction(funding, 0);
    input.set_unlocking_script_template(P2PKH::unlock(&key, SignOutputs::All, false));
    spend.add_input(input).unwrap();
    spend.add_p2pkh_output(&address, Some(9_900)).unwrap();
    futures::executor::block_on(spend.sign()).unwrap();

    println!("txid {}", spend.id());
    println!("size {} bytes", spend.to_binary().len());

    // `verify` walks the ancestry by txid: a proven transaction is checked
    // against the chain tracker; an unproven one has every input's script
    // EXECUTED against its source output, and its outputs weighed against its
    // inputs. The spend is unproven, so the interpreter judges it; the
    // funding transaction is proven, so the tracker is asked for its root
    // and its own ancestry is not needed.
    let mut tracker = MockChainTracker::new(800_000);
    tracker.add_root(800_000, funding_txid);
    let ok = futures::executor::block_on(spend.verify(&tracker, None, None)).unwrap();
    assert!(ok);
    println!("verified {ok}");
}
```

### BRC-42 keys and the ProtoWallet


```rust
// examples/brc42.rs
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, KeyDeriver, ProtoWallet, Protocol, SecurityLevel,
    VerifySignatureArgs,
};

fn main() {
    let alice = KeyDeriver::new(Some(PrivateKey::random()));
    let bob = KeyDeriver::new(Some(PrivateKey::random()));
    let protocol = Protocol::new(SecurityLevel::App, "payment system");
    let key_id = "invoice-12345";

    // Bob derives a private key for talking to Alice; Alice derives the
    // matching public key for Bob. BRC-42 makes the two agree without either
    // party sharing anything but its identity key.
    let bob_private = bob
        .derive_private_key(
            &protocol,
            key_id,
            &Counterparty::Other(alice.identity_key()),
        )
        .unwrap();
    let bob_public = alice
        .derive_public_key(
            &protocol,
            key_id,
            &Counterparty::Other(bob.identity_key()),
            false,
        )
        .unwrap();
    assert_eq!(
        bob_private.public_key().to_compressed(),
        bob_public.to_compressed()
    );

    // The ProtoWallet is the same derivation behind a wallet-shaped API: sign
    // as Alice for Bob, verify as Bob against Alice.
    let alice_wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let bob_wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let protocol = Protocol::new(SecurityLevel::App, "secure messaging");
    let signed = alice_wallet
        .create_signature(CreateSignatureArgs {
            data: Some(b"Hello, Bob".to_vec()),
            hash_to_directly_sign: None,
            protocol_id: protocol.clone(),
            key_id: "msg-1".to_string(),
            counterparty: Some(Counterparty::Other(bob_wallet.identity_key())),
            ..Default::default()
        })
        .unwrap();
    let verified = bob_wallet
        .verify_signature(VerifySignatureArgs {
            data: Some(b"Hello, Bob".to_vec()),
            hash_to_directly_verify: None,
            signature: signed.signature,
            protocol_id: protocol,
            key_id: "msg-1".to_string(),
            counterparty: Some(Counterparty::Other(alice_wallet.identity_key())),
            for_self: None,
            ..Default::default()
        })
        .unwrap();
    assert!(verified.valid);
    println!("alice → bob signature verified: {}", verified.valid);
}
```

### BEEF: write, read, validate, verify


```rust
// examples/beef_spv.rs
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::{SignOutputs, UnlockingScript};
use bsv_rs::transaction::{
    Beef, MerklePath, MockChainTracker, Transaction, TransactionInput, TransactionOutput,
};

fn main() {
    let key = PrivateKey::random();
    let address = key.public_key().to_address();

    // funding -> spend: a mined transaction and a fresh one spending it, the
    // shape of a payment. The funding transaction spends a coin this BEEF
    // does not carry, which its merkle path vouches for (here it is the one
    // transaction of its block, so the block's root is its txid). Every
    // transaction has an input: a raw transaction with none is no
    // transaction, and a BEEF carrying one is not valid.
    let mut funding = Transaction::new();
    let mut mined = TransactionInput::new("11".repeat(32), 0);
    mined.unlocking_script = Some(UnlockingScript::new());
    funding.add_input(mined).unwrap();
    funding
        .add_output(TransactionOutput::new(
            10_000,
            P2PKH::lock_from_address(&address).unwrap(),
        ))
        .unwrap();
    let funding_txid = funding.id();
    let proof = MerklePath::from_coinbase_txid(&funding_txid, 800_000);
    funding.merkle_path = Some(proof.clone());
    let mut spend = Transaction::new();
    let mut input = TransactionInput::with_source_transaction(funding.clone(), 0);
    input.set_unlocking_script_template(P2PKH::unlock(&key, SignOutputs::All, false));
    spend.add_input(input).unwrap();
    spend.add_p2pkh_output(&address, Some(9_900)).unwrap();
    futures::executor::block_on(spend.sign()).unwrap();
    let subject = spend.id();

    // The BEEF carries every transaction once, however many inputs source it;
    // `to_binary_atomic` prefixes the subject's txid (BRC-95) so a reader
    // knows which transaction the container is ABOUT.
    let mut beef = Beef::new();
    let bump = beef.merge_bump(proof);
    beef.merge_raw_tx(funding.to_binary(), Some(bump));
    beef.merge_transaction(spend);
    let bytes = beef.to_binary_atomic(&subject).unwrap();
    println!("beef {} bytes, subject {subject}", bytes.len());

    // Reading it back: the container is validated (structure, then the
    // merkle roots it claims, one here, for a header service to confirm) and
    // the subject comes out with its input sources LINKED, each distinct
    // parent linked once (linear in the BEEF, never exponential on a diamond
    // chain).
    let mut parsed = Beef::from_binary(&bytes).unwrap();
    let validation = parsed.verify_valid(false);
    assert!(validation.valid);
    assert_eq!(validation.roots.get(&800_000), Some(&funding_txid));
    let tx = Transaction::from_beef(&bytes, None).unwrap();
    assert_eq!(tx.id(), subject);
    assert!(tx.inputs[0].source_transaction.is_some());

    // And the verdict: the spend's script executed against the linked
    // source; the proven ancestor checked against the tracker and not
    // descended.
    let mut tracker = MockChainTracker::new(800_000);
    tracker.add_root(800_000, funding_txid);
    let ok = futures::executor::block_on(tx.verify(&tracker, None, None)).unwrap();
    assert!(ok);
    println!("verified {ok}");
}
```

### The overlay network

The overlay example reaches network services when executed.

```rust
// examples/overlay.rs
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, TopicBroadcaster,
    TopicBroadcasterConfig,
};
use bsv_rs::transaction::Transaction;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Lookup: the resolver discovers competent hosts for the service through
    // the SLAP trackers (cached, coalesced across concurrent askers, backed
    // off per host by its reputation) and fans the question out.
    let resolver = LookupResolver::new(LookupResolverConfig::default());
    let question = LookupQuestion::new("ls_kvstore", serde_json::json!({ "key": "hello" }));
    match resolver.query(&question, Some(5_000)).await {
        Ok(LookupAnswer::OutputList { outputs }) => {
            println!("lookup answered {} output(s)", outputs.len())
        }
        Ok(other) => println!("lookup answered a {:?} shape", other.answer_type()),
        Err(e) => println!("lookup failed: {e}"),
    }

    // Broadcast: the transaction rides SHIP to every host advertising the
    // topic, as a BEEF; the answer is a STEAK per topic naming what each host
    // admitted.
    let broadcaster = TopicBroadcaster::new(
        vec!["tm_kvstore".to_string()],
        TopicBroadcasterConfig::default(),
    )
    .unwrap();
    let tx = Transaction::new();
    match broadcaster.broadcast_tx(&tx).await {
        Ok(steak) => println!("broadcast acknowledged: {steak:?}"),
        Err(e) => println!("broadcast refused: {e:?}"),
    }
}
```

More: BRC-103 over HTTP or Socket.IO (`auth`, `socketio`), the wallet wire protocol (`wallet::wire`), UHRP storage, the registry, the KV stores and identity all carry worked examples in their module docs on [docs.rs](https://docs.rs/bsv-rs).

## License

Licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE).
