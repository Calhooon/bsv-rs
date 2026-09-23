# bsv-rs

A Rust SDK for BSV: cryptographic primitives, the Bitcoin Script interpreter, transactions with BEEF and SPV, BRC-42 wallets, BRC-103 mutual authentication, and the overlay network (SHIP, SLAP, STEAK), with storage, registry, key-value and identity clients on top.

It is a reference-parity port of the TypeScript [`@bsv/sdk`](https://github.com/bitcoin-sv/ts-sdk), cross-checked against the [Go SDK](https://github.com/bitcoin-sv/go-sdk): the same bytes on the wire, the same verdicts from the interpreter, pinned by shared test vectors and by the `ts-stack` conformance corpus. It builds for `wasm32-unknown-unknown` and runs in production inside Cloudflare Workers.

[![Crates.io](https://img.shields.io/crates/v/bsv-rs.svg)](https://crates.io/crates/bsv-rs)
[![Documentation](https://docs.rs/bsv-rs/badge.svg)](https://docs.rs/bsv-rs)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

## What you get

| Module | Feature | What it is |
|---|---|---|
| `primitives` | default | SHA-256/512, RIPEMD-160, HMAC, PBKDF2, HMAC-DRBG (RFC 6979), secp256k1 and P-256 ECDSA, ECDH, Shamir, AES-256-GCM, `BigNumber`, hex/base58/base64, a binary `Reader`/`Writer` with varints |
| `script` | default | `Script` parsing (hex, ASM, chunks), every BSV opcode, the `Spend` interpreter, templates: P2PKH, P2PK, Multisig, RPuzzle, PushDrop |
| `transaction` | | `Transaction` building, signing, fee models (static and ARC live policy), `MerklePath` (BRC-74 BUMP), `Beef` (BRC-62/95/96), `verify` (scripts and merkle roots against a `ChainTracker`), ARC and WhatsOnChain clients |
| `wallet` | | BRC-42/43 `KeyDeriver`, `ProtoWallet` (sign, verify, encrypt, decrypt, HMAC), `WalletClient` over HTTP, the BRC-100 binary wire protocol (28 methods, Go-compatible) |
| `messages` | | BRC-77 signed and BRC-78 encrypted messages |
| `compat` | | BIP-32 HD keys, BIP-39 mnemonics (eight wordlists), Bitcoin Signed Messages, Electrum and Bitcore ECIES |
| `totp` | | RFC 6238 one-time passwords |
| `auth` | | BRC-103 mutual authentication (`Peer`, sessions, BRC-52/53 certificates) over BRC-104 HTTP; `socketio` adds a Socket.IO 5 transport, `websocket` a tokio-tungstenite one |
| `overlay` | | `LookupResolver` (SLAP host discovery, request coalescing, per-host reputation), `TopicBroadcaster` (SHIP, STEAK acknowledgements), signed SHIP/SLAP admin tokens, `Historian` |
| `storage` | | UHRP content-addressed upload and download |
| `registry` | | On-chain definitions for baskets, protocols and certificate types |
| `kvstore` | | `LocalKVStore` (encrypted, wallet baskets) and `GlobalKVStore` (public, overlay-backed) |
| `identity` | | Certificate-based identity resolution and contacts |

`default = ["primitives", "script"]`; `full` turns every module on (including `socketio`). Platform and transport flags: `http` (reqwest), `websocket` (opt-in, not in `full`), `wasm`, `dhat-profiling`. The dependency order is `primitives → script → transaction → wallet → { messages, auth, overlay }`, with `storage`, `registry` and `kvstore` on `overlay`, `identity` on `auth` and `overlay`, and `compat` and `totp` on `primitives` alone.

```toml
[dependencies]
bsv-rs = "0.3"                                                            # primitives + script
bsv-rs = { version = "0.3", features = ["transaction"] }                  # + transactions, BEEF, SPV
bsv-rs = { version = "0.3", features = ["wallet"] }                       # + BRC-42 keys, ProtoWallet
bsv-rs = { version = "0.3", features = ["auth", "http"] }                 # + BRC-103 over HTTP
bsv-rs = { version = "0.3", features = ["overlay", "http"] }              # + SHIP/SLAP
bsv-rs = { version = "0.3", features = ["full", "http"] }                 # everything, native
bsv-rs = { version = "0.3", default-features = false,
           features = ["auth", "wallet", "transaction", "overlay", "socketio", "wasm"] }  # a Worker
```

## Examples

Every code block below is a file under [`examples/`](examples/), compiled by CI (`cargo build --examples --all-features`) and pinned to the README byte for byte by `tests/readme_examples.rs`. The first five run with no network.

### Keys, hashes, signatures

`cargo run --example keys`

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

`cargo run --example script`

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

`cargo run --example transaction --features transaction`

```rust
// examples/transaction.rs
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::SignOutputs;
use bsv_rs::transaction::{MockChainTracker, Transaction, TransactionInput, TransactionOutput};

fn main() {
    let key = PrivateKey::random();
    let address = key.public_key().to_address();

    // A funding transaction that pays our address (synthetic: no inputs, so it
    // is a root the verifier never has to judge).
    let mut funding = Transaction::new();
    funding
        .add_output(TransactionOutput::new(
            10_000,
            P2PKH::lock_from_address(&address).unwrap(),
        ))
        .unwrap();

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
    // inputs. This chain is unproven end to end, so the tracker is never
    // asked and the interpreter is the whole verdict.
    let tracker = MockChainTracker::new(0);
    let ok = futures::executor::block_on(spend.verify(&tracker, None)).unwrap();
    assert!(ok);
    println!("verified {ok}");
}
```

### BRC-42 keys and the ProtoWallet

`cargo run --example brc42 --features wallet`

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
        })
        .unwrap();
    assert!(verified.valid);
    println!("alice → bob signature verified: {}", verified.valid);
}
```

### BEEF: write, read, validate, verify

`cargo run --example beef_spv --features transaction`

```rust
// examples/beef_spv.rs
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::SignOutputs;
use bsv_rs::transaction::{
    Beef, MockChainTracker, Transaction, TransactionInput, TransactionOutput,
};

fn main() {
    let key = PrivateKey::random();
    let address = key.public_key().to_address();

    // funding -> spend, both unproven (no merkle paths): the shape of a fresh
    // wallet chain before anything is mined.
    let mut funding = Transaction::new();
    funding
        .add_output(TransactionOutput::new(
            10_000,
            P2PKH::lock_from_address(&address).unwrap(),
        ))
        .unwrap();
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
    beef.merge_transaction(funding);
    beef.merge_transaction(spend);
    let bytes = beef.to_binary_atomic(&subject).unwrap();
    println!("beef {} bytes, subject {subject}", bytes.len());

    // Reading it back: the container is validated (structure, then the
    // merkle roots it claims, none here) and the subject comes out with its
    // input sources LINKED, each distinct parent linked once (linear in the
    // BEEF, never exponential on a diamond chain).
    let mut parsed = Beef::from_binary(&bytes).unwrap();
    let validation = parsed.verify_valid(false);
    assert!(validation.valid);
    assert!(validation.roots.is_empty(), "nothing here is mined");
    let tx = Transaction::from_beef(&bytes, None).unwrap();
    assert_eq!(tx.id(), subject);
    assert!(tx.inputs[0].source_transaction.is_some());

    // And the verdict: scripts executed against the linked sources; a proven
    // ancestor would instead be checked against the tracker and not descended.
    let tracker = MockChainTracker::new(0);
    let ok = futures::executor::block_on(tx.verify(&tracker, None)).unwrap();
    assert!(ok);
    println!("verified {ok}");
}
```

### The overlay network

`cargo build --example overlay --features "overlay,http"` (running it reaches the public mainnet hosts)

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

## The contracts that matter

**The interpreter runs in the TypeScript SDK's default mode, or under a node's flag word.** Without a word, `Spend` is the TypeScript SDK's default evaluation mode: a transaction of version 1 or lower runs strict (minimal pushes and minimally encoded numbers, low-S, an empty CHECKMULTISIG dummy, push-only unlocking scripts, a clean stack, strict DER and public-key encodings, `SIGHASH_FORKID` required); version 2 and above runs the post-Genesis relaxed mode (MINIMALDATA, LOW_S, CLEANSTACK and NULLDUMMY not enforced), as `Spend.isRelaxed()` does upstream; `set_require_minimal` and `set_require_push_only` override either way. That mode is neither of the two words a node validates under. With `set_flags(ScriptFlags::block(era))` the interpreter applies the block-validation word bitcoin-sv v1.2.2 derives for a block of that era, and with `ScriptFlags::standard(era)` the mempool word (the block word plus exactly NULLDUMMY, MINIMALDATA, DISCOURAGE_UPGRADABLE_NOPS and CLEANSTACK); every rule, including NULLFAIL, MINIMALIF and the discouraged NOPs, is enforced at the reference's site under the reference's version gate (at Chronicle a transaction of version 2 or above is malleable and every malleability restriction is off for it). A caller judging a spend on the network's behalf selects the block word; `ScriptFlags` carries the reference's bit values and names, so a word can be compared with a node's own. The opcode set is post-Genesis BSV (OP_MUL, OP_CAT, OP_LSHIFT and the rest enabled; OP_2MUL, OP_2DIV, OP_VER, OP_VERIF, OP_VERNOTIF disabled, also for a post-Chronicle UTXO, which is this crate's known gap; no pre-Genesis size or count limits; no P2SH evaluation; CLTV and CSV are NOPs). A CHECKSIG's signed subscript continues across the unlock/lock boundary after an OP_CODESEPARATOR, so OP_PUSH_TX covenants verify. A script element may be up to 1 GiB; the working memory budget is 32 MB by default (`memory_limit`); exhausting it is a `ScriptResourceLimit` (`Stack`, `AltStack`, `ElementSize`) that `is_resource_limit()` tells apart from a refusal, and `OP_NUM2BIN` refuses an oversized size operand before allocating it.

**BEEF linking is linear and `verify` walks by txid.** `Transaction::from_beef` links each distinct unproven parent once and gives every later input sourcing the same txid a stub, so a diamond chain (each level spending both outputs of the last) links in time and memory linear in the BEEF; `verify` gathers the reachable transactions into a map by txid, checks a proven one against the `ChainTracker` and does not descend it, executes every input script of an unproven one against its source looked up by txid, and refuses an unproven transaction whose outputs exceed its inputs (a transaction with no inputs is a synthetic root and exempt). A BEEF whose links form a cycle terminates.

**Sighash computation lives in the script templates, not in `Transaction`,** as in the reference SDKs. `SighashCache` computes the three BIP-143 midstates once per transaction and reuses them across inputs (the free functions recompute per call, quadratic in the input count).

**Parsers are bounded.** Every pre-allocation sized by an attacker-controlled count is capped by what the remaining bytes could hold (`primitives::bounded_capacity`): a crafted 20-byte BEEF with a `u32::MAX` input count is an `Err`, never an abort, on native and on `wasm32` (where `panic = abort` would otherwise be unrecoverable).

**wasm32 is a first-class target.** The `wasm` feature routes randomness through the JS host, wall-clock reads through `js_sys::Date` (`std::time::SystemTime` is unimplemented on `wasm32-unknown-unknown`), and the `Peer` handshake timeout through `futures-timer`'s `setTimeout` backend (no tokio time driver exists in a Worker). The Socket.IO transport pulls in no dependency, so enabling it never breaks a wasm build. This build is exercised on every change:

```sh
cargo build --target wasm32-unknown-unknown --no-default-features \
  --features "auth,wallet,transaction,overlay,socketio,wasm"
```

## Conformance

Parity with the reference SDKs is a discipline, not a claim:

- **`tests/vectors/`**: 2,031 JSON vectors shared with the TypeScript and Go SDKs (sighash 500; script evaluation 1,488 across valid, invalid and spend cases; BRC-42 derivation, HMAC-DRBG, AES-256-GCM, certificates, overlay types and admin tokens, wallet wire messages).
- **The `ts-stack` conformance corpus**: `tests/conformance_scripts.rs` drives the interpreter, the sighash builder and the `Script` API through the script-domain corpus (5,116 vectors, the total pinned) and `tests/conformance_beef.rs` the BUMP, serialization, BEEF and regression corpora. They read `$BSV_CONFORMANCE_DIR` (default `../ts-stack/conformance` beside the crate) and skip, loudly, when the corpus is absent; when present, every vector is executed or counted against an enumerated `unsupported` allowlist with a reason, and the per-class counts are pinned so corpus or harness drift is a red test.
- **Cross-SDK wire protocol**: the BRC-100 wallet wire (`WalletWireTransceiver` / `WalletWireProcessor`) round-trips all 28 methods against vectors captured from the Go SDK's serializer.
- **Known divergences are written down**, in `CHANGELOG.md` and in `CLAUDE.md`: the Go SDK's default counterparty (`Anyone` vs `Self`), Go's missing TOTP, overlay caching, historian, reputation and RPuzzle; the TypeScript TOTP default of 2 digits (this crate uses 6, per the RFC); the SDKs' disagreement on the nonce HMAC inputs (`verify_nonce` is only ever called on a peer's own nonces); the Go admin-token signing key; and RFC 6979 nonces for a digest at or above the curve order, where k256 follows the RFC and libsecp256k1 does not (signatures differ in that regime only, and both verify).

## Numbers (measured at 0.3.26)

| | |
|---|---|
| Source | 89,799 lines of Rust under `src/`, 13 feature-gated modules, one `Error` enum |
| Tests | 2,900 passed, 0 failed (1,490 unit, 1,241 integration across 38 files, 169 doc tests); 128 doc examples are `ignore`d illustrations |
| Vectors | 2,031 shared JSON vectors + the `ts-stack` corpus (5,116 script-domain vectors pinned) |
| Fuzzing | 4 libFuzzer targets: the script parser, the transaction parser, the wire protocol, base58 |
| Benchmarks | 4 Criterion suites: hashes, primitives, script, memory (with RSS tracking) |
| CI | Linux, macOS and Windows on stable and beta; clippy with `-D warnings`; rustfmt; doc build |

Run it yourself: `cargo test --features "full,http,websocket"` (with `~/bsv/ts-stack` beside the crate the conformance census runs too).

## Who runs it

The LOW stack ([bsv-low](https://github.com/Calgooon/bsv-low), a real-money card game on mainnet) runs bsv-rs in every one of its Cloudflare Workers: its overlay engine executes every submitted spend with `Transaction::verify` before broadcasting it, its watchtower co-signs 2-of-3 pot spends and verifies BRC-103 envelopes with `ProtoWallet` and `Peer`, its relay speaks BRC-103 over Socket.IO with this crate's transport, its app-layer authenticates with the BRC-104 middleware built on it, and its monitor parses and classifies spends with `Transaction`. Several of this crate's fixes were found there first (see the changelog: bounded pre-allocation, linear BEEF linking, the interpreter's resource-limit class).

## Standards

| BRC | What | Module |
|---|---|---|
| BRC-42 / BRC-43 | Key derivation, security levels, protocol IDs | `wallet` |
| BRC-52 / BRC-53 | Identity certificates, field encryption | `auth` |
| BRC-62 / BRC-74 / BRC-95 / BRC-96 | BEEF, BUMP merkle paths, atomic BEEF, BEEF v2 | `transaction` |
| BRC-77 / BRC-78 | Signed and encrypted messages | `messages` |
| BRC-100 | The wallet interface and its binary wire protocol | `wallet` |
| BRC-103 / BRC-104 | Mutual authentication and its HTTP transport (the successors of BRC-31/Authrite; some older comments still use that name) | `auth` |
| SHIP / SLAP / STEAK | Overlay submission, lookup availability, acknowledgements | `overlay` |
| UHRP | Content-addressed storage | `storage` |

## Development

```sh
cargo test --features "full,http,websocket"        # the suite (conformance census with ts-stack present)
cargo build --examples --all-features              # every README example
cargo test --test readme_examples                  # the README is the examples, byte for byte
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
cargo doc --no-deps --all-features
cargo bench                                        # Criterion suites
cd fuzz && cargo fuzz run fuzz_script_parser       # needs cargo-fuzz
```

Releases: bump `version` in `Cargo.toml`, write the `CHANGELOG.md` entry (what changed, why, which test pins it), `cargo publish`, tag `vX.Y.Z`, push `main` and the tag. Every public API change is additive within 0.3; a struct gaining a public field is called out in the changelog with what a downstream literal needs.

## License

MIT or Apache-2.0, at your option ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).
