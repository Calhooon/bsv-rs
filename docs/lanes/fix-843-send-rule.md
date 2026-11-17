# Lane fix-843-send-rule: every public async trait is `Send` on every target

#843, the captain's ruling 1 of 2026-11-17 (six design reads; the tie-break 3
of 3 on a compile); BREAKING, in the 0.9.0 cut. Started from `7d571b7b` (pull
request #915 carried onto beta `4c5454be`: `Transaction`, `Script` and `Beef`
`Send` and `Sync`).

## The rule

Every public async trait is `Send` on every target, with no `cfg` in a public
signature; the future of every public async door is `Send`.

| Trait | Before | After |
|---|---|---|
| `ChainTracker`, `WalletInterface`, `WalletWire`, `Transport` | `#[async_trait]`, `: Send + Sync` | unchanged |
| `SocketIoFrameSource` | `#[async_trait]`, `: Send` | unchanged |
| `Broadcaster` | `#[async_trait(?Send)]`, `: Send + Sync` | `#[async_trait]` |
| `OverlayLookupFacilitator` | `#[async_trait(?Send)]`, `: Send + Sync` | `#[async_trait]` |
| `OverlayBroadcastFacilitator` | `#[async_trait(?Send)]`, `: Send + Sync` | `#[async_trait]` |

The reference returns a promise at each of the three (`ts-stack@edf6e03`
`Broadcaster.ts:148-151`, `LookupResolver.ts:692-707`,
`SHIPBroadcaster.ts:88-90`; each interface the same text at its head
`11faa7d16`, `@bsv/sdk` 4.1.1, compared by `git show` on 2026-11-17), and
go-sdk@2ca481c a plain interface (`transaction/broadcaster.go:70-73`): neither
has the notion, no wire byte or verdict moves, and no divergence row opens or
closes.

## What was measured

All on the base `7d571b7b` and on the lane's tip, toolchain 1.100.0.

- **The doors.** 241 public async doors under `src/`: 201 `pub async fn`
  (a name once per file; six are written twice under `http` and its
  negation) in 40 files, and the 40 `async fn` of the eight traits. 240 have
  a witness; one cannot be named from outside its module
  (`PeerState::wait_for_certificates`, `pub(super)`, reached through
  `AuthFetch`'s doors).
- **The witnesses on the base** (the eight files of `src/send_rule/` and the
  one `mod` line overlaid): natively under every feature 36 refused, 49
  errors (the six methods of the three traits; `LookupResolver::query` and
  `find_competent_hosts`; `TopicBroadcaster::broadcast_tx` and
  `find_interested_hosts`; eight doors of `IdentityClient`, the nine of
  `GlobalKVStore`, six of `RegistryClient`, `StorageDownloader::resolve` and
  `download`; `Historian::build_history`); in the wasm32 slice of rule 6
  (`auth,wallet,transaction,overlay,socketio,wasm`) 11 refused, 12 errors.
  The 204 other witnesses compiled there: the five traits that were `Send`
  already and every door over them alone.
- **The witnesses on the tip.** 0 errors natively under every feature, in
  rule 6's wasm32 slice, and on wasm32 under `full,wasm` (every module but
  `http`).
- **The change itself.** Nine attribute lines in six files of `src/` (the
  three traits and the crate's six implementations: the three HTTP
  broadcasters, `TopicBroadcaster`, the two HTTPS facilitators), one more in
  a test module, two doc examples, the alias `InterpreterFn`, and 71
  attributes in 59 files of `tests/` (and one comment there that said a
  lookup could not be spawned). Nothing else: with #915 in, no implementation of the crate or of
  its tests held a value that is not `Send` across an `.await` (the whole
  suite compiled after the attributes alone).
- **The `http` paths on wasm32.** None exists: `build.rs` refuses `http` on a
  wasm32 target (#152), and no other feature holds a client. So the crate
  carries no per-target bridge, private or public.

## The class (rule 11)

The invariant: a public async door's future is `Send`, by its signature, on
every target. The siblings were looked for by a run (the witnesses over every
`pub async fn`, compiled) and by a lexical scan (every `dyn Future` and
`impl Future` written under `src/`):

| Sibling | Found by | Answer |
|---|---|---|
| `InterpreterFn<T, C>`: `Pin<Box<dyn Future<Output = Option<T>>>>`, no `Send`, so `Historian::build_history` could not be spawned | the witness of `build_history` (E0277) and the scan | mended in this change: the future carries `+ Send` (no dependent on this host names the alias or `Historian`) |
| `AsyncByteSource::next_chunk`: `impl Future` with no bound | the scan | stated, not changed: a static trait (no object, no `async_trait`), its future's `Send` its implementor's, so `AsyncStreamVerifier::run` and `verify_stream_async` are `Send` when the source's future is (witnessed with a `Send` source). A `+ Send` on it would break a Worker reading its request body, and a `Send` sibling is additive later |
| `with_double_spend_retry<T, F, Fut>` | the witness | `Send` when the caller's operation is (witnessed with one) |
| `WalletWireProcessor`'s private `invoke_wallet(operation: impl Future)` | the scan | private; `Send` by inference at each call, held by `process_message`'s witness |

The machine for the class is the pair: the compiler (`src/send_rule/`) and
the census (`tests/arch_send_rule_843.rs`), so a door added later lands with
its witness or fails by name.

## The bridge for a wasm32 implementor, compiled

A wasm32 implementor that holds JS values (which are not `Send`) wraps the
handle it holds and the call it awaits in its platform's bridge. For a
Cloudflare Worker that is `worker::send` (`worker` 0.8.7, `src/send.rs`:
`SendFuture`, `SendWrapper`). The probe below was compiled against this
lane's tip (`bsv-rs` by path, features `overlay,wasm`) with `cargo check
--offline`, natively and for `wasm32-unknown-unknown`: 0 errors on both, with
`#![forbid(unsafe_code)]` in the implementor and no `cfg`. `Handle` stands in
for a JS handle and `js_call` for a `JsFuture`.

```rust
#![forbid(unsafe_code)]
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, OverlayBroadcastFacilitator, OverlayLookupFacilitator, Steak,
    TaggedBEEF,
};
use bsv_rs::transaction::{
    BroadcastFailure, BroadcastResponse, BroadcastResult, Broadcaster, ChainTracker,
    ChainTrackerError, Transaction,
};
use std::cell::RefCell;
use std::rc::Rc;
use worker::send::{SendFuture, SendWrapper};

type Handle = Rc<RefCell<u32>>; // not `Send`, not `Sync`

async fn js_call(handle: Handle) -> u32 {
    let held = handle.clone();
    std::future::ready(()).await;
    let value = *held.borrow();
    value
}

pub struct WorkerTracker {
    handle: SendWrapper<Handle>,
}

#[async_trait::async_trait]
impl ChainTracker for WorkerTracker {
    async fn is_valid_root_for_height(
        &self,
        _root: &str,
        height: u32,
    ) -> Result<bool, ChainTrackerError> {
        let handle = self.handle.clone();
        Ok(SendFuture::new(async move { js_call(handle.0).await }).await == height)
    }

    async fn current_height(&self) -> Result<u32, ChainTrackerError> {
        let handle = self.handle.clone();
        Ok(SendFuture::new(async move { js_call(handle.0).await }).await)
    }
}

pub struct WorkerBroadcaster {
    handle: SendWrapper<Handle>,
}

#[async_trait::async_trait]
impl Broadcaster for WorkerBroadcaster {
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult {
        let handle = self.handle.clone();
        let txid = tx.id();
        match SendFuture::new(async move { js_call(handle.0).await }).await {
            0 => Err(BroadcastFailure::new("REFUSED".into(), "refused".into())),
            _ => Ok(BroadcastResponse::success(txid, "sent".into())),
        }
    }
}

pub struct WorkerLookup {
    handle: SendWrapper<Handle>,
}

#[async_trait::async_trait]
impl OverlayLookupFacilitator for WorkerLookup {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        let handle = self.handle.clone();
        SendFuture::new(async move { js_call(handle.0).await }).await;
        Ok(LookupAnswer::OutputList { outputs: vec![] })
    }
}

pub struct WorkerSubmit {
    handle: SendWrapper<Handle>,
}

#[async_trait::async_trait]
impl OverlayBroadcastFacilitator for WorkerSubmit {
    async fn send(&self, _url: &str, _tagged: &TaggedBEEF) -> bsv_rs::Result<Steak> {
        let handle = self.handle.clone();
        SendFuture::new(async move { js_call(handle.0).await }).await;
        Ok(Steak::new())
    }
}
```

The same bridge on a production tracker: the overlay Worker's
`ChainTracker` implementation, rewritten in a scratch copy at its own pin
(bsv-rs 0.8.11, whose `ChainTracker` is the trait of this tip line for line,
a path spelling of `ChainTip` aside) onto `SendWrapper` fields and
`SendFuture` calls under plain `#[async_trait]`, compiled for wasm32 and
natively with every target: 0 errors, one file, +23 and -76 lines, no
`unsafe` left in it. The rule itself needs no change there: the trait's bound
did not move.

## The dependents

| Dependent | Pin | How measured | From this rule |
|---|---|---|---|
| the wallet toolbox | `=0.9.0-beta.8` | compiled at its pin through `[patch.crates-io]`, natively, every target, against the base and against the tip | 0: the same 9 errors on both (the `chunks()` slice of #843d1, in its tests) |
| the overlay Worker | `0.8.11` | the pin does not reach this line; `git grep` | 0: no implementation of the three traits (its own `Broadcaster` is its engine's trait), no `InterpreterFn` |
| the wallet CLI | `=0.8.11` | `git grep` | 0 |
| the middleware | `0.3` | `git grep` | 0 |
| the message box | `=0.4.5` | `git grep` | 0 (its 47 `?Send` attributes are on its own traits) |

## What this does not hold

- A witness says a future is `Send` for the argument types the witness
  names or infers; that they are the door's own is the compiler's claim, by
  the call itself.
- A wasm32 slice CI does not build (`kvstore`, `registry`, `storage`,
  `identity` on wasm32) holds its witnesses only where someone builds it;
  the lane built `full,wasm` once.
- cargo-semver-checks 0.51.0 fires no lint on this break (202 checks pass, 58
  skipped): the label `api-break` is the pull request's, by hand.
