# Lane fix-843-setter-receivers: a field's setter is a chainable `self` method

#843, the captain's ruling 10 (2026-11-17), from a row of pull request
#1038's strength read: on a `#[non_exhaustive]` struct whose fields are set
by chainable setters, a public field's setter takes `self` and returns
`Self`. A function named `with_<field>` that takes no `self` is a
constructor, and a field whose only setter is such a constructor cannot be
set in a chain. BREAKING, in the 0.9.0 cut. Run on 2026-11-17 from
`5bb43bb4` (`origin/lane/rebase-843d8c`, pull request #1038, stacked on
#1005). The rule is this crate's own; no reference record decides it.

## The machine

`tests/arch_non_exhaustive_843d.rs` accepted a setter by its name alone
(`with_<field>`, or the one `NAMED_SETTERS` names). It now reads each
inherent method's signature (`chainable`): a setter's receiver is `self` or
`mut self` and it returns `Self`, or its receiver is `&mut self` (a lifetime
allowed) and it returns `&mut Self`. A `with_<field>` (or named setter) that
takes no `self`, when it is its field's only setter and the field is no
parameter of `new`, is refused by name and `path:line`, whatever `ASSIGNED`
says. `a_setter_is_a_chainable_self_method_the_receiver_read_843` pins the
reading on a sample text (six forms: an associated function, `mut self ->
Self`, `&'x mut self -> &'x mut Self`, `self -> Option<Self>`, `&self ->
Self`, `self -> Self where ..`; three refused).

## The class, as the test printed it on the base

On a scratch copy of `5bb43bb4` with the test file overlaid (log:
`/Volumes/Lanes/out/bsv-rs/fix-843-setter-receivers/`), the table test
failed naming two, and no other field of the 33 attributed structs:

| Type | Field | Function | Place |
|---|---|---|---|
| `IdentityClientConfig` | `originator` | `with_originator(originator: impl Into<String>) -> Self` | `src/identity/types.rs:683` |
| `ContactsManagerConfig` | `originator` | `with_originator(originator: impl Into<String>) -> Self` | `src/identity/types.rs:767` |

Both had a `Default`, so each became `with_originator(mut self, ..) ->
Self`, and the construction it gave is `Type::default().with_originator(..)`.

## The call sites converted (19)

| File | Sites |
|---|---:|
| `src/identity/client.rs` (unit tests) | 2 |
| `src/identity/mod.rs` (module doc, a compiled doc test) | 1 |
| `src/identity/types_tests.rs` | 1 |
| `tests/identity_tests.rs` | 6 |
| `tests/identity_reveal_create_action_315.rs` | 1 |
| `tests/identity_wallet_calls_318.rs` | 1 |
| `tests/wallet_originator_option_329.rs` | 3 |
| `src/identity/CLAUDE.md` (the manual, not compiled) | 4 |

No assertion moved. Dependents' clones on this host, call sites of either
function under `src/`, `tests/` (and `crates/`, `workers/` where present):
`bsv-wallet-toolbox-rs` 0, `bsv-wallet-cli` 0, `bsv-overlay-cloudflare` 0,
`rust-message-box` 0, `bsv-middleware-rs` 0, `chaintracks-cloudflare` 0;
`bsv-middleware-cloudflare-public`, `rust-chaintracks` and
`bsv-middleware-cloudflare` absent.

## What is not in the class

Every public `fn with_*` under `src/` that takes no `self`, after the change
(34). None is on an attributed struct, so the rule does not read any of
them; none is a constructor on an attributed struct beside a `self` setter
of the same field.

| Type | Function(s) | Judged | Why it stays |
|---|---|---|---|
| `AuthFetch` | `with_client`, `with_transport_factory` | no | client, not a fields struct |
| `SimplifiedFetchTransport` | `with_client` | no | transport, private fields |
| `PeerSession` | `with_nonce` | no | Record row, not attributed |
| `IdentityClient` | `with_resolver` | no | client, private fields |
| `GlobalKVStore` | `with_network`, `with_resolver` | no | store, private fields |
| `HostReputationTracker` | `with_config`, `with_storage`, `with_config_and_storage` | no | tracker, private fields |
| (free function) | `overlay::with_double_spend_retry` | no | a function, no type |
| `TaggedBEEF` | `with_off_chain_values` | no | Record row, not attributed |
| `Writer` | `with_capacity` | no | Rust's ordinary constructor name |
| `TokenData` | `with_beef` | no | Record row, not attributed |
| `Spend` | `with_transaction` | no | interpreter, private fields |
| `Beef` | `with_version` | no | not all-public, not attributed |
| `BroadcastFailure` | `with_txid`, `with_details` | no | Record row, not attributed |
| `ArcBroadcaster`, `TeranodeBroadcaster`, `WhatsOnChainBroadcaster` | `with_config` | no | broadcaster built from config |
| `WhatsOnChainBroadcaster`, `WhatsOnChainTracker` | `with_base_url` | no | built from a URL |
| `BlockHeadersServiceTracker`, `LivePolicy` | `with_url`, `with_config` | no | built from URL or config |
| `TransactionInput` | `with_source_transaction` | no | Record row, not attributed |
| `Transaction` | `with_params` | no | private fields, owned type |
| `WalletClient` | `with_substrate` | no | client, private fields |
| `ReviewActionsRefusal` | `with_members` | no | Unruled row, not attributed |
| `HttpWalletJson`, `HttpWalletWire` | `with_client` | no | substrate, private fields |
| `WireWriter` | `with_capacity` | no | Rust's ordinary constructor name |

Not public, not read: `TopicBroadcaster`'s cache `with_clock`
(`pub(super)`), `merkle_path_legal`'s two (`pub(super)`),
`with_wallet_double_spend_retry` (`pub(crate)`).

Two names to watch: `TaggedBEEF::with_off_chain_values` and
`Beef::with_version` share a field's name. Neither type is attributed
today; if either takes `#[non_exhaustive]` the test reads the function and
refuses it unless a `self` setter of that field exists beside it.

## semver

`cargo-semver-checks` 0.51.0, as beta's job runs it (`check-release
--baseline-rev 5bb43bb4 --all-features --release-type minor`, Rust 1.95.0):
202 checks, 202 pass, 58 skip, "no semver update required". It has no lint
for an associated function that becomes a method, so this break is not
seen by the tool: the pull request carries the `api-break` label on the
CHANGELOG's word, not the tool's.
