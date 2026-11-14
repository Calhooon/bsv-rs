# Lane fix-912-primitives: the bucket #912 (primitives, the ECDH result)

Opened from `origin/beta` at `80532565`. The bucket holds three lines, what
the builder of #899 (`SharedSecret`) saw and left. No peer's bytes reach any
of them: each is how this process holds its own secret.

## The table

| Line | Fate | Evidence |
|---|---|---|
| 1a. The private scalar is copied out through `to_bytes()` for `mul_scalar` and the copy is not wiped | BUILT | Both `derive_shared_secret` doors and the Schnorr proof's `S' = r*B` (`src/primitives/bsv/schnorr.rs`, the sibling the survey found) multiply through the crate-private `PublicKey::mul_secret(&PrivateKey)`, which reads `PrivateKey::secret_scalar()` (`Zeroizing<NonZeroScalar>`) and exports no byte copy. RED: `tests/arch_ecdh_secret_hygiene_912.rs`, 3 of 3 on a scratch copy of `80532565`. The point unchanged: `mul_secret_is_mul_scalar_of_the_keys_bytes_912` and `tests/shared_secret_bytes_843d6.rs` against `tests/vectors/shared_secret_843d6.json` (not edited) |
| 1b. Whether `SharedSecret`'s point can be wiped on drop (the line asks a measured answer) | ANSWERED, nothing built | k256 0.14.0 `AffinePoint` is `DefaultIsZeroes` (`src/arithmetic/affine.rs:202`), so the point's type can be wiped; elliptic-curve 0.14.3's `PublicKey` has no `Zeroize` and lends the point by `&` alone (`src/public_key.rs:154`), and its `NonIdentity` wipe is a plain store of the generator (`src/point/non_identity.rs:318-322`). So this crate's `PublicKey` cannot be wiped in place without `unsafe` (forbidden, #135). The rustdoc's sentence stands (`src/primitives/ec/shared_secret.rs`). What a wipe would take is below |
| 2. `PublicKey`'s `==` compares compressed bytes in variable time | BUILT (both remedies) | `impl PartialEq for PublicKey` compares through `subtle::ConstantTimeEq`, the same answer for every pair; `SharedSecret::to_point`'s rustdoc says to compare the `SharedSecret`s. RED: `public_key_equality_reads_its_bytes_without_an_early_exit_912` (`PublicKey's eq does not call ct_eq` on the scratch copy) |
| 3. `derive_child` has no shared-secret cache callbacks | NEEDS A DECISION | The reference at the pin, read: below. Nothing built |

## Line 1: the survey (root rule 11)

The shape: a private scalar exported as bytes inside the crate and left
unwiped. Every non-test site under `src/primitives/` that calls `to_bytes()`
on a private key, at `80532565`:

- `ec/private_key.rs:294`, `ec/public_key.rs:327-328`, `bsv/schnorr.rs:107`:
  the scalar handed to `mul_scalar`. Fixed here, and held by the arch test's
  rule (1) (the `public_key.rs` site bound the bytes on one line and passed
  them on the next, which the rule's stated bound does not see; it is gone).
- Left, each its own change, none asked by the bucket's line:
  `ec/private_key.rs:345` (`derive_child`'s `BigNumber::from_bytes_be(&self.to_bytes())`;
  a `BigNumber` is heap digits with no wipe, so wrapping the 32 bytes wipes
  the smaller half), `:380` (`PartialEq`'s two copies), `p256.rs:240` (the
  same for P-256), `bsv/shamir.rs:466,533` (the polynomial's coefficients as
  `BigNumber`s), `bsv/shamir_legacy.rs:34` (a hash of the key's bytes).
  `bsv/schnorr.rs:114-115` (added by the strength read: `generate_proof`'s
  `z = r + e*a` reads the nonce `r` and the key `a` through `to_bytes()`
  into `BigNumber`s two lines after `r*B` moved to `mul_secret`, so the
  nonce's bytes, from which `z` and `e` give `a`, are still copied out
  unwiped in the same function; the survey's list missed the two lines).
  `to_hex`, `to_wif` (`:235`, `:258`) return the secret by name.

What a wipe does not reach, stated in the CHANGELOG entry: a moved value's
old place, k256's own temporaries (`mul_scalar`'s and `mul_secret`'s
projective and affine products are ordinary stack values), and the copies
the public doors return.

## Line 1b: what a wipe of the point would take (not built)

`SharedSecret` would hold `Zeroizing<AffinePoint>` in place of this crate's
`PublicKey`. `to_compressed` and `x` read the affine point directly;
`to_point` rebuilds a `PublicKey` through `k256::PublicKey::from_affine`,
which answers a `Result` (the identity refused), so the infallible
`to_point` would carry a branch no input reaches (clippy's `unwrap_used`,
`expect_used` and `panic` are denied, and the mutation gate would hold an
unkillable mutant there). The wipe would cover the stored field alone: the
`PublicKey` handed to `from_point`, and every value `to_point`, `x` and
`to_compressed` return, are copies it does not reach. No public shape
moves either way. Recommendation: leave it stated until `PublicKey` itself
holds an `AffinePoint` (a change of its own), then wipe both.

## Line 3: the question for the captain

The reference at the pin (`ts-stack@edf6e03`, read by `git show`):
`PrivateKey.deriveChild(publicKey, invoiceNumber, cacheSharedSecret?, retrieveCachedSharedSecret?)`
(`packages/sdk/src/primitives/PrivateKey.ts:439-444`, used `:446-457`) and
`PublicKey.deriveChild(privateKey, invoiceNumber, cacheSharedSecret?, retrieveCachedSharedSecret?)`
(`PublicKey.ts:205-210`, used `:212-224`): when the retrieve callback is
given and answers a point, that point is the shared secret; else it is
derived and handed to the store callback. Callers at the pin, by
`git grep` over `packages/`: `KeyDeriver` alone passes them on
(`wallet/KeyDeriver.ts:137-141`, `:172-173`, `:180-181`, `:202-203`, and
its own use at `:232-237`, `:293`, `:306`), and the one constructor call
that supplies them is `CachedKeyDeriver`'s (`wallet/CachedKeyDeriver.ts:50-58`);
the eleven other `new KeyDeriver(` sites outside tests and docs pass the
root key alone. go-sdk@2ca481c's `DeriveChild` takes no such parameter
(`primitives/ec/privatekey.go:208`, `publickey.go:305`). This crate:
`PrivateKey::derive_child(other_pubkey, invoice_number)` and
`PublicKey::derive_child(other_privkey, invoice_number)`; `CachedKeyDeriver`
caches the derived public, private and symmetric keys by protocol, key id
and counterparty (`src/wallet/cached_key_deriver.rs:180-182`), not the
shared secret. No derived key differs: a cache changes no byte.

- Way A, a row in the divergence list: `derive_child` takes no cache
  callbacks; `CachedKeyDeriver`'s own caches stand for the one use the
  reference makes of them. Cost to a caller: a port of reference code that
  passes its own cache drops the two arguments and derives each time (one
  point multiplication), or caches the derived key itself.
- Way B, additive doors: `derive_child_with_cache` on both keys and a
  `KeyDeriver` constructor taking a cache. Cost: a new public surface that
  hands `SharedSecret`s to caller-held storage (the type has no `Hash` and
  no serde by design, #843d6), a retrieve callback that can answer any
  point for any pair (the derived key is then whatever the callback says),
  and a shape to keep through 0.9's freeze.
- Way C, nothing: the difference stays unstated.

Recommendation: Way A. The pin's one supplier of the callbacks is the
reference's own cached deriver, this crate has that type with its own
caches, and Way B opens a door for a secret that #843d6 closed. The row is
a sentence in the root `CLAUDE.md` list and a CHANGELOG parity note, the
captain's to word (a stated divergence is not a lane's to add under this
brief).

## The RED

A scratch copy of `80532565` (`git archive`), `tests/arch_ecdh_secret_hygiene_912.rs`
added and nothing else, its own target dir (removed):

```
test the_scalar_the_private_key_lends_is_wiped_when_dropped_912 ... FAILED
test public_key_equality_reads_its_bytes_without_an_early_exit_912 ... FAILED
test no_private_scalar_is_copied_out_for_a_point_multiplication_912 ... FAILED
`PrivateKey::secret_scalar` is in src/primitives/ec/private_key.rs
left: Some("`PublicKey`'s `eq` does not call `ct_eq`")
src/primitives/bsv/schnorr.rs:107: let s_prime = big_b.mul_scalar(&r.to_bytes())?;
src/primitives/ec/private_key.rs:294: .mul_scalar(&self.to_bytes())
```

Green on the lane: 3 of 3. The RED is lexical: a wipe cannot be observed
by safe code, and a comparison's timing is no hermetic test.

## Files under `src/`

`src/primitives/ec/private_key.rs`, `src/primitives/ec/public_key.rs`,
`src/primitives/ec/shared_secret.rs` (rustdoc alone),
`src/primitives/bsv/schnorr.rs`, `src/primitives/ec/CLAUDE.md`.

## The gate

Run in the foreground on macOS arm64, a private target dir, one cargo at a
time, at the lane's commit over `80532565`:

- The lint job's Rustfmt step, its three lines: clean.
- `cargo +1.100.0 clippy --all-targets --all-features -- -D warnings`: exit 0.
- `cargo check --all-targets --all-features`: exit 0.
- The wasm32 slice of root rule 6: exit 0.
- `cargo test --features "full,http" --lib primitives::`, three times, the
  third with `--test-threads=1`: 392 passed, 0 failed each.
- `--test arch_ecdh_secret_hygiene_912 --test shared_secret_bytes_843d6
  --test secret_debug --test arch_shared_secret_843d6
  --test primitives_public_key_forms_498`, three times, the third
  single-threaded: 34 passed, 0 failed each.
- `cargo test --features "full,http" --test 'arch_*'`: 35 files, 181
  passed, 0 failed, 1 ignored.
- `--test fixtures_replay`, `--test readme_examples`: 1 and 1 passed.
- `RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --all-features`: exit 0;
  `cargo test --doc --all-features primitives::ec`: 21 passed.
- `tools/ratchet/run --check --against origin/beta`: all 7 counters,
  oversized-file limits and mutation floors pass.
- `mutants_entries.py`: PASS, 28 entries. `rows_from_sources.py --check`:
  0 refusals. gitleaks, git mode, `origin/beta..HEAD`: no leaks found.

Not run: the whole suite, the clippy slices beyond `--all-features`,
`cargo mutants` on the two new functions, a Linux or Windows witness (CI's).
