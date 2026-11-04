# #737, the list: `resolve_by_identity_key` returns every admitted identity in the reference's order

Base `89acc4ff` (`origin/beta`'s tip at the lane's start). The owner's word
of 2026-11-04 13:5xZ on #737's held item: the door takes the reference's
shape, the list, with the reference's trust sort ported in the same row.
#737's first row (`docs/lanes/fix-737.md`) landed the parse of every output
and the subject filter, returning the earliest admitted identity.

## The reference's order, by its code

At `ts-stack@edf6e03`:

- `IdentityClient.resolveByIdentityKey`
  (`packages/sdk/src/identity/IdentityClient.ts:559-591`) returns
  `Promise<DisplayableIdentity[]>`: `parseIdentities` (`:994-1011`) of the
  wallet's `certificates`, one identity per certificate, in the wallet's
  order; with contacts, the contacts' list when there is one (`:575-576`).
- The wallet's `discoverByIdentityKey`
  (`packages/wallet/wallet-toolbox/src/Wallet.ts:966-1016`): the trust
  settings read fresh (`:990`), the certifiers their keys (`:992`), the
  overlay answer through `parseResults`, then
  `transformVerifiableCertificatesWithTrust(trustSettings,
  filterCertificatesByIdentityKey(..))` (`:1010-1013`) and `discoveryPage`
  (`:228-233`, offset 0 and limit 10 by default,
  `validationHelpers.ts:1541-1542`).
- The trust step (`identityUtils.ts:313-382`): the leading 256 certificates
  (`MAX_IDENTITY_RESULTS`, `:22`); one with an empty subject or certifier
  dropped; one whose certifier the settings do not name dropped
  (`:333-334`); grouped by subject in the order each is seen, one certificate per
  `type\0serialNumber\0certifier` (`:360-362`), each certifier's trust
  added to the group once; a group under `trustLevel` dropped
  (`:369-374`); the flattened list sorted by `certifierInfo.trust`
  descending (`:378`), `Array.prototype.sort` stable, so ties keep the
  answer's order.
- go-sdk@2ca481c's `ResolveByIdentityKey` (`identity/client.go:239-255`)
  returns `[]DisplayableIdentity`, its wallet's certificates in order.

## What this crate holds, and the port

This crate has no trust settings (#754's record). Its parser writes one
`CertifierInfo` for every certificate (`trust: 5`, `client.rs`'s
`parse_output_to_certificate`, Step 9). Ported (`src/identity/client_trust.rs`,
`ordered_by_trust`): the cap of 256, the repeat rule, the stable sort by
`certifier_info.trust` descending. After the subject filter there is one
subject group, so the group order is the members' order. Not ported: the
untrusted-certifier drop, the threshold and the settings' trust levels, and
the page. With one trust figure the order here is the answer's; the
reference's is the same when its settings trust the certifiers equally (the
vector's equal-trust shapes) and the most trusted leading otherwise (the
stated shape).

`resolve_by_attributes` keeps its own rule (the `discoverByAttributes`
path, attributes not subject, contacts substituted per subject); not the
same function.

## The signature and the callers

    before: pub async fn resolve_by_identity_key(&self, identity_key: &str, override_with_contacts: bool) -> Result<Option<DisplayableIdentity>>
    after:  pub async fn resolve_by_identity_key(&self, identity_key: &str, override_with_contacts: bool) -> Result<Vec<DisplayableIdentity>>

`grep -rn resolve_by_identity_key src tests examples README.md docs`: the
door and its doc example, `IdentityClient`'s doc example (`client.rs`),
`src/identity/mod.rs`'s module example, `src/identity/CLAUDE.md`'s example,
and four test files (`identity_question_754.rs` `.is_empty()`;
`identity_contact_badges_558.rs`, `identity_from_identity_abbreviated_key_568.rs`
the contact as the one element; `identity_resolve_737.rs` the list;
`identity_evidence_736.rs` maps the result away, unchanged). No README,
example or `docs/` call. The dependents (`~/bsv/bsv-wallet-cli`,
`~/bsv/bsv-wallet-toolbox-rs`, `~/bsv/rust-message-box`,
`~/bsv/bsv-overlay-cloudflare`, `*.rs` and `*.md`, `target` excluded): none.

## The shapes

`tests/support/identity_resolve_737.mjs` extended: `published` takes the
certifier's scalar (7 unless named); a token of the subject (the scalar 9)
by the certifier 8 (`dave@example.com`, serial 32 bytes of 6) issued after
the two earlier tokens, so the counter stream gives them their old bytes;
`trust_levels` per shape. The old recorder re-run beforehand: `cmp` equal to the
committed vector. The new one's two runs byte-identical; the eleven earlier
shapes and two tokens byte for byte.

| Shape | Answer | The reference | `89acc4ff` | Tip |
|---|---|---|---|---|
| (ii) | two certificates of the subject | `[alice, Unknown Identity]` | `[alice]` | the same as the reference |
| (v) | certifier 7's, invalid evidence, certifier 8's, equal trust | `[alice, dave]` | `[alice]` | the same as the reference |
| (v) | the same, certifier 8 trusted at 2 | `[dave, alice]` | `[alice]` | `[alice, dave]`: stated |
| (v) | one output | `[alice]` | `[alice]` | `[alice]` |
| (v) | no output | `[]` | `[]` (`Ok(None)`) | `[]` |
| (ii) | one certificate at two outpoints | `[alice]` | `[alice]` | `[alice]` (the repeat rule) |

On `89acc4ff` (a scratch copy, its own target dir, the tip's test and
vector copied in) 3 of 9 RED; the base's `Ok(None)` reads as no element
through the test's `into_iter`, so the empty cases are GREEN there. On the
tip 9 of 9 GREEN. Below the door, `client_trust.rs`'s three units (trusts 1
and 3 from three certifiers; a repeat beside another certifier's same
serial; 257 certificates). In a scratch copy of the tip with the repeat rule
removed and the sort ascending: `the_token_first_and_one_certificate_twice_resolve_to_its_identity_737`
RED at the door, two of three units RED.

## The recorder

`~/.nvm/versions/node/v22.18.0/bin/node`, bun 1.3.11, the bundle of
`packages/sdk` and the toolbox's `identityUtils.ts` at `edf6e03` built by
the recipe in the recorder's header under
`/Volumes/Lanes/out/bsv-rs/fix-737-list/ref`. The vector's SHA-256
`c47ac59b2ce6f71a64550b3b4a30f42630c7ca42a56a844141cde2d65f42790f`.
