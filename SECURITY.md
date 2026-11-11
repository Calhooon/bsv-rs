# Security policy

## Reporting a vulnerability

Report it privately, through GitHub's private vulnerability reporting: open this repository's **Security** tab and choose **Report a vulnerability**. The report reaches the maintainers alone and becomes a draft security advisory that you can follow and comment on.

Please do not open a public issue, a pull request or a discussion for it, and do not describe it in one. This repository is public, and every published version a defect is in stays installable until a patch is out.

Include what you can: the version or commit, the feature set, the door (the function or the reader) the input reaches, what you expected and what happened, and a minimal witness if you have one.

## What counts

A defect that a peer's bytes or text can reach, where the peer is anyone who can hand this crate input: a transaction, a BEEF, a script, a signature, a key, a certificate, a wallet wire frame, an HTTP or JSON body, an overlay answer. In particular:

- **A wrong identity:** a txid, hash or index entry that is not the one of the value held, or two byte forms of one value that this crate accepts as one (the class of #840, `docs/design/843-identity-and-framing.md`).
- **A wrong verdict:** a script, transaction, BEEF, merkle proof, signature or certificate accepted where it should be refused.
- **A panic on input:** on wasm32 a panic is an abort nobody can catch.
- **A refusal that should be an acceptance at a consensus door:** a valid transaction or block-level verdict refused under the node's word.
- Unbounded work or memory from a small input, where the crate claims a bound.

Out of scope: a difference from another SDK that the root `CLAUDE.md` already states as a known divergence; a defect in a dependency (report it to that project; tell us too if this crate's use of it makes it reachable); behaviour that needs the caller's own hand edit of a value, with no peer input involved (report it as an ordinary issue).

## Supported lines

| Line | Supported |
|---|---|
| The stable line: the latest patch of the minor on `main` | yes, by a patch release |
| The current beta prerelease on `beta` | yes, in the next prerelease |
| Older minors and older prereleases | no: upgrade to the latest patch of the stable minor |

`Cargo.toml` on each line names its version; crates.io lists every published one.

## What happens after a report

1. The maintainers confirm the report in the draft advisory and say whether it is in scope.
2. The fix is made off the public repository, on the advisory's temporary private fork, with a test that fails before it, for `beta` and for the stable line as a patch under `RELEASING.md`'s direction rule (the security-advisory class; the procedure is `RELEASING.md` step 23). The public pull requests are opened only when the release can follow in the same sitting, their two public CI runs (on `beta` and on the stable line) included.
3. The patch lands, is tagged and is published to crates.io in one sitting, and the advisory is published then, on GitHub (with a CVE requested) and in the RustSec advisory database: the affected range, the patched versions, and the migration if there is one.
4. The advisory is what reaches users, through `cargo audit` and `cargo deny`. A defect that every published release carries is answered by the patch and the advisory, and nothing is yanked: a yank reaches no lockfile and leaves a build with nothing to resolve to. A release that is wrong against its predecessor is yanked and superseded (`RELEASING.md` step 9).

## Published advisories

| Advisory | Patched in | Affected, as published | RustSec |
|---|---|---|---|
| [GHSA-j8hr-pjhm-6h27](https://github.com/Calhooon/bsv-rs/security/advisories/GHSA-j8hr-pjhm-6h27) (published 2026-11-10 20:53Z; High, CVSS 3.1 7.5; a CVE requested, none assigned when this line was written): the transaction readers accepted bytes after the transaction, and the BEEF verdict doors answered valid for a raw entry that is not exactly one transaction | 0.8.5 | `< 0.8.5`, and `>= 0.9.0-beta.1, <= 0.9.0-beta.7` (no patched prerelease yet: the next one that carries the fix is added to both records, `RELEASING.md` step 14) | [rustsec/advisory-db#3539](https://github.com/rustsec/advisory-db/pull/3539) (open when this line was written) |
| [GHSA-9c8r-76f3-m426](https://github.com/Calhooon/bsv-rs/security/advisories/GHSA-9c8r-76f3-m426) (published 2026-11-11 16:58Z; Medium, CVSS 3.1 5.3; a CVE requested, none assigned when this line was written): `Signature::from_der` read malformed encodings of a valid signature (bytes after it, a wrong sequence length, an unneeded zero) as that signature, so one signature verified under many byte forms | 0.8.6 | `< 0.8.6`, and `>= 0.9.0-beta.1, <= 0.9.0-beta.7` (no patched prerelease yet) | [rustsec/advisory-db#3549](https://github.com/rustsec/advisory-db/pull/3549) |
| [GHSA-84xq-3662-pvx5](https://github.com/Calhooon/bsv-rs/security/advisories/GHSA-84xq-3662-pvx5) (published 2026-11-11 16:58Z; Medium, CVSS 3.1 5.3; a CVE requested, none assigned when this line was written): `Transaction::from_json` held an input txid that is not 64 hex digits as given and wrote that input as spending the txid of 32 zero bytes | 0.8.6 | `< 0.8.6`, and `>= 0.9.0-beta.1, <= 0.9.0-beta.7` (no patched prerelease yet) | [rustsec/advisory-db#3549](https://github.com/rustsec/advisory-db/pull/3549) |

Each advisory carries its own corrections, each dated inside it. Read the advisory, not this table, for the doors, the workaround and the current state.
