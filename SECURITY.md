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

They are on this repository's [Security tab](https://github.com/Calhooon/bsv-rs/security/advisories): each one's affected ranges, its patched versions, its workaround and its own corrections, dated inside it. Each is also filed with the [RustSec advisory database](https://github.com/rustsec/advisory-db), which `cargo audit` and `cargo deny` read once its maintainers merge the file. This page keeps no table of them: a table kept by hand goes stale, and the Security tab does not.
