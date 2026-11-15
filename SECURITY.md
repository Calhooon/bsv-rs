# Security policy

## Reporting a vulnerability

Report it privately, through GitHub's private vulnerability reporting: open this repository's **Security** tab and choose **Report a vulnerability**. The report reaches the maintainers alone and becomes a draft security advisory that you can follow and comment on.

Please do not open a public issue, a pull request or a discussion for it, and do not describe it in one. This repository is public, and every published version a defect is in stays installable until a patch is out.

Include what you can: the version or commit, the feature set, the door (the function or the reader) the input reaches, what you expected and what happened, and a minimal witness if you have one.

## What counts

A defect that a peer's bytes or text can reach, where the peer is anyone who can hand this crate input: a transaction, a BEEF, a script, a signature, a key, a certificate, a wallet wire frame, an HTTP or JSON body, an overlay answer. In particular:

- **A wrong identity:** a txid, hash or index entry that is not the one of the value held, or two byte forms of one value that this crate accepts as one (the class of #840).
- **A wrong verdict:** a script, transaction, BEEF, merkle proof, signature or certificate accepted where it should be refused.
- **A panic on input:** on wasm32 a panic is an abort nobody can catch.
- **A refusal that should be an acceptance at a consensus door:** a valid transaction or block-level verdict refused under the node's word.
- Unbounded work or memory from a small input, where the crate claims a bound.

Out of scope: a difference from another SDK that the root `CLAUDE.md` already states as a known divergence; a defect in a dependency (report it to that project; tell us too if this crate's use of it makes it reachable); behaviour that needs the caller's own hand edit of a value, with no peer input involved (report it as an ordinary issue).

## Audits

This crate has had no third-party security audit. The advisories published so far were found by this project's own reads; each says so in its text.

## Supported lines

| Line | Supported |
|---|---|
| The stable line: the latest patch of the minor on `main` | yes, by a patch release |
| The current beta prerelease on `beta` | yes, in the next prerelease |
| Older minors and older prereleases | no: upgrade to the latest patch of the stable minor |

`Cargo.toml` on each line names its version; crates.io lists every published one.

## What happens after a report

1. The maintainers confirm the report in the draft advisory and say whether it is in scope.
2. The fix is made off the public repository, on the advisory's temporary private fork, with a test that fails before it, for `beta` and for the stable line as a patch under `RELEASING.md`'s direction rule (its security-advisory class). The public pull requests are opened only when the release can follow in the same sitting, their two public CI runs (on `beta` and on the stable line) included.
3. The patch lands, is tagged and is published to crates.io in one sitting, and the advisory is published then on this repository's Security tab: the affected range, the patched versions, and the migration if there is one. No file is sent to the RustSec advisory database ("Published advisories", below; "CVE ids" there says what is true of a CVE id).
4. The advisory on the Security tab is what reaches users. `cargo audit` and `cargo deny` report no advisory of this crate published after 2026-11-13: "Published advisories", below, says what each tool reports and how to hear of an advisory. A defect that every published release carries is answered by the patch and the advisory, and nothing is yanked: a yank reaches no lockfile and leaves a build with nothing to resolve to. A release that is wrong against its predecessor is yanked and superseded (`RELEASING.md` step 9).

## Published advisories

They are on this repository's [Security tab](https://github.com/Calhooon/bsv-rs/security/advisories): each one's affected ranges, its patched versions, its workaround and its own corrections, dated inside it. That tab is the record, and the one place where every advisory of this crate is published.

### What `cargo audit`, `cargo deny` and Dependabot report

`cargo audit` and `cargo deny` read the [RustSec advisory database](https://github.com/rustsec/advisory-db). This project files no advisory of this crate with the RustSec advisory database any more (a decision of the project's owner, 2026-11-13): the last one it filed is 0.8.9's, published that day. So neither tool reports an advisory of this crate published after 2026-11-13, and a clean `cargo audit` or `cargo deny check advisories` says nothing about one.

The six advisories published through 2026-11-13, as the public databases read on 2026-11-14:

| Advisory | Patched in | In the RustSec database |
|---|---|---|
| [GHSA-j8hr-pjhm-6h27](https://github.com/Calhooon/bsv-rs/security/advisories/GHSA-j8hr-pjhm-6h27) | 0.8.5 | yes: RUSTSEC-2026-0498, RUSTSEC-2026-0500 |
| [GHSA-9c8r-76f3-m426](https://github.com/Calhooon/bsv-rs/security/advisories/GHSA-9c8r-76f3-m426) | 0.8.6 | yes: RUSTSEC-2026-0499 |
| [GHSA-84xq-3662-pvx5](https://github.com/Calhooon/bsv-rs/security/advisories/GHSA-84xq-3662-pvx5) | 0.8.6 | yes: RUSTSEC-2026-0497 |
| [GHSA-cwxv-4866-5gq2](https://github.com/Calhooon/bsv-rs/security/advisories/GHSA-cwxv-4866-5gq2) | 0.8.7 | yes: RUSTSEC-2026-0501 |
| [GHSA-gg5p-wgff-v3hr](https://github.com/Calhooon/bsv-rs/security/advisories/GHSA-gg5p-wgff-v3hr) | 0.8.8 | no |
| [GHSA-mj2m-jxgv-r446](https://github.com/Calhooon/bsv-rs/security/advisories/GHSA-mj2m-jxgv-r446) | 0.8.9 | yes: RUSTSEC-2026-0529 |

That day each of the six also named the prereleases 0.9.0-beta.1 to 0.9.0-beta.7 as affected, and no later prerelease was published; the advisory itself names the prerelease that carries its fix once there is one. The table is closed: it gains no row, and an advisory published after 2026-11-13 is on the Security tab and filed nowhere else by this project.

Dependabot reads the GitHub Advisory Database (`github.com/advisories`), which is not this repository's Security tab. On 2026-11-14 that database listed none of the six, so none of them raised a Dependabot alert that day; `gh api advisories/<GHSA id>` answers 404 for an advisory it does not list.

### CVE ids

A CVE was requested from GitHub for each of the six advisories of the table, at its publication: GHSA-j8hr-pjhm-6h27 on 2026-11-10, GHSA-9c8r-76f3-m426 on 2026-11-11, GHSA-84xq-3662-pvx5 on 2026-11-11, GHSA-cwxv-4866-5gq2 on 2026-11-12, GHSA-gg5p-wgff-v3hr on 2026-11-12 and GHSA-mj2m-jxgv-r446 on 2026-11-13 (the comment that records each release on [#849](https://github.com/Calhooon/bsv-rs/issues/849) says so, the same day). GitHub's record showed no CVE id for any of the six on 2026-11-15; an id GitHub assigns after that day is in the advisory itself.

The CVE id of an advisory published after 2026-11-13, if it has one, is in the advisory on the Security tab. This page states no rule about requesting one.

### How to hear of an advisory

- Read the Security tab before you upgrade, and on a schedule of your own. A script or a scheduled CI job reads the same list: `gh api repos/Calhooon/bsv-rs/security-advisories --jq '.[] | select(.state == "published") | [.ghsa_id, .severity, .published_at] | @tsv'`.
- Watch this repository's [releases](https://github.com/Calhooon/bsv-rs/releases) (**Watch**, then **Custom**, then **Releases**, or the feed `https://github.com/Calhooon/bsv-rs/releases.atom`). A security patch is a release, published in the sitting that publishes its advisory, so a new patch release is the moment to read the Security tab.
- Read `CHANGELOG.md`: the section of a patch release says what it fixed.
