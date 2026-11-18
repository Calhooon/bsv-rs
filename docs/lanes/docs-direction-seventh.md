# Lane docs-direction-seventh: the direction rule's seventh class and the advisories shape beside the classes (2026-11-17)

Opened from `origin/beta` at `4c5454be`. The owner's word of 2026-11-17, on the captain's recommendation, given for #1042 and #1043 and for the pick of #1034's workflow (pull request #1035): (1) the stable line takes an additive item that a live dependent's stable line needs, under a bar; (2) the advisories shape of #1034 is taken by `main`. The rule's text is the captain's, placed in `RELEASING.md` with its grammar fitted to the section; one parenthetical added to the seventh bullet says how a port names its `beta` commit (step 17's `-x` line), the mark `beta-born` reads.

## The search

```
git grep -n -i -E 'six classes|six class|the sixth|classes only|direction rule' -- . ':!CHANGELOG.md'
git grep -n -i -E '(four|five|six|seven) (quick-fix )?classes|class(es)? (main|`main`) (takes|accepts)' -- . ':!CHANGELOG.md' ':!docs/lanes/*'
git grep -l 'RELEASING.md' -- tests .github/scripts | xargs grep -n -i 'class'
```

The hits that are another sense of "sixth" or "class" (a fold, a fixture, the foreign-type classes of `arch_no_foreign_type_843d23.rs`, #408's four classes) are not listed.

| Place | What it says | Fate |
|---|---|---|
| `RELEASING.md:38` | `main` accepts a quick fix of six classes only | changed: seven, the seventh named as the fifth and sixth are |
| `RELEASING.md:45-46` | the six bullets | changed: the sixth ends with `;`, the seventh bullet added |
| `RELEASING.md:48` | Beside the six classes ... | changed: seven; the advisories shape added to the list |
| `RELEASING.md:23` (step 8) | the `version` job is none of the direction rule's six classes | changed: seven (still none of them) |
| `CLAUDE.md:20` (rule 10) | six classes only, the fifth and sixth named; beside the six classes | changed: seven, the seventh named, the advisories shape beside |
| `docs/lanes/README.md:17` | only in the four classes (`beta-born` holds every PR into `main` to that) | changed: the seven classes that rule names; `beta-born` reads no class |
| `SECURITY.md:40` | a patch under the direction rule (the security-advisory class) | true as it stands |
| `docs/releases/README.md:10` | the front pages under the fifth class | true as it stands |
| `tests/arch_ci_lines.rs:58,1679-1877` | pins the class of a security advisory | true as it stands (not the count) |
| `tests/CLAUDE.md:118` | the direction rule, by name | true as it stands |
| `.github/workflows/ci.yml:1058,1102`, `sync-main-into-beta.yml:3,143` | the direction rule, by name | true as it stands |
| `HANDOFF.md:11,365` | four classes | history (a dated record of 2026-11-02), not rewritten |
| `docs/design/843-identity-and-framing.md:189` | four classes only | history (a dated design record), not rewritten |
| `docs/lanes/fix-849-security-page.md:244`, `fix-wallet-buckets.md:145`, other lane briefs | six classes or the rule by name | history (lane records), not rewritten |
| `CHANGELOG.md:5248` and older entries | six classes (#909) | history, not rewritten |

## What enforces a class

Nothing reads a class. `beta-born` (`ci.yml`, the job of that name) asks of each commit of a pull request into `main` that it be on `origin/beta` by patch (`git cherry`), name a `beta` ancestor in a `(cherry picked from commit <40 hex>)` line, be named by such a line of a `beta` commit, or be a release commit. Its shell, cut from `ci.yml` with the fetch line replaced by a no-op (local refs), was run by hand on two stand-in commits over `origin/main` (a tree with one added file, built with `git commit-tree`, no branch):

- a port whose message carries `(cherry picked from commit <origin/beta's sha>)`: passes, exit 0;
- the same port naming its source in prose alone (`ports beta commit <sha> by hand`): refused, exit 1, `1 commit(s) of this PR were not born on beta`.

So a seventh-class port passes as written when it carries the `-x` line, which step 17 already asks of a hand-resolved pick. No change to the job; the bullet says so in its parenthetical.

## `main`'s copy

`origin/main` carries `RELEASING.md` and `CLAUDE.md`, both with the four-class text (the fifth and sixth classes never reached them). No class of the rule carries a change to `RELEASING.md` or `CLAUDE.md` to `main`; whether and how `main`'s copy follows is the captain's.

## Not verified here

`.github/workflows/advisories.yml` is not on `beta` at `4c5454be`; it lives on `origin/lane/fix-1034-deny-shape`. The paragraph names it as the owner's word does, ahead of its landing.

## The fold (2026-11-17)

- The bar's release clause, by the captain's ruling on the rule read's note: a patch of its own, carrying items of this class alone, never a release that carries the fix of a security advisory; several items of the class may share that patch (#1042's port and #1043's setter among them). `RELEASING.md` says it in one sentence; rule 10 and the CHANGELOG entry say the same in short.
- The clause on a security advisory's release is the maintainers' rule, recorded with the class on 2026-11-17.
- Row for the captain: `main`'s copies of `RELEASING.md` and `CLAUDE.md` take the seven classes when a port of this class next reaches `main`; nothing is changed on `main` by this lane.
