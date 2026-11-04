# The checkpoint of 2026-11-04: the pause

The owner's word, through the keeper at 18:5xZ, verbatim in four messages: "We need to come to a clean checkpoint pause on all of htis everyehrwe........." / "besdies bsv-low" / "and bsv-dd" / "wrap up whats in progress... so we can cleanly pause everywher and reusme later....". The keeper's protocol, RULED for every captain: a lane running at the word runs to its DONE and lands through its reads; a PR at MERGE lands; the sequencer lands what is in it; nothing new starts after the word (no lane, read, dispatch or cut); each captain writes a checkpoint record in its repository and one channel line, then stops its cadence; a scheduled night runs only if its captain leaves it armed and says so; nothing is deleted, moved or re-pinned at the pause. This is bsv-rs's record. The programme resumes on the owner's word, through the keeper.

## The lines

| Line | Tip | State |
|---|---|---|
| `beta` (the programme's line) | `7ad38399` (#797's merge at 19:26Z, the last landing before this record; this record's merge is the tip at the pause) | every push run green through #794's (`41893883640` on `27917891`); the tag `v0.9.0-beta.7` (the annotated object `7b0254d9` on `22f03d84`) on crates.io since 18:28:50Z; the CLI and the toolbox pin it through the keeper's chain |
| `main` (the stable line) | `8729f8a5` (`origin/main`) | takes beta commits by `git cherry-pick -x` in the keeper's order only; nothing cherry-picked at the pause; the Studio's main checkout sits at `efe12e63`, 32 behind, untouched |

The landings of the day on beta before the word: #780 (the complete run's record, 16:17Z), #788 (the version commit, 16:38Z), #790 (the cargo home step, 16:50Z), #783 (the hermetic discovery tests, 16:57Z), #793 (the Intel macOS leg, 17:52Z), #777 (`resolve_by_identity_key`'s list, 18:15Z), #784 (the timeout judge, 18:22Z), #778 (the SLAP backoff, 18:43Z, beta `e7f5d4f7`); after the word, the wrap: #794 (the heavy-run cap by window, 19:07Z, `27917891`) and #797 (#766's atomic writer, 19:26Z, `7ad38399`). The intakes bsv-wallet-cli#386 and bsv-wallet-toolbox-rs#533 carry a line per landing.

## The pull requests at the pause

| PR | Branch | What | State |
|---|---|---|---|
| #794 | `lane/fix-791` (`3cb2a7b5` on `e7f5d4f7`) | the nightly's heavy-run cap by window (#791, after-cut): fourteen of the twenty hosted slots inside the run's own window, six otherwise, the windows as data, the tail matrix | in the sequencer at the word; MERGED 19:07Z as `27917891`; #791 closed; its worktree removed by its landing script |
| #797 | `lane/fix-766` | the atomic writer copies no BUMP for a txid-only entry without a matching index, as the reference does (#766, blocks-cut); the raw entry's shape left as #798 | the lane DONE at 18:59Z (0.93); the rule read ACCEPT 0.9, the strength read ACCEPT 0.86 (one docs row asked and folded by hand), the cold read with the gate MERGE 0.92; MERGED 19:26Z as `7ad38399`; #766 closed; the intake lines posted |
| #795 | `lane/fix-735` (`8d8a08a0` on `e7f5d4f7`, rebased and pushed) | `OutputListItem.txid: Option<String>` carries the lookup output's txid hint; a disagreeing hint is read and counted (`IdentityClient::txid_hint_contradictions`), never refused (the owner's word on #735, 14:12Z); the migration `txid: None` | OPEN, held at the word: the rule read FIX (the binary answer's per-txid `to_binary_atomic` BEEF per output, `src/overlay/facilitators.rs:534-551`, with a two-transaction vector; its docs commit taken), the strength read FIX docs (the limit-order consequence; the migration's timing against the toolbox's exact pin); the fold brief and the cold re-read brief ready in captain-notes (`brief-fix-735-fold.md`, `review-fix-735.md`); the keeper's open question, "recorded as the host's fault" needs a host carrier or a tracing event; the fold and the re-read are the resume's |

No other pull request is open.

## The blocking set (milestone `0.9.0`; the beta.8 cut follows it)

Ten rows at the word: #734 (the lone-leaf coinbase reading), #735 (PR #795), #751 (`IdentityClient::query` checks nothing on the answer), #756 (`IdentityQuery`'s forms refused locally), #766 (PR #797), #775 (the facilitator's unbounded read; with #785 in one brief, `brief-fix-775.md`, ready), #782 (PushDrop's wallet-aware lock), #785 (the discovered host order), #786 (`parse_slap_token`'s 1-satoshi rule and txid hint), #796 (the resolver's merge drops a disagreeing hint before any consumer sees it; filed 18:55Z from #795's reads). Beside them the epics #75 and #101. After #797's landing nine rows remain open: #734, #735, #751, #756, #775, #782, #785, #786, #796.

The after-cut set: 35 rows on the `hardening` milestone at the word, plus #798 (the raw entry's BUMP shape, filed 19:04Z from #797's reads); #792 (the Intel leg) stays open for the arm64 entry's return. The triage rule of 17:2xZ classes every row at filing: `blocks-cut` on `0.9.0`, `after-cut` on `hardening`; out-of-subject findings to a per-module bucket row, one fold lane per module per day.

## The strength line

The complete run of 2026-11-04 (run 41753882105 at `2ff81a44`, the record #780, `docs/census/mutants-2026-11-04.md`): 4,902 mutants over 23 shards, 332 survivors (152 on the gate paths; the previous widened run 1,583 and 548); under the record's floors 80 PASS, 0 FAIL, 4 NO MUTANTS, 1 NO VIABLE MUTANTS of 85 files; 29 floors in `docs/ratchets.json` (`mutation_floors`), 27 of them raised by the record to the run's score rounded down, 2 already at their figure, no margin (the keeper's word of 15:2xZ). The timeout judge (#784) and the cap by window (#794) are in force for the next run. The nightly is dispatch-only (`workflow_dispatch`, no `schedule`): nothing is armed and nothing to disarm.

## What was running at the word, and how it ended

- The #766 lane (`fix-766`, the Studio) ran to DONE at 18:59Z and wrapped: pushed, PR #797, three reads, rebased onto `27917891` with keep-both on the changelog, the gate green on the rebased tip, landed through the sequencer 19:26Z as `7ad38399`, #766 closed.
- #794 sat in the sequencer (CLEAN at 18:57Z, the labelled whole-suite re-run pending); merged 19:07Z; its landing script posted the intake lines, closed #791 and removed its worktree and target.
- The queued launches of the #775/#785 lane and of the #735 fold lane and its cold re-read were stopped before they fired: nothing started after the word.
- The box: no lane of this captain (the fleet lock L61 since 16:0xZ; the box is bsv-low's and bsv-dd's at the pause). Another captain's `pin-0-9-0-beta-7` lane ran on the Studio (the keeper's pin chain, not this record's).

## The three steps on resume, in order

1. **Verify this checkpoint's landings** (#794 and #797 merged, #791 and #766 closed, the intake lines posted), then run #795's fold (`brief-fix-735-fold.md`, a `--cwd` lane on `/Volumes/Lanes/worktrees/bsv-rs/fix-735`) and its scoped cold re-read (`review-fix-735.md`), answer the keeper's host-attribution question in the fold's record, and land #795 through the sequencer (`sequencer16.sh`, `landed.sh 795 fix-735 735`).
2. **The rest of the blocking set, each through three Opus reads:** the #775+#785 lane (`brief-fix-775.md`), then #786, #796, #751, #756, #734, #782 (briefs to write from their rows); the per-module bucket rows of the day.
3. **The beta.8 cut** by the ritual as run for beta.7 (`version-cut.py`, `version-beta7.sh` adapted to beta.8, `tag-beta7.sh`, `beta7-release-poll.sh`; the owner's word on the cut through the keeper), then the CLI's and the toolbox's pins (the keeper's chain; the toolbox's four `OutputListItem` literal sites take `txid: None`), then the after-cut rows on `hardening`, #798 among them, and #792's arm64 return.

The hourly batch to the keeper (xx:10Z) restarts only when the keeper's wakes do.

## Stopped by name at the checkpoint

- The session cron `84f69937` (the hourly batch at :08) deleted at 19:13Z.
- The Monitor `bjg3wrcqh` (the sequencer log of #794) stopped at 19:10Z after "all merged".
- The chain `b1c1z1lj3` (sequencer16 794 then its landing script) ended at 19:09Z, exit 0.
- The launch `b0eyo8nd1` (the cold read of #797) ended with the read; the launches `bfxucim3m` and `b2pq260ol` (the rule and strength reads) ended at 19:0xZ.
- The wrap chain `bgagdq39k` (`fix-766-wrap.sh`: the gate on the rebased tip, the leased push, sequencer16 on #797, its landing script) ended at 19:28:19Z; the Monitor `bag3ufa6y` (the sequencer log of #797) stopped at 19:18Z and re-armed as `bcze0r1ih` with the poll lines filtered out, which ended at 19:28Z.
- The checkpoint's own landing: the chain `b6zk2fbfd` (`checkpoint-land.sh`) ended at 19:28Z at the changelog conflict of the rebase onto #797's merge, resolved by hand with keep-both; the continuation `checkpoint-land2.sh` (this record's push, its pull request, sequencer16 on it, the wait for its beta push run; its chain named in the channel line) and the Monitor on its sequencer log (`bgf7co8id`, stopped 19:18Z and re-armed as `bn68vw4kh`) end with that run; the sequencer process on this record's pull request ended at its merge; the beta push run of that merge is the last GitHub run of bsv-rs, finishes on its own; none follows (its end minute is in the channel line and the keeper's line).
- The launches `bbduzexx3` (the #775 lane), `bm8trl2k7` (the #735 fold) and `bs400bhye` (the #735 cold re-read) were stopped before firing.
- No other watcher, loop, timer, launcher or scheduled workflow of this captain exists.

## The worktrees (nothing deleted, moved or re-pinned)

| Worktree | Branch at sha | State |
|---|---|---|
| `/Volumes/Lanes/worktrees/bsv-rs/fix-735` | `lane/fix-735` at `8d8a08a0` | clean, pushed; PR #795 open |
| `/Volumes/Lanes/worktrees/bsv-rs/fix-766` | `lane/fix-766` at `e05d06a3` (the squashed commit on `27917891`) | PR #797 merged; the worktree and its target removed by the landing script |
| `/Volumes/Lanes/worktrees/bsv-rs/fix-789` | `lane/fix-789` at `898da710` | clean; #790 landed 16:50Z; kept at the pause, to remove on resume |
| `/Volumes/Lanes/worktrees/bsv-rs/fix-792` | `lane/fix-792` at `fd9e6ff6` | clean; #793 landed 17:52Z; kept at the pause (#792 open for the arm64 return) |
| `/Volumes/Lanes/worktrees/bsv-rs/fix-791` | removed by #794's landing script, with its target | |

The review worktrees of the day's reads stay as they are at the pause (report-only lanes; their branches carry nothing the captain has not taken): `review-fix-781`, `review-fix-791`, `review-fold-791`, `review-record-1104`, `review-rule-fix-735`, `review-rule-fix-779`, `review-rule-fix-781`, `review-rule-fix-791`, `review-rule-record-1104`, `review-strength-fix-735`, `review-strength-fix-791`, `review-strength-record-1104`; the three reads of #797 removed theirs at their end. The checkpoint worktree `/Volumes/Lanes/worktrees/bsv-rs/checkpoint-1104` (`lane/checkpoint-1104`) carries this record and is removed on resume with the others. The Studio's main checkout (`/Users/johncalhoun/bsv/bsv-rs`, `main` at `efe12e63`) is untouched.

## The records to resume from

- `/Volumes/Lanes/out/bsv-rs/captain-notes/`: the pending list (`pending-launches.txt`, rows A to G12), the day's notes (`docs-fold-notes.md`), the scripts (`sequencer16.sh`, `landed.sh`, `launch-gate.sh`, `rules-line.txt`, `version-cut.py`, `version-beta7.sh`, `tag-beta7.sh`, `beta7-release-poll.sh`, `rebase-after-cut.sh` and `.py`, `keep-both.py`, `dedupe-rows.py`, `tables-merge.py`, `sync-tail-steps.py`) and every brief of the day, mirrored at 19:08Z. The session scratchpad is per session and may be gone.
- The lane records under `docs/lanes/` (`fix-766.md`, `fix-791.md`, `record-complete-1104.md` among the day's), the census under `docs/census/`.
- The captains' channel `Calgooon/epoch` `IDENTITY-PROGRAM-2026-10.md`: the keeper's pause line of 18:5xZ and this captain's checkpoint line.
