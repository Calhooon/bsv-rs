# Lane fix-97c: #97's judge after its first live day (2026-11-13)

Started from `origin/beta` at `5f44121775b4f3eb95a55fb989d502e114e93fad` (`origin/main` at
`deed716567e33460c81e83182f5f0a061a5388dd`, the trampoline byte for byte beta's). Nothing pushed,
nothing written to GitHub; reads by `gh api` alone.

## What the live day showed

- Witness 11 (#947, head `68c86777`): the pull request's job dispatched stage R on its branch with
  the `GITHUB_TOKEN`, run 43476255821 (`workflow_dispatch`, actor and triggering actor
  `github-actions[bot]`, created 17:47:21Z, completed 17:48:36Z, `success`). The trampoline's runs
  between 17:40Z and 18:30Z (`gh api .../workflows/sibling-judge.yml/runs?created=...`) hold no
  `workflow_run` judgement of it; the pull request's own run 43476238287 (completed 17:48:16Z) was
  judged by run 43476411806 (17:48:19Z), which answered `no check: run 43476238287 attempt 1 is
  superseded by run 43476255821`. A re-judge by hand (run 43480851449) posted `GREEN`.
- The cause, documented and observed: GitHub's page "Triggering a workflow" (section "Triggering a
  workflow from a workflow") says events triggered by the `GITHUB_TOKEN` "will not create a new
  workflow run", `workflow_dispatch` and `repository_dispatch` excepted. The end of a run the token
  dispatched is such an event for `workflow_run`: observed on the run ids above (no judgement
  created for 43476255821; one for the pull request's run, whose actor is the owner's account).
  That the `workflow_run` of a token-started run is covered by the page's sentence is our reading
  of it, confirmed by the observation, not a sentence of the page.
- The sweep at 19:01Z named GitHub's failed `push` run 43478395899 of witness 12's unparsed
  `sibling-run.yml` with a re-judge act, and read `check absent` for a head whose judgement was
  still running.

## The mends

1. The sync's step (S2). It takes the stage R run's id from the dispatch's own answer
   (`POST .../actions/workflows/sibling-run.yml/dispatches` with `return_run_details: true`
   answers `200` with `workflow_run_id` and `run_url`; GitHub's changelog of 2026-02-19 and the
   REST page "Create a workflow dispatch event"; the step reads the id from `run_url`), waits for
   that run (160 reads, 15 s apart; the step's `timeout-minutes: 45`) and dispatches
   `sibling-judge.yml` on main with the id. The job keeps its permissions (`actions: write` already
   held, for ci.yml's dispatch) and holds no key; an answer that is no run id, a refused dispatch
   or a run not completed in 40 minutes fails the job, its error line carrying the re-judge.
   Chosen over a smaller change: the only event a token can raise is a dispatch, so the judge must
   be dispatched by whoever started the run, and only that dispatcher knows the run by an id no
   second run shares; a listing of the branch's runs ("the latest") can name a hand re-drive.
   Not run live on this host: the dispatch's answer with `return_run_details` is GitHub's
   documented behaviour, and the step fails closed if the answer carries no id.
2. One verdict per head (J). Every judgement resolves its run to the newest stage R run of the
   same head (`resolve`: the runs whose path, head repository and event are stage R's, by id, at
   the latest attempt), waits up to 300 s for one still running, and reads the identity on the
   run judged. `report` resolves again with no wait. The rule: the newest COMPLETED stage R run of
   a head is the head's verdict; a newer run still running after the wait: no check, the sweep
   names it.
3. The trampoline's comment (T2), the group kept per head.
4. The documents say what a J diff of `sibling-run.yml` runs (its own file).
5. The sweep's words.
6. `report` does not trust `post=no` where it owes a check; the manual's three rows.

## The table of interleavings

A and B are stage R runs of one head, A's id below B's. "Event judge" is a `workflow_run`
judgement; a token's run has none.

| Row | What happens | Which invocation posts | Whose verdict | Test (`test_sibling_judge.py`, `Interleavings` unless named) |
|---|---|---|---|---|
| 1 | A (the pull request's run) completes; B (a token's dispatch) still running | A's event judge, after waiting for B | B's | `test_row1_the_pull_requests_run_then_a_token_dispatch_still_running_is_waited_for_and_judged` |
| 1' | the same, B still running after 300 s | none; the sweep names the head (`run B in_progress`, its re-judge once it completes) | none | `test_row1_a_newer_run_still_running_after_the_wait_posts_nothing_and_names_it`; `Sweep.test_a_newest_run_still_running_is_named_with_its_rejudge_after` |
| 2 | B is the pull request's run, A a token dispatch started before it | B's event judge (A has none) | B's | `test_row2_a_token_dispatch_then_the_pull_requests_run_judges_the_pull_requests` |
| 2' | A's judgement (the sync's dispatch of the judge) after B completed | A's dispatched judge, and B's event judge | B's, twice (one verdict) | `test_row2_the_older_runs_judge_after_the_newer_completed_judges_the_newer` |
| 3 | a re-run: the event for attempt 1, attempt 2 completed or running | attempt 1's event judge (attempt 2's own when it ends) | attempt 2's; running: none, then attempt 2's own | `test_row3_a_reruns_newer_attempt_completed_is_judged_and_running_is_waited_for` |
| 4 | two pushes inside a minute: A's head is no longer the pull request's (A cancelled by stage R's group, or completed) | none for A; B's event judge | B's | `test_row4_two_pushes_inside_a_minute_the_older_heads_run_posts_nothing` |
| 5 | a hand re-judge of A beside B's event judge | both | B's, twice | `test_row5_a_hand_rejudge_of_an_older_run_judges_the_newest_as_the_events_judge_does` |
| 6 | a newer run that is no stage R run of this repository (a fork's, another path's, a `push` run) | A's event judge | A's | `test_row6_a_newer_run_that_is_no_stage_r_run_of_this_repository_is_not_judged_and_silences_nothing` |
| 7 | the run judged fails the identity (its event, its pull request) | none | none | `test_the_identity_is_read_on_the_run_judged` |
| 8 | the judge job wrote `post=no`, `report` reads a completed run whose identity holds | `report`, `NOT JUDGED` with the re-judge | none | `Report.test_post_no_where_report_owes_a_check_posts_not_judged_with_the_rejudge` |
| 9 | a newer run starts between the judge job and `report` | none (report sees it running) | none, then the newer's | `Report.test_a_newer_run_still_running_at_report_time_posts_nothing` |

Row 2', 5: two checks of one verdict on one head, harmless. A judgement dropped by the
trampoline's group (one pending per group; a newer pending replaces it) is recovered by the
judgement that does run, which resolves to the newest run of the head; so no row needs a group per
stage R run, and the group stays per head. Rows 2 and 4 and the `post=no` control with no check owed
are green on the base too (agreement rows); every other row is RED there (`red-j.log`).

## RED before green

- S2: `tests/arch_ci_lines.rs` of the tip over the base's tree, 5 of 17 RED (the new rule's test,
  the pin, the digest, the plants' anchors, the reads).
- J: `test_sibling_judge.py` of the tip over the base's `sibling_judge.py`, 15 failures and 3
  errors of 104 (2 of the errors are the scratch copy's own paths, outside the tree).

## Rows left

- The App's token minted only after the identity passed (the key read's row 3): it needs a step
  before the mint (the identity read with the job's own token, an output the mint's `if:` reads)
  and a `report` mode the step calls, an interface the two stages share, so two sittings (the
  script's reader first, then the trampoline), each with the queue held. Nothing leaks today: the
  token is minted, unused and revoked.
- The deprecated `app-id` input (the captain's act, written in the REPORT): the owner adds the
  environment variable `SIBLING_JUDGE_CLIENT_ID` (the App's client id, not 5700082), then one T
  commit changes the mint step's `app-id: ${{ vars.SIBLING_JUDGE_APP_ID }}` to
  `client-id: ${{ vars.SIBLING_JUDGE_CLIENT_ID }}`, keeping `APP_ID` for `report` (`standing()`
  compares the numeric app id).
- The class of this lane's own pull request: S2 and the RELEASING commit are class C, T2 and J
  class J, so one pull request carrying all of them reads `REFUSED: one pull request changes the
  judge and the crate` by the judge's own rule (no protection requires the check yet).
