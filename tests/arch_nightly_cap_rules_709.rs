//! The cap guard's rule read (#709): four ways a later edit could put two heavy runs on the
//! twenty runners at once with `tests/arch_nightly_cap.rs` green, each read from the YAML by a
//! rule, never by a list of today's jobs.
//!
//! 1. Every workflow is read for a dispatch of a workflow (a `gh workflow run <file>` or a
//!    `gh api .../dispatches` at a command position, never a comment or an `echo`'s text) or a
//!    reusable call (`uses: ./.github/workflows/<file>`). In the nightly such a job is a heavy
//!    job, with a `needs:` path to every other heavy job (a reusable call is a whole run as a
//!    dispatch is). Outside the nightly it is refused unless its workflow starts by a hand act
//!    alone (`workflow_dispatch`, a push of tags: `release.yml`'s calls on a version tag, the
//!    owner's release ritual, RELEASING.md) or [`STATED`] names it with its reason.
//! 2. Every heavy job of the nightly that runs after the shards (`needs: mutants`, directly or
//!    through another job) carries `!cancelled()` in its `if:` and no `always()`, so a failed
//!    or skipped shard still sequences it and a cancelled run skips it. `mutation-score` is not
//!    heavy (one runner, no dispatch) and keeps its `always()`.
//! 3. Every wait (a job with `gh run watch`) gives up at or under its job's `timeout-minutes`
//!    minus five: the budget's minutes (`budget="$((N * 60 - SECONDS))"`) and the poll for the
//!    new run (`seq 1 P` × `sleep I`) each, so the job ends by its own give-up, never by the
//!    timeout, and the job after it follows a finished wait.
//! 4. Every wait's `--workflow` names the workflow file its job dispatched, so the run watched
//!    is that workflow's.
//!
//! This guard reads every `.github/workflows/*.yml` (nothing else; no network, no environment)
//! at the string level, through `support/nightly_cap_rules.rs`; each refusal is shown below on
//! a mutated text of the tip's YAML. Rule 4 reads both directions since #713, and the two rules
//! #713 adds (a watch for every dispatch job with a job after it, the watch bounded by the budget
//! rule 3 reads) are `tests/arch_nightly_cap_watch_713.rs`'s.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

#[path = "support/nightly_cap_rules.rs"]
mod rules;

use rules::*;

#[test]
fn every_workflow_is_read_for_a_dispatch_or_a_call_of_a_workflow_709() {
    assert_eq!(dispatch_rule_errors(&workflows()), Vec::<String>::new());
    let all = workflows();
    assert!(hand_triggered(text_of(&all, "release.yml")));
    let release_jobs = block(text_of(&all, "release.yml"), "jobs");
    let calls: Vec<String> = release_jobs
        .iter()
        .flat_map(|(_, l)| dispatches(l))
        .collect();
    assert!(
        calls.contains(&"bench.yml".to_owned()) && calls.contains(&"ci.yml".to_owned()),
        "{calls:?}"
    );
    // An echo's text and a comment are no dispatch (bench.yml, sync-main-into-beta.yml).
    let bench_jobs = block(text_of(&all, "bench.yml"), "jobs");
    assert!(bench_jobs.iter().all(|(_, l)| dispatches(l).is_empty()));

    let step = "      - name: Rustfmt\n";
    let refused = |form: &str| {
        let text = with("ci.yml", |t| {
            in_job(t, "lint", step, &format!("      - run: {form}\n{step}"))
        });
        dispatch_rule_errors(&text)
    };
    let expected = "ci.yml lint: starts bench.yml outside nightly.yml on a trigger that is not a hand act, so its run can start beside the nightly's heavy work";
    assert_eq!(refused("gh workflow run bench.yml --ref beta"), [expected]);
    assert_eq!(
        refused("gh api -X POST repos/o/r/actions/workflows/bench.yml/dispatches -f ref=beta"),
        [expected]
    );
    let called = with("ci.yml", |t| {
        format!("{t}\n  bench-call:\n    uses: ./.github/workflows/bench.yml\n")
    });
    assert_eq!(
        dispatch_rule_errors(&called),
        ["ci.yml bench-call: starts bench.yml outside nightly.yml on a trigger that is not a hand act, so its run can start beside the nightly's heavy work"]
    );
}

#[test]
fn a_release_on_a_branch_push_and_a_stale_record_are_refused_709() {
    let on_branch = with("release.yml", |t| {
        t.replacen(
            "    tags: ['v*']\n",
            "    tags: ['v*']\n    branches: [main]\n",
            1,
        )
    });
    let errors = dispatch_rule_errors(&on_branch);
    assert_eq!(errors.len(), 6, "{errors:?}");
    assert!(errors.contains(&"release.yml bench: starts bench.yml outside nightly.yml on a trigger that is not a hand act, so its run can start beside the nightly's heavy work".to_owned()));

    let sync_gone = with("sync-main-into-beta.yml", |t| {
        t.replacen("run: gh workflow run ci.yml", "run: echo ci.yml", 1)
    });
    assert_eq!(
        dispatch_rule_errors(&sync_gone),
        ["sync-main-into-beta.yml sync: STATED names its start of ci.yml, which the workflows no longer carry"]
    );
    let sync_moved = with("sync-main-into-beta.yml", |t| {
        t.replacen("gh workflow run ci.yml", "gh workflow run bench.yml", 1)
    });
    assert_eq!(dispatch_rule_errors(&sync_moved).len(), 2);
}

#[test]
fn a_reusable_call_in_the_nightly_is_a_heavy_job_709() {
    let extra = with("nightly.yml", |t| {
        t.replacen(
            "  source:\n",
            "  extra:\n    uses: ./.github/workflows/bench.yml\n\n  source:\n",
            1,
        )
    });
    let errors = dispatch_rule_errors(&extra);
    assert!(
        errors.contains(
            &"nightly.yml extra and mutants can overlap: no `needs:` path between them".to_owned()
        ),
        "{errors:?}"
    );
    assert!(errors.iter().all(|e| e.contains(" extra ")), "{errors:?}");
    let api = with("nightly.yml", |t| {
        let line = "  source:\n";
        let job = "  extra:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          gh api -X POST \\\n            repos/o/r/actions/workflows/msrv.yml/dispatches\n\n";
        t.replacen(line, &format!("{job}{line}"), 1)
    });
    assert!(dispatch_rule_errors(&api).contains(
        &"nightly.yml bench and extra can overlap: no `needs:` path between them".to_owned()
    ));
}

#[test]
fn every_heavy_job_after_the_shards_keeps_not_cancelled_709() {
    let nightly = workflows()
        .into_iter()
        .find(|(n, _)| n == "nightly.yml")
        .expect("nightly")
        .1;
    assert_eq!(cancelled_errors(&nightly), Vec::<String>::new());
    let jobs = block(&nightly, "jobs");
    let graph = graph(&jobs);
    let judged: Vec<&String> = jobs
        .iter()
        .filter(|(n, l)| heavy(l) && after(&graph, n, "mutants"))
        .map(|(n, _)| n)
        .collect();
    assert_eq!(judged, ["ci-full-beta", "ci-full-main", "bench", "fuzz"]);

    let bench = in_job(
        &nightly,
        "bench",
        "!cancelled() && inputs.weekly",
        "inputs.weekly",
    );
    assert_eq!(
        cancelled_errors(&bench),
        ["nightly.yml bench: runs after the shards with `if: ${{ inputs.weekly }}`, not `!cancelled()`, so a failed shard does not sequence it or a cancelled run starts it"]
    );
    let main = in_job(
        &nightly,
        "ci-full-main",
        "    if: ${{ !cancelled() }}\n",
        "",
    );
    assert_eq!(
        cancelled_errors(&main),
        ["nightly.yml ci-full-main: runs after the shards with no `if:`, not `!cancelled()`, so a failed shard does not sequence it or a cancelled run starts it"]
    );
    let always = in_job(&nightly, "ci-full-beta", "!cancelled()", "always()");
    assert_eq!(
        cancelled_errors(&always),
        ["nightly.yml ci-full-beta: runs after the shards with `if: ${{ always() }}`, not `!cancelled()`, so a failed shard does not sequence it or a cancelled run starts it"]
    );
}

#[test]
fn every_wait_gives_up_inside_its_timeout_and_watches_its_own_workflow_709() {
    let all = workflows();
    assert_eq!(give_up_errors(&all), Vec::<String>::new());
    assert_eq!(wait_workflow_errors(&all), Vec::<String>::new());

    let nightly =
        |job: &str, from: &str, to: &str| with("nightly.yml", |t| in_job(t, job, from, to));
    assert_eq!(
        give_up_errors(&nightly("bench", "55 * 60", "58 * 60")),
        ["nightly.yml bench: the wait can run 58 minutes (the larger of the budget's 58 and the poll's 30 × 10 s, 5), past the job's timeout-minutes 60 minus five"]
    );
    assert_eq!(
        give_up_errors(&nightly("ci-full-beta", "timeout-minutes: 60", "timeout-minutes: 50")),
        ["nightly.yml ci-full-beta: the wait can run 55 minutes (the larger of the budget's 55 and the poll's 30 × 10 s, 5), past the job's timeout-minutes 50 minus five"]
    );
    assert_eq!(
        give_up_errors(&nightly("bench", "seq 1 30", "seq 1 400")),
        ["nightly.yml bench: the wait can run 67 minutes (the larger of the budget's 55 and the poll's 400 × 10 s, 67), past the job's timeout-minutes 60 minus five"]
    );
    assert_eq!(
        wait_workflow_errors(&nightly("bench", "--workflow bench.yml", "--workflow ci.yml")),
        ["nightly.yml bench: the wait lists `--workflow` [\"ci.yml\"] after starting [\"bench.yml\"], so a run it started goes unwatched or it watches another workflow's run"]
    );
    assert_eq!(
        wait_workflow_errors(&nightly("ci-full-beta", "--workflow ci.yml", "--workflow bench.yml")),
        ["nightly.yml ci-full-beta: the wait lists `--workflow` [\"bench.yml\"] after starting [\"ci.yml\"], so a run it started goes unwatched or it watches another workflow's run"]
    );
}
