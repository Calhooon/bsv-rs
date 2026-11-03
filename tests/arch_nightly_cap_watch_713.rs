//! The cap guard's watch rules (#713, the strength read of #709's guard), beside
//! `tests/arch_nightly_cap_rules_709.rs` and reading the same YAML through
//! `support/nightly_cap_rules.rs`:
//!
//! 5. Every job of the nightly that dispatches a workflow and has a job after it (by `needs:`,
//!    directly or through another) carries a `gh run watch` per dispatch, so the job after it
//!    never starts beside the run it started (a reusable call, a job-level `uses:`, is its own
//!    wait; a step's `uses:` is no call). Until #713 the bench's watch deleted kept both guards
//!    green: the old guard checks `ci-full-beta`'s watch alone, and rules 3 and 4 skip a job
//!    with no watch.
//! 6. Every watch runs under `timeout "$budget"`, the bound the step's exit 124 arm reads as the
//!    give-up, and `budget` is the one assignment `budget="$((N * 60 - SECONDS))"` that rule 3
//!    reads (the floor `budget=1` aside), so the give-up rule 3 judges is the watch's bound: a
//!    watch with no `timeout`, a literal one, and a budget doubled inside `$((...))` are refused.
//!
//! And rule 4's other direction: the set of workflows a waiting job starts equals the set its
//! list names (`--workflow X`, `--workflow=X`, `-w X`), and a variable (`WF=bench.yml`, a
//! step's `env:` key) is read through the job's one literal assignment or refused as
//! unreadable.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

#[path = "support/nightly_cap_rules.rs"]
mod rules;

use rules::*;

/// The bench's watch, its two lines, as the tip writes them.
const BENCH_WATCH: &str = "          timeout \"$budget\" gh run watch \"$run\" --repo \"$GITHUB_REPOSITORY\" \\\n            --interval 60 > /dev/null || watched=$?\n";

#[test]
fn every_dispatch_before_another_job_carries_a_watch_713() {
    let nightly = text_of(&workflows(), "nightly.yml").to_owned();
    assert_eq!(watch_errors(&nightly), Vec::<String>::new());
    let jobs = block(&nightly, "jobs");
    let graph = graph(&jobs);
    let judged: Vec<&String> = jobs
        .iter()
        .filter(|(n, l)| !dispatches(l).is_empty() && jobs.iter().any(|(m, _)| after(&graph, m, n)))
        .map(|(n, _)| n)
        .collect();
    assert_eq!(judged, ["ci-full-beta", "bench"]);

    // The bench's wait deleted: rules 3, 4 and 6 read no wait, so only this one refuses it.
    let unwatched = in_job(&nightly, "bench", BENCH_WATCH, "");
    assert_eq!(
        watch_errors(&unwatched),
        ["nightly.yml bench: starts [\"bench.yml\"] with 0 `gh run watch` for its 1 dispatches, so ci-full-main after it can start beside a run it did not wait for"]
    );
    let unwatched = with("nightly.yml", |t| in_job(t, "bench", BENCH_WATCH, ""));
    assert_eq!(give_up_errors(&unwatched), Vec::<String>::new());
    assert_eq!(wait_workflow_errors(&unwatched), Vec::<String>::new());
    let beta = in_job(
        &nightly,
        "ci-full-beta",
        "timeout \"$budget\" gh run watch",
        "echo",
    );
    assert_eq!(
        watch_errors(&beta),
        ["nightly.yml ci-full-beta: starts [\"ci.yml\"] with 0 `gh run watch` for its 1 dispatches, so ci-full-main, bench after it can start beside a run it did not wait for"]
    );
    // A reusable call is its own wait; the last dispatch job waits for nothing until a job
    // follows it.
    let called = nightly.replacen(
        "  source:\n",
        "  extra:\n    uses: ./.github/workflows/bench.yml\n\n  tail:\n    needs: [extra]\n    runs-on: ubuntu-latest\n\n  source:\n",
        1,
    );
    assert_eq!(watch_errors(&called), Vec::<String>::new());
    let followed = nightly.replacen(
        "  source:\n",
        "  tail:\n    needs: [ci-full-main]\n    runs-on: ubuntu-latest\n\n  source:\n",
        1,
    );
    assert_eq!(
        watch_errors(&followed),
        ["nightly.yml ci-full-main: starts [\"ci.yml\"] with 0 `gh run watch` for its 1 dispatches, so tail after it can start beside a run it did not wait for"]
    );
}

#[test]
fn every_watch_runs_under_the_budget_the_give_up_reads_713() {
    let all = workflows();
    assert_eq!(watch_bound_errors(&all), Vec::<String>::new());
    let nightly =
        |job: &str, from: &str, to: &str| with("nightly.yml", |t| in_job(t, job, from, to));

    let unbounded = nightly("bench", "timeout \"$budget\" gh run watch", "gh run watch");
    assert_eq!(
        watch_bound_errors(&unbounded),
        ["nightly.yml bench: the watch runs under ``, not `timeout \"$budget\"`, so the give-up rule 3 reads bounds nothing"]
    );
    assert_eq!(give_up_errors(&unbounded), Vec::<String>::new());
    let literal = nightly("bench", "timeout \"$budget\" gh", "timeout 7200 gh");
    assert_eq!(
        watch_bound_errors(&literal),
        ["nightly.yml bench: the watch runs under `timeout 7200`, not `timeout \"$budget\"`, so the give-up rule 3 reads bounds nothing"]
    );
    let braced = nightly(
        "bench",
        "timeout \"$budget\" gh",
        "timeout \"${budget}\" gh",
    );
    assert_eq!(watch_bound_errors(&braced), Vec::<String>::new());

    for doubled in [
        "55 * 60 * 2 - SECONDS",
        "55 * 120 - SECONDS",
        "55 * 60 + 3600 - SECONDS",
    ] {
        let text = nightly("ci-full-beta", "55 * 60 - SECONDS", doubled);
        assert_eq!(
            watch_bound_errors(&text),
            ["nightly.yml ci-full-beta: no one `budget=\"$((N * 60 - SECONDS))\"` (the floor `budget=1` aside), so the watch's bound is not the give-up rule 3 reads"],
            "{doubled}"
        );
        assert_eq!(
            give_up_errors(&text),
            ["nightly.yml ci-full-beta: a wait without a timeout-minutes, a budget, a poll count or an interval (read Some(60), None, Some(30), Some(10))"],
            "{doubled}"
        );
    }
    let second = nightly(
        "bench",
        "          watched=0\n",
        "          budget=\"$((300 * 60 - SECONDS))\"\n          watched=0\n",
    );
    assert_eq!(
        watch_bound_errors(&second).len(),
        1,
        "{:?}",
        watch_bound_errors(&second)
    );

    // The poll read whole: a unit-suffixed sleep is unreadable, a decoy before it no reading.
    assert_eq!(
        give_up_errors(&nightly("bench", "sleep 10\n", "sleep 2m\n")),
        ["nightly.yml bench: a wait without a timeout-minutes, a budget, a poll count or an interval (read Some(60), Some(55), Some(30), None)"]
    );
    let decoy = nightly(
        "bench",
        "          before=\"$(list)\"\n",
        "          sleep 1; seq 1 1\n          before=\"$(list)\"\n",
    );
    assert_eq!(give_up_errors(&decoy), Vec::<String>::new());
    let raised = with("nightly.yml", |t| {
        let t = in_job(t, "bench", "sleep 10\n", "sleep 200\n");
        let before = "          before=\"$(list)\"\n";
        in_job(&t, "bench", before, &format!("          sleep 1\n{before}"))
    });
    assert_eq!(
        give_up_errors(&raised),
        ["nightly.yml bench: the wait can run 100 minutes (the larger of the budget's 55 and the poll's 30 × 200 s, 100), past the job's timeout-minutes 60 minus five"]
    );
}

#[test]
fn every_started_workflow_is_listed_and_a_variable_is_read_through_its_assignment_713() {
    let nightly =
        |job: &str, from: &str, to: &str| with("nightly.yml", |t| in_job(t, job, from, to));
    let dispatch = "gh workflow run bench.yml --repo";
    let two = nightly(
        "bench",
        dispatch,
        "gh workflow run ci.yml --repo \"$GITHUB_REPOSITORY\" --ref \"$LINE\"\n          gh workflow run bench.yml --repo",
    );
    assert_eq!(
        wait_workflow_errors(&two),
        ["nightly.yml bench: the wait lists `--workflow` [\"bench.yml\"] after starting [\"bench.yml\", \"ci.yml\"], so a run it started goes unwatched or it watches another workflow's run"]
    );
    let short = nightly("bench", "--workflow bench.yml", "-w bench.yml");
    assert_eq!(wait_workflow_errors(&short), Vec::<String>::new());
    let short = nightly("bench", "--workflow bench.yml", "-w ci.yml");
    assert_eq!(
        wait_workflow_errors(&short),
        ["nightly.yml bench: the wait lists `--workflow` [\"ci.yml\"] after starting [\"bench.yml\"], so a run it started goes unwatched or it watches another workflow's run"]
    );
    let equals = nightly("bench", "--workflow bench.yml", "--workflow=bench.yml");
    assert_eq!(wait_workflow_errors(&equals), Vec::<String>::new());

    let by_variable = |assignments: &str| {
        with("nightly.yml", |t| {
            let t = in_job(t, "bench", "--workflow bench.yml", "--workflow \"$WF\"");
            let t = in_job(&t, "bench", dispatch, "gh workflow run \"$WF\" --repo");
            let set = "          set -euo pipefail\n";
            match assignments {
                "" => t,
                _ => in_job(&t, "bench", set, &format!("{set}{assignments}")),
            }
        })
    };
    let read = by_variable("          WF=bench.yml\n");
    assert_eq!(wait_workflow_errors(&read), Vec::<String>::new());
    assert_eq!(dispatch_rule_errors(&read), Vec::<String>::new());
    let reassigned = by_variable("          WF=bench.yml\n          WF=ci.yml\n");
    assert_eq!(
        wait_workflow_errors(&reassigned),
        ["nightly.yml bench: the wait's workflows [\"$WF\", \"$WF\"] are variables the job does not assign one literal, so the run watched cannot be read"]
    );
    let unassigned = by_variable("");
    assert_eq!(wait_workflow_errors(&unassigned).len(), 1);
}

#[test]
fn a_steps_uses_does_not_make_a_dispatch_job_a_reusable_call_713() {
    let nightly = text_of(&workflows(), "nightly.yml").to_owned();
    let step = "      - name: Dispatch bench.yml on the line";
    let checkout = in_job(
        &nightly,
        "bench",
        step,
        &format!("      - name: Check out\n        uses: actions/checkout@v4\n{step}"),
    );
    assert_eq!(watch_errors(&checkout), Vec::<String>::new());
    let unwatched = in_job(&checkout, "bench", BENCH_WATCH, "");
    assert_eq!(
        watch_errors(&unwatched),
        ["nightly.yml bench: starts [\"bench.yml\"] with 0 `gh run watch` for its 1 dispatches, so ci-full-main after it can start beside a run it did not wait for"]
    );
}
