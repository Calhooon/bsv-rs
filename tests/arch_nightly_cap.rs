//! Every heavy run on the runners holds at most six of the account's twenty.
//!
//! The fleet's runner cap (the keeper's line of 10:0xZ 2026-11-03, on the opening API read of
//! the pool, after 14 from 06:2xZ; `docs/lanes/ci-speed-7.md`, "The fleet's runner cap"): the
//! account's twenty hosted runners are one pool across bsv-rs, the CLI, the toolbox and the
//! stack, at twenty in 22 of 24 hours with a non-heavy p95 of 14 slots, and a complete
//! nightly that put its twenty shards on them in one wave (run 41579707627) held PR #679's
//! twelve-minute job 52 minutes in the queue. The cap rises when a read shows that p95
//! under 10. Every matrix that is a heavy run (a job that runs mutants or
//! fuzzes) carries `max-parallel` at most [`HEAVY_MAX_PARALLEL`]. GitHub reads no `env`
//! in `strategy`, so a matrix writes the literal or reads the mutation plan's output,
//! whose number is `HEAVY_MAX_PARALLEL` in `.github/scripts/nightly_mutants.py` (its
//! owner loop four's #675). This guard reads every `.github/workflows/*.yml` and that
//! script (nothing else; no network, no environment) at the string level and refuses,
//! naming it: a heavy matrix without `max-parallel`, a literal above the cap, a reading
//! of anything but the plan's output, a plan whose constants pass the cap or whose
//! complete run does not take `HEAVY_MAX_PARALLEL`, and the two heavy jobs gone from the
//! nightly (so the guard cannot pass by finding nothing). `ci.yml`'s two matrices (the Test
//! Suite cells, the dependents) are not heavy on a pull request, but the nightly dispatches the
//! whole file on each line: they carry `max-parallel` at most 6 too, and the nightly dispatches
//! beta's run, waits for it, then main's (#682's second fold, the keeper's word (a)); the run
//! waited for is the one it dispatched, its conclusion read (#682's third fold), and a failed
//! watch other than the give-up fails the job (#682's fourth fold). A job that dispatches any
//! workflow is a heavy job of the nightly (#683: the weekly bench dispatched `bench.yml` beside
//! the opening wave of shards), ordered by `needs:` with every other, and one that another job runs
//! after waits for the run it dispatched under the same rule as `ci-full-beta`.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

use std::fs;
use std::path::PathBuf;

/// The cap: a heavy run holds at most six of the twenty runners.
const HEAVY_MAX_PARALLEL: u32 = 6;

/// The one reading of the plan the mutants matrix may make.
const PLAN_READING: &str = "${{ fromJSON(needs.source.outputs.max_parallel) }}";

/// The plan's line that gives the complete run the cap and a night its six.
const PLAN_LINE: &str = "result[\"max_parallel\"] = HEAVY_MAX_PARALLEL if result[\"mode\"] == \"complete\" else NIGHT_PARALLEL";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    // A Windows checkout converts the workflows to CRLF; the needles are written with `\n`.
    fs::read_to_string(root().join(path))
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .replace("\r\n", "\n")
}

/// Every workflow's file name and text, by name.
fn workflows() -> Vec<(String, String)> {
    let dir = root().join(".github/workflows");
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("workflow entry").file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".yml") || name.ends_with(".yaml"))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let text = read(&format!(".github/workflows/{name}"));
            (name, text)
        })
        .collect()
}

/// The jobs of a workflow: each key at two spaces under `jobs:`, with its lines.
fn jobs(text: &str) -> Vec<(String, Vec<&str>)> {
    let mut out: Vec<(String, Vec<&str>)> = Vec::new();
    let mut in_jobs = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.starts_with('#') && !line.trim().is_empty() {
            in_jobs = line.trim_end() == "jobs:";
            continue;
        }
        if !in_jobs {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let key = line.trim();
        if indent == 2 && key.ends_with(':') && !key.starts_with('#') {
            out.push((key.trim_end_matches(':').to_owned(), Vec::new()));
        } else if let Some((_, lines)) = out.last_mut() {
            lines.push(line);
        }
    }
    out
}

/// A job is a heavy run when a line of it (not a comment) runs mutants or fuzzes.
fn is_heavy(lines: &[&str]) -> bool {
    lines.iter().map(|line| line.trim()).any(|line| {
        !line.starts_with('#')
            && (line.contains("nightly_mutants.py run")
                || line.contains("cargo fuzz run")
                || (line.contains("cargo mutants") && !line.contains("--list")))
    })
}

/// The plan's `NAME = <integer>` constant.
fn constant(plan: &str, name: &str) -> Option<u32> {
    plan.lines()
        .find_map(|line| line.strip_prefix(&format!("{name} = ")))
        .and_then(|value| value.trim().parse().ok())
}

/// What is wrong with the plan's cap: its constants and the line that hands it out.
fn plan_errors(plan: &str) -> Vec<String> {
    let mut errors = Vec::new();
    for name in ["HEAVY_MAX_PARALLEL", "NIGHT_PARALLEL"] {
        match constant(plan, name) {
            Some(n) if (1..=HEAVY_MAX_PARALLEL).contains(&n) => {}
            Some(n) => errors.push(format!(
                "nightly_mutants.py: {name} = {n}, above the fleet's cap of {HEAVY_MAX_PARALLEL}"
            )),
            None => errors.push(format!("nightly_mutants.py: no `{name} = <integer>`")),
        }
    }
    if !plan.lines().any(|line| line.trim() == PLAN_LINE) {
        errors.push(format!(
            "nightly_mutants.py: the plan does not hand out the cap: no `{PLAN_LINE}`"
        ));
    }
    errors
}

/// What is wrong with the workflows' heavy matrices; `plan` is the mutation plan's script.
fn cap_errors(workflows: &[(String, String)], plan: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let mut heavy = Vec::new();
    let mut reads_plan = false;
    for (file, text) in workflows {
        for (job, lines) in jobs(text) {
            if !is_heavy(&lines)
                || !lines
                    .iter()
                    .any(|line| line.trim() == "matrix:" || line.trim().starts_with("matrix: "))
            {
                continue;
            }
            heavy.push(format!("{file} {job}"));
            let values: Vec<&str> = lines
                .iter()
                .map(|line| line.trim())
                .filter(|line| !line.starts_with('#'))
                .filter_map(|line| line.strip_prefix("max-parallel:"))
                .map(str::trim)
                .collect();
            match values.as_slice() {
                [] => errors.push(format!("{file} {job}: a heavy matrix without `max-parallel`")),
                [value] if *value == PLAN_READING => reads_plan = true,
                [value] => match value.parse::<u32>() {
                    Ok(n) if (1..=HEAVY_MAX_PARALLEL).contains(&n) => {},
                    Ok(n) => errors.push(format!(
                        "{file} {job}: max-parallel {n}, above the fleet's cap of {HEAVY_MAX_PARALLEL}"
                    )),
                    Err(_) => errors.push(format!(
                        "{file} {job}: max-parallel `{value}` is neither a literal nor `{PLAN_READING}`"
                    )),
                },
                _ => errors.push(format!("{file} {job}: more than one `max-parallel`")),
            }
        }
    }
    for job in ["nightly.yml mutants", "nightly.yml fuzz"] {
        if !heavy.iter().any(|found| found == job) {
            errors.push(format!(
                "{job}: not found as a heavy matrix (found {heavy:?})"
            ));
        }
    }
    if reads_plan {
        errors.extend(plan_errors(plan));
    }
    errors
}

/// The nightly's edges that keep its heavy work in sequence, `(job, the job it needs)`:
/// fuzz after the shards (6 + 6 would be twelve), the score job after them (6 + 1), beta's
/// dispatch of `ci.yml` after both, the weekly bench after beta's run (#683), and main's after
/// beta's and the bench's (#682's second fold, the keeper's word (a)). The two dispatched runs ask for up to 9 jobs at once (beta's: six test cells,
/// `lint`, `checks`, the plan) and up to 22 (main's, on main's `ci.yml`: six cells, nine gates
/// and the plan, 16, then the seven dependents after the plan), 31 together, so they run one
/// after the other: 9 (10 with the waiting job), then 22. A `max-parallel` caps one matrix, not
/// the sum of a run's singleton jobs: main's run, on main's uncapped file, stays above 14 for
/// about a minute and a half, and a run on beta's file holds up to 14 (six cells, six
/// dependents, `lint`, `checks`) under matrix caps of 6 (`docs/lanes/ci-speed-7.md`, "The
/// fleet's runner cap", the residual).
const HEAVY_EDGES: [(&str, &str); 9] = [
    ("fuzz", "mutants"),
    ("mutation-score", "mutants"),
    ("ci-full-beta", "mutants"),
    ("ci-full-beta", "fuzz"),
    ("bench", "mutants"),
    ("bench", "fuzz"),
    ("bench", "ci-full-beta"),
    ("ci-full-main", "ci-full-beta"),
    ("ci-full-main", "bench"),
];

/// The workflow a job dispatches (`gh workflow run <file>`), from a line that is not a comment.
fn dispatched_workflow(lines: &[&str]) -> Option<String> {
    lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once("gh workflow run ").map(|(_, rest)| rest))
        .find_map(|rest| rest.split_whitespace().next().map(str::to_owned))
}

/// A heavy job of the nightly: a heavy matrix, or a job that dispatches any workflow (a whole
/// run on the runners: `ci.yml`'s 9 or 22, `bench.yml`'s two and its scoreboard; #683).
fn is_heavy_job(lines: &[&str]) -> bool {
    is_heavy(lines) || dispatched_workflow(lines).is_some()
}

/// A job's `needs:` (a name or a flow list), at four spaces.
fn needs(lines: &[&str]) -> Vec<String> {
    let value = lines
        .iter()
        .filter(|line| line.len() - line.trim_start().len() == 4)
        .find_map(|line| line.trim().strip_prefix("needs:"))
        .map(str::trim)
        .unwrap_or("");
    value
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Whether `job` reaches `ancestor` through `needs:` edges.
fn reaches(graph: &[(String, Vec<String>)], job: &str, ancestor: &str) -> bool {
    let mut stack = vec![job.to_owned()];
    let mut seen = Vec::new();
    while let Some(next) = stack.pop() {
        if seen.contains(&next) {
            continue;
        }
        let parents = graph.iter().find(|(name, _)| *name == next).map(|(_, p)| p);
        for parent in parents.into_iter().flatten() {
            if parent == ancestor {
                return true;
            }
            stack.push(parent.clone());
        }
        seen.push(next);
    }
    false
}

/// What is wrong with the order of the nightly's heavy work: an edge of [`HEAVY_EDGES`]
/// missing, or two heavy jobs (a heavy matrix, a dispatch of any workflow) with no `needs:`
/// path between them, so the two can hold the runners at once.
fn edge_errors(nightly: &str) -> Vec<String> {
    let parsed = jobs(nightly);
    let graph: Vec<(String, Vec<String>)> = parsed
        .iter()
        .map(|(name, lines)| (name.clone(), needs(lines)))
        .collect();
    let mut errors = Vec::new();
    for (job, parent) in HEAVY_EDGES {
        match graph.iter().find(|(name, _)| name == job) {
            None => errors.push(format!("nightly.yml {job}: not found")),
            Some((_, have)) if !have.iter().any(|name| name == parent) => errors.push(format!(
                "nightly.yml {job} and {parent} can overlap: no `needs: {parent}` edge on {job} (its needs: {have:?})"
            )),
            Some(_) => {}
        }
    }
    let heavy: Vec<&String> = parsed
        .iter()
        .filter(|(_, lines)| is_heavy_job(lines))
        .map(|(name, _)| name)
        .collect();
    for (i, a) in heavy.iter().enumerate() {
        for b in &heavy[i + 1..] {
            if !reaches(&graph, a, b) && !reaches(&graph, b, a) {
                errors.push(format!(
                    "nightly.yml {a} and {b} can overlap: no `needs:` path between them"
                ));
            }
        }
    }
    errors
}

/// The nightly with `edit` applied to its text, the other workflows as they are.
fn with_nightly(edit: impl Fn(&str) -> String) -> Vec<(String, String)> {
    workflows()
        .into_iter()
        .map(|(name, text)| {
            let text = if name == "nightly.yml" {
                edit(&text)
            } else {
                text
            };
            (name, text)
        })
        .collect()
}

#[test]
fn every_heavy_matrix_carries_max_parallel_at_most_six() {
    let plan = read(".github/scripts/nightly_mutants.py");
    assert_eq!(cap_errors(&workflows(), &plan), Vec::<String>::new());
    assert_eq!(
        constant(&plan, "HEAVY_MAX_PARALLEL"),
        Some(HEAVY_MAX_PARALLEL)
    );
}

#[test]
fn the_cap_removed_or_raised_is_refused() {
    let plan = read(".github/scripts/nightly_mutants.py");
    let fuzz_six = "      max-parallel: 6\n";
    let mutants_line = format!("      max-parallel: {PLAN_READING}\n");
    let gone = with_nightly(|text| {
        assert!(text.contains(&mutants_line));
        text.replacen(&mutants_line, "", 1)
    });
    assert_eq!(
        cap_errors(&gone, &plan).len(),
        1,
        "{:?}",
        cap_errors(&gone, &plan)
    );
    let fuzz_raised = with_nightly(|text| {
        assert!(text.contains(fuzz_six));
        text.replacen(fuzz_six, "      max-parallel: 7\n", 1)
    });
    assert_eq!(cap_errors(&fuzz_raised, &plan).len(), 1);
    let literal_twenty =
        with_nightly(|text| text.replacen(&mutants_line, "      max-parallel: 20\n", 1));
    assert_eq!(cap_errors(&literal_twenty, &plan).len(), 1);
    let raised = plan.replacen("HEAVY_MAX_PARALLEL = 6\n", "HEAVY_MAX_PARALLEL = 14\n", 1);
    assert_ne!(raised, plan);
    assert_eq!(cap_errors(&workflows(), &raised).len(), 1);
    let slots = plan.replacen(PLAN_LINE, "result[\"max_parallel\"] = SLOT_LIMIT", 1);
    assert_ne!(slots, plan);
    assert_eq!(cap_errors(&workflows(), &slots).len(), 1);
}

#[test]
fn no_two_heavy_jobs_of_the_nightly_hold_the_runners_at_once() {
    let nightly = read(".github/workflows/nightly.yml");
    assert_eq!(edge_errors(&nightly), Vec::<String>::new());
    let fuzz_edge = "    needs: [source, mutants]\n    if: ${{ !cancelled() && needs.source.result";
    assert!(nightly.contains(fuzz_edge));
    let fuzz_free = nightly.replacen(fuzz_edge, &fuzz_edge.replacen(", mutants", "", 1), 1);
    assert_eq!(
        edge_errors(&fuzz_free),
        [
            "nightly.yml fuzz and mutants can overlap: no `needs: mutants` edge on fuzz (its needs: [\"source\"])",
            "nightly.yml mutants and fuzz can overlap: no `needs:` path between them",
        ]
    );
    let ci_edge = "    needs: [mutants, fuzz]\n";
    assert!(nightly.contains(ci_edge));
    let ci_free = nightly.replacen(ci_edge, "", 1);
    let errors = edge_errors(&ci_free);
    assert_eq!(errors.len(), 4, "{errors:?}");
    assert!(errors.contains(&"nightly.yml ci-full-beta and fuzz can overlap: no `needs: fuzz` edge on ci-full-beta (its needs: [])".to_owned()));
    let main_edge = "    needs: [ci-full-beta, bench]\n";
    assert!(nightly.contains(main_edge));
    let main_free = nightly.replacen(main_edge, "", 1);
    let errors = edge_errors(&main_free);
    assert!(
        errors.contains(&"nightly.yml ci-full-main and ci-full-beta can overlap: no `needs: ci-full-beta` edge on ci-full-main (its needs: [])".to_owned()),
        "{errors:?}"
    );
}

/// A job runs a matrix when it has a `strategy:` (a job's `outputs` may name a `matrix` too).
fn has_strategy(lines: &[&str]) -> bool {
    lines.iter().any(|line| line.starts_with("    strategy:"))
}

/// The `--ref` a dispatch of `ci.yml` names, from a job's lines.
fn dispatched_lines(lines: &[&str]) -> Vec<String> {
    lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once("gh workflow run ci.yml"))
        .filter_map(|(_, rest)| rest.split_once("--ref ").map(|(_, r)| r))
        .map(|r| {
            r.split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches('"')
                .to_owned()
        })
        .collect()
}

/// What is wrong with the nightly's dispatches of `ci.yml`: a dispatch job with a matrix (its
/// cells would start the runs at once), a job dispatching anything but one line, the two lines
/// not each dispatched by [`HEAVY_EDGES`]' job, or beta's job not waiting for its run.
fn dispatch_errors(nightly: &str) -> Vec<String> {
    let mut errors = Vec::new();
    for (job, lines) in jobs(nightly) {
        let refs = dispatched_lines(&lines);
        if refs.is_empty() {
            continue;
        }
        if has_strategy(&lines) {
            errors.push(format!(
                "nightly.yml {job}: a dispatch of ci.yml in a matrix, its cells at once"
            ));
        }
        let expected = match job.as_str() {
            "ci-full-beta" => "beta",
            "ci-full-main" => "main",
            _ => "",
        };
        if refs != [expected] {
            errors.push(format!(
                "nightly.yml {job}: dispatches ci.yml on {refs:?}, not on its one line"
            ));
        }
        if job == "ci-full-beta"
            && !lines
                .iter()
                .any(|line| !line.trim().starts_with('#') && line.contains("gh run watch"))
        {
            errors.push(format!("nightly.yml {job}: does not wait for beta's run (`gh run watch`), so main's starts beside it"));
        }
    }
    for job in ["ci-full-beta", "ci-full-main"] {
        if !jobs(nightly)
            .iter()
            .any(|(name, lines)| name == job && !dispatched_lines(lines).is_empty())
        {
            errors.push(format!(
                "nightly.yml {job}: not found as a dispatch of ci.yml"
            ));
        }
    }
    errors
}

/// The matrices of `ci.yml` the guard must find (the Test Suite cells and the dependents).
const CI_MATRICES: [&str; 2] = ["test", "dependent-check"];

/// What is wrong with `ci.yml`'s matrices under a dispatch: one without `max-parallel`, or
/// with a literal above the cap (or an expression whose dispatch value is above it).
fn ci_matrix_errors(ci: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let mut found = Vec::new();
    for (job, lines) in jobs(ci) {
        if !has_strategy(&lines) {
            continue;
        }
        found.push(job.clone());
        let value = lines
            .iter()
            .map(|line| line.trim())
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| line.strip_prefix("max-parallel:"))
            .map(str::trim);
        let dispatch = value.map(|v| {
            v.strip_prefix("${{ github.event_name == 'workflow_dispatch' && ")
                .and_then(|rest| rest.split_once(" ||").map(|(n, _)| n))
                .unwrap_or(v)
        });
        match dispatch.map(str::parse::<u32>) {
            None => errors.push(format!("ci.yml {job}: a matrix without `max-parallel`")),
            Some(Ok(n)) if (1..=HEAVY_MAX_PARALLEL).contains(&n) => {}
            Some(Ok(n)) => errors.push(format!(
                "ci.yml {job}: max-parallel {n} on a dispatch, above the fleet's cap of {HEAVY_MAX_PARALLEL}"
            )),
            Some(Err(_)) => errors.push(format!("ci.yml {job}: max-parallel `{}` unread", value.unwrap_or(""))),
        }
    }
    for job in CI_MATRICES {
        if !found.iter().any(|name| name == job) {
            errors.push(format!(
                "ci.yml {job}: not found as a matrix (found {found:?})"
            ));
        }
    }
    errors
}

#[test]
fn the_dispatched_ci_runs_go_beta_then_main_each_matrix_capped() {
    let nightly = read(".github/workflows/nightly.yml");
    let ci = read(".github/workflows/ci.yml");
    assert_eq!(dispatch_errors(&nightly), Vec::<String>::new());
    assert_eq!(ci_matrix_errors(&ci), Vec::<String>::new());
    let watch = " gh run watch \"$run\"";
    assert_eq!(nightly.matches(watch).count(), 2);
    let no_wait = nightly.replacen(watch, " true \"$run\"", 1);
    assert_eq!(
        dispatch_errors(&no_wait),
        ["nightly.yml ci-full-beta: does not wait for beta's run (`gh run watch`), so main's starts beside it"]
    );
    let one_job = nightly.replacen(
        "    name: CI full set (main)\n",
        "    name: CI full set (main)\n    strategy:\n      matrix:\n        line: [main]\n",
        1,
    );
    assert_ne!(one_job, nightly);
    assert_eq!(
        dispatch_errors(&one_job).len(),
        1,
        "{:?}",
        dispatch_errors(&one_job)
    );
    let both = nightly.replacen("--ref main", "--ref beta", 1);
    assert_ne!(both, nightly);
    assert_eq!(
        dispatch_errors(&both).len(),
        1,
        "{:?}",
        dispatch_errors(&both)
    );
    let cap = "      max-parallel: 6\n";
    assert_eq!(ci.matches(cap).count(), 2);
    let uncapped = ci.replacen(cap, "", 1);
    assert_eq!(
        ci_matrix_errors(&uncapped).len(),
        1,
        "{:?}",
        ci_matrix_errors(&uncapped)
    );
    let raised = ci.replacen(cap, "      max-parallel: 14\n", 1);
    assert_eq!(
        ci_matrix_errors(&raised).len(),
        1,
        "{:?}",
        ci_matrix_errors(&raised)
    );
    let expression = ci.replacen(
        cap,
        "      max-parallel: ${{ github.event_name == 'workflow_dispatch' && 6 || 4 }}\n",
        1,
    );
    assert_eq!(ci_matrix_errors(&expression), Vec::<String>::new());
    let expression_raised = expression.replacen("&& 6 ||", "&& 7 ||", 1);
    assert_eq!(ci_matrix_errors(&expression_raised).len(), 1);
}

/// The bot's identity: a dispatch by the nightly's token is `github-actions[bot]`'s.
const BOT_FILTER: &str = "--user 'github-actions[bot]'";

/// What is wrong with `ci-full-beta`'s wait (#682's third fold): the run watched must be
/// the one it dispatched, so the lookup lists the runs before the dispatch and takes only
/// a new one, and only the bot's (a hand dispatch of `ci.yml` on beta in the same minute,
/// taken by a newest-run lookup, was watched in its place, and cancelled by ours); and the
/// run's conclusion is read after the watch, a `failure` failing the job, so the night
/// shows beta's CI verdict (`gh run watch` alone ends 0 on a red run).
fn wait_errors(nightly: &str, job: &str) -> Vec<String> {
    let Some((_, lines)) = jobs(nightly).into_iter().find(|(name, _)| name == job) else {
        return vec![format!("nightly.yml {job}: not found")];
    };
    let what = job.strip_prefix("ci-full-").unwrap_or(job);
    let code: Vec<&str> = lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.starts_with('#'))
        .collect();
    let at = |needle: &str| code.iter().position(|line| line.contains(needle));
    let dispatch = at("gh workflow run ").unwrap_or(usize::MAX);
    let watch = at("gh run watch").unwrap_or(usize::MAX);
    let mut errors = Vec::new();
    let listed_before = at("before=").is_some_and(|i| i < dispatch)
        && code
            .iter()
            .skip(dispatch)
            .any(|line| line.contains("$before"));
    if !listed_before {
        errors.push(format!("nightly.yml {job}: no list of the runs before the dispatch, so a run that existed before it can be watched"));
    }
    if at(BOT_FILTER).is_none() {
        errors.push(format!("nightly.yml {job}: the lookup keeps no actor ({BOT_FILTER}), so a hand dispatch can be watched"));
    }
    let read = code
        .iter()
        .skip(watch)
        .any(|line| line.contains("--json conclusion"));
    let failing = code
        .windows(3)
        .any(|w| w[0].starts_with("failure") && w.iter().any(|line| line.contains("exit 1")));
    if !read || !failing {
        errors.push(format!("nightly.yml {job}: the run's conclusion is not read after the watch with a failure failing the job, so a red {what} run leaves the night green"));
    }
    errors
}

#[test]
fn the_beta_wait_watches_the_run_it_dispatched_and_fails_on_its_failure() {
    let nightly = read(".github/workflows/nightly.yml");
    assert_eq!(wait_errors(&nightly, "ci-full-beta"), Vec::<String>::new());

    let no_actor = nightly.replacen(&format!(" {BOT_FILTER}"), "", 1);
    assert_ne!(no_actor, nightly);
    assert_eq!(
        wait_errors(&no_actor, "ci-full-beta"),
        ["nightly.yml ci-full-beta: the lookup keeps no actor (--user 'github-actions[bot]'), so a hand dispatch can be watched"]
    );

    let before = "          before=\"$(list)\"\n";
    assert!(nightly.contains(before));
    let no_before = nightly.replacen(before, "", 1);
    assert_eq!(
        wait_errors(&no_before, "ci-full-beta"),
        ["nightly.yml ci-full-beta: no list of the runs before the dispatch, so a run that existed before it can be watched"]
    );

    let conclusion = "--json conclusion --jq .conclusion";
    assert!(nightly.contains(conclusion));
    let unread = nightly.replacen(conclusion, "--json status --jq .status", 1);
    let green = nightly.replacen(
        "            failure | timed_out",
        "            timed_out",
        1,
    );
    assert_ne!(green, nightly);
    for text in [unread, green] {
        assert_eq!(
            wait_errors(&text, "ci-full-beta"),
            ["nightly.yml ci-full-beta: the run's conclusion is not read after the watch with a failure failing the job, so a red beta run leaves the night green"]
        );
    }
}

/// What is wrong with how `ci-full-beta` reads its watch's exit (#682's fourth fold): the
/// step runs under `set -euo pipefail`, so a failing `list | jq` in the poll is an error,
/// not an empty count; after the watch, 124 (the give-up) is the one exit warned and let
/// through to the conclusion read, and any other non-zero exit (the API, the network) is
/// `exit 1`, with no `exit 0` before the read (the swallow: every failed watch was warned
/// and the night left green without beta's verdict).
fn watch_exit_errors(nightly: &str, job: &str) -> Vec<String> {
    let Some((_, lines)) = jobs(nightly).into_iter().find(|(name, _)| name == job) else {
        return vec![format!("nightly.yml {job}: not found")];
    };
    let code: Vec<&str> = lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.starts_with('#'))
        .collect();
    let at = |needle: &str| code.iter().position(|line| line.contains(needle));
    let mut errors = Vec::new();
    if at("set -euo pipefail").is_none() {
        errors.push(format!("nightly.yml {job}: the step is not under set -euo pipefail, so a failing poll reads as no new run"));
    }
    let watch = at("gh run watch").unwrap_or(code.len());
    let read = at("--json conclusion").unwrap_or(code.len());
    let arms = code.get(watch..read).unwrap_or_default();
    let give_up = arms.iter().any(|line| line.starts_with("124)"));
    let other = arms
        .windows(3)
        .any(|w| w[0].starts_with("*)") && w.iter().any(|line| line.contains("exit 1")));
    let swallow = arms.iter().any(|line| line.contains("exit 0"));
    if !give_up || !other || swallow {
        errors.push(format!("nightly.yml {job}: the watch's exit is not read as 124 the give-up and any other failure exit 1, so a failed watch leaves the night green"));
    }
    errors
}

#[test]
fn a_failed_watch_other_than_the_give_up_fails_the_beta_job() {
    let nightly = read(".github/workflows/nightly.yml");
    assert_eq!(
        watch_exit_errors(&nightly, "ci-full-beta"),
        Vec::<String>::new()
    );

    let arm = "            *)\n              echo \"::error::watching beta's run $run failed (exit $watched)\"\n              exit 1 ;;\n";
    assert!(nightly.contains(arm));
    let swallowed = nightly.replacen(
        arm,
        "            *)\n              echo \"::warning::stopped waiting for beta's run $run (exit $watched)\"\n              exit 0 ;;\n",
        1,
    );
    let unarmed = nightly.replacen(arm, "", 1);
    let no_give_up = nightly.replacen("            124) echo", "            125) echo", 1);
    assert_ne!(no_give_up, nightly);
    for text in [swallowed, unarmed, no_give_up] {
        assert_eq!(
            watch_exit_errors(&text, "ci-full-beta"),
            ["nightly.yml ci-full-beta: the watch's exit is not read as 124 the give-up and any other failure exit 1, so a failed watch leaves the night green"]
        );
    }

    let lax = nightly.replacen("          set -euo pipefail\n", "", 1);
    assert_ne!(lax, nightly);
    assert_eq!(
        watch_exit_errors(&lax, "ci-full-beta"),
        ["nightly.yml ci-full-beta: the step is not under set -euo pipefail, so a failing poll reads as no new run"]
    );
}

/// The dispatch jobs another job of the nightly runs after: each must wait for the run it
/// dispatched (#683), or the job after it starts beside that run.
fn waiting_dispatches(nightly: &str) -> Vec<String> {
    let parsed = jobs(nightly);
    let graph: Vec<(String, Vec<String>)> = parsed
        .iter()
        .map(|(name, lines)| (name.clone(), needs(lines)))
        .collect();
    parsed
        .iter()
        .filter(|(_, lines)| dispatched_workflow(lines).is_some())
        .map(|(name, _)| name)
        .filter(|name| graph.iter().any(|(other, _)| reaches(&graph, other, name)))
        .cloned()
        .collect()
}

#[test]
fn the_weekly_bench_runs_after_the_shards_fuzz_and_beta_and_waits_for_its_run_683() {
    let nightly = read(".github/workflows/nightly.yml");
    assert_eq!(edge_errors(&nightly), Vec::<String>::new());
    assert_eq!(waiting_dispatches(&nightly), ["ci-full-beta", "bench"]);
    for job in waiting_dispatches(&nightly) {
        assert_eq!(wait_errors(&nightly, &job), Vec::<String>::new(), "{job}");
        assert_eq!(
            watch_exit_errors(&nightly, &job),
            Vec::<String>::new(),
            "{job}"
        );
    }

    // The bench as it was before #683: no edge, so it dispatched beside the opening wave.
    let bench_edge = "    needs: [mutants, fuzz, ci-full-beta]\n";
    assert_eq!(nightly.matches(bench_edge).count(), 1);
    let bench_free = nightly.replacen(bench_edge, "", 1);
    let errors = edge_errors(&bench_free);
    for expected in [
        "nightly.yml bench and mutants can overlap: no `needs: mutants` edge on bench (its needs: [])",
        "nightly.yml bench and fuzz can overlap: no `needs: fuzz` edge on bench (its needs: [])",
        "nightly.yml bench and ci-full-beta can overlap: no `needs: ci-full-beta` edge on bench (its needs: [])",
        "nightly.yml ci-full-beta and bench can overlap: no `needs:` path between them",
        "nightly.yml bench and mutants can overlap: no `needs:` path between them",
        "nightly.yml bench and fuzz can overlap: no `needs:` path between them",
    ] {
        assert!(errors.contains(&expected.to_owned()), "{expected} not in {errors:?}");
    }
    assert_eq!(errors.len(), 6, "{errors:?}");

    // Main's dispatch no longer after the bench: the bench's run and main's 22 at once.
    let main_edge = "    needs: [ci-full-beta, bench]\n";
    let main_beside = nightly.replacen(main_edge, "    needs: [ci-full-beta]\n", 1);
    assert_eq!(
        edge_errors(&main_beside),
        [
            "nightly.yml ci-full-main and bench can overlap: no `needs: bench` edge on ci-full-main (its needs: [\"ci-full-beta\"])",
            "nightly.yml ci-full-main and bench can overlap: no `needs:` path between them",
        ]
    );

    // A new job that dispatches a workflow, named by no list, is refused by its name.
    let extra = nightly.replacen(
        "  source:\n",
        "  extra:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh workflow run msrv.yml --ref beta\n\n  source:\n",
        1,
    );
    assert_ne!(extra, nightly);
    let errors = edge_errors(&extra);
    assert!(
        errors.contains(
            &"nightly.yml bench and extra can overlap: no `needs:` path between them".to_owned()
        ),
        "{errors:?}"
    );
    assert!(errors.iter().all(|e| e.contains(" extra ")), "{errors:?}");

    // The bench's wait removed: main's dispatch would follow the dispatch, not the run.
    let watch = " gh run watch \"$run\"";
    let at = nightly.rfind(watch).expect("the bench's watch");
    let no_wait = format!(
        "{} true \"$run\"{}",
        &nightly[..at],
        &nightly[at + watch.len()..]
    );
    assert_eq!(
        watch_exit_errors(&no_wait, "bench"),
        ["nightly.yml bench: the watch's exit is not read as 124 the give-up and any other failure exit 1, so a failed watch leaves the night green"]
    );
    assert_eq!(
        wait_errors(&no_wait, "bench"),
        ["nightly.yml bench: the run's conclusion is not read after the watch with a failure failing the job, so a red bench run leaves the night green"]
    );

    // The bench's lookup without the actor: a hand dispatch of bench.yml could be watched.
    let job = nightly.find("\n  bench:\n").expect("the bench job");
    let no_actor = format!(
        "{}{}",
        &nightly[..job],
        nightly[job..].replacen(&format!(" {BOT_FILTER}"), "", 1)
    );
    assert_ne!(no_actor, nightly);
    assert_eq!(wait_errors(&no_actor, "ci-full-beta"), Vec::<String>::new());
    assert_eq!(
        wait_errors(&no_actor, "bench"),
        ["nightly.yml bench: the lookup keeps no actor (--user 'github-actions[bot]'), so a hand dispatch can be watched"]
    );
}
