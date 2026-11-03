//! A docs-only pull request's exit (#668, speed round two): the `Test Suite` job restores no
//! cache, installs nothing and builds nothing when its plan reaches no target (`build`
//! false), and reports green from a last step; `lint` and `checks` install and build nothing
//! when the plan reads the change as docs only (`docs_only`), their gates skipped and read
//! as `SKIP` by the verdict step, `secrets` still scanning the commits. Each step after the
//! plan carries the condition or a condition that implies it: a step without one would
//! restore, install or build on a docs-only run. Read at the string level as
//! `arch_ci_runs_every_test.rs` reads ci.yml; no network, no environment.
#![allow(clippy::expect_used, clippy::panic)]

fn ci_yml() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/ci.yml"
    ))
    .expect("ci.yml")
    .replace("\r\n", "\n")
}

/// A step: its name, its id and its condition, from its `- ` line to the next step.
#[derive(Debug)]
struct Step {
    name: String,
    id: Option<String>,
    condition: Option<String>,
    text: String,
}

/// A job's text: from `  <job>:` to the next top-level job.
fn job<'a>(ci: &'a str, name: &str) -> &'a str {
    let start = ci
        .find(&format!("\n  {name}:\n"))
        .unwrap_or_else(|| panic!("a `{name}` job"));
    let rest = &ci[start + 1..];
    let end = rest
        .match_indices("\n  ")
        .find(|(at, _)| {
            let line = rest[at + 1..].lines().next().unwrap_or_default();
            !line.starts_with("   ") && line.trim_end().ends_with(':')
        })
        .map_or(rest.len(), |(at, _)| at + 1);
    &rest[..end]
}

fn field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim_start().trim_start_matches("- ");
        line.strip_prefix(key)
            .map(|value| value.trim().trim_matches('"').to_owned())
    })
}

fn steps(job: &str) -> Vec<Step> {
    let mut found: Vec<Step> = Vec::new();
    for line in job.lines() {
        if line.starts_with("      - ") {
            found.push(Step {
                name: String::new(),
                id: None,
                condition: None,
                text: String::new(),
            });
        }
        if let Some(step) = found.last_mut() {
            step.text.push_str(line);
            step.text.push('\n');
        }
    }
    for step in &mut found {
        let head: String = step
            .text
            .lines()
            .take_while(|l| !l.trim_start().starts_with("run:") && !l.contains("with:"))
            .collect::<Vec<_>>()
            .join("\n");
        step.name =
            field(&head, "name:").unwrap_or_else(|| field(&head, "uses:").unwrap_or_default());
        step.id = field(&head, "id:");
        step.condition = field(&head, "if:");
    }
    found
}

const BUILD: &str = "steps.plan.outputs.build == 'true'";
const NO_BUILD: &str = "steps.plan.outputs.build != 'true'";
const NOT_DOCS: &str = "steps.plan.outputs.docs_only != 'true'";
const READY: &str = "${{ !cancelled() && steps.ready.outcome == 'success' }}";
const SECRETS: &str = "${{ !cancelled() && (steps.ready.outcome == 'success' || steps.plan.outputs.docs_only == 'true') }}";
const VERDICT: &str = "${{ !cancelled() }}";

/// A test-step condition that is `build` or implies it, read whole (the #688 fold: a
/// condition read by substring passed `build == 'true' || always()`): `build`, the reached-set
/// check's, a plan flag, or the reached step's.
fn implies_build(condition: &str) -> bool {
    let flag = condition
        .strip_prefix("steps.plan.outputs.")
        .and_then(|rest| rest.strip_suffix(" == 'true'"))
        .is_some_and(|flag| ["build", "whole", "lib", "doc", "memory", "tracing"].contains(&flag));
    flag || [
        "github.event_name == 'pull_request' && steps.plan.outputs.build == 'true'",
        "steps.plan.outputs.whole != 'true' && steps.plan.outputs.reached != '0'",
    ]
    .contains(&condition)
}

/// The steps after the plan; every step before it a checkout and nothing else (the #688
/// fold: a cache restore, an install or a cargo run placed above the plan would run on a
/// docs-only change with no condition the plan could set).
fn after_plan(steps: Vec<Step>, job: &str, errors: &mut Vec<String>) -> Vec<Step> {
    match steps.iter().position(|s| s.id.as_deref() == Some("plan")) {
        Some(at) => {
            for step in &steps[..at] {
                let checkout = step.name.starts_with("actions/checkout@")
                    && !step.text.contains("run:")
                    && !step.text.contains("cargo");
                if !checkout {
                    errors.push(format!(
                        "{job}: `{}` runs before the plan: only a checkout may, a docs-only run would reach it",
                        step.name
                    ));
                }
            }
            steps.into_iter().skip(at + 1).collect()
        }
        None => {
            errors.push(format!("{job}: no plan step (`id: plan`)"));
            Vec::new()
        }
    }
}

/// The Test Suite's refusals: each step after the plan under `build` or a flag implying it,
/// the last step the green report under its negation, the push path writing `build=true`.
fn test_suite_refusals(ci: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let found = after_plan(steps(job(ci, "test")), "test", &mut errors);
    let Some((last, before)) = found.split_last() else {
        return errors;
    };
    for step in before {
        let condition = step.condition.as_deref().unwrap_or_default();
        if !implies_build(condition) {
            errors.push(format!(
                "test: `{}` runs under `{condition}`, not `{BUILD}` or a flag implying it: a docs-only run would reach it",
                step.name
            ));
        }
    }
    if last.condition.as_deref() != Some(NO_BUILD)
        || !last.text.contains("docs-only: nothing to build")
    {
        errors.push(format!(
            "test: the last step `{}` is not the docs-only report under `{NO_BUILD}`",
            last.name
        ));
    }
    if !ci
        .lines()
        .any(|l| l.contains("whole=true build=true") && l.contains("$GITHUB_OUTPUT"))
    {
        errors.push(
            "test: the plan's whole path does not write build=true: a push would build nothing"
                .to_owned(),
        );
    }
    errors
}

/// `lint`'s and `checks`' refusals: each step after the plan under `docs_only`'s negation or
/// waiting on `ready` (which carries it), `secrets` running on a docs-only change, the
/// verdict step reading a docs-only skip as `SKIP` for every gate but `secrets`.
fn gate_job_refusals(ci: &str, name: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let found = after_plan(steps(job(ci, name)), name, &mut errors);
    for step in &found {
        let condition = step.condition.as_deref().unwrap_or_default();
        let verdict = step.name == "Every gate passed";
        let secrets = step.id.as_deref() == Some("secrets");
        let ready = step.id.as_deref() == Some("ready");
        let ok = if verdict {
            condition == VERDICT
                && step
                    .text
                    .contains("DOCS_ONLY: ${{ steps.plan.outputs.docs_only }}")
                && step
                    .text
                    .contains("[ \"$DOCS_ONLY\" = true ] && [ \"$gate\" != secrets ]")
        } else if secrets {
            condition == SECRETS
        } else {
            condition == NOT_DOCS || (!ready && condition == READY)
        };
        if !ok {
            errors.push(format!(
                "{name}: `{}` runs under `{condition}`: a docs-only run would reach it, or its verdict misread",
                step.name
            ));
        }
    }
    if name == "checks" && !found.iter().any(|s| s.id.as_deref() == Some("secrets")) {
        errors.push("checks: no secrets step after the plan".to_owned());
    }
    errors
}

fn refusals(ci: &str) -> Vec<String> {
    let mut errors = test_suite_refusals(ci);
    errors.extend(gate_job_refusals(ci, "lint"));
    errors.extend(gate_job_refusals(ci, "checks"));
    errors
}

#[test]
fn every_step_after_the_plan_carries_the_docs_only_exit() {
    assert_eq!(refusals(&ci_yml()), Vec::<String>::new());
}

#[test]
fn the_plan_steps_read_the_runs_and_the_docs_only_flag() {
    let ci = ci_yml();
    for name in ["lint", "checks"] {
        let plan = steps(job(&ci, name))
            .into_iter()
            .find(|s| s.id.as_deref() == Some("plan"))
            .expect("a plan step");
        assert!(
            plan.text
                .contains("echo \"docs_only=false\" >> \"$GITHUB_OUTPUT\""),
            "{name}: a push is never docs only"
        );
        assert!(
            plan.text
                .contains("affected_tests.py plan --range HEAD^1..HEAD --runs \"$runs\""),
            "{name}"
        );
        assert!(
            plan.text
                .contains("grep -o -- '--test [a-z0-9_]*' .github/workflows/ci.yml"),
            "{name}"
        );
    }
}

#[test]
fn a_step_without_the_exit_is_refused_by_name() {
    let ci = ci_yml();
    let cases = [
        (
            "      - name: Install cargo-nextest\n        if: steps.plan.outputs.build == 'true'\n",
            "      - name: Install cargo-nextest\n",
            "test: `Install cargo-nextest` runs under ``",
        ),
        (
            "      - name: Cache the Clippy and ratchet builds\n        if: steps.plan.outputs.docs_only != 'true'\n",
            "      - name: Cache the Clippy and ratchet builds\n",
            "lint: `Cache the Clippy and ratchet builds` runs under ``",
        ),
        (
            "        id: ready\n        if: steps.plan.outputs.docs_only != 'true'\n        run: test -f",
            "        id: ready\n        run: test -f",
            "checks: `Resolve dependencies when no lock is committed` runs under ``",
        ),
        (
            "|| steps.plan.outputs.docs_only == 'true') }}",
            ") }}",
            "checks: `Scan the commits the event brings` runs under",
        ),
        (
            "whole=true build=true",
            "whole=true",
            "test: the plan's whole path does not write build=true",
        ),
        (
            "        if: steps.plan.outputs.build != 'true'\n",
            "",
            "test: the last step `Nothing to build` is not the docs-only report",
        ),
        // #688 fold: a condition is read whole, never by substring
        (
            "      - name: Install cargo-nextest\n        if: steps.plan.outputs.build == 'true'\n",
            "      - name: Install cargo-nextest\n        if: steps.plan.outputs.build == 'true' || always()\n",
            "test: `Install cargo-nextest` runs under `steps.plan.outputs.build == 'true' || always()`",
        ),
        (
            "      - name: Cache the Clippy and ratchet builds\n        if: steps.plan.outputs.docs_only != 'true'\n",
            "      - name: Cache the Clippy and ratchet builds\n        if: steps.plan.outputs.docs_only != 'true' || always()\n",
            "lint: `Cache the Clippy and ratchet builds` runs under",
        ),
    ];
    for (old, new, refusal) in cases {
        assert_eq!(ci.matches(old).count(), 1, "{old}");
        let errors = refusals(&ci.replacen(old, new, 1));
        assert!(
            errors.iter().any(|e| e.starts_with(refusal)),
            "{refusal}: {errors:?}"
        );
    }
}

/// A step placed before the plan runs on a docs-only change whatever it carries (#688
/// fold): the Test Suite's cache restore moved above its plan, and a cargo run before
/// `lint`'s, are refused by name.
#[test]
fn a_step_before_the_plan_is_refused_by_name() {
    let ci = ci_yml();
    let cache_start = ci
        .find("      - name: Cache the dependencies' build\n")
        .expect("the cache step");
    let cache_end = cache_start
        + ci[cache_start..]
            .find("\n\n")
            .expect("the cache step's end")
        + 2;
    let cache = &ci[cache_start..cache_end];
    let plan = "      - name: Plan the targets the change reaches\n";
    assert_eq!(ci.matches(plan).count(), 1);
    let moved = ci
        .replacen(cache, "", 1)
        .replacen(plan, &format!("{cache}{plan}"), 1);
    let errors = refusals(&moved);
    assert!(
        errors
            .iter()
            .any(|e| e.starts_with("test: `Cache the dependencies' build` runs before the plan")),
        "{errors:?}"
    );

    let lint_plan = "      - name: Plan whether the change is docs only\n";
    let at = ci.find("\n  lint:\n").expect("lint")
        + ci[ci.find("\n  lint:\n").expect("lint")..]
            .find(lint_plan)
            .expect("lint's plan");
    let mut early = ci.clone();
    early.insert_str(
        at,
        "      - name: Fetch early\n        run: cargo fetch\n\n",
    );
    let errors = refusals(&early);
    assert!(
        errors
            .iter()
            .any(|e| e.starts_with("lint: `Fetch early` runs before the plan")),
        "{errors:?}"
    );
}
