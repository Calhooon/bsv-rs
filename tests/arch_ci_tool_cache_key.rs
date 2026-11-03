//! A tool a job builds after its `Swatinem/rust-cache` step is cached only when the cache key
//! carries the tool's version (#699, speed loop three): the action saves on a miss alone, never
//! after an exact hit, so a key taken before the install arrived is restored by a full match on
//! every run and the tool is built again each time (cargo-mutants in `checks`, 64 to 71 s of the
//! mutants-entries step on three runs, the entry saved before the install landed). For every
//! `cargo install` after a rust-cache step the version it names must reach the key: a variable
//! at the job (or workflow) level whose name the action hashes (`CARGO*`, `RUST*`, ..., or one
//! the step lists in `env-vars:`), or the version in the step's `prefix-key:` or `shared-key:`
//! (its `key:` input is ignored beside `shared-key:` at v2.9.3, `src/config.ts:75-82`); the step
//! keeps `cache-bin` and the environment hash on. Read at the string level, as
//! `arch_ci_semver_tool_seed.rs` reads ci.yml; no network, no environment.

#![allow(clippy::expect_used, clippy::panic)]

/// The prefixes rust-cache v2.9.3 hashes into its key (`src/config.ts:111`).
const HASHED_PREFIXES: &[&str] = &["CARGO", "CC", "CFLAGS", "CXX", "CMAKE", "RUST"];

fn ci_yml() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/ci.yml"
    ))
    .expect("ci.yml")
    .replace("\r\n", "\n")
}

/// The jobs under `jobs:`, each `(id, text)` from `  <id>:` to the next two-space key.
fn jobs(ci: &str) -> Vec<(String, &str)> {
    let Some(start) = ci.find("\njobs:\n") else {
        return Vec::new();
    };
    let body = &ci[start + "\njobs:\n".len()..];
    let mut found: Vec<(String, usize)> = Vec::new();
    let mut at = 0;
    for line in body.split_inclusive('\n') {
        if line.starts_with("  ") && !line.starts_with("   ") && line.trim_end().ends_with(':') {
            let id = line.trim().trim_end_matches(':').to_owned();
            found.push((id, at));
        }
        at += line.len();
    }
    let mut out = Vec::new();
    for (i, (id, from)) in found.iter().enumerate() {
        let to = found.get(i + 1).map_or(body.len(), |next| next.1);
        out.push((id.clone(), &body[*from..to]));
    }
    out
}

/// The `env:` block's names and values at `indent` (the workflow's at 0, a job's at 4).
fn env_block(text: &str, indent: usize) -> Vec<(String, String)> {
    let head = format!("{}env:", " ".repeat(indent));
    let mut lines = text.lines().skip_while(|l| l.trim_end() != head);
    if lines.next().is_none() {
        return Vec::new();
    }
    let inner = indent + 2;
    let mut vars = Vec::new();
    for line in lines {
        let depth = line.len() - line.trim_start().len();
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if depth < inner {
            break;
        }
        if let Some((name, value)) = line.trim().split_once(':') {
            vars.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    vars
}

/// A job's own `env:` (before its `steps:`).
fn job_env(job: &str) -> Vec<(String, String)> {
    let head = job.split("\n    steps:\n").next().unwrap_or(job);
    env_block(head, 4)
}

/// The steps of a job, each from its `      - ` line to the next.
fn steps(job: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in job.lines() {
        if line.starts_with("      - ") {
            found.push(String::new());
        }
        if let Some(step) = found.last_mut() {
            step.push_str(line);
            step.push('\n');
        }
    }
    found
}

/// A key's value in a step, from the line carrying it, quotes removed.
fn field(step: &str, key: &str) -> Option<String> {
    step.lines().find_map(|line| {
        let line = line.trim_start().trim_start_matches("- ");
        line.strip_prefix(key)
            .map(|v| v.trim().trim_matches('"').trim_matches('\'').to_owned())
    })
}

/// Each `cargo install <tool> ... --version <v>` line of a step: (tool, version token).
fn installs(step: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in step.lines().filter(|l| !l.trim_start().starts_with('#')) {
        let Some(rest) = line.split("cargo install ").nth(1) else {
            continue;
        };
        let words: Vec<&str> = rest.split_whitespace().collect();
        let tool = words.first().copied().unwrap_or("").to_owned();
        let version = words
            .iter()
            .position(|w| *w == "--version")
            .and_then(|i| words.get(i + 1))
            .map(|v| v.trim_matches('"').trim_matches('\'').to_owned())
            .unwrap_or_default();
        out.push((tool, version));
    }
    out
}

/// A `$NAME` or `${NAME}` token's name.
fn variable(token: &str) -> Option<&str> {
    let name = token.strip_prefix('$')?;
    Some(name.trim_start_matches('{').trim_end_matches('}'))
}

/// The refusals, and the installs judged (job, tool) so a vacuous pass is visible.
fn refusals(ci: &str) -> (Vec<String>, Vec<(String, String)>) {
    let mut errors = Vec::new();
    let mut judged = Vec::new();
    let workflow_env = env_block(ci.split("\njobs:\n").next().unwrap_or(""), 0);
    for (id, job) in jobs(ci) {
        let all = steps(job);
        let Some(at) = all
            .iter()
            .position(|s| s.contains("uses: Swatinem/rust-cache@"))
        else {
            continue;
        };
        let cache = &all[at];
        let mut env = workflow_env.clone();
        env.extend(job_env(job));
        let listed = field(cache, "env-vars:").unwrap_or_default();
        let shared = field(cache, "shared-key:");
        let key_text = format!(
            "{} {}",
            field(cache, "prefix-key:").unwrap_or_default(),
            shared.clone().unwrap_or_default()
        );
        if shared.is_some() && field(cache, "key:").is_some() {
            errors.push(format!(
                "`{id}`'s cache step sets `key:` beside `shared-key:`, which the action ignores"
            ));
        }
        for step in &all[at + 1..] {
            for (tool, version) in installs(step) {
                judged.push((id.clone(), tool.clone()));
                let what = format!("`{id}`'s install of {tool}");
                if field(cache, "cache-bin:").as_deref() == Some("false") {
                    errors.push(format!("{what} follows a cache step with cache-bin off"));
                }
                if version.is_empty() {
                    errors.push(format!("{what} names no --version"));
                    continue;
                }
                let Some(name) = variable(&version) else {
                    if !key_text.contains(&version) {
                        errors.push(format!(
                            "{what} pins {version}, which the cache key does not carry"
                        ));
                    }
                    continue;
                };
                let set = env.iter().any(|(n, v)| n == name && !v.is_empty());
                if set && key_text.contains(&format!("env.{name}")) {
                    continue;
                }
                if env_block(step, 8).iter().any(|(n, _)| n == name) {
                    errors.push(format!(
                        "{what} sets {name} at step level, outside the cache key"
                    ));
                    continue;
                }
                let hashed = HASHED_PREFIXES.iter().any(|p| name.starts_with(p))
                    || listed.split_whitespace().any(|n| n == name);
                if !(set && hashed) {
                    errors.push(format!(
                        "{what} reads {name}, which the cache key does not carry"
                    ));
                } else if field(cache, "add-rust-environment-hash-key:").as_deref() == Some("false")
                {
                    errors.push(format!(
                        "{what} reads {name}, but the cache step hashes no environment"
                    ));
                }
            }
        }
    }
    (errors, judged)
}

#[test]
fn a_tool_built_after_the_cache_step_is_keyed_by_its_version_699() {
    let (errors, judged) = refusals(&ci_yml());
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    assert!(
        judged
            .iter()
            .any(|(job, tool)| job == "checks" && tool == "cargo-mutants"),
        "the guard judged no cargo-mutants install in `checks`: {judged:?}"
    );
}

/// Replaces `old` in `ci` once, asserting it is there.
fn edited(ci: &str, old: &str, new: &str) -> String {
    assert_eq!(ci.matches(old).count(), 1, "the edit's site: {old}");
    ci.replacen(old, new, 1)
}

#[test]
fn a_cache_key_that_misses_the_installed_version_is_refused_699() {
    let ci = ci_yml();
    let job_level = "      CARGO_MUTANTS_VERSION: '27.1.0'\n    steps:\n";
    let install =
        "        run: |\n          trap 'if [ $? -eq 0 ]; then echo \"PASS mutants-entries\"";
    let step_level = format!(
        "        env:\n          CARGO_MUTANTS_VERSION: '27.1.0'\n{}",
        install
    );
    let back_to_the_step = edited(
        &edited(&ci, job_level, "    steps:\n"),
        install,
        &step_level,
    );
    let cache = "          shared-key: checks\n";
    let cases = [
        (
            back_to_the_step,
            "`checks`'s install of cargo-mutants sets CARGO_MUTANTS_VERSION at step level",
        ),
        (
            edited(&ci, job_level, "    steps:\n"),
            "`checks`'s install of cargo-mutants reads CARGO_MUTANTS_VERSION, which the cache key",
        ),
        (
            edited(&ci, cache, &format!("{cache}          key: the-tool\n")),
            "`checks`'s cache step sets `key:` beside `shared-key:`",
        ),
        (
            edited(
                &ci,
                cache,
                &format!("{cache}          cache-bin: \"false\"\n"),
            ),
            "`checks`'s install of cargo-mutants follows a cache step with cache-bin off",
        ),
        (
            edited(
                &ci,
                cache,
                &format!("{cache}          add-rust-environment-hash-key: \"false\"\n"),
            ),
            "`checks`'s install of cargo-mutants reads CARGO_MUTANTS_VERSION, but the cache",
        ),
        (
            edited(
                &ci,
                "--version \"$CARGO_MUTANTS_VERSION\" --locked",
                "--version 27.1.0 --locked",
            ),
            "`checks`'s install of cargo-mutants pins 27.1.0, which the cache key",
        ),
    ];
    for (text, refusal) in cases {
        let (errors, _) = refusals(&text);
        assert!(
            errors.iter().any(|e| e.starts_with(refusal)),
            "{refusal}: {errors:?}"
        );
    }
    let keyed = edited(
        &edited(&ci, job_level, "    steps:\n"),
        cache,
        "          shared-key: checks-cargo-mutants-${{ env.CARGO_MUTANTS_VERSION }}\n",
    );
    assert!(
        refusals(&keyed)
            .0
            .iter()
            .any(|e| e.contains("CARGO_MUTANTS_VERSION")),
        "an env reference to a variable the job no longer sets is no key"
    );
}
