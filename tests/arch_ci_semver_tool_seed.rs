//! The semver tool's cache seed (#696, speed loop three): a push to a line saves the pinned
//! cargo-semver-checks under exactly the key the `semver` job restores, so every pull request's
//! opening `semver` run restores it from the base line's scope (a pull request's own cache is read
//! by that pull request's re-runs alone). The two jobs' cache steps name the same action, path
//! and key; the seed only looks the key up (`lookup-only`, nothing downloaded on a hit), the
//! restore downloads; the toolchain and the install are the same lines, the install pinned to
//! the version the key names. A key that drifts on either side is a seed nobody restores, every
//! pull request back to the 241 to 294 s build. Read at the string level, as
//! `arch_ci_docs_only_exit.rs` reads ci.yml; no network, no environment.
#![allow(clippy::expect_used, clippy::panic)]

const VERSION: &str = "0.51.0";
const TOOLCHAIN: &str = "1.95.0";

fn ci_yml() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/ci.yml"
    ))
    .expect("ci.yml")
    .replace("\r\n", "\n")
}

/// A job's text: from `  <job>:` to the next two-space key.
fn job<'a>(ci: &'a str, id: &str) -> Option<&'a str> {
    let start = ci.find(&format!("\n  {id}:\n"))? + 1;
    let rest = &ci[start..];
    let mut at = rest.find('\n')? + 1;
    for line in rest[at..].split_inclusive('\n') {
        if line.starts_with("  ") && !line.starts_with("   ") && line.trim_end().ends_with(':') {
            return Some(&rest[..at]);
        }
        at += line.len();
    }
    Some(rest)
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

/// A key's value in a step, from the line carrying it.
fn field(step: &str, key: &str) -> Option<String> {
    step.lines().find_map(|line| {
        let line = line.trim_start().trim_start_matches("- ");
        line.strip_prefix(key).map(|v| v.trim().to_owned())
    })
}

/// The step of `job` whose text contains `needle`.
fn step_with(job: &str, needle: &str) -> Option<String> {
    steps(job).into_iter().find(|s| s.contains(needle))
}

/// What the two jobs must share: (what, the step's needle, the fields compared).
const SHARED: &[(&str, &str, &[&str])] = &[
    ("cache", "uses: actions/cache@", &["uses:", "path:", "key:"]),
    (
        "toolchain",
        "uses: dtolnay/rust-toolchain@",
        &["uses:", "toolchain:"],
    ),
    (
        "install",
        "cargo install cargo-semver-checks",
        &["RUSTFLAGS:", "run:"],
    ),
];

fn refusals(ci: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let (Some(restore), Some(seed)) = (job(ci, "semver"), job(ci, "semver-tool-seed")) else {
        return vec!["ci.yml has no `semver` job or no `semver-tool-seed` job".to_owned()];
    };
    for (what, needle, fields) in SHARED {
        let (Some(a), Some(b)) = (step_with(restore, needle), step_with(seed, needle)) else {
            errors.push(format!(
                "the {what} step is missing from `semver` or the seed"
            ));
            continue;
        };
        for key in *fields {
            let (x, y) = (field(&a, key), field(&b, key));
            if x.is_none() || x != y {
                errors.push(format!(
                    "the {what} step's `{key}` differs: `semver` {x:?}, the seed {y:?}"
                ));
            }
        }
    }
    let lookup = |text: &str| {
        step_with(text, "uses: actions/cache@").and_then(|s| field(&s, "lookup-only:"))
    };
    if lookup(seed).as_deref() != Some("true") {
        errors.push("the seed's cache step does not look the key up alone".to_owned());
    }
    if lookup(restore).is_some() {
        errors.push("`semver`'s cache step is a lookup; it must restore the tool".to_owned());
    }
    let key = step_with(restore, "uses: actions/cache@").and_then(|s| field(&s, "key:"));
    if !key.is_some_and(|k| k.contains(&format!("semver-checks-{VERSION}-rust-{TOOLCHAIN}-"))) {
        errors.push(format!(
            "the key does not name cargo-semver-checks {VERSION} on Rust {TOOLCHAIN}"
        ));
    }
    let install = step_with(restore, "cargo install cargo-semver-checks")
        .and_then(|s| field(&s, "run:"))
        .unwrap_or_default();
    if !install.contains(&format!("--version {VERSION} --locked")) {
        errors.push(format!(
            "the install is not pinned to {VERSION}: `{install}`"
        ));
    }
    errors
}

#[test]
fn the_seed_saves_the_semver_tool_under_the_key_semver_restores() {
    let errors = refusals(&ci_yml());
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Replaces `old` in the seed's job once, asserting it is there.
fn edited_seed(ci: &str, old: &str, new: &str) -> String {
    let seed = job(ci, "semver-tool-seed").expect("the seed");
    assert_eq!(seed.matches(old).count(), 1, "the edit's site: {old}");
    ci.replacen(seed, &seed.replacen(old, new, 1), 1)
}

#[test]
fn a_seed_whose_key_path_or_install_drifts_is_refused() {
    let ci = ci_yml();
    let key = "key: semver-checks-0.51.0-rust-1.95.0-${{ runner.os }}-${{ runner.arch }}";
    let cases = [
        (
            key,
            "key: semver-checks-0.51.1-rust-1.95.0-${{ runner.os }}-${{ runner.arch }}",
            "the cache step's `key:` differs",
        ),
        (
            "path: ${{ runner.temp }}/tools",
            "path: ~/.cargo/tools",
            "the cache step's `path:` differs",
        ),
        (
            "--version 0.51.0 --locked",
            "--version 0.52.0 --locked",
            "the install step's `run:` differs",
        ),
        (
            "toolchain: 1.95.0",
            "toolchain: stable",
            "the toolchain step's `toolchain:` differs",
        ),
        (
            "          lookup-only: true\n",
            "",
            "the seed's cache step does not look the key up alone",
        ),
    ];
    for (old, new, refusal) in cases {
        let errors = refusals(&edited_seed(&ci, old, new));
        assert!(
            errors.iter().any(|e| e.starts_with(refusal)),
            "{old} -> {new}: {errors:?}"
        );
    }
    let without = ci.replacen("\n  semver-tool-seed:\n", "\n  semver-tool-seed-gone:\n", 1);
    assert_eq!(
        refusals(&without),
        ["ci.yml has no `semver` job or no `semver-tool-seed` job"]
    );
}
