//! The `secrets` job scans the commits the event brings, never every ref of the checkout
//! (bsv-rs#272): on a pull request the PR's own commits (`<base sha>..HEAD`), on a push or a
//! dispatch the line's full history (`HEAD`), the findings' locations printed (`-v`) with the
//! values redacted. gitleaks's default is every ref, so a key-looking literal on any pushed
//! branch failed every pull request's scan until this pin. Read at the string level as
//! `arch_ci_runs_every_test.rs` reads ci.yml; no network, no environment.
#![allow(clippy::expect_used, clippy::panic)]

fn ci_yml() -> String {
    // A Windows checkout converts the workflows to CRLF (`.gitattributes` keeps only the
    // vectors, fixtures and corpora byte for byte); the needles are written with `\n`.
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/ci.yml"
    ))
    .expect("ci.yml")
    .replace("\r\n", "\n")
}

/// The scan step's lines: from its `- name:` line to the next step or the next top-level job.
fn scan_step(ci: &str) -> String {
    let start = ci
        .find("- name: Scan the commits the event brings")
        .expect("the secrets job's scan step");
    let mut lines = Vec::new();
    for (i, line) in ci[start..].lines().enumerate() {
        let next_step = i > 0 && line.trim_start().starts_with("- name:");
        let next_job =
            line.starts_with("  ") && !line.starts_with("   ") && !line.trim().is_empty();
        if next_step || next_job {
            break;
        }
        lines.push(line);
    }
    lines.join("\n")
}

#[test]
fn the_secrets_scan_covers_the_commits_the_event_brings() {
    let ci = ci_yml();
    let step = scan_step(&ci);
    assert!(
        step.contains("--log-opts=\"${log_opts}\""),
        "the secrets job's scan takes its range from the event:\n{step}"
    );
    assert!(
        step.contains("log_opts=\"${PR_BASE_SHA}..HEAD\""),
        "a pull request's scan covers the PR's own commits:\n{step}"
    );
    assert!(
        step.contains("log_opts=\"HEAD\""),
        "a push's scan covers the line's history:\n{step}"
    );
    assert!(
        step.contains("-n \"${PR_BASE_SHA}\""),
        "an empty base sha falls back to the line's history, never a vacuous range:\n{step}"
    );
    assert!(
        step.contains("PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}"),
        "the base sha comes from the pull request event:\n{step}"
    );
    assert!(
        step.contains(" -v "),
        "a finding's location is printed:\n{step}"
    );
    assert!(
        step.contains("--redact"),
        "a finding's value stays redacted:\n{step}"
    );
}
