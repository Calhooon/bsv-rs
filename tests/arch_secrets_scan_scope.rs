//! The `secrets` job scans the commits the event brings, never every ref of the checkout
//! (bsv-rs#272): on a pull request the PR's own commits (`<base sha>..HEAD`), on a push or a
//! dispatch the line's full history (`HEAD`), the findings' locations printed (`-v`) with the
//! values redacted. gitleaks's default is every ref, so a key-looking literal on any pushed
//! branch failed every pull request's scan until this pin.

fn ci_yml() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/ci.yml"
    ))
    .expect("ci.yml")
}

fn secrets_job(ci: &str) -> &str {
    let start = ci.find("\n  secrets:\n").expect("the secrets job");
    let rest = &ci[start + 1..];
    let end = rest[1..]
        .find("\n  ")
        .map(|i| {
            // the next top-level job: a line that starts a two-space key after this job's steps
            let mut off = i + 1;
            while let Some(j) = rest[off + 1..].find("\n  ") {
                if rest[off + 1 + j + 3..].starts_with(' ')
                    || rest[off + 1 + j + 3..].starts_with('#')
                {
                    off = off + 1 + j;
                } else {
                    return off + 1 + j;
                }
            }
            rest.len()
        })
        .unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn the_secrets_scan_covers_the_commits_the_event_brings() {
    let ci = ci_yml();
    let job = secrets_job(&ci);
    assert!(
        job.contains("--log-opts=\"${log_opts}\""),
        "the secrets job's scan takes its range from the event"
    );
    assert!(
        job.contains("log_opts=\"${PR_BASE_SHA}..HEAD\""),
        "a pull request's scan covers the PR's own commits"
    );
    assert!(
        job.contains("log_opts=\"HEAD\""),
        "a push's scan covers the line's history"
    );
    assert!(
        job.contains("PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}"),
        "the base sha comes from the pull request event"
    );
    assert!(job.contains(" -v "), "a finding's location is printed");
    assert!(job.contains("--redact"), "a finding's value stays redacted");
}
