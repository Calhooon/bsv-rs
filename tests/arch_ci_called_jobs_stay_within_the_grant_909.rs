//! A called workflow's jobs ask no permission its caller does not grant (`RELEASING.md` step 22,
//! #909), and a job of `ci.yml` that hands a step the run's token holds read permissions alone.
//!
//! GitHub refuses, when a run starts, a called workflow one of whose jobs asks a permission
//! above what the calling job grants: the run dies with "a workflow file issue" before any job
//! runs. `release.yml` calls `ci.yml` and five more workflows on every `v*` tag, and a tag does
//! not move, so a permission added to a called job without the grant beside it is found by the
//! tag's run alone, after the tag is made. Until this file the rule was step 22's sentence.
//!
//! The rule, over every file of `.github/workflows/` (no network, no environment, no crate
//! module): for each job that names `uses: ./.github/workflows/<file>`, the grant is the job's
//! own `permissions:`, else its workflow's, and a caller that states neither is refused (the
//! default is a repository setting no file shows); every job of the called file must ask, by
//! its own `permissions:` or else the called file's, no scope the grant lacks and none above
//! the grant's level (`read` under `write`). A called job that itself calls a workflow is held
//! the same way, as every call in the tree is. A job that states nothing, in a file that states
//! nothing, asks nothing of its own and takes the caller's grant.
//!
//! The second rule holds what #909's line on the token rests on: a job of `ci.yml` whose text
//! names `github.token` runs the pull request's own code (the tool's build of the tree, the
//! tree's Python) with that token in a step's environment, and what bounds it is the job's
//! permissions. Every such job's permissions, its own or else the workflow's, are stated and
//! hold `read` alone.
//!
//! The reader takes two spellings of a permissions key, the block (`permissions:` and its
//! entries on the lines below, deeper) and `permissions: {}`, at column 0 (the workflow's) and
//! column 4 (a job's). Any other line whose key is `permissions` (quoted, a flow mapping,
//! `read-all`, `write-all`, a space before the colon, another column) is refused by name, so a
//! spelling this file does not read cannot pass it unread. Each refusal is shown on a planted
//! copy of the tree's own text.
//!
//! What it cannot see, stated: a workflow called from another repository or by a ref, a
//! permission GitHub adds or renames, the repository's default token setting, and whether
//! GitHub's own check is this one (the rule is step 22's as written, and the one run that
//! showed it is the toolbox's `v0.14.0-beta.2`).
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// File name under `.github/workflows/` to its text.
type Tree = BTreeMap<String, String>;
/// Scope to level: 0 `none`, 1 `read`, 2 `write`.
type Permissions = BTreeMap<String, u8>;

const CALL_PREFIX: &str = "./.github/workflows/";

struct Job {
    id: String,
    line: usize,
    uses: Option<String>,
    permissions: Option<Permissions>,
    names_the_token: bool,
}

struct Workflow {
    permissions: Option<Permissions>,
    jobs: Vec<Job>,
}

fn tree() -> Tree {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let mut out = Tree::new();
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("a directory entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("a file name")
            .to_string();
        if name.ends_with(".yml") || name.ends_with(".yaml") {
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
                .replace("\r\n", "\n");
            out.insert(name, text);
        }
    }
    out
}

/// A line without its trailing comment (a ` #` outside quotes is not told from one inside: no
/// key this file reads carries a `#` in its value) and without trailing white space.
fn bare(line: &str) -> &str {
    let cut = line.find(" #").map_or(line, |at| &line[..at]);
    cut.trim_end()
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

fn level(word: &str) -> Option<u8> {
    match word {
        "none" => Some(0),
        "read" => Some(1),
        "write" => Some(2),
        _ => None,
    }
}

/// The permissions a `permissions` key at `lines[at]` states, or the refusal.
fn permissions_at(file: &str, lines: &[&str], at: usize) -> Result<Permissions, String> {
    let head = bare(lines[at]);
    let column = indent(head);
    let refuse = |why: &str| {
        Err(format!(
            "{file} line {}: `{}`: {why}",
            at + 1,
            lines[at].trim()
        ))
    };
    match head.trim_start() {
        "permissions: {}" => return Ok(Permissions::new()),
        "permissions:" => {}
        _ => return refuse("a permissions key in a spelling this guard does not read (the block form or `{}` alone)"),
    }
    let mut out = Permissions::new();
    for line in &lines[at + 1..] {
        let text = bare(line);
        if text.trim().is_empty() || text.trim_start().starts_with('#') {
            continue;
        }
        if indent(text) <= column {
            break;
        }
        let Some((scope, word)) = text.trim().split_once(": ") else {
            return refuse("an entry that is not `<scope>: <level>`");
        };
        let Some(level) = level(word.trim()) else {
            return refuse("an entry whose level is not `read`, `write` or `none`");
        };
        if out.insert(scope.to_string(), level).is_some() {
            return refuse("a scope stated twice");
        }
    }
    Ok(out)
}

/// Whether a line's key is `permissions` in any spelling, at any column.
fn permissions_key(line: &str) -> bool {
    let text = bare(line).trim_start();
    let text = text.strip_prefix("- ").unwrap_or(text);
    ["permissions", "\"permissions\"", "'permissions'"]
        .iter()
        .any(|key| {
            text.strip_prefix(key)
                .is_some_and(|rest| rest.trim_start().starts_with(':'))
        })
}

fn parse(file: &str, text: &str) -> Result<Workflow, String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut workflow = Workflow {
        permissions: None,
        jobs: Vec::new(),
    };
    let mut in_jobs = false;
    for (at, line) in lines.iter().enumerate() {
        let text = bare(line);
        if text.trim().is_empty() || text.trim_start().starts_with('#') {
            continue;
        }
        let column = indent(text);
        if column == 0 {
            in_jobs = text == "jobs:";
        }
        if permissions_key(text) {
            let stated = permissions_at(file, &lines, at)?;
            let slot = match (column, in_jobs) {
                (0, _) => &mut workflow.permissions,
                (4, true) => match workflow.jobs.last_mut() {
                    Some(job) => &mut job.permissions,
                    None => return Err(format!("{file} line {}: a permissions key before any job", at + 1)),
                },
                _ => {
                    return Err(format!(
                        "{file} line {}: `{}`: a permissions key at a column this guard does not read (0, the workflow's; 4, a job's)",
                        at + 1,
                        line.trim()
                    ))
                }
            };
            if slot.is_some() {
                return Err(format!("{file} line {}: permissions stated twice", at + 1));
            }
            *slot = Some(stated);
            continue;
        }
        if !in_jobs {
            continue;
        }
        if column == 2 {
            let Some(id) = text.trim().strip_suffix(':') else {
                return Err(format!(
                    "{file} line {}: `{}`: a job line that is not `<id>:`",
                    at + 1,
                    line.trim()
                ));
            };
            workflow.jobs.push(Job {
                id: id.to_string(),
                line: at + 1,
                uses: None,
                permissions: None,
                names_the_token: false,
            });
            continue;
        }
        let Some(job) = workflow.jobs.last_mut() else {
            continue;
        };
        if text.contains("github.token") || text.contains("secrets.GITHUB_TOKEN") {
            job.names_the_token = true;
        }
        if column == 4 {
            if let Some(target) = text.trim().strip_prefix("uses:") {
                job.uses = Some(
                    target
                        .trim()
                        .trim_matches(|c| c == '"' || c == '\'')
                        .to_string(),
                );
            }
        }
    }
    Ok(workflow)
}

fn said(permissions: &Permissions) -> String {
    if permissions.is_empty() {
        return "{}".to_string();
    }
    permissions
        .iter()
        .map(|(scope, level)| format!("{scope}: {}", ["none", "read", "write"][*level as usize]))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The calls found and every refusal of the two rules.
fn judge(tree: &Tree) -> (Vec<String>, Vec<String>) {
    let (mut calls, mut refusals) = (Vec::new(), Vec::new());
    let mut parsed = BTreeMap::new();
    for (file, text) in tree {
        match parse(file, text) {
            Ok(workflow) => {
                parsed.insert(file.as_str(), workflow);
            }
            Err(refusal) => refusals.push(refusal),
        }
    }
    for (file, workflow) in &parsed {
        for job in &workflow.jobs {
            let Some(target) = job
                .uses
                .as_deref()
                .and_then(|u| u.strip_prefix(CALL_PREFIX))
            else {
                continue;
            };
            let call = format!("{file} `{}` (line {}) calls {target}", job.id, job.line);
            calls.push(format!("{file}:{}:{target}", job.id));
            let Some(grant) = job.permissions.as_ref().or(workflow.permissions.as_ref()) else {
                refusals.push(format!(
                    "{call} and states no grant, nor does its workflow: the grant is then a repository setting no file shows; state `permissions:` on the calling job (RELEASING.md step 22)"
                ));
                continue;
            };
            let Some(called) = parsed.get(target) else {
                if !tree.contains_key(target) {
                    refusals.push(format!("{call}, a file .github/workflows/ does not hold"));
                }
                continue;
            };
            for asked_by in &called.jobs {
                let Some(asked) = asked_by
                    .permissions
                    .as_ref()
                    .or(called.permissions.as_ref())
                else {
                    continue;
                };
                for (scope, level) in asked {
                    let granted = grant.get(scope).copied().unwrap_or(0);
                    if *level > granted {
                        refusals.push(format!(
                            "{call} granting `{}`, and {target}'s job `{}` (line {}) asks `{scope}: {}`: a called job asking more than its caller grants never starts, and the run of a tag dies at startup (RELEASING.md step 22); add the grant to the calling job in the same change, on every line that carries the job",
                            said(grant),
                            asked_by.id,
                            asked_by.line,
                            ["none", "read", "write"][*level as usize]
                        ));
                    }
                }
            }
        }
    }
    if let Some(ci) = parsed.get("ci.yml") {
        for job in ci.jobs.iter().filter(|job| job.names_the_token) {
            match job.permissions.as_ref().or(ci.permissions.as_ref()) {
                None => refusals.push(format!(
                    "ci.yml `{}` (line {}) hands a step the run's token and neither it nor the workflow states permissions",
                    job.id, job.line
                )),
                Some(held) => {
                    for (scope, level) in held.iter().filter(|(_, level)| **level > 1) {
                        refusals.push(format!(
                            "ci.yml `{}` (line {}) hands a step the run's token and holds `{scope}: {}`: the job runs the pull request's own code with that token in a step's environment, and read permissions are what bound it (#909)",
                            job.id,
                            job.line,
                            ["none", "read", "write"][*level as usize]
                        ));
                    }
                }
            }
        }
    }
    (calls, refusals)
}

/// The tree with one file's text changed: `old` must stand in it exactly once.
fn planted(tree: &Tree, file: &str, old: &str, new: &str) -> Tree {
    let mut out = tree.clone();
    let text = out.get_mut(file).unwrap_or_else(|| panic!("no {file}"));
    assert_eq!(
        text.matches(old).count(),
        1,
        "{file}: `{old}` is not there exactly once"
    );
    *text = text.replacen(old, new, 1);
    out
}

#[track_caller]
fn refused(tree: &Tree, wanted: &[&str]) {
    let (_, refusals) = judge(tree);
    assert!(
        refusals.len() == 1 && wanted.iter().all(|part| refusals[0].contains(part)),
        "wanted one refusal holding {wanted:?}, found {refusals:#?}"
    );
}

const CI_GRANT: &str = "    uses: ./.github/workflows/ci.yml
    secrets:
      DEPENDENTS_READ_TOKEN: ${{ secrets.DEPENDENTS_READ_TOKEN }}
    # ci.yml's Test Suite asks pull-requests: read for its label read (#667); a called job asking
    # more than its caller grants never starts
    permissions:
      contents: read
      pull-requests: read
";
const SEMVER_ASKS: &str = "    name: semver
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    # pull-requests: read for the label read below (#886); release.yml's call grants the same,
    # a nested job asking more than its caller grants never starts (RELEASING.md step 22)
    permissions:
      contents: read
      pull-requests: read
";

#[test]
fn every_called_job_asks_no_more_than_its_caller_grants_909() {
    let tree = tree();
    let (calls, refusals) = judge(&tree);
    assert!(refusals.is_empty(), "{refusals:#?}");
    // the reader is not blind: the tag's six calls are found, by caller and file
    for call in [
        "release.yml:ci:ci.yml",
        "release.yml:docs:docs.yml",
        "release.yml:msrv:msrv.yml",
        "release.yml:features:features.yml",
        "release.yml:machete:machete.yml",
        "release.yml:bench:bench.yml",
    ] {
        assert!(
            calls.iter().any(|c| c == call),
            "{call} was not found among {calls:?}"
        );
    }
}

#[test]
fn a_called_job_asking_more_than_the_grant_is_refused_909() {
    let tree = tree();
    // the scenario of the finding: the calling job grants `contents: read` alone, as the
    // stable line's did when the finding was written, and two jobs of ci.yml ask the label read's scope
    let lone = planted(
        &tree,
        "release.yml",
        CI_GRANT,
        &CI_GRANT.replace("      pull-requests: read\n", ""),
    );
    let (_, refusals) = judge(&lone);
    assert_eq!(refusals.len(), 2, "{refusals:#?}");
    for (refusal, job) in refusals.iter().zip(["semver", "test"]) {
        assert!(
            refusal.contains("release.yml `ci`")
                && refusal.contains("granting `contents: read`")
                && refusal.contains(&format!("ci.yml's job `{job}`"))
                && refusal.contains("asks `pull-requests: read`"),
            "{refusal}"
        );
    }
    // a called job asking a scope above the grant's level (the token rule speaks of it too:
    // `semver` hands a step the token), and one the grant does not name
    let (_, refusals) = judge(&planted(
        &tree,
        "ci.yml",
        SEMVER_ASKS,
        &SEMVER_ASKS.replace("contents: read", "contents: write"),
    ));
    assert_eq!(refusals.len(), 2, "{refusals:#?}");
    assert!(
        refusals[0].contains("ci.yml's job `semver`")
            && refusals[0].contains("asks `contents: write`"),
        "{refusals:#?}"
    );
    refused(
        &planted(
            &tree,
            "docs.yml",
            "\npermissions:\n  contents: read\n",
            "\npermissions:\n  contents: read\n  issues: write\n",
        ),
        &[
            "release.yml `docs`",
            "docs.yml's job",
            "asks `issues: write`",
        ],
    );
    // the called file's own permissions are what a job with none of its own asks
    let (_, refusals) = judge(&planted(
        &tree,
        "msrv.yml",
        "\npermissions:\n  contents: read\n",
        "\npermissions:\n  contents: write\n",
    ));
    assert!(
        !refusals.is_empty()
            && refusals
                .iter()
                .all(|r| r.contains("release.yml `msrv`") && r.contains("asks `contents: write`")),
        "{refusals:#?}"
    );
    // a grant of nothing grants nothing
    let (_, refusals) = judge(&planted(
        &tree,
        "release.yml",
        CI_GRANT,
        &CI_GRANT.replace(
            "    permissions:\n      contents: read\n      pull-requests: read\n",
            "    permissions: {}\n",
        ),
    ));
    assert!(
        refusals
            .iter()
            .any(|r| r.contains("granting `{}`") && r.contains("asks `contents: read`")),
        "{refusals:#?}"
    );
}

#[test]
fn a_caller_that_states_no_grant_and_an_unread_spelling_are_refused_909() {
    let tree = tree();
    // neither the job nor its workflow states a grant
    let mut bare_caller = planted(
        &tree,
        "release.yml",
        "permissions:\n  contents: read\n\nconcurrency:",
        "concurrency:",
    );
    bare_caller = planted(
        &bare_caller,
        "release.yml",
        CI_GRANT,
        &CI_GRANT.replace(
            "    permissions:\n      contents: read\n      pull-requests: read\n",
            "",
        ),
    );
    refused(&bare_caller, &["release.yml `ci`", "states no grant"]);
    // the job's grant absent, the workflow's is the grant: `contents: read` alone
    let inherited = planted(
        &tree,
        "release.yml",
        CI_GRANT,
        &CI_GRANT.replace(
            "    permissions:\n      contents: read\n      pull-requests: read\n",
            "",
        ),
    );
    let (_, refusals) = judge(&inherited);
    assert_eq!(refusals.len(), 2, "{refusals:#?}");
    // spellings the reader does not take are refused by name, never passed unread
    for spelling in [
        "    permissions: { contents: read, pull-requests: read }\n",
        "    permissions: write-all\n",
        "    \"permissions\":\n      contents: read\n      pull-requests: read\n",
        "    permissions :\n      contents: read\n      pull-requests: read\n",
        "     permissions:\n       contents: read\n       pull-requests: read\n",
    ] {
        let odd = planted(
            &tree,
            "release.yml",
            CI_GRANT,
            &CI_GRANT.replace(
                "    permissions:\n      contents: read\n      pull-requests: read\n",
                spelling,
            ),
        );
        let (_, refusals) = judge(&odd);
        assert!(
            refusals
                .iter()
                .any(|r| r.starts_with("release.yml line ")
                    && r.contains("this guard does not read")),
            "{spelling:?}: {refusals:#?}"
        );
    }
    refused(
        &planted(
            &tree,
            "release.yml",
            CI_GRANT,
            &CI_GRANT.replace("pull-requests: read", "pull-requests: all"),
        ),
        &["release.yml line ", "level is not"],
    );
    // a call of a file the folder does not hold
    refused(
        &planted(
            &tree,
            "release.yml",
            "uses: ./.github/workflows/msrv.yml",
            "uses: ./.github/workflows/msrv2.yml",
        ),
        &["release.yml `msrv`", "does not hold"],
    );
}

#[test]
fn a_job_of_ci_that_hands_a_step_the_token_holds_read_alone_909() {
    let tree = tree();
    // the three jobs the rule reads today, so the rule is seen to read them
    let ci = parse("ci.yml", &tree["ci.yml"]).expect("ci.yml parses");
    let holders: Vec<&str> = ci
        .jobs
        .iter()
        .filter(|j| j.names_the_token)
        .map(|j| j.id.as_str())
        .collect();
    assert_eq!(holders, ["dependent-check", "semver", "test"]);
    // a write beside the token, on the job and on the workflow (which `dependent-check` takes)
    let job = planted(
        &tree,
        "ci.yml",
        SEMVER_ASKS,
        &SEMVER_ASKS.replace("pull-requests: read", "pull-requests: write"),
    );
    let (_, refusals) = judge(&job);
    assert!(
        refusals.iter().any(|r| r.starts_with("ci.yml `semver`") && r.contains("holds `pull-requests: write`")),
        "{refusals:#?}"
    );
    let workflow = planted(
        &tree,
        "ci.yml",
        "\npermissions:\n  contents: read\n",
        "\npermissions:\n  contents: write\n",
    );
    let (_, refusals) = judge(&workflow);
    assert!(
        refusals
            .iter()
            .any(|r| r.starts_with("ci.yml `dependent-check`")
                && r.contains("holds `contents: write`")),
        "{refusals:#?}"
    );
    // a job that names the token nowhere is not this rule's
    assert!(ci.jobs.iter().any(|j| j.id == "lint" && !j.names_the_token));
}
