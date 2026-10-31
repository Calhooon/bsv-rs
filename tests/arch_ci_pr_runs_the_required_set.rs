//! A pull request and a push run exactly their line's required set; a dispatch and a tag's
//! call run every job of ci.yml and the whole test matrix.
//!
//! The keeper's rule for every public repository of the stack, the owner's
//! word behind it (2026-10-26 for a pull request, 2026-10-27 for a push): the
//! jobs a pull request runs are exactly the required contexts of its base
//! line's branch protection, and a push to `beta` or `main` runs the same set,
//! less the contexts that read a pull request ([`PULL_REQUEST_ONLY`]). A job
//! that runs but cannot refuse is load on GitHub and noise; a job that could
//! refuse but is not required is a hole. The jobs a required job `needs` are
//! part of it (`Plan pinned dependents` and each `dependent (<id>)` decide
//! `dependents`). A dispatch on each line (the nightly's, the sync's) and a
//! tag's call from release.yml (its event the tag's push) run every job, save
//! the few named in [`NOT_ON_THE_FULL_SET`], and every cell of the test
//! matrix. The jobs that judge something other than the commit live in
//! workflows of their own (bench.yml, msrv.yml, features.yml, machete.yml,
//! docs.yml for actionlint), which no push and no pull request starts.
//! Documentation belongs to ci.yml's required set on both lines (#515).
//!
//! This guard reads `.github/workflows/*.yml` (no network, no environment)
//! at the string level and evaluates each job's `if:` and its
//! matrix for an event. The parser is small and its limits are deliberate: a
//! job is a two-space key under `jobs:`; it reads the job's `name:`, `if:`
//! (inline or a `>-` block), `needs:` (one id or a flow list) and the keys of
//! `strategy.matrix` written as a flow list or as
//! `${{ fromJSON(<condition> && '<json list>' || '<json list>') }}`; a matrix
//! with `include:` or `exclude:` is refused as unreadable, and a matrix
//! written as one expression (`dependent-check`'s plan output) is unknown. An
//! expression is read in three values (true, false, unknown): `github.*`
//! takes the event's values, `inputs.*` is empty on a pull request,
//! `always()` is true, `startsWith` of two known strings is read as GitHub
//! reads it (ignoring case), every other context or function (`needs.*`,
//! `contains(github.event.pull_request.body, ..)`) is unknown. An unknown
//! required job is a refusal (it is not proven to run) and an unknown job
//! outside the set is one too (it is not proven to stay off).
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

/// `beta`'s required contexts as they will be after #515 lands, not a live snapshot.
/// Existing protection read 2026-10-30 by
/// `gh api repos/Calhooon/bsv-rs/branches/beta/protection/required_status_checks --jq '.contexts'`.
/// The captain adds `Documentation` and reads the protection back after landing.
const REQUIRED_ON_BETA: &[&str] = &[
    "Test Suite (ubuntu-latest, stable)",
    "Clippy",
    "Rustfmt",
    "Documentation",
    "vectors",
    "deny",
    "main-in-beta",
    "ratchet",
    "fixtures",
    "secrets",
    "semver",
    "wasm32 (combined)",
];

/// `main`'s required contexts as they will be after #515 reaches `main`, not a live snapshot.
/// Existing protection read 2026-10-30 by
/// `gh api repos/Calhooon/bsv-rs/branches/main/protection/required_status_checks --jq '.contexts'`.
/// The protection follows the landing: the captain PATCHes `Documentation` into `main`'s contexts
/// only after the job has reported green on `main`, never before, and reads it back.
const REQUIRED_ON_MAIN: &[&str] = &[
    "Test Suite (ubuntu-latest, stable)",
    "Clippy",
    "Rustfmt",
    "Documentation",
    "vectors",
    "deny",
    "dependents",
    "semver",
    "beta-born",
    "ratchet",
    "fixtures",
    "secrets",
    "wasm32 (combined)",
];

/// Required contexts a push cannot run, with the reason: (context, reason).
/// A push to a line runs every other required context of the line, nothing else.
const PULL_REQUEST_ONLY: &[(&str, &str)] = &[
    (
        "semver",
        "it reads the pull request's base; no push has one",
    ),
    ("beta-born", "it judges a pull request into main"),
];

/// Jobs a dispatch or a tag's call does not run, with the reason: (job id,
/// event label or `*` for every one, reason). Nothing else belongs here.
const NOT_ON_THE_FULL_SET: &[(&str, &str, &str)] = &[
    (
        "semver",
        "*",
        "it reads the pull request's base; no dispatch and no tag has one",
    ),
    ("beta-born", "*", "it judges a pull request into main"),
    (
        "main-in-beta",
        "main-dispatch",
        "main is in main by definition",
    ),
    (
        "main-in-beta",
        "beta-dispatch",
        "a push to beta and the sync's dispatch run it; the nightly's dispatch does not",
    ),
    (
        "main-in-beta",
        "tag",
        "a pull request into beta and a push to beta judged it; release.yml checks the tag's line",
    ),
];

/// The cells of each matrix job on the full set (the five other wasm32 slices are features.yml's).
const FULL_MATRIX: &[(&str, usize)] = &[("test", 6), ("wasm32", 1)];

fn read(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // A Windows checkout converts the workflows to CRLF; the parser reads `\n` lines.
    fs::read_to_string(root.join(path))
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .replace("\r\n", "\n")
}

/// The event a run is judged for.
struct Event {
    name: &'static str,
    base_ref: &'static str,
    git_ref: &'static str,
}

const fn pull_request(line: &'static str) -> Event {
    Event {
        name: "pull_request",
        base_ref: line,
        git_ref: "refs/pull/1/merge",
    }
}

fn push(line: &'static str) -> Event {
    Event {
        name: "push",
        base_ref: "",
        git_ref: if line == "beta" {
            "refs/heads/beta"
        } else {
            "refs/heads/main"
        },
    }
}

/// A job as the parser reads it.
#[derive(Default)]
struct Job {
    id: String,
    name: Option<String>,
    condition: Option<String>,
    needs: Vec<String>,
    /// `None`: no matrix; `Some(Err(why))`: a matrix this parser cannot read.
    matrix: Option<Result<Vec<(String, String)>, String>>,
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn jobs(ci: &str) -> Vec<Job> {
    let mut out: Vec<Job> = Vec::new();
    let mut lines = ci.lines().skip_while(|l| *l != "jobs:").skip(1).peekable();
    let mut in_matrix = false;
    while let Some(line) = lines.next() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let depth = indent(line);
        if depth == 0 {
            break;
        }
        let text = line.trim();
        if depth == 2 {
            let id = text
                .strip_suffix(':')
                .unwrap_or_else(|| panic!("a job header: {line}"));
            out.push(Job {
                id: id.to_string(),
                ..Job::default()
            });
            in_matrix = false;
            continue;
        }
        let job = out.last_mut().expect("a line under a job");
        if depth == 4 {
            in_matrix = false;
            if let Some(name) = text.strip_prefix("name: ") {
                job.name = Some(name.to_string());
            } else if let Some(value) = text.strip_prefix("if: ") {
                let mut condition = value.to_string();
                if value == ">-" || value == ">" || value == "|" {
                    condition.clear();
                    while let Some(next) = lines.peek() {
                        if !next.trim().is_empty() && indent(next) <= 4 {
                            break;
                        }
                        condition.push(' ');
                        condition.push_str(next.trim());
                        lines.next();
                    }
                }
                job.condition = Some(condition.trim().to_string());
            } else if let Some(value) = text.strip_prefix("needs: ") {
                job.needs = value
                    .trim_matches(|c| c == '[' || c == ']')
                    .split(',')
                    .map(|n| n.trim().to_string())
                    .filter(|n| !n.is_empty())
                    .collect();
            }
        } else if depth == 6 && text.starts_with("matrix:") {
            let inline = text.trim_start_matches("matrix:").trim();
            if inline.is_empty() {
                job.matrix = Some(Ok(Vec::new()));
                in_matrix = true;
            } else {
                job.matrix = Some(Err(format!("a matrix written as one expression: {inline}")));
            }
        } else if depth <= 6 {
            in_matrix = false;
        } else if depth == 8 && in_matrix {
            if let Some(Ok(keys)) = job.matrix.as_mut() {
                let (key, value) = text.split_once(':').expect("a matrix key");
                if key == "include" || key == "exclude" {
                    job.matrix = Some(Err(format!("a matrix with `{key}:` (write it as lists)")));
                } else {
                    keys.push((key.to_string(), value.trim().to_string()));
                }
            }
        }
    }
    out
}

/// A value of an expression in three states: known, or unknown.
#[derive(Clone, Debug, PartialEq)]
enum Value {
    Null,
    Bool(bool),
    Str(String),
    Unknown,
}

impl Value {
    fn truthy(&self) -> Option<bool> {
        match self {
            Value::Null => Some(false),
            Value::Bool(b) => Some(*b),
            Value::Str(s) => Some(!s.is_empty()),
            Value::Unknown => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Open,
    Close,
    And,
    Or,
    Not,
    Eq,
    Ne,
    Comma,
    Str(String),
    Word(String),
}

fn tokens(text: &str) -> Vec<Token> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i + 1).copied();
        match (c, next) {
            (' ', _) => i += 1,
            ('(', _) => (out.push(Token::Open), i += 1).1,
            (')', _) => (out.push(Token::Close), i += 1).1,
            (',', _) => (out.push(Token::Comma), i += 1).1,
            ('&', Some('&')) => (out.push(Token::And), i += 2).1,
            ('|', Some('|')) => (out.push(Token::Or), i += 2).1,
            ('=', Some('=')) => (out.push(Token::Eq), i += 2).1,
            ('!', Some('=')) => (out.push(Token::Ne), i += 2).1,
            ('!', _) => (out.push(Token::Not), i += 1).1,
            ('\'', _) => {
                let end = (i + 1..chars.len())
                    .find(|&j| chars.get(j) == Some(&'\''))
                    .unwrap_or_else(|| panic!("an unclosed string in {text}"));
                out.push(Token::Str(chars[i + 1..end].iter().collect()));
                i = end + 1;
            }
            _ => {
                let end = (i..chars.len())
                    .find(|&j| !matches!(chars.get(j), Some(c) if c.is_alphanumeric() || "._-".contains(*c)))
                    .unwrap_or(chars.len());
                assert!(
                    end > i,
                    "an expression character this parser does not read: {c:?} in {text}"
                );
                out.push(Token::Word(chars[i..end].iter().collect()));
                i = end;
            }
        }
    }
    out
}

/// A recursive-descent reader: `or := and ('||' and)*`, `and := unary ('&&' unary)*`,
/// `unary := '!' unary | cmp`, `cmp := atom (('=='|'!=') atom)?`.
struct Reader<'a> {
    tokens: Vec<Token>,
    at: usize,
    event: &'a Event,
}

impl Reader<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn take(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.at).cloned();
        self.at += 1;
        token
    }

    fn or(&mut self) -> Value {
        let mut left = self.and();
        while self.peek() == Some(&Token::Or) {
            self.take();
            let right = self.and();
            left = match left.truthy() {
                Some(true) => left,
                Some(false) => right,
                None if right.truthy() == Some(true) => right,
                None => Value::Unknown,
            };
        }
        left
    }

    fn and(&mut self) -> Value {
        let mut left = self.unary();
        while self.peek() == Some(&Token::And) {
            self.take();
            let right = self.unary();
            left = match left.truthy() {
                Some(false) => left,
                Some(true) => right,
                None if right.truthy() == Some(false) => Value::Bool(false),
                None => Value::Unknown,
            };
        }
        left
    }

    fn unary(&mut self) -> Value {
        if self.peek() == Some(&Token::Not) {
            self.take();
            return match self.unary().truthy() {
                Some(b) => Value::Bool(!b),
                None => Value::Unknown,
            };
        }
        let left = self.atom();
        let negate = match self.peek() {
            Some(Token::Eq) => false,
            Some(Token::Ne) => true,
            _ => return left,
        };
        self.take();
        let right = self.atom();
        let equal = match (&left, &right) {
            (Value::Unknown, _) | (_, Value::Unknown) => return Value::Unknown,
            // GitHub compares strings ignoring case
            (Value::Str(a), Value::Str(b)) => a.eq_ignore_ascii_case(b),
            (a, b) => a == b,
        };
        Value::Bool(equal != negate)
    }

    fn atom(&mut self) -> Value {
        match self.take() {
            Some(Token::Open) => {
                let value = self.or();
                assert_eq!(self.take(), Some(Token::Close), "an unclosed parenthesis");
                value
            }
            Some(Token::Str(s)) => Value::Str(s),
            Some(Token::Word(word)) if self.peek() == Some(&Token::Open) => {
                self.take();
                let mut arguments = Vec::new();
                while self.peek() != Some(&Token::Close) {
                    arguments.push(self.or());
                    if self.peek() == Some(&Token::Comma) {
                        self.take();
                    }
                }
                self.take();
                match (word.as_str(), arguments.as_slice()) {
                    ("always", _) => Value::Bool(true),
                    ("fromJSON", _) => arguments.into_iter().next().unwrap_or(Value::Unknown),
                    // GitHub compares strings ignoring case
                    ("startsWith", [Value::Str(text), Value::Str(prefix)]) => Value::Bool(
                        text.to_ascii_lowercase()
                            .starts_with(&prefix.to_ascii_lowercase()),
                    ),
                    _ => Value::Unknown,
                }
            }
            Some(Token::Word(word)) => match word.as_str() {
                "true" => Value::Bool(true),
                "false" => Value::Bool(false),
                "github.event_name" => Value::Str(self.event.name.to_string()),
                "github.ref" => Value::Str(self.event.git_ref.to_string()),
                "github.base_ref" => Value::Str(self.event.base_ref.to_string()),
                w if w.starts_with("inputs.") && self.event.name == "pull_request" => Value::Null,
                _ => Value::Unknown,
            },
            other => panic!("an expression this parser does not read at {other:?}"),
        }
    }
}

fn evaluate(expression: &str, event: &Event) -> Value {
    let inner = expression.trim();
    let inner = inner
        .strip_prefix("${{")
        .and_then(|e| e.strip_suffix("}}"))
        .unwrap_or(inner);
    let mut reader = Reader {
        tokens: tokens(inner),
        at: 0,
        event,
    };
    let value = reader.or();
    assert!(reader.peek().is_none(), "unread tokens in {expression}");
    value
}

/// A matrix key's values: a flow list `[a, b]`, or an expression whose value is a JSON
/// list of strings. `None`: unknown for this event.
fn values(raw: &str, event: &Event) -> Option<Vec<String>> {
    let list = if raw.starts_with("${{") {
        match evaluate(raw, event) {
            Value::Str(json) => json,
            _ => return None,
        }
    } else {
        raw.to_string()
    };
    let list = list.trim().strip_prefix('[')?.strip_suffix(']')?;
    Some(
        list.split(',')
            .map(|v| v.trim().trim_matches('"').to_string())
            .filter(|v| !v.is_empty())
            .collect(),
    )
}

/// The contexts a job reports when it runs, or why they are unknown.
fn contexts(job: &Job, event: &Event) -> Result<Vec<String>, String> {
    let name = job.name.clone().unwrap_or_else(|| job.id.clone());
    let keys = match &job.matrix {
        None => return Ok(vec![name]),
        Some(Err(why)) => return Err(why.clone()),
        Some(Ok(keys)) => keys,
    };
    let mut cells: Vec<Vec<(String, String)>> = vec![Vec::new()];
    for (key, raw) in keys {
        let values =
            values(raw, event).ok_or_else(|| format!("matrix key `{key}` unknown: {raw}"))?;
        cells = cells
            .into_iter()
            .flat_map(|cell| {
                values.iter().map(move |v| {
                    let mut cell = cell.clone();
                    cell.push((key.clone(), v.clone()));
                    cell
                })
            })
            .collect();
    }
    Ok(cells
        .into_iter()
        .map(|cell| {
            let mut named = name.clone();
            let mut substituted = false;
            for (key, value) in &cell {
                let site = format!("${{{{ matrix.{key} }}}}");
                substituted |= named.contains(&site);
                named = named.replace(&site, value);
            }
            if substituted || cell.is_empty() {
                named
            } else {
                let joined: Vec<&str> = cell.iter().map(|(_, v)| v.as_str()).collect();
                format!("{named} ({})", joined.join(", "))
            }
        })
        .collect())
}

/// Whether each job runs for the event: its needs ran (unless a status function
/// waives them) and its condition holds. `None`: unknown.
fn runs(all: &[Job], event: &Event) -> BTreeMap<String, Option<bool>> {
    let mut out: BTreeMap<String, Option<bool>> = BTreeMap::new();
    for job in all {
        let condition = job
            .condition
            .as_deref()
            .map(|c| evaluate(c, event).truthy());
        let waives = job
            .condition
            .as_deref()
            .is_some_and(|c| c.contains("always()"));
        let needs = if waives {
            Some(true)
        } else {
            let ran: Vec<Option<bool>> = job
                .needs
                .iter()
                .map(|n| out.get(n).copied().flatten())
                .collect();
            if ran.contains(&Some(false)) {
                Some(false)
            } else if ran.iter().all(|r| *r == Some(true)) {
                Some(true)
            } else {
                None
            }
        };
        let verdict = match (needs, condition.unwrap_or(Some(true))) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (Some(true), Some(true)) => Some(true),
            _ => None,
        };
        out.insert(job.id.clone(), verdict);
    }
    out
}

/// The refusals of the exact-set rule on a pull request into `line`.
fn pr_refusals(ci: &str, line: &'static str, required: &[&str]) -> Vec<String> {
    let label = format!("a pull request into {line}");
    exact_refusals(ci, &pull_request(line), line, &label, required, &[])
}

/// The refusals of the exact-set rule on a push to `line`: its required set less
/// [`PULL_REQUEST_ONLY`], which must not run.
fn push_refusals(ci: &str, line: &'static str, required: &[&str]) -> Vec<String> {
    let label = format!("a push to {line}");
    let absent: Vec<&str> = PULL_REQUEST_ONLY.iter().map(|(c, _)| *c).collect();
    exact_refusals(ci, &push(line), line, &label, required, &absent)
}

/// The refusals of the exact-set rule for `event`: every context of `required` but
/// those of `absent` proven to run, no job proven to run `absent`'s, and no other
/// context run (the jobs a deciding job needs aside).
fn exact_refusals(
    ci: &str,
    event: &Event,
    line: &str,
    label: &str,
    required: &[&str],
    absent: &[&str],
) -> Vec<String> {
    let all = jobs(ci);
    let ran = runs(&all, event);
    let absent: BTreeSet<&str> = absent.iter().copied().collect();
    let required: BTreeSet<&str> = required
        .iter()
        .copied()
        .filter(|c| !absent.contains(c))
        .collect();
    let mut errors = Vec::new();
    let mut deciders = BTreeSet::new();
    for context in &required {
        let producers: Vec<&Job> = all
            .iter()
            .filter(|j| contexts(j, event).is_ok_and(|c| c.iter().any(|c| c == context)))
            .collect();
        if !producers
            .iter()
            .any(|j| ran.get(&j.id) == Some(&Some(true)))
        {
            errors.push(format!(
                "`{context}` is required on {line} but no job is proven to run it on {label}"
            ));
        }
        for job in producers {
            deciders.insert(job.id.clone());
        }
    }
    // the jobs a deciding job needs decide with it (a decider's own other cells do not)
    let mut helpers = BTreeSet::new();
    let mut stack: Vec<String> = deciders.iter().cloned().collect();
    while let Some(id) = stack.pop() {
        if let Some(job) = all.iter().find(|j| j.id == id) {
            for need in &job.needs {
                if !deciders.contains(need) && helpers.insert(need.clone()) {
                    stack.push(need.clone());
                }
            }
        }
    }
    for job in &all {
        if ran.get(&job.id) == Some(&Some(false)) {
            continue;
        }
        let helper = helpers.contains(&job.id);
        match contexts(job, event) {
            Ok(names) => {
                for name in names.iter().filter(|n| !required.contains(n.as_str())) {
                    if absent.contains(name.as_str()) {
                        errors.push(format!(
                            "job `{}` may run `{name}` on {label}, which cannot judge it",
                            job.id
                        ));
                    } else if !helper {
                        errors.push(format!(
                            "job `{}` runs `{name}` on {label}, not a required context there",
                            job.id
                        ));
                    }
                }
            }
            Err(why) if !helper => errors.push(format!(
                "job `{}` may run on {label} and its contexts are unreadable ({why})",
                job.id
            )),
            Err(_) => {}
        }
    }
    errors
}

/// The refusals of the full set: every job runs (or may, by a plan's output)
/// on a dispatch on each line and on a tag's call, save the named exceptions,
/// and the matrix jobs run every cell.
fn full_refusals(ci: &str) -> Vec<String> {
    let all = jobs(ci);
    let mut errors = Vec::new();
    for (event, label) in [
        (
            Event {
                name: "workflow_dispatch",
                base_ref: "",
                git_ref: "refs/heads/beta",
            },
            "beta-dispatch",
        ),
        (
            Event {
                name: "workflow_dispatch",
                base_ref: "",
                git_ref: "refs/heads/main",
            },
            "main-dispatch",
        ),
        // a called workflow sees its caller's event: release.yml's, the tag's push
        (
            Event {
                name: "push",
                base_ref: "",
                git_ref: "refs/tags/v0.9.0-beta.2",
            },
            "tag",
        ),
    ] {
        let ran = runs(&all, &event);
        for job in &all {
            let excused = NOT_ON_THE_FULL_SET
                .iter()
                .any(|(id, l, _)| *id == job.id && (*l == label || *l == "*"));
            if ran.get(&job.id) == Some(&Some(false)) && !excused {
                errors.push(format!(
                    "job `{}` does not run on {} ({label})",
                    job.id, event.name
                ));
            }
            if let Some((_, cells)) = FULL_MATRIX.iter().find(|(id, _)| *id == job.id) {
                match contexts(job, &event) {
                    Ok(names) if names.len() == *cells => {}
                    other => errors.push(format!(
                        "job `{}` runs {other:?} on {} ({label}), not its {cells} cells",
                        job.id, event.name
                    )),
                }
            }
        }
    }
    errors
}

#[test]
fn a_pull_request_into_beta_runs_exactly_betas_required_set() {
    let errors = pr_refusals(&read(".github/workflows/ci.yml"), "beta", REQUIRED_ON_BETA);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn a_pull_request_into_main_runs_exactly_mains_required_set() {
    let errors = pr_refusals(&read(".github/workflows/ci.yml"), "main", REQUIRED_ON_MAIN);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn a_push_to_beta_runs_exactly_betas_required_set() {
    let errors = push_refusals(&read(".github/workflows/ci.yml"), "beta", REQUIRED_ON_BETA);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn a_push_to_main_runs_exactly_mains_required_set() {
    let errors = push_refusals(&read(".github/workflows/ci.yml"), "main", REQUIRED_ON_MAIN);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn documentation_is_a_pr_and_push_gate_with_warnings_denied() {
    let ci = read(".github/workflows/ci.yml");
    assert!(ci.contains("  pull_request:\n    branches: [main, beta]\n"));
    assert!(ci.contains("  push:\n    branches: [main, beta]\n"));
    assert!(ci.contains(
        "        run: cargo doc --no-deps --all-features\n        env:\n          RUSTDOCFLAGS: -Dwarnings\n"
    ));
    for (line, required) in [("beta", REQUIRED_ON_BETA), ("main", REQUIRED_ON_MAIN)] {
        assert!(required.contains(&"Documentation"));
        assert!(pr_refusals(&ci, line, required).is_empty());
        assert!(push_refusals(&ci, line, required).is_empty());
    }
    assert!(
        !read(".github/workflows/docs.yml").contains("cargo doc"),
        "release.yml already runs Documentation through ci.yml"
    );
}

#[test]
fn benchmark_comparisons_skip_tags_and_allow_branch_dispatches_and_pr_callers() {
    let all = jobs(&read(".github/workflows/bench.yml"));
    for (event, expected) in [
        (
            Event {
                name: "push",
                base_ref: "",
                git_ref: "refs/tags/v0.9.0-beta.4",
            },
            false,
        ),
        (
            Event {
                name: "workflow_dispatch",
                base_ref: "",
                git_ref: "refs/tags/v0.9.0-beta.4",
            },
            false,
        ),
        (
            Event {
                name: "workflow_dispatch",
                base_ref: "",
                git_ref: "refs/heads/beta",
            },
            true,
        ),
        (
            Event {
                name: "workflow_dispatch",
                base_ref: "",
                git_ref: "refs/heads/main",
            },
            true,
        ),
        (pull_request("beta"), true),
        (pull_request("main"), true),
    ] {
        let ran = runs(&all, &event);
        assert_eq!(
            ran.get("benchmarks"),
            Some(&Some(expected)),
            "benchmark comparisons on {} at {}",
            event.name,
            event.git_ref
        );
        assert_eq!(ran.get("benchmarks-build"), Some(&Some(true)));
        assert_eq!(ran.get("scoreboard"), Some(&Some(true)));
    }
}

#[test]
fn a_dispatch_and_a_tags_call_run_every_job_and_the_whole_matrix() {
    let errors = full_refusals(&read(".github/workflows/ci.yml"));
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    for (id, line, reason) in NOT_ON_THE_FULL_SET {
        assert!(!reason.is_empty(), "{id} on {line} names no reason");
    }
    for (context, reason) in PULL_REQUEST_ONLY {
        assert!(!reason.is_empty(), "{context} names no reason");
    }
}

/// The measurement workflows: none starts on a push or a pull request, each runs on
/// a dispatch and on release.yml's call, and release.yml calls each.
#[test]
fn the_measurements_run_on_dispatch_and_before_a_tag_never_on_a_push() {
    let release = read(".github/workflows/release.yml");
    for file in ["bench", "msrv", "features", "machete", "docs"] {
        let text = read(&format!(".github/workflows/{file}.yml"));
        let on = text
            .split("\non:\n")
            .nth(1)
            .unwrap_or_else(|| panic!("{file}.yml: no `on:`"));
        let triggers: Vec<&str> = on
            .lines()
            .take_while(|l| l.is_empty() || l.starts_with(' '))
            .filter(|l| indent(l) == 2)
            .map(str::trim)
            .collect();
        assert_eq!(
            triggers,
            ["workflow_dispatch:", "workflow_call:"],
            "{file}.yml's triggers"
        );
        assert!(
            release.contains(&format!("uses: ./.github/workflows/{file}.yml\n")),
            "release.yml does not call {file}.yml"
        );
    }
}

/// A job outside every required set, inserted first under `jobs:` with `condition`.
fn with_unrequired_job(ci: &str, condition: Option<&str>) -> String {
    let condition = condition.map_or(String::new(), |c| format!("    if: {c}\n"));
    edited(
        ci,
        "\njobs:\n",
        &format!(
            "\njobs:\n  extra:\n    name: Unrequired check\n{condition}    runs-on: ubuntu-latest\n"
        ),
    )
}

/// Replaces `old` in `text` once, asserting it is there.
fn edited(text: &str, old: &str, new: &str) -> String {
    assert_eq!(text.matches(old).count(), 1, "the edit's site: {old}");
    text.replacen(old, new, 1)
}

#[test]
fn a_required_job_gated_off_pull_requests_is_refused() {
    for (id, name) in [("clippy", "Clippy"), ("docs", "Documentation")] {
        let ci = edited(
            &read(".github/workflows/ci.yml"),
            &format!("  {id}:\n    name: {name}\n"),
            &format!("  {id}:\n    name: {name}\n    if: github.event_name != 'pull_request'\n"),
        );
        for (line, required) in [("beta", REQUIRED_ON_BETA), ("main", REQUIRED_ON_MAIN)] {
            let errors = pr_refusals(&ci, line, required);
            assert_eq!(
                errors,
                [format!(
                    "`{name}` is required on {line} but no job is proven to run it on a pull request into {line}"
                )]
            );
        }
    }
}

#[test]
fn an_unrequired_job_left_on_pull_requests_is_refused() {
    let ci = with_unrequired_job(&read(".github/workflows/ci.yml"), None);
    let errors = pr_refusals(&ci, "beta", REQUIRED_ON_BETA);
    assert_eq!(
        errors,
        ["job `extra` runs `Unrequired check` on a pull request into beta, not a required context there"]
    );
    // the old condition, off pull requests alone, puts it back on the push run
    let ci = with_unrequired_job(
        &read(".github/workflows/ci.yml"),
        Some("github.event_name != 'pull_request'"),
    );
    assert!(pr_refusals(&ci, "beta", REQUIRED_ON_BETA).is_empty());
    for (line, required) in [("beta", REQUIRED_ON_BETA), ("main", REQUIRED_ON_MAIN)] {
        assert_eq!(
            push_refusals(&ci, line, required),
            [format!(
                "job `extra` runs `Unrequired check` on a push to {line}, not a required context there"
            )]
        );
    }
}

#[test]
fn the_dependents_on_a_push_to_beta_are_refused() {
    let ci = edited(
        &read(".github/workflows/ci.yml"),
        "    if: >-\n      github.base_ref == 'main' ||\n      (github.event_name != 'pull_request' && !(github.event_name == 'push' && github.ref == 'refs/heads/beta'))\n",
        "    if: github.event_name != 'pull_request' || github.base_ref == 'main'\n",
    );
    assert!(push_refusals(&ci, "main", REQUIRED_ON_MAIN).is_empty());
    // the plan's old condition (every event but a pull request into beta) puts it and the
    // consumer checks back on beta's push; the plan's `outputs.matrix` reads as a matrix
    // expression, unreadable where the jobs decide nothing
    assert_eq!(
        push_refusals(&ci, "beta", REQUIRED_ON_BETA),
        [
            "job `dependents-plan` may run on a push to beta and its contexts are unreadable (a matrix written as one expression: ${{ steps.plan.outputs.matrix }})",
            "job `dependent-check` may run on a push to beta and its contexts are unreadable (a matrix written as one expression: ${{ fromJSON(needs.dependents-plan.outputs.matrix) }})",
        ]
    );
}

#[test]
fn a_pull_request_only_job_on_a_push_is_refused() {
    let ci = edited(
        &read(".github/workflows/ci.yml"),
        // main's semver also runs on a tag's call (#214): its condition, not beta's
        "    name: semver\n    if: github.event_name == 'pull_request' || startsWith(github.ref, 'refs/tags/v')\n",
        "    name: semver\n",
    );
    assert_eq!(
        push_refusals(&ci, "beta", REQUIRED_ON_BETA),
        ["job `semver` may run `semver` on a push to beta, which cannot judge it"]
    );
}

#[test]
fn the_whole_test_matrix_on_a_pull_request_is_refused_cell_by_cell() {
    let ci = edited(
        &read(".github/workflows/ci.yml"),
        "os: ${{ fromJSON((github.event_name == 'workflow_dispatch' || startsWith(github.ref, 'refs/tags/')) && '[\"ubuntu-latest\", \"macos-latest\", \"windows-latest\"]' || '[\"ubuntu-latest\"]') }}",
        "os: [ubuntu-latest, macos-latest, windows-latest]",
    );
    let errors = pr_refusals(&ci, "main", REQUIRED_ON_MAIN);
    assert_eq!(
        errors,
        [
            "job `test` runs `Test Suite (macos-latest, stable)` on a pull request into main, not a required context there",
            "job `test` runs `Test Suite (windows-latest, stable)` on a pull request into main, not a required context there",
        ]
    );
    let errors = push_refusals(&ci, "beta", REQUIRED_ON_BETA);
    assert_eq!(
        errors,
        [
            "job `test` runs `Test Suite (macos-latest, stable)` on a push to beta, not a required context there",
            "job `test` runs `Test Suite (windows-latest, stable)` on a push to beta, not a required context there",
        ]
    );
}

#[test]
fn a_job_on_a_condition_the_parser_cannot_decide_is_refused_both_ways() {
    // the benchmarks job's old record trigger: a pull request whose body names a marker
    let ci = with_unrequired_job(
        &read(".github/workflows/ci.yml"),
        Some("contains(github.event.pull_request.body, '[docs]')"),
    );
    let errors = pr_refusals(&ci, "beta", REQUIRED_ON_BETA);
    assert_eq!(
        errors,
        ["job `extra` runs `Unrequired check` on a pull request into beta, not a required context there"]
    );
    let ci = edited(
        &read(".github/workflows/ci.yml"),
        "  clippy:\n    name: Clippy\n",
        "  clippy:\n    name: Clippy\n    if: contains(github.event.pull_request.body, '[lint]')\n",
    );
    assert_eq!(pr_refusals(&ci, "beta", REQUIRED_ON_BETA).len(), 1);
}

#[test]
fn the_evaluator_reads_the_files_idioms() {
    let into_main = pull_request("main");
    let push = Event {
        name: "push",
        base_ref: "",
        git_ref: "refs/heads/beta",
    };
    let pr_or_main = "github.event_name != 'pull_request' || github.base_ref == 'main'";
    assert_eq!(evaluate(pr_or_main, &into_main), Value::Bool(true));
    assert_eq!(
        evaluate(pr_or_main, &pull_request("beta")),
        Value::Bool(false)
    );
    assert_eq!(evaluate(pr_or_main, &push), Value::Bool(true));
    assert_eq!(evaluate("${{ always() }}", &into_main), Value::Bool(true));
    assert_eq!(
        evaluate("needs.plan.outputs.count != '0'", &into_main),
        Value::Unknown
    );
    assert_eq!(
        evaluate("needs.plan.outputs.count != '0' && false", &into_main),
        Value::Bool(false)
    );
    assert_eq!(
        evaluate("!(github.event_name == 'PULL_REQUEST')", &into_main),
        Value::Bool(false)
    );
    assert_eq!(evaluate("inputs.record", &into_main), Value::Null);
    assert_eq!(
        evaluate("startsWith(github.ref, 'REFS/heads/')", &push),
        Value::Bool(true)
    );
    assert_eq!(
        evaluate("startsWith(github.ref, 'refs/tags/')", &push),
        Value::Bool(false)
    );
    assert_eq!(
        evaluate("startsWith(needs.a.outputs.b, 'x')", &push),
        Value::Unknown
    );
    assert_eq!(
        values(
            "${{ fromJSON(github.event_name == 'pull_request' && '[\"a\"]' || '[\"a\", \"b\"]') }}",
            &push
        ),
        Some(vec!["a".to_string(), "b".to_string()])
    );
}
