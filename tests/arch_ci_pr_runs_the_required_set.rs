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
//! Documentation belongs to ci.yml's required set on both lines (#515), a step of `checks`
//! since the small gates were bundled into `lint` and `checks` (docs/lanes/ci-speed-2.md).
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

/// `beta`'s required contexts as they will be after the speed cut lands
/// (docs/lanes/ci-speed-2.md), not a live snapshot: `lint` carries Rustfmt, Clippy, deny and
/// ratchet, `checks` carries vectors, fixtures, front page, secrets, Documentation and wasm32 (combined),
/// each a step with its own `PASS`/`FAIL` line; `main-in-beta` stays a job of its own (beta's
/// alone, on its own events). The twelve before, read 2026-11-02 by
/// `gh api repos/Calhooon/bsv-rs/branches/beta/protection/required_status_checks --jq '.contexts'`:
/// the five below less `lint` and `checks`, plus the nine contexts they replace. The captain
/// PATCHes the protection at the landing and reads it back.
const REQUIRED_ON_BETA: &[&str] = &[
    "Test Suite (ubuntu-latest, stable)",
    "lint",
    "checks",
    "main-in-beta",
    "semver",
    // the node's oracle (#97, S1; the owner's decision of 2026-11-10): beta's line alone, as
    // `main-in-beta`; the captain PATCHes beta's protection after the job runs green on its tip
    "sibling",
];

/// `main`'s required contexts once `main`'s `ci.yml` carries `lint` and `checks`, not a live
/// snapshot; until then `main`'s protection keeps the contexts its own `ci.yml` reports.
const REQUIRED_ON_MAIN: &[&str] = &[
    "Test Suite (ubuntu-latest, stable)",
    "lint",
    "checks",
    "dependents",
    "semver",
    "beta-born",
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

/// Jobs a push to either line runs beside its required set, with the reason: (job id, reason).
/// A seed judges nothing and reports no required context: it saves a cache under the key a
/// pull-request-only job restores, in the line's scope, since a pull request's own cache is read
/// by that pull request's re-runs alone. Each is proven to run on a push to both lines (an entry
/// whose job does not is refused as stale), stays off pull requests by the exact-set rule and
/// off the full set by [`NOT_ON_THE_FULL_SET`].
const PUSH_SEEDS: &[(&str, &str)] = &[(
    "semver-tool-seed",
    "it saves the semver tool under the key `semver` restores; no pull request can seed another (#696)",
)];

/// Jobs a dispatch or a tag's call does not run, with the reason: (job id,
/// event label or `*` for every one, reason). Nothing else belongs here: an
/// entry naming no job, or a job that runs (or may) on an event it covers, is
/// refused (#347).
const NOT_ON_THE_FULL_SET: &[(&str, &str, &str)] = &[
    (
        "semver",
        "*",
        "it reads the pull request's base; no dispatch and no tag has one",
    ),
    ("beta-born", "*", "it judges a pull request into main"),
    (
        "semver-tool-seed",
        "*",
        "a push to a line seeds the line's cache; a dispatch's or a tag's seeds none a pull request reads",
    ),
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

/// The cells of each matrix job on the full set (`wasm32 (combined)` is a step of `checks`; the
/// five other wasm32 slices are features.yml's).
const FULL_MATRIX: &[(&str, usize)] = &[("test", 6)];

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
    exact_refusals(ci, &pull_request(line), line, &label, required, &[], &[])
}

/// The refusals of the exact-set rule on a push to `line`: its required set less
/// [`PULL_REQUEST_ONLY`], which must not run, plus the [`PUSH_SEEDS`], which must.
fn push_refusals(ci: &str, line: &'static str, required: &[&str]) -> Vec<String> {
    let label = format!("a push to {line}");
    let absent: Vec<&str> = PULL_REQUEST_ONLY.iter().map(|(c, _)| *c).collect();
    let seeds: Vec<&str> = PUSH_SEEDS.iter().map(|(id, _)| *id).collect();
    exact_refusals(ci, &push(line), line, &label, required, &absent, &seeds)
}

/// The refusals of the exact-set rule for `event`: every context of `required` but
/// those of `absent` proven to run, no job proven to run `absent`'s, every job of `seeds`
/// proven to run, and no other context run (the jobs a deciding job needs aside).
fn exact_refusals(
    ci: &str,
    event: &Event,
    line: &str,
    label: &str,
    required: &[&str],
    absent: &[&str],
    seeds: &[&str],
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
        let helper = helpers.contains(&job.id) || seeds.contains(&job.id.as_str());
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
    for seed in seeds {
        if ran.get(*seed) != Some(&Some(true)) {
            errors.push(format!(
                "push seed `{seed}` is not proven to run on {label}; delete the entry or restore the job"
            ));
        }
    }
    errors
}

/// The refusals of the full set: every job runs (or may, by a plan's output)
/// on a dispatch on each line and on a tag's call, save the named exceptions,
/// and the matrix jobs run every cell; an exception no run needs is stale.
fn full_refusals(ci: &str, excuses: &[(&str, &str, &str)]) -> Vec<String> {
    let all = jobs(ci);
    let mut errors = Vec::new();
    let mut ran_anyway: Vec<Option<&str>> = vec![None; excuses.len()];
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
            let skipped = ran.get(&job.id) == Some(&Some(false));
            let mut excused = false;
            for (i, (id, l, _)) in excuses.iter().enumerate() {
                if *id == job.id && (*l == label || *l == "*") {
                    excused = true;
                    if !skipped && ran_anyway[i].is_none() {
                        ran_anyway[i] = Some(label);
                    }
                }
            }
            if skipped && !excused {
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
    errors.extend(stale_exceptions(&all, excuses, &ran_anyway));
    errors
}

/// The full-set exceptions no run needs (#347): one naming no job, or one whose
/// job runs (or may) on an event it covers (`ran_anyway`, the first such event).
fn stale_exceptions(
    all: &[Job],
    excuses: &[(&str, &str, &str)],
    ran_anyway: &[Option<&str>],
) -> Vec<String> {
    let mut errors = Vec::new();
    for ((id, l, _), ran) in excuses.iter().zip(ran_anyway) {
        if !all.iter().any(|job| job.id == *id) {
            errors.push(format!(
                "full-set exception `{id}` on {l} names no job of ci.yml; delete the entry"
            ));
        } else if let Some(label) = ran {
            errors.push(format!(
                "full-set exception `{id}` on {l}: the job runs (or may) on {label}; delete or narrow the entry"
            ));
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
    // a step of `checks`, its warnings denied
    let checks = ci
        .split("\n  checks:\n")
        .nth(1)
        .expect("a `checks` job")
        .split("\n  main-in-beta:\n")
        .next()
        .unwrap_or_default();
    assert!(checks.contains(
        "      - name: Documentation\n        id: docs\n        if: ${{ !cancelled() && steps.ready.outcome == 'success' }}\n        env:\n          RUSTDOCFLAGS: -Dwarnings\n"
    ));
    assert!(checks.contains("          cargo doc --no-deps --all-features\n"));
    for (line, required) in [("beta", REQUIRED_ON_BETA), ("main", REQUIRED_ON_MAIN)] {
        assert!(required.contains(&"checks"));
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
    let errors = full_refusals(&read(".github/workflows/ci.yml"), NOT_ON_THE_FULL_SET);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    for (id, line, reason) in NOT_ON_THE_FULL_SET {
        assert!(!reason.is_empty(), "{id} on {line} names no reason");
    }
    for (context, reason) in PULL_REQUEST_ONLY {
        assert!(!reason.is_empty(), "{context} names no reason");
    }
    for (id, reason) in PUSH_SEEDS {
        assert!(!reason.is_empty(), "{id} names no reason");
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
    for (id, name) in [("lint", "lint"), ("checks", "checks")] {
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
        "    name: semver\n    if: github.event_name == 'pull_request'\n",
        "    name: semver\n",
    );
    assert_eq!(
        push_refusals(&ci, "beta", REQUIRED_ON_BETA),
        ["job `semver` may run `semver` on a push to beta, which cannot judge it"]
    );
}

/// #696: the seed off a push is a stale entry, and on a pull request a context no line requires.
#[test]
fn a_push_seed_off_the_push_or_on_a_pull_request_is_refused() {
    let seed = "    name: semver tool cache\n    if: github.event_name == 'push' && startsWith(github.ref, 'refs/heads/')\n";
    let ci = edited(
        &read(".github/workflows/ci.yml"),
        seed,
        "    name: semver tool cache\n    if: github.event_name == 'pull_request'\n",
    );
    for (line, required) in [("beta", REQUIRED_ON_BETA), ("main", REQUIRED_ON_MAIN)] {
        assert_eq!(
            push_refusals(&ci, line, required),
            [format!(
                "push seed `semver-tool-seed` is not proven to run on a push to {line}; delete the entry or restore the job"
            )]
        );
        assert_eq!(
            pr_refusals(&ci, line, required),
            [format!(
                "job `semver-tool-seed` runs `semver tool cache` on a pull request into {line}, not a required context there"
            )]
        );
    }
}

/// #347: a full-set exception naming no job, or a job that runs on an event it
/// covers, is refused naming the entry.
#[test]
fn a_stale_full_set_exception_is_refused_naming_the_entry() {
    let mut excuses = NOT_ON_THE_FULL_SET.to_vec();
    excuses.push(("lint", "*", "lint runs on every full set"));
    excuses.push(("gone", "tag", "no such job"));
    assert_eq!(
        full_refusals(&read(".github/workflows/ci.yml"), &excuses),
        [
            "full-set exception `lint` on *: the job runs (or may) on beta-dispatch; delete or narrow the entry",
            "full-set exception `gone` on tag names no job of ci.yml; delete the entry",
        ]
    );
}

#[test]
fn the_whole_test_matrix_on_a_pull_request_is_refused_cell_by_cell() {
    let ci = edited(
        &read(".github/workflows/ci.yml"),
        "os: ${{ fromJSON((github.event_name == 'workflow_dispatch' || startsWith(github.ref, 'refs/tags/')) && '[\"ubuntu-latest\", \"macos-15-intel\", \"windows-latest\"]' || '[\"ubuntu-latest\"]') }}",
        "os: [ubuntu-latest, macos-15-intel, windows-latest]",
    );
    let errors = pr_refusals(&ci, "main", REQUIRED_ON_MAIN);
    assert_eq!(
        errors,
        [
            "job `test` runs `Test Suite (macos-15-intel, stable)` on a pull request into main, not a required context there",
            "job `test` runs `Test Suite (windows-latest, stable)` on a pull request into main, not a required context there",
        ]
    );
    let errors = push_refusals(&ci, "beta", REQUIRED_ON_BETA);
    assert_eq!(
        errors,
        [
            "job `test` runs `Test Suite (macos-15-intel, stable)` on a push to beta, not a required context there",
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
        "  lint:\n    name: lint\n",
        "  lint:\n    name: lint\n    if: contains(github.event.pull_request.body, '[lint]')\n",
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

/// The `sibling` job, byte for byte, from its key line to its last line (#853's third fold, the
/// scoped re-read of the second: a pin of the judging step alone left the job's other lines
/// open). A step inserted before the judging step (one rewriting `tests/sibling/column.json` or
/// `.github/scripts/sibling_harness.py`, or appending `BASH_ENV` to `$GITHUB_ENV`), a job `env:`
/// key (`BASH_ENV`, `PATH`, `PYTHONPATH`, `RUNNER_TEMP`), a `container:`, a `strategy:`, a
/// `timeout-minutes:`, another `runs-on:`, another action or `ref:` for the sibling's checkout,
/// a step after the judging one, and every change to the judging step itself (a
/// `continue-on-error`, a `|| true`, an `exit 0` or an `echo` before the harness, `exit "$rc"`
/// changed to `exit 0`, `--corpus all` narrowed, another shell) each change these bytes, so a
/// change to the job is a change to this constant in the same diff. `shell: bash` is GitHub's
/// `bash --noprofile --norc -eo pipefail {0}` (the runner's documented template for `bash`): the
/// block stops at the first failing command and a pipeline fails with its last failing member;
/// `set -euo pipefail` repeats it in the block, and the harness's own status is taken from
/// `PIPESTATUS[0]` between `set +e` and `set -e`. The constant is data: the YAML as it stands.
const SIBLING_JOB: &str = r##"  sibling:
    name: sibling
    if: >-
      (github.event_name != 'pull_request' || github.base_ref == 'beta') &&
      (github.event_name != 'push' || github.ref != 'refs/heads/main')
    runs-on: ubuntu-latest
    env:
      # THE PIN, in this one place. The sibling's public edition (bsv-script-lean's home since
      # 2026-10-27; the private Calgooon repository is archived): no token is read. To move it:
      # set SIBLING_PIN to the new commit, run tests/sibling/CLAUDE.md's one command against a
      # checkout at it with `--record`, and commit the pin and the re-recorded column together
      # (a commit of its own, Q97.6). The script refuses a column read at another commit (exit 2).
      SIBLING_REPOSITORY: Calhooon/bsv-script-lean
      SIBLING_PIN: 1c051eaef1077cc95e5d1618686d5efacc4aa097
      CARGO_TARGET_DIR: ${{ github.workspace }}/sibling-target
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          persist-credentials: false

      - name: The command's unit tests
        run: python3 -B -m unittest discover -s .github/scripts -p 'test_sibling_harness.py'

      # the harness, the pins it reads and the nine corpora (`harness/run:32`), nothing else
      - name: Check out the sibling at the pin
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          repository: ${{ env.SIBLING_REPOSITORY }}
          ref: ${{ env.SIBLING_PIN }}
          path: sibling
          persist-credentials: false
          sparse-checkout-cone-mode: false
          sparse-checkout: |
            /harness/
            /docs/PROVENANCE.md
            /corpus/seed/
            /corpus/flow/
            /corpus/arith/
            /corpus/stack/
            /corpus/crypto/
            /corpus/bytes/
            /corpus/eras/
            /corpus/gen/
            /corpus/tx/

      # the harness's own toolchain file (`harness/rust-toolchain.toml`) names 1.95.0
      - name: Install Rust
        uses: dtolnay/rust-toolchain@e2a55d2ffb04f378e9626c28d38b36d230d1e12f # v1
        with:
          toolchain: 1.95.0

      - name: Cache the harness's build
        uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2.9.3
        with:
          shared-key: sibling
          workspaces: sibling/harness -> ../../sibling-target
          save-if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/beta' }}

      - name: sibling
        shell: bash
        run: |
          set -euo pipefail
          test "$(git -C sibling rev-parse HEAD)" = "$SIBLING_PIN"
          set +e
          python3 -B .github/scripts/sibling_harness.py run --tree . --sibling sibling \
            --corpus all --scratch "$RUNNER_TEMP/sibling-scratch" --out "$RUNNER_TEMP/sibling-out" \
            --column tests/sibling/column.json 2>&1 | tee "$RUNNER_TEMP/sibling.log"
          rc="${PIPESTATUS[0]}"
          set -e
          {
            echo '```'
            grep -E '^(VERDICTS|REASONS|sibling_harness: (GREEN|RED|SETUP))|^  ' "$RUNNER_TEMP/sibling.log" | head -200 || true
            echo '```'
          } >> "$GITHUB_STEP_SUMMARY"
          exit "$rc"
"##;

/// What every job of ci.yml inherits from the workflow, each block byte for byte (#853's third
/// fold): a workflow `env:` key (`BASH_ENV` among them) reaches the judging step's shell, the
/// `permissions:` its token, the `concurrency:` whether it is cancelled. ci.yml's workflow-level
/// keys are [`WORKFLOW_KEYS`] alone, so a `defaults:` (or any other key) is refused wherever it
/// sits in the file; a workflow `env:` that gains a key is a change to this test in the same diff.
const SIBLING_INHERITS: &[(&str, &str)] = &[
    (
        "permissions",
        r##"permissions:
  contents: read
"##,
    ),
    (
        "concurrency",
        r##"concurrency:
  group: ci-${{ github.event_name }}-${{ github.ref }}
  cancel-in-progress: ${{ !startsWith(github.ref, 'refs/tags/') }}
"##,
    ),
    (
        "env",
        r##"env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -Dwarnings
"##,
    ),
];

/// ci.yml's workflow-level keys, each once: the three [`SIBLING_INHERITS`] pins, the name, the
/// triggers (their path filters refused apart) and the jobs.
const WORKFLOW_KEYS: &[&str] = &["name", "on", "permissions", "concurrency", "env", "jobs"];

/// The block a key line opens: the line and every line under it, to the next line at the key's
/// indent or less that is neither blank nor a comment (a comment ends no YAML block, so a key
/// after a comment at the key's own indent is still inside), less the trailing blanks and the
/// trailing comments at that indent (the next key's preamble).
fn block<'a>(lines: &[&'a str], start: usize, depth: usize) -> Vec<&'a str> {
    let ends =
        |l: &&str| !l.trim().is_empty() && !l.trim_start().starts_with('#') && indent(l) <= depth;
    let rest = &lines[start + 1..];
    let end = rest.iter().position(ends).unwrap_or(rest.len());
    let mut out: Vec<&str> = std::iter::once(lines[start])
        .chain(rest[..end].iter().copied())
        .collect();
    while out.len() > 1
        && out.last().is_some_and(|l| {
            l.trim().is_empty() || (l.trim_start().starts_with('#') && indent(l) <= depth)
        })
    {
        out.pop();
    }
    out
}

/// The first difference of `found` (whose first line is ci.yml's line `line`) from `pinned`,
/// or `None` when they are equal byte for byte: the line number in ci.yml, the pinned line and
/// the line found, each quoted so that a space or a tab shows.
fn first_difference(
    what: &str,
    name: &str,
    found: &[&str],
    pinned: &str,
    line: usize,
) -> Option<String> {
    let text: String = found.iter().map(|l| format!("{l}\n")).collect();
    if text == pinned {
        return None;
    }
    let expected: Vec<&str> = pinned.lines().collect();
    let at = found
        .iter()
        .zip(&expected)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| found.len().min(expected.len()));
    let shown = |l: Option<&&str>| l.map_or("<end>".to_string(), |l| format!("{l:?}"));
    Some(format!(
        "{what} is not {name} byte for byte (a change to it is a change to this test in the same diff): ci.yml line {}\n  expected: {}\n  found:    {}",
        line + at,
        shown(expected.get(at)),
        shown(found.get(at))
    ))
}

/// ci.yml's triggers carry no `paths` or `paths-ignore`.
fn trigger_refusals(ci: &str) -> Vec<String> {
    let head = ci.split("\njobs:\n").next().unwrap_or_default();
    head.lines()
        .filter(|line| {
            let key = line.trim_start();
            key.starts_with("paths:") || key.starts_with("paths-ignore:")
        })
        .map(|line| format!("ci.yml's triggers carry a path filter: `{}`", line.trim()))
        .collect()
}

/// ci.yml's workflow-level keys are [`WORKFLOW_KEYS`], each once, wherever they sit in the file,
/// and each block of [`SIBLING_INHERITS`] is its pin byte for byte.
fn inherited_refusals(ci: &str) -> Vec<String> {
    let lines: Vec<&str> = ci.lines().collect();
    let mut seen: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (at, line) in lines.iter().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') || indent(line) > 0 {
            continue;
        }
        let key = line.split(':').next().unwrap_or(line);
        seen.entry(key).or_default().push(at);
    }
    let mut errors = Vec::new();
    for (key, at) in &seen {
        let numbers: Vec<String> = at.iter().map(|n| (n + 1).to_string()).collect();
        if !WORKFLOW_KEYS.contains(key) {
            errors.push(format!(
                "ci.yml carries a workflow-level `{key}:` the `sibling` job would inherit (line {}; the workflow's keys are WORKFLOW_KEYS alone)",
                numbers.join(", ")
            ));
        } else if at.len() > 1 {
            errors.push(format!(
                "ci.yml carries a workflow-level `{key}:` more than once (lines {})",
                numbers.join(", ")
            ));
        }
    }
    for (key, pinned) in SIBLING_INHERITS {
        let Some(&start) = seen.get(key).and_then(|at| at.first()) else {
            errors.push(format!(
                "ci.yml has no workflow-level `{key}:`, which SIBLING_INHERITS pins"
            ));
            continue;
        };
        let found = block(&lines, start, 0);
        let what = format!("the workflow's `{key}:` (every job inherits it)");
        let name = format!("SIBLING_INHERITS' `{key}`");
        errors.extend(first_difference(&what, &name, &found, pinned, start + 1));
    }
    errors
}

/// The `sibling` context is reported by ci.yml's `sibling` job alone: no second job of ci.yml
/// (a twin key, or another id with `name: sibling`) and no job of another workflow carries it, so
/// a green twin cannot stand beside the judging job. A name written as an expression is not read.
fn sibling_context_refusals(ci: &str, others: &[(String, String)]) -> Vec<String> {
    let reports = |job: &Job| {
        job.name.as_deref().map_or(job.id.as_str(), |n| {
            n.trim_matches(|c| c == '\'' || c == '"')
        }) == "sibling"
    };
    let mut errors = Vec::new();
    let ids: Vec<String> = jobs(ci)
        .iter()
        .filter(|j| reports(j))
        .map(|j| j.id.clone())
        .collect();
    if ids != ["sibling"] {
        errors.push(format!(
            "the `sibling` context is reported by ci.yml's jobs {ids:?}: by the `sibling` job alone"
        ));
    }
    for (file, text) in others {
        for job in jobs(text)
            .iter()
            .filter(|j| reports(j) || j.id == "sibling")
        {
            errors.push(format!(
                "{file}'s job `{}` reports `sibling`: ci.yml's `sibling` job alone may",
                job.id
            ));
        }
    }
    errors
}

/// The named rules over the job's lines: what each change would do, beside the pin's bytes.
/// The job's own `if:` reads only the event (`github.event_name`, `github.base_ref`,
/// `github.ref`), the job has no `needs:` (a skipped plan job would skip it), no step of it
/// carries an `if:`, no line carries `continue-on-error`, the job carries no `defaults:` or
/// `shell:` (the step names its shell), and its `sibling` step runs the harness.
fn job_rule_refusals(ci: &str, job: &[&str]) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(job) = jobs(ci).into_iter().find(|j| j.id == "sibling") {
        if !job.needs.is_empty() {
            errors.push(format!(
                "job `sibling` needs {:?}: a skipped job would skip it",
                job.needs
            ));
        }
        let condition = job.condition.unwrap_or_default();
        let unquoted: String = condition
            .split('\'')
            .step_by(2)
            .collect::<Vec<_>>()
            .join(" ");
        let read: Vec<&str> = unquoted
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
            .filter(|word| word.contains('.'))
            .filter(|word| !["github.event_name", "github.base_ref", "github.ref"].contains(word))
            .collect();
        if !read.is_empty() {
            errors.push(format!(
                "job `sibling`'s `if:` reads more than the event ({}): `{condition}`",
                read.join(", ")
            ));
        }
    }
    for line in &job[1..] {
        let text = line.trim_start().trim_start_matches("- ");
        if text.starts_with('#') {
            continue;
        }
        if text.starts_with("continue-on-error:") {
            errors.push(format!(
                "job `sibling` carries `continue-on-error`: `{}`",
                line.trim()
            ));
        }
        if indent(line) == 4 && (text.starts_with("defaults:") || text.starts_with("shell:")) {
            errors.push(format!(
                "job `sibling` carries `{}`: the judging step's shell is its own",
                line.trim()
            ));
        }
        if indent(line) > 4 && text.starts_with("if:") {
            errors.push(format!(
                "a step of `sibling` carries a condition: `{}`",
                line.trim()
            ));
        }
    }
    match job.iter().position(|l| l.trim() == "- name: sibling") {
        None => errors.push("job `sibling` has no step named `sibling`".to_string()),
        Some(at) => {
            let mut step = job[at + 1..]
                .iter()
                .take_while(|l| !l.trim_start().starts_with("- "));
            if !step.any(|l| l.contains("sibling_harness.py run")) {
                errors.push("the `sibling` step does not run `sibling_harness.py run`".to_string());
            }
        }
    }
    errors
}

/// The `sibling` job judges on every event it runs on (#97's fold, the captain's ruling of
/// 2026-11-10), and nothing in ci.yml can turn it green without judging (#853's second and third
/// folds): its triggers carry no path filter, what it inherits from the workflow is
/// [`SIBLING_INHERITS`] and [`WORKFLOW_KEYS`], its whole text is [`SIBLING_JOB`] byte for byte,
/// and the named rules of [`job_rule_refusals`] say why a change would matter. A required context
/// whose job or judging step is skipped by a path test reports success without a judgment.
fn sibling_refusals(ci: &str) -> Vec<String> {
    let mut errors = trigger_refusals(ci);
    errors.extend(inherited_refusals(ci));
    let lines: Vec<&str> = ci.lines().collect();
    let Some(start) = lines.iter().position(|l| *l == "  sibling:") else {
        errors.push("no `sibling` job in ci.yml".to_string());
        return errors;
    };
    let job = block(&lines, start, 2);
    errors.extend(job_rule_refusals(ci, &job));
    errors.extend(first_difference(
        "the `sibling` job",
        "SIBLING_JOB",
        &job,
        SIBLING_JOB,
        start + 1,
    ));
    errors
}

/// The workflows other than ci.yml, by file name.
fn other_workflows() -> Vec<(String, String)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let mut out: Vec<(String, String)> = fs::read_dir(&root)
        .expect("the workflows")
        .map(|e| {
            e.expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|n| n.ends_with(".yml") && n != "ci.yml")
        .map(|n| {
            let text = read(&format!(".github/workflows/{n}"));
            (n, text)
        })
        .collect();
    out.sort();
    out
}

const JOB_PINNED: &str = "the `sibling` job is not SIBLING_JOB byte for byte";

#[test]
fn the_sibling_job_judges_on_every_event_it_runs_on_with_no_reach_filter_97() {
    let ci = read(".github/workflows/ci.yml");
    let errors = sibling_refusals(&ci);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    let errors = sibling_context_refusals(&ci, &other_workflows());
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    // the judging step behind a path output, as at 4d81e9da
    let step = edited(
        &ci,
        "      - name: sibling\n        shell: bash\n",
        "      - name: sibling\n        if: steps.plan.outputs.reached == 'true'\n        shell: bash\n",
    );
    let errors = sibling_refusals(&step);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert_eq!(
        errors[0],
        "a step of `sibling` carries a condition: `if: steps.plan.outputs.reached == 'true'`"
    );
    assert!(errors[1].starts_with(JOB_PINNED), "{errors:?}");
    // the job behind a plan job's output
    let job = edited(
        &ci,
        "      (github.event_name != 'push' || github.ref != 'refs/heads/main')\n    runs-on: ubuntu-latest\n    env:\n      # THE PIN",
        "      (github.event_name != 'push' || github.ref != 'refs/heads/main') &&\n      needs.plan.outputs.reached == 'true'\n    needs: plan\n    runs-on: ubuntu-latest\n    env:\n      # THE PIN",
    );
    let errors = sibling_refusals(&job);
    assert_eq!(errors.len(), 3, "{errors:?}");
    assert!(
        errors[0].starts_with("job `sibling` needs [\"plan\"]"),
        "{errors:?}"
    );
    assert!(
        errors[1].starts_with("job `sibling`'s `if:` reads more than the event"),
        "{errors:?}"
    );
    assert!(errors[2].starts_with(JOB_PINNED), "{errors:?}");
    // a path filter on the trigger
    let paths = edited(
        &ci,
        "  pull_request:\n    branches: [main, beta]\n",
        "  pull_request:\n    branches: [main, beta]\n    paths: ['src/script/**']\n",
    );
    assert_eq!(
        sibling_refusals(&paths),
        ["ci.yml's triggers carry a path filter: `paths: ['src/script/**']`"]
    );
    // the harness taken out of the judging step
    let gone = edited(
        &ci,
        "python3 -B .github/scripts/sibling_harness.py run --tree .",
        "echo skipped --tree .",
    );
    let errors = sibling_refusals(&gone);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert_eq!(
        errors[0],
        "the `sibling` step does not run `sibling_harness.py run`"
    );
    assert!(errors[1].starts_with(JOB_PINNED), "{errors:?}");
}

/// The seven ways the cold and rule re-reads of #853's fold ended green without judging, each
/// planted alone in ci.yml and each refused, plus a job `defaults:` and a workflow `defaults:`.
#[test]
fn the_sibling_step_is_pinned_and_no_failure_of_it_is_absorbed_97() {
    let ci = read(".github/workflows/ci.yml");
    let harness = "python3 -B .github/scripts/sibling_harness.py run --tree . --sibling sibling";
    let plants: [(&str, &str, String, &str); 7] = [
        (
            "continue-on-error on the step",
            "      - name: sibling\n        shell: bash\n",
            "      - name: sibling\n        continue-on-error: true\n        shell: bash\n".into(),
            "job `sibling` carries `continue-on-error`: `continue-on-error: true`",
        ),
        (
            "`|| true` after the harness",
            "--column tests/sibling/column.json 2>&1 | tee \"$RUNNER_TEMP/sibling.log\"\n",
            "--column tests/sibling/column.json 2>&1 | tee \"$RUNNER_TEMP/sibling.log\" || true\n"
                .into(),
            JOB_PINNED,
        ),
        (
            "an `exit 0` before the harness",
            &format!("          set +e\n          {harness}"),
            format!("          set +e\n          exit 0\n          {harness}"),
            JOB_PINNED,
        ),
        (
            "an `echo` before the harness",
            harness,
            format!("echo {harness}"),
            JOB_PINNED,
        ),
        (
            "`exit \"$rc\"` changed to `exit 0`",
            "          exit \"$rc\"\n",
            "          exit 0\n".into(),
            JOB_PINNED,
        ),
        (
            "`--corpus all` narrowed to one corpus",
            "            --corpus all --scratch",
            "            --corpus seed --scratch".into(),
            JOB_PINNED,
        ),
        (
            "the step's shell changed",
            "      - name: sibling\n        shell: bash\n",
            "      - name: sibling\n        shell: sh\n".into(),
            JOB_PINNED,
        ),
    ];
    for (what, old, new, refusal) in &plants {
        let errors = sibling_refusals(&edited(&ci, old, new));
        assert!(
            errors.iter().any(|e| e.starts_with(refusal)),
            "{what}: not refused: {errors:?}"
        );
    }
    // continue-on-error on the job: its line named, the job's bytes changed
    let site = "      (github.event_name != 'push' || github.ref != 'refs/heads/main')\n    runs-on: ubuntu-latest\n    env:\n      # THE PIN";
    let job = edited(
        &ci,
        site,
        &site.replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    continue-on-error: true\n",
        ),
    );
    let errors = sibling_refusals(&job);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert_eq!(
        errors[0],
        "job `sibling` carries `continue-on-error`: `continue-on-error: true`"
    );
    assert!(errors[1].starts_with(JOB_PINNED), "{errors:?}");
    // a job `defaults:` naming another shell
    let defaults = edited(
        &ci,
        site,
        &site.replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    defaults:\n      run:\n        shell: sh {0}\n",
        ),
    );
    let errors = sibling_refusals(&defaults);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert_eq!(
        errors[0],
        "job `sibling` carries `defaults:`: the judging step's shell is its own"
    );
    assert!(errors[1].starts_with(JOB_PINNED), "{errors:?}");
    // a workflow `defaults:`
    let workflow = edited(
        &ci,
        "\npermissions:\n",
        "\ndefaults:\n  run:\n    shell: sh {0}\npermissions:\n",
    );
    let errors = sibling_refusals(&workflow);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors[0].starts_with(
            "ci.yml carries a workflow-level `defaults:` the `sibling` job would inherit"
        ),
        "{errors:?}"
    );
}

/// The ways a pin of the judging step alone left the job green without judging (#853's third
/// fold, the second fold's scoped re-read), each planted alone in ci.yml and each refused by the
/// pin of the whole job or of what it inherits, and the failure's form: the line in ci.yml, the
/// pinned line, the line found.
#[test]
fn the_sibling_job_and_what_it_inherits_are_pinned_whole_97() {
    let ci = read(".github/workflows/ci.yml");
    let judging = "      - name: sibling\n        shell: bash\n";
    let before = |run: &str| format!("      - name: prepare\n        run: {run}\n\n{judging}");
    let at_runs_on = "    runs-on: ubuntu-latest\n    env:\n      # THE PIN";
    let job_key = |key: &str| format!("    runs-on: ubuntu-latest\n{key}    env:\n      # THE PIN");
    let pin = "      SIBLING_PIN: 1c051eaef1077cc95e5d1618686d5efacc4aa097\n";
    let job_env = |key: &str| format!("{pin}      {key}\n");
    let checkout = "      - name: Check out the sibling at the pin\n        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0\n";
    let job_plants: Vec<(&str, &str, String)> = vec![
        ("a step before the judging one rewriting the column", judging, before("echo '{}' > tests/sibling/column.json")),
        ("a step before the judging one rewriting the judge", judging, before("echo 'print(\"GREEN\")' > .github/scripts/sibling_harness.py")),
        ("a step before the judging one writing BASH_ENV", judging, before("echo BASH_ENV=./evil.sh >> \"$GITHUB_ENV\"")),
        ("a job env: BASH_ENV", pin, job_env("BASH_ENV: ./evil.sh")),
        ("a job env: PATH", pin, job_env("PATH: ./bin")),
        ("a job env: PYTHONPATH", pin, job_env("PYTHONPATH: ./shadow")),
        ("a job env: RUNNER_TEMP", pin, job_env("RUNNER_TEMP: ./shadow")),
        ("a job container:", at_runs_on, job_key("    container: python:3\n")),
        ("another action for the sibling's checkout", checkout, checkout.replace("actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0", "someone/checkout@v4")),
        ("the sibling checkout's ref changed", "          ref: ${{ env.SIBLING_PIN }}\n", "          ref: main\n".into()),
        ("a step after the judging one on failure()", "          exit \"$rc\"\n", "          exit \"$rc\"\n\n      - name: rescue\n        if: failure()\n        run: exit 0\n".into()),
        ("timeout-minutes: 0", at_runs_on, job_key("    timeout-minutes: 0\n")),
        ("runs-on changed", at_runs_on, at_runs_on.replace("ubuntu-latest", "self-hosted")),
        ("a strategy: added", at_runs_on, job_key("    strategy:\n      matrix:\n        os: [ubuntu-latest]\n")),
        ("a job key behind a comment at the job's indent", "          exit \"$rc\"\n", "          exit \"$rc\"\n  # an aside\n    continue-on-error: true\n".into()),
        ("one byte changed in a comment of the job", "set SIBLING_PIN to the new commit", "set SIBLING_PIN to the new commits".into()),
    ];
    for (what, old, new) in &job_plants {
        let errors = sibling_refusals(&edited(&ci, old, new));
        assert!(
            errors.iter().any(|e| e.starts_with(JOB_PINNED)),
            "{what}: not refused: {errors:?}"
        );
    }
    let env = "env:\n  CARGO_TERM_COLOR: always\n  RUSTFLAGS: -Dwarnings\n";
    let workflow_plants: Vec<(&str, &str, String, &str)> = vec![
        ("a workflow env: BASH_ENV", env, format!("{env}  BASH_ENV: ./evil.sh\n"), "the workflow's `env:` (every job inherits it) is not SIBLING_INHERITS' `env`"),
        ("a workflow env: key behind a column-0 comment", env, format!("{env}# an aside\n  BASH_ENV: ./evil.sh\n"), "the workflow's `env:` (every job inherits it) is not SIBLING_INHERITS' `env`"),
        ("the permissions widened", "permissions:\n  contents: read\n", "permissions:\n  contents: write\n".into(), "the workflow's `permissions:` (every job inherits it) is not SIBLING_INHERITS' `permissions`"),
        ("the concurrency changed", "  cancel-in-progress: ${{ !startsWith(github.ref, 'refs/tags/') }}\n", "  cancel-in-progress: true\n".into(), "the workflow's `concurrency:` (every job inherits it) is not SIBLING_INHERITS' `concurrency`"),
        ("a second workflow env:", "\njobs:\n", "\nenv:\n  BASH_ENV: ./evil.sh\n\njobs:\n".into(), "ci.yml carries a workflow-level `env:` more than once"),
    ];
    for (what, old, new, refusal) in &workflow_plants {
        let errors = sibling_refusals(&edited(&ci, old, new));
        assert!(
            errors.iter().any(|e| e.starts_with(refusal)),
            "{what}: not refused: {errors:?}"
        );
    }
    // a workflow `defaults:` after the jobs, at the file's end
    let late = format!("{ci}defaults:\n  run:\n    shell: sh {{0}}\n");
    assert!(
        sibling_refusals(&late)
            .iter()
            .any(|e| e.starts_with("ci.yml carries a workflow-level `defaults:`")),
        "a late defaults: not refused"
    );
    // the failure's form: the line in ci.yml, the pinned line, the line found
    let exit = ci
        .lines()
        .position(|l| l == "          exit \"$rc\"")
        .expect("the exit line")
        + 1;
    let errors = sibling_refusals(&edited(
        &ci,
        "          exit \"$rc\"\n",
        "          exit 0\n",
    ));
    assert_eq!(
        errors,
        [format!("{JOB_PINNED} (a change to it is a change to this test in the same diff): ci.yml line {exit}\n  expected: \"          exit \\\"$rc\\\"\"\n  found:    \"          exit 0\"")]
    );
    // a green twin of the context, in ci.yml and in another workflow
    let twin = format!("{ci}  sibling-twin:\n    name: sibling\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n");
    assert_eq!(
        sibling_context_refusals(&twin, &[]),
        ["the `sibling` context is reported by ci.yml's jobs [\"sibling\", \"sibling-twin\"]: by the `sibling` job alone"]
    );
    let other = (
        "other.yml".to_string(),
        "on: pull_request\njobs:\n  green:\n    name: 'sibling'\n    runs-on: ubuntu-latest\n"
            .to_string(),
    );
    assert_eq!(
        sibling_context_refusals(&ci, &[other]),
        ["other.yml's job `green` reports `sibling`: ci.yml's `sibling` job alone may"]
    );
}
