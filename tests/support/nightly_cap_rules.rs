//! The cap guard's readers (#709, #713): every `.github/workflows/*.yml` read at the string
//! level (nothing else; no network, no environment) for its jobs, their `needs:`, `if:` and
//! `timeout-minutes`, the workflows a job dispatches or calls, a wait's figures and the
//! workflows it lists, and the six rules' refusals; the rules' tests are
//! `tests/arch_nightly_cap_rules_709.rs` (rules 1 to 4) and `tests/arch_nightly_cap_watch_713.rs`
//! (rule 4's both directions, rules 5 and 6).
#![allow(dead_code)]
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

use std::fs;
use std::path::PathBuf;

/// A dispatch outside the nightly whose workflow a trigger other than a hand act starts:
/// `(file, job, dispatched, reason)`. The rule refuses one missing here and an entry the
/// workflows no longer carry.
pub const STATED: [(&str, &str, &str, &str); 3] = [
    (
        "sync-main-into-beta.yml",
        "sync",
        "ci.yml",
        "a push to main starts it; the sync PR's CI (a GITHUB_TOKEN push starts no run), ci.yml's \
         matrices at max-parallel 6, not sequenced with the nightly (the residual of #709)",
    ),
    (
        "sync-main-into-beta.yml",
        "sync",
        "sibling-run.yml",
        "a push to main starts it; the sync PR's stage R of the node oracle's judge (#97: a \
         GITHUB_TOKEN push starts no run), one job of one harness build, not sequenced with the \
         nightly",
    ),
    (
        "sync-main-into-beta.yml",
        "sync",
        "sibling-judge.yml",
        "the sync's stage R run completed; its judge on main (#97, fix-97c: a run the \
         GITHUB_TOKEN starts raises no workflow_run), two short jobs, no heavy work",
    ),
];

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every workflow's file name and text (CRLF read as LF), sorted by name.
pub fn workflows() -> Vec<(String, String)> {
    let dir = root().join(".github/workflows");
    let mut out: Vec<(String, String)> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("workflow entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
        })
        .map(|path| {
            let name = path
                .file_name()
                .expect("name")
                .to_string_lossy()
                .into_owned();
            let text = fs::read_to_string(&path).expect("workflow text");
            (name, text.replace("\r\n", "\n"))
        })
        .collect();
    out.sort();
    out
}

pub fn text_of<'a>(workflows: &'a [(String, String)], file: &str) -> &'a str {
    workflows
        .iter()
        .find(|(name, _)| name == file)
        .map(|(_, text)| text.as_str())
        .unwrap_or_else(|| panic!("{file}: not found"))
}

/// The keys at two spaces under the top-level `key:`, each with the lines under it.
pub fn block<'a>(text: &'a str, key: &str) -> Vec<(String, Vec<&'a str>)> {
    let mut out: Vec<(String, Vec<&str>)> = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            inside = line.trim_end() == format!("{key}:");
        } else if inside && line.starts_with("  ") && !line.starts_with("   ") {
            out.push((line.trim().trim_end_matches(':').to_owned(), Vec::new()));
        } else if let Some((_, lines)) = out.last_mut().filter(|_| inside) {
            lines.push(line);
        }
    }
    out
}

/// A job's value at four spaces (`needs`, `if`, `timeout-minutes`, `uses`); a step's key,
/// at six or more, is not read.
pub fn field<'a>(lines: &[&'a str], name: &str) -> Option<&'a str> {
    lines
        .iter()
        .filter(|line| line.starts_with("    ") && !line.starts_with("     "))
        .find_map(|line| line.trim().strip_prefix(name)?.strip_prefix(':'))
        .map(str::trim)
}

pub fn needs_of(lines: &[&str]) -> Vec<String> {
    let value = field(lines, "needs").unwrap_or("");
    value
        .trim_matches(|c| c == '[' || c == ']')
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A job's code: its lines without comments, trimmed, a `\` continuation joined to the next.
pub fn code(lines: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut open = false;
    for line in lines.iter().map(|line| line.trim()) {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let part = line.trim_end_matches('\\').trim_end();
        match out.last_mut().filter(|_| open) {
            Some(last) => *last = format!("{last} {part}"),
            None => out.push(part.to_owned()),
        }
        open = line.ends_with('\\');
    }
    out
}

/// The text after `needle` where it stands at a command position: the line's start (after
/// `- `, `run:`), or after `&&`, `||`, `;`, `|`, `$(`, `then`, `do`; never inside an `echo`.
pub fn invoked<'a>(line: &'a str, needle: &str) -> Option<&'a str> {
    let (before, after) = line.split_once(needle)?;
    let before = before.trim_start_matches("- ").trim_start();
    let before = before.strip_prefix("run:").unwrap_or(before).trim();
    let command = before.is_empty()
        || ["&&", "||", ";", "|", "$(", "then", "do"]
            .iter()
            .any(|end| before.ends_with(end));
    command.then_some(after)
}

/// A line's commands: split at `&&`, `||`, `;`, each trimmed of `- `, `run:`, `export `.
pub fn commands(line: &str) -> Vec<&str> {
    line.split(';')
        .flat_map(|part| part.split("&&"))
        .flat_map(|part| part.split("||"))
        .map(|part| {
            let part = part.trim().trim_start_matches("- ").trim_start();
            let part = part.strip_prefix("run:").unwrap_or(part).trim_start();
            part.strip_prefix("export ").unwrap_or(part).trim()
        })
        .collect()
}

/// The one literal value a job gives the variable `name` (a shell `NAME=value` at a command's
/// start, or a step's `env:` key `NAME: value`); none when it is unassigned, assigned twice
/// with other values, or assigned an expression (`$`, `${{ }}`): such a name is unreadable.
pub fn assigned(lines: &[&str], name: &str) -> Option<String> {
    let mut values: Vec<String> = Vec::new();
    for line in code(lines) {
        for command in commands(&line) {
            let value = command
                .strip_prefix(&format!("{name}="))
                .or_else(|| command.strip_prefix(&format!("{name}:")));
            if let Some(value) = value.filter(|_| !name.is_empty()) {
                let value = value
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_matches('"');
                values.push(value.to_owned());
            }
        }
    }
    values.dedup();
    match values.as_slice() {
        [one] if !one.is_empty() && !one.contains('$') => Some(one.clone()),
        _ => None,
    }
}

/// `target` read through the job's assignment when it is a variable (`$WF`, `${WF}`); kept
/// as written (beginning `$`, so unreadable) when the job gives it no one literal value.
pub fn resolved(lines: &[&str], target: String) -> String {
    let Some(name) = target.strip_prefix('$') else {
        return target;
    };
    let name = name.trim_start_matches('{').trim_end_matches('}');
    assigned(lines, name).unwrap_or(target)
}

/// The workflows a job dispatches or calls, by file name, a variable read through its
/// assignment (a dispatch whose file is unreadable keeps its text: it is still a dispatch).
pub fn dispatches(lines: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for line in code(lines) {
        let word = |rest: &str| {
            rest.split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches('"')
                .to_owned()
        };
        if let Some(rest) = invoked(&line, "gh workflow run ") {
            out.push(word(rest));
        } else if let Some(rest) =
            invoked(&line, "gh api ").filter(|rest| rest.contains("/dispatches"))
        {
            let path = rest.split("/dispatches").next().unwrap_or("");
            out.push(match path.split_once("actions/workflows/") {
                Some((_, file)) => word(file),
                None => "repository_dispatch".to_owned(),
            });
        } else if let Some(rest) = line
            .strip_prefix("uses:")
            .filter(|rest| rest.contains(".github/workflows/"))
        {
            let file = rest.rsplit(".github/workflows/").next().unwrap_or("");
            out.push(word(file.split('@').next().unwrap_or("")));
        }
    }
    out.into_iter().map(|t| resolved(lines, t)).collect()
}

/// A job runs mutants or fuzzes (from a line that is not a comment).
pub fn runs_heavy(lines: &[&str]) -> bool {
    code(lines).iter().any(|line| {
        line.contains("nightly_mutants.py run")
            || line.contains("cargo fuzz run")
            || (line.contains("cargo mutants") && !line.contains("--list"))
    })
}

pub fn heavy(lines: &[&str]) -> bool {
    runs_heavy(lines) || !dispatches(lines).is_empty()
}

/// Whether `job` reaches `ancestor` by `needs:`.
pub fn after(graph: &[(String, Vec<String>)], job: &str, ancestor: &str) -> bool {
    let parents = |name: &str| {
        graph
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, p)| p.clone())
            .unwrap_or_default()
    };
    let (mut todo, mut seen) = (parents(job), Vec::<String>::new());
    while let Some(next) = todo.pop() {
        if next == ancestor {
            return true;
        }
        if !seen.contains(&next) {
            todo.extend(parents(&next));
            seen.push(next);
        }
    }
    false
}

pub fn graph(jobs: &[(String, Vec<&str>)]) -> Vec<(String, Vec<String>)> {
    jobs.iter()
        .map(|(name, lines)| (name.clone(), needs_of(lines)))
        .collect()
}

/// Whether a workflow starts by a hand act alone: its `on:` keys are `workflow_dispatch` and a
/// `push` of tags with no branch.
pub fn hand_triggered(text: &str) -> bool {
    let triggers = block(text, "on");
    !triggers.is_empty()
        && triggers.iter().all(|(key, lines)| match key.as_str() {
            "workflow_dispatch" => true,
            "push" => {
                let keys: Vec<&str> = lines.iter().map(|line| line.trim()).collect();
                keys.iter().any(|k| k.starts_with("tags:"))
                    && !keys
                        .iter()
                        .any(|k| k.starts_with("branches") || k.starts_with("paths"))
            }
            _ => false,
        })
}

/// Rule 1: what is wrong with the dispatches and calls of workflows in every workflow.
pub fn dispatch_rule_errors(workflows: &[(String, String)]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut stated_seen = Vec::new();
    for (file, text) in workflows {
        let jobs = block(text, "jobs");
        let graph = graph(&jobs);
        if file == "nightly.yml" {
            let heavy: Vec<&String> = jobs
                .iter()
                .filter(|(_, l)| heavy(l))
                .map(|(n, _)| n)
                .collect();
            for (i, a) in heavy.iter().enumerate() {
                for b in &heavy[i + 1..] {
                    if !after(&graph, a, b) && !after(&graph, b, a) {
                        errors.push(format!(
                            "nightly.yml {a} and {b} can overlap: no `needs:` path between them"
                        ));
                    }
                }
            }
            continue;
        }
        for (job, lines) in &jobs {
            for target in dispatches(lines) {
                let stated = STATED
                    .iter()
                    .any(|(f, j, t, _)| (*f, *j, *t) == (file, job, &target));
                if stated {
                    stated_seen.push((file.clone(), job.clone(), target));
                } else if !hand_triggered(text) {
                    errors.push(format!("{file} {job}: starts {target} outside nightly.yml on a trigger that is not a hand act, so its run can start beside the nightly's heavy work"));
                }
            }
        }
    }
    for (file, job, target, _) in STATED {
        if !stated_seen
            .iter()
            .any(|(f, j, t)| (f.as_str(), j.as_str(), t.as_str()) == (file, job, target))
        {
            errors.push(format!("{file} {job}: STATED names its start of {target}, which the workflows no longer carry"));
        }
    }
    errors
}

/// Rule 2: every heavy job of the nightly after the shards keeps `!cancelled()` in its `if:`.
pub fn cancelled_errors(nightly: &str) -> Vec<String> {
    let jobs = block(nightly, "jobs");
    let graph = graph(&jobs);
    jobs.iter()
        .filter(|(name, lines)| heavy(lines) && after(&graph, name, "mutants"))
        .filter_map(|(name, lines)| {
            let cond = field(lines, "if");
            let kept = cond.is_some_and(|c| c.contains("!cancelled()") && !c.contains("always()"));
            let read = cond.map_or("no `if:`".to_owned(), |c| format!("`if: {c}`"));
            (!kept).then(|| format!("nightly.yml {name}: runs after the shards with {read}, not `!cancelled()`, so a failed shard does not sequence it or a cancelled run starts it"))
        })
        .collect()
}

/// Every integer after `prefix` in a job's code, the token up to a space, `;`, `)`, `|`, `&`;
/// `None` when one is no plain integer (`sleep 2m`, `seq 1 "$P"`): the figure is unreadable.
pub fn numbers_after(code: &[String], prefix: &str) -> Option<Vec<u32>> {
    let mut out = Vec::new();
    for line in code {
        for (at, _) in line.match_indices(prefix) {
            let rest = &line[at + prefix.len()..];
            let token = rest
                .split(|c: char| c.is_whitespace() || ";)|&".contains(c))
                .next()
                .unwrap_or("");
            out.push(token.parse().ok()?);
        }
    }
    Some(out)
}

/// The figures of a wait, one reading for rules 3 and 5: the job's `timeout-minutes`; the
/// budget's minutes, from the one assignment `budget="$((N * 60 - SECONDS))"` (every other
/// assignment of `budget` the floor `budget=1`, which only lowers it); the largest poll count
/// (`seq 1 P`) and the largest interval (`sleep I`, plain seconds), so an earlier decoy is no
/// reading. A figure absent or in any other form is `None`.
pub struct Figures {
    pub timeout: Option<u32>,
    pub budget: Option<u32>,
    pub polls: Option<u32>,
    pub interval: Option<u32>,
}

pub fn figures(lines: &[&str]) -> Figures {
    let code = code(lines);
    let mut minutes: Vec<Option<u32>> = Vec::new();
    for line in &code {
        for value in commands(line)
            .iter()
            .filter_map(|c| c.strip_prefix("budget="))
        {
            let n = value
                .strip_prefix("\"$((")
                .and_then(|v| v.strip_suffix(" * 60 - SECONDS))\""))
                .and_then(|n| n.parse().ok());
            if value != "1" {
                minutes.push(n);
            }
        }
    }
    let max = |prefix: &str| numbers_after(&code, prefix).and_then(|n| n.into_iter().max());
    Figures {
        timeout: field(lines, "timeout-minutes").and_then(|t| t.parse().ok()),
        budget: match minutes.as_slice() {
            [Some(n)] => Some(*n),
            _ => None,
        },
        polls: max("seq 1 "),
        interval: max("sleep "),
    }
}

/// A job's waits: its lines with `gh run watch`.
pub fn watches(lines: &[&str]) -> Vec<String> {
    code(lines)
        .into_iter()
        .filter(|line| line.contains("gh run watch"))
        .collect()
}

/// Rule 3: every wait gives up at or under its job's `timeout-minutes` minus five.
pub fn give_up_errors(workflows: &[(String, String)]) -> Vec<String> {
    let mut errors = Vec::new();
    for (file, text) in workflows {
        for (job, lines) in block(text, "jobs") {
            if watches(&lines).is_empty() {
                continue;
            }
            let Figures {
                timeout,
                budget,
                polls,
                interval,
            } = figures(&lines);
            match (timeout, budget, polls, interval) {
                (Some(t), Some(b), Some(p), Some(i)) => {
                    let poll = (p * i).div_ceil(60);
                    let worst = b.max(poll);
                    if worst + 5 > t {
                        errors.push(format!("{file} {job}: the wait can run {worst} minutes (the larger of the budget's {b} and the poll's {p} × {i} s, {poll}), past the job's timeout-minutes {t} minus five"));
                    }
                }
                _ => errors.push(format!("{file} {job}: a wait without a timeout-minutes, a budget, a poll count or an interval (read {timeout:?}, {budget:?}, {polls:?}, {interval:?})")),
            }
        }
    }
    errors
}

/// The workflows a job's `gh run` lines list (`--workflow X`, `--workflow=X`, `-w X`), each
/// read through the job's assignment when it is a variable.
pub fn listed(lines: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for line in code(lines).iter().filter(|line| line.contains("gh run ")) {
        let mut tokens = line.split_whitespace();
        while let Some(token) = tokens.next() {
            let name = match token.strip_prefix("--workflow=") {
                Some(name) => Some(name),
                None if token == "--workflow" || token == "-w" => tokens.next(),
                None => None,
            };
            if let Some(name) = name {
                out.push(resolved(lines, name.trim_matches('"').to_owned()));
            }
        }
    }
    out
}

/// Rule 4: the set of workflows a waiting job dispatches is the set its list names, both
/// directions, every name read (a variable the job does not assign once is refused).
pub fn wait_workflow_errors(workflows: &[(String, String)]) -> Vec<String> {
    let mut errors = Vec::new();
    for (file, text) in workflows {
        for (job, lines) in block(text, "jobs") {
            if watches(&lines).is_empty() {
                continue;
            }
            let (mut started, mut listed) = (dispatches(&lines), listed(&lines));
            let unread: Vec<&String> = started
                .iter()
                .chain(&listed)
                .filter(|w| w.starts_with('$'))
                .collect();
            if !unread.is_empty() {
                errors.push(format!("{file} {job}: the wait's workflows {unread:?} are variables the job does not assign one literal, so the run watched cannot be read"));
                continue;
            }
            for set in [&mut started, &mut listed] {
                set.sort();
                set.dedup();
            }
            if listed.is_empty() || started != listed {
                errors.push(format!("{file} {job}: the wait lists `--workflow` {listed:?} after starting {started:?}, so a run it started goes unwatched or it watches another workflow's run"));
            }
        }
    }
    errors
}

/// Rule 5: every job of the nightly that dispatches a workflow and has a job after it (by
/// `needs:`, directly or through another) carries a `gh run watch` per dispatch (a reusable
/// call, a job-level `uses:` and not a step's, is its own wait: the caller ends with the
/// called run).
pub fn watch_errors(nightly: &str) -> Vec<String> {
    let jobs = block(nightly, "jobs");
    let graph = graph(&jobs);
    let mut errors = Vec::new();
    for (name, lines) in &jobs {
        let calls = field(lines, "uses").is_some();
        let started = dispatches(lines);
        let later: Vec<&str> = jobs
            .iter()
            .map(|(n, _)| n.as_str())
            .filter(|n| after(&graph, n, name))
            .collect();
        let watched = watches(lines).len();
        if !calls && !later.is_empty() && watched < started.len() {
            errors.push(format!("nightly.yml {name}: starts {started:?} with {watched} `gh run watch` for its {} dispatches, so {} after it can start beside a run it did not wait for", started.len(), later.join(", ")));
        }
    }
    errors
}

/// Rule 6: every watch runs under `timeout "$budget"` (`timeout "${budget}"` and
/// `timeout $budget` read the same), the bound the step's exit 124 arm reads as the give-up,
/// and `budget` is the one assignment rule 3 reads, so the give-up rule 3 judges is the
/// watch's bound; a `timeout` with options, a literal or another variable is refused.
pub fn watch_bound_errors(workflows: &[(String, String)]) -> Vec<String> {
    let bounds = [
        "timeout \"$budget\"",
        "timeout \"${budget}\"",
        "timeout $budget",
    ];
    let mut errors = Vec::new();
    for (file, text) in workflows {
        for (job, lines) in block(text, "jobs") {
            for watch in watches(&lines) {
                let (before, _) = watch.split_once("gh run watch").unwrap_or_default();
                let before = commands(before).last().copied().unwrap_or("");
                if !bounds.contains(&before) {
                    errors.push(format!("{file} {job}: the watch runs under `{before}`, not `timeout \"$budget\"`, so the give-up rule 3 reads bounds nothing"));
                }
            }
            if !watches(&lines).is_empty() && figures(&lines).budget.is_none() {
                errors.push(format!("{file} {job}: no one `budget=\"$((N * 60 - SECONDS))\"` (the floor `budget=1` aside), so the watch's bound is not the give-up rule 3 reads"));
            }
        }
    }
    errors
}

/// The workflows with `edit` applied to `file`'s text.
pub fn with(file: &str, edit: impl Fn(&str) -> String) -> Vec<(String, String)> {
    workflows()
        .into_iter()
        .map(|(name, text)| {
            let text = if name == file { edit(&text) } else { text };
            (name, text)
        })
        .collect()
}

/// `text` with `from` replaced by `to` inside the job `job` alone (its key to the next key at
/// two spaces or at none).
pub fn in_job(text: &str, job: &str, from: &str, to: &str) -> String {
    let at = text.find(&format!("\n  {job}:\n")).expect("the job") + 1;
    let body = at + job.len() + 4;
    let end = text[body..]
        .match_indices('\n')
        .map(|(i, _)| body + i + 1)
        .find(|&i| {
            let rest = &text[i..];
            !rest.starts_with("   ") && !rest.starts_with('\n') && !rest.starts_with("  #")
        })
        .unwrap_or(text.len());
    let edited = text[at..end].replacen(from, to, 1);
    assert_ne!(edited, text[at..end], "{from} not in {job}");
    format!("{}{edited}{}", &text[..at], &text[end..])
}
