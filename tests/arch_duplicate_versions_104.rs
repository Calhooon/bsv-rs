//! The duplicate dependency versions are a counted list, and CI refuses one outside it (#104).
//!
//! `cargo deny` warns on a crate the graph holds in two versions and passes (`deny.toml`,
//! `multiple-versions = "warn"`, nothing skipped), so until #104's gate a change of the manifest
//! or a release under it could add one with every check green. The `deny` step of ci.yml's
//! `lint` job now runs `.github/scripts/duplicate_versions.py`, which reads each graph the
//! crate ships from the resolved lockfile and refuses a duplicate that
//! `docs/duplicate-versions.txt` does not hold (and a row whose pair moved or ended).
//!
//! This guard reads four files and nothing else (no cargo, no network, no environment), at
//! the string level, and names what it misses:
//!
//! - the list: every row four cells with a reason, one row a crate in name order (no space in
//!   a name), the graphs known and in order, the lines two or more, distinct and in order
//!   (the script's rule, written out below), and the totals pinned here (`ROWS`, `TOTALS`,
//!   `LINES`), so a row added, dropped, widened to another graph or widened by a line is a
//!   change of this file in the same diff;
//! - ci.yml: the `deny` step runs the script's tests and the script, each failing the step;
//! - `deny.toml`: duplicates still warn there and nothing is skipped, so the list is the one
//!   record of them;
//! - the script: it reads the list at this path and the wasm32 slice the `deny` step checks.
//!
//! The script's rule for a row's `lines` cell (`parse_rows`, `line_of`, `line_key`), which
//! `list_errors` mirrors: the cell is split on `,` and each text trimmed; a text is a line
//! when `line_of(text) == text`, and `line_of` cuts a version at its leftmost `-`, then at its
//! leftmost `+`, and keeps the parts up to the leftmost one that is not `0`. So the script
//! refuses, and `is_line` and `list_errors` refuse with it:
//!
//! - fewer than two lines (`0.10`, an empty cell);
//! - an empty line (`0.10, `, `0.10, , 0.11`);
//! - a line carrying `-`, a pre-release (`0.11-rc`, `0.11-`);
//! - a line carrying `+`, build metadata (`0.11+x`, `0.11+`);
//! - a line with a part after its leftmost part that is not `0`, a full version among them
//!   (`0.10.4`, `1.2`, `0..11`, `.11`);
//! - a line repeated (`0.10, 0.10`);
//! - lines out of `line_key`'s order, numeric by part (`0.11, 0.10`; `0.10, 0.9`).
//!
//! `REFUSED_LINES` plants each spelling and `READ_LINES` the spellings read; the script's
//! tests read both tables from this file and hold `parse_rows` to them
//! (`test_every_spelling_the_arch_test_refuses_is_refused_here`, `..._reads_is_read_here`),
//! so the two readers agree on the tables by a run on each side. Beyond the tables the
//! agreement is by reading, on a list of ASCII text whose line parts are numbers as cargo
//! writes them (no leading zero, within `u64`). Outside that the two can part and no test
//! holds them: two spellings of one number (`01, 1`: refused here, the script's answer its
//! set's order), a number past `u64` (text here, a number there), a digit outside ASCII, and
//! white space or line ends that Python's `strip` and `splitlines` take and Rust's `trim`
//! and `lines` do not.
//!
//! The bound: the pinned totals say the list did not grow unseen; whether the graphs hold
//! what the list says is the script's run in CI, on the lockfile that run resolves (the crate
//! commits none), never this file's.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

const LIST: &str = "docs/duplicate-versions.txt";
const SCRIPT: &str = ".github/scripts/duplicate_versions.py";
const CI: &str = ".github/workflows/ci.yml";

/// The rows of the list: one a crate held in more than one version in some graph.
const ROWS: usize = 11;

/// The rows naming each graph, in the list's order of graphs: `cargo deny`'s duplicate
/// warnings on the same lockfile for `all`, `wasm32` and `default` (11, 3 and 5 on
/// 2026-11-14), `native` (`full,http,websocket`) the same eleven as `all`.
const TOTALS: [(&str, usize); 4] = [("all", 11), ("native", 11), ("wasm32", 3), ("default", 5)];

/// The lines the rows hold, summed over the rows (eleven pairs on 2026-11-14): a row that
/// admits a third line moves this, so it cannot be widened in the list alone.
const LINES: usize = 22;

const RUN_TESTS: &str =
    "          python3 -B -m unittest discover -s .github/scripts -p 'test_duplicate_versions.py' || result=1\n";
const RUN_SCRIPT: &str = "          python3 -B .github/scripts/duplicate_versions.py || result=1\n";
const WASM32_DENY: &str = "          cargo-deny --locked --no-default-features --features \"auth,wallet,transaction,overlay,socketio,wasm\" --target wasm32-unknown-unknown check bans licenses sources || result=1\n";

/// A line's order, the script's `line_key`: numeric by part, a part that is no number after
/// every number.
fn line_key(line: &str) -> Vec<(bool, u64, &str)> {
    line.split('.')
        .map(|part| match part.parse::<u64>() {
            Ok(number) if part.bytes().all(|b| b.is_ascii_digit()) => (false, number, ""),
            _ => (true, 0, part),
        })
        .collect()
}

/// Whether a text is a semver-compatible line, the script's `v and line_of(v) == v`: no `-`
/// and no `+` (`line_of` cuts a version at either, so a text holding one is never its own
/// line), then zero parts, the leftmost part that is not `0` and nothing after it (`3`,
/// `0.22`, `0.0.4`), or all zeros.
fn is_line(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    !text.is_empty()
        && !text.contains(['-', '+'])
        && parts[..parts.len() - 1].iter().all(|part| *part == "0")
}

/// Every spelling of a row's `lines` cell the script refuses (the header's list), each one
/// fault: where a line carries `-` or `+` the lines are otherwise two, distinct and in order.
/// The script's tests read this table from this file and refuse each text too.
const REFUSED_LINES: [&str; 21] = [
    // fewer than two lines
    "0.10",
    "",
    // an empty line
    "0.10, ",
    ", 0.10",
    "0.10, , 0.11",
    // a pre-release
    "0.10, 0.11-rc",
    "0.10-rc, 0.11",
    "0.10, 0.11-",
    "0.10, 0.11-rc.1",
    // build metadata
    "0.10, 0.11+x",
    "0.10+x, 0.11",
    "0.10, 0.11+",
    "0.10, 0.11-rc+x",
    // a part after the leftmost part that is not `0`
    "0.10.4, 0.11",
    "0.10, 0.11.0",
    "1.2, 2",
    "0.10, 0..11",
    "0.10, .11",
    // repeated, and out of order
    "0.10, 0.10",
    "0.11, 0.10",
    "0.10, 0.9",
];

/// Spellings the script reads as two or more distinct lines in order, read here too.
const READ_LINES: [&str; 7] = [
    "0.10, 0.11",
    "0.9, 0.10",
    "2, 3",
    "2, 10",
    "0.0.4, 0.0.5",
    "0.0.0, 0.0.4, 0.4, 4",
    "0.10,0.11",
];

/// What is wrong with the list's text: its form, then its totals against the pins.
fn list_errors(text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let mut counts = [0usize; 4];
    let mut rows = 0usize;
    let mut held_lines = 0usize;
    let mut last = String::new();
    for (at, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let number = at + 1;
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let [graphs, name, lines, reason] = cells[..] else {
            errors.push(format!(
                "{LIST}:{number}: {} cells, not `graphs | crate | lines | reason`",
                cells.len()
            ));
            continue;
        };
        rows += 1;
        let named: Vec<&str> = graphs.split(',').map(str::trim).collect();
        let ordered: Vec<&str> = TOTALS
            .iter()
            .map(|(graph, _)| *graph)
            .filter(|graph| named.contains(graph))
            .collect();
        if named != ordered {
            errors.push(format!(
                "{LIST}:{number}: {name}: `{graphs}` is not graphs of all, native, wasm32, default, each once in that order"
            ));
        }
        for (slot, (graph, _)) in TOTALS.iter().enumerate() {
            if named.contains(graph) {
                counts[slot] += 1;
            }
        }
        let held: Vec<&str> = lines.split(',').map(str::trim).collect();
        held_lines += held.len();
        if held.len() < 2
            || !held.iter().all(|line| is_line(line))
            || held
                .windows(2)
                .any(|pair| line_key(pair[0]) >= line_key(pair[1]))
        {
            errors.push(format!(
                "{LIST}:{number}: {name}: `{lines}` is not two or more distinct lines in order"
            ));
        }
        if reason.is_empty() {
            errors.push(format!("{LIST}:{number}: {name}: no reason"));
        }
        if name.contains(' ') {
            errors.push(format!("{LIST}:{number}: `{name}` is no crate name"));
        }
        if name.is_empty() || name <= last.as_str() {
            errors.push(format!(
                "{LIST}:{number}: `{name}` is not after `{last}` (one row a crate, by name)"
            ));
        }
        last = name.to_owned();
    }
    if rows != ROWS {
        errors.push(format!(
            "{LIST}: {rows} rows, pinned {ROWS}: a duplicate version added or ended is a finding; read it, then move ROWS in the same diff"
        ));
    }
    for (slot, (graph, pinned)) in TOTALS.iter().enumerate() {
        if counts[slot] != *pinned {
            errors.push(format!(
                "{LIST}: {} rows name `{graph}`, pinned {pinned}: read the change, then move TOTALS in the same diff",
                counts[slot]
            ));
        }
    }
    if held_lines != LINES {
        errors.push(format!(
            "{LIST}: {held_lines} lines over the rows, pinned {LINES}: a row widened or narrowed by a line is a finding; read it, then move LINES in the same diff"
        ));
    }
    errors
}

/// The `deny` step of ci.yml: from its `- name: deny` line to the next step.
fn deny_step(ci: &str) -> Option<&str> {
    let open = ci.find("      - name: deny\n        id: deny\n")?;
    let rest = &ci[open..];
    let end = rest[1..].find("\n      - ").map_or(rest.len(), |at| at + 2);
    Some(&rest[..end])
}

/// What the `deny` step no longer holds of the duplicate check.
fn ci_errors(ci: &str) -> Vec<String> {
    let Some(step) = deny_step(ci) else {
        return vec![format!("{CI}: no `deny` step with the id `deny`")];
    };
    let mut errors = Vec::new();
    for (line, what) in [
        (RUN_TESTS, "the duplicate check's own tests"),
        (RUN_SCRIPT, "the duplicate check"),
        (
            WASM32_DENY,
            "cargo-deny on the wasm32 slice the check reads",
        ),
    ] {
        if step.matches(line).count() != 1 {
            errors.push(format!(
                "{CI}: the `deny` step does not run {what} once, failing the step: `{}`",
                line.trim()
            ));
        }
    }
    let ends = step.trim_end().ends_with("          exit \"$result\"");
    let set = step.contains("          result=0\n");
    let reset = step
        .rfind(RUN_SCRIPT)
        .is_some_and(|last| step[last..].contains("result=0"));
    if !ends || !set || reset {
        errors.push(format!(
            "{CI}: the `deny` step does not end with `exit \"$result\"` over one `result=0` set before the checks"
        ));
    }
    if step.contains("continue-on-error") {
        errors.push(format!("{CI}: the `deny` step carries `continue-on-error`"));
    }
    errors
}

/// What `deny.toml` no longer says of duplicates: a warning, and nothing skipped.
fn deny_toml_errors(text: &str) -> Vec<String> {
    let settings: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .collect();
    let mut errors = Vec::new();
    let levels: Vec<&&str> = settings
        .iter()
        .filter(|l| l.starts_with("multiple-versions ") || l.starts_with("multiple-versions="))
        .collect();
    if levels != [&"multiple-versions = \"warn\""] {
        errors.push(
            "deny.toml: `multiple-versions = \"warn\"` is not its one setting: the refusal is the list's check, and cargo-deny still names every duplicate".to_owned(),
        );
    }
    for line in &settings {
        if line.starts_with("skip") {
            errors.push(format!(
                "deny.toml: `{line}`: a duplicate is recorded in {LIST} with its reason, never skipped here"
            ));
        }
    }
    errors
}

/// What the script no longer reads: the list at its path and the deny step's wasm32 slice.
fn script_errors(script: &str) -> Vec<String> {
    let mut errors = Vec::new();
    for needle in [
        "LIST = \"docs/duplicate-versions.txt\"\n",
        "WASM32_SLICE = \"auth,wallet,transaction,overlay,socketio,wasm\"\n",
        "    \"all\": [\"--all-features\", \"--target\", \"all\"],\n",
        "    \"native\": [\"--features\", \"full,http,websocket\", \"--target\", \"all\"],\n",
        "    \"default\": [\"--target\", \"all\"],\n",
        "\"cargo\", \"tree\", \"--locked\"",
        "\"-e\", \"normal,build,dev\"",
    ] {
        if !script.contains(needle) {
            errors.push(format!("{SCRIPT}: no `{}`", needle.trim()));
        }
    }
    errors
}

fn assert_none(errors: &[String]) {
    assert!(
        errors.is_empty(),
        "{} refusals:\n{}",
        errors.len(),
        errors.join("\n")
    );
}

#[test]
fn the_duplicate_versions_list_holds_its_pinned_totals_104() {
    assert_none(&list_errors(&arch_support::read(LIST)));
}

#[test]
fn a_duplicate_row_added_dropped_or_widened_without_its_total_is_refused_104() {
    let list = arch_support::read(LIST);

    let added = format!("{list}all, native | zzz-new | 1, 2 | a reason\n");
    assert_eq!(
        list_errors(&added),
        [
            format!("{LIST}: 12 rows, pinned 11: a duplicate version added or ended is a finding; read it, then move ROWS in the same diff"),
            format!("{LIST}: 12 rows name `all`, pinned 11: read the change, then move TOTALS in the same diff"),
            format!("{LIST}: 12 rows name `native`, pinned 11: read the change, then move TOTALS in the same diff"),
            format!("{LIST}: 24 lines over the rows, pinned 22: a row widened or narrowed by a line is a finding; read it, then move LINES in the same diff"),
        ]
    );

    let row = "all, native | sha1 | 0.10, 0.11 | ";
    assert_eq!(list.matches(row).count(), 1, "the sha1 row");
    let at = list.find(row).expect("sha1");
    let end = at + list[at..].find('\n').expect("the row's end") + 1;
    let dropped = format!("{}{}", &list[..at], &list[end..]);
    let errors = list_errors(&dropped);
    assert_eq!(errors.len(), 4, "{errors:?}");
    assert!(errors[0].contains("10 rows, pinned 11"), "{errors:?}");
    assert!(
        errors[3].contains("20 lines over the rows, pinned 22"),
        "{errors:?}"
    );

    let widened = list.replace(row, "all, native, wasm32 | sha1 | 0.10, 0.11 | ");
    assert_eq!(
        list_errors(&widened),
        [format!(
            "{LIST}: 4 rows name `wasm32`, pinned 3: read the change, then move TOTALS in the same diff"
        )]
    );

    // widened by a line: no row and no graph total moves, the lines' total does
    let syn = "all, native, wasm32, default | syn | 2, 3 | ";
    assert_eq!(list.matches(syn).count(), 1, "the syn row");
    let by_a_line = list.replace(syn, "all, native, wasm32, default | syn | 1, 2, 3 | ");
    assert_eq!(
        list_errors(&by_a_line),
        [format!(
            "{LIST}: 23 lines over the rows, pinned 22: a row widened or narrowed by a line is a finding; read it, then move LINES in the same diff"
        )]
    );
}

#[test]
fn a_duplicate_row_without_a_reason_or_out_of_form_is_refused_104() {
    let list = arch_support::read(LIST);
    let row = "all, native | sha1 | 0.10, 0.11 | ";
    let at = list.find(row).expect("sha1");
    let end = at + list[at..].find('\n').expect("the row's end");
    let with = |new: &str| format!("{}{new}{}", &list[..at], &list[end..]);
    let one = |text: String, needle: &str| {
        let errors = list_errors(&text);
        assert!(
            errors.iter().any(|e| e.contains(needle)),
            "no `{needle}` in {errors:?}"
        );
    };
    one(with("all, native | sha1 | 0.10, 0.11 |"), "sha1: no reason");
    one(with("all, native | sha1 | 0.10, 0.11"), "3 cells, not");
    one(
        with("native, all | sha1 | 0.10, 0.11 | r"),
        "each once in that order",
    );
    one(
        with("all, all, native | sha1 | 0.10, 0.11 | r"),
        "each once in that order",
    );
    one(
        with("all, linux | sha1 | 0.10, 0.11 | r"),
        "each once in that order",
    );
    let form = "is not two or more distinct lines in order";
    for lines in REFUSED_LINES {
        one(with(&format!("all, native | sha1 | {lines} | r")), form);
    }
    for lines in READ_LINES {
        let errors = list_errors(&with(&format!("all, native | sha1 | {lines} | r")));
        assert!(
            !errors.iter().any(|e| e.contains(form)),
            "`{lines}` is refused: {errors:?}"
        );
    }
    one(
        with("all, native | sha 1 | 0.10, 0.11 | r"),
        "`sha 1` is no crate name",
    );
    one(
        with("all, native | rand_core | 0.10, 0.11 | r"),
        "`rand_core` is not after `rand_core`",
    );
    one(
        with("all, native | aaa | 0.10, 0.11 | r"),
        "`aaa` is not after `rand_core`",
    );
}

#[test]
fn the_deny_step_runs_the_duplicate_check_and_its_tests_104() {
    let ci = arch_support::read(CI);
    assert_none(&ci_errors(&ci));

    let one = |text: String, needle: &str| {
        let errors = ci_errors(&text);
        assert!(
            errors.iter().any(|e| e.contains(needle)),
            "no `{needle}` in {errors:?}"
        );
    };
    one(
        ci.replace(RUN_SCRIPT, ""),
        "does not run the duplicate check once",
    );
    one(
        ci.replace(
            RUN_SCRIPT,
            "          python3 -B .github/scripts/duplicate_versions.py || true\n",
        ),
        "does not run the duplicate check once",
    );
    one(
        ci.replace(
            RUN_SCRIPT,
            "          python3 -B .github/scripts/duplicate_versions.py\n",
        ),
        "does not run the duplicate check once",
    );
    one(ci.replace(RUN_TESTS, ""), "the duplicate check's own tests");
    one(
        ci.replace(RUN_SCRIPT, &format!("{RUN_SCRIPT}          result=0\n")),
        "does not end with `exit \"$result\"`",
    );
    one(
        ci.replace(
            &format!("{RUN_SCRIPT}          exit \"$result\"\n"),
            &format!("{RUN_SCRIPT}          exit 0\n"),
        ),
        "does not end with `exit \"$result\"`",
    );
    one(
        ci.replace("--features \"auth,wallet,transaction,overlay,socketio,wasm\" --target wasm32-unknown-unknown check bans", "--features \"auth,wasm\" --target wasm32-unknown-unknown check bans"),
        "cargo-deny on the wasm32 slice the check reads",
    );
    // moved out of the gate: the lines in another step leave the `deny` step without them
    let moved = ci.replace(RUN_SCRIPT, "").replace(RUN_TESTS, "").replace(
        "      - name: ratchet\n",
        &format!(
            "      - name: other\n        run: |\n{RUN_TESTS}{RUN_SCRIPT}\n      - name: ratchet\n"
        ),
    );
    assert_eq!(ci_errors(&moved).len(), 2, "{:?}", ci_errors(&moved));
    one(
        ci.replace("        id: deny\n", "        id: deny-gone\n"),
        "no `deny` step",
    );
}

#[test]
fn deny_toml_warns_on_duplicates_and_skips_none_104() {
    let deny = arch_support::read("deny.toml");
    assert_none(&deny_toml_errors(&deny));

    let level = "multiple-versions = \"warn\"\n";
    for (text, needle) in [
        (
            deny.replace(level, "multiple-versions = \"allow\"\n"),
            "is not its one setting",
        ),
        (deny.replace(level, ""), "is not its one setting"),
        (
            deny.replace(
                level,
                &format!("{level}skip = [{{ crate = \"syn@2\", reason = \"r\" }}]\n"),
            ),
            "never skipped here",
        ),
        (
            deny.replace(
                level,
                &format!("{level}skip-tree = [{{ crate = \"reqwest\" }}]\n"),
            ),
            "never skipped here",
        ),
    ] {
        let errors = deny_toml_errors(&text);
        assert!(
            errors.iter().any(|e| e.contains(needle)),
            "no `{needle}` in {errors:?}"
        );
    }
}

#[test]
fn the_duplicate_check_reads_the_list_and_the_graphs_the_deny_step_checks_104() {
    let script = arch_support::read(SCRIPT);
    assert_none(&script_errors(&script));
    let narrowed = script.replace("socketio,wasm\"\n", "wasm\"\n");
    assert_eq!(script_errors(&narrowed).len(), 1);
    let unlocked = script.replace("\"tree\", \"--locked\"", "\"tree\"");
    assert_eq!(script_errors(&unlocked).len(), 1);
}
