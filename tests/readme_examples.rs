//! The README's code blocks ARE the `examples/` files, byte for byte.
//!
//! Every ```rust block in `README.md` that opens with a `// examples/<name>.rs`
//! line must equal the body of that file (its module doc comment stripped),
//! and every example file must appear in the README. The examples are
//! compiled by `cargo build --examples --all-features` (CI), so a README
//! snippet can never drift from something that builds. Edit the example file,
//! then paste it into the README under its marker line; this test names the
//! first divergent line.

use std::fs;
use std::path::Path;

fn readme_blocks(readme: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut lines = readme.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim_start() != "```rust" {
            continue;
        }
        let Some(first) = lines.peek() else { break };
        let Some(name) = first
            .trim()
            .strip_prefix("// examples/")
            .and_then(|s| s.strip_suffix(".rs"))
        else {
            continue;
        };
        let name = name.to_string();
        lines.next();
        let mut body = String::new();
        for l in lines.by_ref() {
            if l.trim_start() == "```" {
                break;
            }
            body.push_str(l);
            body.push('\n');
        }
        out.push((name, body));
    }
    out
}

/// An example file without its leading `//!` doc block and the blank line after it.
fn example_body(path: &Path) -> String {
    let src = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut lines = src.lines().peekable();
    while matches!(lines.peek(), Some(l) if l.starts_with("//!")) {
        lines.next();
    }
    while matches!(lines.peek(), Some(l) if l.trim().is_empty()) {
        lines.next();
    }
    let mut body: String = lines.map(|l| format!("{l}\n")).collect();
    while body.ends_with("\n\n") {
        body.pop();
    }
    body
}

#[test]
fn every_readme_snippet_is_an_example_file_and_every_example_is_in_the_readme() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    let blocks = readme_blocks(&readme);
    assert!(
        !blocks.is_empty(),
        "the README carries no `// examples/<name>.rs` blocks"
    );

    let mut example_files: Vec<String> = fs::read_dir(root.join("examples"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".rs"))
        .map(|n| n.trim_end_matches(".rs").to_string())
        .collect();
    example_files.sort();

    let mut seen = Vec::new();
    for (name, body) in &blocks {
        let path = root.join("examples").join(format!("{name}.rs"));
        assert!(
            path.exists(),
            "README block `{name}` names no examples/{name}.rs"
        );
        let expected = example_body(&path);
        if body != &expected {
            let (mut i, mut got, mut want) = (0usize, "", "");
            for (k, (a, b)) in body.lines().zip(expected.lines()).enumerate() {
                if a != b {
                    i = k + 1;
                    got = a;
                    want = b;
                    break;
                }
            }
            panic!(
                "README block `{name}` diverges from examples/{name}.rs at line {i}:\n  README:  {got}\n  example: {want}\n(edit the example, then paste it into the README under `// examples/{name}.rs`)"
            );
        }
        seen.push(name.clone());
    }
    seen.sort();
    seen.dedup();
    assert_eq!(
        seen, example_files,
        "every example file must be in the README exactly once"
    );
}
