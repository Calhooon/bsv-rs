use crate::model::Metrics;
use crate::{tree, Result, TOOLCHAIN};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

fn command(root: &Path, source: &Path) -> Result<Command> {
    let target =
        std::env::var_os("CARGO_TARGET_DIR").ok_or("set CARGO_TARGET_DIR outside the checkout")?;
    // Separate the library cache from the tool's cache, also avoiding a Cargo
    // target-lock deadlock when the integration test invokes this command.
    let target = tree::outside_checkout(&Path::new(&target).join("ratchet-library"), root)?;
    let mut command = Command::new("cargo");
    command
        .arg(format!("+{TOOLCHAIN}"))
        .current_dir(source)
        .env("CARGO_TARGET_DIR", target)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_TERM_COLOR", "never")
        .env("RUSTFLAGS", "")
        .env("CARGO_ENCODED_RUSTFLAGS", "")
        .env_remove("RUSTDOCFLAGS")
        .env_remove("CARGO_ENCODED_RUSTDOCFLAGS")
        .env("RUSTC_WRAPPER", "")
        .env("RUSTC_WORKSPACE_WRAPPER", "")
        .env_remove("CARGO_BUILD_TARGET");
    Ok(command)
}

/// Only root-library diagnostics count; a unique primary site is one warning.
fn diagnostics(bytes: &[u8]) -> Result<BTreeSet<(String, String)>> {
    let mut found = BTreeSet::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let message: Value = serde_json::from_slice(line)?;
        if message["reason"] != "compiler-message"
            || message["target"]["name"] != "bsv_rs"
            || !message["target"]["kind"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|kind| kind == "lib"))
        {
            continue;
        }
        let diagnostic = &message["message"];
        if diagnostic["level"] != "warning" {
            continue;
        }
        let Some(code) = diagnostic["code"]["code"].as_str() else {
            continue;
        };
        let mut sites = Vec::new();
        if let Some(spans) = diagnostic["spans"].as_array() {
            for span in spans.iter().filter(|span| span["is_primary"] == true) {
                sites.push(format!(
                    "{}:{}:{}",
                    span["file_name"], span["line_start"], span["column_start"]
                ));
            }
        }
        sites.sort();
        found.insert((
            code.into(),
            format!("{}:{}", sites.join(";"), diagnostic["message"]),
        ));
    }
    Ok(found)
}

fn run(mut command: Command, label: &str) -> Result<BTreeSet<(String, String)>> {
    eprintln!("ratchet: {label}");
    let output = command.output()?;
    if !output.status.success() {
        // Do not print compiler excerpts, which can contain literal input data.
        return Err(format!(
            "{label} failed ({}); no measurement was recorded",
            output.status
        )
        .into());
    }
    diagnostics(&output.stdout)
}

pub fn measure(source: &Path, root: &Path, metrics: &mut Metrics) -> Result<()> {
    let config = source.join("ratchet-clippy");
    std::fs::create_dir(&config)?;
    let original = match std::fs::read_to_string(source.join("clippy.toml")) {
        Ok(config) => config,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };
    let original = original
        .lines()
        .filter(|line| {
            !line
                .trim_start()
                .starts_with("cognitive-complexity-threshold")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config_text = format!("cognitive-complexity-threshold = 25\n{original}\n");
    std::fs::write(config.join("clippy.toml"), config_text)?;

    let mut clippy = command(root, source)?;
    clippy
        .args([
            "clippy",
            "--locked",
            "--lib",
            "--all-features",
            "--message-format=json",
            "--",
            "--cap-lints",
            "allow",
            "--force-warn",
            "clippy::pedantic",
            "--force-warn",
            "clippy::cognitive_complexity",
        ])
        .env("CLIPPY_CONF_DIR", &config);
    let clippy = run(clippy, "cargo clippy (pedantic, cognitive complexity >25)")?;
    metrics.cognitive_complexity_over_25 = clippy
        .iter()
        .filter(|(code, _)| code == "clippy::cognitive_complexity")
        .count();
    metrics.pedantic_warnings = clippy
        .iter()
        .filter(|(code, _)| code.starts_with("clippy::") && code != "clippy::cognitive_complexity")
        .count();

    let mut doc = command(root, source)?;
    doc.args([
        "doc",
        "--locked",
        "--no-deps",
        "--lib",
        "--all-features",
        "--message-format=json",
    ])
    .env(
        "RUSTDOCFLAGS",
        "--cap-lints allow --force-warn missing_docs",
    );
    let doc = run(doc, "cargo doc (missing_docs)")?;
    metrics.missing_docs = doc
        .iter()
        .filter(|(code, _)| code == "missing_docs")
        .count();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn real_compiler_reports_all_requested_warning_groups_despite_allows() -> Result<()> {
        let fixture = crate::test_support::fixture()?;
        std::fs::write(
            fixture.path.join("Cargo.toml"),
            "[package]\nname = \"bsv-rs\"\nversion = \"0.0.0\"\nedition = \"2021\"\n[workspace]\n",
        )?;
        std::fs::write(
            fixture.path.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = \"bsv-rs\"\nversion = \"0.0.0\"\n",
        )?;
        let mut code = String::from("#![allow(missing_docs, clippy::pedantic, clippy::cognitive_complexity)]\npub fn branches(mut value: u32) -> u32 {\n");
        // Above 25 but below Clippy's default 30, to exercise our config too.
        for number in 0..26 {
            code.push_str(&format!("if value == {number} {{ value += 1; }}\n"));
        }
        code.push_str("value\n}\n");
        std::fs::write(fixture.path.join("src/lib.rs"), code)?;
        let mut metrics = Metrics::default();
        measure(&fixture.path, &std::env::current_dir()?, &mut metrics)?;
        assert!(metrics.cognitive_complexity_over_25 > 0);
        assert!(metrics.missing_docs >= 2);
        assert!(metrics.pedantic_warnings > 0);
        Ok(())
    }

    #[test]
    fn diagnostics_are_deduplicated_and_scoped_to_the_library() -> Result<()> {
        let diagnostic = json!({
            "reason": "compiler-message", "target": {"name": "bsv_rs", "kind": ["lib"]},
            "message": {"level": "warning", "code": {"code": "missing_docs"}, "message": "missing documentation",
                "spans": [{"is_primary": true, "file_name": "src/lib.rs", "line_start": 2, "column_start": 1}]}
        });
        let mut dependency = diagnostic.clone();
        dependency["target"]["name"] = json!("dependency");
        let mut binary = diagnostic.clone();
        binary["target"]["kind"] = json!(["bin"]);
        let bytes = format!("{diagnostic}\n{diagnostic}\n{dependency}\n{binary}\n");
        assert_eq!(diagnostics(bytes.as_bytes())?.len(), 1);
        assert!(diagnostics(b"not json\n").is_err());
        Ok(())
    }
}
