//! Every BEEF this tree's vectors hold, for #817's sweeps: the hex BEEFs of
//! the JSON files under `tests/fixtures`, `tests/vectors` and
//! `tests/transaction/vectors`, and the `beef_of_any_size` binaries, by the
//! reading of `beef_two_readers_agree.rs`, deduplicated by bytes.

use std::path::{Path, PathBuf};

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            files(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// A string of hex that opens as a BEEF does.
fn beef_hex(s: &str) -> Option<Vec<u8>> {
    let lower = s.to_ascii_lowercase();
    let opens = ["0100beef", "0200beef", "01010101"]
        .iter()
        .any(|p| lower.starts_with(p));
    if opens && lower.len().is_multiple_of(2) {
        bsv_rs::primitives::from_hex(&lower).ok()
    } else {
        None
    }
}

fn hex_in_json(value: &serde_json::Value, out: &mut Vec<Vec<u8>>) {
    match value {
        serde_json::Value::String(s) => out.extend(beef_hex(s)),
        serde_json::Value::Array(items) => items.iter().for_each(|v| hex_in_json(v, out)),
        serde_json::Value::Object(map) => map.values().for_each(|v| hex_in_json(v, out)),
        _ => {}
    }
}

/// Each seed's name (the file, and the string's index in it) and bytes.
pub fn seeds() -> Vec<(String, Vec<u8>)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    for dir in [
        "tests/fixtures",
        "tests/vectors",
        "tests/transaction/vectors",
    ] {
        let mut paths = Vec::new();
        files(&root.join(dir), &mut paths);
        for path in paths {
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let Some(value) = std::fs::read_to_string(&path)
                .ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            else {
                continue;
            };
            let mut found = Vec::new();
            hex_in_json(&value, &mut found);
            let name = path.display().to_string().replace('\\', "/");
            for (i, bytes) in found.into_iter().enumerate() {
                seeds.push((format!("{name}#{i}"), bytes));
            }
        }
    }
    let mut paths = Vec::new();
    files(&root.join("tests/vectors/beef_of_any_size"), &mut paths);
    for path in paths {
        if path.extension().is_some_and(|e| e == "bin") {
            if let Ok(bytes) = std::fs::read(&path) {
                seeds.push((path.display().to_string().replace('\\', "/"), bytes));
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    seeds.retain(|(_, bytes)| seen.insert(bytes.clone()));
    seeds
}
