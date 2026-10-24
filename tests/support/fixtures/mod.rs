mod binary;
mod cases;
mod http;
mod wallet;
mod wallet_json;
mod wire;

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const BRC_PIN: &str = "ed1b015bac53106ff34e5d1831acda378cbe5c04";

// Count entries, not bytes or assertions. A new/dropped case changes this census.
pub const COUNTS: [(&str, usize, usize); 5] = [
    ("wire", 29, 323),
    ("http_json", 29, 72),
    ("beef", 4, 8),
    ("merkle_path", 1, 5),
    ("transaction", 2, 505),
];

#[derive(Default)]
pub struct Suite(BTreeMap<String, Value>);

impl Suite {
    pub fn add(&mut self, path: &str, references: &[(&str, &str)], cases: Vec<Value>) {
        let citations: Vec<_> = references
            .iter()
            .map(|(document, section)| {
                json!({
                "repository": "bsv-blockchain/BRCs", "commit": BRC_PIN,
                        "document": document, "section": section,
                    })
            })
            .collect();
        let fixture = json!({"schema_version": 1, "references": citations, "cases": cases});
        assert!(
            self.0.insert(path.into(), fixture).is_none(),
            "duplicate {path}"
        );
    }

    fn finish(self) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let record = std::env::var("BSV_FIXTURES_RECORD").as_deref() == Ok("1");
        for (surface, file_count, entry_count) in COUNTS {
            let files: Vec<_> = self
                .0
                .iter()
                .filter(|(p, _)| p.starts_with(&format!("{surface}/")))
                .collect();
            let entries: usize = files
                .iter()
                .map(|(_, v)| v["cases"].as_array().unwrap().len())
                .sum();
            assert_eq!(files.len(), file_count, "{surface}: file census");
            assert_eq!(
                entries, entry_count,
                "{surface}: entry census (change COUNTS deliberately)"
            );
            println!("{surface}: {file_count} files, {entry_count} entries");
        }
        for (name, actual) in &self.0 {
            let path = root.join(name);
            if record {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(
                    &path,
                    format!("{}\n", serde_json::to_string_pretty(actual).unwrap()),
                )
                .unwrap();
            } else {
                let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                    panic!("{name}: {e}; record deliberately with BSV_FIXTURES_RECORD=1")
                });
                let expected: Value = serde_json::from_str(&text).unwrap();
                if let Some(diff) = difference("", &expected, actual) {
                    panic!("fixture {name}: {diff}");
                }
            }
        }
        let mut found = BTreeSet::new();
        inventory(&root, &root, &mut found);
        let expected: BTreeSet<_> = self.0.keys().cloned().collect();
        assert_eq!(found, expected, "fixture file inventory changed");
        println!(
            "{} {} files",
            if record { "recorded" } else { "replayed" },
            found.len()
        );
    }
}

fn inventory(root: &Path, dir: &Path, found: &mut BTreeSet<String>) {
    for item in std::fs::read_dir(dir).unwrap() {
        let path: PathBuf = item.unwrap().path();
        if path.is_dir() {
            inventory(root, &path, found);
        } else {
            assert_eq!(
                path.extension().and_then(|s| s.to_str()),
                Some("json"),
                "unexpected fixture {path:?}"
            );
            found.insert(
                path.strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/"),
            );
        }
    }
}

fn difference(field: &str, expected: &Value, actual: &Value) -> Option<String> {
    if expected == actual {
        return None;
    }
    match (expected, actual) {
        (Value::Object(a), Value::Object(b)) => {
            for key in a.keys().chain(b.keys()).collect::<BTreeSet<_>>() {
                if let Some(diff) = difference(
                    &format!("{field}/{key}"),
                    a.get(key).unwrap_or(&Value::Null),
                    b.get(key).unwrap_or(&Value::Null),
                ) {
                    return Some(diff);
                }
                if a.contains_key(key) != b.contains_key(key) {
                    return Some(format!("{field}/{key}: field presence differs"));
                }
            }
        }
        (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
            for (i, (a, b)) in a.iter().zip(b).enumerate() {
                let name = a
                    .get("name")
                    .and_then(Value::as_str)
                    .map(|s| format!("[{s}]"))
                    .unwrap_or_default();
                if let Some(diff) = difference(&format!("{field}/{i}{name}"), a, b) {
                    return Some(diff);
                }
            }
        }
        (Value::String(a), Value::String(b)) => {
            let offset = a
                .bytes()
                .zip(b.bytes())
                .position(|(a, b)| a != b)
                .unwrap_or(a.len().min(b.len()));
            return Some(format!(
                "{field}: string byte {offset}: expected {a:?}, actual {b:?}"
            ));
        }
        _ => {}
    }
    Some(format!("{field}: expected {expected}, actual {actual}"))
}

pub async fn run() {
    let mut suite = Suite::default();
    wire::record(&mut suite).await;
    http::record(&mut suite).await;
    binary::record(&mut suite);
    suite.finish();
}
