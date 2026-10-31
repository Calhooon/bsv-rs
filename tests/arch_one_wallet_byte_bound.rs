//! The wallet substrates' 256 MiB byte bound, the reference's
//! `MAX_WALLET_WIRE_FRAME_BYTES` read by `validateWalletResult`, has one
//! definition (bsv-rs#526): `MAX_BYTES` in `substrates/byte_fields.rs`, which
//! `result_values/boundary.rs` reads rather than defining a second. Read from
//! the source: every `.rs` file under `src/wallet`, every line that defines a
//! `const` as `256 * 1024 * 1024` or `268435456`. Since bsv-rs#532 the three
//! copies of `MAX_WALLET_WIRE_FRAME_BYTES` at other sites read `MAX_BYTES`, so
//! one other definition remains, enumerated: the reference's own request
//! bound, a different bound of the same value; a definition that moves in or
//! out of the list is a finding.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

use std::path::{Path, PathBuf};

/// The one definition of the substrates' byte bound.
const THE_BOUND: (&str, &str) = ("src/wallet/substrates/byte_fields.rs", "MAX_BYTES");

/// `(file, name)`: the value's other definition: the reference's
/// `MAX_WALLET_JSON_REQUEST_BYTES`, a bound of its own (#532).
const OTHER_CONSTANTS: &[(&str, &str)] = &[
    // `HTTPWalletJSON.ts:60`.
    (
        "src/wallet/substrates/http_json.rs",
        "MAX_WALLET_JSON_REQUEST_BYTES",
    ),
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read a source directory") {
        let path = entry.expect("read a directory entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `(file, name)` for every `const` line whose initializer is the bound.
fn definitions() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src/wallet"), &mut files);
    let mut found = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("read a source file");
        let relative = file
            .strip_prefix(root)
            .expect("a file under the crate")
            .to_string_lossy()
            .replace('\\', "/");
        for line in text.lines() {
            let line = line.trim();
            let Some(at) = line.find("const ") else {
                continue;
            };
            let Some((head, init)) = line[at + "const ".len()..].split_once('=') else {
                continue;
            };
            let init = init.trim().trim_end_matches(';').trim();
            if init == "256 * 1024 * 1024" || init == "268435456" {
                let name = head.split(':').next().unwrap_or("").trim();
                found.push((relative.clone(), name.to_string()));
            }
        }
    }
    found.sort();
    found
}

#[test]
fn the_wallet_substrates_byte_bound_is_defined_once() {
    let found = definitions();
    let bound: Vec<_> = found
        .iter()
        .filter(|(_, name)| name == THE_BOUND.1)
        .collect();
    assert_eq!(
        bound,
        [&(THE_BOUND.0.to_string(), THE_BOUND.1.to_string())],
        "the substrates' byte bound must have one definition (#526)"
    );
    let mut expected: Vec<(String, String)> = OTHER_CONSTANTS
        .iter()
        .chain(std::iter::once(&THE_BOUND))
        .map(|(f, n)| (f.to_string(), n.to_string()))
        .collect();
    expected.sort();
    assert_eq!(
        found, expected,
        "a 256 MiB const under src/wallet appeared or went; name it here with its reference site"
    );
}
