use super::Suite;
use bsv_rs::primitives::{from_hex, sha256, PrivateKey};
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::{SignOutputs, UnlockingScript};
use bsv_rs::transaction::beef_stream::{display_hex, BeefStream, Element};
use bsv_rs::transaction::{
    Beef, MerklePath, MockChainTracker, Transaction, TransactionInput, TransactionOutput,
};
use serde_json::{json, Value};
use std::io::Read;

#[path = "../../transaction/vectors/beef_cross_sdk.rs"]
mod shared_beef;
#[path = "../../transaction/vectors/bump_valid.rs"]
mod shared_bump;

const README_SEED: &str = "bsv-rs oracle-fixtures README transaction v1";
const BEEF_V1: u32 = 0xefbe0001;
const BEEF_V2: u32 = 0xefbe0002;

// The README's transaction and beef_spv programs, with their random key
// replaced by SHA256(README_SEED). Signing is deterministic and offline.
fn readme_chain() -> (Transaction, Transaction) {
    let key = PrivateKey::from_bytes(&sha256(README_SEED.as_bytes())).unwrap();
    let address = key.public_key().to_address();
    let mut funding = Transaction::new();
    let mut mined = TransactionInput::new("11".repeat(32), 0);
    mined.unlocking_script = Some(UnlockingScript::new());
    funding.add_input(mined).unwrap();
    funding
        .add_output(TransactionOutput::new(
            10_000,
            P2PKH::lock_from_address(&address).unwrap(),
        ))
        .unwrap();
    let funding_txid = funding.id();
    funding.merkle_path = Some(MerklePath::from_coinbase_txid(&funding_txid, 800_000));
    let mut spend = Transaction::new();
    let mut input = TransactionInput::with_source_transaction(funding.clone(), 0);
    input.set_unlocking_script_template(P2PKH::unlock(&key, SignOutputs::All, false));
    spend.add_input(input).unwrap();
    spend.add_p2pkh_output(&address, Some(9_900)).unwrap();
    futures::executor::block_on(spend.sign()).unwrap();
    let mut tracker = MockChainTracker::new(800_000);
    tracker.add_root(800_000, funding_txid);
    assert!(futures::executor::block_on(spend.verify(&tracker, None)).unwrap());
    (funding, spend)
}

fn tx_entry(name: &str, input: Value, transaction: &Transaction) -> Value {
    let bytes = transaction.to_binary();
    let parsed = Transaction::from_binary(&bytes).unwrap();
    assert_eq!(parsed.to_binary(), bytes, "{name}: transaction round trip");
    assert_eq!(parsed.id(), transaction.id(), "{name}: txid");
    json!({"name": name, "input": input, "expected": {"hex": hex::encode(bytes), "txid": parsed.id()}})
}

fn merkle_entry(name: &str, input: Value, merkle: &MerklePath) -> Value {
    let bytes = merkle.to_binary();
    let parsed = MerklePath::from_binary(&bytes).unwrap();
    let parsed_hex = MerklePath::from_hex(&merkle.to_hex()).unwrap();
    assert_eq!(parsed.to_binary(), bytes, "{name}: binary round trip");
    assert_eq!(parsed_hex.to_binary(), bytes, "{name}: hex round trip");
    json!({"name": name, "input": input, "expected": {"binary_hex": hex::encode(bytes),
        "hex": merkle.to_hex(), "block_height": merkle.block_height, "root": merkle.compute_root(None).unwrap()}})
}

struct Chunks<'a> {
    bytes: &'a [u8],
    size: usize,
}
impl Read for Chunks<'_> {
    fn read(&mut self, target: &mut [u8]) -> std::io::Result<usize> {
        let n = self.size.min(target.len()).min(self.bytes.len());
        target[..n].copy_from_slice(&self.bytes[..n]);
        self.bytes = &self.bytes[n..];
        Ok(n)
    }
}

fn stream(bytes: &[u8], chunk_size: usize) -> Value {
    let mut stream = BeefStream::new(Chunks {
        bytes,
        size: chunk_size,
    });
    let mut elements = Vec::new();
    while let Some(element) = stream.next_element().unwrap() {
        let value = match element {
            Element::Bump(bump) => json!({"kind": "bump", "offset": bump.offset,
                "hex": bump.to_merkle_path().unwrap().to_hex(), "root": display_hex(&bump.root)}),
            Element::Tx {
                offset,
                txid,
                bump_index,
                body,
            } => json!({"kind": "transaction", "offset": offset,
                "txid": display_hex(&txid), "bump_index": bump_index, "hex": hex::encode(&body.raw)}),
            Element::TxidOnly { offset, txid } => {
                json!({"kind": "txid_only", "offset": offset, "txid": display_hex(&txid)})
            }
        };
        elements.push(value);
    }
    assert_eq!(stream.offset(), bytes.len() as u64);
    json!({"version": stream.version(), "subject": stream.subject().map(|hash| display_hex(&hash)),
        "bytes_read": stream.offset(), "elements": elements})
}

fn beef_entry(name: &str, input: Value, mut beef: Beef, atomic: bool) -> Value {
    let bytes = if atomic {
        beef.to_binary_atomic(beef.atomic_txid.clone().as_deref().unwrap())
            .unwrap()
    } else {
        beef.to_binary()
    };
    let mut parsed = Beef::from_binary(&bytes).unwrap();
    let roundtrip = if atomic {
        parsed
            .to_binary_atomic(parsed.atomic_txid.clone().as_deref().unwrap())
            .unwrap()
    } else {
        parsed.to_binary()
    };
    assert_eq!(roundtrip, bytes, "{name}: BEEF round trip");
    let expected_stream = stream(&bytes, bytes.len());
    for chunk in [1, 7, 64] {
        assert_eq!(
            stream(&bytes, chunk),
            expected_stream,
            "{name}: stream chunks of {chunk}"
        );
    }
    assert_eq!(expected_stream["version"], parsed.version);
    assert_eq!(expected_stream["subject"], json!(parsed.atomic_txid));
    // Independently compare each streamed payload with the whole parser.
    for (i, bump) in parsed.bumps.iter().enumerate() {
        assert_eq!(
            expected_stream["elements"][i]["hex"],
            bump.to_hex(),
            "{name}: bump {i}"
        );
    }
    for (i, tx) in parsed.txs.iter().enumerate() {
        assert_eq!(
            expected_stream["elements"][parsed.bumps.len() + i]["txid"],
            tx.txid(),
            "{name}: txid {i}"
        );
    }
    json!({"name": name, "input": input, "expected": {"hex": hex::encode(bytes), "stream": expected_stream}})
}

fn file(path: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap()
}

pub fn record(suite: &mut Suite) {
    // A changed example needs a recipe review. Keep this guard in test code so
    // an example's comment/format edit can leave the golden bytes unchanged.
    for (source, expected) in [
        (
            "examples/transaction.rs",
            "f592e06733160b618e3e002ffab42fb5d6c5d547fa995a008df8ad468324fda7",
        ),
        (
            "examples/beef_spv.rs",
            "38f468b6942f27988a763e28646def62209685a1fb12a83d9e7c8850a612ce6a",
        ),
        (
            "examples/overlay.rs",
            "e6649e58bc2a8309d0ca6a0e4ff25cb831a5eda731ab5b462c3b0015184d2316",
        ),
    ] {
        // Git may check Rust sources out with CRLF on Windows. This guard is
        // about the recipe; fixture and transport bytes are compared unchanged.
        let source_text = String::from_utf8(file(source))
            .unwrap()
            .replace("\r\n", "\n");
        assert_eq!(
            hex::encode(sha256(source_text.as_bytes())),
            expected,
            "{source}: review the seeded recipe and update this source guard"
        );
    }
    let (funding, spend) = readme_chain();
    let mut readme = Vec::new();
    for source in ["examples/transaction.rs", "examples/beef_spv.rs"] {
        for (name, tx) in [("funding", &funding), ("spend", &spend)] {
            readme.push(tx_entry(
                &format!("{source}/{name}"),
                json!({"source": source,
                "seed": README_SEED, "transaction": name}),
                tx,
            ));
        }
    }
    // The overlay README program constructs an empty transaction. Record only
    // its serialization here; do not execute its lookup or broadcast.
    readme.push(tx_entry(
        "examples/overlay.rs/empty",
        json!({"source": "examples/overlay.rs",
        "seed": "Transaction::new()"}),
        &Transaction::new(),
    ));
    suite.add(
        "transaction/readme.json",
        &[("transactions/0012.md", "Specification")],
        readme,
    );

    let sighash: Vec<Value> = serde_json::from_slice(&file("tests/vectors/sighash.json")).unwrap();
    let entries = sighash
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let bytes = from_hex(row["raw_tx"].as_str().unwrap()).unwrap();
            let transaction = Transaction::from_binary(&bytes).unwrap();
            assert_eq!(
                transaction.to_binary(),
                bytes,
                "sighash/{index}: source bytes"
            );
            tx_entry(
                &format!("sighash/{index}"),
                json!({"source": "tests/vectors/sighash.json", "index": index}),
                &transaction,
            )
        })
        .collect();
    suite.add(
        "transaction/sighash.json",
        &[("transactions/0012.md", "Specification")],
        entries,
    );

    let mut merkle = vec![merkle_entry(
        "readme",
        json!({"seed": README_SEED, "height": 800000}),
        funding.merkle_path.as_ref().unwrap(),
    )];
    for (name, hex) in [
        ("BRC74_HEX", shared_beef::BRC74_HEX),
        ("SINGLE_TX_BUMP_HEX", shared_beef::SINGLE_TX_BUMP_HEX),
        ("BUMP_VALID_1", shared_bump::BUMP_VALID_1),
        ("BUMP_VALID_2", shared_bump::BUMP_VALID_2),
    ] {
        let source = if name.starts_with("BUMP_VALID") {
            "tests/transaction/vectors/bump_valid.rs"
        } else {
            "tests/transaction/vectors/beef_cross_sdk.rs"
        };
        let path = MerklePath::from_hex(hex).unwrap();
        assert_eq!(path.to_hex(), hex, "{name}: source bytes");
        merkle.push(merkle_entry(
            name,
            json!({"source": source, "constant": name}),
            &path,
        ));
    }
    suite.add(
        "merkle_path/paths.json",
        &[("transactions/0074.md", "Binary Encoding")],
        merkle,
    );

    for (version, name) in [(BEEF_V1, "v1"), (BEEF_V2, "v2")] {
        let mut beef = Beef::with_version(version);
        let bump = beef.merge_bump(funding.merkle_path.clone().unwrap());
        beef.merge_raw_tx(funding.to_binary(), Some(bump));
        beef.merge_raw_tx(spend.to_binary(), None);
        let source = if version == BEEF_V1 {
            shared_beef::BRC62_HEX
        } else {
            shared_beef::BEEF_SET_HEX
        };
        let entries = vec![
            beef_entry(
                "readme_chain",
                json!({"seed": README_SEED, "version": version}),
                beef,
                false,
            ),
            beef_entry(
                "shared_vector",
                json!({"source": "tests/transaction/vectors/beef_cross_sdk.rs",
                "constant": if version == BEEF_V1 {"BRC62_HEX"} else {"BEEF_SET_HEX"}}),
                Beef::from_hex(source).unwrap(),
                false,
            ),
        ];
        suite.add(
            &format!("beef/{name}.json"),
            &[
                ("transactions/0062.md", "Specification"),
                ("transactions/0096.md", "Specification"),
            ],
            entries,
        );
    }
    let mut atomic = Beef::new();
    let bump = atomic.merge_bump(funding.merkle_path.clone().unwrap());
    atomic.merge_raw_tx(funding.to_binary(), Some(bump));
    atomic.merge_raw_tx(spend.to_binary(), None);
    atomic.atomic_txid = Some(spend.id());
    let existing = Beef::from_binary(&file(
        "tests/vectors/beef_of_any_size/example_atomic_payment.bin",
    ))
    .unwrap();
    suite.add(
        "beef/atomic.json",
        &[(
            "transactions/0095.md",
            "Header Structure / Transaction Inclusion Rules",
        )],
        vec![
            beef_entry(
                "readme_chain",
                json!({"seed": README_SEED, "subject": spend.id()}),
                atomic,
                true,
            ),
            beef_entry(
                "shared_atomic",
                json!({"source": "tests/vectors/beef_of_any_size/example_atomic_payment.bin"}),
                existing,
                true,
            ),
        ],
    );
    let mut stub = Beef::new();
    stub.merge_txid_only(funding.id());
    suite.add(
        "beef/txid_only.json",
        &[("transactions/0096.md", "Specification")],
        vec![
            beef_entry(
                "unproven_stub",
                json!({"seed": README_SEED, "txid": funding.id()}),
                stub,
                false,
            ),
            beef_entry(
                "proven_stub",
                json!({"source": "tests/vectors/beef_of_any_size/stub_proven.bin"}),
                Beef::from_binary(&file("tests/vectors/beef_of_any_size/stub_proven.bin")).unwrap(),
                false,
            ),
        ],
    );
}
