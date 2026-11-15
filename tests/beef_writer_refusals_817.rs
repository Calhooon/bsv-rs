//! The BEEF writers, `merge_beef` and `merge_raw_tx` return `Result` and
//! refuse what they cannot write faithfully (#817, the second change of the
//! ensemble's decision).
//!
//! The rule: a writer refuses only a state it cannot write faithfully (bytes
//! that would not frame, or would read back as another state) and writes
//! every other state, valid or not, as the reference does; the reference's
//! words where it refuses; where it writes bytes no reader reads back as
//! written, this crate refuses in its own words and the row is stated.
//! Against `vectors/beef_v1_txid_only_writer_817.json` (the recorder
//! `support/beef_v1_txid_only_writer_817.mjs`, `ts-stack@edf6e03` under Node
//! v22.18.0, two runs byte-identical): `writers` (what `toHex` throws or
//! writes for each state, and what its readers make of the bytes),
//! `raw_door` (`mergeRawTx`), `txid_door` (`mergeTxidOnly`), `merge_door`
//! (`mergeBeef`, the target's bytes before and after) and `bump_door`
//! (`mergeBump`). Every fixture is this crate's writer's (`to_beef_v1`), its
//! bytes the recording's.
//!
//! Since #843b a `Beef` owns its rows and a txid is a `Txid`: the recorded
//! states that hold a txid-only entry whose txid text is not 64 hex digits
//! cannot be built (`beef_merge_states_817::UNBUILDABLE_843B`), so the three
//! writer refusals for such a text are gone with the states. Each such cell
//! is counted by name where its group is replayed, and every recorded cell
//! is replayed, refused at its door, or on that list.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "support/beef_merge_states_817.rs"]
mod beef_merge_states_817;
#[path = "support/beef_seeds_817.rs"]
mod beef_seeds_817;

use beef_merge_states_817::{
    fixture, merge_source, vector, writer_state, BAD_WORD, FRESH, UNBUILDABLE_843B,
};

use bsv_rs::primitives::{from_hex, Writer};
use bsv_rs::transaction::{Beef, BeefTx, MerklePath, MerklePathLeaf, Txid, BEEF_V1, BEEF_V2};
use bsv_rs::Error;
use serde_json::Value;

/// A change made to a source through its public doors.
type Change = Box<dyn Fn(&mut Beef)>;

/// The words `Txid::from_hex` refuses a text in, the reference's
/// `requireTXID` (`Transaction.ts:95-100` at `ts-stack@edf6e03`).
const NOT_A_TXID: &str = "txid must be a 32-byte hexadecimal transaction ID.";

/// `name` is on the list of recorded states no door builds since #843b.
fn unbuildable(name: &str) -> bool {
    UNBUILDABLE_843B.contains(&name)
}

fn cell<'a>(v: &'a Value, group: &str, name: &str) -> &'a Value {
    v[group]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no {group} cell {name}"))
}

/// The words of a refusal of either class this change returns.
fn words<T: std::fmt::Debug>(result: bsv_rs::Result<T>) -> String {
    match result {
        Err(Error::BeefError(w)) | Err(Error::MerklePathError(w)) => w,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn version_words(word: u32) -> String {
    format!("Serialized BEEF must start with 4022206465 or 4022206466 but starts with {word}")
}

/// Each writer refuses `beef` in `expected`, a caller's writer untouched.
fn refused_by_every_writer(beef: &mut Beef, expected: &str, name: &str) {
    let mut writer = Writer::new();
    writer.write_u8(0x5a);
    assert_eq!(
        words(beef.to_writer(&mut writer)),
        expected,
        "{name}: to_writer"
    );
    assert_eq!(
        writer.into_bytes(),
        vec![0x5a],
        "{name}: the writer untouched"
    );
    assert_eq!(words(beef.to_binary()), expected, "{name}: to_binary");
    assert_eq!(words(beef.to_hex()), expected, "{name}: to_hex");
}

/// The cells where this crate refuses and the reference writes bytes no
/// reader reads back as written (the stated rows), with this crate's words.
fn stated_refusal(name: &str) -> Option<String> {
    Some(match name {
        "version_word_efbe0003" => version_words(BAD_WORD),
        "version_word_atomic" => version_words(0x0101_0101),
        "version_word_zero" => version_words(0),
        _ => return None,
    })
}

/// The `writers` group: where the reference throws, this crate refuses in
/// its words; where it writes bytes its own reader reads back as written,
/// this crate writes the same bytes; where its bytes do not read back as
/// written, this crate refuses (stated); and where the recorded state holds
/// a txid text that is no txid, this crate has no state (counted by name).
///
/// Replaces `each_writer_cell_is_the_reference_s_or_a_stated_refusal_817`,
/// which built sixteen of the nineteen cells. Seven of them held a
/// txid-only entry whose txid was `zz`, the empty text or a text of 62, 63
/// or 66 digits, taken as given by `merge_txid_only` and refused late by
/// the writers (`Invalid txid-only entry txid: expected 64 hex digits, got
/// N`, `Invalid hex string`, the empty txid ahead of everything). A txid is
/// a `Txid` since #843b, so those states and their three refusals are gone;
/// the cells stay in the vector and are counted here by name.
#[test]
fn each_writer_cell_is_the_reference_s_a_stated_refusal_or_counted_unbuildable_843b() {
    let v = vector();
    let f = fixture(&v);
    let (mut pinned, mut no_state, mut at_the_door) = (0, Vec::new(), 0);
    for c in v["writers"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let Some(mut beef) = writer_state(name, &f) else {
            // Either the raw door refuses the bytes (pinned at the door,
            // below) or the state's txid text is no `Txid`.
            if unbuildable(name) {
                no_state.push(name);
            } else {
                assert!(
                    name.starts_with("raw_with") || name.starts_with("raw_without"),
                    "{name}: a recorded cell neither replayed nor counted"
                );
                at_the_door += 1;
            }
            continue;
        };
        assert!(!unbuildable(name), "{name}: listed unbuildable, yet built");
        pinned += 1;
        let reference = &c["write"];
        if let Some(stated) = stated_refusal(name) {
            refused_by_every_writer(&mut beef, &stated, name);
            if let Some(ok) = reference["ok"].as_str() {
                // The stated rows' premise: the reference's bytes are not
                // read back strictly as the state written.
                let strict = &c["read_back"]["from_binary_strict"];
                let held = beef.txs().first().map(BeefTx::id);
                let same_text = strict["ok"]["txids"][0].as_str() == held.as_deref();
                assert!(
                    strict.get("thrown").is_some() || !same_text,
                    "{name}: the reference read {ok} back as written"
                );
            }
        } else if let Some(thrown) = reference["thrown"].as_str() {
            refused_by_every_writer(&mut beef, thrown, name);
        } else {
            let ok = reference["ok"].as_str().unwrap();
            assert_eq!(
                beef.to_hex()
                    .expect("the reference writes it and reads it back"),
                ok,
                "{name}: the reference's bytes"
            );
            assert!(
                c["read_back"]["from_binary_strict"].get("ok").is_some(),
                "{name}"
            );
            Beef::from_binary(&from_hex(ok).unwrap()).expect("this crate reads them too");
        }
    }
    assert_eq!(pinned, 9, "every writer cell this crate can build");
    assert_eq!(at_the_door, 3, "the three raw frames the raw door refuses");
    // The seven cells whose txid text is no txid, by name: each stays in the
    // vector, and none has a state here (#843b).
    assert_eq!(
        no_state,
        [
            "txid_only_non_hex",
            "txid_only_62_digits",
            "txid_only_66_digits",
            "txid_only_63_digits",
            "txid_only_non_hex_short",
            "txid_only_empty_after_merge_threw",
            "txid_only_empty_with_non_hex_bump_hash",
        ]
    );
    // The texts those cells hold, each refused where it would enter.
    for text in [
        "zz".repeat(32),
        "ab".repeat(31),
        "ab".repeat(33),
        format!("a{}", "bc".repeat(31)),
        "zz".to_string(),
        String::new(),
    ] {
        assert_eq!(
            Txid::from_hex(&text),
            Err(Error::TransactionError(NOT_A_TXID.to_string())),
            "a text of {} characters",
            text.len()
        );
    }
}

/// The upper-case cell on the law (#843b): an upper-case text and its
/// lower-case twin are one `Txid`, so the two merges hold one entry, found
/// by either text, and the bytes are the reference's for the upper-case
/// text. Until #843b the texts were compared as text and held as two
/// entries.
#[test]
fn an_upper_case_txid_and_its_lower_case_twin_are_one_entry_843b() {
    let v = vector();
    let recorded = cell(&v, "writers", "txid_only_upper_case")["write"]["ok"]
        .as_str()
        .unwrap();
    let (upper, lower) = ("AB".repeat(32), "ab".repeat(32));
    let mut beef = Beef::new();
    beef.merge_txid_only(upper.parse().unwrap());
    beef.merge_txid_only(lower.parse().unwrap());
    assert_eq!(beef.txs().len(), 1, "one entry");
    for text in [&upper, &lower] {
        let found = beef.find_txid(text.parse().unwrap()).expect("found");
        assert_eq!(found.id(), lower, "shown in lower case");
    }
    assert_eq!(beef.to_hex().unwrap(), recorded);
}

/// The atomic word is stated beside the other words: the reference's reader
/// reads `01010101` as an Atomic prefix and names the word after the
/// subject's 32 bytes, where this crate names the word held.
#[test]
fn the_atomic_version_word_is_named_as_held_where_the_reference_reads_past_it_817() {
    let v = vector();
    let c = cell(&v, "writers", "version_word_atomic");
    assert_eq!(
        c["read_back"]["from_binary_strict"]["thrown"]
            .as_str()
            .unwrap(),
        version_words(2_958_992_019)
    );
    let mut beef = writer_state("version_word_atomic", &fixture(&v)).unwrap();
    assert_eq!(words(beef.to_binary()), version_words(16_843_009));
}

/// `merge_raw_tx` and `BeefTx::from_raw_tx` refuse bytes that are not
/// exactly one transaction, with or without an index, the BEEF untouched:
/// the reference's scan's words where its door throws (no index); where it
/// takes the bytes (an index, or trailing bytes) the same refusal, stated.
#[test]
fn the_raw_door_refuses_bytes_that_are_not_one_transaction_817() {
    let v = vector();
    let f = fixture(&v);
    let raw = |name: &str| -> Vec<u8> {
        let c = &f.child_raw;
        match name {
            "empty" => Vec::new(),
            "truncated_version" => from_hex("010000").unwrap(),
            "truncated_in_input" => c[..10].to_vec(),
            "truncated_lock_time" => c[..c.len() - 1].to_vec(),
            "trailing_byte" => [c.as_slice(), &[0]].concat(),
            "non_canonical_input_count" => [&c[..4], &[0xfd, 0x01, 0x00][..], &c[5..]].concat(),
            "one_transaction" => c.clone(),
            other => panic!("no raw {other}"),
        }
    };
    let cells = v["raw_door"].as_array().unwrap();
    assert_eq!(cells.len(), 14);
    for c in cells {
        let name = c["name"].as_str().unwrap();
        let index = c["bump_index"].as_u64().map(|i| i as usize);
        let bytes = raw(name);
        let mut beef = Beef::new();
        let before = beef.to_hex().unwrap();
        let ours = beef.merge_raw_tx(bytes.clone(), index).map(|t| t.txid());
        let entry = BeefTx::from_raw_tx(bytes, index).map(|t| t.txid());
        assert_eq!(ours, entry, "{name} {index:?}: the two doors agree");
        if name == "one_transaction" {
            assert_eq!(ours.unwrap(), c["merge"]["ok"]["txid"].as_str().unwrap());
            continue;
        }
        let refused = words(ours);
        assert_eq!(beef.to_hex().unwrap(), before, "{name}: the BEEF untouched");
        assert!(beef.txs().is_empty());
        match (c["merge"]["thrown"].as_str(), name) {
            (Some(thrown), _) => assert_eq!(refused, thrown, "{name}: the reference's words"),
            // Stated: the reference's door takes these bytes.
            (None, "trailing_byte") => assert_eq!(
                refused, "Serialized transaction has 1 bytes after its lock time",
                "{name} {index:?}"
            ),
            (None, _) => {
                assert_eq!(index, Some(0), "{name}: only an index skips the scan there");
                let unindexed = cells
                    .iter()
                    .find(|o| o["name"] == name && o["bump_index"].is_null())
                    .unwrap();
                assert_eq!(
                    refused,
                    unindexed["merge"]["thrown"].as_str().unwrap(),
                    "{name}"
                );
            }
        }
    }
}

/// The reference writes the bytes its door kept, and its strict reader
/// refuses them: the frame the raw door's refusal keeps from the wire.
#[test]
fn the_writers_cells_of_the_three_raw_frames_are_pinned_as_recorded_817() {
    let v = vector();
    for name in [
        "raw_with_index_truncated",
        "raw_with_index_trailing_byte",
        "raw_without_index_trailing_byte",
    ] {
        let c = cell(&v, "writers", name);
        assert!(c["write"]["ok"].is_string(), "{name}: written there");
        assert!(
            c["read_back"]["from_binary_strict"]["thrown"].is_string(),
            "{name}: refused by its own strict reader"
        );
    }
}

/// `merge_txid_only` takes a `Txid`, so the three texts of the `txid_door`
/// group are refused where they would enter and no entry is held, where the
/// reference's door holds each (after throwing `Internal` for `""`) and its
/// writer throws or writes two bytes.
///
/// Replaces `the_txid_door_takes_any_text_and_the_writer_judges_it_817`,
/// which pinned the hole: `merge_txid_only` held any text and the writers
/// refused it late. A call with a text does not compile
/// (`src/transaction/beef/rows.rs`' `compile_fail` doc tests); the text is
/// parsed at the caller, in `Txid::from_hex`'s words.
#[test]
fn the_txid_door_takes_a_txid_and_a_text_that_is_none_is_refused_where_it_enters_843b() {
    let v = vector();
    let cells = v["txid_door"].as_array().unwrap();
    assert_eq!(cells.len(), 3, "the recorded cells");
    for (name, text) in [("empty", ""), ("non_hex", "zz"), ("short_hex", "abcd")] {
        let c = cell(&v, "txid_door", name);
        // The reference's recorded side, kept: the entry is held there.
        assert_eq!(c["txs_after"], 1, "{name}: taken there");
        match name {
            "empty" => assert_eq!(c["merge"]["thrown"], "Internal"),
            "non_hex" => assert_eq!(c["write_after"]["thrown"], "Invalid hex string"),
            _ => assert_eq!(
                c["write_after"]["ok"], "0200beef000102cdab",
                "two bytes there"
            ),
        }
        // Stated: no text that is not 64 hex digits is a txid, so nothing is
        // held and nothing is left for a writer to refuse (#843b).
        let mut beef = Beef::new();
        let parsed = text.parse::<Txid>().map(|txid| {
            beef.merge_txid_only(txid);
        });
        assert_eq!(
            parsed,
            Err(Error::TransactionError(NOT_A_TXID.to_string())),
            "{name}"
        );
        assert!(beef.txs().is_empty(), "{name}: nothing held");
        assert_eq!(
            beef.to_hex().unwrap(),
            "0200beef0000",
            "{name}: an empty BEEF"
        );
    }
}

/// A source in each `merge_door` state, built here as the recorder built it.
/// `merge_beef` gives the reference snapshot's verdict, the target untouched
/// on `Err`: the reference's words where its writer throws and where its
/// reader refuses at the version word; this crate's reader's words where its
/// reader refuses a BUMP (#477's row); this crate's writer's words where the
/// reference's writer and reader carry a state this crate cannot write
/// faithfully (stated).
///
/// Replaces `merge_beef_refuses_what_the_snapshot_refuses_the_target_untouched_817`,
/// which built eleven of the twelve sources: three held a txid-only entry
/// whose txid text was `zz` repeated or 62 digits, a state no door builds
/// since #843b; they are counted by name and the other eight replayed.
#[test]
fn merge_beef_refuses_what_the_snapshot_refuses_the_target_untouched_843b() {
    let v = vector();
    let f = fixture(&v);
    let (mut pinned, mut no_state) = (0, Vec::new());
    for c in v["merge_door"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let Some(source) = merge_source(name, &f) else {
            if unbuildable(name) {
                // A source holding a txid text that is no txid: no state
                // since #843b, counted by name below.
                no_state.push(name);
                continue;
            }
            // The raw entry with a byte after its frame: the door refuses it.
            assert_eq!(name, "source_raw_trailing_byte_with_index");
            assert!(BeefTx::from_raw_tx([f.child_raw.as_slice(), &[0]].concat(), Some(0)).is_err());
            continue;
        };
        assert!(!unbuildable(name), "{name}: listed unbuildable, yet built");
        pinned += 1;
        let mut target = Beef::new();
        target
            .merge_raw_tx(f.parent_raw.clone(), None)
            .expect("the bytes are one transaction");
        let before = target.to_hex().unwrap();
        let ours = target.merge_beef(&source);
        let reference = c["merge"]["thrown"].as_str();
        match (name, reference) {
            ("source_valid", None) => {
                ours.expect("the source writes and reads back");
                assert_ne!(target.to_hex().unwrap(), before);
                continue;
            }
            ("source_bump_duplicate_with_hash", None) => {
                // Stated: the reference's reader drops the duplicate's hash.
                assert_eq!(
                    words(ours),
                    "Duplicate leaf at height 0, offset 1 carries a hash, which a BUMP's duplicate flag cannot write"
                );
            }
            ("source_bump_two_leaves_at_one_offset" | "source_bump_no_levels", Some(_)) => {
                // This crate's reader's refusal of the snapshot, in its words.
                let refused = words(ours);
                assert!(
                    refused.starts_with("invalid BEEF at byte "),
                    "{name}: {refused}"
                );
                let kind = if name.ends_with("no_levels") {
                    "TreeHeightZero"
                } else {
                    "DuplicateOffset"
                };
                assert!(refused.contains(kind), "{name}: {refused}");
            }
            (_, Some(thrown)) => assert_eq!(words(ours), thrown, "{name}: the reference's words"),
            (_, None) => panic!("{name}: a cell this test does not read"),
        }
        // The reference's target untouched where it refused; this crate's
        // wherever it refuses.
        assert_eq!(c["target_unchanged"], reference.is_some(), "{name}");
        assert_eq!(
            target.to_hex().unwrap(),
            before,
            "{name}: the target untouched"
        );
    }
    assert_eq!(pinned, 8, "every source this crate can build");
    // The three sources whose txid-only entry held a text that is no txid
    // (`merge_txid_only` held it as given until #843b), by name.
    assert_eq!(
        no_state,
        [
            "source_txid_only_non_hex",
            "source_txid_only_62_digits",
            "source_version_word_and_txid_only_62_digits",
        ]
    );
}

/// The verdict is the literal round trip: on every BEEF this tree's vectors
/// hold (read, then each of five states made in it through the public
/// doors), `merge_beef`'s Ok or Err is that of
/// `Beef::from_binary(&source.clone().to_binary()?)`, and its words the
/// writer's where the writer refuses.
///
/// Replaces `merge_beef_s_verdict_is_the_write_then_read_round_trip_on_every_vector_beef_817`,
/// whose six states were written through the public fields. One of them, a
/// txid-only entry of 62 hex digits, has no state since #843b (a txid is a
/// `Txid`); the two BUMP states are made through `edit_bump`, which marks
/// the source for a sort and no longer as read, where the hand write left a
/// BEEF read from bytes as read.
#[test]
fn merge_beef_s_verdict_is_the_write_then_read_round_trip_on_every_vector_beef_843b() {
    let mut compared = 0;
    for (name, bytes) in beef_seeds_817::seeds() {
        let Ok(read) = Beef::from_binary(&bytes) else {
            continue;
        };
        let variants: Vec<Change> = vec![
            Box::new(|_| {}),
            Box::new(|b| b.version = BAD_WORD),
            Box::new(|b| {
                b.merge_txid_only(FRESH.parse().unwrap());
            }),
            // A second leaf at an offset of the leading BUMP's level 0.
            Box::new(|b| {
                if !b.bumps().is_empty() {
                    b.edit_bump(0, |p| {
                        if let Some(level) = p.path.first_mut() {
                            if let Some(leaf) = level.first().cloned() {
                                level.push(leaf);
                            }
                        }
                    })
                    .unwrap();
                }
            }),
            // No levels in the leading BUMP.
            Box::new(|b| {
                if !b.bumps().is_empty() {
                    b.edit_bump(0, |p| p.path.clear()).unwrap();
                }
            }),
        ];
        for (k, change) in variants.iter().enumerate() {
            let mut source = read.clone();
            change(&mut source);
            let round_trip = source
                .clone()
                .to_binary()
                .and_then(|w| Beef::from_binary(&w).map(drop));
            let mut target = Beef::new();
            let verdict = target.merge_beef(&source);
            assert_eq!(
                verdict.is_ok(),
                round_trip.is_ok(),
                "{name} variant {k}: {verdict:?} against {round_trip:?}"
            );
            if let (Err(ours), Err(trip)) = (&verdict, &round_trip) {
                if !matches!(trip, Error::BeefError(w) if w.starts_with("invalid BEEF at byte")) {
                    assert_eq!(ours, trip, "{name} variant {k}: the writer's words");
                }
            }
            compared += 1;
        }
    }
    // 337 BEEFs read until #840's vector brought its clean V2 BEEF; 338
    // until #844's brought three V2 BEEFs at an output of 2^53 - 1; 341
    // until #844's fold recorded fifteen control BEEFs of its writer cells;
    // 356 until 0.8.8's `beef_tx_order.json` brought its witnesses' five
    // distinct V1 BEEFs; 361 until #817's transaction fold, whose vector
    // holds two V2 BEEFs; 363 until #904's `contacts_listed_spend.json`
    // brought nine distinct V1 BEEFs (three listings, six Atomic signable
    // transactions over V1).
    assert_eq!(compared, 5 * 372, "five states of every BEEF read");
}

/// The order of the checks is the order the reference meets them: a BUMP's
/// non-hex hash ahead of an entry V1 cannot carry, that entry ahead of the
/// version word, and the version word after the reference's writer's throws
/// and before the states only this crate refuses (`mergeBeef`'s reader at
/// byte 0).
///
/// Replaces `the_checks_run_in_the_order_the_reference_meets_them_817`. Its
/// cells of a txid-only entry of 62 digits (the recorded
/// `source_version_word_and_txid_only_62_digits`, and two hand states under
/// the V2 word) have no state since #843b, and with them the refusal that
/// was ordered: this crate's own refusal of an entry's txid text. The
/// recorded cell is counted by name; the two hand states are restated with
/// a txid-only entry that is a txid, where the BUMP's refusal is the one
/// left and an entry V1 cannot carry is still met ahead of it.
#[test]
fn the_checks_run_in_the_order_the_reference_meets_them_843b() {
    let v = vector();
    let f = fixture(&v);
    // Writer cells pinned by name in the cell test; the merge order cells here.
    for name in [
        "source_version_word_and_txid_only_62_digits",
        "source_version_word_and_bump_no_levels",
    ] {
        let c = cell(&v, "merge_door", name);
        let Some(source) = merge_source(name, &f) else {
            assert!(unbuildable(name), "{name}: neither replayed nor counted");
            assert_eq!(name, "source_version_word_and_txid_only_62_digits");
            continue;
        };
        let mut target = Beef::new();
        let ours = words(target.merge_beef(&source));
        assert_eq!(ours, c["merge"]["thrown"].as_str().unwrap(), "{name}");
    }
    // A txid-only entry under the V2 word beside a BUMP of no levels: the
    // BUMP's state is written by both (the readers judge it), and since
    // #843b the entry has nothing to be refused for, so the BEEF is written.
    let mut beef = Beef::from_binary(&f.v1).unwrap();
    beef.version = BEEF_V2;
    beef.edit_bump(0, |bump| bump.path.clear()).unwrap();
    beef.merge_txid_only(FRESH.parse().unwrap());
    let written = beef.to_binary().expect("written, the readers' to judge");
    assert!(words(Beef::from_binary(&written)).contains("TreeHeightZero"));
    // A BUMP hash of 62 digits under the V2 word: MerklePath's own refusal,
    // the one left beside a txid-only entry.
    let mut beef = Beef::from_binary(&f.v1).unwrap();
    beef.version = BEEF_V2;
    beef.edit_bump(0, |bump| bump.path[0][0].hash = Some("ab".repeat(31)))
        .unwrap();
    beef.merge_txid_only(FRESH.parse().unwrap());
    assert_eq!(
        words(beef.to_binary()),
        "Invalid hash at height 0, offset 0: expected 64 hex digits, got 62"
    );
    // The same BEEF under the V1 word: the entry V1 cannot carry is met
    // ahead of the BUMP's own refusal (the reference's writer throws there).
    beef.version = BEEF_V1;
    assert_eq!(
        words(beef.to_binary()),
        "a valid serialized Transaction is expected"
    );
    assert_eq!(BEEF_V1, 0xEFBE_0001);
}

/// A BUMP index naming no BUMP is written as the reference writes it.
#[test]
fn a_bump_index_out_of_range_is_written_as_the_reference_writes_it_817() {
    let v = vector();
    let f = fixture(&v);
    let mut beef = writer_state("raw_index_out_of_range", &f).unwrap();
    assert_eq!(
        beef.to_hex().expect("the frame carries any index"),
        cell(&v, "writers", "raw_index_out_of_range")["write"]["ok"]
            .as_str()
            .unwrap()
    );
}

/// `merge_bump`'s combine cannot fail where it is called (both roots
/// computed and equal first), and a BUMP whose root does not compute is
/// appended where a BUMP of its height is held: the reference's
/// `#findOrInsertBump` throws `computeRoot`'s error there (stated), and
/// appends it where none is held, as this crate does.
#[test]
fn a_bump_whose_root_does_not_compute_is_appended_where_the_reference_throws_817() {
    let v = vector();
    let f = fixture(&v);
    let txid = Beef::from_binary(&f.v1).unwrap().bumps()[0].path[0][0]
        .hash
        .clone()
        .unwrap();
    let rootless = || {
        let mut p = MerklePath::new(
            817_000,
            vec![vec![MerklePathLeaf::new_txid(0, txid.clone())]],
        )
        .unwrap();
        p.path[0][0].hash = None;
        p
    };
    let held = cell(&v, "bump_door", "held_height_root_does_not_compute");
    assert_eq!(
        held["merge"]["thrown"],
        "No valid leaf found in the Merkle Path"
    );
    let mut beef = Beef::from_binary(&f.v1).unwrap();
    assert_eq!(
        beef.merge_bump(rootless()),
        1,
        "appended beside the held BUMP"
    );
    assert_eq!(beef.bumps().len(), 2);
    // The writer refuses the hashless txid leaf (MerklePath's words).
    assert_eq!(
        words(beef.to_binary()),
        "Missing hash at height 0, offset 0"
    );

    let none_held = cell(&v, "bump_door", "no_held_height_root_does_not_compute");
    let mut beef = Beef::new();
    assert_eq!(
        beef.merge_bump(rootless()) as u64,
        none_held["merge"]["ok"].as_u64().unwrap()
    );
    // Two BUMPs at 817000 whose roots do not compute are never combined
    // (#817's fold, the strength read's survivor: `merge_bump` with
    // `root.is_some() &&` dropped combined them, two `None` roots equal):
    // the held one passed over, the second appended at index 1 (the
    // reference's loop throws `computeRoot`'s error at the held BUMP,
    // `Beef.ts:797-798`, the rule read's stated row).
    assert_eq!(
        beef.merge_bump(rootless()),
        1,
        "the second rootless BUMP appended"
    );
    assert_eq!(beef.bumps().len(), 2);
    // A BUMP of the same height and root is combined, once.
    let mut beef = Beef::from_binary(&f.v1).unwrap();
    let again = beef.bumps()[0].clone();
    assert_eq!(beef.merge_bump(again), 0);
    assert_eq!(beef.bumps().len(), 1);
}

/// The #764 row's residues this change answers, beyond the recorded cells:
/// a source BUMP with an empty level 0, and a source whose duplicate leaf is
/// flagged txid, are refused by `merge_beef` (this crate's reader's words;
/// `MerklePath`'s writer's), the target untouched, where they were merged.
#[test]
fn the_764_rows_bump_residues_are_refused_by_merge_beef_817() {
    let v = vector();
    let f = fixture(&v);
    let mut empty = Beef::from_binary(&f.v1).unwrap();
    empty.edit_bump(0, |bump| bump.path[0].clear()).unwrap();
    let mut target = Beef::new();
    let refused = words(target.merge_beef(&empty));
    assert!(refused.starts_with("invalid BEEF at byte "), "{refused}");
    assert!(
        target.txs().is_empty() && target.bumps().is_empty(),
        "the target untouched"
    );

    let mut flagged = Beef::from_binary(&f.v1).unwrap();
    let mut dup = MerklePathLeaf::new_duplicate(1);
    dup.txid = true;
    flagged.edit_bump(0, |bump| bump.path[0].push(dup)).unwrap();
    assert_eq!(
        words(target.merge_beef(&flagged)),
        "Duplicate leaf at height 0, offset 1 is flagged txid, which a BUMP's duplicate flag cannot write"
    );
    assert!(
        target.txs().is_empty() && target.bumps().is_empty(),
        "the target untouched"
    );
}

/// A BEEF's entries as the readers and writers see them: each txid, whether
/// it is a txid alone, and its BUMP index.
fn entries_of(beef: &Beef) -> Vec<(String, bool, Option<usize>)> {
    beef.txs()
        .iter()
        .map(|t| (t.id(), t.is_txid_only(), t.bump_index()))
        .collect()
}

/// The `doubled_txid` cell's entries held as the recorder holds them after
/// its hand pushes (`BeefTx.fromRawTx`, `BeefTx.fromTxid`): two entries of
/// one txid, in a BEEF that is not as read.
///
/// No merge door holds a txid twice and no door pushes an entry since #843b,
/// so the rows are written as a frame by this crate's own writers
/// (`MerklePath::to_writer`, `BeefTx::to_writer`) and read by
/// `Beef::from_binary`, which keeps both entries in the order written. A
/// BEEF read from bytes is "as read" (its `merge_beef` as a source walks
/// the read order) and each raw entry holds its bytes and its parse;
/// `retain_txs` keeping every entry then marks it no longer as read, the
/// state a hand push left, so `to_hex` sorts it and `merge_beef` walks its
/// sorted order.
fn doubled_pushed(v: &Value, name: &str, version: u32, bytes: &str) -> Beef {
    let (child, parent) = (
        v["child_raw"].as_str().unwrap(),
        v["parent_raw"].as_str().unwrap(),
    );
    let (c, p) = (
        v["child_txid"].as_str().unwrap(),
        v["parent_txid"].as_str().unwrap(),
    );
    let entries: &[(&str, &str)] = match name {
        "raw_twice" => &[("raw", child), ("raw", child)],
        "raw_then_txid_only" => &[("raw", child), ("txid", c)],
        "txid_only_then_raw" => &[("txid", c), ("raw", child)],
        "proven_raw_twice" => &[("proven", parent), ("proven", parent)],
        "proven_raw_then_txid_only" => &[("proven", parent), ("txid", p)],
        other => panic!("no doubled cell {other}"),
    };
    let bumps = if name.starts_with("proven") {
        vec![Beef::from_hex(bytes).unwrap().bumps()[0].clone()]
    } else {
        Vec::new()
    };
    let mut frame = Writer::new();
    frame.write_u32_le(version);
    frame.write_var_int(bumps.len() as u64);
    for bump in &bumps {
        bump.to_writer(&mut frame).expect("the BUMP is writable");
    }
    frame.write_var_int(entries.len() as u64);
    for &(kind, x) in entries {
        let entry = match kind {
            "txid" => BeefTx::from_txid(x.parse().unwrap()),
            "raw" => BeefTx::from_raw_tx(from_hex(x).unwrap(), None).unwrap(),
            _ => BeefTx::from_raw_tx(from_hex(x).unwrap(), Some(0)).unwrap(),
        };
        entry
            .to_writer(&mut frame, version)
            .expect("the entry is writable");
    }
    let mut beef = Beef::from_binary(&frame.into_bytes()).expect("the frame reads back");
    beef.retain_txs(|_| true);
    beef
}

/// The two cells read from bytes whose entries this crate's `to_binary`
/// sorts, where the reference's `toBinary` returns the bytes read (the older
/// writer difference the #764 row states, #621): written here as the
/// reference writes the same entries pushed by hand.
const READ_SORTED_HERE: &[(&str, u32)] = &[
    ("txid_only_then_raw", BEEF_V2),
    ("proven_raw_then_txid_only", BEEF_V2),
];

/// The ensemble's handed cell (2026-11-10): a BEEF holding one txid twice
/// (a raw entry twice, raw and txid-only in both orders, a proven entry
/// twice, V1 and V2). The reference writes every such state and both its
/// readers read two entries back (`Beef.ts:1262-1266` pushes each one read);
/// this crate's reader keeps both too (the stream's `enter`, the #603 S2
/// row), so the bytes read back as the state written and the writers write
/// it, by the rule, with nothing stated. `merge_beef` of it holds one entry
/// on both sides, the raw one (`#mergeBeefTxEntry`, `Beef.ts:950-967`).
#[test]
fn a_beef_holding_one_txid_twice_is_written_and_read_back_as_held_817() {
    let v = vector();
    let cells = v["doubled_txid"].as_array().unwrap();
    assert_eq!(cells.len(), 7, "the recorded cells");
    for cell in cells {
        let name = cell["name"].as_str().unwrap();
        let version = u32::try_from(cell["version"].as_u64().unwrap()).unwrap();
        let bytes = cell["bytes"].as_str().unwrap();
        let reference_pushed = cell["pushed"]["write"]["ok"].as_str().unwrap();
        for how in ["read", "pushed"] {
            let at = format!("{name} {version:#x} {how}");
            let recorded = &cell[how];
            let mut beef = match how {
                "read" => Beef::from_hex(bytes).unwrap(),
                _ => doubled_pushed(&v, name, version, bytes),
            };
            assert_eq!(beef.txs().len(), 2, "{at}: two entries held");
            assert_eq!(recorded["held"], 2, "{at}: the reference holds two");
            let written = beef.to_hex().unwrap_or_else(|e| panic!("{at}: {e}"));
            let expected = if how == "read" && !READ_SORTED_HERE.contains(&(name, version)) {
                recorded["write"]["ok"].as_str().unwrap()
            } else {
                reference_pushed
            };
            assert_eq!(written, expected, "{at}: the reference's bytes");
            let back = Beef::from_hex(&written).unwrap();
            assert_eq!(
                entries_of(&back),
                entries_of(&beef),
                "{at}: read back as held"
            );
            for reader in ["from_binary", "from_binary_strict"] {
                let theirs = &recorded["read_back"][reader]["ok"];
                let txids: Vec<String> = back.txs().iter().map(BeefTx::id).collect();
                assert_eq!(theirs["txs"], 2, "{at}: {reader} reads two");
                assert_eq!(theirs["txids"], serde_json::json!(txids), "{at}: {reader}");
            }
            let source = match how {
                "read" => Beef::from_hex(bytes).unwrap(),
                _ => doubled_pushed(&v, name, version, bytes),
            };
            let mut target = Beef::new();
            target.merge_beef(&source).unwrap();
            let merged = &recorded["merge_into_empty"]["ok"];
            let txids: Vec<String> = target.txs().iter().map(BeefTx::id).collect();
            let txid_only: Vec<bool> = target.txs().iter().map(BeefTx::is_txid_only).collect();
            assert_eq!(merged["txids"], serde_json::json!(txids), "{at}: merged");
            assert_eq!(
                merged["txid_only"],
                serde_json::json!(txid_only),
                "{at}: merged"
            );
        }
    }
}

/// The entries' order after a refusal (#817's fold, the rule read): the
/// reference's `#getSerializedBytes` (`ts-stack@edf6e03` `Beef.ts:360-373`)
/// throws `Internal` for a txid-only entry with an empty txid from
/// `#ensureSerializableState`, before `#ensureSortedForSerialization`, so
/// its entries come back unsorted; every other refusal is met inside
/// `toWriter`, after the sort, and the entries come back sorted. Against the
/// vector's `sort_on_refusal` (a child merged raw ahead of its parent, then
/// each fault): this crate's words (the empty txid's and the version word's
/// its own, stated rows), and its `txs` after `to_hex` the reference's
/// order on all four cells, the version word's included (written there
/// after its sort, refused here after the same sort).
///
/// Replaces `the_entries_order_after_a_refusal_is_the_reference_s_817`,
/// which replayed all four cells. Two of them (`empty_txid`,
/// `non_hex_txid`) merged a txid-only entry whose text is no txid; since
/// #843b neither state can be held, so neither refusal exists and there is
/// no order after it to read: both are counted by name, and the reference's
/// recorded words for them are asserted as recorded. The refusal met before
/// the sort was the empty txid's alone, so every refusal left is met after
/// the sort.
#[test]
fn the_entries_order_after_a_refusal_is_the_reference_s_843b() {
    let v = vector();
    let f = fixture(&v);
    // The two cells with no state here, by name, and why.
    let no_state = [
        ("empty_txid", String::new(), "Internal"),
        ("non_hex_txid", "zz".repeat(32), "Invalid hex string"),
    ];
    for (name, text, thrown) in &no_state {
        let c = cell(&v, "sort_on_refusal", name);
        assert_eq!(
            c["write"]["thrown"], *thrown,
            "{name}: the reference's words"
        );
        assert_eq!(c["before"][2], text.as_str(), "{name}: the text held there");
        assert!(
            text.parse::<Txid>().is_err(),
            "{name}: no txid, so no state"
        );
    }
    let replayed = ["v1_txid_only", "version_word"];
    for c in v["sort_on_refusal"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        assert!(
            replayed.contains(&name) || no_state.iter().any(|(n, ..)| *n == name),
            "{name}: a recorded cell neither replayed nor counted"
        );
    }
    let order = |b: &Beef| b.txs().iter().map(BeefTx::txid).collect::<Vec<_>>();
    let recorded = |c: &Value, key: &str| -> Vec<String> {
        c[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_string())
            .collect()
    };
    let faults: [(&str, Change, String); 2] = [
        (
            "v1_txid_only",
            Box::new(|b| {
                b.version = BEEF_V1;
                b.merge_txid_only(FRESH.parse().unwrap());
            }),
            "a valid serialized Transaction is expected".to_string(),
        ),
        (
            "version_word",
            Box::new(|b| b.version = 0x0102_0304),
            version_words(0x0102_0304),
        ),
    ];
    for (name, fault, expected) in faults {
        assert!(replayed.contains(&name));
        let c = cell(&v, "sort_on_refusal", name);
        let mut beef = Beef::new();
        beef.merge_raw_tx(f.child_raw.clone(), None).unwrap();
        beef.merge_raw_tx(f.parent_raw.clone(), None).unwrap();
        fault(&mut beef);
        assert_eq!(order(&beef), recorded(c, "before"), "{name}: before");
        assert_eq!(words(beef.to_hex()), expected, "{name}");
        assert_eq!(order(&beef), recorded(c, "after"), "{name}: after");
    }
}

/// The other side of #621's fold: an entry edited in place is written from
/// its fields by every writer, `to_writer`, `to_binary` and `merge_beef`
/// alike. Until #843 `to_writer` wrote the transaction's cache, stale after
/// an edit through the public field, bytes another transaction's; since
/// #843 an edit goes through `set_lock_time`, which clears the caches.
///
/// Replaces `an_entry_edited_through_tx_mut_is_written_from_its_fields_by_to_writer_621`,
/// which assigned the edited transaction through `*tx_mut()`, the entry
/// then waiting for a whole-BEEF door to re-key it. `tx_mut` does not
/// compile since #843b (`src/transaction/beef/rows.rs`' `compile_fail` doc
/// tests); the assignment goes through `edit_tx`, which stores the edited
/// bytes and re-keys the entry at once. The unit twin is
/// `beef/merge_entry_621_tests.rs`'
/// `to_writer_writes_an_edited_entry_from_its_fields_843b`.
#[test]
fn an_entry_edited_through_edit_tx_is_written_from_its_fields_by_to_writer_843b() {
    let f = fixture(&vector());
    let mut stale = bsv_rs::transaction::Transaction::from_binary(&f.parent_raw).unwrap();
    assert_eq!(
        stale.to_binary(),
        f.parent_raw,
        "the cache the parent's bytes"
    );
    stale.set_lock_time(stale.lock_time() ^ 1);
    let mut fresh = bsv_rs::transaction::Transaction::from_binary(&f.parent_raw).unwrap();
    fresh.set_lock_time(fresh.lock_time() ^ 1);
    let edited = fresh.to_binary();
    assert_ne!(edited, f.parent_raw, "the edit moves the bytes");

    let mut beef = Beef::new();
    let held = beef
        .merge_raw_tx(f.parent_raw.clone(), None)
        .unwrap()
        .txid();
    let renamed = stale.txid();
    beef.edit_tx(held, |tx| *tx = stale).unwrap();
    assert!(beef.find_txid(held).is_none(), "re-keyed at once");
    assert!(beef.find_txid(renamed).is_some());
    let mut writer = Writer::new();
    beef.to_writer(&mut writer).unwrap();
    let written = writer.into_bytes();
    let back = Beef::from_binary(&written).expect("to_writer's bytes read back");
    assert_eq!(
        back.txs()[0].raw_tx().unwrap(),
        edited.as_slice(),
        "to_writer writes the edited fields, not the stale cache"
    );
    assert_eq!(
        beef.to_binary().unwrap(),
        written,
        "to_binary writes the same"
    );
    let mut merged = Beef::new();
    merged.merge_beef(&beef).unwrap();
    assert_eq!(merged.to_binary().unwrap(), written, "merge_beef the same");
}
