//! #869's third fold (the cold re-read of the second fold, `5bf34e29`): the
//! BEEF linker keyed its stubs by an input's raw `source_txid` text, so a
//! transaction whose two inputs hold one text that does not parse (`"zz"`,
//! `""`, `"abc"`), each linked to its own source, came back from
//! `find_atomic_transaction` of its id with the second input relinked to the
//! first input's source: another transaction, another id. The stubs are now
//! keyed by the id of what an input links (its own source's, else the text
//! the BEEF is asked by), and the BEEF's graph reads an input's outpoint by
//! the serializer's rule (`outpoint_txid_name`): its `input_txids` and the
//! in-memory judge name the txids the written bytes name.
//!
//! Two inputs sharing a text that DOES parse over two sources whose ids differ
//! from it: the id is the text's either way (the serializer never reads the
//! source); each input keeps the source it was given, as the reference's
//! `#resolveInputSource` never replaces a linked source and its walk visits
//! by the source's id (`ts-stack@edf6e03` `Beef.ts:649-679`). Until the fold
//! the second input was handed the first one's stub.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code

use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Beef, Transaction, TransactionInput, TransactionOutput};

fn out(v: u64) -> TransactionOutput {
    TransactionOutput::new(v, LockingScript::from_binary(&[0x51]).unwrap())
}

fn source(tag: u8) -> Transaction {
    let mut t = Transaction::new();
    t.inputs_mut()
        .push(TransactionInput::new(format!("{tag:02x}").repeat(32), 0));
    t.outputs_mut().push(out(1000 + u64::from(tag)));
    t
}

/// A transaction of two inputs naming `text`, linked to sources 1 and 2.
fn child(text: &str) -> (Transaction, [String; 2]) {
    let mut c = Transaction::new();
    let mut ids = [String::new(), String::new()];
    for (k, tag) in [1u8, 2].into_iter().enumerate() {
        let s = source(tag);
        ids[k] = s.id();
        let mut i = TransactionInput::new(text.into(), 0);
        i.source_transaction = Some(Box::new(s));
        c.inputs_mut().push(i);
    }
    c.outputs_mut().push(out(5));
    (c, ids)
}

fn linked(tx: &Transaction) -> Vec<String> {
    tx.inputs()
        .iter()
        .map(|i| i.source_transaction.as_deref().expect("linked").id())
        .collect()
}

fn judge(text: &str) {
    let (c, ids) = child(text);
    let cid = c.id();
    let mut beef = Beef::new();
    beef.merge_transaction(c.clone());
    let atomic = beef.find_atomic_transaction(&cid).expect("held");
    assert_eq!(atomic.id(), cid, "[{text:?}] find_atomic_transaction's id");
    assert_eq!(
        linked(&atomic),
        ids,
        "[{text:?}] find_atomic_transaction's sources"
    );
    let signing = beef.find_transaction_for_signing(&cid).expect("held");
    assert_eq!(
        signing.id(),
        cid,
        "[{text:?}] find_transaction_for_signing's id"
    );
    assert_eq!(
        linked(&signing),
        ids,
        "[{text:?}] find_transaction_for_signing's sources"
    );
    let back = Transaction::from_beef(&c.to_beef(true).unwrap(), Some(&cid)).unwrap();
    assert_eq!(back.id(), cid, "[{text:?}] from_beef of to_beef");
}

#[test]
fn two_inputs_sharing_a_text_that_does_not_parse_keep_their_own_sources_869() {
    for text in ["zz", "", "abc"] {
        judge(text);
    }
}

#[test]
fn two_inputs_sharing_a_text_that_parses_keep_their_own_sources_869() {
    judge(&"ab".repeat(32));
}

/// The BEEF's graph names what its bytes name: the subject's `input_txids`
/// are the sources' ids, and the in-memory judge gives the verdict the reader
/// gives the BEEF's own bytes (until the fold `input_txids` held the text,
/// and both inputs' outpoints read as one, a repeated outpoint the bytes do
/// not carry).
#[test]
fn a_beefs_graph_names_the_outpoints_its_bytes_carry_869() {
    for text in ["zz", "", "abc"] {
        let (c, ids) = child(text);
        let cid = c.id();
        let mut beef = Beef::new();
        beef.merge_transaction(c);
        let mut entry = beef.find_txid(&cid).unwrap().input_txids.clone();
        entry.sort();
        let mut want = ids.to_vec();
        want.sort();
        assert_eq!(entry, want, "[{text:?}] input_txids");
        let mut reread = Beef::from_binary(&beef.to_binary().unwrap()).unwrap();
        assert_eq!(
            beef.verify_structure(),
            reread.verify_structure(),
            "[{text:?}] the in-memory verdict against the bytes'"
        );
    }
}
