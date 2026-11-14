#![cfg(test)]
//! The linking door, `Transaction::replace_source` (#869's second fold): the
//! caches kept exactly when the input names its txid by a text that parses
//! (the serializer never reads the source then), emptied otherwise, and the
//! IDENTITY law after every link: `id()` the hash of the fields, read on a
//! copy rebuilt from the parts (no cache).
#![allow(clippy::unwrap_used, clippy::expect_used)] // #134: test code

use super::{outpoint_txid, OutpointTxid};
use crate::script::LockingScript;
use crate::transaction::{Transaction, TransactionInput, TransactionOutput, Txid};

fn tx_paying(sats: u64, prev: &str) -> Transaction {
    let mut tx = Transaction::new();
    tx.inputs_mut()
        .push(TransactionInput::new(prev.parse().unwrap(), 0));
    tx.outputs_mut().push(TransactionOutput::new(
        sats,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ));
    tx
}

/// The id of `tx`'s fields, no cache of `tx` read.
fn fields_id(tx: &Transaction) -> String {
    Transaction::from_parts(tx.clone().into_parts()).id()
}

/// A child whose input 0 is named by `txid` and linked to `first`, its
/// caches full; then `second` linked through the door.
fn linked_then_relinked(txid: Option<Txid>) -> (Transaction, bool) {
    let first = tx_paying(1_000, &"11".repeat(32));
    let second = tx_paying(2_000, &"22".repeat(32));
    let mut child = tx_paying(500, &"33".repeat(32));
    {
        let input = &mut child.inputs_mut()[0];
        input.source_txid = txid;
        input.source_transaction = Some(Box::new(first));
    }
    let _ = (child.id(), child.to_hex());
    let old = child.replace_source(0, Some(Box::new(second)));
    assert!(old.is_some(), "the door returns the source it held");
    let kept = child.with_cached_bytes(|bytes| bytes.is_some());
    (child, kept)
}

#[test]
fn a_link_under_a_txid_that_is_the_source_s_keeps_the_caches_and_the_law_869() {
    let second_id = tx_paying(2_000, &"22".repeat(32)).id();
    let (child, kept) = linked_then_relinked(Some(second_id.parse().unwrap()));
    assert_eq!(child.id(), fields_id(&child), "the law after the link");
    assert!(kept, "a named input: the caches kept");
}

#[test]
fn a_link_under_another_parsing_txid_keeps_the_caches_and_the_law_869() {
    let (child, kept) = linked_then_relinked(Some("44".repeat(32).parse().unwrap()));
    assert_eq!(child.id(), fields_id(&child), "the law after the link");
    assert!(kept, "a named input: the caches kept");
}

#[test]
fn a_link_with_no_txid_empties_the_caches_and_keeps_the_law_869() {
    let (child, kept) = linked_then_relinked(None);
    assert_eq!(child.id(), fields_id(&child), "the law after the link");
    assert!(!kept, "the bytes read the source: the caches emptied");
}

/// Until #845 a text that did not parse (`"zz"`, `""`, 62 digits) could be
/// held: the serializer read the source through it and the door emptied the
/// caches. No such text becomes a `Txid`, so the state is unbuildable and
/// every held txid is the `Named` arm.
#[test]
fn a_text_that_does_not_parse_is_no_txid_so_the_state_is_unbuildable_845() {
    for text in ["zz".to_string(), String::new(), "ab".repeat(31)] {
        assert!(Txid::from_hex(&text).is_err(), "{text:?}");
    }
}

#[test]
fn the_outpoint_rule_is_the_serializer_s_869() {
    let source = tx_paying(1_000, &"11".repeat(32));
    let mut input = TransactionInput::default();
    assert!(matches!(outpoint_txid(&input), OutpointTxid::Zero));
    assert_eq!(super::outpoint_txid_bytes(&input), [0; 32]);
    assert_eq!(super::outpoint_txid_name(&input), None);
    input.source_transaction = Some(Box::new(source.clone()));
    assert!(matches!(outpoint_txid(&input), OutpointTxid::Source(_)));
    assert_eq!(super::outpoint_txid_bytes(&input), source.hash());
    assert_eq!(super::outpoint_txid_name(&input), Some(source.id()));
    input.source_txid = Some("AB".repeat(32).parse().unwrap());
    assert!(matches!(outpoint_txid(&input), OutpointTxid::Named(_)));
    // The bytes `get_source_txid_bytes` gives, and the name in lower case.
    assert_eq!(
        super::outpoint_txid_bytes(&input),
        input.get_source_txid_bytes().unwrap()
    );
    assert_eq!(super::outpoint_txid_bytes(&input), [0xab; 32]);
    assert_eq!(super::outpoint_txid_name(&input), Some("ab".repeat(32)));
}

/// The `Named` arm is exactly the texts `Txid::from_hex` reads (64 hex
/// digits, the serializer's acceptance until #845), on every text length 0
/// to 70 of each character class and a sweep of single changes; every other
/// text is refused at the door and never reaches the serializer.
#[test]
fn the_named_arm_is_exactly_the_texts_a_txid_reads_869() {
    let source = tx_paying(1_000, &"11".repeat(32));
    let mut texts: Vec<String> = Vec::new();
    for len in 0..=70 {
        for c in ['0', 'a', 'F', 'g', ' ', 'é', 'x'] {
            texts.push(std::iter::repeat_n(c, len).collect());
        }
    }
    let base = "0123456789abcdefABCDEF".repeat(3)[..64].to_string();
    for at in 0..64 {
        for c in ['G', 'z', ' ', '-', '+', '\u{0}', 'é'] {
            let mut t: Vec<char> = base.chars().collect();
            t[at] = c;
            texts.push(t.into_iter().collect());
        }
    }
    texts.push(base);
    let mut read = 0;
    for text in texts {
        let sixty_four_digits = text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit());
        let Ok(txid) = Txid::from_hex(&text) else {
            assert!(!sixty_four_digits, "{text:?}");
            continue;
        };
        assert!(sixty_four_digits, "{text:?}");
        read += 1;
        let mut wire: [u8; 32] = hex::decode(&text).unwrap().try_into().unwrap();
        wire.reverse();
        let mut input = TransactionInput::new(txid, 0);
        assert!(matches!(outpoint_txid(&input), OutpointTxid::Named(_)));
        assert_eq!(super::outpoint_txid_bytes(&input), wire, "{text:?}");
        input.source_transaction = Some(Box::new(source.clone()));
        assert_eq!(super::outpoint_txid_bytes(&input), wire, "{text:?}");
    }
    assert_eq!(read, 4, "64 of '0', 'a', 'F' and the base");
}
