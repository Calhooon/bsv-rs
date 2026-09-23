//! Regression: every in-place mutator of `Script` must PARSE before it invalidates the byte
//! cache. On a `from_binary` script (raw bytes cached, chunks not yet parsed) the old order
//! `invalidate_caches(); ensure_parsed();` dropped the only source of chunks, so the script
//! came back EMPTY after `set_chunk_opcode` / `write_*` / `find_and_delete` /
//! `remove_codeseparators`. A mutation census downstream tested a zero-byte lock and read it as
//! a clean result (bolt-rs, 2026-08; btg-token #11).
use bsv_rs::script::Script;

fn p2pkh() -> Vec<u8> {
    let mut b = vec![0x76u8, 0xa9, 0x14];
    b.extend_from_slice(&[0x11u8; 20]);
    b.extend_from_slice(&[0x88, 0xac]);
    b
}

#[test]
fn set_chunk_opcode_on_a_from_binary_script_keeps_every_other_chunk() {
    let mut s = Script::from_binary(&p2pkh()).unwrap();
    s.set_chunk_opcode(4, 0xad); // OP_CHECKSIG -> OP_CHECKSIGVERIFY
    let out = s.to_binary();
    let mut want = p2pkh();
    *want.last_mut().unwrap() = 0xad;
    assert_eq!(
        out, want,
        "the mutated script must be the original bytes with one opcode changed"
    );
}

#[test]
fn write_opcode_on_a_from_binary_script_appends_after_the_original_chunks() {
    let mut s = Script::from_binary(&p2pkh()).unwrap();
    s.write_opcode(0x61); // OP_NOP
    let mut want = p2pkh();
    want.push(0x61);
    assert_eq!(s.to_binary(), want);
}

#[test]
fn write_bin_and_write_number_on_a_from_binary_script_keep_the_prefix() {
    let mut s = Script::from_binary(&p2pkh()).unwrap();
    s.write_bin(&[0xaa, 0xbb]);
    s.write_number(7);
    let out = s.to_binary();
    assert!(
        out.starts_with(&p2pkh()),
        "the original chunks must survive a write: {}",
        hex(&out)
    );
    assert!(out.len() > p2pkh().len() + 2);
}

#[test]
fn write_script_on_a_from_binary_script_keeps_the_prefix() {
    let mut s = Script::from_binary(&p2pkh()).unwrap();
    let tail = Script::from_binary(&[0x61u8, 0x61]).unwrap();
    s.write_script(&tail);
    let mut want = p2pkh();
    want.extend_from_slice(&[0x61, 0x61]);
    assert_eq!(s.to_binary(), want);
}

#[test]
fn find_and_delete_on_a_from_binary_script_keeps_the_rest() {
    let mut s = Script::from_binary(&p2pkh()).unwrap();
    let needle = Script::from_binary(&[0x88u8]).unwrap(); // OP_EQUALVERIFY
    s.find_and_delete(&needle);
    let out = s.to_binary();
    assert_eq!(
        out.len(),
        p2pkh().len() - 1,
        "exactly the deleted chunk is gone: {}",
        hex(&out)
    );
    assert!(out.starts_with(&p2pkh()[..23]));
    assert_eq!(*out.last().unwrap(), 0xac);
}

#[test]
fn remove_codeseparators_on_a_from_binary_script_keeps_the_rest() {
    let mut bytes = p2pkh();
    bytes.insert(3 + 20, 0xab); // an OP_CODESEPARATOR before OP_EQUALVERIFY
    let mut s = Script::from_binary(&bytes).unwrap();
    s.remove_codeseparators();
    assert_eq!(s.to_binary(), p2pkh());
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
