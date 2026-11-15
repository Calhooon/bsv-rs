//! The template classifiers answer by the template's bytes.
//!
//! `Script::is_p2pkh`, `is_p2pk`, `is_p2sh` and `is_multisig`, and the readers
//! built on them (`extract_pubkey_hash`, `get_public_key`,
//! `get_public_key_hex`, `LockingScript::to_address`), say yes to a script only
//! when every push the template holds is made by the opcode that is its length,
//! the one form this crate's writers emit: P2PKH is 25 bytes with `0x14` at
//! offset 2, P2SH 23 bytes with `0x14` at offset 1, a P2PK key and each
//! multisig key a `0x21` or `0x41` push. A script that frames the same data by
//! `OP_PUSHDATA1`, `OP_PUSHDATA2` or `OP_PUSHDATA4` is another script and is
//! not the template; until this fix each classifier read the data's length
//! alone and said yes to it.
//!
//! The cells: the other framings through every door (RED before the fix); a
//! push of a length the template does not hold, by its own opcode, through
//! every door; the writers' forms through every door (unchanged); 20,000
//! honest scripts through every door, the answers' digest pinned, equal on the
//! tree before the fix and after it; and the invariant as a property over
//! generated scripts, each template in its writer's form and in the three
//! other framings, with a floor per shape (RED before the fix).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a failed unwrap is the test failing

use bsv_rs::primitives::ec::PrivateKey;
use bsv_rs::primitives::{sha256, to_hex};
use bsv_rs::script::op::{
    OP_CHECKMULTISIG, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_PUSHDATA1,
    OP_PUSHDATA2, OP_PUSHDATA4,
};
use bsv_rs::script::templates::{Multisig, PushDrop, P2PK, P2PKH};
use bsv_rs::script::{LockingScript, Script, ScriptTemplate};

/// A deterministic generator (xorshift64).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.below(256) as u8).collect()
    }
}

/// A push of `data` framed by `op`: the length itself (1 to 75), or
/// `OP_PUSHDATA1`/`2`/`4` with its little-endian length.
fn push(op: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![op];
    match op {
        OP_PUSHDATA1 => out.push(data.len() as u8),
        OP_PUSHDATA2 => out.extend_from_slice(&(data.len() as u16).to_le_bytes()),
        OP_PUSHDATA4 => out.extend_from_slice(&(data.len() as u32).to_le_bytes()),
        _ => assert_eq!(op as usize, data.len()),
    }
    out.extend_from_slice(data);
    out
}

const OTHER_FRAMINGS: [u8; 3] = [OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4];

fn p2pkh_bytes(op: u8, hash: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![OP_DUP, OP_HASH160];
    s.extend(push(op, hash));
    s.extend([OP_EQUALVERIFY, OP_CHECKSIG]);
    s
}

fn p2sh_bytes(op: u8, hash: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![OP_HASH160];
    s.extend(push(op, hash));
    s.push(OP_EQUAL);
    s
}

fn p2pk_bytes(op: u8, key: &[u8]) -> Vec<u8> {
    let mut s = push(op, key);
    s.push(OP_CHECKSIG);
    s
}

/// `OP_m <keys> OP_n OP_CHECKMULTISIG`, the key at `odd` framed by `op`, the
/// others by their length.
fn multisig_bytes(m: u8, keys: &[Vec<u8>], odd: usize, op: u8) -> Vec<u8> {
    let mut s = vec![0x50 + m];
    for (i, k) in keys.iter().enumerate() {
        let framing = if i == odd { op } else { k.len() as u8 };
        s.extend(push(framing, k));
    }
    s.push(0x50 + keys.len() as u8);
    s.push(OP_CHECKMULTISIG);
    s
}

fn key(seed: u8) -> PrivateKey {
    let mut b = [0u8; 32];
    b[31] = seed;
    b[0] = 0x11;
    PrivateKey::from_bytes(&b).unwrap()
}

fn locking(bytes: &[u8]) -> LockingScript {
    LockingScript::from_binary(bytes).unwrap()
}

/// Every door the fix touches, its answer as one line.
fn answers(script: &LockingScript) -> String {
    let s: &Script = script.as_script();
    format!(
        "p2pkh={} p2pk={} p2sh={} multisig={:?} hash={:?} key={:?} keyhex={:?} address={:?}",
        s.is_p2pkh(),
        s.is_p2pk(),
        s.is_p2sh(),
        s.is_multisig(),
        s.extract_pubkey_hash().map(|h| to_hex(&h)),
        s.get_public_key().map(|k| to_hex(&k)),
        s.get_public_key_hex(),
        script.to_address().map(|a| a.to_string()),
    )
}

const NONE_OF_THEM: &str =
    "p2pkh=false p2pk=false p2sh=false multisig=None hash=None key=None keyhex=None address=None";

#[test]
fn a_p2pkh_hash_framed_by_another_push_opcode_is_not_p2pkh_at_any_door() {
    let hash = key(1).public_key().hash160();
    for op in OTHER_FRAMINGS {
        let script = locking(&p2pkh_bytes(op, &hash));
        assert_eq!(answers(&script), NONE_OF_THEM, "framing 0x{op:02x}");
    }
}

#[test]
fn a_p2pk_key_framed_by_another_push_opcode_is_not_p2pk_at_any_door() {
    let pk = key(2).public_key();
    for k in [pk.to_compressed().to_vec(), pk.to_uncompressed().to_vec()] {
        for op in OTHER_FRAMINGS {
            let script = locking(&p2pk_bytes(op, &k));
            assert_eq!(
                answers(&script),
                NONE_OF_THEM,
                "{}-byte key, 0x{op:02x}",
                k.len()
            );
        }
    }
}

#[test]
fn a_p2sh_hash_framed_by_another_push_opcode_is_not_p2sh() {
    let hash = [0x5au8; 20];
    for op in OTHER_FRAMINGS {
        let script = locking(&p2sh_bytes(op, &hash));
        assert_eq!(answers(&script), NONE_OF_THEM, "framing 0x{op:02x}");
    }
}

#[test]
fn a_multisig_with_one_key_framed_by_another_push_opcode_is_not_multisig() {
    let keys: Vec<Vec<u8>> = (3..6)
        .map(|i| key(i).public_key().to_compressed().to_vec())
        .collect();
    for odd in 0..keys.len() {
        for op in OTHER_FRAMINGS {
            let script = locking(&multisig_bytes(2, &keys, odd, op));
            assert_eq!(answers(&script), NONE_OF_THEM, "key {odd}, 0x{op:02x}");
        }
    }
}

/// The length half of each template: a push made by the opcode that is its
/// length, of any length the template does not hold (1 to 75 bytes), is no
/// template at any door: a P2PKH or P2SH "hash" of 19 or 21 bytes, a P2PK
/// "key" of 32 bytes, a multisig whose key at any position is of another
/// length.
#[test]
fn a_template_push_of_another_length_by_its_own_opcode_is_no_template_at_any_door() {
    let keys: Vec<Vec<u8>> = (12..15)
        .map(|i| key(i).public_key().to_compressed().to_vec())
        .collect();
    for len in 1u8..=75 {
        let data = vec![0xa5u8; usize::from(len)];
        if len != 20 {
            let mut p2pkh = vec![OP_DUP, OP_HASH160];
            p2pkh.extend(push(len, &data));
            p2pkh.extend([OP_EQUALVERIFY, OP_CHECKSIG]);
            assert_eq!(answers(&locking(&p2pkh)), NONE_OF_THEM, "p2pkh, {len}");
            let mut p2sh = vec![OP_HASH160];
            p2sh.extend(push(len, &data));
            p2sh.push(OP_EQUAL);
            assert_eq!(answers(&locking(&p2sh)), NONE_OF_THEM, "p2sh, {len}");
        }
        if len != 33 && len != 65 {
            let p2pk = locking(&p2pk_bytes(len, &data));
            assert_eq!(answers(&p2pk), NONE_OF_THEM, "p2pk, {len}");
            for odd in 0..keys.len() {
                let mut ks = keys.clone();
                ks[odd] = data.clone();
                let ms = locking(&multisig_bytes(2, &ks, usize::MAX, 0));
                assert_eq!(answers(&ms), NONE_OF_THEM, "multisig key {odd}, {len}");
            }
        }
    }
}

#[test]
fn the_writers_forms_still_classify_at_every_door() {
    let pk = key(7).public_key();
    let hash = pk.hash160();

    let p2pkh = P2PKH::new().lock(&hash).unwrap();
    assert_eq!(p2pkh.to_binary(), p2pkh_bytes(20, &hash));
    assert!(p2pkh.as_script().is_p2pkh());
    assert_eq!(p2pkh.as_script().extract_pubkey_hash(), Some(hash));
    assert_eq!(p2pkh.to_address().unwrap().to_string(), pk.to_address());

    for k in [pk.to_compressed().to_vec(), pk.to_uncompressed().to_vec()] {
        let p2pk = P2PK::new().lock(&k).unwrap();
        assert_eq!(p2pk.to_binary(), p2pk_bytes(k.len() as u8, &k));
        assert!(p2pk.as_script().is_p2pk());
        assert_eq!(p2pk.as_script().get_public_key(), Some(k.clone()));
        assert_eq!(p2pk.as_script().get_public_key_hex(), Some(to_hex(&k)));
    }

    let p2sh = locking(&p2sh_bytes(20, &hash));
    assert!(p2sh.as_script().is_p2sh());

    let keys: Vec<_> = (8..11).map(|i| key(i).public_key()).collect();
    let ms = Multisig::new(2).lock_from_keys(&keys).unwrap();
    assert_eq!(ms.as_script().is_multisig(), Some((2, 3)));
    let long: Vec<Vec<u8>> = keys.iter().map(|k| k.to_uncompressed().to_vec()).collect();
    let ms65 = locking(&multisig_bytes(1, &long, usize::MAX, 0));
    assert_eq!(ms65.as_script().is_multisig(), Some((1, 3)));
}

/// One honest script of the kinds the doors take: each template as this
/// crate's writers write it, data carriers, push-only scripts and arbitrary
/// bytes.
fn honest_script(r: &mut Rng, keys: &[PrivateKey]) -> Option<LockingScript> {
    let pick = |r: &mut Rng| keys[r.below(keys.len() as u64) as usize].public_key();
    Some(match r.below(8) {
        0 => P2PKH::new().lock(&pick(r).hash160()).unwrap(),
        1 => P2PK::new().lock(&pick(r).to_compressed()).unwrap(),
        2 => P2PK::new().lock(&pick(r).to_uncompressed()).unwrap(),
        3 => {
            let h: [u8; 20] = r.bytes(20).try_into().unwrap();
            locking(&p2sh_bytes(20, &h))
        }
        4 => {
            let n = 1 + r.below(5) as usize;
            let ks: Vec<_> = (0..n).map(|_| pick(r)).collect();
            let m = 1 + r.below(n as u64) as u8;
            Multisig::new(m).lock_from_keys(&ks).unwrap()
        }
        5 => {
            let mut s = Script::new();
            s.write_opcode(0).write_opcode(0x6a);
            let len = r.below(120) as usize;
            s.write_bin(&r.bytes(len));
            LockingScript::from_script(s)
        }
        6 => {
            let mut s = Script::new();
            for _ in 0..1 + r.below(4) {
                let len = r.below(300) as usize;
                s.write_bin(&r.bytes(len));
            }
            if r.below(2) == 0 {
                s.write_opcode(OP_CHECKSIG);
            }
            LockingScript::from_script(s)
        }
        _ => {
            let len = r.below(40) as usize;
            return LockingScript::from_binary(&r.bytes(len)).ok();
        }
    })
}

/// The answers of every door on 20,000 honest scripts, as one digest: the
/// same on the tree before the fix and after it (`HONEST_DIGEST` was read on
/// both).
const HONEST_DIGEST: &str = "e3d138f0e74b93c431239682018c0064c5e4b722dbe09bc228884f2cfcca31ec";

#[test]
fn twenty_thousand_honest_scripts_answer_as_before_at_every_door() {
    let keys: Vec<PrivateKey> = (1..=24).map(key).collect();
    let mut r = Rng(0x7e3a_11b5_c0de_2311);
    let mut all = Vec::new();
    let mut read = 0usize;
    let mut classified = [0usize; 4];
    while read < 20_000 {
        let Some(script) = honest_script(&mut r, &keys) else {
            continue;
        };
        let s = script.as_script();
        classified[0] += usize::from(s.is_p2pkh());
        classified[1] += usize::from(s.is_p2pk());
        classified[2] += usize::from(s.is_p2sh());
        classified[3] += usize::from(s.is_multisig().is_some());
        all.extend_from_slice(answers(&script).as_bytes());
        all.push(b'|');
        // PushDrop's reader is not one of the doors the fix touches; its
        // answer is in the digest so that a change to it shows here too.
        all.extend_from_slice(format!("{:?}", PushDrop::decode(&script).is_ok()).as_bytes());
        all.push(b'\n');
        read += 1;
    }
    for (i, n) in classified.iter().enumerate() {
        assert!(*n >= 1_500, "template {i} classified only {n} times");
    }
    assert_eq!(to_hex(&sha256(&all)), HONEST_DIGEST);
}

#[test]
fn a_classifier_says_yes_only_to_the_writers_bytes_over_generated_scripts() {
    let keys: Vec<PrivateKey> = (1..=16).map(key).collect();
    let mut r = Rng(0x0b17_e5f0_7e3a_2311);
    // Per shape: [writer's form seen, other framing seen].
    let mut seen = [[0usize; 2]; 4];
    for _ in 0..4_000 {
        let shape = r.below(4) as usize;
        let other = r.below(2) == 1;
        let op = OTHER_FRAMINGS[r.below(3) as usize];
        let pk = keys[r.below(keys.len() as u64) as usize].public_key();
        let (bytes, writer): (Vec<u8>, Vec<u8>) = match shape {
            0 => {
                let h = pk.hash160();
                let w = P2PKH::new().lock(&h).unwrap().to_binary();
                (
                    if other {
                        p2pkh_bytes(op, &h)
                    } else {
                        w.clone()
                    },
                    w,
                )
            }
            1 => {
                let k = if r.below(2) == 0 {
                    pk.to_compressed().to_vec()
                } else {
                    pk.to_uncompressed().to_vec()
                };
                let w = P2PK::new().lock(&k).unwrap().to_binary();
                (if other { p2pk_bytes(op, &k) } else { w.clone() }, w)
            }
            2 => {
                let h: [u8; 20] = r.bytes(20).try_into().unwrap();
                let w = p2sh_bytes(20, &h);
                (if other { p2sh_bytes(op, &h) } else { w.clone() }, w)
            }
            _ => {
                let n = 1 + r.below(4) as usize;
                let ks: Vec<Vec<u8>> = (0..n)
                    .map(|_| {
                        keys[r.below(keys.len() as u64) as usize]
                            .public_key()
                            .to_compressed()
                            .to_vec()
                    })
                    .collect();
                let odd = if other {
                    r.below(n as u64) as usize
                } else {
                    usize::MAX
                };
                let w = multisig_bytes(1, &ks, usize::MAX, 0);
                (multisig_bytes(1, &ks, odd, op), w)
            }
        };
        let s = locking(&bytes);
        let yes = match shape {
            0 => s.as_script().is_p2pkh() && s.to_address().is_some(),
            1 => s.as_script().is_p2pk() && s.as_script().get_public_key().is_some(),
            2 => s.as_script().is_p2sh(),
            _ => s.as_script().is_multisig().is_some(),
        };
        assert_eq!(
            yes,
            bytes == writer,
            "shape {shape}, other framing {other}: {}",
            to_hex(&bytes)
        );
        seen[shape][usize::from(other)] += 1;
    }
    for (shape, counts) in seen.iter().enumerate() {
        assert!(
            counts[0] >= 300 && counts[1] >= 300,
            "shape {shape} under its floor: {counts:?}"
        );
    }
}
