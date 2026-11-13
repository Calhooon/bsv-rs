//! #843d1, the cache law for `Script`: its chunks, its bytes and its hex
//! always agree, with no duty on the caller.
//!
//! `Script` holds its chunks and the two serializations in `OnceLock`s whose
//! fields only `src/script/script_cache.rs` can name, every edit going
//! through its one write door. The compiler holds that no code reaches the
//! chunks mutably without the serializations emptied; this file holds that
//! each cache is FILLED with the right value. A seeded property: scripts built
//! by `from_chunks`, `from_binary`, `from_hex` and `from_asm` over generated
//! bytes (truncated pushes, a folded `OP_RETURN`, a stray `OP_ENDIF`, chunks
//! whose opcode and data disagree as #661's do), each read in a random order
//! of `chunks()`, `to_binary()`, `to_hex()`, `to_asm()` and `clone()`, then
//! edited by a random run of the seven write doors with reads between (one
//! script in three edited before any read). The
//! law after every read:
//!
//! - `to_hex()` is the hex of `to_binary()`;
//! - before any edit, `to_binary()` is the bytes given (`from_binary`,
//!   `from_hex`; the reference's `Script.ts:529`), or the chunks' serialization
//!   (`from_chunks`, `from_asm`);
//! - after any edit, `to_binary()` is `Script::from_chunks(s.chunks().to_vec())
//!   .to_binary()`;
//! - a clone answers as its source did when it was taken and does not move
//!   with it;
//! - after each edit, the script answers the bytes of a shadow held as its
//!   chunks and given the same edits (the door parses before it empties).
//!
//! Each door, builder and read is counted over the run and held to a floor.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code

use std::collections::BTreeMap;

use bsv_rs::primitives::to_hex;
use bsv_rs::script::{Script, ScriptChunk};

/// The seed of the property run; a failure prints it with the step.
const SEED: u64 = 0x0843_d1ca_c4e0_0001;
/// Scripts in the property run.
const SCRIPTS: usize = 4_000;
/// The most edits per script.
const EDITS: u64 = 6;
/// The least each counted act may happen over the run.
const FLOOR: usize = 200;

/// xorshift64*: the test's own generator, reproducible from its seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }

    /// Script bytes: opcodes, complete and truncated pushes of each form, a
    /// conditional, a stray `OP_ENDIF`, an `OP_RETURN` with data after it.
    fn script_bytes(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..self.below(8) {
            match self.below(10) {
                0 => out.push(0x6a), // OP_RETURN: folds the rest at depth 0
                1 => out.push([0x63, 0x64, 0x67, 0x68][self.below(4) as usize]), // IF NOTIF ELSE ENDIF
                2 => {
                    let n = 1 + self.below(75) as usize;
                    out.push(n as u8);
                    let have = if self.below(5) == 0 {
                        self.below(n as u64) as usize
                    } else {
                        n
                    };
                    out.extend(self.bytes(have)); // truncated one time in five
                }
                3 => {
                    let n = self.below(80) as usize;
                    out.extend([0x4c, n as u8]);
                    let have = if self.below(5) == 0 {
                        self.below(n as u64 + 1) as usize
                    } else {
                        n
                    };
                    out.extend(self.bytes(have));
                }
                4 => {
                    let n = 256 + self.below(60) as usize;
                    out.extend([0x4d, n as u8, (n >> 8) as u8]);
                    out.extend(self.bytes(n));
                }
                5 => out.extend([0x4e, self.byte(), 0, 0, 0]), // PUSHDATA4, usually cut short
                6 => out.push(0x4c),                           // a bare PUSHDATA1
                _ => out.push(self.byte()),
            }
        }
        out
    }

    /// Chunks as a caller builds them by hand, opcode and data agreeing or not (#661).
    fn chunks(&mut self) -> Vec<ScriptChunk> {
        (0..self.below(6))
            .map(|_| match self.below(4) {
                0 => ScriptChunk::new_opcode(self.byte()),
                1 => {
                    let n = self.below(90) as usize;
                    ScriptChunk::new_push(self.bytes(n))
                }
                2 => {
                    let op = self.byte();
                    let n = self.below(4) as usize;
                    ScriptChunk::new(op, Some(self.bytes(n)))
                }
                _ => {
                    let n = self.below(4) as usize;
                    ScriptChunk::new(0x6a, Some(self.bytes(n)))
                }
            })
            .collect()
    }
}

/// What a script answered before any edit: the bytes given, or `None` when it
/// was built from chunks.
#[derive(Clone)]
struct Origin {
    given: Option<Vec<u8>>,
}

struct Run {
    rng: Rng,
    counts: BTreeMap<&'static str, usize>,
}

impl Run {
    fn count(&mut self, what: &'static str) {
        *self.counts.entry(what).or_default() += 1;
    }

    /// The law on `s` at `at`.
    fn judge(&self, s: &Script, edited: bool, origin: &Origin, at: &str) {
        let bytes = s.to_binary();
        assert_eq!(
            s.to_hex(),
            to_hex(&bytes),
            "seed {SEED:#x}, {at}: the hex is the bytes'"
        );
        let chunks_bytes = Script::from_chunks(s.chunks().to_vec()).to_binary();
        match (&origin.given, edited) {
            (Some(given), false) => {
                assert_eq!(&bytes, given, "seed {SEED:#x}, {at}: the bytes given")
            }
            _ => assert_eq!(
                bytes, chunks_bytes,
                "seed {SEED:#x}, {at}: the chunks' bytes"
            ),
        }
    }

    /// The five reads in a random order, the law after each; clones kept with
    /// what their source answered.
    fn reads(
        &mut self,
        s: &Script,
        edited: bool,
        origin: &Origin,
        clones: &mut Vec<(Script, Vec<u8>, String, Vec<ScriptChunk>)>,
        at: &str,
    ) {
        let mut order = [0u8, 1, 2, 3, 4];
        for i in (1..order.len()).rev() {
            order.swap(i, self.rng.below(i as u64 + 1) as usize);
        }
        for read in order {
            match read {
                0 => {
                    self.count("read chunks");
                    let _ = s.chunks().len();
                }
                1 => {
                    self.count("read to_binary");
                    let _ = s.to_binary();
                }
                2 => {
                    self.count("read to_hex");
                    let _ = s.to_hex();
                }
                3 => {
                    self.count("read to_asm");
                    let _ = s.to_asm();
                }
                _ => {
                    self.count("read clone");
                    let c = s.clone();
                    assert_eq!(
                        c.to_binary(),
                        s.to_binary(),
                        "seed {SEED:#x}, {at}: a clone's bytes"
                    );
                    assert_eq!(
                        c.to_hex(),
                        s.to_hex(),
                        "seed {SEED:#x}, {at}: a clone's hex"
                    );
                    assert_eq!(
                        c.chunks(),
                        s.chunks(),
                        "seed {SEED:#x}, {at}: a clone's chunks"
                    );
                    clones.push((c, s.to_binary(), s.to_hex(), s.chunks().to_vec()));
                }
            }
            self.judge(s, edited, origin, &format!("{at}, after read {read}"));
        }
    }

    /// One script built by a random builder.
    fn build(&mut self) -> (Script, Origin) {
        match self.rng.below(4) {
            0 => {
                self.count("build from_binary");
                let bytes = self.rng.script_bytes();
                (
                    Script::from_binary(&bytes).unwrap(),
                    Origin { given: Some(bytes) },
                )
            }
            1 => {
                self.count("build from_hex");
                let bytes = self.rng.script_bytes();
                let hex = to_hex(&bytes);
                let text = if self.rng.below(2) == 0 {
                    hex.to_uppercase()
                } else {
                    hex
                };
                let s = Script::from_hex(&text).unwrap();
                assert_eq!(
                    s.to_hex(),
                    text.to_lowercase(),
                    "seed {SEED:#x}: the hex given"
                );
                (s, Origin { given: Some(bytes) })
            }
            2 => {
                self.count("build from_chunks");
                (
                    Script::from_chunks(self.rng.chunks()),
                    Origin { given: None },
                )
            }
            _ => {
                let bytes = self.rng.script_bytes();
                match Script::from_asm(&Script::from_binary(&bytes).unwrap().to_asm()) {
                    Ok(s) => {
                        self.count("build from_asm");
                        (s, Origin { given: None })
                    }
                    Err(_) => {
                        self.count("build from_asm refused");
                        (
                            Script::from_binary(&bytes).unwrap(),
                            Origin { given: Some(bytes) },
                        )
                    }
                }
            }
        }
    }

    /// One of the seven write doors on `s` and the same on `shadow`, its
    /// arguments read from `shadow` alone, so `s` goes to the door as it was.
    fn edit(&mut self, s: &mut Script, shadow: &mut Script) -> &'static str {
        match self.rng.below(7) {
            0 => {
                let (other, _) = self.build();
                let twin = other.clone();
                s.write_script(&other);
                shadow.write_script(&twin);
                "write_script"
            }
            1 => {
                let op = self.rng.byte();
                s.write_opcode(op);
                shadow.write_opcode(op);
                "write_opcode"
            }
            2 => {
                let n = [0, 1, 75, 76, 255, 256, 300][self.rng.below(7) as usize];
                let data = self.rng.bytes(n);
                s.write_bin(&data);
                shadow.write_bin(&data);
                "write_bin"
            }
            3 => {
                let num = self.rng.next() as i64 >> self.rng.below(64);
                s.write_number(num);
                shadow.write_number(num);
                "write_number"
            }
            4 => {
                s.remove_codeseparators();
                shadow.remove_codeseparators();
                "remove_codeseparators"
            }
            5 => {
                let at = self.rng.below(shadow.len() as u64 + 1) as usize;
                let target = match shadow.chunks().get(at) {
                    Some(chunk) => Script::from_chunks(vec![chunk.clone()]),
                    None => Script::from_binary(&[0xab]).unwrap(),
                };
                s.find_and_delete(&target);
                shadow.find_and_delete(&target);
                "find_and_delete"
            }
            _ => {
                let at = self.rng.below(shadow.len() as u64 + 2) as usize;
                let op = self.rng.byte();
                s.set_chunk_opcode(at, op);
                shadow.set_chunk_opcode(at, op);
                "set_chunk_opcode"
            }
        }
    }
}

#[test]
fn every_read_of_a_script_agrees_with_its_chunks_through_every_door_843d1() {
    let mut run = Run {
        rng: Rng(SEED),
        counts: BTreeMap::new(),
    };
    for n in 0..SCRIPTS {
        let (mut s, origin) = run.build();
        // the same script held as its chunks, read before every edit: the
        // edited script must answer what it answers
        let mut shadow = Script::from_chunks(s.clone().chunks().to_vec());
        let mut clones = Vec::new();
        // one script in three is edited before any read: the door must
        // parse the bytes given before it empties them
        if run.rng.below(3) == 0 {
            run.count("edit unread");
        } else {
            run.reads(
                &s,
                false,
                &origin,
                &mut clones,
                &format!("script {n}, built"),
            );
        }
        let edits = 1 + run.rng.below(EDITS);
        for k in 0..edits {
            let door = run.edit(&mut s, &mut shadow);
            run.count(door);
            assert_eq!(
                s.to_binary(),
                shadow.to_binary(),
                "seed {SEED:#x}, script {n}, edit {k} ({door}): the edit kept the chunks it was given"
            );
            run.judge(&s, true, &origin, &format!("script {n}, edit {k} ({door})"));
            run.reads(
                &s,
                true,
                &origin,
                &mut clones,
                &format!("script {n}, after edit {k} ({door})"),
            );
        }
        for (c, bytes, hex, chunks) in &clones {
            assert_eq!(
                &c.to_binary(),
                bytes,
                "seed {SEED:#x}, script {n}: a clone moved"
            );
            assert_eq!(
                &c.to_hex(),
                hex,
                "seed {SEED:#x}, script {n}: a clone's hex moved"
            );
            assert_eq!(
                c.chunks(),
                &chunks[..],
                "seed {SEED:#x}, script {n}: a clone's chunks moved"
            );
        }
    }
    let short: Vec<String> = [
        "build from_binary",
        "build from_hex",
        "build from_chunks",
        "build from_asm",
        "edit unread",
        "read chunks",
        "read to_binary",
        "read to_hex",
        "read to_asm",
        "read clone",
        "write_script",
        "write_opcode",
        "write_bin",
        "write_number",
        "remove_codeseparators",
        "find_and_delete",
        "set_chunk_opcode",
    ]
    .iter()
    .filter(|what| run.counts.get(*what).copied().unwrap_or(0) < FLOOR)
    .map(|what| format!("{what}: {}", run.counts.get(what).copied().unwrap_or(0)))
    .collect();
    assert!(
        short.is_empty(),
        "seed {SEED:#x}: the reach fell below {FLOOR}: {short:?}"
    );
}

/// The write door parses before it empties the bytes: a script read from
/// bytes and edited at once keeps its chunks (btg-token #11's order, at every
/// door), and its bytes after the edit are its chunks'.
#[test]
fn an_edit_of_an_unread_script_keeps_the_chunks_it_was_given_843d1() {
    let given = [0x76, 0xa9, 0x01, 0x07];
    type Door = (&'static str, fn(&mut Script));
    let doors: [Door; 7] = [
        ("write_script", |s| {
            s.write_script(&Script::from_binary(&[0x87]).unwrap());
        }),
        ("write_opcode", |s| {
            s.write_opcode(0x87);
        }),
        ("write_bin", |s| {
            s.write_bin(&[0x09]);
        }),
        ("write_number", |s| {
            s.write_number(5);
        }),
        ("remove_codeseparators", |s| {
            s.remove_codeseparators();
        }),
        ("find_and_delete", |s| {
            s.find_and_delete(&Script::from_binary(&[0xab]).unwrap());
        }),
        ("set_chunk_opcode", |s| {
            s.set_chunk_opcode(3, 0x87);
        }),
    ];
    for (door, edit) in doors {
        for read_first in [false, true] {
            let mut s = Script::from_binary(&given).unwrap();
            if read_first {
                assert_eq!(s.to_binary(), given);
                assert_eq!(s.to_hex(), to_hex(&given), "{door}: the hex read first");
            }
            edit(&mut s);
            let bytes = s.to_binary();
            assert!(
                bytes.starts_with(&given),
                "{door}: the chunks given kept: {}",
                to_hex(&bytes)
            );
            assert_eq!(
                bytes,
                Script::from_chunks(s.chunks().to_vec()).to_binary(),
                "{door}"
            );
            assert_eq!(s.to_hex(), to_hex(&bytes), "{door}");
        }
    }
}

/// `Debug` of a script prints the cache's three members as they stand, the
/// text `CHANGELOG.md` states (#843d1's fold, the strength read's line): read
/// from bytes, the bytes alone; each read fills its own member; an edit leaves
/// the chunks alone.
#[test]
fn a_script_debug_prints_the_cache_as_it_stands_843d1() {
    let mut s = Script::from_binary(&[0x51]).unwrap();
    assert_eq!(
        format!("{s:?}"),
        "Script { cache: Cache { chunks: None, bytes: Some([81]), hex: None } }"
    );
    assert_eq!(s.to_hex(), "51");
    assert_eq!(
        format!("{s:?}"),
        "Script { cache: Cache { chunks: None, bytes: Some([81]), hex: Some(\"51\") } }"
    );
    assert_eq!(s.chunks().len(), 1);
    assert_eq!(
        format!("{s:?}"),
        "Script { cache: Cache { chunks: Some([ScriptChunk { op: 81, data: None }]), \
         bytes: Some([81]), hex: Some(\"51\") } }"
    );
    s.write_opcode(0x87);
    assert_eq!(
        format!("{s:?}"),
        "Script { cache: Cache { chunks: Some([ScriptChunk { op: 81, data: None }, \
         ScriptChunk { op: 135, data: None }]), bytes: None, hex: None } }"
    );
}
