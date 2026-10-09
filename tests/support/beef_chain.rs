//! The P0-5 deep chain as a byte source that writes itself link by link, so a
//! reading of it holds no BEEF: `tx[0]` carries a BUMP and every `tx[i]`
//! spends `tx[i-1]:0` unproven, `OP_TRUE` locks spent by empty unlocks
//! (`tests/beef_deep_chain.rs`, bsv-stack-lean #57). The source's bytes are
//! the bytes `Beef::to_binary` writes for that chain (`beef_stream_deep.rs`
//! holds the two equal).
#![allow(dead_code)]

use std::io::Read;

use bsv_rs::primitives::sha256d;

pub type Hash32 = [u8; 32];

pub const SATS: u64 = 1_000;
pub const HEIGHT: u64 = 800_000;
const OP_TRUE: u8 = 0x51;

pub fn varint(n: u64) -> Vec<u8> {
    if n < 0xFD {
        vec![n as u8]
    } else if n < 0x1_0000 {
        let mut v = vec![0xFD];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n < 0x1_0000_0000 {
        let mut v = vec![0xFE];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xFF];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

/// A transaction spending `prev:0` with an empty unlock, paying `outputs`
/// `OP_TRUE` outputs of `SATS` each (the P0-5 `spend`).
pub fn spend(prev: &Hash32, outputs: usize) -> Vec<u8> {
    let mut v = 1u32.to_le_bytes().to_vec();
    v.push(1);
    v.extend_from_slice(prev);
    v.extend_from_slice(&0u32.to_le_bytes());
    v.push(0);
    v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    v.extend(varint(outputs as u64));
    for _ in 0..outputs {
        v.extend_from_slice(&SATS.to_le_bytes());
        v.push(1);
        v.push(OP_TRUE);
    }
    v.extend_from_slice(&0u32.to_le_bytes());
    v
}

/// The proven funding transaction of the P0-5 chain.
pub fn funding() -> Vec<u8> {
    spend(&[0xAA; 32], 2)
}

/// The funding transaction's txid: the root its one-leaf BUMP computes.
pub fn funding_root() -> Hash32 {
    sha256d(&funding())
}

/// The subject of the chain of `n` transactions: the last one's txid.
pub fn subject(n: usize) -> Hash32 {
    let mut prev = funding_root();
    for _ in 1..n {
        prev = sha256d(&spend(&prev, 1));
    }
    prev
}

/// The chain of `n` transactions as a BEEF V2, written as it is read.
pub struct ChainSource {
    n: usize,
    /// The transactions written so far.
    written: usize,
    prev: Hash32,
    piece: Vec<u8>,
    at: usize,
    /// The bytes handed out.
    pub total: u64,
}

impl ChainSource {
    pub fn new(n: usize) -> Self {
        assert!(n >= 1);
        // The version word, one BUMP (the coinbase shape: one level, the one
        // leaf at offset 0 flagged as a txid), the transaction count.
        let mut piece = 0xEFBE_0002u32.to_le_bytes().to_vec();
        piece.push(1);
        piece.extend(varint(HEIGHT));
        piece.extend_from_slice(&[1, 1, 0, 2]);
        piece.extend_from_slice(&funding_root());
        piece.extend(varint(n as u64));
        Self {
            n,
            written: 0,
            prev: [0u8; 32],
            piece,
            at: 0,
            total: 0,
        }
    }

    /// The source positioned at `offset`: the rest of the same BEEF.
    pub fn from_offset(n: usize, offset: u64) -> Self {
        let mut source = Self::new(n);
        std::io::copy(&mut (&mut source).take(offset), &mut std::io::sink()).unwrap();
        source
    }

    fn next_piece(&mut self) -> bool {
        if self.written == self.n {
            return false;
        }
        self.piece.clear();
        self.at = 0;
        let raw = if self.written == 0 {
            // The funding transaction, format 1 with BUMP index 0.
            self.piece.extend_from_slice(&[1, 0]);
            funding()
        } else {
            self.piece.push(0);
            spend(&self.prev, 1)
        };
        self.prev = sha256d(&raw);
        self.piece.extend_from_slice(&raw);
        self.written += 1;
        true
    }
}

impl Read for ChainSource {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut n = 0;
        while n < buf.len() {
            if self.at == self.piece.len() && !self.next_piece() {
                break;
            }
            let take = (buf.len() - n).min(self.piece.len() - self.at);
            buf[n..n + take].copy_from_slice(&self.piece[self.at..self.at + take]);
            self.at += take;
            n += take;
        }
        self.total += n as u64;
        Ok(n)
    }
}
