//! Whether bytes are exactly one transaction (#817): the framing
//! `BeefTx::from_raw_tx` (so `Beef::merge_raw_tx`) and the BEEF writers'
//! check read before they hold or write a raw entry.
//!
//! A raw entry has no length prefix in a BEEF, so bytes that are not one
//! transaction (cut short, or with bytes after the lock time) misframe every
//! element written after them. The scan reads what the reference's
//! `scanRawTransaction` reads, in its order and with its refusals' words
//! (`ts-stack@edf6e03` `BeefTx.ts:16-48`: `skipBytes`,
//! `readVarIntNumStrict(false)` in `readVarIntNumStrict.ts`, the
//! `ReaderUint8Array` reads), varints and lengths only, linear in the bytes
//! and allocating nothing; this crate's transaction reader takes exactly the
//! bytes it accepts (`a_frame_the_scan_accepts_is_the_one_the_parser_reads_817`).
//! Bytes after the lock time are refused in this crate's words: the
//! reference's scan reads a prefix and its door keeps the whole buffer, which
//! its writer then writes as a frame no reader reads back (a stated row).

/// The reference's `skipBytes` refusal (`BeefTx.ts:16-19`).
pub(crate) const EXCEEDS: &str = "Serialized transaction exceeds available BEEF data";
/// The reference's `ReaderUint8Array` read refusal (`ReaderUint8Array.ts:46`).
pub(crate) const READ_EXCEEDS: &str = "ReaderUint8Array read exceeds available data";
/// `readVarIntNumStrict`'s refusal of a varint in a longer form than its value needs.
pub(crate) const NON_CANONICAL: &str = "non-canonical varInt";
/// `readVarIntNumStrict`'s refusal of a value past 2^53 - 1.
pub(crate) const TOO_LARGE: &str = "number too large to retain precision - use readVarIntBn";

/// The largest integer a JavaScript number holds exactly (`Number.MAX_SAFE_INTEGER`).
const MAX_SAFE: u64 = (1 << 53) - 1;

/// The scan's position in the bytes.
struct Scan<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Scan<'_> {
    /// `skipBytes`: `n` bytes, else [`EXCEEDS`].
    fn skip(&mut self, n: u64) -> Result<(), &'static str> {
        let left = (self.bytes.len() - self.pos) as u64;
        if n > MAX_SAFE || n > left {
            return Err(EXCEEDS);
        }
        self.pos += n as usize;
        Ok(())
    }

    /// A fixed read (`readUInt8`, `readUInt16LE`, `readReverse(32)`, ...):
    /// `n` bytes, else [`READ_EXCEEDS`].
    fn read(&mut self, n: usize) -> Result<&[u8], &'static str> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.bytes.len());
        let end = end.ok_or(READ_EXCEEDS)?;
        let read = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(read)
    }

    /// `readVarIntNumStrict(false)`.
    fn var_int(&mut self) -> Result<u64, &'static str> {
        let little = |b: &[u8]| b.iter().rev().fold(0u64, |v, &x| (v << 8) | u64::from(x));
        let first = self.read(1)?[0];
        let (value, least) = match first {
            0xfd => (little(self.read(2)?), 0xfd),
            0xfe => (little(self.read(4)?), 0x1_0000),
            0xff => (little(self.read(8)?), 0x1_0000_0000),
            small => return Ok(u64::from(small)),
        };
        if value < least {
            return Err(NON_CANONICAL);
        }
        if value > MAX_SAFE {
            return Err(TOO_LARGE);
        }
        Ok(value)
    }
}

/// `Ok` when `bytes` are exactly one transaction, else the earliest refusal:
/// the reference scan's words where it refuses, `Serialized transaction has
/// N bytes after its lock time` where its scan stops before the end.
pub(crate) fn one_transaction(bytes: &[u8]) -> Result<(), String> {
    let mut scan = Scan { bytes, pos: 0 };
    let framed = (|| {
        scan.skip(4)?;
        for _ in 0..scan.var_int()? {
            scan.read(32)?;
            scan.skip(4)?;
            let script = scan.var_int()?;
            scan.skip(script.saturating_add(4))?;
        }
        for _ in 0..scan.var_int()? {
            scan.skip(8)?;
            let script = scan.var_int()?;
            scan.skip(script)?;
        }
        scan.skip(4)
    })();
    framed.map_err(str::to_string)?;
    match bytes.len() - scan.pos {
        0 => Ok(()),
        after => Err(format!(
            "Serialized transaction has {after} bytes after its lock time"
        )),
    }
}

#[cfg(test)]
#[path = "raw_frame_817_tests.rs"]
mod tests;
