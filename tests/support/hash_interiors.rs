//! The interior bytes of each 32-byte hash of a well-formed BUMP or BEEF:
//! the bytes the two-readers sweeps leave unchanged (speed loop two, #670).
//!
//! Both readers of each pair take a hash (a BUMP leaf, an input's previous
//! txid, an atomic subject, a txid-only entry) as 32 opaque bytes: they hash
//! it, compare it whole and order it (the stream's trie), and no byte of it
//! is read apart from the others. A change at byte 17 goes down the path a
//! change at byte 31 does: the hash differs and its order among the seed's
//! hashes, which its leading bytes decide, stays. A sweep that changes and
//! cuts at bytes 0, 1 and 31 of each hash, and at every byte that is not a
//! hash's, asks the readers what the sweep at every byte asked. Bytes the
//! walk cannot read to their end give no mask, and the sweep reads every
//! byte of them.
#![allow(dead_code)]

/// The hash bytes the sweeps skip: bytes 2 to 30 of each hash.
const KEPT_HEAD: usize = 2;
const KEPT_TAIL: usize = 1;

struct Walk<'a> {
    bytes: &'a [u8],
    at: usize,
    interior: Vec<bool>,
}

impl Walk<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(n)?;
        let taken = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(taken)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn var_int(&mut self) -> Option<u64> {
        let lead = self.u8()?;
        let width = match lead {
            0xfd => 2,
            0xfe => 4,
            0xff => 8,
            n => return Some(u64::from(n)),
        };
        let mut value = [0u8; 8];
        value[..width].copy_from_slice(self.take(width)?);
        Some(u64::from_le_bytes(value))
    }

    fn hash(&mut self) -> Option<()> {
        let start = self.at;
        self.take(32)?;
        for flag in &mut self.interior[start + KEPT_HEAD..start + 32 - KEPT_TAIL] {
            *flag = true;
        }
        Some(())
    }

    fn bump(&mut self) -> Option<()> {
        self.var_int()?;
        let height = self.u8()?;
        for _ in 0..height {
            for _ in 0..self.var_int()? {
                self.var_int()?;
                if self.u8()? & 1 == 0 {
                    self.hash()?;
                }
            }
        }
        Some(())
    }

    fn script(&mut self) -> Option<()> {
        let len = usize::try_from(self.var_int()?).ok()?;
        self.take(len).map(|_| ())
    }

    fn transaction(&mut self) -> Option<()> {
        self.take(4)?;
        for _ in 0..self.var_int()? {
            self.hash()?;
            self.take(4)?;
            self.script()?;
            self.take(4)?;
        }
        for _ in 0..self.var_int()? {
            self.take(8)?;
            self.script()?;
        }
        self.take(4).map(|_| ())
    }

    fn beef(&mut self) -> Option<()> {
        let mut version = u32::from_le_bytes(self.take(4)?.try_into().ok()?);
        if version == 0x0101_0101 {
            self.hash()?;
            version = u32::from_le_bytes(self.take(4)?.try_into().ok()?);
        }
        let v2 = match version {
            0xEFBE_0001 => false,
            0xEFBE_0002 => true,
            _ => return None,
        };
        for _ in 0..self.var_int()? {
            self.bump()?;
        }
        for _ in 0..self.var_int()? {
            if v2 {
                match self.u8()? {
                    0 => self.transaction()?,
                    1 => {
                        self.var_int()?;
                        self.transaction()?;
                    }
                    2 => self.hash()?,
                    _ => return None,
                }
            } else {
                self.transaction()?;
                if self.u8()? == 1 {
                    self.var_int()?;
                }
            }
        }
        Some(())
    }
}

fn mask<'a>(bytes: &'a [u8], read: impl FnOnce(&mut Walk<'a>) -> Option<()>) -> Option<Vec<bool>> {
    let mut walk = Walk {
        bytes,
        at: 0,
        interior: vec![false; bytes.len() + 1],
    };
    read(&mut walk)?;
    (walk.at == bytes.len()).then_some(walk.interior)
}

/// The skipped bytes of a well-formed BUMP, one flag per byte and one for
/// the cut at the end; `None` for bytes the walk cannot read to their end.
pub fn of_bump(bytes: &[u8]) -> Option<Vec<bool>> {
    mask(bytes, |walk| walk.bump())
}

/// The skipped bytes of a well-formed BEEF (V1, V2 or atomic).
pub fn of_beef(bytes: &[u8]) -> Option<Vec<bool>> {
    mask(bytes, |walk| walk.beef())
}
