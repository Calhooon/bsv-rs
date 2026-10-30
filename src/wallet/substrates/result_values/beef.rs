//! Read-only result BEEF: exact framing, loose historical formats and subject selection.
//! WalletResultBEEF.ts at edf6e03. This is not transaction/script verification.

use super::{bytes, invalid, Result};
use crate::primitives::{sha256d, Reader};
use crate::transaction::{MerklePath, MerklePathLeaf};
use serde_json::value::RawValue;
use std::collections::{HashMap, HashSet};

pub(super) struct Envelope {
    pub atomic: Option<String>,
    pub transactions: indexmap::IndexMap<String, Option<Transaction>>,
    bumps: Vec<HashSet<String>>,
    bump_indexes: HashMap<String, Option<usize>>,
}

#[derive(Clone)]
pub(super) struct Transaction {
    pub txid: String,
    pub version: u32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub lock_time: u32,
}

#[derive(Clone)]
pub(super) struct Input {
    pub txid: String,
    pub index: u32,
    pub script: Vec<u8>,
    pub sequence: u32,
    pub satoshis: Option<u64>,
}

#[derive(Clone)]
pub(super) struct Output {
    pub satoshis: u64,
    pub script: Vec<u8>,
}

impl Input {
    pub fn outpoint(&self) -> String {
        format!("{}.{}", self.txid, self.index)
    }
}

fn malformed() -> crate::Error {
    crate::Error::WalletError("invalid result BEEF".into())
}

fn count(reader: &mut Reader<'_>) -> Result<usize> {
    let n = reader.read_var_int()?;
    if n > 9_007_199_254_740_991 {
        return Err(malformed());
    }
    usize::try_from(n).map_err(|_| malformed())
}

fn reversed(reader: &mut Reader<'_>) -> Result<String> {
    let mut bytes = reader.read_bytes(32)?.to_vec();
    bytes.reverse();
    Ok(hex::encode(bytes))
}

fn script(reader: &mut Reader<'_>) -> Result<Vec<u8>> {
    let length = count(reader)?;
    Ok(reader.read_bytes(length)?.to_vec())
}

fn raw_transaction(reader: &mut Reader<'_>) -> Result<Transaction> {
    let start = reader.position();
    let version = reader.read_u32_le()?;
    let length = count(reader)?;
    if length > reader.remaining() / 41 {
        return Err(malformed());
    }
    let mut inputs = Vec::new();
    for _ in 0..length {
        inputs.push(Input {
            txid: reversed(reader)?,
            index: reader.read_u32_le()?,
            script: script(reader)?,
            sequence: reader.read_u32_le()?,
            satoshis: None,
        });
    }
    let length = count(reader)?;
    if length > reader.remaining() / 9 {
        return Err(malformed());
    }
    let mut outputs = Vec::new();
    for _ in 0..length {
        outputs.push(Output {
            satoshis: reader.read_u64_le()?,
            script: script(reader)?,
        });
    }
    let lock_time = reader.read_u32_le()?;
    let mut hash = sha256d(reader.consumed_since(start));
    hash.reverse();
    Ok(Transaction {
        txid: hex::encode(hash),
        version,
        inputs,
        outputs,
        lock_time,
    })
}

fn bump(reader: &mut Reader<'_>) -> Result<HashSet<String>> {
    count(reader)?; // The result reader validates framing, not a chain's height.
    let height = reader.read_u8()?;
    if !(1..=32).contains(&height) {
        return Err(malformed());
    }
    let mut path = Vec::new();
    for level in 0..height {
        let length = count(reader)?;
        if length > reader.remaining() / 2 {
            return Err(malformed());
        }
        let mut leaves = Vec::new();
        let mut seen = HashSet::new();
        for _ in 0..length {
            let offset = count(reader)? as u64;
            if offset > (u64::from(u32::MAX) >> level) || !seen.insert(offset) {
                return Err(malformed());
            }
            let flags = reader.read_u8()?;
            let leaf = if flags & 1 != 0 {
                MerklePathLeaf::new_duplicate(offset)
            } else {
                MerklePathLeaf::new(offset, reversed(reader)?)
            };
            leaves.push(leaf);
        }
        leaves.sort_by_key(|leaf| leaf.offset);
        path.push(leaves);
    }
    // The reference attempts a root for duplicate-only level-zero leaves too.
    if path[0].iter().all(|leaf| leaf.hash.is_none()) {
        return Err(malformed());
    }
    let path = MerklePath::new_unchecked(0, path)?;
    Ok(path.path[0]
        .iter()
        .filter_map(|leaf| leaf.hash.clone())
        .collect())
}

pub(super) fn parse(bytes: &[u8]) -> Result<Envelope> {
    let mut reader = Reader::new(bytes);
    let mut version = reader.read_u32_le()?;
    let atomic = if version == 0x0101_0101 {
        let id = reversed(&mut reader)?;
        version = reader.read_u32_le()?;
        Some(id)
    } else {
        None
    };
    if !matches!(version, 0xefbe_0001 | 0xefbe_0002) {
        return Err(malformed());
    }
    let length = count(&mut reader)?;
    if length > reader.remaining() {
        return Err(malformed());
    }
    let mut bumps = Vec::new();
    for _ in 0..length {
        bumps.push(bump(&mut reader)?);
    }
    let length = count(&mut reader)?;
    if length > reader.remaining() {
        return Err(malformed());
    }
    let mut transactions = indexmap::IndexMap::new();
    let mut bump_indexes = HashMap::new();
    for _ in 0..length {
        let (id, transaction, index) = entry(&mut reader, version)?;
        if transactions.insert(id.clone(), transaction).is_some() {
            return Err(malformed());
        }
        bump_indexes.insert(id, index);
    }
    if !reader.is_empty() {
        return Err(malformed());
    }
    resolve_sources(&mut transactions);
    Ok(Envelope {
        atomic,
        transactions,
        bumps,
        bump_indexes,
    })
}

fn entry(
    reader: &mut Reader<'_>,
    version: u32,
) -> Result<(String, Option<Transaction>, Option<usize>)> {
    let format = if version == 0xefbe_0002 {
        reader.read_u8()?
    } else {
        0
    };
    let entry = if format == 2 {
        (reversed(reader)?, None, None)
    } else {
        let mut index = if version == 0xefbe_0002 && format == 1 {
            Some(count(reader)?)
        } else {
            None
        };
        let tx = raw_transaction(reader)?;
        if version == 0xefbe_0001 && reader.read_u8()? != 0 {
            index = Some(count(reader)?);
        }
        (tx.txid.clone(), Some(tx), index)
    };
    Ok(entry)
}

fn resolve_sources(transactions: &mut indexmap::IndexMap<String, Option<Transaction>>) {
    let sources: HashMap<_, _> = transactions
        .iter()
        .filter_map(|(id, tx)| {
            tx.as_ref().map(|tx| {
                (
                    id.clone(),
                    tx.outputs.iter().map(|o| o.satoshis).collect::<Vec<_>>(),
                )
            })
        })
        .collect();
    for tx in transactions.values_mut().flatten() {
        for input in &mut tx.inputs {
            input.satoshis = sources
                .get(&input.txid)
                .and_then(|outputs| outputs.get(input.index as usize))
                .copied();
        }
    }
}

impl Envelope {
    fn partial_atomic_subject(&self) -> Option<&Transaction> {
        let subject = self.atomic.as_ref()?;
        let tx = self.transactions.get(subject)?.as_ref()?;
        let mut seen = HashSet::new();
        let mut pending = vec![subject.as_str()];
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            let index = self.bump_indexes.get(id).copied().flatten();
            if index
                .and_then(|i| self.bumps.get(i))
                .is_some_and(|b| b.contains(id))
            {
                continue;
            }
            if let Some(Some(tx)) = self.transactions.get(id) {
                pending.extend(
                    tx.inputs
                        .iter()
                        .filter(|i| self.transactions.contains_key(&i.txid))
                        .map(|i| i.txid.as_str()),
                );
            }
        }
        (seen.len() == self.transactions.len()).then_some(tx)
    }

    pub fn subject(mut self, expected: Option<&str>) -> Option<Transaction> {
        let id = if let Some(tx) = self.partial_atomic_subject() {
            tx.txid.clone()
        } else if let Some(id) = expected
            .map(str::to_ascii_lowercase)
            .filter(|id| self.transactions.get(id).is_some_and(Option::is_some))
        {
            id
        } else if let Some(id) = &self.atomic {
            id.clone()
        } else {
            self.transactions
                .iter()
                .rev()
                .find(|(_, tx)| tx.is_some())?
                .0
                .clone()
        };
        self.transactions.swap_remove(&id).flatten()
    }
}

pub(super) fn read(
    raw: Option<&RawValue>,
    call: &str,
    field: &str,
    bytes: &bytes::Fields<'_>,
) -> Result<Envelope> {
    let encoded = bytes.read(raw, call, field, None, None)?;
    parse(&encoded).map_err(|_| invalid(call, field, "a complete, exactly framed BEEF envelope"))
}

pub(super) fn transaction(
    raw: Option<&RawValue>,
    call: &str,
    field: &str,
    expected: Option<&str>,
    bytes: &bytes::Fields<'_>,
) -> Result<Transaction> {
    let encoded = bytes.read(raw, call, field, None, None)?;
    parse(&encoded)
        .ok()
        .and_then(|beef| beef.subject(expected))
        .ok_or_else(|| invalid(call, field, "a complete, exactly framed BEEF transaction"))
}
