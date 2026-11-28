//! #730: the reference's evidence check at the `ls_identity` door.
//!
//! The toolbox's discovery reads a lookup output only after its
//! `IdentityEvidenceVerifier` admits the evidence (`ts-stack@edf6e03`
//! `packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:600-634`,
//! the coordinator calling `parseEvidence` under
//! `defaultTransactionEvidenceLimits`,
//! `packages/sdk/src/transaction/TransactionEvidenceCoordinator.ts:184`).
//! [`parse_evidence`] is that `parseEvidence`
//! (`packages/sdk/src/transaction/TransactionEvidence.ts:93-201`): the
//! bytes bound, the strict parse, the transaction count, the target (the
//! atomic txid, else the last transaction), the output index, then
//! `assertUnconfirmedGraph`'s walk of the complete unconfirmed graph from
//! the subject. The walk reads the BEEF as `Beef.#addInputProof` links it
//! (`Beef.ts:639-680`): an input's source is the entry the BEEF holds under
//! its txid, and a transaction is proven when a BUMP of the BEEF carries
//! its txid (`findBump`, `:570-574`), whatever BUMP index its entry names.
//! It never asks a BUMP index of its leaf (`#verifyBumpIndexLeaves` is
//! `verifyValid`'s, `:1129-1138`, uncalled there), so neither does this
//! port.
//!
//! Not ported: the coordinator's script and proof verification against a
//! chain tracker (`TransactionEvidenceCoordinator.ts:317-345`), the
//! `CLAUDE.md` #553 row's remaining residue; the lookup output's `txid`
//! hint (`loadEvidenceTransaction` compares it, `TransactionEvidence.ts:123-124`)
//! which the stable line's `OutputListItem` does not carry (the beta line's
//! #735 public field, left out of this stable-line port): this door reads
//! the subject the evidence proves and counts no host contradiction. The
//! reference's `timeout` code comes from the coordinator's tracker verify,
//! unported: this check has no timeout path.

use crate::overlay::OutputListItem;
use crate::transaction::{Beef, BeefTx, Transaction};
use crate::Error;
use std::collections::HashSet;

/// `defaultTransactionEvidenceLimits.candidateBytes`
/// (`TransactionEvidence.ts:62`).
pub(super) const CANDIDATE_BYTES: usize = 1024 * 1024;
/// `defaultTransactionEvidenceLimits.transactions` (`:64`).
pub(super) const TRANSACTIONS: usize = 256;
/// `defaultTransactionEvidenceLimits.inputs` (`:65`).
pub(super) const INPUTS: usize = 4096;
/// `defaultTransactionEvidenceLimits.scriptBytes` (`:66`).
pub(super) const SCRIPT_BYTES: usize = 256 * 1024;

/// The reference's two codes this check throws
/// (`TransactionEvidenceErrorCode`, `TransactionEvidence.ts:23-24`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Code {
    /// `invalid-evidence`: the toolbox's verifier skips the output.
    InvalidEvidence,
    /// `limit`: the toolbox's verifier rethrows it and the discovery fails
    /// (`identityUtils.ts:630-634`, `Wallet.ts:950-955`).
    Limit,
}

impl Code {
    /// The reference's code text.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Code::InvalidEvidence => "invalid-evidence",
            Code::Limit => "limit",
        }
    }
}

/// A refusal: the code and the reference's line that throws it. Internal,
/// never read by a caller: the parsers skip on `InvalidEvidence` and answer
/// `Limit` in the reference's words, `Transaction evidence: limit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Refusal {
    /// The reference's code.
    pub(super) code: Code,
    /// `TransactionEvidence.ts:<line>`.
    pub(super) site: &'static str,
}

const fn invalid(site: &'static str) -> Refusal {
    Refusal {
        code: Code::InvalidEvidence,
        site,
    }
}

const fn limit(site: &'static str) -> Refusal {
    Refusal {
        code: Code::Limit,
        site,
    }
}

/// The parsers' door: the subject, `None` where the toolbox's verifier
/// skips the output (`invalid-evidence`), and the reference's words,
/// `Transaction evidence: limit` (`TransactionEvidence.ts:29`), where it
/// rethrows and the discovery fails (`identityUtils.ts:630-634`).
pub(super) fn admit(output: &OutputListItem) -> crate::Result<Option<Transaction>> {
    match parse_evidence(&output.beef, output.output_index) {
        Ok(subject) => Ok(Some(subject)),
        Err(refusal) if refusal.code == Code::InvalidEvidence => Ok(None),
        Err(refusal) => Err(Error::IdentityError(format!(
            "Transaction evidence: {}",
            refusal.code.as_str()
        ))),
    }
}

/// `parseEvidence` (`TransactionEvidence.ts:179-201`) on a lookup output's
/// BEEF and index: the subject, or the refusal.
pub(super) fn parse_evidence(bytes: &[u8], output_index: u32) -> Result<Transaction, Refusal> {
    // snapshotEvidenceBytes (:93-108): the length before anything else
    if bytes.len() > CANDIDATE_BYTES {
        return Err(limit("TransactionEvidence.ts:101"));
    }
    if bytes.is_empty() {
        return Err(invalid("TransactionEvidence.ts:104"));
    }
    let (beef, subject) = load_evidence_transaction(bytes, output_index)?;
    assert_unconfirmed_graph(&beef, &subject)?;
    Ok(subject)
}

/// `loadEvidenceTransaction` (`:110-128`). `Beef::from_binary` reads a
/// whole frame, refusing a byte after it, as `Beef.fromBinaryStrict` does
/// (`Beef.ts:1286-1309`); the target is `Transaction::from_beef`'s rule
/// with no txid, read here directly to bound the count first.
fn load_evidence_transaction(
    bytes: &[u8],
    output_index: u32,
) -> Result<(Beef, Transaction), Refusal> {
    let beef = Beef::from_binary(bytes).map_err(|_| invalid("TransactionEvidence.ts:116"))?;
    if beef.txs.len() > TRANSACTIONS {
        return Err(limit("TransactionEvidence.ts:117"));
    }
    let target = match &beef.atomic_txid {
        Some(atomic) => atomic.clone(),
        None => beef
            .txs
            .last()
            .map(BeefTx::txid)
            .ok_or(invalid("TransactionEvidence.ts:119"))?,
    };
    let subject = beef
        .find_txid(&target)
        .and_then(BeefTx::tx)
        .cloned()
        .ok_or(invalid("TransactionEvidence.ts:120-121"))?;
    if output_index as usize >= subject.outputs.len() {
        return Err(invalid("TransactionEvidence.ts:126"));
    }
    Ok((beef, subject))
}

/// `graphScriptBytes` (`:130-135`): every locking and unlocking script's
/// serialized bytes.
fn graph_script_bytes(tx: &Transaction) -> usize {
    let locking: usize = tx
        .outputs
        .iter()
        .map(|o| o.locking_script.to_binary().len())
        .sum();
    let unlocking: usize = tx
        .inputs
        .iter()
        .filter_map(|i| i.unlocking_script.as_ref())
        .map(|s| s.to_binary().len())
        .sum();
    locking + unlocking
}

/// `assertUnconfirmedGraph` (`:155-177`): the whole unconfirmed graph from
/// `subject`, popped in the reference's stack order. The walk holds
/// references into the BEEF (and the subject), never a clone of a graph
/// transaction, so its memory stays O(the input count it bounds).
fn assert_unconfirmed_graph<'a>(beef: &'a Beef, subject: &'a Transaction) -> Result<(), Refusal> {
    let mut pending: Vec<&'a Transaction> = vec![subject];
    let mut visited = HashSet::new();
    let mut spent = HashSet::new();
    let (mut inputs, mut script_bytes) = (0usize, 0usize);
    while let Some(current) = pending.pop() {
        let id = current.id();
        if !visited.insert(id.clone()) {
            continue;
        }
        script_bytes += graph_script_bytes(current);
        inputs += current.inputs.len();
        if inputs > INPUTS || script_bytes > SCRIPT_BYTES {
            return Err(limit("TransactionEvidence.ts:170-171"));
        }
        if beef.find_bump(&id).is_some() {
            continue;
        }
        if current.inputs.is_empty() {
            return Err(invalid("TransactionEvidence.ts:174"));
        }
        enqueue_unconfirmed_parents(beef, current, &mut pending, &mut spent)?;
    }
    Ok(())
}

/// `enqueueUnconfirmedParents` (`:137-153`): each input's source the entry
/// the BEEF holds under its txid (`Beef.#resolveInputSource`,
/// `Beef.ts:670-680`), a txid-only entry none.
fn enqueue_unconfirmed_parents<'a>(
    beef: &'a Beef,
    current: &Transaction,
    pending: &mut Vec<&'a Transaction>,
    spent: &mut HashSet<(String, u32)>,
) -> Result<(), Refusal> {
    for input in &current.inputs {
        let named = input.source_txid.as_deref();
        let Some(source) = named.and_then(|t| beef.find_txid(t)).and_then(BeefTx::tx) else {
            return Err(invalid("TransactionEvidence.ts:143"));
        };
        let source_txid = source.id();
        if named != Some(source_txid.as_str()) {
            return Err(invalid("TransactionEvidence.ts:145-146"));
        }
        if !spent.insert((source_txid, input.source_output_index)) {
            return Err(invalid("TransactionEvidence.ts:149"));
        }
        pending.push(source);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The walk's resource bounds and graph checks, each pinned by a run of
    //! `admit` on a hand-built BEEF. A `limit` (over a bound) fails the
    //! discovery with `Err`; an `invalid-evidence` (a bad graph) skips the
    //! output with `Ok(None)`; a clean graph is admitted with `Ok(Some)`.
    //! Each test is RED with its one guard removed or loosened (recorded in
    //! the fold ledger). The redundant guards (an empty BEEF, an output index
    //! past the outputs, a source txid that disagrees with the entry it keys)
    //! are subsumed by another check and are not pinned here: an empty BEEF is
    //! refused by `Beef::from_binary` with the same skip, an out-of-range
    //! index by the parser's own `outputs.get`, and a keyed entry's id equals
    //! the txid `find_txid` looked it up by, so the last never disagrees.

    use super::{admit, CANDIDATE_BYTES, INPUTS, SCRIPT_BYTES, TRANSACTIONS};
    use crate::overlay::OutputListItem;
    use crate::script::LockingScript;
    use crate::transaction::{
        Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
    };

    fn small_script() -> LockingScript {
        LockingScript::from_binary(&[0x51]).unwrap()
    }

    /// A transaction spending each `(txid, vout)` parent, its one output a
    /// locking script of `script_len` bytes (a small script when zero).
    fn tx(parents: &[(String, u32)], script_len: usize) -> Transaction {
        let mut t = Transaction::new();
        for (txid, vout) in parents {
            t.add_input(TransactionInput::new(txid.clone(), *vout))
                .unwrap();
        }
        let script = if script_len == 0 {
            small_script()
        } else {
            LockingScript::from_binary(&vec![0x61u8; script_len]).unwrap()
        };
        t.add_output(TransactionOutput::new(1, script)).unwrap();
        t
    }

    fn out(beef: Vec<u8>, output_index: u32) -> OutputListItem {
        OutputListItem {
            beef,
            output_index,
            context: None,
        }
    }

    /// A BEEF proving `t` by a block of its own (a lone leaf at offset 0).
    fn proven(t: &Transaction) -> (Beef, usize) {
        let leaf = MerklePathLeaf::new_txid(0, t.id());
        let mut beef = Beef::new();
        let idx = beef.merge_bump(MerklePath::new(900, vec![vec![leaf]]).unwrap());
        (beef, idx)
    }

    // e1: bytes over 1 MiB refuse the discovery with `limit` before any parse;
    // removed, the invalid bytes merely skip.
    #[test]
    fn evidence_over_one_mebibyte_is_a_limit_1118e() {
        let err = admit(&out(vec![7u8; CANDIDATE_BYTES + 1], 0))
            .unwrap_err()
            .to_string();
        assert!(err.contains("limit"), "{err}");
    }

    // e3: a BEEF of more than 256 transactions refuses with `limit`; removed,
    // the no-input last transaction merely skips.
    #[test]
    fn evidence_over_256_transactions_is_a_limit_1118e() {
        let mut beef = Beef::new();
        for i in 0..=TRANSACTIONS {
            let mut t = Transaction::new();
            t.add_output(TransactionOutput::new((i + 1) as u64, small_script()))
                .unwrap();
            beef.merge_raw_tx(t.to_binary(), None);
        }
        let err = admit(&out(beef.to_binary(), 0)).unwrap_err().to_string();
        assert!(err.contains("limit"), "{err}");
    }

    // e6 (inputs): a graph of more than 4096 inputs refuses with `limit`;
    // removed, the absent parents skip.
    #[test]
    fn evidence_over_4096_inputs_is_a_limit_1118e() {
        let parents: Vec<(String, u32)> = (0..=INPUTS).map(|i| (format!("{i:064x}"), 0)).collect();
        let mut beef = Beef::new();
        beef.merge_raw_tx(tx(&parents, 0).to_binary(), None);
        let err = admit(&out(beef.to_binary(), 0)).unwrap_err().to_string();
        assert!(err.contains("limit"), "{err}");
    }

    // e6 (script bytes): a graph of more than 256 KiB of script refuses with
    // `limit`; removed, the absent parent skips.
    #[test]
    fn evidence_over_256_kib_of_script_is_a_limit_1118e() {
        let mut beef = Beef::new();
        let subject = tx(&[(format!("{:064x}", 0xdeadu32), 0)], SCRIPT_BYTES + 1);
        beef.merge_raw_tx(subject.to_binary(), None);
        let err = admit(&out(beef.to_binary(), 0)).unwrap_err().to_string();
        assert!(err.contains("limit"), "{err}");
    }

    // e9: an input whose source is not in the BEEF skips the output; removed,
    // the output is admitted.
    #[test]
    fn evidence_with_an_absent_parent_skips_1118e() {
        let mut beef = Beef::new();
        beef.merge_raw_tx(
            tx(&[(format!("{:064x}", 0xabcdu32), 0)], 0).to_binary(),
            None,
        );
        assert!(admit(&out(beef.to_binary(), 0)).unwrap().is_none());
    }

    // e11: a graph spending one parent output twice skips the output; removed,
    // it is admitted.
    #[test]
    fn evidence_spending_one_outpoint_twice_skips_1118e() {
        let parent = tx(&[], 0);
        let parent_txid = parent.id();
        let (mut beef, idx) = proven(&parent);
        beef.merge_raw_tx(parent.to_binary(), Some(idx));
        let subject = tx(&[(parent_txid.clone(), 0), (parent_txid, 0)], 0);
        beef.merge_raw_tx(subject.to_binary(), None);
        assert!(admit(&out(beef.to_binary(), 0)).unwrap().is_none());
    }
}
