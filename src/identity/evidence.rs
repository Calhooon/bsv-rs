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
//! port: `TxidNotInBump` (`Beef::verify_structure`'s and the streaming
//! reader's `check_bump_index`) is not this door's refusal.
//!
//! The walk is over the BEEF and not over `source_transaction` links:
//! `Beef::find_atomic_transaction` hands a repeated parent to a later input
//! as a stub with its own inputs unlinked (the linear linking), so a walk
//! in the reference's stack order could reach the stub before the full
//! link. Not ported: the coordinator's script and proof verification
//! against a chain tracker (`TransactionEvidenceCoordinator.ts:317-345`),
//! the `CLAUDE.md` #553 row's remaining residue.
//!
//! The lookup output's `txid` hint (`OutputListItem::txid` since #735, the
//! toolbox passing the whole output at `identityUtils.ts:602`) is compared
//! with the subject as `loadEvidenceTransaction` compares it
//! (`TransactionEvidence.ts:123-124`, lower-cased), but a disagreement does
//! not refuse the evidence here: the subject is read and the contradiction
//! counted as the host's fault ([`HintContradictions`], read by
//! `IdentityClient::txid_hint_contradictions`), by the owner's word of
//! 2026-11-04 13:5xZ, where the reference refuses it as `invalid-evidence`
//! and skips the output (ts-stack #1482). The reference's `timeout` code
//! comes from the coordinator's tracker verify, unported: this check has no
//! timeout path.
//!
//! Three consequences of reading and counting, stated (#735's fold, the
//! strength read of 2026-11-04):
//!
//! - The limit order. The reference tests the hint inside
//!   `loadEvidenceTransaction` (`:123-124`), before `assertUnconfirmedGraph`
//!   (`:187`, the graph's inputs and script-bytes limits, `:168-171`). An
//!   output with a disagreeing hint whose graph passes one of those limits
//!   is `invalid-evidence` there, skipped, the discovery going on; here the
//!   hint refuses nothing, the walk runs, the limit is hit and the whole
//!   discovery fails (`Transaction evidence: limit`) with nothing counted,
//!   [`admit`] counting only a subject it admits. The limits ahead of the
//!   hint on both sides (the bytes, `:101`; the transaction count, `:117`)
//!   end the same way on both.
//! - The count is per parse. One output read by both parsers
//!   (`resolve_by_attributes`' and `discover_certificates`') is counted
//!   twice, once by each call that reads it.
//! - The count comes before the record checks. [`admit`] runs ahead of the
//!   token's and the certificate record's checks (`client_record.rs`,
//!   `client_token.rs`), so an output those checks then skip is counted too.
//!
//! A binary aggregated answer gives no honest host a contradiction: since
//! the fold each of its outputs carries the Atomic BEEF of its own
//! outpoint's txid (`overlay::facilitators`, `LookupResolver.ts:905-936`),
//! whose subject is the hint.

use crate::overlay::OutputListItem;
use crate::transaction::{Beef, BeefTx, Transaction};
use crate::wallet::WalletInterface;
use crate::Error;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

/// The admitted outputs whose host's `txid` hint named another transaction
/// than the BEEF's subject (#735): a counted outcome, the subject read.
#[derive(Debug, Default)]
pub(super) struct HintContradictions(AtomicU64);

impl HintContradictions {
    fn record(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

impl<W: WalletInterface> super::IdentityClient<W> {
    /// How many lookup outputs this client read whose host's `txid` hint
    /// disagreed with the BEEF's subject (#735). The output is read from its
    /// subject, as the evidence proves it, and the disagreement counted as
    /// the host's fault, a figure the caller can log or act on; the
    /// reference skips such an output (`TransactionEvidence.ts:123-124`,
    /// ts-stack #1482). Outputs the evidence check refuses are not counted,
    /// an evidence limit hit after the hint included (the discovery fails
    /// there, where the reference skips the output on its hint before). The
    /// count is per parse and taken before the token's and the record's
    /// checks: an output read by two calls is counted by each, and one those
    /// checks then skip is counted too.
    ///
    /// Only the copies the resolver's merge kept are read here. A lying copy
    /// the merge displaced for an agreeing or hintless copy of the same
    /// output (#796), or dropped behind a copy it already held, is counted by
    /// `LookupResolver::txid_hint_contradictions` alone: this count reads 0
    /// for it, so read the resolver's count beside this one (#818). That
    /// needs a client built by `IdentityClient::with_resolver` over an
    /// `Arc<LookupResolver>` the caller keeps: a client built by
    /// `IdentityClient::new` owns its resolver and has no door to the
    /// resolver's count.
    pub fn txid_hint_contradictions(&self) -> u64 {
        self.hint_contradictions.0.load(Ordering::Relaxed)
    }
}

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
/// rethrows and the discovery fails (`identityUtils.ts:630-634`). A
/// subject whose output carries a disagreeing hint is admitted and counted
/// in `contradictions` (#735).
pub(super) fn admit(
    output: &OutputListItem,
    contradictions: &HintContradictions,
) -> crate::Result<Option<Transaction>> {
    match parse_evidence(&output.beef, output.output_index) {
        Ok(subject) => {
            if hint_disagrees(output.txid.as_deref(), &subject) {
                contradictions.record();
            }
            Ok(Some(subject))
        }
        Err(refusal) if refusal.code == Code::InvalidEvidence => Ok(None),
        Err(refusal) => Err(Error::IdentityError(format!(
            "Transaction evidence: {}",
            refusal.code.as_str()
        ))),
    }
}

/// `loadEvidenceTransaction`'s hint test (`TransactionEvidence.ts:123-124`):
/// a hint present that, lower-cased, is not the subject's txid. The
/// reference refuses the evidence there; [`admit`] counts it (#735).
pub(super) fn hint_disagrees(hint: Option<&str>, subject: &Transaction) -> bool {
    hint.is_some_and(|hint| hint.to_ascii_lowercase() != subject.id())
}

/// `parseEvidence` (`TransactionEvidence.ts:179-201`) on a lookup output's
/// BEEF and index, the txid hint left to [`admit`] (#735): the subject, or
/// the refusal.
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
    if output_index as usize >= subject.outputs().len() {
        return Err(invalid("TransactionEvidence.ts:126"));
    }
    Ok((beef, subject))
}

/// `graphScriptBytes` (`:130-135`): every locking and unlocking script's
/// serialized bytes.
fn graph_script_bytes(tx: &Transaction) -> usize {
    let locking: usize = tx
        .outputs()
        .iter()
        .map(|o| o.locking_script.to_binary().len())
        .sum();
    let unlocking: usize = tx
        .inputs()
        .iter()
        .filter_map(|i| i.unlocking_script.as_ref())
        .map(|s| s.to_binary().len())
        .sum();
    locking + unlocking
}

/// `assertUnconfirmedGraph` (`:155-177`): the whole unconfirmed graph from
/// `subject`, popped in the reference's stack order.
fn assert_unconfirmed_graph(beef: &Beef, subject: &Transaction) -> Result<(), Refusal> {
    let mut pending = vec![subject];
    let mut visited = HashSet::new();
    let mut spent = HashSet::new();
    let (mut inputs, mut script_bytes) = (0usize, 0usize);
    while let Some(current) = pending.pop() {
        let id = current.id();
        if !visited.insert(id.clone()) {
            continue;
        }
        script_bytes += graph_script_bytes(current);
        inputs += current.inputs().len();
        if inputs > INPUTS || script_bytes > SCRIPT_BYTES {
            return Err(limit("TransactionEvidence.ts:170-171"));
        }
        if beef.find_bump(&id).is_some() {
            continue;
        }
        if current.inputs().is_empty() {
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
    for input in current.inputs() {
        let named = input.source_txid.map(|t| t.to_string());
        let named = named.as_deref();
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
#[path = "evidence_730_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "evidence_736_tests.rs"]
mod tests_736;

#[cfg(test)]
#[path = "evidence_741_tests.rs"]
mod tests_741;

#[cfg(test)]
#[path = "evidence_748_tests.rs"]
mod tests_748;

#[cfg(test)]
#[path = "evidence_731_tests.rs"]
mod tests_731;

#[cfg(test)]
#[path = "evidence_818_tests.rs"]
mod tests_818;
