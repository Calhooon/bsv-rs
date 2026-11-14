//! #843, the IDENTITY law for `Transaction`: a transaction's id is always the
//! hash of its current fields, with no duty on the caller.
//!
//! The law as a property: seeded random sequences of edits through every
//! public door that can change a serialized field (the four writers,
//! `parts_mut`, `from_parts`/`into_parts`, `add_input`, `add_output` and its
//! family, `add_input_from`, `add_inputs_from_utxos`, `sign`, `fee`, an edit
//! of a linked `source_transaction` through the child's `inputs_mut()`, a
//! `Clone`, a JSON round trip, a re-read from hex); after every step the
//! caches are read (so the next step edits a value whose caches are full)
//! and judged against this file's own serializer of the fields. Then the
//! adversary's probes A to E and #843's `lock_time = 7` table as the nearest
//! cells the tip can express (on the base each answered the stale value:
//! `docs/lanes/break-tx-fields.md`, the RED output).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code

use bsv_rs::primitives::{from_hex, sha256d, to_hex, PrivateKey};
use bsv_rs::script::template::SignOutputs;
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::{LockingScript, Script, ScriptTemplate, UnlockingScript};
use bsv_rs::transaction::{
    Beef, ChangeDistribution, Transaction, TransactionInput, TransactionOutput, TransactionParts,
    Txid, Utxo,
};

/// The seed of the property run; a failure prints it with the sequence.
const SEED: u64 = 0x0843_1d3e_7171_0001;
/// Sequences in the property run (the brief's floor: 10,000 inside a minute).
const SEQUENCES: usize = 10_000;
/// Steps per sequence.
const STEPS: usize = 12;
/// The least each counted act may happen over the run (#869's fold).
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
    fn u32(&mut self) -> u32 {
        self.next() as u32
    }
    fn txid(&mut self) -> String {
        let bytes: Vec<u8> = (0..32).map(|_| self.next() as u8).collect();
        to_hex(&bytes)
    }
    fn script(&mut self) -> LockingScript {
        let len = self.below(6) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| 0x51 + (self.next() % 16) as u8).collect();
        LockingScript::from_binary(&bytes).unwrap()
    }
}

fn var_int(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// The outpoint txid an input's bytes carry, by the serializer's rule as
/// written here (#869's second fold): the `source_txid` when it is hex of
/// exactly 32 bytes, else the linked source's own fields' hash, else zeros.
fn wire_txid(input: &TransactionInput) -> Vec<u8> {
    let named = input.source_txid.map(|t| t.to_display_bytes().to_vec());
    match (named, input.source_transaction.as_deref()) {
        (Some(mut b), _) => {
            b.reverse();
            b
        }
        (None, Some(source)) => sha256d(&fields_bytes(source)).to_vec(),
        (None, None) => vec![0; 32],
    }
}

/// The fields' serialization, written here from the four doors alone (no
/// cache of the crate read): a linked source the input does not name by a
/// parsing txid named by its own fields' hash, recursively.
fn fields_bytes(tx: &Transaction) -> Vec<u8> {
    let mut out = tx.version().to_le_bytes().to_vec();
    var_int(&mut out, tx.inputs().len() as u64);
    for input in tx.inputs() {
        let wire = wire_txid(input);
        out.extend_from_slice(&wire);
        out.extend_from_slice(&input.source_output_index.to_le_bytes());
        let script = input
            .unlocking_script
            .as_ref()
            .map(|s| s.to_binary())
            .unwrap_or_default();
        var_int(&mut out, script.len() as u64);
        out.extend_from_slice(&script);
        out.extend_from_slice(&input.sequence.to_le_bytes());
    }
    var_int(&mut out, tx.outputs().len() as u64);
    for output in tx.outputs() {
        out.extend_from_slice(&output.satoshis.unwrap_or(0).to_le_bytes());
        let script = output.locking_script.to_binary();
        var_int(&mut out, script.len() as u64);
        out.extend_from_slice(&script);
    }
    out.extend_from_slice(&tx.lock_time().to_le_bytes());
    out
}

fn display(hash: [u8; 32]) -> String {
    let mut h = hash;
    h.reverse();
    to_hex(&h)
}

/// The law at one point, every cache read (so each is full afterwards).
fn law(tx: &Transaction, at: &str) {
    let bytes = tx.to_binary();
    assert_eq!(
        bytes,
        fields_bytes(tx),
        "{at}: to_binary() is the fields' bytes"
    );
    assert_eq!(
        tx.id(),
        display(sha256d(&bytes)),
        "{at}: id() is sha256d(to_binary())"
    );
    assert_eq!(tx.hash(), sha256d(&bytes), "{at}: hash()");
    assert_eq!(
        tx.to_hex(),
        to_hex(&bytes),
        "{at}: to_hex() is the hex of to_binary()"
    );
    let fresh = Transaction::from_binary(&bytes).unwrap();
    assert_eq!(fresh.id(), tx.id(), "{at}: a fresh parse has the same id");
    assert!(fresh == *tx, "{at}: a fresh parse compares equal");
    let copy = tx.clone();
    assert!(copy == *tx, "{at}: a clone compares equal");
    assert_eq!(copy.id(), tx.id(), "{at}: a clone has the same id");
    for (i, input) in tx.inputs().iter().enumerate() {
        if let Some(source) = input.source_transaction.as_deref() {
            law(source, &format!("{at}, the source of input {i}"));
        }
    }
}

/// The law on `tx` and every transaction linked below it, at any depth
/// (an explicit stack): `id()` the hash of its fields' bytes, `to_binary()`
/// those bytes, and a fresh parse of them the same id (#869's second fold).
fn law_reach(tx: &Transaction, at: &str) -> usize {
    let mut judged = 0;
    let mut stack = vec![(tx, at.to_string())];
    while let Some((t, at)) = stack.pop() {
        let fields = fields_bytes(t);
        assert_eq!(
            t.id(),
            display(sha256d(&fields)),
            "{at}: id() is the hash of the fields"
        );
        assert_eq!(
            t.to_binary(),
            fields,
            "{at}: to_binary() is the fields' bytes"
        );
        let fresh = Transaction::from_binary(&fields).unwrap();
        assert_eq!(
            fresh.id(),
            t.id(),
            "{at}: from_binary(to_binary()) has the id"
        );
        judged += 1;
        for (i, input) in t.inputs().iter().enumerate() {
            if let Some(source) = input.source_transaction.as_deref() {
                stack.push((source, format!("{at}, the source of input {i}")));
            }
        }
    }
    judged
}

/// The law over every entry a BEEF stores, each linked one level again
/// (`find_transaction_for_signing`), and the last entry, the subject, linked
/// whole (`find_atomic_transaction`): the linking door's two callers. (Every
/// entry linked whole judged the chain once per entry, quadratic, and took
/// the run past its minute.)
fn beef_entries_law(beef: &Beef, at: &str) -> usize {
    let mut judged = 0;
    for (k, entry) in beef.txs.iter().enumerate() {
        if let Some(t) = entry.tx() {
            judged += law_reach(t, &format!("{at}, entry {k}"));
            if let Some(linked) = beef.find_transaction_for_signing(&entry.txid()) {
                assert_eq!(
                    linked.id(),
                    entry.txid(),
                    "{at}, entry {k}: the id for signing"
                );
                judged += law_reach(&linked, &format!("{at}, entry {k} for signing"));
            }
        }
    }
    if let Some(subject) = beef.txs.last().filter(|e| e.tx().is_some()) {
        if let Some(linked) = beef.find_atomic_transaction(&subject.txid()) {
            assert_eq!(
                linked.id(),
                subject.txid(),
                "{at}: the last entry's id linked"
            );
            judged += law_reach(&linked, &format!("{at}, the last entry linked"));
        }
    }
    judged
}

/// The law through every door that stores a copy of a transaction in a
/// BEEF or reads one back (#869's second fold, the cold re-read's FIX):
/// `merge_transaction`, `merge_beef` into an empty BEEF and into itself,
/// `to_beef` and `to_atomic_beef` read back by `Beef::from_binary`,
/// `from_beef` and `from_atomic_beef`, and `clone`. Every transaction
/// reachable is judged; the count of those judged is returned.
fn beef_law(tx: &Transaction, at: &str) -> usize {
    let mut judged = 0;
    let mut beef = Beef::new();
    beef.merge_transaction(tx.clone());
    // The id merged is the id handed back, with the sources given (#869's
    // third fold).
    let id = tx.id();
    let atomic = beef
        .find_atomic_transaction(&id)
        .expect("the transaction merged is held");
    assert_eq!(
        atomic.id(),
        id,
        "{at}: find_atomic_transaction of the id merged"
    );
    same_sources(tx, &atomic, &format!("{at}: find_atomic_transaction"));
    let signing = beef.find_transaction_for_signing(&id).expect("held");
    assert_eq!(
        signing.id(),
        id,
        "{at}: find_transaction_for_signing of the id merged"
    );
    same_sources(tx, &signing, &format!("{at}: find_transaction_for_signing"));
    judged += beef_entries_law(&beef, &format!("{at}: merge_transaction"));
    let mut empty = Beef::new();
    if empty.merge_beef(&beef).is_ok() {
        judged += beef_entries_law(&empty, &format!("{at}: merge_beef into an empty BEEF"));
    }
    let same = beef.clone();
    if beef.merge_beef(&same).is_ok() {
        judged += beef_entries_law(&beef, &format!("{at}: merge_beef into itself"));
    }
    if let Ok(bytes) = tx.to_beef(true) {
        if let Ok(read) = Beef::from_binary(&bytes) {
            judged += beef_entries_law(&read, &format!("{at}: to_beef read back"));
        }
        if let Ok(t) = Transaction::from_beef(&bytes, None) {
            judged += law_reach(&t, &format!("{at}: from_beef"));
        }
    }
    if let Ok(bytes) = tx.to_atomic_beef(true) {
        if let Ok(read) = Beef::from_binary(&bytes) {
            judged += beef_entries_law(&read, &format!("{at}: to_atomic_beef read back"));
        }
        if let Ok(t) = Transaction::from_atomic_beef(&bytes) {
            judged += law_reach(&t, &format!("{at}: from_atomic_beef"));
        }
    }
    judged += law_reach(&tx.clone(), &format!("{at}: clone"));
    judged
}

fn key() -> PrivateKey {
    PrivateKey::from_bytes(&[7u8; 32]).unwrap()
}

fn p2pkh_lock() -> LockingScript {
    P2PKH::new().lock(&key().public_key().hash160()).unwrap()
}

/// A small parent, itself linked to a grandparent one time in two, and that
/// grandparent to a great-grandparent two times in three of those (the
/// strength read: depth three was never built).
fn parent(rng: &mut Rng) -> Transaction {
    let mut p = Transaction::new();
    if rng.below(2) == 0 {
        let mut g = Transaction::new();
        if rng.below(3) != 0 {
            let mut gg = Transaction::new();
            gg.add_input(TransactionInput::new(rng.txid().parse().unwrap(), 0))
                .unwrap();
            gg.add_output(TransactionOutput::new(6_000, rng.script()))
                .unwrap();
            g.add_input(TransactionInput::with_source_transaction(gg, 0))
                .unwrap();
        } else {
            g.add_input(TransactionInput::new(
                rng.txid().parse().unwrap(),
                rng.u32() % 4,
            ))
            .unwrap();
        }
        g.add_output(TransactionOutput::new(5_000, rng.script()))
            .unwrap();
        p.add_input(TransactionInput::with_source_transaction(g, 0))
            .unwrap();
    } else {
        p.add_input(TransactionInput::new(rng.txid().parse().unwrap(), 0))
            .unwrap();
    }
    p.add_output(TransactionOutput::new(4_000, rng.script()))
        .unwrap();
    p.set_lock_time(rng.u32() % 3);
    p
}

/// The txid an input holds for `text` (#845): `Txid::from_hex`'s answer, a
/// text that does not parse refused there, so the input names none.
/// `parses` is what the caller expects of the text, asserted.
fn held(text: &str, parses: bool) -> Option<Txid> {
    let txid = Txid::from_hex(text).ok();
    assert_eq!(txid.is_some(), parses, "{text:?}");
    txid
}

/// One step through a public door; its name for the failure's log.
fn step(
    tx: &mut Transaction,
    rng: &mut Rng,
    rt: &tokio::runtime::Runtime,
    counts: &mut Counts,
) -> &'static str {
    let room = tx.inputs().len() < 10 && tx.outputs().len() < 10;
    match rng.below(31) {
        0 => {
            tx.set_version(rng.u32() % 3);
            "set_version"
        }
        1 | 2 => {
            tx.set_lock_time(rng.u32());
            "set_lock_time"
        }
        3 if room => {
            let mut input = TransactionInput::new(rng.txid().parse().unwrap(), rng.u32() % 8);
            input.sequence = rng.u32();
            tx.inputs_mut().push(input);
            "inputs_mut().push"
        }
        4 if room => {
            let output = TransactionOutput::new(rng.below(1 << 40), rng.script());
            tx.outputs_mut().push(output);
            "outputs_mut().push"
        }
        5 if !tx.inputs().is_empty() => {
            let i = rng.below(tx.inputs().len() as u64) as usize;
            let seq = rng.u32();
            let input = &mut tx.inputs_mut()[i];
            match seq % 3 {
                0 => input.sequence = seq,
                1 => input.source_output_index = seq % 16,
                _ => {
                    input.unlocking_script =
                        Some(UnlockingScript::from_binary(&[0x51, (seq & 0x3f) as u8]).unwrap())
                }
            }
            "inputs_mut()[i] edit"
        }
        6 if !tx.outputs().is_empty() => {
            let i = rng.below(tx.outputs().len() as u64) as usize;
            let (sats, script) = (rng.below(1 << 40), rng.script());
            let output = &mut tx.outputs_mut()[i];
            if sats.is_multiple_of(2) {
                output.satoshis = Some(sats);
            } else {
                output.locking_script = script;
            }
            "outputs_mut()[i] edit"
        }
        7 => {
            if rng.below(2) == 0 {
                tx.inputs_mut().pop();
                "inputs_mut().pop"
            } else {
                let keep = rng.next();
                let mut n = 0;
                tx.outputs_mut().retain(|_| {
                    n += 1;
                    keep >> (n % 64) & 1 == 1
                });
                "outputs_mut().retain"
            }
        }
        8 => {
            let txid = rng.txid();
            let flip = rng.u32();
            let parts = tx.parts_mut();
            *parts.lock_time = parts.inputs.len() as u32 ^ flip;
            *parts.version = parts.outputs.len() as u32;
            if parts.inputs.len() < 10 {
                parts
                    .inputs
                    .push(TransactionInput::new(txid.parse().unwrap(), 1));
            }
            "parts_mut"
        }
        9 => {
            // The parts are lossless (#869's fold): metadata and the merkle
            // path travel through them, nothing saved around the call.
            let TransactionParts {
                version,
                mut inputs,
                outputs,
                lock_time,
                metadata,
                merkle_path,
            } = std::mem::take(tx).into_parts();
            if inputs.len() > 1 {
                inputs.swap(0, 1);
            }
            *tx = Transaction::from_parts(TransactionParts {
                version: lock_time % 3,
                inputs,
                outputs,
                lock_time: version,
                metadata,
                merkle_path,
            });
            "into_parts/from_parts"
        }
        10 if room => {
            let input = TransactionInput::new(rng.txid().parse().unwrap(), rng.u32() % 4);
            tx.add_input(input).unwrap();
            "add_input"
        }
        11 if room => {
            match rng.below(5) {
                0 => tx
                    .add_output(TransactionOutput::new(rng.below(1 << 30), rng.script()))
                    .unwrap(),
                1 => tx.add_op_return_output(b"843").unwrap(),
                2 => tx.add_op_return_parts_output(&[b"a", b"bc"]).unwrap(),
                3 => tx
                    .add_p2pkh_output(&key().public_key().to_address(), Some(rng.below(1 << 20)))
                    .unwrap(),
                _ => tx
                    .add_hash_puzzle_output("secret", &"ab".repeat(20), rng.below(1 << 20))
                    .unwrap(),
            }
            "add_output family"
        }
        12 if room => {
            let p = parent(rng);
            tx.add_input(TransactionInput::with_source_transaction(p, 0))
                .unwrap();
            "add_input of a linked parent"
        }
        13 | 14 | 23 => {
            let linked: Vec<usize> = (0..tx.inputs().len())
                .filter(|&i| tx.inputs()[i].source_transaction.is_some())
                .collect();
            let Some(&i) = linked.get(rng.below(linked.len() as u64 + 1) as usize) else {
                return "no linked parent to edit";
            };
            let lock = rng.u32();
            // Walk down to a depth the generator picks (1 to 3, 3 one time in
            // two), through the
            // deepest linked input at each level, each level through its own
            // `inputs_mut()` (so every ancestor on the way is cleared).
            let target = [1, 2, 3, 3][rng.below(4) as usize];
            // Below the parent, the input whose ancestry is deepest.
            let i = if target > 1 {
                linked
                    .iter()
                    .copied()
                    .max_by_key(|&k| depth(tx.inputs()[k].source_transaction.as_deref().unwrap()))
                    .unwrap_or(i)
            } else {
                i
            };
            let mut cur = tx.inputs_mut()[i].source_transaction.as_mut().unwrap();
            let mut at = 1;
            while at < target
                && cur
                    .inputs()
                    .iter()
                    .any(|input| input.source_transaction.is_some())
            {
                // The deepest linked input, so depth three is reached.
                let k = (0..cur.inputs().len())
                    .filter(|&k| cur.inputs()[k].source_transaction.is_some())
                    .max_by_key(|&k| depth(cur.inputs()[k].source_transaction.as_deref().unwrap()))
                    .unwrap();
                cur = cur.inputs_mut()[k].source_transaction.as_mut().unwrap();
                at += 1;
            }
            match at {
                1 => {
                    if lock.is_multiple_of(2) {
                        cur.set_lock_time(lock);
                    } else {
                        cur.outputs_mut()[0].satoshis = Some(u64::from(lock));
                    }
                    "a linked parent's edit through inputs_mut()"
                }
                2 => {
                    cur.set_lock_time(lock);
                    "a linked grandparent's set_lock_time"
                }
                _ => {
                    cur.set_lock_time(lock);
                    "a linked great-grandparent's set_lock_time"
                }
            }
        }
        15 => {
            *tx = tx.clone();
            "clone"
        }
        16 => {
            // `from_json` refuses an input txid that is not 64 hex digits
            // (#845), so a transaction holding one is kept as it is.
            match tx
                .to_json()
                .ok()
                .and_then(|j| Transaction::from_json(&j).ok())
            {
                Some(back) => {
                    *tx = back;
                    "JSON round trip"
                }
                None => "JSON round trip refused",
            }
        }
        17 => {
            let hex = if rng.below(2) == 0 {
                tx.to_hex()
            } else {
                tx.to_hex().to_uppercase()
            };
            *tx = Transaction::from_hex(&hex).unwrap();
            "from_hex re-read"
        }
        18 if room => {
            let templated = tx
                .inputs()
                .iter()
                .filter(|i| i.unlocking_script_template.is_some())
                .count();
            if templated < 2 {
                tx.add_input_from(
                    &rng.txid(),
                    rng.u32() % 3,
                    &p2pkh_lock(),
                    10_000 + rng.below(10_000),
                    P2PKH::unlock(&key(), SignOutputs::All, false),
                )
                .unwrap();
            }
            "add_input_from"
        }
        19 if room => {
            let utxo = Utxo {
                txid: rng.txid(),
                vout: rng.u32() % 3,
                satoshis: 1_000 + rng.below(1_000),
                locking_script: rng.script(),
            };
            tx.add_inputs_from_utxos(&[utxo]).unwrap();
            "add_inputs_from_utxos"
        }
        20 => {
            let signable = tx.inputs().iter().all(|i| {
                i.unlocking_script_template.is_none()
                    || (i.source_satoshis().is_some() && i.source_locking_script().is_some())
            });
            if signable && tx.outputs().iter().all(|o| o.satoshis.is_some()) {
                let before: Vec<Option<Vec<u8>>> = scripts(tx);
                // A txid text that does not parse can refuse a signing; the
                // law holds whatever was written before the refusal.
                let signed = rt.block_on(tx.sign()).is_ok();
                if signed && scripts(tx) != before
                    || tx
                        .inputs()
                        .iter()
                        .any(|i| i.unlocking_script_template.is_some())
                {
                    counts.signings += 1;
                }
            }
            "sign"
        }
        21 => {
            // Unfunded inputs dropped first (through the door), so `fee` runs
            // often (the strength read: it rarely ran).
            tx.inputs_mut().retain(|i| i.source_satoshis().is_some());
            if tx.inputs().is_empty() {
                tx.add_input_from(
                    &rng.txid(),
                    0,
                    &p2pkh_lock(),
                    20_000 + rng.below(10_000),
                    P2PKH::unlock(&key(), SignOutputs::All, false),
                )
                .unwrap();
            }
            if tx.outputs().len() < 10 {
                for _ in 0..=rng.below(2) {
                    tx.add_p2pkh_output(&key().public_key().to_address(), None)
                        .unwrap();
                }
                // Funded before `fee` (#871: `fee` refuses inputs that
                // cannot pay the outputs and the fee, as the reference does,
                // where it saturated the change to 0 until then): an input
                // of the shortfall, by a txid drawn from no generator, so the
                // sequence the seed draws is unchanged.
                let paid: u64 = tx
                    .outputs()
                    .iter()
                    .filter(|o| !o.change)
                    .filter_map(|o| o.satoshis)
                    .sum();
                let funded: u64 = tx.inputs().iter().filter_map(|i| i.source_satoshis()).sum();
                if funded < paid + 200 {
                    let vout = tx.inputs().len() as u32;
                    tx.add_input_from(
                        &"77".repeat(32),
                        vout,
                        &p2pkh_lock(),
                        paid + 200 - funded,
                        P2PKH::unlock(&key(), SignOutputs::All, false),
                    )
                    .unwrap();
                }
                // The caches full before `fee` writes (a plant of `fee`'s or
                // `distribute_change`'s door was caught only so).
                let _ = (tx.id(), tx.to_hex());
                // `Random` over any number of change outputs: #868 is fixed
                // on beta (the avoidance this line held until #869's fold).
                let changes = tx.outputs().iter().filter(|o| o.change).count();
                let distribution = if rng.below(2) == 0 {
                    counts.fee_equal += 1;
                    ChangeDistribution::Equal
                } else {
                    counts.fee_random += 1;
                    counts.fee_random_multi += usize::from(changes > 1);
                    ChangeDistribution::Random
                };
                rt.block_on(tx.fee(Some(rng.below(200)), distribution))
                    .unwrap();
                // A change output left uncomputed (no change) is removed by
                // `fee`; one left by a later edit is given an amount here.
                for (i, o) in tx.outputs().to_vec().iter().enumerate() {
                    if o.satoshis.is_none() {
                        tx.outputs_mut()[i].satoshis = Some(1);
                    }
                }
            }
            "fee"
        }
        22 => {
            tx.update_metadata("k", serde_json::json!(rng.u32()));
            "update_metadata"
        }
        24..=26 => odd_txid(tx, rng, counts),
        27 | 28 => link_kind(tx, rng),
        29 | 30 => shared_txid(tx, rng, counts),
        _ => "no step",
    }
}

/// A source txid text the serializer cannot read (#869's second fold, the
/// cold re-read's states), on an input of `tx` (one pushed when it has
/// none), with and without a linked source; or a text that parses and is
/// not the linked source's id.
fn odd_txid(top: &mut Transaction, rng: &mut Rng, counts: &mut Counts) -> &'static str {
    // One time in two on a linked source's input, through the child's door:
    // a BEEF stores the top as given and every ancestor as a copy, and the
    // copy is where the cold re-read's probe broke the law.
    let linked: Vec<usize> = (0..top.inputs().len())
        .filter(|&k| top.inputs()[k].source_transaction.is_some())
        .collect();
    let below = !linked.is_empty() && rng.below(2) == 0;
    let tx: &mut Transaction = if below {
        counts.odd_below_the_top += 1;
        let k = linked[rng.below(linked.len() as u64) as usize];
        top.inputs_mut()[k].source_transaction.as_mut().unwrap()
    } else {
        top
    };
    if tx.inputs().is_empty() {
        tx.inputs_mut()
            .push(TransactionInput::new(rng.txid().parse().unwrap(), 0));
    }
    let i = rng.below(tx.inputs().len() as u64) as usize;
    let kind = rng.below(7);
    let (text, linked, name) = match kind {
        0 => ("zz".repeat(32), true, "odd txid: not hex, linked"),
        1 => ("zz".repeat(32), false, "odd txid: not hex, unlinked"),
        2 => (
            rng.txid()[..62].to_string(),
            true,
            "odd txid: wrong length, linked",
        ),
        3 => (
            format!("{}00", rng.txid()),
            false,
            "odd txid: wrong length, unlinked",
        ),
        4 => (String::new(), true, "odd txid: empty, linked"),
        5 => (String::new(), false, "odd txid: empty, unlinked"),
        _ => (
            rng.txid(),
            true,
            "odd txid: parses and differs from the source",
        ),
    };
    let source = if linked {
        Some(Box::new(parent(rng)))
    } else {
        None
    };
    let input = &mut tx.inputs_mut()[i];
    // #845: a text that is no txid is refused where it enters, so the odd
    // arms that do not parse leave the input naming no txid (the serializer
    // reads the linked source, or writes zeros); the last arm holds its id.
    input.source_txid = held(&text, kind == 6);
    input.source_transaction = source;
    name
}

/// Two or three inputs of one transaction (the top, or one time in two a
/// linked source) sharing one txid text, each linked to a source of its own
/// (#869's third fold, the cold re-read of the second fold): a text that
/// does not parse (`"zz"`, `""`, `"abc"`), whose outpoints are then the
/// sources' ids, or one that parses and is none of their ids. The BEEF
/// linker keyed its stubs by the text, so the second input was handed the
/// first one's source.
fn shared_txid(top: &mut Transaction, rng: &mut Rng, counts: &mut Counts) -> &'static str {
    let linked: Vec<usize> = (0..top.inputs().len())
        .filter(|&k| top.inputs()[k].source_transaction.is_some())
        .collect();
    let below = !linked.is_empty() && rng.below(2) == 0;
    let tx: &mut Transaction = if below {
        counts.shared_below_the_top += 1;
        let k = linked[rng.below(linked.len() as u64) as usize];
        top.inputs_mut()[k].source_transaction.as_mut().unwrap()
    } else {
        top
    };
    if tx.inputs().len() >= 10 {
        return "no room to share a txid";
    }
    let (text, name) = match rng.below(4) {
        0 => ("zz".to_string(), "shared txid: does not parse"),
        1 => (String::new(), "shared txid: does not parse"),
        2 => ("abc".to_string(), "shared txid: does not parse"),
        _ => (rng.txid(), "shared txid: parses"),
    };
    let shared = held(&text, name == "shared txid: parses");
    for _ in 0..2 + rng.below(2) {
        let mut input = TransactionInput {
            source_txid: shared,
            source_output_index: rng.u32() % 2,
            ..TransactionInput::default()
        };
        input.source_transaction = Some(Box::new(parent(rng)));
        tx.inputs_mut().push(input);
    }
    name
}

/// Each input of `given` that carries a source and whose counterpart in
/// `linked` does too names the same source, by id, at every depth both
/// reach (#869's third fold): a door that links a transaction hands back
/// the sources it was given.
fn same_sources(given: &Transaction, linked: &Transaction, at: &str) {
    let mut stack = vec![(given, linked)];
    while let Some((g, l)) = stack.pop() {
        for (k, (gi, li)) in g.inputs().iter().zip(l.inputs()).enumerate() {
            if let (Some(gs), Some(ls)) = (
                gi.source_transaction.as_deref(),
                li.source_transaction.as_deref(),
            ) {
                assert_eq!(ls.id(), gs.id(), "{at}: input {k}'s linked source");
                stack.push((gs, ls));
            }
        }
    }
}

/// A source linked to an input of `tx` under each of the four namings the
/// linking door distinguishes (#869's second fold): `source_txid` set and
/// the source's id, set and another, `None`, and a text that does not
/// parse. The BEEF law after the step links it again through the door.
fn link_kind(tx: &mut Transaction, rng: &mut Rng) -> &'static str {
    if tx.inputs().len() >= 10 {
        return "no room to link";
    }
    let source = parent(rng);
    let (txid, name) = match rng.below(4) {
        0 => (Some(source.txid()), "link: txid the source's id"),
        1 => (held(&rng.txid(), true), "link: txid another"),
        2 => (None, "link: no txid"),
        _ => (held("zz", false), "link: txid not hex"),
    };
    tx.inputs_mut().push(TransactionInput {
        source_txid: txid,
        source_transaction: Some(Box::new(source)),
        ..TransactionInput::default()
    });
    name
}

/// What the property's sequences did, counted (the strength read: the
/// 4,976 "signs" were picks of the step, not signings).
#[derive(Default, Debug)]
struct Counts {
    /// `sign` calls that ran over a templated input (a script written).
    signings: usize,
    fee_equal: usize,
    fee_random: usize,
    /// `Random` over two or more change outputs (#868's cell).
    fee_random_multi: usize,
    /// Steps after which the deepest linked source sat at depth 1, 2, 3.
    depth: [usize; 4],
    /// Each step by its name.
    steps: std::collections::BTreeMap<&'static str, usize>,
    /// Transactions the BEEF law judged (a BEEF's stored copies, at every
    /// depth, through every door of `beef_law`).
    beef_copies: usize,
    /// The BEEF law's runs, by the step before each.
    beef_after: std::collections::BTreeMap<&'static str, usize>,
    /// Odd namings made on a linked source's input, not the top's.
    odd_below_the_top: usize,
    /// Shared txid texts made on a linked source's inputs, not the top's.
    shared_below_the_top: usize,
}

/// Each input's unlocking script bytes.
fn scripts(tx: &Transaction) -> Vec<Option<Vec<u8>>> {
    tx.inputs()
        .iter()
        .map(|i| i.unlocking_script.as_ref().map(|s| s.to_binary()))
        .collect()
}

/// The deepest linked source below `tx` (0 with none).
fn depth(tx: &Transaction) -> usize {
    tx.inputs()
        .iter()
        .filter_map(|i| i.source_transaction.as_deref())
        .map(|s| 1 + depth(s))
        .max()
        .unwrap_or(0)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

/// One seeded run of `sequences` sequences of [`STEPS`] steps, the law after
/// every step; with `beef`, the BEEF law of [`beef_law`] too after every step
/// that made an odd naming or a link and after each sequence's last.
fn run(seed: u64, sequences: usize, beef: bool) -> (Counts, std::time::Duration) {
    let rt = runtime();
    let started = std::time::Instant::now();
    let mut rng = Rng(seed);
    let mut counts = Counts::default();
    for sequence in 0..sequences {
        let mut tx = if rng.below(2) == 0 {
            parent(&mut rng)
        } else {
            Transaction::new()
        };
        let mut log: Vec<&'static str> = Vec::new();
        for _ in 0..STEPS {
            let name = step(&mut tx, &mut rng, &rt, &mut counts);
            *counts.steps.entry(name).or_default() += 1;
            counts.depth[depth(&tx).min(3)] += 1;
            log.push(name);
            let at = format!("seed {seed:#x}, sequence {sequence}, steps {log:?}");
            let judge = beef
                && (name.starts_with("odd txid")
                    || name.starts_with("link:")
                    || name.starts_with("shared txid")
                    || log.len() == STEPS);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                law(&tx, &at);
                if judge {
                    beef_law(&tx, &at)
                } else {
                    0
                }
            }));
            match outcome {
                Ok(judged) => {
                    counts.beef_copies += judged;
                    if judge {
                        *counts.beef_after.entry(name).or_default() += 1;
                    }
                }
                Err(e) => std::panic::resume_unwind(e),
            }
        }
    }
    (counts, started.elapsed())
}

#[test]
fn every_edit_through_a_door_keeps_the_id_the_hash_of_the_fields_843() {
    let (counts, elapsed) = run(SEED, SEQUENCES, false);
    println!("{SEQUENCES} sequences of {STEPS} steps in {elapsed:?}: {counts:#?}");
    reach_floors(&counts);
    assert!(
        elapsed.as_secs() < 60,
        "the property run stays inside a minute: {elapsed:?}"
    );
}

/// The seed of the BEEF-copy run.
const BEEF_SEED: u64 = 0x0869_beef_0002;
/// Sequences of the BEEF-copy run.
const BEEF_SEQUENCES: usize = 2_000;

/// The law over every copy a BEEF stores (#869's second fold, the cold
/// re-read's FIX): the property's own steps, the odd namings and the four
/// links among them, and after each odd naming, each link and each
/// sequence's last step every transaction reachable through
/// `merge_transaction`, `merge_beef` (into an empty BEEF and into itself),
/// `to_beef` and `to_atomic_beef` read back, `from_beef`,
/// `from_atomic_beef`, the linking door's two callers and `clone` keeps
/// `id()` the hash of its fields and of `from_binary(to_binary())`.
#[test]
fn every_copy_a_beef_stores_keeps_the_law_869() {
    let (counts, elapsed) = run(BEEF_SEED, BEEF_SEQUENCES, true);
    println!("{BEEF_SEQUENCES} sequences, the BEEF law, in {elapsed:?}: {counts:#?}");
    let after = |name: &str| counts.beef_after.get(name).copied().unwrap_or(0);
    let names = [
        "odd txid: not hex, linked",
        "odd txid: not hex, unlinked",
        "odd txid: wrong length, linked",
        "odd txid: wrong length, unlinked",
        "odd txid: empty, linked",
        "odd txid: empty, unlinked",
        "odd txid: parses and differs from the source",
        "link: txid the source's id",
        "link: txid another",
        "link: no txid",
        "link: txid not hex",
        "shared txid: does not parse",
        "shared txid: parses",
    ];
    let short: Vec<String> = names
        .iter()
        .filter(|n| after(n) < FLOOR)
        .map(|n| format!("{n}: {} < {FLOOR}", after(n)))
        .collect();
    assert!(
        short.is_empty(),
        "seed {BEEF_SEED:#x}: the BEEF law's reach fell below its floor: {short:?}"
    );
    assert!(
        counts.odd_below_the_top >= FLOOR,
        "odd namings below the top: {}",
        counts.odd_below_the_top
    );
    assert!(
        counts.shared_below_the_top >= FLOOR,
        "shared txid texts below the top: {}",
        counts.shared_below_the_top
    );
    assert!(
        counts.beef_copies >= 100 * FLOOR,
        "the BEEF law judged {} copies",
        counts.beef_copies
    );
    assert!(
        elapsed.as_secs() < 60,
        "the BEEF-copy run stays inside a minute: {elapsed:?}"
    );
}

/// The property's reach, asserted: a floor per count, each printed with the
/// seed on failure (#869's fold).
fn reach_floors(c: &Counts) {
    let step = |name: &str| c.steps.get(name).copied().unwrap_or(0);
    let floors: &[(&str, usize, usize)] = &[
        ("signings that wrote a script", c.signings, FLOOR),
        ("fee, Equal", c.fee_equal, FLOOR),
        ("fee, Random", c.fee_random, FLOOR),
        (
            "fee, Random over two or more change outputs",
            c.fee_random_multi,
            FLOOR,
        ),
        ("steps ending at depth 1", c.depth[1], FLOOR),
        ("steps ending at depth 2", c.depth[2], FLOOR),
        ("steps ending at depth 3", c.depth[3], FLOOR),
        ("set_version", step("set_version"), FLOOR),
        ("set_lock_time", step("set_lock_time"), FLOOR),
        ("inputs_mut().push", step("inputs_mut().push"), FLOOR),
        ("outputs_mut().push", step("outputs_mut().push"), FLOOR),
        ("inputs_mut()[i] edit", step("inputs_mut()[i] edit"), FLOOR),
        (
            "outputs_mut()[i] edit",
            step("outputs_mut()[i] edit"),
            FLOOR,
        ),
        ("inputs_mut().pop", step("inputs_mut().pop"), FLOOR),
        ("outputs_mut().retain", step("outputs_mut().retain"), FLOOR),
        ("parts_mut", step("parts_mut"), FLOOR),
        (
            "into_parts/from_parts",
            step("into_parts/from_parts"),
            FLOOR,
        ),
        ("add_input", step("add_input"), FLOOR),
        ("add_output family", step("add_output family"), FLOOR),
        (
            "add_input of a linked parent",
            step("add_input of a linked parent"),
            FLOOR,
        ),
        (
            "a linked parent's edit",
            step("a linked parent's edit through inputs_mut()"),
            FLOOR,
        ),
        (
            "a linked grandparent's edit",
            step("a linked grandparent's set_lock_time"),
            FLOOR,
        ),
        (
            "a linked great-grandparent's edit",
            step("a linked great-grandparent's set_lock_time"),
            FLOOR,
        ),
        ("clone", step("clone"), FLOOR),
        ("JSON round trip", step("JSON round trip"), FLOOR),
        ("from_hex re-read", step("from_hex re-read"), FLOOR),
        ("add_input_from", step("add_input_from"), FLOOR),
        (
            "add_inputs_from_utxos",
            step("add_inputs_from_utxos"),
            FLOOR,
        ),
        ("update_metadata", step("update_metadata"), FLOOR),
        (
            "odd txid: not hex, linked",
            step("odd txid: not hex, linked"),
            FLOOR,
        ),
        (
            "odd txid: not hex, unlinked",
            step("odd txid: not hex, unlinked"),
            FLOOR,
        ),
        (
            "odd txid: wrong length, linked",
            step("odd txid: wrong length, linked"),
            FLOOR,
        ),
        (
            "odd txid: wrong length, unlinked",
            step("odd txid: wrong length, unlinked"),
            FLOOR,
        ),
        (
            "odd txid: empty, linked",
            step("odd txid: empty, linked"),
            FLOOR,
        ),
        (
            "odd txid: empty, unlinked",
            step("odd txid: empty, unlinked"),
            FLOOR,
        ),
        (
            "odd txid: parses and differs from the source",
            step("odd txid: parses and differs from the source"),
            FLOOR,
        ),
        (
            "link: txid the source's id",
            step("link: txid the source's id"),
            FLOOR,
        ),
        ("link: txid another", step("link: txid another"), FLOOR),
        ("link: no txid", step("link: no txid"), FLOOR),
        ("link: txid not hex", step("link: txid not hex"), FLOOR),
        ("odd txid below the top", c.odd_below_the_top, FLOOR),
        (
            "shared txid: does not parse",
            step("shared txid: does not parse"),
            FLOOR,
        ),
        ("shared txid: parses", step("shared txid: parses"), FLOOR),
        ("shared txid below the top", c.shared_below_the_top, FLOOR),
    ];
    let short: Vec<String> = floors
        .iter()
        .filter(|(_, n, floor)| n < floor)
        .map(|(name, n, floor)| format!("{name}: {n} < {floor}"))
        .collect();
    assert!(
        short.is_empty(),
        "seed {SEED:#x}: the property's reach fell below its floor: {short:?}\n{c:#?}"
    );
}

/// Probe A: a linked parent edited through the child, the child's id moves
/// with it. On the base the parent was edited through the public field,
/// `invalidate_caches()` called on the child, and the child's `id()` stayed.
#[test]
fn an_edited_linked_parent_changes_the_child_id_843() {
    let mut rng = Rng(SEED ^ 0xa);
    let mut parent = Transaction::new();
    parent
        .add_input(TransactionInput::new(rng.txid().parse().unwrap(), 0))
        .unwrap();
    parent
        .add_output(TransactionOutput::new(1_000, rng.script()))
        .unwrap();
    let mut child = Transaction::new();
    child
        .add_input(TransactionInput::with_source_transaction(parent, 0))
        .unwrap();
    child
        .add_output(TransactionOutput::new(900, rng.script()))
        .unwrap();
    let (child_before, parent_before) = (
        child.id(),
        child.inputs()[0].source_transaction.as_ref().unwrap().id(),
    );
    child.inputs_mut()[0]
        .source_transaction
        .as_mut()
        .unwrap()
        .set_lock_time(7);
    let parent_after = child.inputs()[0].source_transaction.as_ref().unwrap().id();
    assert_ne!(parent_after, parent_before, "the parent's id moved");
    assert_ne!(child.id(), child_before, "the child's id moved with it");
    let mut wire = parent_after.clone();
    wire = {
        let mut b = from_hex(&wire).unwrap();
        b.reverse();
        to_hex(&b)
    };
    assert_eq!(
        to_hex(&child.to_binary()[5..37]),
        wire,
        "the child writes the parent's new id"
    );
    law(&child, "probe A");
}

/// Probe B: equality follows the fields. On the base `a.lock_time = 7` left
/// `a == b` true.
#[test]
fn an_edit_makes_unequal_what_it_changed_843() {
    let mut rng = Rng(SEED ^ 0xb);
    let a0 = parent(&mut rng);
    let (mut a, mut b) = (a0.clone(), a0);
    let _ = (a.to_binary(), b.to_binary());
    a.set_lock_time(a.lock_time() + 7);
    assert!(a != b, "an edited value is not equal to its unedited twin");
    b.set_lock_time(b.lock_time() + 7);
    assert!(a == b, "the same edit on both: equal again");
}

/// Probe C: the JSON round trip keeps the edit. On the base `to_json` wrote
/// the stale `hex` beside `"lockTime":7`, and `from_json` read `lock_time` 0.
#[test]
fn a_json_round_trip_keeps_the_edit_843() {
    let mut rng = Rng(SEED ^ 0xc);
    let mut c = parent(&mut rng);
    let _ = c.id();
    c.set_lock_time(7);
    let back = Transaction::from_json(&c.to_json().unwrap()).unwrap();
    assert_eq!(back.lock_time(), 7);
    assert_eq!(back.id(), c.id());
}

/// Probe D: a clone after an edit carries the edit. On the base the clone
/// copied the stale cache.
#[test]
fn a_clone_after_an_edit_carries_the_edit_843() {
    let mut rng = Rng(SEED ^ 0xd);
    let mut d = parent(&mut rng);
    let before = d.id();
    d.set_lock_time(d.lock_time() + 7);
    let copy = d.clone();
    assert_ne!(copy.id(), before);
    assert_eq!(copy.id(), display(sha256d(&fields_bytes(&copy))));
}

/// Probe E: `id()` is the hash of the fields, after an edit made with the
/// caches full.
#[test]
fn the_id_is_the_hash_of_the_fields_843() {
    let mut rng = Rng(SEED ^ 0xe);
    let mut e = parent(&mut rng);
    let _ = (e.id(), e.to_hex());
    e.set_lock_time(e.lock_time() + 7);
    assert_eq!(e.id(), display(sha256d(&fields_bytes(&e))));
}

/// #843's table: after `set_lock_time(7)` (the base's `lock_time = 7`, then
/// `invalidate_caches()`), `id()`, `to_binary()` and `to_hex()` are the
/// edited ones at once. On the base, before `invalidate_caches()`, the three
/// answered the bytes before the edit (last four bytes `00 00 00 00`).
#[test]
fn the_lock_time_table_843() {
    let mut t = Transaction::new();
    t.add_input(TransactionInput::new("11".repeat(32).parse().unwrap(), 0))
        .unwrap();
    t.add_output(TransactionOutput::new(
        1_000,
        LockingScript::from_script(Script::from_binary(&[0x51]).unwrap()),
    ))
    .unwrap();
    let (id0, bin0, hex0) = (t.id(), t.to_binary(), t.to_hex());
    assert!(bin0.ends_with(&[0, 0, 0, 0]));
    t.set_lock_time(7);
    let bin = t.to_binary();
    assert!(bin.ends_with(&[7, 0, 0, 0]), "to_binary() ends 07 00 00 00");
    assert_ne!(bin, bin0);
    assert_ne!(t.id(), id0, "id() moved");
    assert_ne!(t.to_hex(), hex0, "to_hex() moved");
    assert_eq!(t.to_hex(), to_hex(&bin));
    assert_eq!(t.id(), display(sha256d(&bin)));
    // The base's values, recorded on `7ab65f65` (the lane record's RED).
    assert_eq!(
        id0,
        "99296a9c40f5e307530147cc99133f35ae866b280d362d7c487bfd30ea1d72d8"
    );
    assert_eq!(
        t.id(),
        "32571cd650a936108dc37b97eb6515d3fc89dc9973a6b6b3ffaca457733c32fb"
    );
}

/// `fee` writes the change (or removes a change output it cannot fund)
/// through the doors: after the caches are full, the id is the hash of the
/// fields with the change written, for each distribution and for no change.
/// A plant of `fee`'s `retain` or of `distribute_change` that wrote the field
/// past its door went uncaught by the property run until this cell (the lane
/// record's plant table).
#[test]
fn fee_writes_the_change_through_the_doors_after_the_caches_are_full_843() {
    let rt = runtime();
    for (fee, distribution, changes) in [
        (100, ChangeDistribution::Equal, 2),
        (100, ChangeDistribution::Random, 1),
        // No change: the output removed. The inputs exactly the payment and
        // the fee (#871: a fee they cannot pay is refused, as the reference
        // refuses it; 50,000 over 20,000 saturated to no change until then).
        (19_000, ChangeDistribution::Equal, 1),
    ] {
        let mut tx = Transaction::new();
        tx.add_input_from(
            &"22".repeat(32),
            0,
            &p2pkh_lock(),
            20_000,
            P2PKH::unlock(&key(), SignOutputs::All, false),
        )
        .unwrap();
        tx.add_output(TransactionOutput::new(1_000, p2pkh_lock()))
            .unwrap();
        for _ in 0..changes {
            tx.add_p2pkh_output(&key().public_key().to_address(), None)
                .unwrap();
        }
        let before = (tx.id(), tx.to_hex(), tx.to_binary());
        rt.block_on(tx.fee(Some(fee), distribution)).unwrap();
        law(
            &tx,
            &format!("fee {fee} {distribution:?} over {changes} change outputs"),
        );
        assert_ne!(tx.id(), before.0, "the change is written: the id moved");
        rt.block_on(tx.sign()).unwrap();
        law(&tx, "signed after fee");
    }
}

/// A transaction holding a merkle path and metadata, with a linked parent.
fn proven_with_metadata() -> Transaction {
    let mut rng = Rng(SEED ^ 0x869);
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::with_source_transaction(
        parent(&mut rng),
        0,
    ))
    .unwrap();
    tx.add_output(TransactionOutput::new(3_000, rng.script()))
        .unwrap();
    tx.merkle_path = Some(bsv_rs::transaction::MerklePath::from_coinbase_txid(
        &tx.id(),
        900,
    ));
    tx.update_metadata("note", serde_json::json!("kept"));
    tx
}

/// The parts are lossless (#869's fold, the rule read's FIX): on `98f09276`
/// `into_parts` dropped `metadata` and `merkle_path`, so this round trip lost
/// the proof while `==` (the bytes alone) still answered true, and a child's
/// `to_beef` then walked past it.
#[test]
fn into_parts_then_from_parts_keeps_the_merkle_path_and_the_metadata_869() {
    let tx = proven_with_metadata();
    let (id, path, metadata) = (tx.id(), tx.merkle_path.clone(), tx.metadata.clone());
    let back = Transaction::from_parts(tx.clone().into_parts());
    assert!(back == tx, "the same bytes");
    assert_eq!(back.id(), id);
    assert_eq!(
        back.merkle_path.as_ref().map(|p| p.to_hex().unwrap()),
        path.as_ref().map(|p| p.to_hex().unwrap()),
        "the merkle path kept"
    );
    assert_eq!(back.metadata, metadata, "the metadata kept");
    assert_eq!(back.inputs().len(), 1);
    assert!(
        back.inputs()[0].source_transaction.is_some(),
        "the link kept"
    );
    // The proof still stops the walk: the child's BEEF holds one BUMP and
    // no ancestor of `back` beyond `back` itself.
    let mut child = Transaction::new();
    child
        .add_input(TransactionInput::with_source_transaction(back, 0))
        .unwrap();
    child
        .add_output(TransactionOutput::new(2_000, p2pkh_lock()))
        .unwrap();
    let beef = bsv_rs::transaction::Beef::from_binary(&child.to_beef(false).unwrap()).unwrap();
    assert_eq!(beef.bumps.len(), 1, "the proof travelled through the parts");
    assert_eq!(beef.txs.len(), 2, "the walk stopped at the proven parent");
    law(&child, "a child of the round-tripped transaction");
}

/// `parts_mut` lends the six fields, the merkle path and the metadata among
/// them, and clears the caches as the other doors do (#869's fold).
#[test]
fn parts_mut_lends_the_merkle_path_and_the_metadata_869() {
    let mut tx = proven_with_metadata();
    let before = tx.id();
    {
        let parts = tx.parts_mut();
        assert!(parts.merkle_path.is_some());
        assert_eq!(parts.metadata.get("note"), Some(&serde_json::json!("kept")));
        parts.metadata.insert("more".into(), serde_json::json!(1));
        *parts.lock_time = 5;
    }
    assert!(tx.merkle_path.is_some(), "the path held while lent");
    assert_eq!(tx.metadata.len(), 2);
    assert_ne!(tx.id(), before);
    law(&tx, "after parts_mut");
    let defaulted = Transaction::from_parts(TransactionParts {
        version: 1,
        lock_time: 3,
        ..Default::default()
    });
    assert!(defaulted.merkle_path.is_none() && defaulted.metadata.is_empty());
    assert_eq!(defaulted.lock_time(), 3);
}

/// The parts' default is `Transaction::new()`'s (#869's second fold, the
/// rule re-read's FIX): version 1 and lock time 0, as the reference's
/// constructor defaults them (`ts-stack@edf6e03` `Transaction.ts:581-595`);
/// the derived `Default` gave version 0.
#[test]
fn the_parts_default_is_transaction_new_869() {
    let new = Transaction::new();
    let from_default = Transaction::from_parts(TransactionParts::default());
    assert_eq!(from_default.to_binary(), new.to_binary(), "byte for byte");
    assert_eq!(from_default.id(), new.id(), "by id");
    assert_eq!(from_default.version(), 1, "version 1");
    assert_eq!(from_default.lock_time(), 0, "lock time 0");
    assert!(from_default.inputs().is_empty() && from_default.outputs().is_empty());
    assert!(from_default.metadata.is_empty() && from_default.merkle_path.is_none());

    let parts = Transaction::new().into_parts();
    let default = TransactionParts::default();
    assert_eq!(parts.version, default.version, "into_parts' version");
    assert_eq!(parts.lock_time, default.lock_time, "into_parts' lock time");
    assert_eq!(parts.inputs.len(), default.inputs.len());
    assert_eq!(parts.outputs.len(), default.outputs.len());
    assert_eq!(parts.metadata, default.metadata);
    assert_eq!(parts.merkle_path.is_none(), default.merkle_path.is_none());

    let literal = TransactionParts {
        inputs: vec![TransactionInput::new("11".repeat(32).parse().unwrap(), 0)],
        outputs: vec![TransactionOutput::new(1, p2pkh_lock())],
        ..Default::default()
    };
    assert_eq!(
        literal.version, 1,
        "a `..Default::default()` literal is version 1"
    );
}

/// The cold re-read's probe (#869's second fold): an input whose txid text
/// does not parse and which has a linked source writes the source's hash;
/// the BEEF's copy of that transaction kept the cached id and dropped the
/// source, so its fields wrote 32 zero bytes under the id of the source's.
#[test]
fn a_beef_copy_of_a_parent_whose_txid_text_does_not_parse_keeps_the_law_869() {
    let script = || LockingScript::from_binary(&[0x51]).unwrap();
    let mut grandparent = Transaction::new();
    grandparent
        .inputs_mut()
        .push(TransactionInput::new("11".repeat(32).parse().unwrap(), 0));
    grandparent
        .outputs_mut()
        .push(TransactionOutput::new(1_000, script()));
    let mut parent = Transaction::new();
    // `"zz"` until #845: no txid now, the outpoint read through the source.
    let mut input = TransactionInput {
        source_txid: held("zz", false),
        ..TransactionInput::default()
    };
    input.source_transaction = Some(Box::new(grandparent));
    parent.inputs_mut().push(input);
    parent
        .outputs_mut()
        .push(TransactionOutput::new(900, script()));
    let mut child = Transaction::new();
    let input = TransactionInput::with_source_transaction(parent, 0);
    child.inputs_mut().push(input);
    child
        .outputs_mut()
        .push(TransactionOutput::new(800, script()));

    let parent_id = child.inputs()[0]
        .source_transaction
        .as_deref()
        .unwrap()
        .id();
    let mut beef = Beef::new();
    beef.merge_transaction(child.clone());
    let stored = beef.find_txid(&parent_id).expect("the parent held");
    let stored = stored.tx().expect("held as a transaction");
    assert_eq!(
        stored.id(),
        display(sha256d(&fields_bytes(stored))),
        "the BEEF's copy of the parent keeps the law"
    );
    assert!(beef_law(&child, "the probe's chain") > 0);
}
