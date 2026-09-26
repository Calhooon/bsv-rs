//! The dispatch of the signature hash on the CHRONICLE bit, on a witness from
//! the differential run against bitcoin-sv v1.2.2 (`879fc8b`),
//! Calhooon/bsv-rs#22. The reference's `SignatureHash`
//! (`interpreter.cpp:2112-2124`) computes the BIP143 digest only when
//! `SCRIPT_ENABLE_SIGHASH_FORKID` is in the flags and the hash type carries
//! the FORKID bit and not the CHRONICLE bit (`SIGHASH_CHRONICLE = 0x20`,
//! `sighashtype.h:14`); every other type is hashed by the original serializer
//! (`SignatureHashOriginal`, `2086-2110`; `CTransactionSignatureSerializer`,
//! `1841-1958`). 0.3.28 computed BIP143 for every type. Under STRICTENC the
//! CHRONICLE bit is legal only when `SCRIPT_CHRONICLE` is in the flags
//! (`291-303`, `SCRIPT_ERR_ILLEGAL_CHRONICLE`).
//!
//! The witness: a version-2 P2PK spend of a coin created after Chronicle
//! whose locking script is `<pubkey> OP_CHECKSIG OP_RETURN 0x4c` (the
//! truncated push after a top-level `OP_RETURN` is data the interpreter never
//! reads, `interpreter.cpp:856-871`), signed with the hash type `0x61`
//! (ALL | CHRONICLE | FORKID) over the original digest: valid on the
//! reference, a false top on 0.3.28. The table holds the other twenty
//! transactions of the class, each run as a node runs it, every input.
//!
//! Every outpoint is synthetic; the previous outputs never existed on any chain.
use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxInput, TxOutput};
use bsv_rs::primitives::from_hex;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

struct Prevout {
    script_hex: &'static str,
    satoshis: u64,
    utxo_after_chronicle: bool,
}

struct Case {
    what: &'static str,
    tx_hex: &'static str,
    prevouts: &'static [Prevout],
    /// The reference's verdict under its block flags, as the interpreter
    /// reports it: `Ok(true)`, or the message of the refusal.
    reference: Result<bool, &'static str>,
    /// What 0.3.28 said, as the differential recorded it.
    recorded_0_3_28: &'static str,
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Block,
    Standard,
    Default,
    /// A block word of the era before Chronicle: no `CHRONICLE` bit.
    PreChronicleBlock,
}

const EVAL_FALSE: &str = "The top stack element must be truthy after script evaluation.";
const ILLEGAL_CHRONICLE: &str = "The signature must not use SIGHASH_CHRONICLE before Chronicle.";

/// Runs every input of the transaction as a node validates it; the verdict is
/// the first input's that does not accept.
fn run(c: &Case, mode: Mode) -> Result<bool, String> {
    let tx = parse_transaction(&from_hex(c.tx_hex).unwrap()).expect("a parseable transaction");
    assert_eq!(
        tx.inputs.len(),
        c.prevouts.len(),
        "{}: one prevout per input",
        c.what
    );
    let outputs: Vec<TxOutput> = tx
        .outputs
        .iter()
        .map(|o| TxOutput {
            satoshis: o.satoshis,
            script: o.script.clone(),
        })
        .collect();
    for (i, input) in tx.inputs.iter().enumerate() {
        let other_inputs: Vec<TxInput> = tx
            .inputs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, o)| TxInput {
                txid: o.txid,
                output_index: o.output_index,
                script: o.script.clone(),
                sequence: o.sequence,
            })
            .collect();
        let p = &c.prevouts[i];
        let mut spend = Spend::new(SpendParams {
            source_txid: input.txid,
            source_output_index: input.output_index,
            source_satoshis: p.satoshis,
            locking_script: LockingScript::from_hex(p.script_hex).unwrap(),
            transaction_version: tx.version,
            other_inputs,
            outputs: outputs.clone(),
            input_index: i,
            unlocking_script: UnlockingScript::from_binary(&input.script).unwrap(),
            input_sequence: input.sequence,
            lock_time: tx.locktime,
            memory_limit: None,
        });
        match mode {
            Mode::Block => spend.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle)),
            Mode::Standard => spend.set_flags(ScriptFlags::standard(ProtocolEra::PostChronicle)),
            Mode::PreChronicleBlock => {
                spend.set_flags(ScriptFlags::block(ProtocolEra::PostGenesis))
            }
            Mode::Default => {}
        }
        spend.set_utxo_after_chronicle(p.utxo_after_chronicle);
        match spend.validate() {
            Ok(true) => {}
            Ok(false) => return Ok(false),
            Err(e) => return Err(e.message),
        }
    }
    Ok(true)
}

fn expected(c: &Case) -> Result<bool, String> {
    c.reference.map_err(|m| m.to_string())
}

/// The witness (the first row of the table) alone, under the block word.
#[test]
fn the_witness_is_valid_under_the_block_word() {
    let w = &CASES[0];
    assert_eq!(run(w, Mode::Block), Ok(true), "{}", w.what);
}

/// And on the mempool path.
#[test]
fn the_witness_is_valid_under_the_standard_word() {
    let w = &CASES[0];
    assert_eq!(run(w, Mode::Standard), Ok(true), "{}", w.what);
}

/// The dispatch is on the hash type's bit in every mode (the TypeScript SDK
/// dispatches on it too): valid in the default mode as well.
#[test]
fn the_witness_is_valid_in_the_default_mode() {
    let w = &CASES[0];
    assert_eq!(run(w, Mode::Default), Ok(true), "{}", w.what);
}

/// Under a block word of the era before Chronicle (STRICTENC and no
/// `SCRIPT_CHRONICLE`), the bit is illegal (`interpreter.cpp:302-303`).
#[test]
fn the_chronicle_bit_is_illegal_under_a_pre_chronicle_word() {
    let w = &CASES[0];
    assert_eq!(
        run(w, Mode::PreChronicleBlock),
        Err(ILLEGAL_CHRONICLE.to_string()),
        "{}",
        w.what
    );
}

/// The whole class under the block word: every row's verdict is the reference's.
#[test]
fn every_row_of_the_class_agrees_with_the_reference_under_the_block_word() {
    let mismatches: Vec<String> = CASES
        .iter()
        .filter_map(|c| {
            let got = run(c, Mode::Block);
            (got != expected(c)).then(|| {
                format!(
                    "  {}: got {:?}, the reference {:?} (0.3.28: {})",
                    c.what,
                    got,
                    expected(c),
                    c.recorded_0_3_28
                )
            })
        })
        .collect();
    assert!(
        mismatches.is_empty(),
        "{} of {} rows differ from the reference:\n{}",
        mismatches.len(),
        CASES.len(),
        mismatches.join("\n")
    );
}

/// And under the standard word: the same verdicts (nothing here is policy).
#[test]
fn every_row_of_the_class_agrees_with_the_reference_under_the_standard_word() {
    let mismatches: Vec<String> = CASES
        .iter()
        .filter_map(|c| {
            let got = run(c, Mode::Standard);
            (got != expected(c))
                .then(|| format!("  {}: got {:?}, expected {:?}", c.what, got, expected(c)))
        })
        .collect();
    assert!(
        mismatches.is_empty(),
        "{} of {} rows differ:\n{}",
        mismatches.len(),
        CASES.len(),
        mismatches.join("\n")
    );
}

/// The twenty-one transactions of the class; the witness first.
const CASES: &[Case] = &[
    Case {
        what: "<pubkey> OP_CHECKSIG OP_RETURN 4c: a PUSHDATA1 with no length byte after a top-level OP_RETURN (the witness)",
        tx_hex: "0200000001f12dc0c202a0f1424b3e6ed0da68dd3de8f5e9fa167a386c49dece738e2a00d700000000484730440220340ad8df4a96ecef60d77132007bf641084e25e995a3d0178fbf00224fd406c3022028748cd6503e4e5e9956c89f87cf6869ddfe3264f161928ec1e3e4f43528a50e61ffffffff010100000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac6a4c", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "a three-input spend whose middle signature carries the CHRONICLE bit but was made over the BIP143 digest",
        tx_hex: "02000000030a6b7831c705da4781e047db39e41761ba557d76473771cbb424b7c500d1eb970000000049483045022100e6b1f33afe4caa33f2900a6663a4773ae2f12908915148a1a6d51981af1828d202207474bb800f007493249a4f6cf38f0bd3a3c4facb5cf2600582d0e705fb90259541ffffffff6df5178fc1d9c4d5c524be40251b639d77347bacb05c482bb1decec9a912a0240000000049483045022100c1289c99ec910bc03b02b0a5acf6b55cb5a98a0d36dbf38eb75af2df1db9810202204cc3ab187cd70720900e92439171457ba8cc55ea38bd2142feb5a69f7c06858361ffffffffed20daa50564fd0fbef7f6007fbc85b004414edbc0a4b485e25e0f6a7810c3230000000049483045022100929a9e440ba38e16157d00759e1f81357d9a087b2fafd9cad6d1af97f597e888022042ebfee82ccd6c8532975b9d092602e10b8932687d02104db5855bf4d981c2d141ffffffff02010000000000000001510200000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "2103c10f4fba86c5439080cb87226bc19b344eb56e6f4f6db673b6674fdfa63f6d57ac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "2102dae175dcbf94e5b79a4a53a67ba1259b7825079ec03b2c39101b9438eff5d904ac", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Err(EVAL_FALSE),
        recorded_0_3_28: "valid",
    },
    Case {
        what: "three inputs, the middle one signed ALL | CHRONICLE | FORKID over the original digest",
        tx_hex: "0200000003ff54fb76c8ee231682c1d225ae237d13d463574afc2a4eab87a5d0b19568e0d6000000004847304402206329c57b94079e22bd3c690bc31a768550451f48f0cb7c970bf567f9525f6b440220744897d02c3ebb49d7288d85114c91b2203feae04a47680671ad213746c3320a41ffffffffb2fb9fba3010fc89ffa149e1909d7b5e64295298e9a2ad7146f79c60ae25518e0000000049483045022100e2f8c95062cf629f2ec262c9cd3d2eadc62472bbd52bb71559aab9760eaade8e02203c0e108423f26154a9c62fa1dff08b75c2da82715eb8aa22ad47920d54fecc5b61ffffffff6907a67d6acd2a799c8ccec4e4da33c08842df1d331f0af92cef12ae38e03851000000004847304402201426130b847c1ef74d69902f83d444362cb5b990fa69e846e449846fec3a824f02207b70e88479cc24b14b003ca1decf949cb04e0d8ab25502dd9369215940df0e6441ffffffff02010000000000000001510200000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "2103c10f4fba86c5439080cb87226bc19b344eb56e6f4f6db673b6674fdfa63f6d57ac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "2102dae175dcbf94e5b79a4a53a67ba1259b7825079ec03b2c39101b9438eff5d904ac", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "three inputs, the middle one signed NONE | CHRONICLE | FORKID: no outputs, the other sequences zero",
        tx_hex: "0200000003f37f1e84fe73c95a86d88a1b535f78a53e791833fad29ef962e08347992c314f000000004847304402202b655b02470b637e485541bf429195dc8d3eb6753d70eef0aef880786e4296c60220713c431740a113dfeab6d032511e12a922e384d7aadf805775824093725e74ab41ffffffff0bb259f764094e88df8901e1557953a2e032077e0718f36b87c9ba4d25d95fee000000004847304402203e4ef82b93328eed2bc4d3c7bf3f407f33324c309035b9af65548ca15cb3518c02204ebe6950e330ec3d783a3407b5003afdefdda1b9c07cc1900c277e0a3bd4c37562ffffffffaf920850fda56d891e22c5cbe9a11b71216a8fc1016f1d7b7f17b1708a4dc6b00000000048473044022069dea182a5f28f502702e56f8119d6048a09ba5f99ed6aa18cb200f9fb8d64fe022006be2585e5dc0b5d8f1afaa1852ce4c72966c4af9fcfce4db769dca9d081de2e41ffffffff02010000000000000001510200000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "2103c10f4fba86c5439080cb87226bc19b344eb56e6f4f6db673b6674fdfa63f6d57ac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "2102dae175dcbf94e5b79a4a53a67ba1259b7825079ec03b2c39101b9438eff5d904ac", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "three inputs, input 1 signed SINGLE | CHRONICLE | FORKID with its output present: the null output at index 0",
        tx_hex: "0200000003c4075e4136631a8e0a346c3ef1754abf8d4c673db7cd333edb82a980600ec3760000000048473044022054e2f464d2f4112a4d23caeb22c43f26af6df9e75c9315dddf91bac3312c3d19022013e36d6c91972bbabb38190be8b1e7443006b1f494955cd63aa8be658751cf2941ffffffff90b50cb6f7d0f00b8247caecb5e0b0b8bf3606c657928deb8a0a7b5c45c6221f0000000049483045022100c18c9074c8cc22d058e6124ac2bacd2cec85954b81ba443bf31f233e0037ba3602203981f855abb9a76bf549700e3eafce2f1edfd1c1f45cef122a512c3683dc733b63ffffffffd644b9c91628712fc47f9c8a86aa42df79aaaeab0a5f2d9c86c7225c075bb1580000000048473044022055168a12c1242fd9bc4547306f5ccf97cce2989d110b1b74a87f14a70a8250e002202bb77f86eccd1ac6dd4cf445f557d7c5b7d14656760b6e7c2c1b9519c563198f41ffffffff02010000000000000001510200000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "2103c10f4fba86c5439080cb87226bc19b344eb56e6f4f6db673b6674fdfa63f6d57ac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "2102dae175dcbf94e5b79a4a53a67ba1259b7825079ec03b2c39101b9438eff5d904ac", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "three inputs, input 2 signed SINGLE | CHRONICLE | FORKID with no output at index 2: the digest is the constant one",
        tx_hex: "02000000035af7eb4c8e3c5997e4f65851cc2a9a80c69516599bc4ad341b5b8e97e99d81660000000049483045022100ebe6e07e456bef2947707f2d5441d8c4df99d585d705f2e322793029e5027252022062861a80c37c92ce0b2866fc828cfb0910057596311b60829188f9ef0c2e895141ffffffff51d9bf27a77c3c8abe628a31c6177ba376b6ab05479aededbe7851cc6fe11189000000004847304402206dca9c9cd8943fa56718de94d8ee2fecdfc058f40bb4c1a321dc930c03d20e4a0220799745e577708d96d2e05831f3a0e4cca7ff5f4534af985d355443d9f385e7d341ffffffff7f40268e1c9956ebc02ffb77edcdfec97b7f5f81b34b884ffee68cb156dee5af000000004847304402207360b6bfd534691c97cbe4a516cfc1630c15c3ec19e3a71df14af1dfe566bc62022030277a8ab317cde40331715a5ca32dcf7ab9d4b403d9f0b14357c3b480bc3fd863ffffffff02010000000000000001510200000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "2103c10f4fba86c5439080cb87226bc19b344eb56e6f4f6db673b6674fdfa63f6d57ac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "2102dae175dcbf94e5b79a4a53a67ba1259b7825079ec03b2c39101b9438eff5d904ac", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "three inputs, the middle one signed ALL | ANYONECANPAY | CHRONICLE | FORKID: only the signed input serialized",
        tx_hex: "020000000302b3bff4f37c4d2e1132b9e9aff8bf8da93e7463b2bba5d0dee51e61e4a68c95000000004847304402207590cfd5d5574b2f03edb534d5de17ee39782c6375ec5d818130d808882c370902204460c1e2db7c14d0df9d63064dd697cad24b9852b020a1ca8f239f55416a9cb841ffffffffe82838fa414f8e92a90a68e12457524f21a049f549b91ec6e446b50e297a1775000000004847304402201c26f8ae11013789851926e1677ff1e5711bfaa1f7407827a77ecac85a492b9d022078593dbebd060d2b584bf7203a71464e8918ac0cc2d27866c5683ff939928786e1ffffffff25b87f1b8a3b3585ea424f9ce0bc0d9724357613ab4d9a10203321498be158a40000000049483045022100b105963894ec38613af65b7aa9168e1bd4878ffc9a8ee91f862b25efca9b15890220131dd184db356945ee537d1e6ae80b91c7545a01681c75bb99ae72abeff898d241ffffffff02010000000000000001510200000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "2103c10f4fba86c5439080cb87226bc19b344eb56e6f4f6db673b6674fdfa63f6d57ac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "2102dae175dcbf94e5b79a4a53a67ba1259b7825079ec03b2c39101b9438eff5d904ac", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "the middle lock is <pubkey> OP_CODESEPARATOR OP_CHECKSIG: the scriptCode is OP_CHECKSIG alone",
        tx_hex: "0200000003f13357a3fa0b36246e558c95ad9c8119593549571c1732926b434786d0edc0cd0000000049483045022100e7938d007e8193e11ed77d01fb04f57917d1af0eaa28a900c570cb5c9d5b438202204e1e4af7b66732dff152a98a2f93fcb49184b91334ebd566d3d82bb7addec9be41ffffffffc2e2a2e464d1f3e98cd29cbb09cdc5384f8202097d2fa6feab13d743e0f73f7a0000000049483045022100b116517bf1d7bb8b89e7ce39ee2df18f7d02abe663c465ee79201726c87887760220482b6c93c0946a063a175ea68f544ac52af2b099122c510e74cd82ed4d40123861ffffffff2903764ce9689668d274b2df50021ba06eca7742117e604670c0628c720dce3a0000000049483045022100fdf1f151ac2d85b3300e5d6280a9503a8c0ac145df212b197386961bb3a6437602204bb7936ff85fb24c56821e7ed8c73cf840291819450cb22dddbb5f106b231fa241ffffffff02010000000000000001510200000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "2103c10f4fba86c5439080cb87226bc19b344eb56e6f4f6db673b6674fdfa63f6d57abac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "2102dae175dcbf94e5b79a4a53a67ba1259b7825079ec03b2c39101b9438eff5d904ac", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "two OP_CODESEPARATORs before the OP_CHECKSIG: the scriptCode after the last one",
        tx_hex: "02000000035307cbe2f4d9fb83a4559ea0759a94f96ee0f096c8e5fc6e3d01221a2c61e673000000004847304402204087a26457922a184c176bcdfdf6f92ac1b0f49e8fb3cfe8ded2440cbde590b302204100dde5661aeb59f0101d6e1a8a5723c698c8b38f1cbe49c25305dc11c0412e41ffffffff77924bd30f310db3dd04afc25c3bf4f515253d55977c267c8d6f3e7965875dc9000000004948304502210093728a11644002dfb4a5922ed879532021c4f9ee40015785776df02c75192ee70220518aaea4a6a9067c10d349b6985d006c220658b8626042064bdc2092f2e8c66361ffffffff41bc9ebda1dd5d6c77dc56f1c0938b553a436de1fde22b3b7e47abf97943b7ef0000000049483045022100d40a19716c081fb2f33309ebe770ee5fa0208de7e38045545b0fa7cd375a4985022022260df43fef6e878efae60118bb856250d88f2556cbf0347375f0961bf1093d41ffffffff02010000000000000001510200000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "ab2103c10f4fba86c5439080cb87226bc19b344eb56e6f4f6db673b6674fdfa63f6d57abac", satoshis: 1000, utxo_after_chronicle: true }, Prevout { script_hex: "2102dae175dcbf94e5b79a4a53a67ba1259b7825079ec03b2c39101b9438eff5d904ac", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "<pubkey> OP_CHECKSIG OP_RETURN 4c05aabb: a PUSHDATA1 with a short payload",
        tx_hex: "0200000001f81e0cf3c931477cbe57a9388d22c15466688974e66c7a7fae77a5623925265d0000000049483045022100e7bd08a7cf0a1bda318923e1e931e83070adb546eed21d79fbc92ef12966f958022071a9fada8e08eafc1758a8dc47501e4999ea89774872a3d96d0611d5aab7548761ffffffff010100000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac6a4c05aabb", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "<pubkey> OP_CHECKSIG OP_RETURN 4d05: a PUSHDATA2 with one length byte",
        tx_hex: "0200000001df9aea25028895f34dd187cd56c319ed0eb8d6896c2cd0866bc0544fe52394d9000000004847304402204519a364c695b04b7e5017be05deb0a3fdf25d09d31f0940b3e9efedbe7f496f02202c7b917f465dd4a505816f2a28d839d2044dbbdaeb1df9f3c39e9975c6f7e3de61ffffffff010100000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac6a4d05", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "<pubkey> OP_CHECKSIG OP_RETURN 4d0500aa: a PUSHDATA2 with a short payload",
        tx_hex: "02000000015f81631934d14dfcbb41e8cfb13b89d453a3665e7e92eba3a9d1d59a242db8f5000000004847304402200524b6dabec8fe8caf39777aa11a2cc24377adbf0252c71c36756cbc924978a20220524a640604e5fc9fee5d0f4694485697ee9234719cbbc4dba339150571fb39dc61ffffffff010100000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac6a4d0500aa", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "<pubkey> OP_CHECKSIG OP_RETURN 05aabb: a direct push with a short payload",
        tx_hex: "0200000001d9169cdf6a40a4fdf2caa3f438e3a01bcbfa9775d699e19ef6ae1832e61fd0020000000049483045022100b72ed094f1f41ab15b6f458e0bd8f8a02d436f79b80098652531761074ae023e02206a49939fd74fc93bb7221d62a568ef30b5ad4648ee173ca6e89b232d020d35db61ffffffff010100000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac6a05aabb", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "<pubkey> OP_CHECKSIG OP_RETURN 4e0500: a PUSHDATA4 with two length bytes",
        tx_hex: "0200000001640bd0f32d6a7771c4d4c4bf54f3922252b08784135d3398505aa4fa63b79bb60000000049483045022100e9bcb63373e1468ac6c813eadbfe26711b123346e5fd242abff355b74c7b056b0220515e5d9d8a8388ad5c587137fa4ebe053dfb36bab2dc0f8dacc2c5e983b70dd061ffffffff010100000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac6a4e0500", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "a P2PK spend signed 0x61 (ALL | CHRONICLE | FORKID) over the original digest",
        tx_hex: "0200000001fe36cabf1bda3fadc611f3f5fe3522a21f196de9e3bae7c6c1334615ae7d247c0000000049483045022100d3c30fd1dcb27ad8a113961b2d7da02c09afd6b33a9645cdd4ac2de16e2ceb2d022024531a2fe6b42f0dcc640b35e199174d54a02ef40474d6dcbbd078e92968ceec61ffffffff02010000000000000001510200000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "a P2PK spend signed 0xe1 (ALL | ANYONECANPAY | CHRONICLE | FORKID)",
        tx_hex: "0200000001120016067293875fa3a3e95a192e125ae507ebd0f7d2f0a76caf30da6fa01aef00000000484730440220594e7ede87b9bb31d9b1e67dea0546cbe4ad64b17ac25d9b0cbaee35aa25a18502201d71f7ac0e6387233982854ec94aa848c3f97d4a1e357772e08e65140bbb89f5e1ffffffff02010000000000000001510200000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "a P2PK spend signed 0x62 (NONE | CHRONICLE | FORKID)",
        tx_hex: "0200000001ed14d6b29ecb093edac3d94c3b31948b4256c30ff24dafae4e838b67b48da5f7000000004847304402205cf9ee353a8da169355daaf30e82d991078c3e131a092a322f5f41333b8d3f2402206fc2f357f39f4cd1842975b16238538fc19a980d7ad170118d6b32d9da47547462ffffffff02010000000000000001510200000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "a P2PK spend signed 0xe2 (NONE | ANYONECANPAY | CHRONICLE | FORKID)",
        tx_hex: "02000000013f1e0eacd105391cfbcedb7539f07f6156f7cf27896ef82d37b8ee7149eefec0000000004847304402202e5572e868ef959789a34e68fb2f32a48e04024184794d9dd66ea8490a71c35302204365c73cdcdc0a19e15cd849bd4c4ff951f3201631a9f2a5f8719f669ac75740e2ffffffff02010000000000000001510200000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "a P2PK spend signed 0x63 (SINGLE | CHRONICLE | FORKID)",
        tx_hex: "0200000001d384cb922ef8abfccbf08fa5e7ec5185f243b5e05a0750976602aaa51e63c630000000004948304502210080d686e28cbf3e4da23912cf12747709034cfccb0c945512ab845e5d2ad7e318022062eddffff7294b26ef6aff84e22a6c52bc3e8f8a74ee563e07bd6102daf8dade63ffffffff02010000000000000001510200000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "a P2PK spend signed 0xe3 (SINGLE | ANYONECANPAY | CHRONICLE | FORKID)",
        tx_hex: "02000000018809cdbbe99db27a4b8e6dd8f3efe9ccb55eb0774974dd187b6a4f2c309c16500000000049483045022100df7db2b2182ed42aa8c16492a40307ef28f1d47bebbc3a7ec78d84fc55a46664022054e2427fad37ed366be6968a2358470032d9fa4c728b3e4962114fbcb1bbb9c6e3ffffffff02010000000000000001510200000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac", satoshis: 1000, utxo_after_chronicle: true }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
    Case {
        what: "the CHRONICLE bit spending a coin created before Chronicle in a block after it: legal, the check reads the spend's flags",
        tx_hex: "0200000001421e09a1497b8976eafb681be43ab7ff15ca2075266f785f9610e4f935a8f8360000000049483045022100874e74f0c4921c200fbb90fd537ebefb84844f1b74d02355896bee35d213ee1b022048a1a59726aa089318f650f58b413615f32789d9eba562f6a1254d657f75992d61ffffffff02010000000000000001510200000000000000015100000000",
        prevouts: &[Prevout { script_hex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac", satoshis: 1000, utxo_after_chronicle: false }],
        reference: Ok(true),
        recorded_0_3_28: "invalid: The top stack element must be truthy after script evaluation.",
    },
];
