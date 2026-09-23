//! Scripts: build, parse, classify, and EXECUTE with the interpreter.
//!
//! Run with `cargo run --example script`.
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

fn main() {
    // A P2PKH locking script from an address, and the same script parsed
    // back from hex and from ASM.
    let locking = P2PKH::lock_from_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").unwrap();
    let from_hex = Script::from_hex(&locking.to_hex()).unwrap();
    assert_eq!(from_hex.to_asm(), locking.to_asm());
    assert!(from_hex.is_p2pkh());
    println!("p2pkh  {}", locking.to_asm());

    // The interpreter is `Spend`: it executes an unlocking script against a
    // locking script inside its transaction context, exactly as the TypeScript
    // SDK's default evaluation mode does. Here the context is synthetic: one
    // input, no outputs, transaction version 1 (the strict mode: minimal
    // pushes, low-S, a clean stack).
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: LockingScript::from_asm("OP_1 OP_EQUAL").unwrap(),
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_asm("OP_1").unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
    });
    assert!(spend.validate().unwrap());

    // A refusal is an error that names the failing step; a script that only
    // exhausts the interpreter's memory budget is a DIFFERENT class
    // (`is_resource_limit()`), so a caller judging on the network's behalf can
    // tell "invalid" from "too big for this evaluator".
    let mut refused = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: LockingScript::from_asm("OP_1 OP_EQUAL").unwrap(),
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_asm("OP_2").unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
    });
    let err = refused.validate().unwrap_err();
    assert!(!err.is_resource_limit());
    println!("refused {}", err.message);

    // A node validates under a FLAG WORD and derives two of them: the block
    // word (what a mining node applies when it connects a block) and the
    // standard word (the block word plus the relay-only restrictions of its
    // mempool policy). Without a word `Spend` is the TypeScript SDK's default
    // mode, which is neither; a consensus oracle selects the block word. Here
    // a version-1 spend leaves two elements on the stack: refused by the
    // default mode and by the standard word (CLEANSTACK, a relay rule), valid
    // under the block word, exactly as it is in a block.
    let untidy = || {
        Spend::new(SpendParams {
            source_txid: [0u8; 32],
            source_output_index: 0,
            source_satoshis: 1,
            locking_script: LockingScript::from_asm("OP_1 OP_1").unwrap(),
            transaction_version: 1,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: UnlockingScript::new(),
            input_sequence: 0xffff_ffff,
            lock_time: 0,
            memory_limit: None,
        })
    };
    assert!(untidy().validate().is_err());
    let mut consensus = untidy();
    consensus.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
    assert!(consensus.validate().unwrap());
    let mut relay = untidy();
    relay.set_flags(ScriptFlags::standard(ProtocolEra::PostChronicle));
    println!("relay   {}", relay.validate().unwrap_err().message);
}
