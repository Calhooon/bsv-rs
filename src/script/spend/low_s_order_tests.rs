#![cfg(test)]

use super::*;
use crate::primitives::BigNumber;

const N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
const HALF: &str = "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0";

/// A strict-DER signature (r, s as 32-byte big-endian hex) with the FORKID hash type.
fn der(r: &str, s: &str) -> Vec<u8> {
    fn int(hex: &str) -> Vec<u8> {
        let mut v = crate::primitives::from_hex(hex).unwrap();
        while v.len() > 1 && v[0] == 0 && v[1] & 0x80 == 0 {
            v.remove(0);
        }
        if v[0] & 0x80 != 0 {
            v.insert(0, 0);
        }
        let mut out = vec![0x02, v.len() as u8];
        out.extend(v);
        out
    }
    let body = [int(r), int(s)].concat();
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out.push(0x41);
    out
}

fn checker() -> Spend {
    Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_asm("OP_1").unwrap(),
        transaction_version: 1, // the default mode at version 1 requires low S
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::new(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    })
}

fn s_plus(hex: &str, k: u64) -> String {
    let v = BigNumber::from_bytes_be(&crate::primitives::from_hex(hex).unwrap())
        .add(&BigNumber::from_i64(k as i64));
    crate::primitives::to_hex(&v.to_bytes_be(32))
}

#[test]
fn s_at_or_above_the_order_passes_the_low_s_check_as_the_zero_signature() {
    let one = "0000000000000000000000000000000000000000000000000000000000000001";
    let c = checker();
    assert!(c.check_signature_encoding(&der(one, N)).is_ok(), "s = n");
    assert!(
        c.check_signature_encoding(&der(one, &s_plus(N, 1))).is_ok(),
        "s = n + 1"
    );
    assert!(c.check_signature_encoding(&der(N, one)).is_ok(), "r = n");
    // the boundary: n/2 is low, n/2 + 1 through n - 1 are high
    assert!(
        c.check_signature_encoding(&der(one, HALF)).is_ok(),
        "s = n/2"
    );
    let high = c
        .check_signature_encoding(&der(one, &s_plus(HALF, 1)))
        .unwrap_err();
    assert_eq!(high.message, "The signature must have a low S value.");
    let n_minus_1 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
    assert_eq!(
        c.check_signature_encoding(&der(one, n_minus_1))
            .unwrap_err()
            .message,
        "The signature must have a low S value."
    );
    // and such a signature never verifies: a CHECKSIG with s = n at version 1 under the
    // block word is NULLFAIL, in the default mode a false top
    let pk = "035935f55855afd8c999bdb5a8d08ae8e73b7618e200d4ef7687cd55d3c2e4c9d7";
    let sig_hex = crate::primitives::to_hex(&der(one, N));
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_asm(&format!("{pk} OP_CHECKSIG")).unwrap(),
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_asm(&sig_hex).unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    spend.set_flags(ScriptFlags::block(
        crate::script::flags::ProtocolEra::PostChronicle,
    ));
    assert_eq!(
        spend.validate().unwrap_err().message,
        "OP_CHECKSIG requires failing signatures to be empty."
    );
}
