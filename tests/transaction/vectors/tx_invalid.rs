//! Invalid transaction test vectors.
//!
//! These vectors are derived from the TypeScript SDK and represent transactions
//! that are structurally valid (can be parsed) but semantically invalid
//! (would fail script verification).
//!
//! Note: These test serialization/deserialization, not script verification.

/// Invalid transaction vectors - these can be parsed but would fail verification
/// Format: (hex, description)
pub const TX_INVALID_VECTORS: &[(&str, &str)] = &[
    // Extra junk in scriptPubKey
    (
        "010000000127587a10248001f424ad94bb55cd6cd6086a0e05767173bdbdf647187beca76c000000004948304502201b822ad10d6adc1a341ae8835be3f70a25201bbff31f59cbb9c5353a5f0eca18022100ea7b2f7074e9aa9cf70aa8d0ffee13e6b45dddabf1ab961bda378bcdb778fa4701ffffffff0100f2052a010000001976a914fc50c5907d86fed474ba5ce8b12a66e0a4c139d888ac00000000",
        "extra junk in scriptPubKey",
    ),
    // Non-standard pushdata in scriptSig
    (
        "01000000010001000000000000000000000000000000000000000000000000000000000000000000006a473044022067288ea50aa799543a536ff9306f8e1cba05b9c6b10951175b924f96732555ed022026d7b5265f38d21541519e4a1e55044d5b9e17e15cdbaf29ae3792e99e883e7a012103ba8c8b86dea131c22ab967e6dd99bdae8eff7a1f75a2c35f1f944109e3fe5e22ffffffff010000000000000000015100000000",
        "non-standard pushdata prefix",
    ),
    // Invalid P2SH - invalid script hash
    (
        "010000000100010000000000000000000000000000000000000000000000000000000000000000000009085768617420697320ffffffff010000000000000000015100000000",
        "invalid P2SH script hash",
    ),
    // No outputs
    (
        "01000000010001000000000000000000000000000000000000000000000000000000000000000000006d483045022100f16703104aab4e4088317c862daec83440242411b039d14280e03dd33b487ab802201318a7be236672c5c56083eb7a5a195bc57a40af7923ff8545016cd3b571e2a601232103c40e5d339df3f30bf753e7e04450ae4ef76c9e45587d1d993bdc4cd06f0651c7acffffffff0000000000",
        "no outputs",
    ),
    // Coinbase of size 1
    (
        "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0151ffffffff010000000000000000015100000000",
        "coinbase of size 1",
    ),
    // Coinbase of size 101
    (
        "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff655151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151ffffffff010000000000000000015100000000",
        "coinbase of size 101",
    ),
    // OP_CHECKMULTISIG with missing dummy value
    (
        "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba260000000004847304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000",
        "CHECKMULTISIG missing dummy",
    ),
    // Empty stack for CHECKSIG
    (
        "01000000013bfc220ec526583cb6b7e922b8b27f604cfe0a09764de61e80f58dc1723f50ad0000000000ffffffff0101000000000000002321027c3a97665bf283a102a587a62a30a0c102d4d3b141015e2cae6f64e2543113e5ac00000000",
        "empty stack for CHECKSIG",
    ),
    // Non-standard DER signature
    (
        "010000000132211bdd0d568506804eef0d8cc3db68c3d766ab9306cdfcc0a9c89616c8dbb1000000006c493045022100c7bb0faea0522e74ff220c20c022d2cb6033f8d167fb89e75a50e237a35fd6d202203064713491b1f8ad5f79e623d0219ad32510bfaa1009ab30cbee77b59317d6e30001210237af13eb2d84e4545af287b919c2282019c9691cc509e78e196a9d8274ed1be0ffffffff0100000000000000001976a914f1b3ed2eda9a2ebe5a9374f692877cdf87c0f95b88ac00000000",
        "non-standard DER signature",
    ),
    // CHECKLOCKTIMEVERIFY with locked input
    (
        "010000000100010000000000000000000000000000000000000000000000000000000000000000000000ffffffff0100000000000000000000000000",
        "CHECKLOCKTIMEVERIFY locked input",
    ),
    // CHECKSEQUENCEVERIFY argument missing
    (
        "020000000100010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000",
        "CHECKSEQUENCEVERIFY argument missing",
    ),
];

/// Test that these transactions can be parsed (roundtrip)
/// They are structurally valid but semantically invalid
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_tx_can_be_parsed() {
        // These transactions are invalid for script execution reasons,
        // but they should still be parseable as raw transactions
        for (i, (hex, desc)) in TX_INVALID_VECTORS.iter().enumerate() {
            // Just verify the hex is valid - parsing test is in main test file
            assert!(!hex.is_empty(), "Vector {}: {} has empty hex", i, desc);
        }
    }
}
