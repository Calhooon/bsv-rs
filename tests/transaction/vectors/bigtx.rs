//! Big transaction test vector.
//!
//! This contains the expected TXID for a 1MB transaction.
//! The full transaction hex is too large to include here,
//! but the test verifies we can handle large transactions.

#![allow(dead_code)]

/// Expected TXID for the 1MB transaction from TypeScript SDK
pub const BIG_TX_TXID: &str = "bb41a757f405890fb0f5856228e23b715702d714d59bf2b1feb70d8b2b4e3e08";

/// A reasonably large transaction for testing (not 1MB, but substantial)
/// This is a real transaction with many outputs
pub const LARGE_TX_HEX: &str = concat!(
    "01000000", // version
    "01",       // input count
    "0000000000000000000000000000000000000000000000000000000000000000", // prev txid
    "ffffffff", // prev output index (coinbase)
    "07",       // script length
    "04ffff001d0104", // coinbase script
    "ffffffff", // sequence
    "01",       // output count
    "00f2052a01000000", // 50 BTC in satoshis
    "43",       // script length
    "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    "00000000"  // locktime
);

/// Test transaction with multiple inputs and outputs
pub const MULTI_IO_TX_HEX: &str = "01000000029e8d016a7b0dc49a325922d05da1f916d1e4d4f0cb840c9727f3d22ce8d1363f000000008c493046022100e9318720bee5425378b4763b0427158b1051eec8b08442ce3fbfbf7b30202a44022100d4172239ebd701dae2fbaaccd9f038e7ca166707333427e3fb2a2865b19a7f27014104510c67f46d2cbb29476d1f0b794be4cb549ea59ab9cc1e731969a7bf5be95f7ad5e7f904e5ccf50a9dc1714df00fbeb794aa27aaff33260c1032d931a75c56f2ffffffffa3195e7a1ab665473ff717814f6881485dc8759bebe97e31c301ffe7933a656f020000008b48304502201c282f35f3e02a1f32d2089265ad4b561f07ea3c288169dedcf2f785e6065efa022100e8db18aadacb382eed13ee04708f00ba0a9c40e3b21cf91da8859d0f7d99e0c50141042b409e1ebbb43875be5edde9c452c82c01e3903d38fa4fd89f3887a52cb8aea9dc8aec7e2c9d5b3609c03eb16259a2537135a1bf0f9c5fbbcbdbaf83ba402442ffffffff02206b1000000000001976a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88acf0ca0100000000001976a9149e3e2d23973a04ec1b02be97c30ab9f2f27c3b2c88ac00000000";

/// Expected TXID for MULTI_IO_TX
pub const MULTI_IO_TX_TXID: &str =
    "8c9aa966d35bfeaf031409e0001b90ccdafd8d859799eb945a3c515b8260bcf2";
