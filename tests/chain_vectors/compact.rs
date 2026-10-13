// Rust transcriptions at the sibling@50d437b node pin.
// bitcoin-sv@6504a3af src/test/arith_uint256_tests.cpp:501-538.
pub const SET_COMPACT: [(u32, bool, bool, &str); 14] = [
    (0x00123456, false, false, "0"),
    (0x01123456, false, false, "12"),
    (0x02123456, false, false, "1234"),
    (0x03123456, false, false, "123456"),
    (0x04123456, false, false, "12345600"),
    (
        0x20123456,
        false,
        false,
        "1234560000000000000000000000000000000000000000000000000000000000",
    ),
    (
        0x21123456,
        false,
        true,
        "3456000000000000000000000000000000000000000000000000000000000000",
    ),
    (0x00923456, false, false, "0"),
    (0x01923456, true, false, "12"),
    (0x02923456, true, false, "1234"),
    (0x03923456, true, false, "123456"),
    (0x04923456, true, false, "12345600"),
    (
        0x20923456,
        true,
        false,
        "1234560000000000000000000000000000000000000000000000000000000000",
    ),
    (
        0x21923456,
        true,
        true,
        "3456000000000000000000000000000000000000000000000000000000000000",
    ),
];
// bitcoin-sv@6504a3af src/test/arith_uint256_tests.cpp:540-703.
// Includes the design probe's repeated zero regression row.
pub const GET_COMPACT: [(u32, u32, bool, bool, bool); 21] = [
    (0, 0, false, false, false),
    (0x00123456, 0, false, false, false),
    (0x01003456, 0, false, false, false),
    (0x02000056, 0, false, false, false),
    (0x03000000, 0, false, false, false),
    (0x04000000, 0, false, false, false),
    (0x00923456, 0, false, false, false),
    (0x01803456, 0, false, false, false),
    (0x02800056, 0, false, false, false),
    (0x03800000, 0, false, false, false),
    (0x04800000, 0, false, false, false),
    (0x01123456, 0x01120000, false, false, false),
    (0x01fedcba, 0x01fe0000, true, true, false),
    (0x02123456, 0x02123400, false, false, false),
    (0x03123456, 0x03123456, false, false, false),
    (0x04123456, 0x04123456, false, false, false),
    (0x04923456, 0x04923456, true, true, false),
    (0x05009234, 0x05009234, false, false, false),
    (0x20123456, 0x20123456, false, false, false),
    (0xff123456, 0, false, false, true),
    (0, 0, false, false, false),
];
