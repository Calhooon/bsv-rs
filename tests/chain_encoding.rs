//! Encoding vectors from bitcoin-sv@6504a3af, as pinned by sibling@50d437b.
#![cfg(feature = "primitives")]

use bsv_rs::primitives::encoding::*;
use bsv_rs::Error;

#[path = "chain_vectors/base58.rs"]
mod vectors;

#[test]
fn node_base58_vectors_with_documented_differences() {
    assert_eq!(vectors::BASE58_ROWS.len(), 12);
    for &(raw, encoded) in vectors::BASE58_ROWS {
        let bytes = hex::decode(raw).unwrap();
        assert_eq!(to_base58(&bytes), encoded);
        if encoded.is_empty() {
            assert!(from_base58(encoded).is_err());
        } else {
            assert_eq!(from_base58(encoded).unwrap(), bytes);
        }
    }
    // bitcoin-sv@6504a3af src/test/base58_tests.cpp:73-80.
    assert!(from_base58("invalid").is_err());
    assert!(from_base58(" \t\n\x0b\x0c\r skip \r\x0c\x0b\n\t ").is_err());
    assert_eq!(from_base58("skip").unwrap(), hex::decode("971a55").unwrap());
}

#[test]
fn node_base58check_fifty_keys() {
    assert_eq!(vectors::BASE58_KEYS.len(), 50);
    for &(encoded, raw, version) in vectors::BASE58_KEYS {
        let payload = hex::decode(raw).unwrap();
        assert_eq!(
            from_base58_check(encoded).unwrap(),
            (vec![version], payload.clone())
        );
        assert_eq!(to_base58_check(&payload, &[version]), encoded);
    }
    // bitcoin-sv@6504a3af src/base58.cpp:143-156, bad checksum and short body.
    let mut raw = from_base58(vectors::BASE58_KEYS[0].0).unwrap();
    let end = raw.len() - 1;
    raw[end] ^= 1;
    assert_eq!(
        from_base58_check(&to_base58(&raw)),
        Err(Error::InvalidChecksum)
    );
    assert!(from_base58_check_with_prefix_length(&to_base58(&[1, 2, 3]), 0).is_err());
}

#[test]
fn node_seven_compact_size_refusals() {
    // bitcoin-sv@6504a3af src/test/serialize_tests.cpp:359-399 and
    // src/serialize.h:336-338. The last row is canonical but over MAX_SIZE.
    let rows = [
        ("fd0000", 3, 0),
        ("fdfc00", 3, 252),
        ("fe00000000", 5, 0),
        ("feffff0000", 5, 65535),
        ("ff0000000000000000", 9, 0),
        ("ffffffff0100000000", 9, 0x1ffffff),
        ("ff0000000001000000", 9, 0x1_0000_0000),
    ];
    for (raw, width, value) in rows {
        let bytes = hex::decode(raw).unwrap();
        let error = if value > MAX_COMPACT_SIZE {
            Error::CompactSizeTooLarge(value)
        } else {
            Error::NonCanonicalVarInt { width, value }
        };
        assert_eq!(Reader::new(&bytes).read_compact_size(), Err(error));
        assert_eq!(Reader::new(&bytes).read_var_int_lenient(), Ok(value));
        if value > MAX_COMPACT_SIZE {
            assert_eq!(from_var_int(&bytes), Ok((value, 9)));
        } else {
            assert_eq!(
                from_var_int(&bytes),
                Err(Error::NonCanonicalVarInt { width, value })
            );
        }
    }
}

#[test]
fn node_compact_size_boundaries_and_u64_varints() {
    // bitcoin-sv@6504a3af src/test/serialize_tests.cpp:324-347;
    // src/serialize.h:296-299 adds the writer's MAX_SIZE refusal.
    let mut count = 0;
    for power in 0..32 {
        for value in [(1u64 << power) - 1, 1u64 << power] {
            let mut writer = Writer::new();
            writer.write_compact_size(value).unwrap();
            assert_eq!(
                Reader::new(writer.as_bytes()).read_compact_size(),
                Ok(value)
            );
            count += 1;
        }
    }
    assert_eq!(count, 64);
    for value in [
        0,
        252,
        253,
        65535,
        65536,
        MAX_COMPACT_SIZE,
        MAX_COMPACT_SIZE + 1,
        i64::MAX as u64,
        u64::MAX,
    ] {
        let bytes = to_var_int(value);
        assert_eq!(bytes.len(), var_int_len(value));
        assert_eq!(from_var_int(&bytes), Ok((value, bytes.len())));
        let mut writer = Writer::new();
        writer.write_u8(42);
        if value > MAX_COMPACT_SIZE {
            assert_eq!(
                writer.write_compact_size(value).err(),
                Some(Error::CompactSizeTooLarge(value))
            );
            assert_eq!(writer.as_bytes(), [42]);
        } else {
            writer.write_compact_size(value).unwrap();
            assert_eq!(
                Reader::new(&writer.as_bytes()[1..]).read_compact_size(),
                Ok(value)
            );
        }
        for len in 0..bytes.len() {
            assert!(matches!(
                from_var_int(&bytes[..len]),
                Err(Error::ReaderUnderflow { .. })
            ));
        }
        let mut framed = bytes.clone();
        framed.push(42);
        assert_eq!(from_var_int(&framed), Ok((value, bytes.len())));
    }
}
