#![no_main]
use bsv_rs::block::{merkle_root, BlockHeader, ChainWork, CompactTarget};
use bsv_rs::primitives::{from_var_int, to_var_int, Reader, U256};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = BlockHeader::from_binary(data) {
        assert_eq!(header.to_binary().as_slice(), data);
        assert_eq!(BlockHeader::from_hex(&header.to_hex()).unwrap(), header);
        let _ = header.hash();
        let _ = header.work();
    }
    let _ = BlockHeader::from_reader(&mut Reader::new(data));
    let _ = Reader::new(data).read_compact_size();
    let _ = Reader::new(data).read_var_int_lenient();
    if let Ok((value, used)) = from_var_int(data) {
        assert_eq!(to_var_int(value), data[..used]);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(work) = ChainWork::from_hex(text) {
            assert_eq!(ChainWork::from_hex(&work.to_hex()).unwrap(), work);
        }
        let _ = BlockHeader::from_hex(text);
    }
    if let Some(word) = data.get(..4) {
        let bits = u32::from_le_bytes(word.try_into().unwrap());
        let target = CompactTarget::from_bits(bits);
        let work = ChainWork::from_bits(bits);
        if !target.is_valid() {
            assert_eq!(work, ChainWork::ZERO);
        }
        let encoded = target.target.to_compact_signed(target.negative);
        let canonical = CompactTarget::from_bits(encoded);
        assert_eq!(
            canonical.target.to_compact_signed(canonical.negative),
            encoded
        );
    }
    if let Some(word) = data.get(..32) {
        let value = U256::from_le_bytes(word.try_into().unwrap());
        assert_eq!(value.checked_div(U256::ONE), Some(value));
        assert_eq!(value.wrapping_add(value.wrapping_neg()), U256::ZERO);
    }
    let leaves: Vec<[u8; 32]> = data
        .chunks_exact(32)
        .map(|s| s.try_into().unwrap())
        .collect();
    let _ = merkle_root(&leaves);
});
