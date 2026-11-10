#![no_main]
//! The DER signature reader (`Signature::from_der`, the reference's
//! `Signature.fromDER`, #842) and the checksig reader on arbitrary input. The
//! assertions: each returns; an accepted DER has exactly the length its
//! sequence header names, its lengths in the short form and S ending the
//! input; an accepted checksig input is its last byte's scope over an
//! accepted DER. The writer's round trip: the input's leading 64 bytes as
//! (R, S), with R and S nonzero and S below the order, written by `to_der`
//! (which writes the low-S twin) and by `to_checksig_format`, read back equal.
use bsv_rs::primitives::bsv::tx_signature::TransactionSignature;
use bsv_rs::primitives::ec::Signature;
use bsv_rs::primitives::BigNumber;
use libfuzzer_sys::fuzz_target;

fn assert_framed(der: &[u8]) {
    let length = |at: usize| usize::from(*der.get(at).expect("a length byte"));
    assert_eq!(der[0], 0x30);
    assert!(
        der[1] < 0x80 && length(1) + 2 == der.len(),
        "the sequence names the input"
    );
    let r_len = length(3);
    assert!(r_len < 0x80);
    let s_len = length(5 + r_len);
    assert!(
        s_len < 0x80 && 6 + r_len + s_len == der.len(),
        "S ends the input"
    );
}

fuzz_target!(|data: &[u8]| {
    if let Ok(sig) = Signature::from_der(data) {
        assert_framed(data);
        let _ = sig.is_low_s();
    }
    match TransactionSignature::from_checksig_format(data) {
        Ok(read) => {
            if let Some((&scope, der)) = data.split_last() {
                assert_eq!(read.scope(), u32::from(scope));
                assert_eq!(Signature::from_der(der).as_ref(), Ok(read.signature()));
                assert_framed(der);
            }
        }
        Err(_) => assert!(!data.is_empty()),
    }
    if data.len() >= 64 {
        let sig = Signature::from_compact_slice(&data[..64]).expect("64 bytes");
        let n = BigNumber::secp256k1_order();
        let zero = [0u8; 32];
        if sig.r() != &zero && sig.s() != &zero && BigNumber::from_bytes_be(sig.s()) < n {
            let der = sig.to_der();
            let read = Signature::from_der(&der).expect("this crate's DER reads back");
            assert_eq!(read, sig.to_low_s());
            assert_eq!(read.to_der(), der);
            let scope = data.get(64).copied().unwrap_or(0x41);
            let checksig =
                TransactionSignature::new(sig.clone(), u32::from(scope)).to_checksig_format();
            let read = TransactionSignature::from_checksig_format(&checksig)
                .expect("this crate's checksig reads back");
            assert_eq!(read.signature(), &sig.to_low_s());
            assert_eq!(read.scope(), u32::from(scope));
        }
    }
});
