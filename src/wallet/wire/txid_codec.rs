//! The 32 bytes of a transaction id as the wallet wire and the certificate
//! binary carry them (#843, W1).
//!
//! Both wires carry a txid in display order: the reference holds a wallet's
//! txid as text (`TXIDHexString`, `ts-stack@edf6e03`
//! `wallet/Wallet.interfaces.ts:87`) and writes the decoded hex unreversed
//! (`WalletWireTransceiver.ts:724-726,732,1211`,
//! `auth/certificates/Certificate.ts:271,351-354`); BRC-100 names no order.
//! A [`Txid`] holds wire order, so the conversion is made here and nowhere
//! else: this file is the only code outside `src/transaction/` that names
//! `to_display_bytes` or `from_display_bytes`
//! (`tests/arch_one_txid_843w1.rs`).

use super::{WireReader, WireWriter};
use crate::transaction::Txid;
use crate::Error;

/// The 32 bytes a wallet wire frame or a certificate binary carries for
/// `txid`: its display order.
#[must_use]
pub(crate) fn write_txid(txid: &Txid) -> [u8; 32] {
    txid.to_display_bytes()
}

/// The id whose 32 bytes on a wallet wire frame or in a certificate binary
/// are `bytes`; `None` for a slice of any other length, which the calling
/// reader answers in its own words.
#[must_use]
pub(crate) fn read_txid(bytes: &[u8]) -> Option<Txid> {
    let display: [u8; 32] = bytes.try_into().ok()?;
    Some(Txid::from_display_bytes(display))
}

impl WireReader<'_> {
    /// Reads a txid's 32 bytes as the wallet wire carries them.
    pub(crate) fn read_txid(&mut self) -> Result<Txid, Error> {
        // `read_bytes(32)` answers 32 bytes or its own short-read refusal;
        // the arm below repeats those words and is not reached.
        read_txid(self.read_bytes(32)?).ok_or_else(|| {
            Error::WalletError("ReaderUint8Array read exceeds available data".into())
        })
    }
}

impl WireWriter {
    /// Writes a txid's 32 bytes as the wallet wire carries them.
    pub(crate) fn write_txid(&mut self, txid: &Txid) -> &mut Self {
        self.write_bytes(&write_txid(txid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";

    #[test]
    fn the_pair_carries_the_decoded_text_unreversed_843w1() {
        let txid = Txid::from_hex(TEXT).unwrap();
        let carried = write_txid(&txid);
        assert_eq!(carried.to_vec(), hex::decode(TEXT).unwrap());
        assert_ne!(
            &carried,
            txid.as_wire_bytes(),
            "the id is not its own reverse"
        );
        assert_eq!(read_txid(&carried), Some(txid));
    }

    #[test]
    fn a_slice_that_is_not_32_bytes_is_no_txid_843w1() {
        for length in [0usize, 1, 31, 33, 64] {
            assert_eq!(read_txid(&vec![0xab; length]), None, "{length}");
        }
    }
}
