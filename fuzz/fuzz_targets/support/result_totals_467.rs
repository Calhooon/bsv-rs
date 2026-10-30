//! #467: totals written by the crate round-trip exactly through the safe bound.
use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver, WireWriter};
use bsv_rs::Error;

struct Answer(Vec<u8>);

#[async_trait::async_trait]
impl WalletWire for Answer {
    async fn transmit_to_wallet(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }
}

pub fn exercise(data: &[u8]) {
    let mut bytes = [0; 8];
    let count = data.len().min(bytes.len());
    bytes[..count].copy_from_slice(&data[..count]);
    let total = u64::from_le_bytes(bytes);
    futures::executor::block_on(async {
        for call in 0..5 {
            let mut writer = WireWriter::new();
            writer.write_u8(0).write_var_int(total);
            if call == 1 {
                writer.write_optional_bytes(None);
            }
            let client = WalletWireTransceiver::new(Answer(writer.into_bytes()));
            let result = match call {
                0 => client
                    .list_actions(crate::support::list_actions(), None)
                    .await
                    .map(|r| r.total_actions),
                1 => client
                    .list_outputs(crate::support::list_outputs(), None)
                    .await
                    .map(|r| r.total_outputs),
                2 => client
                    .list_certificates(crate::support::list_certificates(), None)
                    .await
                    .map(|r| r.total_certificates),
                3 => client
                    .discover_by_identity_key(crate::support::discover_by_identity_key(), None)
                    .await
                    .map(|r| r.total_certificates),
                _ => client
                    .discover_by_attributes(crate::support::discover_by_attributes(), None)
                    .await
                    .map(|r| r.total_certificates),
            };
            if total <= (1 << 53) - 1 {
                assert_eq!(result, Ok(total));
            } else {
                assert_eq!(
                    result,
                    Err(Error::WalletError(
                        "number too large to retain precision - use readVarIntBn".into()
                    ))
                );
            }
        }
    });
}
