//! Keep a JSON null remittance distinct from an absent member (#393).

use super::{BasketInsertion, WalletPayment};
use crate::wallet::validation::remittance_error;
use serde::{de::Error, Deserialize, Deserializer, Serialize};

/// Output specification for internalization.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InternalizeOutput {
    /// Index of the output within the transaction.
    pub output_index: u32,
    /// Protocol type: "wallet payment" or "basket insertion".
    pub protocol: String,
    /// Remittance data for wallet payment protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_remittance: Option<WalletPayment>,
    /// Remittance data for basket insertion protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insertion_remittance: Option<BasketInsertion>,
}

#[derive(Deserialize)]
#[serde(rename = "InternalizeOutput", rename_all = "camelCase")]
struct JsonOutput {
    output_index: u32,
    protocol: String,
    #[serde(default, deserialize_with = "present")]
    payment_remittance: Option<Option<WalletPayment>>,
    #[serde(default, deserialize_with = "present")]
    insertion_remittance: Option<Option<BasketInsertion>>,
}

// Outer None means absent; Some(None) means a JSON null was supplied.
fn present<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

impl<'de> Deserialize<'de> for InternalizeOutput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let output = JsonOutput::deserialize(deserializer)?;
        // The typed API cannot retain null. Refuse it here in the reference's
        // order: protocol, remittance presence, then the remittance's object
        // check (validationHelpers.ts:966-984 at edf6e03).
        let payment_null = matches!(output.payment_remittance, Some(None));
        let insertion_null = matches!(output.insertion_remittance, Some(None));
        if payment_null || insertion_null {
            if let Some(message) = remittance_error(
                &output.protocol,
                output.payment_remittance.is_some(),
                output.insertion_remittance.is_some(),
            ) {
                return Err(D::Error::custom(message));
            }
            let field = if payment_null {
                "paymentRemittance"
            } else {
                "insertionRemittance"
            };
            return Err(D::Error::custom(format!(
                "The {field} parameter must be a plain object"
            )));
        }
        Ok(Self {
            output_index: output.output_index,
            protocol: output.protocol,
            payment_remittance: output.payment_remittance.flatten(),
            insertion_remittance: output.insertion_remittance.flatten(),
        })
    }
}
