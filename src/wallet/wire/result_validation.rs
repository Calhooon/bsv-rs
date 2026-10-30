//! The nine client result-validation sites in WalletWireTransceiver.ts (#487).
//! The existing BRC-100 serde forms borrow the typed answer for the shared
//! validator; returning the original value preserves every public field.

use crate::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use crate::wallet::substrates::result_values;
use crate::{Error, Result};
use serde::Serialize;
use serde_json::{json, Value};

pub(super) struct Binding {
    call: &'static str,
    request: Value,
}

impl Binding {
    /// Capture only the reference's binding fields before crossing the wire.
    pub(super) fn new(call: &'static str, args: &impl Serialize) -> Result<Self> {
        let bytes = serde_json::to_vec(args).map_err(|e| Error::WalletError(e.to_string()))?;
        Ok(Self {
            call,
            request: result_values::request(call, &bytes)?,
        })
    }

    pub(super) fn counterparty(args: &RevealCounterpartyKeyLinkageArgs) -> Result<Self> {
        Self::new(
            "revealCounterpartyKeyLinkage",
            &json!({"verifier": args.verifier, "counterparty": args.counterparty}),
        )
    }

    pub(super) fn specific(args: &RevealSpecificKeyLinkageArgs) -> Result<Self> {
        Self::new(
            "revealSpecificKeyLinkage",
            &json!({
                "verifier": args.verifier, "counterparty": match &args.counterparty {
                    crate::wallet::Counterparty::Self_ => "self".into(),
                    crate::wallet::Counterparty::Anyone => "anyone".into(),
                    crate::wallet::Counterparty::Other(key) => key.to_hex(),
                },
                "protocolID": [args.protocol_id.security_level.as_u8(), args.protocol_id.protocol_name],
                "keyID": args.key_id,
            }),
        )
    }

    pub(super) fn check<R: Serialize>(&self, result: R) -> Result<R> {
        result_values::wire(self.call, &result, &self.request)?;
        Ok(result)
    }
}

/// Signature bytes have no serde impl on their public result record.
pub(super) fn signature(signature: &[u8]) -> Result<()> {
    #[derive(Serialize)]
    struct Signature<'a> {
        signature: &'a [u8],
    }
    result_values::wire("createSignature", &Signature { signature }, &Value::Null)
}

pub(super) fn response_length(length: usize) -> Result<()> {
    result_values::wire_response_length(length)
}

/// Certificate.fromBinary bounds the entire certificate, including its prefix.
pub(super) fn certificate_size(length: usize) -> Result<()> {
    if length > super::MAX_CERTIFICATE_BINARY_BYTES {
        return Err(super::refused(super::certificate_binary_read_refusal()));
    }
    Ok(())
}
