//! The eleven client result-validation sites in WalletWireTransceiver.ts (#487, #495).
//! The existing BRC-100 serde forms borrow the typed answer for the shared
//! validator; returning the original value preserves every public field.

use crate::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use crate::wallet::substrates::result_values;
use crate::wallet::CreateActionArgs;
use crate::{Error, Result};
use serde::Serialize;
use serde_json::{json, Value};

pub(super) struct Binding<'a> {
    call: &'static str,
    request: Value,
    action: Option<&'a CreateActionArgs>,
}

impl<'a> Binding<'a> {
    pub(super) fn create_action(args: &'a CreateActionArgs) -> Result<Self> {
        let sources = crate::wallet::validation::client::create_action_sources(args)?;
        // Capture the binding fields without ever serializing inputBEEF.
        let mut request = result_values::request("createAction", &serde_json::to_vec(&json!({
            "inputs": args.inputs.as_ref().map(|inputs| inputs.iter().map(|input| {
                let mut value = json!({"outpoint": input.outpoint});
                if input.unlocking_script.is_some() { value["unlockingScript"] = json!(""); }
                if let Some(sequence) = input.sequence_number { value["sequenceNumber"] = json!(sequence); }
                value
            }).collect::<Vec<_>>()),
            "outputs": args.outputs.as_ref().map(|outputs| outputs.iter().map(|output| {
                json!({"satoshis": output.satoshis, "lockingScript": ""})
            }).collect::<Vec<_>>()),
            "version": args.version,
            "lockTime": args.lock_time, "options": args.options,
        })).map_err(|e| Error::WalletError(e.to_string()))?)?;
        // Absent optional arguments must remain absent, as in their serde form.
        if let Some(object) = request.as_object_mut() {
            object.retain(|_, value| !value.is_null());
        }
        request["$sourceValues"] =
            serde_json::to_value(sources).map_err(|e| Error::WalletError(e.to_string()))?;
        Ok(Self {
            call: "createAction",
            request,
            action: Some(args),
        })
    }

    /// Capture only the reference's binding fields before crossing the wire.
    pub(super) fn new(call: &'static str, args: &impl Serialize) -> Result<Self> {
        let bytes = serde_json::to_vec(args).map_err(|e| Error::WalletError(e.to_string()))?;
        Ok(Self {
            call,
            request: result_values::request(call, &bytes)?,
            action: None,
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

    pub(super) fn check<R: result_values::WireResult>(&self, result: R) -> Result<R> {
        result.check(self.call, &self.request, self.action)?;
        Ok(result)
    }
}

/// Signature bytes have no serde impl on their public result record.
pub(super) fn signature(signature: &[u8]) -> Result<()> {
    result_values::wire_signature(signature)
}

pub(super) fn request_length(length: usize) -> Result<()> {
    result_values::wire_request_length(length)
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
