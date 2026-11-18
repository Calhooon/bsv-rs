//! The wire's flag bytes, read as the reference reads them (#1002):
//! `ts-stack@edf6e03` `WalletWireProcessor.ts:38-61,831-842` for a request,
//! `WalletWireTransceiver.ts:395-399,1855-1858,1915-1916,1971-1977` for a
//! result. Each refusal is the reference's sentence, pinned against its
//! recorded frames by `tests/wallet_wire_flags_1002.rs`.

use super::{refused, status_codes, WireReader};
use crate::wallet::types::{ActionStatus, QueryMode};
use crate::Error;

/// An action result's optional txid and optional tx.
pub(super) type FlaggedTx = (Option<[u8; 32]>, Option<Vec<u8>>);

impl WireReader<'_> {
    /// An optional boolean of a request: -1 absent, 0, 1, another byte
    /// refused naming the field (`#readOptionalBooleanFlag`, `:46-52`).
    pub(super) fn read_optional_boolean_flag(&mut self, name: &str) -> Result<Option<bool>, Error> {
        match self.read_i8()? {
            -1 => Ok(None),
            0 => Ok(Some(false)),
            1 => Ok(Some(true)),
            flag => Err(refused(format!(
                "Invalid {name} flag: expected -1, 0, or 1, received {flag}"
            ))),
        }
    }

    /// A request's closing `seekPermission` flag (`:874`, `:1165`, `:1403`).
    pub(super) fn read_seek_permission(&mut self) -> Result<Option<bool>, Error> {
        self.read_optional_boolean_flag("seekPermission")
    }

    /// An optional length carried in one signed byte: -1 absent, 0 to 127,
    /// another negative refused (`#readOptionalInt8Length`, `:54-61`).
    pub(super) fn read_optional_int8_length(&mut self, name: &str) -> Result<Option<usize>, Error> {
        match self.read_i8()? {
            -1 => Ok(None),
            length => usize::try_from(length).map(Some).map_err(|_| {
                refused(format!(
                    "Invalid {name} length: expected -1 or 0–127, received {length}"
                ))
            }),
        }
    }

    /// listActions' `labelQueryMode`: -1 absent, 1 `any`, 2 `all` (`:831-842`;
    /// the transceiver writes them at `WalletWireTransceiver.ts:358-360`).
    /// listOutputs' `tagQueryMode` is the other way round, 1 `all` and 2
    /// `any` (`:1206-1217`), and is not read here.
    pub(super) fn read_label_query_mode(&mut self) -> Result<Option<QueryMode>, Error> {
        match self.read_i8()? {
            -1 => Ok(None),
            1 => Ok(Some(QueryMode::Any)),
            2 => Ok(Some(QueryMode::All)),
            flag => Err(refused(format!(
                "Invalid labelQueryMode flag: expected -1, 1, or 2, received {flag}"
            ))),
        }
    }

    /// An action result's txid and tx, each behind a presence flag that is
    /// 0 or 1 (`WalletWireTransceiver.ts:238-244` createAction, `:310-315`
    /// signAction; `#readBooleanFlag`, `:1971-1977`).
    pub(super) fn read_flagged_txid_and_tx(&mut self, call: &str) -> Result<FlaggedTx, Error> {
        let txid = if self.read_boolean_flag(&format!("{call} txid present"))? {
            let mut txid = [0u8; 32];
            txid.copy_from_slice(self.read_bytes(32)?);
            Some(txid)
        } else {
            None
        };
        let tx = if self.read_boolean_flag(&format!("{call} tx present"))? {
            let length = self.read_length()?;
            Some(self.read_bytes(length)?.to_vec())
        } else {
            None
        };
        Ok((txid, tx))
    }

    /// A listed action's status: the reference writes no absent status and
    /// reads none (`WalletWireTransceiver.ts:422`).
    pub(super) fn read_listed_action_status(&mut self) -> Result<ActionStatus, Error> {
        action_status(self.read_i8()?)
    }
}

/// The status a code names, 1 to 8, another code refused in the reference's
/// words (`#parseActionStatus`, `WalletWireTransceiver.ts:395-399`).
pub(super) fn action_status(code: i8) -> Result<ActionStatus, Error> {
    Ok(match code {
        status_codes::COMPLETED => ActionStatus::Completed,
        status_codes::UNPROCESSED => ActionStatus::Unprocessed,
        status_codes::SENDING => ActionStatus::Sending,
        status_codes::UNPROVEN => ActionStatus::Unproven,
        status_codes::UNSIGNED => ActionStatus::Unsigned,
        status_codes::NOSEND => ActionStatus::NoSend,
        status_codes::NONFINAL => ActionStatus::NonFinal,
        status_codes::FAILED => ActionStatus::Failed,
        code => return Err(refused(format!("Unknown status code: {code}"))),
    })
}

/// A result that is exactly one byte, 0 or 1: isAuthenticated's verdict and
/// getNetwork's network (`WalletWireTransceiver.ts:1855-1858`, `:1915-1916`).
/// Another length is the reference's length refusal, another byte `invalid`.
pub(super) fn single_flag(response: &[u8], call: &str, invalid: &str) -> Result<bool, Error> {
    super::require_response_length(response, 1, call)?;
    match response {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(refused(invalid)),
    }
}
