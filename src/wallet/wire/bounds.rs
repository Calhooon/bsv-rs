//! Bounds at the reference's reads, before allocating or parsing entries (#473).
//! `ts-stack@edf6e03`: WalletWireTransceiver.ts:1955-1969 and
//! WalletWireProcessor.ts:109-126. Generic string-array/map codecs stay uncapped.

use super::{integer_refusal, refused, WireReader};
use crate::wallet::{ListActionsResult, ListOutputsResult};
use crate::Error;

impl WireReader<'_> {
    pub(super) fn read_height_result(&mut self) -> Result<u64, Error> {
        // Transceiver:1882-1888: unsigned strict read, trailing data, then range.
        let height = self.read_var_int_num_strict_u64()?;
        if !self.is_empty() {
            return Err(refused(
                "Wallet Wire getHeight response contains trailing data",
            ));
        }
        if !(1..=u64::from(u32::MAX)).contains(&height) {
            return Err(refused("Wallet returned an invalid height"));
        }
        Ok(height)
    }

    pub(super) fn read_satoshis(&mut self, field: &str) -> Result<u64, Error> {
        // Transceiver:480-485,523-528,670-675. Result validation repeats
        // 0..=21e14 at WalletResultValidation.ts:2010,2053,2105.
        let value = self.read_var_int_num_strict_u64()?;
        const MAXIMUM: u64 = 2_100_000_000_000_000;
        if value > MAXIMUM {
            return Err(refused(integer_refusal(field, value, 0, MAXIMUM)));
        }
        Ok(value)
    }

    pub(super) fn read_response_count(
        &mut self,
        name: &str,
        maximum: u64,
        minimum_bytes: u64,
    ) -> Result<u64, Error> {
        let count = self.read_optional_count()?;
        if count == u64::MAX {
            return Ok(count);
        }
        if count > maximum {
            return Err(refused(format!(
                "Wallet Wire {name} exceeds the maximum collection size of {maximum}"
            )));
        }
        if count > self.remaining() as u64 / minimum_bytes {
            return Err(refused(format!(
                "Wallet Wire {name} count exceeds the remaining response data"
            )));
        }
        Ok(count)
    }

    pub(super) fn read_request_count(&mut self, name: &str) -> Result<u64, Error> {
        let count = self.read_var_int_num_strict_u64()?;
        if count > 100_000 {
            return Err(refused(format!(
                "Invalid {name} length: expected 0 through 100000, received {count}"
            )));
        }
        if count > self.remaining() as u64 {
            return Err(refused(format!(
                "Invalid {name} length: exceeds the remaining Wallet Wire frame"
            )));
        }
        Ok(count)
    }

    pub(super) fn read_response_strings(&mut self, name: &str) -> Result<Vec<String>, Error> {
        let count = self.read_response_count(name, 100_000, 1)?;
        self.read_bounded_strings(count)
    }

    pub(super) fn read_insertion_tags(&mut self) -> Result<Vec<String>, Error> {
        // Processor:1121-1132: optional, unlike signAction's required spends.
        let count = self.read_optional_count()?;
        if count == u64::MAX {
            return Ok(Vec::new());
        }
        if count > 100_000 {
            return Err(refused(format!(
                "Invalid internalizeAction output tags length: expected 0 through 100000, received {count}"
            )));
        }
        if count > self.remaining() as u64 {
            return Err(refused(
                "Invalid internalizeAction output tags length: exceeds the remaining Wallet Wire frame",
            ));
        }
        self.read_bounded_strings(count)
    }

    fn read_bounded_strings(&mut self, count: u64) -> Result<Vec<String>, Error> {
        if count == u64::MAX {
            return Ok(Vec::new());
        }
        // Both callers checked the cap and remaining bytes before allocation.
        let mut strings = Vec::with_capacity(count as usize);
        for _ in 0..count {
            strings.push(self.read_string()?);
        }
        Ok(strings)
    }

    pub(super) fn read_actions_page(
        &mut self,
        limit: Option<u32>,
    ) -> Result<ListActionsResult, Error> {
        let total_actions = self.read_var_int_u32("listActions totalActions")?;
        let mut actions = Vec::new();
        while !self.is_empty() {
            super::require_page_capacity(actions.len(), limit, "listActions")?;
            actions.push(self.read_wallet_action()?);
        }
        super::assert_page_count(actions.len(), total_actions, "listActions")?;
        Ok(ListActionsResult {
            total_actions,
            actions,
        })
    }

    pub(super) fn read_outputs_page(
        &mut self,
        limit: Option<u32>,
    ) -> Result<ListOutputsResult, Error> {
        let total_outputs = self.read_var_int_u32("listOutputs totalOutputs")?;
        let beef = self.read_optional_bytes()?;
        let mut outputs = Vec::new();
        while !self.is_empty() {
            super::require_page_capacity(outputs.len(), limit, "listOutputs")?;
            outputs.push(self.read_wallet_output()?);
        }
        super::assert_page_count(outputs.len(), total_outputs, "listOutputs")?;
        Ok(ListOutputsResult {
            total_outputs,
            beef,
            outputs,
        })
    }
}
