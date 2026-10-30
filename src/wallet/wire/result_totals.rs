//! Page totals have the result validator's safe-integer range (#467).
//! `WalletResultValidation.ts:1926` at ts-stack@edf6e03; its wire's narrower
//! field guard is a documented divergence. Totals never set a read-loop bound.

use super::{refused, WireReader};
use crate::Error;

impl WireReader<'_> {
    pub(super) fn result_page_capacity(&self, total: u64) -> usize {
        // A total may exceed usize on wasm32. Reserve only for available bytes.
        usize::try_from(total)
            .unwrap_or(usize::MAX)
            .min(self.remaining())
    }
}

/// `#assertPageCount` (`WalletWireTransceiver.ts:1940-1946`), after the page
/// is read: no more entries than the declared total (bsv-rs#190, #467).
pub(crate) fn assert_page_count(returned: usize, total: u64, call: &str) -> Result<(), Error> {
    if returned as u64 > total {
        return Err(refused(format!(
            "Wallet Wire {call} response returned {returned} records but declared a total of {total}"
        )));
    }
    Ok(())
}
