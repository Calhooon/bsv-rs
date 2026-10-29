//! The wire header's originator (#338), as read and written by
//! `ts-stack@edf6e03` `WalletWireProcessor.ts:286-294` and
//! `WalletWireTransceiver.ts:95-100`. An empty header keeps #329's `None`.

use super::encoding::WireReader;
use super::validation::Refusal;
use crate::wallet::validation::validate_originator;
use crate::Error;

const MAX_ORIGINATOR_BYTES: usize = 250;

fn length_refusal(length: usize) -> String {
    format!(
        "Invalid originator length: expected at most {MAX_ORIGINATOR_BYTES} bytes, received {length}"
    )
}

/// Refuse the declared byte length before reading; normalize before dispatch.
pub(super) fn read(reader: &mut WireReader<'_>) -> Result<Option<String>, Refusal> {
    let length = usize::from(reader.read_u8()?);
    if length > MAX_ORIGINATOR_BYTES {
        return Err(Refusal::plain(length_refusal(length)));
    }
    let originator = std::str::from_utf8(reader.read_bytes(length)?)
        .map_err(|_| Error::WalletError("invalid originator UTF-8".to_string()))?;
    Ok(validate_originator(
        (!originator.is_empty()).then_some(originator),
    )?)
}

/// Validate before allocating a frame, then narrow its normalized byte length
/// with a checked conversion. The validator supplies the reference's code 6
/// and words for an invalid originator, including one longer than 250 bytes.
pub(super) fn encode(originator: Option<&str>) -> Result<(u8, String), Error> {
    let originator =
        validate_originator(originator.filter(|value| !value.is_empty()))?.unwrap_or_default();
    let length = u8::try_from(originator.len())
        .map_err(|_| Error::WalletError(length_refusal(originator.len())))?;
    Ok((length, originator))
}
