//! The id a broadcaster's success answers: the submitted transaction's own.
//!
//! A service that accepts a transaction may name the id it accepted (the
//! WhatsOnChain body, ARC's `txid` field). [`acknowledged_txid`] is the one
//! rule every broadcaster that reads such a name asks: a name that is the
//! submitted transaction's id (either case) answers as the service wrote it,
//! a service that names no id answers the submitted id, and any other name
//! (another transaction's id, or text that is no transaction id) is not a
//! success but `ERR_TXID_MISMATCH`, carrying the submitted id. So a success's
//! `txid` is always the id of the transaction the caller handed over
//! (`tests/broadcaster_acknowledged_txid.rs`).

use crate::transaction::{BroadcastFailure, BroadcastStatus};

/// The code of a success that names another transaction.
pub(crate) const ERR_TXID_MISMATCH: &str = "ERR_TXID_MISMATCH";

/// 64 hexadecimal digits, either case.
pub(crate) fn is_txid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The txid of a success whose service named `named` (`None`: no id named)
/// for the transaction whose id is `expected`; `description` is the failure's
/// when the name is not `expected`.
pub(crate) fn acknowledged_txid(
    named: Option<&str>,
    expected: &str,
    description: &str,
) -> Result<String, BroadcastFailure> {
    match named {
        None => Ok(expected.to_string()),
        Some(name) if is_txid(name) && name.eq_ignore_ascii_case(expected) => Ok(name.to_string()),
        Some(_) => Err(BroadcastFailure {
            status: BroadcastStatus::Error,
            code: ERR_TXID_MISMATCH.to_string(),
            txid: Some(expected.to_string()),
            description: description.to_string(),
            more: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

    #[test]
    fn a_txid_is_sixty_four_hex_digits_and_no_other_length() {
        assert!(is_txid(ID));
        assert!(is_txid(&ID.to_ascii_uppercase()));
        assert!(!is_txid(&ID[..63]));
        assert!(!is_txid(&format!("{ID}0")));
        assert!(!is_txid(&format!("{}g", &ID[..63])));
        assert!(!is_txid(""));
    }

    #[test]
    fn a_name_of_another_length_is_a_mismatch_carrying_the_submitted_id() {
        for name in [&ID[..63], &format!("{ID}0")[..]] {
            let failure = acknowledged_txid(Some(name), ID, "d").unwrap_err();
            assert_eq!(failure.code, ERR_TXID_MISMATCH);
            assert_eq!(failure.txid.as_deref(), Some(ID));
        }
        assert_eq!(acknowledged_txid(None, ID, "d").unwrap(), ID);
        let upper = ID.to_ascii_uppercase();
        assert_eq!(acknowledged_txid(Some(&upper), ID, "d").unwrap(), upper);
    }
}
