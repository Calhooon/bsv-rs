//! #439: the port's typed metadata preserves each existing display string.
#![cfg(feature = "wallet")]
#![allow(clippy::panic)] // #134: a mismatched error variant is a failed test.

use bsv_rs::{AbortAcceptance, Error, WalletFault, WalletFaultFamily, WalletRefusalClass};

fn assert_fault(family: WalletFaultFamily, message: &str, displayed: &str) {
    let fault = WalletFault::new(family, message);
    assert_eq!(fault.to_string().as_bytes(), message.as_bytes());
    let error = Error::WalletFault(fault.clone());
    assert_eq!(error.to_string().as_bytes(), displayed.as_bytes());
    assert_eq!(
        error.to_string().as_bytes(),
        Error::WalletError(message.to_owned())
            .to_string()
            .as_bytes()
    );
    assert_eq!(error, error.clone());
    assert_eq!(error, Error::WalletFault(fault.clone()));
    match &error {
        Error::WalletFault(actual) => {
            assert_eq!(actual.family, family);
            assert_eq!(actual.message, message);
        }
        other => panic!("expected a typed wallet fault, got {other:?}"),
    }
    let other_family = if family == WalletFaultFamily::Internal {
        WalletFaultFamily::Service
    } else {
        WalletFaultFamily::Internal
    };
    assert_ne!(
        error,
        Error::WalletFault(WalletFault::new(other_family, message))
    );
    assert_ne!(
        error,
        Error::WalletFault(WalletFault::new(family, "changed"))
    );
    assert_ne!(error, Error::WalletError(message.to_owned()));
    assert_eq!(
        error.transport_fault(),
        None,
        "no delivery promise was added"
    );
}

#[test]
fn transport_fault_text_and_type_agree() {
    assert_fault(
        WalletFaultFamily::Transport,
        "Network error: response timed out",
        "wallet error: Network error: response timed out",
    );
}

#[test]
fn service_fault_text_and_type_agree() {
    assert_fault(
        WalletFaultFamily::Service,
        "Service error: provider unavailable\n réessayer\t",
        "wallet error: Service error: provider unavailable\n réessayer\t",
    );
}

#[test]
fn storage_fault_text_and_type_agree() {
    for (message, displayed) in [
        (
            "Storage error: write failed",
            "wallet error: Storage error: write failed",
        ),
        (
            "Database error: disk full",
            "wallet error: Database error: disk full",
        ),
    ] {
        assert_fault(WalletFaultFamily::Storage, message, displayed);
    }
}

#[test]
fn internal_fault_text_and_type_agree() {
    for (message, displayed) in [
        (
            "Internal error: invariant\0detail",
            "wallet error: Internal error: invariant\0detail",
        ),
        ("", "wallet error: "),
    ] {
        assert_fault(WalletFaultFamily::Internal, message, displayed);
    }
}

#[test]
fn abort_acceptance_text_and_record_agree_without_changing_the_refusal_class() {
    for (class, txid, status, accepting_word, message) in [
        (
            WalletRefusalClass::InvalidParameter,
            None,
            Some("unproven"),
            None,
            "Invalid transaction status: cannot abort action: action with status 'unproven' records an acceptance and cannot be aborted",
        ),
        (
            WalletRefusalClass::InvalidOperation,
            Some("aa"),
            Some("sending"),
            Some("tracker word 'seen'"),
            "Invalid transaction status: cannot abort action: transaction aa has a recorded acceptance (tracker word 'seen'); only a transaction never accepted can be retired",
        ),
    ] {
        let mut record = Box::new(AbortAcceptance::new("reference/\0é", class, message));
        assert_eq!((&record.txid, &record.status, &record.accepting_word), (&None, &None, &None));
        record.txid = txid.map(Into::into);
        record.status = status.map(Into::into);
        record.accepting_word = accepting_word.map(Into::into);
        assert_eq!(record.to_string().as_bytes(), message.as_bytes());
        let error = Error::AbortAccepted(record.clone());
        assert_eq!(error.to_string().as_bytes(), message.as_bytes());
        assert_eq!(
            error.to_string(),
            Error::WalletRefusal { class, message: message.to_owned() }.to_string()
        );
        assert_eq!(error, error.clone());
        assert_eq!(error, Error::AbortAccepted(record.clone()));
        match &error {
            Error::AbortAccepted(actual) => {
                assert_eq!(actual.reference, "reference/\0é");
                assert_eq!(actual.txid.as_deref(), txid);
                assert_eq!(actual.status.as_deref(), status);
                assert_eq!(actual.accepting_word.as_deref(), accepting_word);
                assert_eq!(actual.class, class);
                assert_eq!(actual.message, message);
            }
            other => panic!("expected stored abort acceptance, got {other:?}"),
        }
        for change in [
            |r: &mut AbortAcceptance| r.reference.push('!'),
            |r: &mut AbortAcceptance| r.txid = Some("different txid".into()),
            |r: &mut AbortAcceptance| r.status = Some("different status".into()),
            |r: &mut AbortAcceptance| r.accepting_word = Some("different word".into()),
            |r: &mut AbortAcceptance| r.class = WalletRefusalClass::Internal,
            |r: &mut AbortAcceptance| r.message.push('!'),
        ] {
            let mut changed = record.clone();
            change(&mut changed);
            assert_ne!(error, Error::AbortAccepted(changed));
        }
        assert_eq!(error.transport_fault(), None);
    }
}
