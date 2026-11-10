//! `AcquireCertificateArgs` writes its `Debug` by hand (the second fold of
//! the secret Debug lane, 2026-11-10): every field as the derive printed it,
//! the certifier's URL through `crate::util::debug_redact::OptionUrl` (user
//! info, a query and a fragment `<redacted>`), since a caller's certifier
//! endpoint can carry a credential there. `tests/secret_debug.rs` pins it.

use std::fmt::{Debug, Formatter, Result};

use super::types::AcquireCertificateArgs;
use crate::util::debug_redact::OptionUrl;

impl Debug for AcquireCertificateArgs {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("AcquireCertificateArgs")
            .field("certificate_type", &self.certificate_type)
            .field("certifier", &self.certifier)
            .field("acquisition_protocol", &self.acquisition_protocol)
            .field("fields", &self.fields)
            .field("serial_number", &self.serial_number)
            .field("revocation_outpoint", &self.revocation_outpoint)
            .field("signature", &self.signature)
            .field("certifier_url", &OptionUrl(&self.certifier_url))
            .field("keyring_revealer", &self.keyring_revealer)
            .field("keyring_for_subject", &self.keyring_for_subject)
            .field("privileged", &self.privileged)
            .field("privileged_reason", &self.privileged_reason)
            .finish()
    }
}
