//! Certificate types for BRC-52/53 identity certificates.
//!
//! This module provides certificate types for selective attribute disclosure:
//!
//! - [`Certificate`] - Base certificate with encrypted fields
//! - [`MasterCertificate`] - Certificate with master keyring (for subject/certifier)
//! - [`VerifiableCertificate`] - Certificate with verifier-specific keyring
//!
//! ## Certificate Flow
//!
//! 1. **Issuance**: Certifier creates a `MasterCertificate` for the subject
//!    - Fields are encrypted from certifier to subject
//!    - Master keyring stores encryption keys
//!
//! 2. **Storage**: Subject stores the `MasterCertificate`
//!    - Can decrypt all fields using the master keyring
//!
//! 3. **Proving**: Subject creates a `VerifiableCertificate` for a verifier
//!    - Creates verifier-specific keyring for selected fields
//!    - Verifier can only decrypt revealed fields
//!
//! ## Field Encryption
//!
//! Fields are encrypted using BRC-42 key derivation:
//! - Protocol: `"certificate field encryption"`
//! - Security Level: 2 (counterparty-specific)
//! - Key ID (master): `"{field_name}"`
//! - Key ID (verifiable): `"{serial_number_base64} {field_name}"`

mod certificate;
mod master;
mod verifiable;

pub use certificate::Certificate;
pub use master::MasterCertificate;
pub use verifiable::VerifiableCertificate;

/// Protocol name for certificate field encryption.
pub const CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL: &str = "certificate field encryption";

/// Protocol name for certificate signatures.
pub const CERTIFICATE_SIGNATURE_PROTOCOL: &str = "certificate signature";
