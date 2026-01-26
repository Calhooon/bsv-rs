//! WalletWire call codes.
//!
//! This module defines the 28 call codes used in the WalletWire binary protocol.
//! Each call code corresponds to a method on the WalletInterface.

use crate::Error;

/// WalletWire call codes (1-28).
///
/// These codes are used as the first byte in a WalletWire message to identify
/// which wallet method is being called.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WalletCall {
    /// Create a new transaction action.
    CreateAction = 1,
    /// Sign an existing action.
    SignAction = 2,
    /// Abort an in-progress action.
    AbortAction = 3,
    /// List wallet actions.
    ListActions = 4,
    /// Internalize an external action.
    InternalizeAction = 5,
    /// List wallet outputs.
    ListOutputs = 6,
    /// Relinquish an output.
    RelinquishOutput = 7,
    /// Get a public key.
    GetPublicKey = 8,
    /// Reveal counterparty key linkage.
    RevealCounterpartyKeyLinkage = 9,
    /// Reveal specific key linkage.
    RevealSpecificKeyLinkage = 10,
    /// Encrypt data.
    Encrypt = 11,
    /// Decrypt data.
    Decrypt = 12,
    /// Create an HMAC.
    CreateHmac = 13,
    /// Verify an HMAC.
    VerifyHmac = 14,
    /// Create a signature.
    CreateSignature = 15,
    /// Verify a signature.
    VerifySignature = 16,
    /// Acquire a certificate.
    AcquireCertificate = 17,
    /// List certificates.
    ListCertificates = 18,
    /// Prove a certificate.
    ProveCertificate = 19,
    /// Relinquish a certificate.
    RelinquishCertificate = 20,
    /// Discover certificates by identity key.
    DiscoverByIdentityKey = 21,
    /// Discover certificates by attributes.
    DiscoverByAttributes = 22,
    /// Check if authenticated.
    IsAuthenticated = 23,
    /// Wait for authentication.
    WaitForAuthentication = 24,
    /// Get current block height.
    GetHeight = 25,
    /// Get header for a given height.
    GetHeaderForHeight = 26,
    /// Get the current network.
    GetNetwork = 27,
    /// Get the wallet version.
    GetVersion = 28,
}

impl WalletCall {
    /// Returns the call code as a u8.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns the method name for this call.
    pub fn method_name(self) -> &'static str {
        match self {
            WalletCall::CreateAction => "createAction",
            WalletCall::SignAction => "signAction",
            WalletCall::AbortAction => "abortAction",
            WalletCall::ListActions => "listActions",
            WalletCall::InternalizeAction => "internalizeAction",
            WalletCall::ListOutputs => "listOutputs",
            WalletCall::RelinquishOutput => "relinquishOutput",
            WalletCall::GetPublicKey => "getPublicKey",
            WalletCall::RevealCounterpartyKeyLinkage => "revealCounterpartyKeyLinkage",
            WalletCall::RevealSpecificKeyLinkage => "revealSpecificKeyLinkage",
            WalletCall::Encrypt => "encrypt",
            WalletCall::Decrypt => "decrypt",
            WalletCall::CreateHmac => "createHmac",
            WalletCall::VerifyHmac => "verifyHmac",
            WalletCall::CreateSignature => "createSignature",
            WalletCall::VerifySignature => "verifySignature",
            WalletCall::AcquireCertificate => "acquireCertificate",
            WalletCall::ListCertificates => "listCertificates",
            WalletCall::ProveCertificate => "proveCertificate",
            WalletCall::RelinquishCertificate => "relinquishCertificate",
            WalletCall::DiscoverByIdentityKey => "discoverByIdentityKey",
            WalletCall::DiscoverByAttributes => "discoverByAttributes",
            WalletCall::IsAuthenticated => "isAuthenticated",
            WalletCall::WaitForAuthentication => "waitForAuthentication",
            WalletCall::GetHeight => "getHeight",
            WalletCall::GetHeaderForHeight => "getHeaderForHeight",
            WalletCall::GetNetwork => "getNetwork",
            WalletCall::GetVersion => "getVersion",
        }
    }
}

impl TryFrom<u8> for WalletCall {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(WalletCall::CreateAction),
            2 => Ok(WalletCall::SignAction),
            3 => Ok(WalletCall::AbortAction),
            4 => Ok(WalletCall::ListActions),
            5 => Ok(WalletCall::InternalizeAction),
            6 => Ok(WalletCall::ListOutputs),
            7 => Ok(WalletCall::RelinquishOutput),
            8 => Ok(WalletCall::GetPublicKey),
            9 => Ok(WalletCall::RevealCounterpartyKeyLinkage),
            10 => Ok(WalletCall::RevealSpecificKeyLinkage),
            11 => Ok(WalletCall::Encrypt),
            12 => Ok(WalletCall::Decrypt),
            13 => Ok(WalletCall::CreateHmac),
            14 => Ok(WalletCall::VerifyHmac),
            15 => Ok(WalletCall::CreateSignature),
            16 => Ok(WalletCall::VerifySignature),
            17 => Ok(WalletCall::AcquireCertificate),
            18 => Ok(WalletCall::ListCertificates),
            19 => Ok(WalletCall::ProveCertificate),
            20 => Ok(WalletCall::RelinquishCertificate),
            21 => Ok(WalletCall::DiscoverByIdentityKey),
            22 => Ok(WalletCall::DiscoverByAttributes),
            23 => Ok(WalletCall::IsAuthenticated),
            24 => Ok(WalletCall::WaitForAuthentication),
            25 => Ok(WalletCall::GetHeight),
            26 => Ok(WalletCall::GetHeaderForHeight),
            27 => Ok(WalletCall::GetNetwork),
            28 => Ok(WalletCall::GetVersion),
            _ => Err(Error::WalletError(format!(
                "invalid call code: expected 1-28, got {}",
                value
            ))),
        }
    }
}

impl std::fmt::Display for WalletCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.method_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_codes() {
        assert_eq!(WalletCall::CreateAction.as_u8(), 1);
        assert_eq!(WalletCall::GetVersion.as_u8(), 28);
    }

    #[test]
    fn test_try_from_valid() {
        assert_eq!(WalletCall::try_from(1).unwrap(), WalletCall::CreateAction);
        assert_eq!(WalletCall::try_from(28).unwrap(), WalletCall::GetVersion);
    }

    #[test]
    fn test_try_from_invalid() {
        assert!(WalletCall::try_from(0).is_err());
        assert!(WalletCall::try_from(29).is_err());
        assert!(WalletCall::try_from(255).is_err());
    }

    #[test]
    fn test_method_names() {
        assert_eq!(WalletCall::CreateAction.method_name(), "createAction");
        assert_eq!(WalletCall::GetVersion.method_name(), "getVersion");
    }

    #[test]
    fn test_roundtrip() {
        for code in 1..=28u8 {
            let call = WalletCall::try_from(code).unwrap();
            assert_eq!(call.as_u8(), code);
        }
    }
}
