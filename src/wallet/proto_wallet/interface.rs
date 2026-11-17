//! WalletInterface forwarding and unsupported operations for ProtoWallet: the
//! fourteen calls it does not serve answer `Error::WalletRefusal` of class
//! `WalletRefusalClass::NotImplemented` (#843).

use super::*;

// =============================================================================
// WalletInterface Implementation
// =============================================================================

use super::super::interface::{
    RevealCounterpartyKeyLinkageArgs as InterfaceRevealCounterpartyArgs,
    RevealSpecificKeyLinkageArgs as InterfaceRevealSpecificArgs, WalletInterface,
};
use super::super::types::{
    KeyLinkageResult, RevealCounterpartyKeyLinkageResult as TypesRevealCounterpartyResult,
    RevealSpecificKeyLinkageResult as TypesRevealSpecificResult,
};
use super::super::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AuthenticatedResult,
    CreateActionArgs, CreateActionResult, DiscoverByAttributesArgs, DiscoverByIdentityKeyArgs,
    DiscoverCertificatesResult, GetHeaderArgs, GetHeaderResult, GetHeightResult, GetNetworkResult,
    GetVersionResult, InternalizeActionArgs, InternalizeActionResult, ListActionsArgs,
    ListActionsResult, ListCertificatesArgs, ListCertificatesResult, ListOutputsArgs,
    ListOutputsResult, Network, ProveCertificateArgs, ProveCertificateResult,
    RelinquishCertificateArgs, RelinquishCertificateResult, RelinquishOutputArgs,
    RelinquishOutputResult, SignActionArgs, SignActionResult, WalletCertificate,
};
use crate::error::WalletRefusalClass;
use async_trait::async_trait;

/// The answer to a call a `ProtoWallet` does not serve (#843): the typed
/// refusal of the reference's class for it, `WERR_NOT_IMPLEMENTED`
/// (`packages/wallet/wallet-toolbox/src/sdk/WERR_errors.ts:8` at
/// `ts-stack@11faa7d1`, raised by a provider for a call it does not serve,
/// `storage/StorageProvider.ts:445-534`), in the words each stub always
/// answered. The class has no SDK code, so the wire processor frames it as
/// it framed the `WalletError` these were: code 1, `Wallet operation failed`.
fn not_implemented<T>(words: &str) -> Result<T> {
    Err(Error::WalletRefusal {
        class: WalletRefusalClass::NotImplemented,
        message: words.to_string(),
    })
}

#[async_trait]
impl WalletInterface for ProtoWallet {
    // =========================================================================
    // Key Operations (all supported)
    // =========================================================================

    async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        _: Option<&str>,
    ) -> Result<GetPublicKeyResult> {
        self.get_public_key(args)
    }

    async fn encrypt(&self, args: EncryptArgs, _: Option<&str>) -> Result<EncryptResult> {
        self.encrypt(args)
    }

    async fn decrypt(&self, args: DecryptArgs, _: Option<&str>) -> Result<DecryptResult> {
        self.decrypt(args)
    }

    async fn create_hmac(&self, args: CreateHmacArgs, _: Option<&str>) -> Result<CreateHmacResult> {
        self.create_hmac(args)
    }

    async fn verify_hmac(&self, args: VerifyHmacArgs, _: Option<&str>) -> Result<VerifyHmacResult> {
        self.verify_hmac(args)
    }

    async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        _: Option<&str>,
    ) -> Result<CreateSignatureResult> {
        self.create_signature(args)
    }

    async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        _: Option<&str>,
    ) -> Result<VerifySignatureResult> {
        self.verify_signature(args)
    }

    async fn reveal_counterparty_key_linkage(
        &self,
        args: InterfaceRevealCounterpartyArgs,
        _: Option<&str>,
    ) -> Result<TypesRevealCounterpartyResult> {
        crypto::reveal_counterparty_args(
            &args.counterparty.to_compressed(),
            &args.verifier.to_compressed(),
            args.privileged,
            args.privileged_reason.as_deref(),
        )?;
        let result = self.reveal_counterparty_key_linkage(RevealCounterpartyKeyLinkageArgs {
            counterparty: args.counterparty.clone(),
            verifier: args.verifier.clone(),
        })?;

        // Parse the hex strings back to PublicKeys
        let prover = PublicKey::from_hex(&result.prover)?;
        let counterparty_key = PublicKey::from_hex(&result.counterparty)?;

        Ok(TypesRevealCounterpartyResult {
            linkage: KeyLinkageResult {
                encrypted_linkage: result.encrypted_linkage,
                encrypted_linkage_proof: result.encrypted_linkage_proof,
                prover,
                verifier: args.verifier,
                counterparty: counterparty_key,
            },
            revelation_time: result.revelation_time,
        })
    }

    async fn reveal_specific_key_linkage(
        &self,
        args: InterfaceRevealSpecificArgs,
        _: Option<&str>,
    ) -> Result<TypesRevealSpecificResult> {
        crypto::reveal_specific_args(
            Some(&args.counterparty),
            &args.verifier.to_compressed(),
            &args.protocol_id,
            &args.key_id,
            args.privileged,
            args.privileged_reason.as_deref(),
        )?;
        let result = self.reveal_specific_key_linkage(RevealSpecificKeyLinkageArgs {
            counterparty: args.counterparty.clone(),
            verifier: args.verifier.clone(),
            protocol_id: args.protocol_id.clone(),
            key_id: args.key_id.clone(),
        })?;

        // Parse the hex strings back to PublicKeys
        let prover = PublicKey::from_hex(&result.prover)?;
        let counterparty_key = PublicKey::from_hex(&result.counterparty)?;

        Ok(TypesRevealSpecificResult {
            linkage: KeyLinkageResult {
                encrypted_linkage: result.encrypted_linkage,
                encrypted_linkage_proof: result.encrypted_linkage_proof,
                prover,
                verifier: args.verifier,
                counterparty: counterparty_key,
            },
            protocol: result.protocol_id,
            key_id: result.key_id,
            proof_type: result.proof_type,
        })
    }

    // =========================================================================
    // Action Operations (NOT supported - require full wallet)
    // =========================================================================

    async fn create_action(
        &self,
        _args: CreateActionArgs,
        _: Option<&str>,
    ) -> Result<CreateActionResult> {
        not_implemented("createAction requires a full wallet implementation with UTXO management")
    }

    async fn sign_action(
        &self,
        _args: SignActionArgs,
        _: Option<&str>,
    ) -> Result<SignActionResult> {
        not_implemented("signAction requires a full wallet implementation with UTXO management")
    }

    async fn abort_action(
        &self,
        _args: AbortActionArgs,
        _: Option<&str>,
    ) -> Result<AbortActionResult> {
        not_implemented("abortAction requires a full wallet implementation with UTXO management")
    }

    async fn list_actions(
        &self,
        _args: ListActionsArgs,
        _: Option<&str>,
    ) -> Result<ListActionsResult> {
        not_implemented(
            "listActions requires a full wallet implementation with transaction history",
        )
    }

    async fn internalize_action(
        &self,
        args: InternalizeActionArgs,
        _: Option<&str>,
    ) -> Result<InternalizeActionResult> {
        crate::wallet::validation::validate_internalize_action_args(&args)?;
        not_implemented(
            "internalizeAction requires a full wallet implementation with UTXO management",
        )
    }

    // =========================================================================
    // Output Operations (NOT supported - require full wallet)
    // =========================================================================

    async fn list_outputs(
        &self,
        _args: ListOutputsArgs,
        _: Option<&str>,
    ) -> Result<ListOutputsResult> {
        not_implemented("listOutputs requires a full wallet implementation with UTXO management")
    }

    async fn relinquish_output(
        &self,
        _args: RelinquishOutputArgs,
        _: Option<&str>,
    ) -> Result<RelinquishOutputResult> {
        not_implemented(
            "relinquishOutput requires a full wallet implementation with UTXO management",
        )
    }

    // =========================================================================
    // Certificate Operations (NOT supported - require full wallet)
    // =========================================================================

    async fn acquire_certificate(
        &self,
        _args: AcquireCertificateArgs,
        _: Option<&str>,
    ) -> Result<WalletCertificate> {
        not_implemented(
            "acquireCertificate requires a full wallet implementation with certificate storage",
        )
    }

    async fn list_certificates(
        &self,
        _args: ListCertificatesArgs,
        _: Option<&str>,
    ) -> Result<ListCertificatesResult> {
        not_implemented(
            "listCertificates requires a full wallet implementation with certificate storage",
        )
    }

    async fn prove_certificate(
        &self,
        _args: ProveCertificateArgs,
        _: Option<&str>,
    ) -> Result<ProveCertificateResult> {
        not_implemented(
            "proveCertificate requires a full wallet implementation with certificate storage",
        )
    }

    async fn relinquish_certificate(
        &self,
        _args: RelinquishCertificateArgs,
        _: Option<&str>,
    ) -> Result<RelinquishCertificateResult> {
        not_implemented(
            "relinquishCertificate requires a full wallet implementation with certificate storage",
        )
    }

    // =========================================================================
    // Discovery Operations (NOT supported - require full wallet)
    // =========================================================================

    async fn discover_by_identity_key(
        &self,
        _args: DiscoverByIdentityKeyArgs,
        _: Option<&str>,
    ) -> Result<DiscoverCertificatesResult> {
        not_implemented(
            "discoverByIdentityKey requires a full wallet implementation with certificate discovery",
        )
    }

    async fn discover_by_attributes(
        &self,
        _args: DiscoverByAttributesArgs,
        _: Option<&str>,
    ) -> Result<DiscoverCertificatesResult> {
        not_implemented(
            "discoverByAttributes requires a full wallet implementation with certificate discovery",
        )
    }

    // =========================================================================
    // Chain/Status Operations (partial support)
    // =========================================================================

    async fn is_authenticated(&self, _: Option<&str>) -> Result<AuthenticatedResult> {
        // ProtoWallet is always authenticated (it has a key)
        Ok(AuthenticatedResult {
            authenticated: true,
        })
    }

    async fn wait_for_authentication(&self, _: Option<&str>) -> Result<AuthenticatedResult> {
        // ProtoWallet is always authenticated
        Ok(AuthenticatedResult {
            authenticated: true,
        })
    }

    async fn get_height(&self, _: Option<&str>) -> Result<GetHeightResult> {
        // ProtoWallet doesn't track chain state
        // Return 0 to indicate unknown
        Ok(GetHeightResult { height: 0 })
    }

    async fn get_header_for_height(
        &self,
        _args: GetHeaderArgs,
        _: Option<&str>,
    ) -> Result<GetHeaderResult> {
        not_implemented(
            "getHeaderForHeight requires a full wallet implementation with block header storage",
        )
    }

    async fn get_network(&self, _: Option<&str>) -> Result<GetNetworkResult> {
        // ProtoWallet defaults to mainnet
        Ok(GetNetworkResult {
            network: Network::Mainnet,
        })
    }

    async fn get_version(&self, _: Option<&str>) -> Result<GetVersionResult> {
        // BRC-100's vendor-1.0.0 shape (`wallet/0100.md:2517` at `5119a9b`),
        // 7 to 30 bytes as the reference's result check asks
        // (`WalletResultValidation.ts:2304-2306`, bsv-rs#222)
        Ok(GetVersionResult {
            version: concat!("bsv-rs-", env!("CARGO_PKG_VERSION")).to_string(),
        })
    }
}
