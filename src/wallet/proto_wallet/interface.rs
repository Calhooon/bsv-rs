//! WalletInterface forwarding and unsupported operations for ProtoWallet.

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
use async_trait::async_trait;

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
        // Self is the prover's identity key, anyone `PrivateKey(1)`'s key, as
        // the reference names them (`ProtoWallet.ts:235-240`, bsv-rs#216)
        let counterparty_key = match args.counterparty {
            Counterparty::Self_ => self.identity_key(),
            Counterparty::Anyone => super::super::KeyDeriver::anyone_key().1,
            Counterparty::Other(ref pk) => pk.clone(),
        };

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
        Err(Error::WalletError(
            "createAction requires a full wallet implementation with UTXO management".to_string(),
        ))
    }

    async fn sign_action(
        &self,
        _args: SignActionArgs,
        _: Option<&str>,
    ) -> Result<SignActionResult> {
        Err(Error::WalletError(
            "signAction requires a full wallet implementation with UTXO management".to_string(),
        ))
    }

    async fn abort_action(
        &self,
        _args: AbortActionArgs,
        _: Option<&str>,
    ) -> Result<AbortActionResult> {
        Err(Error::WalletError(
            "abortAction requires a full wallet implementation with UTXO management".to_string(),
        ))
    }

    async fn list_actions(
        &self,
        _args: ListActionsArgs,
        _: Option<&str>,
    ) -> Result<ListActionsResult> {
        Err(Error::WalletError(
            "listActions requires a full wallet implementation with transaction history"
                .to_string(),
        ))
    }

    async fn internalize_action(
        &self,
        args: InternalizeActionArgs,
        _: Option<&str>,
    ) -> Result<InternalizeActionResult> {
        crate::wallet::validation::validate_internalize_action_args(&args)?;
        Err(Error::WalletError(
            "internalizeAction requires a full wallet implementation with UTXO management".into(),
        ))
    }

    // =========================================================================
    // Output Operations (NOT supported - require full wallet)
    // =========================================================================

    async fn list_outputs(
        &self,
        _args: ListOutputsArgs,
        _: Option<&str>,
    ) -> Result<ListOutputsResult> {
        Err(Error::WalletError(
            "listOutputs requires a full wallet implementation with UTXO management".to_string(),
        ))
    }

    async fn relinquish_output(
        &self,
        _args: RelinquishOutputArgs,
        _: Option<&str>,
    ) -> Result<RelinquishOutputResult> {
        Err(Error::WalletError(
            "relinquishOutput requires a full wallet implementation with UTXO management"
                .to_string(),
        ))
    }

    // =========================================================================
    // Certificate Operations (NOT supported - require full wallet)
    // =========================================================================

    async fn acquire_certificate(
        &self,
        _args: AcquireCertificateArgs,
        _: Option<&str>,
    ) -> Result<WalletCertificate> {
        Err(Error::WalletError(
            "acquireCertificate requires a full wallet implementation with certificate storage"
                .to_string(),
        ))
    }

    async fn list_certificates(
        &self,
        _args: ListCertificatesArgs,
        _: Option<&str>,
    ) -> Result<ListCertificatesResult> {
        Err(Error::WalletError(
            "listCertificates requires a full wallet implementation with certificate storage"
                .to_string(),
        ))
    }

    async fn prove_certificate(
        &self,
        _args: ProveCertificateArgs,
        _: Option<&str>,
    ) -> Result<ProveCertificateResult> {
        Err(Error::WalletError(
            "proveCertificate requires a full wallet implementation with certificate storage"
                .to_string(),
        ))
    }

    async fn relinquish_certificate(
        &self,
        _args: RelinquishCertificateArgs,
        _: Option<&str>,
    ) -> Result<RelinquishCertificateResult> {
        Err(Error::WalletError(
            "relinquishCertificate requires a full wallet implementation with certificate storage"
                .to_string(),
        ))
    }

    // =========================================================================
    // Discovery Operations (NOT supported - require full wallet)
    // =========================================================================

    async fn discover_by_identity_key(
        &self,
        _args: DiscoverByIdentityKeyArgs,
        _: Option<&str>,
    ) -> Result<DiscoverCertificatesResult> {
        Err(Error::WalletError(
            "discoverByIdentityKey requires a full wallet implementation with certificate discovery"
                .to_string(),
        ))
    }

    async fn discover_by_attributes(
        &self,
        _args: DiscoverByAttributesArgs,
        _: Option<&str>,
    ) -> Result<DiscoverCertificatesResult> {
        Err(Error::WalletError(
            "discoverByAttributes requires a full wallet implementation with certificate discovery"
                .to_string(),
        ))
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
        Err(Error::WalletError(
            "getHeaderForHeight requires a full wallet implementation with block header storage"
                .to_string(),
        ))
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
