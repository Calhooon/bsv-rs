//! Discovery response validation at WalletWireTransceiver.ts:1796,1842 (#495).
//! Decode once, then apply the shared certificate and request-binding rows.

use super::result_validation::Binding;
use super::{WalletCall, WalletWire, WalletWireTransceiver, WireReader, WireWriter};
use crate::primitives::{bounded_capacity, from_hex};
use crate::wallet::{
    DiscoverByAttributesArgs, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult,
};
use crate::Error;

impl<T: WalletWire> WalletWireTransceiver<T> {
    /// Discovers certificates by identity key.
    pub async fn discover_by_identity_key(
        &self,
        args: DiscoverByIdentityKeyArgs,
        originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, Error> {
        let binding = Binding::new("discoverByIdentityKey", &args)?;
        let mut writer = WireWriter::new();

        // Identity key
        let key_bytes = from_hex(&args.identity_key)?;
        writer.write_bytes(&key_bytes);

        writer.write_optional_var_int(args.limit.map(|v| v as u64));
        writer.write_optional_var_int(args.offset.map(|v| v as u64));
        writer.write_optional_bool(args.seek_permission);

        let response = self
            .transmit(
                WalletCall::DiscoverByIdentityKey,
                originator,
                writer.as_bytes(),
            )
            .await?;

        binding.check(parse_discovery_result(&response, args.limit)?)
    }

    /// Discovers certificates by attributes.
    pub async fn discover_by_attributes(
        &self,
        args: DiscoverByAttributesArgs,
        originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, Error> {
        let binding = Binding::new("discoverByAttributes", &args)?;
        let mut writer = WireWriter::new();

        // Attributes
        writer.write_var_int(args.attributes.len() as u64);
        for (key, value) in &args.attributes {
            writer.write_string(key);
            writer.write_string(value);
        }

        writer.write_optional_var_int(args.limit.map(|v| v as u64));
        writer.write_optional_var_int(args.offset.map(|v| v as u64));
        writer.write_optional_bool(args.seek_permission);

        let response = self
            .transmit(
                WalletCall::DiscoverByAttributes,
                originator,
                writer.as_bytes(),
            )
            .await?;

        binding.check(parse_discovery_result(&response, args.limit)?)
    }
}

/// Parses a discovery result: the total of every page, then this page's
/// entries to the end of the frame, no more than `requested_limit` (10
/// when none) nor the total (`#parseDiscoveryResult`,
/// `WalletWireTransceiver.ts:1652-1764`; bsv-rs#190).
fn parse_discovery_result(
    data: &[u8],
    requested_limit: Option<u32>,
) -> Result<DiscoverCertificatesResult, Error> {
    let mut reader = WireReader::new(data);

    let total_certificates = reader.read_var_int_u32("discovery totalCertificates")?;
    let mut certificates = Vec::with_capacity(bounded_capacity(
        total_certificates as usize,
        reader.remaining(),
        1,
    ));

    while !reader.is_empty() {
        super::require_page_capacity(certificates.len(), requested_limit, "discover")?;
        let cert_len = reader.read_length()?;
        let cert_bytes = reader.read_bytes(cert_len)?;
        let certificate = WireReader::new(cert_bytes).read_wallet_certificate()?;

        // Certifier info: three plain strings, an empty one length 0
        // (`#serializeDiscoveryResult`, `WalletWireProcessor.ts:2507-2518`),
        // the trust 1 to 10 (`WalletWireTransceiver.ts:1710`; #183, #247)
        let certifier_info = reader.read_identity_certifier()?;

        // The maps: strict counts, record keys (`WalletWireTransceiver.ts:1711-1752`)
        let (publicly_revealed_keyring, decrypted_fields) = reader.read_discovery_maps()?;

        certificates.push(crate::wallet::IdentityCertificate {
            certificate,
            certifier_info,
            publicly_revealed_keyring,
            decrypted_fields,
        });
    }
    super::assert_page_count(certificates.len(), total_certificates, "discover")?;

    Ok(DiscoverCertificatesResult {
        total_certificates,
        certificates,
    })
}
