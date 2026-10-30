//! BRC-105 action, payment reuse and bounded retries (AuthFetch.ts:711-969).

use super::{
    auth_fetch::{AuthFetch, AuthFetchOptions},
    response::words,
    retry::RetryBudget,
    state::wait,
    Response,
};
use crate::auth::{utils::create_nonce, Transport};
use crate::wallet::{
    Counterparty, CreateActionArgs, CreateActionOptions, CreateActionOutput, GetPublicKeyArgs,
    Protocol, SecurityLevel, WalletInterface,
};
use crate::{
    primitives::{to_base64, PublicKey},
    Result,
};
use serde::Serialize;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// Parses the optional `x-bsv-payment-known-txids` SDK extension.
/// Malformed IDs are dropped; valid IDs are lowercased, deduplicated in first
/// appearance order, and capped at 256. An empty result is absent, as in TS.
pub fn parse_known_txids_header(value: Option<&str>) -> Option<Vec<String>> {
    let mut seen = HashSet::new();
    let ids: Vec<_> = value?
        .split(',')
        .map(super::labels::trim)
        .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
        .filter(|id| seen.insert(id.clone()))
        .take(256)
        .collect();
    if ids.is_empty() {
        None
    } else {
        Some(ids)
    }
}

#[derive(Clone)]
pub(super) struct PaymentContext(Arc<Mutex<PaymentData>>);

#[derive(Clone)]
struct PaymentData {
    satoshis: u64,
    server: String,
    prefix: String,
    suffix: String,
    transaction: String,
    attempts: u32,
    maximum: u32,
}

impl PaymentContext {
    fn snapshot(&self) -> PaymentData {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    fn increment(&self) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .attempts += 1;
    }
}

impl<W: WalletInterface + 'static, T: Transport + 'static> AuthFetch<W, T> {
    pub(super) async fn pay_and_retry(
        &self,
        url: &str,
        mut options: AuthFetchOptions,
        response: Response,
        context: Option<PaymentContext>,
        retry: RetryBudget,
    ) -> Result<Response> {
        let (satoshis, server, prefix) = requirements(&response)?;
        let compatible = context.as_ref().is_some_and(|c| {
            let c = c.snapshot();
            c.satoshis == satoshis && c.server == server && c.prefix == prefix
        });
        let context = if compatible {
            context
        } else {
            Some(
                self.create_payment(url, &options, &response, satoshis, server, prefix)
                    .await?,
            )
        }
        .ok_or_else(|| words("Maximum payment attempts exceeded before retrying"))?;
        loop {
            let payment = context.snapshot();
            if payment.attempts >= payment.maximum {
                return Err(failed(url, &payment));
            }
            let header = PaymentHeader {
                derivation_prefix: &payment.prefix,
                derivation_suffix: &payment.suffix,
                transaction: &payment.transaction,
            };
            let header =
                serde_json::to_string(&header).map_err(|error| words(&error.to_string()))?;
            options.headers.insert("x-bsv-payment".into(), header);
            retry.initialize();
            context.increment();
            if let Ok(response) = Box::pin(self.fetch_inner(
                url,
                options.clone(),
                Some(context.clone()),
                retry.clone(),
            ))
            .await
            {
                return Ok(response);
            } else {
                let current = context.snapshot();
                if current.attempts >= current.maximum {
                    return Err(failed(url, &current));
                }
                wait(250 * u64::from(current.attempts.min(5))).await;
            }
        }
    }

    async fn create_payment(
        &self,
        url: &str,
        options: &AuthFetchOptions,
        response: &Response,
        satoshis: u64,
        server: &str,
        prefix: &str,
    ) -> Result<PaymentContext> {
        let suffix = create_nonce(self.wallet.as_ref(), None, self.originator.as_deref()).await?;
        let output = self
            .payment_output(satoshis, server, prefix, &suffix)
            .await?;
        let args = payment_action_args(url, options, response, prefix, &suffix, output)?;
        let action = self
            .wallet
            .create_action(args, self.originator.as_deref())
            .await?;
        let transaction = action
            .tx
            .filter(|tx| !tx.is_empty() && tx.len() <= 16 * 1024 * 1024)
            .ok_or_else(|| {
                words(
            "BRC-105 payment transaction must be a dense byte array of at most 16777216 bytes.")
            })?;
        // The reference also obtains the client identity after creating the action.
        self.wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    ..Default::default()
                },
                self.originator.as_deref(),
            )
            .await?;
        Ok(PaymentContext(Arc::new(Mutex::new(PaymentData {
            satoshis,
            server: server.into(),
            prefix: prefix.into(),
            suffix,
            transaction: to_base64(&transaction),
            attempts: 0,
            maximum: options
                .payment_retry_attempts
                .filter(|n| *n > 0)
                .unwrap_or(3),
        }))))
    }
    async fn payment_output(
        &self,
        satoshis: u64,
        server: &str,
        prefix: &str,
        suffix: &str,
    ) -> Result<CreateActionOutput> {
        let key = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    protocol_id: Some(Protocol::new(SecurityLevel::Counterparty, "3241645161d8")),
                    key_id: Some(format!("{prefix} {suffix}")),
                    counterparty: Some(Counterparty::Other(PublicKey::from_hex(server)?)),
                    ..Default::default()
                },
                self.originator.as_deref(),
            )
            .await?;
        let public_key = PublicKey::from_hex(&key.public_key)?;
        let locking_script =
            crate::script::templates::P2PKH::lock_from_address(&public_key.to_address())?;
        let instructions = serde_json::to_string(&PaymentInstructions {
            derivation_prefix: prefix,
            derivation_suffix: suffix,
            payee: server,
        })
        .map_err(|error| words(&error.to_string()))?;
        Ok(CreateActionOutput {
            satoshis,
            locking_script: locking_script.to_binary(),
            custom_instructions: Some(instructions),
            output_description: "HTTP request payment".into(),
            basket: None,
            tags: None,
        })
    }
}

fn payment_action_args(
    url: &str,
    options: &AuthFetchOptions,
    response: &Response,
    prefix: &str,
    suffix: &str,
    output: CreateActionOutput,
) -> Result<CreateActionArgs> {
    let labels = options.payment_labels(prefix, suffix)?;
    let known_txids = parse_known_txids_header(response.header("x-bsv-payment-known-txids"))
        .map(|ids| {
            ids.into_iter()
                .map(|id| {
                    let bytes = hex::decode(id).map_err(|error| words(&error.to_string()))?;
                    bytes
                        .try_into()
                        .map_err(|_| words("Invalid transaction ID"))
                })
                .collect::<Result<Vec<[u8; 32]>>>()
        })
        .transpose()?;
    Ok(CreateActionArgs {
        description: format!("Payment for request to {}", origin(url)),
        labels: Some(labels),
        outputs: Some(vec![output]),
        options: Some(CreateActionOptions {
            randomize_outputs: Some(false),
            known_txids,
            ..Default::default()
        }),
        input_beef: None,
        inputs: None,
        lock_time: None,
        version: None,
    })
}

fn requirements(response: &Response) -> Result<(u64, &str, &str)> {
    let version = response.header("x-bsv-payment-version");
    if version != Some("1.0") {
        return Err(words(&format!("Unsupported x-bsv-payment-version response header. Client version: 1.0, Server version: {}", version.unwrap_or("null"))));
    }
    let amount = response
        .header("x-bsv-payment-satoshis-required")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| words("Missing x-bsv-payment-satoshis-required response header."))?;
    let satoshis = amount
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0 && *n < (1 << 53))
        .filter(|_| !amount.starts_with('0') && amount.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| words("Invalid x-bsv-payment-satoshis-required response header value."))?;
    let server = response
        .header("x-bsv-auth-identity-key")
        .ok_or_else(|| words("Missing x-bsv-auth-identity-key response header."))?;
    let prefix = response
        .header("x-bsv-payment-derivation-prefix")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| words("Missing x-bsv-payment-derivation-prefix response header."))?;
    Ok((satoshis, server, prefix))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PaymentHeader<'a> {
    derivation_prefix: &'a str,
    derivation_suffix: &'a str,
    transaction: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PaymentInstructions<'a> {
    derivation_prefix: &'a str,
    derivation_suffix: &'a str,
    payee: &'a str,
}

fn origin(url: &str) -> String {
    url::Url::parse(url).map_or_else(
        |_| "[invalid URL]".into(),
        |url| url.origin().ascii_serialization(),
    )
}

fn failed(url: &str, payment: &PaymentData) -> crate::Error {
    words(&format!(
        "Paid request to {} failed after {}/{} attempts. Sent {} satoshis to {}.",
        origin(url),
        payment.attempts,
        payment.maximum,
        payment.satoshis,
        payment.server
    ))
}
