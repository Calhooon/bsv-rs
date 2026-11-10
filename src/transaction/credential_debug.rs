//! The five service configurations that hold a bearer credential write a
//! redacting `Debug` (the secret Debug fold, 2026-11-10): every other field
//! as the derive printed it, the credential as present or absent, never its
//! value or its length, and the URL through `crate::util::debug_redact::Url`
//! (user info, a query and a fragment `<redacted>`; the second fold). A broadcaster, tracker or fee model holding one has
//! no `Debug` of its own. `tests/secret_debug.rs` pins each output.

#![allow(deprecated)] // ArcConfig, deprecated since 0.9.0 (#350), keeps its Debug

use std::fmt::{Debug, Formatter, Result};

use super::broadcasters::{ArcConfig, TeranodeConfig, WocBroadcastConfig};
use super::chain_trackers::BlockHeadersServiceConfig;
use super::fee_models::LivePolicyConfig;
use crate::util::debug_redact::{OptionUrl, Url};

/// A credential printed as `Some(<redacted>)` or `None`.
struct Credential<'a>(&'a Option<String>);

impl Debug for Credential<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(match self.0 {
            Some(_) => "Some(<redacted>)",
            None => "None",
        })
    }
}

impl Debug for ArcConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("ArcConfig")
            .field("url", &Url(&self.url))
            .field("api_key", &Credential(&self.api_key))
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

impl Debug for TeranodeConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("TeranodeConfig")
            .field("url", &Url(&self.url))
            .field("api_key", &Credential(&self.api_key))
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

impl Debug for WocBroadcastConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("WocBroadcastConfig")
            .field("network", &self.network)
            .field("api_key", &Credential(&self.api_key))
            .field("timeout_ms", &self.timeout_ms)
            .field("base_url", &OptionUrl(&self.base_url))
            .finish()
    }
}

impl Debug for LivePolicyConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("LivePolicyConfig")
            .field("policy_url", &Url(&self.policy_url))
            .field("api_key", &Credential(&self.api_key))
            .field("cache_ttl", &self.cache_ttl)
            .field("fallback_rate", &self.fallback_rate)
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

impl Debug for BlockHeadersServiceConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("BlockHeadersServiceConfig")
            .field("base_url", &Url(&self.base_url))
            .field("auth_token", &Credential(&self.auth_token))
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}
