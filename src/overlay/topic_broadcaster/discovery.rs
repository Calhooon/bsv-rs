//! The SHIP discovery's admission and the endpoint's origin, as the
//! reference's `#fetchInterestedHosts` and `shipEndpoint` read them
//! (`ts-stack@edf6e03` `packages/sdk/src/overlay-tools/SHIPBroadcaster.ts:97-127`,
//! `:725-789`; #804, the SHIP twin of #786).

use crate::overlay::{
    overlay_admin_token_template::decode_and_verify_overlay_admin_token,
    types::{LookupAnswer, OutputListItem, Protocol},
};
use crate::transaction::Transaction;
use crate::{Error, Result};
use std::collections::{HashMap, HashSet};

/// `MAX_SHIP_HOSTS` (`:97`): the hosts a discovery admits, and the
/// specific-host requirements a broadcaster takes (`:204-206`).
pub(super) const MAX_SHIP_HOSTS: usize = 32;
/// `MAX_SHIP_ADVERTISEMENTS` (`:98`): the outputs an answer may carry.
pub(super) const MAX_SHIP_ADVERTISEMENTS: usize = 256;
/// `MAX_SHIP_ADVERTISEMENT_BEEF_BYTES` (`:99`): one output's BEEF.
pub(super) const MAX_SHIP_ADVERTISEMENT_BEEF_BYTES: usize = 16 * 1024 * 1024;
/// `MAX_SHIP_TOTAL_ADVERTISEMENT_BEEF_BYTES` (`:100`): the answer's BEEF.
pub(super) const MAX_SHIP_TOTAL_ADVERTISEMENT_BEEF_BYTES: usize = 64 * 1024 * 1024;

fn refused(words: &str) -> Error {
    Error::OverlayError(words.to_string())
}

/// `shipEndpoint(base, allowHTTP).origin` (`:103-127`): `base` read as a
/// WHATWG URL, refused unless `https:` (or `http:` when allowed), without
/// a username, a password, a query, a fragment or a path other than `/`,
/// in the reference's words; the origin its ASCII serialization (the host
/// lower-cased and in punycode, a default port dropped, no trailing slash).
pub(crate) fn ship_origin(base: &str, allow_http: bool) -> Result<String> {
    let url =
        url::Url::parse(base).map_err(|_| refused("Overlay host must be a valid absolute URL."))?;
    // JavaScript's `search`, `hash` and `password` are `''` for an empty
    // query, fragment or password; only a non-empty one is refused.
    let empty = |part: Option<&str>| part.is_none_or(str::is_empty);
    let scheme = url.scheme() == "https" || (allow_http && url.scheme() == "http");
    if !scheme
        || !url.username().is_empty()
        || !empty(url.password())
        || !empty(url.query())
        || !empty(url.fragment())
        || !(url.path().is_empty() || url.path() == "/")
    {
        return Err(refused(if allow_http {
            "Overlay host must be a credential-free HTTP(S) origin."
        } else {
            "HTTPS facilitator can only use URLs that start with \"https:\" and contain a credential-free origin."
        }));
    }
    Ok(url.origin().ascii_serialization())
}

/// The reference's `/^[0-9a-fA-F]{64}$/` (`:762`).
fn txid_hex(hint: &str) -> bool {
    hint.len() == 64 && hint.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The hosts an `ls_ship` answer admits for `topics`, in the reference's
/// order (`:737-786`): the answer an output list of at most 256 outputs,
/// else `SHIP answer is not a bounded output list.` before any output is
/// read; per output, an empty BEEF, one over 16 MiB or a hint not 64 hex
/// digits skipped before it counts (`:752-764`; the index is a `u32` by
/// type); its BEEF's length added to the total, and over 64 MiB this output
/// and, the total staying over, every later one skipped (`:765-768`: the
/// throw is inside the loop's `try`, swallowed at `:783`); then
/// [`admitted`]; the loop broken once 32 hosts are held (`:782`).
pub(super) fn interested_hosts(
    topics: &[String],
    answer: LookupAnswer,
) -> Result<HashMap<String, HashSet<String>>> {
    let outputs = match answer {
        LookupAnswer::OutputList { outputs } if outputs.len() <= MAX_SHIP_ADVERTISEMENTS => outputs,
        _ => return Err(refused("SHIP answer is not a bounded output list.")),
    };
    let mut results: HashMap<String, HashSet<String>> = HashMap::new();
    let mut total_beef_bytes: usize = 0;
    for output in &outputs {
        if output.beef.is_empty()
            || output.beef.len() > MAX_SHIP_ADVERTISEMENT_BEEF_BYTES
            || output.txid.as_deref().is_some_and(|hint| !txid_hex(hint))
        {
            continue;
        }
        total_beef_bytes = total_beef_bytes.saturating_add(output.beef.len());
        if total_beef_bytes > MAX_SHIP_TOTAL_ADVERTISEMENT_BEEF_BYTES {
            continue;
        }
        if let Some((host, topic)) = admitted(topics, output) {
            results.entry(host).or_default().insert(topic);
            if results.len() >= MAX_SHIP_HOSTS {
                break;
            }
        }
    }
    Ok(results)
}

/// One output's host and topic (`:769-781`), or `None` for the reference's
/// `continue` (and its `catch`): the BEEF's subject; a hint that,
/// lower-cased, is not its txid; the output at the index, exactly 1
/// satoshi; the token authenticated as SHIP (#544); a topic of ours; the
/// host the advertised domain's endpoint origin, `http:` never allowed.
fn admitted(topics: &[String], output: &OutputListItem) -> Option<(String, String)> {
    let tx = Transaction::from_beef(&output.beef, None).ok()?;
    if let Some(hint) = &output.txid {
        if hint.to_ascii_lowercase() != tx.id() {
            return None;
        }
    }
    let selected = tx.outputs.get(output.output_index as usize)?;
    if selected.satoshis != Some(1) {
        return None;
    }
    let token =
        decode_and_verify_overlay_admin_token(&selected.locking_script, Some(Protocol::Ship))
            .ok()?;
    if !topics.contains(&token.topic_or_service) {
        return None;
    }
    let host = ship_origin(&token.domain, false).ok()?;
    Some((host, token.topic_or_service))
}

/// `snapshotSpecificHostRequirements`' keys (`:195-219`): more than 32
/// refused before any is read, each key its endpoint's origin under the
/// preset's `allowHTTP`, a second key of one origin refused, in the
/// reference's words. The requirement values are taken as given.
pub(super) fn specific_hosts<T>(
    requirements: HashMap<String, T>,
    allow_http: bool,
) -> Result<HashMap<String, T>> {
    if requirements.len() > MAX_SHIP_HOSTS {
        return Err(refused(
            "Specific-host acknowledgment requirements contain too many hosts.",
        ));
    }
    let mut result = HashMap::with_capacity(requirements.len());
    for (host, requirement) in requirements {
        let origin = ship_origin(&host, allow_http)?;
        if result.contains_key(&origin) {
            return Err(refused(
                "Specific-host acknowledgment requirements contain a duplicate host.",
            ));
        }
        result.insert(origin, requirement);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_origin_is_the_whatwg_origin_804() {
        assert_eq!(
            ship_origin("https://Host.Example:443/", false).unwrap(),
            "https://host.example"
        );
        assert_eq!(
            ship_origin("https://host.example:8443", false).unwrap(),
            "https://host.example:8443"
        );
        // An empty query and fragment are no query and fragment there.
        assert_eq!(
            ship_origin("https://host.example/?#", false).unwrap(),
            "https://host.example"
        );
        assert_eq!(
            ship_origin("http://localhost:8080", true).unwrap(),
            "http://localhost:8080"
        );
    }

    #[test]
    fn the_endpoint_refusals_are_the_references_words_804() {
        let https = "HTTPS facilitator can only use URLs that start with \"https:\" and contain a credential-free origin.";
        for base in [
            "http://host.example",
            "wss://host.example",
            "https+bsvauth://host.example",
            "https://user@host.example",
            "https://:pw@host.example",
            "https://host.example/path",
            "https://host.example/?q",
            "https://host.example/#f",
        ] {
            assert_eq!(
                ship_origin(base, false),
                Err(Error::OverlayError(https.into())),
                "{base}"
            );
        }
        assert_eq!(
            ship_origin("wss://host.example", true),
            Err(Error::OverlayError(
                "Overlay host must be a credential-free HTTP(S) origin.".into()
            ))
        );
        assert_eq!(
            ship_origin("host.example", false),
            Err(Error::OverlayError(
                "Overlay host must be a valid absolute URL.".into()
            ))
        );
    }
}
