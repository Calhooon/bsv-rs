//! AuthFetch.ts:572-674: request payload, header order and body defaults.

use super::{auth_fetch::AuthFetchOptions, response::words};
use crate::{primitives::Writer, Result};
use rand::RngCore;

pub(super) fn serialize(url: &url::Url, options: &AuthFetchOptions) -> Result<Vec<u8>> {
    let mut id = [0; 32];
    rand::thread_rng().fill_bytes(&mut id);
    let mut writer = Writer::new();
    writer.write_bytes(&id);
    let method = options.method.as_deref().unwrap_or("GET");
    writer.write_var_int(method.encode_utf16().count() as u64);
    writer.write_bytes(method.as_bytes());
    optional_text(&mut writer, url.path());
    let search = url
        .query()
        .filter(|s| !s.is_empty())
        .map(|s| format!("?{s}"));
    optional_text(&mut writer, search.as_deref().unwrap_or(""));
    let headers = included_headers(options)?;
    writer.write_var_int(headers.len() as u64);
    for (name, value) in &headers {
        writer.write_var_bytes(name.as_bytes());
        writer.write_var_bytes(value.as_bytes());
    }
    if let Some(body) = &options.body {
        writer.write_var_bytes(body);
    } else if ["POST", "PUT", "PATCH", "DELETE"].contains(&method.to_uppercase().as_str())
        && headers
            .iter()
            .any(|(key, value)| key == "content-type" && value.contains("application/json"))
    {
        writer.write_var_bytes(b"{}");
    } else {
        writer.write_var_int(u64::MAX);
    }
    Ok(writer.into_bytes())
}

fn optional_text(writer: &mut Writer, value: &str) {
    if value.is_empty() {
        writer.write_var_int(u64::MAX);
    } else {
        writer.write_var_bytes(value.as_bytes());
    }
}

fn included_headers(options: &AuthFetchOptions) -> Result<Vec<(String, String)>> {
    let mut headers = Vec::with_capacity(options.headers.len());
    for (key, value) in &options.headers {
        let key = key.to_lowercase();
        let value = if key.starts_with("x-bsv-") || key == "authorization" {
            if key.starts_with("x-bsv-auth") {
                return Err(words("No BSV auth headers allowed here!"));
            }
            value.clone()
        } else if key.starts_with("content-type") {
            super::labels::trim(value.split(';').next().unwrap_or("")).to_owned()
        } else {
            return Err(words("Unsupported header in the simplified fetch implementation. Only content-type, authorization, and x-bsv-* headers are supported."));
        };
        headers.push((key, value));
    }
    let mut names: Vec<_> = headers.iter().map(|(key, _)| key.as_str()).collect();
    crate::wallet::collation::sort_field_names(&mut names);
    let positions: std::collections::HashMap<_, _> =
        names.iter().enumerate().map(|(n, key)| (*key, n)).collect();
    let mut indices: Vec<_> = (0..headers.len()).collect();
    indices.sort_by_key(|i| positions[headers[*i].0.as_str()]);
    Ok(indices.into_iter().map(|i| headers[i].clone()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_uses_ecmascript_trim_423() -> Result<()> {
        for (value, expected) in [
            (
                "\u{feff}application/json\u{feff}; charset=utf-8",
                "application/json",
            ),
            (
                "\u{0085}text/plain\u{0085}; charset=utf-8",
                "\u{0085}text/plain\u{0085}",
            ),
        ] {
            let mut options = AuthFetchOptions::default();
            options.headers.insert("content-type".into(), value.into());
            assert_eq!(
                included_headers(&options)?,
                [("content-type".into(), expected.into())]
            );
        }
        Ok(())
    }
}
