//! Bypass HTTP framing with constructed Responses to exercise the SDK
//! Content-Length guard itself, using the recorded fake-fetch vectors.

use super::read;
use crate::Error;

#[tokio::test]
async fn issue_416_declared_lengths_use_recorded_words_before_reading_the_body(
) -> Result<(), Box<dyn std::error::Error>> {
    let witness: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/auth_transport_bounds_416.json"
    )))?;
    let cases = witness["references"][0]["cases"]
        .as_array()
        .ok_or("recorded cases")?;
    let url = "https://transport-416.invalid/.well-known/auth";
    let mut checked = 0;
    for case in cases
        .iter()
        .filter(|case| case["content_length"].is_string())
    {
        let response = hyper::Response::builder()
            .header(
                "content-length",
                case["content_length"].as_str().ok_or("recorded length")?,
            )
            .body(Vec::<u8>::new())?;
        let error = case["error"]["message"]
            .as_str()
            .ok_or("recorded error")?
            .replace("{url}", "https://transport-416.invalid");
        assert_eq!(
            read(url, response.into(), 1024 * 1024, "unused").await,
            Err(Error::AuthError(error)),
            "{}",
            case["name"]
        );
        checked += 1;
    }
    assert_eq!(checked, 2);
    Ok(())
}
