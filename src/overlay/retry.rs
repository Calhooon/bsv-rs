//! Double-spend retry helper for overlay operations.
//!
//! Provides a generic async wrapper that retries operations when they fail
//! due to double-spend conflicts. This is useful for overlay broadcast
//! operations where a UTXO may have been spent by a concurrent transaction.

use crate::{Error, Result};
use std::future::Future;

/// Default maximum number of retry attempts.
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// Checks if an error message indicates a double-spend conflict.
fn is_double_spend_error(error: &Error) -> bool {
    let msg = error.to_string().to_lowercase();
    msg.contains("double spend")
        || msg.contains("double-spend")
        || msg.contains("txn-mempool-conflict")
        || msg.contains("already spent")
        || msg.contains("missing inputs")
}

/// Retries an async operation when it fails due to a double-spend conflict.
///
/// This is useful for overlay broadcast operations where UTXOs may be spent
/// concurrently. When a double-spend error is detected, the operation is
/// retried up to `max_retries` times.
///
/// # Arguments
///
/// * `max_retries` - Maximum number of retry attempts. Use `None` for the default (3).
/// * `operation` - An async closure that returns `Result<T>`. Called on each attempt.
///
/// # Returns
///
/// The result of the first successful attempt, or the last error if all retries fail.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::overlay::with_double_spend_retry;
///
/// let result = with_double_spend_retry(None, || async {
///     // Perform overlay broadcast operation
///     broadcaster.broadcast(&tx).await
/// }).await;
/// ```
pub async fn with_double_spend_retry<T, F, Fut>(
    max_retries: Option<u32>,
    mut operation: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let retries = max_retries.unwrap_or(DEFAULT_MAX_RETRIES);
    let mut last_error = None;

    for attempt in 0..=retries {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                if attempt < retries && is_double_spend_error(&e) {
                    last_error = Some(e);
                    continue;
                }
                return Err(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| Error::OverlayError("All retry attempts failed".to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_succeeds_first_try() {
        let result = with_double_spend_retry(None, || async { Ok::<_, Error>(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_retries_on_double_spend() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = with_double_spend_retry(Some(3), move || {
            let counter = counter_clone.clone();
            async move {
                let attempt = counter.fetch_add(1, Ordering::SeqCst);
                if attempt < 2 {
                    Err(Error::OverlayError("double spend detected".to_string()))
                } else {
                    Ok(42)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 3); // 0, 1, 2
    }

    #[tokio::test]
    async fn test_does_not_retry_non_double_spend() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = with_double_spend_retry(Some(3), move || {
            let counter = counter_clone.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err::<i32, _>(Error::OverlayError("some other error".to_string()))
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 1); // Only one attempt
    }

    #[tokio::test]
    async fn test_exhausts_retries() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = with_double_spend_retry(Some(2), move || {
            let counter = counter_clone.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err::<i32, _>(Error::OverlayError("txn-mempool-conflict".to_string()))
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 3); // Initial + 2 retries
    }

    #[tokio::test]
    async fn test_default_retries() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = with_double_spend_retry(None, move || {
            let counter = counter_clone.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err::<i32, _>(Error::OverlayError("already spent".to_string()))
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 4); // Initial + 3 retries (DEFAULT_MAX_RETRIES)
    }

    #[test]
    fn test_is_double_spend_error() {
        assert!(is_double_spend_error(&Error::OverlayError(
            "double spend detected".to_string()
        )));
        assert!(is_double_spend_error(&Error::OverlayError(
            "double-spend conflict".to_string()
        )));
        assert!(is_double_spend_error(&Error::OverlayError(
            "txn-mempool-conflict".to_string()
        )));
        assert!(is_double_spend_error(&Error::OverlayError(
            "input already spent".to_string()
        )));
        assert!(is_double_spend_error(&Error::OverlayError(
            "missing inputs".to_string()
        )));
        assert!(!is_double_spend_error(&Error::OverlayError(
            "network error".to_string()
        )));
        assert!(!is_double_spend_error(&Error::OverlayError(
            "timeout".to_string()
        )));
    }
}
