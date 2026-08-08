use crate::shared::Result;

/// Retries an async operation with linear backoff (100ms * attempt number).
///
/// Calls `f` up to `max_retries` times, waiting between attempts. Returns the
/// first successful result, or the last error if every attempt fails.
///
/// # Errors
/// Returns the error from the final attempt if `f` fails on every call.
///
/// # Panics
/// Panics if `max_retries` is 0 (no attempt is ever made, so there is no error
/// to return). All current call sites pass a positive retry count.
pub async fn fetch_with_retry<F, Fut, T>(max_retries: u32, mut f: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last_error = None;

    for attempt in 1..=max_retries {
        match f().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);
                if attempt < max_retries {
                    tokio::time::sleep(std::time::Duration::from_millis(100 * attempt as u64))
                        .await;
                }
            }
        }
    }

    Err(last_error.unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn test_fetch_with_retry_succeeds_first_attempt() {
        let attempts = AtomicUsize::new(0);
        let result = fetch_with_retry(3, || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async { Ok::<_, anyhow::Error>(42) }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_fetch_with_retry_succeeds_after_failures() {
        let attempts = AtomicUsize::new(0);
        let result = fetch_with_retry(3, || {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                if attempt < 3 {
                    Err(anyhow::anyhow!("transient failure on attempt {}", attempt))
                } else {
                    Ok(99)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 99);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_fetch_with_retry_exhausts_and_returns_last_error() {
        let attempts = AtomicUsize::new(0);
        let result: Result<()> = fetch_with_retry(3, || {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
            async move { Err(anyhow::anyhow!("failure {}", attempt)) }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "failure 3");
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }
}
