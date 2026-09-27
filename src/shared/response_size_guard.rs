//! Streaming, memory-bounded HTTP response body reader.
//!
//! Intended for outbound network adapters (`src/adapters/outbound/network/`)
//! that need to reject oversized API responses before allocating memory for
//! them. The domain layer must never call this directly.
//!
//! [`read_bounded_bytes`] reads the response body via [`reqwest::Response::bytes_stream`]
//! rather than [`reqwest::Response::bytes`], checking the running total against
//! `limit` before each chunk is appended to the buffer. This means the buffer
//! itself never grows past `limit` bytes, even when the server sends no
//! `Content-Length` header (or lies about a smaller one) — unlike a
//! buffer-then-check approach, which downloads the entire body first and can
//! only reject it afterwards. A `content_length()` pre-check is retained as a
//! fast path: an honest, oversized `Content-Length` is rejected without
//! opening the body stream at all. As a side effect, this also bounds memory
//! correctly for a compressed response, since the streamed total reflects the
//! decompressed byte count rather than the (smaller) wire size.
//!
//! HTTP status validation is the caller's responsibility — this function only
//! concerns itself with body size.
//!
//! No network client currently calls this function; each of the four outbound
//! adapters that need it (`OsvClient`, `PyPiLicenseRepository`,
//! `PyPiMaintenanceRepository`, `PyPiCompatibilityClient`) still carries its
//! own inline two-stage guard. Migrating them is tracked by Issue #853's
//! follow-up subtasks.

use crate::shared::Result;
use futures::stream::StreamExt;

/// Reads a response body, rejecting it once its size exceeds `limit`.
///
/// `context`, when set, identifies the resource being fetched (e.g. a
/// vulnerability ID or package name) so a rejection can be traced back to it.
/// Callers should include their own API name in `context` if it matters for
/// the resulting error message (e.g. `"OSV vulnerability CVE-2024-0001"`
/// rather than just `"CVE-2024-0001"`), since this function's own error text
/// is deliberately generic.
///
/// # Errors
/// Returns an error if:
/// - The response's `Content-Length` header, when present, exceeds `limit`
/// - The response body, once fully read, exceeds `limit` bytes (checked
///   incrementally, so the buffer itself never grows past `limit`)
/// - The underlying stream read fails (network error)
#[allow(dead_code)] // WIRE(#859): remove when OsvClient is migrated to call this function
pub async fn read_bounded_bytes(
    response: reqwest::Response,
    limit: usize,
    context: Option<&str>,
) -> Result<Vec<u8>> {
    // Fast path: reject before opening the body stream at all.
    if let Some(len) = response
        .content_length()
        .filter(|&len| len as usize > limit)
    {
        return Err(too_large_error(len, limit, context));
    }

    // Slow path: stream the body, aborting as soon as the running total
    // exceeds `limit`. The check happens before extending the buffer, so it
    // never holds more than `limit` bytes. `bytes_stream()`'s `impl Stream`
    // is not guaranteed `Unpin`, so it must be pinned before `.next()` (which
    // requires `Self: Unpin`) can be called on it.
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = std::pin::pin!(response.bytes_stream());
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if buf.len().saturating_add(chunk.len()) > limit {
            return Err(exceeded_error(limit, context));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[allow(dead_code)] // WIRE(#859): remove when OsvClient is migrated to call this function
fn too_large_error(actual: u64, limit: usize, context: Option<&str>) -> anyhow::Error {
    match context {
        Some(ctx) => anyhow::anyhow!(
            "HTTP response too large for {}: {} bytes (limit: {} bytes)",
            ctx,
            actual,
            limit
        ),
        None => anyhow::anyhow!(
            "HTTP response too large: {} bytes (limit: {} bytes)",
            actual,
            limit
        ),
    }
}

#[allow(dead_code)] // WIRE(#859): remove when OsvClient is migrated to call this function
fn exceeded_error(limit: usize, context: Option<&str>) -> anyhow::Error {
    match context {
        Some(ctx) => anyhow::anyhow!("HTTP response for {} exceeded {} byte limit", ctx, limit),
        None => anyhow::anyhow!("HTTP response exceeded {} byte limit", limit),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_LIMIT: usize = 4 * 1024;

    async fn get(url: &str) -> reqwest::Response {
        reqwest::Client::new().get(url).send().await.unwrap()
    }

    #[tokio::test]
    async fn test_rejects_oversized_response_via_content_length_precheck() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(vec![b'x'; TEST_LIMIT + 1], "application/octet-stream"),
            )
            .mount(&mock_server)
            .await;

        let response = get(&mock_server.uri()).await;
        let err = read_bounded_bytes(response, TEST_LIMIT, None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("too large"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_accepts_response_at_exactly_the_limit() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(vec![b'x'; TEST_LIMIT], "application/octet-stream"),
            )
            .mount(&mock_server)
            .await;

        let response = get(&mock_server.uri()).await;
        let bytes = read_bounded_bytes(response, TEST_LIMIT, None)
            .await
            .unwrap();
        assert_eq!(bytes.len(), TEST_LIMIT);
    }

    #[tokio::test]
    async fn test_returns_body_bytes_unchanged() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(b"hello world".to_vec(), "application/octet-stream"),
            )
            .mount(&mock_server)
            .await;

        let response = get(&mock_server.uri()).await;
        let bytes = read_bounded_bytes(response, TEST_LIMIT, None)
            .await
            .unwrap();
        assert_eq!(bytes, b"hello world");
    }

    #[tokio::test]
    async fn test_context_is_included_in_error_message() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(vec![b'x'; TEST_LIMIT + 1], "application/octet-stream"),
            )
            .mount(&mock_server)
            .await;

        let response = get(&mock_server.uri()).await;
        let err = read_bounded_bytes(response, TEST_LIMIT, Some("numpy"))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("numpy"), "unexpected error: {msg}");
        assert!(msg.contains("too large"), "unexpected error: {msg}");
    }

    /// Serves exactly one HTTP/1.1 chunked response with NO `Content-Length`,
    /// so `Response::content_length()` is `None` and only the streaming loop
    /// can bound the read. wiremock cannot express this: its bodies are
    /// always backed by a known-length buffer, so the underlying hyper
    /// server always emits an accurate `Content-Length`.
    ///
    /// When `terminate` is `false`, the server writes `body_len` bytes and
    /// then parks forever WITHOUT sending the terminating `0\r\n\r\n` chunk —
    /// a reader that buffers the whole body before checking its size would
    /// hang indefinitely, so the caller must wrap the read in a timeout for
    /// this case to prove the size check aborts mid-stream rather than after
    /// a hang.
    fn spawn_chunked_server(chunk_size: usize, body_len: usize, terminate: bool) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf); // drain the (small) request head
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: application/octet-stream\r\n\
                  Transfer-Encoding: chunked\r\n\r\n",
            );
            let chunk = vec![b'x'; chunk_size];
            let mut written = 0usize;
            while written < body_len {
                let this_chunk_len = chunk_size.min(body_len - written);
                let _ = write!(stream, "{:x}\r\n", this_chunk_len);
                let _ = stream.write_all(&chunk[..this_chunk_len]);
                let _ = stream.write_all(b"\r\n");
                written += this_chunk_len;
            }
            if terminate {
                let _ = stream.write_all(b"0\r\n\r\n");
                let _ = stream.flush();
            } else {
                // Deliberately never send the terminating chunk: park this
                // thread forever so a buffer-then-check reader would hang.
                loop {
                    std::thread::park();
                }
            }
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn test_rejects_oversized_chunked_response_while_streaming() {
        // No Content-Length -> the pre-check cannot fire. The server never
        // sends its terminating chunk, so a buffer-then-check implementation
        // would hang here instead of failing fast; wrapping in a timeout
        // turns that hang into a clear test failure rather than a stuck CI
        // job, while proving the streaming implementation returns promptly.
        let base = spawn_chunked_server(1024, TEST_LIMIT + 4096, false);
        let response = get(&base).await;

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_bounded_bytes(response, TEST_LIMIT, None),
        )
        .await
        .expect("read_bounded_bytes hung instead of aborting mid-stream");

        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exceeded"), "unexpected error: {msg}");
        assert!(
            !msg.contains("too large"),
            "expected the streaming check (not the Content-Length pre-check) to fire: {msg}"
        );
    }

    #[tokio::test]
    async fn test_accepts_chunked_response_under_limit() {
        let base = spawn_chunked_server(1024, 2048, true);
        let response = get(&base).await;

        let bytes = read_bounded_bytes(response, TEST_LIMIT, None)
            .await
            .unwrap();
        assert_eq!(bytes.len(), 2048);
    }
}
