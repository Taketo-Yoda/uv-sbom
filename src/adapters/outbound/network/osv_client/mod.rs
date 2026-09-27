mod cvss;
mod dto;

use crate::i18n::{Locale, Messages};
use crate::ports::outbound::{ProgressCallback, VulnerabilityRepository};
use crate::sbom_generation::domain::vulnerability::{
    PackageVulnerabilities, Severity, Vulnerability,
};
use crate::sbom_generation::domain::Package;
use crate::shared::response_size_guard;
use crate::shared::Result;
use async_trait::async_trait;
use cvss::{parse_cvss_score, parse_severity_string};
use dto::{OsvBatchQuery, OsvBatchResponse, OsvPackage, OsvQuery, OsvResult, OsvVulnerability};
use reqwest::Client;
use std::time::Duration;

/// OSV API client for fetching vulnerability data
///
/// Uses the OSV.dev Batch Query API to efficiently check multiple packages.
/// Implements async operations for parallel vulnerability fetching.
///
/// # Security
/// - Implements rate limiting (10 req/sec) using tokio::time::sleep
/// - Implements timeout (30 seconds)
/// - Does not retry failed requests (fail fast for CVE checks)
#[derive(Clone)]
pub struct OsvClient {
    client: Client,
    base_url: String,
    /// Locale for localizing the per-vulnerability detail-fetch soft-fail warning
    /// (see `fetch_vulnerabilities_with_progress`). Held directly on the adapter
    /// rather than threaded through an application-layer error-return channel,
    /// matching the precedent in `FileSystemWriter`
    /// (`src/adapters/outbound/filesystem/file_writer.rs`), which also holds a
    /// `Locale` and formats/prints a localized message itself.
    locale: Locale,
}

impl OsvClient {
    const API_BASE_URL: &'static str = "https://api.osv.dev";
    const TIMEOUT_SECONDS: u64 = 30;
    const RATE_LIMIT_MS: u64 = 100; // 10 req/sec
    const MAX_BATCH_SIZE: usize = 100; // OSV API limit
    const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024; // 10 MB — well above any realistic OSV API response

    /// Creates a new OSV API client with default configuration
    pub fn new(locale: Locale) -> Result<Self> {
        Self::build(Self::API_BASE_URL.to_string(), locale)
    }

    /// Creates a client pointed at a custom base URL (e.g. a wiremock server),
    /// for tests only.
    #[cfg(test)]
    fn new_with_base_url(base_url: impl Into<String>, locale: Locale) -> Result<Self> {
        Self::build(base_url.into(), locale)
    }

    /// Shared constructor logic for [`Self::new`] and [`Self::new_with_base_url`].
    fn build(base_url: String, locale: Locale) -> Result<Self> {
        let version = env!("CARGO_PKG_VERSION");
        let user_agent = format!("uv-sbom/{}", version);
        let client = Client::builder()
            .timeout(Duration::from_secs(Self::TIMEOUT_SECONDS))
            .user_agent(user_agent)
            .build()?;

        Ok(Self {
            client,
            base_url,
            locale,
        })
    }

    /// Fetches vulnerabilities for a batch of packages (async)
    async fn fetch_batch(&self, packages: &[Package]) -> Result<Vec<OsvResult>> {
        // Build batch query
        let queries: Vec<OsvQuery> = packages
            .iter()
            .map(|pkg| OsvQuery {
                package: OsvPackage {
                    name: pkg.name().to_string(),
                    ecosystem: "PyPI".to_string(),
                },
                version: pkg.version().to_string(),
            })
            .collect();

        let batch_query = OsvBatchQuery { queries };

        // Send async request
        let url = format!("{}/v1/querybatch", self.base_url);
        let response = self.client.post(&url).json(&batch_query).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("OSV API returned status code {}", response.status());
        }

        let bytes = response_size_guard::read_bounded_bytes(
            response,
            Self::MAX_RESPONSE_BYTES,
            Some("OSV batch query"),
        )
        .await?;
        let batch_response: OsvBatchResponse = serde_json::from_slice(&bytes)?;
        Ok(batch_response.results)
    }

    /// Fetches detailed vulnerability information by ID (async)
    ///
    /// The batch API returns minimal information. To get severity and other details,
    /// we need to query each vulnerability individually.
    async fn fetch_vulnerability_details(&self, vuln_id: &str) -> Result<OsvVulnerability> {
        let url = format!("{}/v1/vulns/{}", self.base_url, vuln_id);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            anyhow::bail!(
                "OSV API returned status code {} for vulnerability {}",
                response.status(),
                vuln_id
            );
        }

        let bytes = response_size_guard::read_bounded_bytes(
            response,
            Self::MAX_RESPONSE_BYTES,
            Some(&format!("OSV vulnerability {}", vuln_id)),
        )
        .await?;
        let vuln: OsvVulnerability = serde_json::from_slice(&bytes)?;
        Ok(vuln)
    }

    /// Converts a single OSV vulnerability to domain model
    fn convert_to_vulnerability(&self, osv_vuln: &OsvVulnerability) -> Result<Vulnerability> {
        // Extract CVSS score - try V3 first, then V4
        let cvss_score = osv_vuln
            .severity
            .as_ref()
            .and_then(|severities| {
                severities
                    .iter()
                    .find(|s| s.severity_type == "CVSS_V3")
                    .or_else(|| severities.iter().find(|s| s.severity_type == "CVSS_V4"))
            })
            .and_then(|s| parse_cvss_score(&s.score));

        // Determine severity with fallback strategy:
        // 1. First: use CVSS score if available
        // 2. Second: fallback to database_specific.severity string
        // 3. Third: default to Severity::None
        let severity = if let Some(score) = cvss_score {
            Severity::from_cvss_score(score)
        } else if let Some(db_severity) = osv_vuln
            .database_specific
            .as_ref()
            .and_then(|db| db.severity.as_deref())
        {
            parse_severity_string(db_severity)
        } else {
            Severity::None
        };

        // Extract fixed version
        let fixed_version = osv_vuln.affected.as_ref().and_then(|affected| {
            affected.iter().find_map(|a| {
                a.ranges
                    .as_ref()?
                    .iter()
                    .find_map(|r| r.events.iter().find_map(|e| e.fixed.clone()))
            })
        });

        Vulnerability::new(
            osv_vuln.id.clone(),
            cvss_score,
            severity,
            fixed_version,
            osv_vuln.summary.clone(),
        )
    }
}

#[async_trait]
impl VulnerabilityRepository for OsvClient {
    async fn fetch_vulnerabilities(
        &self,
        packages: Vec<Package>,
    ) -> Result<Vec<PackageVulnerabilities>> {
        // Call the version with progress but with a no-op callback
        self.fetch_vulnerabilities_with_progress(packages, Box::new(|_, _| {}))
            .await
    }

    async fn fetch_vulnerabilities_with_progress(
        &self,
        packages: Vec<Package>,
        progress_callback: ProgressCallback<'static>,
    ) -> Result<Vec<PackageVulnerabilities>> {
        // Step 1: Fetch batch results and count total vulnerabilities
        let mut batch_results: Vec<(Package, OsvResult)> = Vec::new();
        let mut total_vulns = 0;

        for chunk in packages.chunks(Self::MAX_BATCH_SIZE) {
            if !batch_results.is_empty() {
                tokio::time::sleep(Duration::from_millis(Self::RATE_LIMIT_MS)).await;
            }

            let osv_results = self.fetch_batch(chunk).await?;

            for (package, osv_result) in chunk.iter().zip(osv_results) {
                total_vulns += osv_result.vulns.len();
                batch_results.push((package.clone(), osv_result));
            }
        }

        // Step 2: Process vulnerabilities with progress reporting
        let mut all_results = Vec::new();
        let mut processed_vulns = 0;

        for (package, osv_result) in batch_results {
            if osv_result.vulns.is_empty() {
                continue;
            }

            let mut vulnerabilities: Vec<Vulnerability> = Vec::new();

            for osv_vuln in &osv_result.vulns {
                // Report progress before fetching
                processed_vulns += 1;
                progress_callback(processed_vulns, total_vulns);

                // Fetch detailed vulnerability information (async)
                match self.fetch_vulnerability_details(&osv_vuln.id).await {
                    Ok(detailed_vuln) => {
                        if let Ok(vuln) = self.convert_to_vulnerability(&detailed_vuln) {
                            vulnerabilities.push(vuln);
                        }
                    }
                    Err(e) => {
                        let msgs = Messages::for_locale(self.locale);
                        eprintln!(
                            "{}",
                            Messages::format(
                                msgs.warn_vuln_detail_fetch_failed,
                                &[&osv_vuln.id, &e.to_string()]
                            )
                        );
                    }
                }

                // Rate limiting: small delay between detail requests (async)
                tokio::time::sleep(Duration::from_millis(Self::RATE_LIMIT_MS)).await;
            }

            if !vulnerabilities.is_empty() {
                all_results.push(PackageVulnerabilities::new(
                    package.name().to_string(),
                    package.version().to_string(),
                    vulnerabilities,
                ));
            }
        }

        Ok(all_results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_osv_client_creation() {
        let client = OsvClient::new(Locale::En);
        assert!(client.is_ok());
    }

    // Integration test - requires network access
    // Uncomment to run with real OSV API
    // #[test]
    // fn test_fetch_vulnerabilities_real() {
    //     let client = OsvClient::new(Locale::En).unwrap();
    //     let packages = vec![
    //         Package::new("requests".to_string(), "2.3.0".to_string()).unwrap(),
    //     ];
    //     let result = client.fetch_vulnerabilities(packages);
    //     assert!(result.is_ok());
    // }

    fn test_package() -> Package {
        Package::new("requests".to_string(), "2.31.0".to_string()).unwrap()
    }

    /// Mounts a batch-query response reporting exactly one vulnerability id
    /// (`CVE-2024-0001`) for the single queried package.
    async fn mount_batch_with_one_vuln(mock_server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [
                    { "vulns": [ { "id": "CVE-2024-0001" } ] }
                ]
            })))
            .mount(mock_server)
            .await;
    }

    #[tokio::test]
    async fn test_fetch_vulnerabilities_detail_fetch_failure_is_soft_failed() {
        // Regression test for the #825 fix: when the per-vulnerability detail
        // fetch fails, the package is soft-failed (excluded from results, no
        // panic/error propagation) rather than aborting the whole check. The
        // exact localized warning text is covered by src/i18n/mod.rs's
        // `test_warn_vuln_detail_fetch_failed_{en,ja}_format` tests; capturing
        // real stderr output in-process is unreliable, so this test instead
        // exercises the actual soft-fail code path end-to-end.
        let mock_server = MockServer::start().await;
        mount_batch_with_one_vuln(&mock_server).await;
        Mock::given(method("GET"))
            .and(path("/v1/vulns/CVE-2024-0001"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let client = OsvClient::new_with_base_url(mock_server.uri(), Locale::En).unwrap();
        let result = client
            .fetch_vulnerabilities(vec![test_package()])
            .await
            .unwrap();

        // The only vulnerability failed to fetch details for, so the package
        // has no successfully-fetched vulnerabilities and is excluded entirely.
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_vulnerabilities_detail_fetch_failure_ja_locale_soft_fails() {
        // Same as above, but with Locale::Ja, to prove the failure path
        // works regardless of which locale the client was constructed with
        // (the localized string itself is verified in src/i18n/mod.rs).
        let mock_server = MockServer::start().await;
        mount_batch_with_one_vuln(&mock_server).await;
        Mock::given(method("GET"))
            .and(path("/v1/vulns/CVE-2024-0001"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let client = OsvClient::new_with_base_url(mock_server.uri(), Locale::Ja).unwrap();
        let result = client
            .fetch_vulnerabilities(vec![test_package()])
            .await
            .unwrap();

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_vulnerabilities_detail_fetch_success_happy_path() {
        // Happy-path coverage for the base_url plumbing introduced alongside
        // the #825 fix: a broken URL template would fail this test even
        // though the failure-path tests above would still pass.
        let mock_server = MockServer::start().await;
        mount_batch_with_one_vuln(&mock_server).await;
        Mock::given(method("GET"))
            .and(path("/v1/vulns/CVE-2024-0001"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "CVE-2024-0001",
                "summary": "Test vulnerability",
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = OsvClient::new_with_base_url(mock_server.uri(), Locale::En).unwrap();
        let result = client
            .fetch_vulnerabilities(vec![test_package()])
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].vulnerabilities().len(), 1);
        assert_eq!(result[0].vulnerabilities()[0].id(), "CVE-2024-0001");
    }

    /// Builds a syntactically valid OSV vulnerability-detail JSON body whose
    /// total length is exactly `total_len` bytes, padded via the `summary`
    /// field. The body is deliberately *valid* JSON: if the size guard were
    /// absent, deserialization would succeed, so an error from the client
    /// proves the guard fired rather than a parse failure.
    fn vuln_json_of_len(total_len: usize) -> Vec<u8> {
        let prefix: &[u8] = br#"{"id":"CVE-2024-0001","summary":""#;
        let suffix: &[u8] = br#""}"#;
        let mut body = Vec::with_capacity(total_len);
        body.extend_from_slice(prefix);
        body.resize(total_len - suffix.len(), b'x');
        body.extend_from_slice(suffix);
        assert_eq!(body.len(), total_len);
        body
    }

    /// Same, for the batch-query endpoint's response shape.
    fn batch_json_of_len(total_len: usize) -> Vec<u8> {
        let prefix: &[u8] = br#"{"results":[{"vulns":[{"id":"CVE-2024-0001","summary":""#;
        let suffix: &[u8] = br#""}]}]}"#;
        let mut body = Vec::with_capacity(total_len);
        body.extend_from_slice(prefix);
        body.resize(total_len - suffix.len(), b'x');
        body.extend_from_slice(suffix);
        assert_eq!(body.len(), total_len);
        body
    }

    #[tokio::test]
    async fn test_fetch_batch_rejects_oversized_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                batch_json_of_len(OsvClient::MAX_RESPONSE_BYTES + 1),
                "application/json",
            ))
            .mount(&mock_server)
            .await;

        let client = OsvClient::new_with_base_url(mock_server.uri(), Locale::En).unwrap();
        let err = client.fetch_batch(&[test_package()]).await.unwrap_err();
        let msg = err.to_string();
        // "too large" is the Content-Length pre-check branch specifically.
        assert!(msg.contains("too large"), "unexpected error: {msg}");
        // Proves the "OSV batch query" context is actually threaded through
        // to the shared guard, not silently dropped at the call site.
        assert!(msg.contains("OSV batch query"), "unexpected error: {msg}");
    }

    #[tokio::test]
    async fn test_fetch_batch_accepts_response_at_limit() {
        // Exactly at the limit must pass: proves the comparison is `>`, not `>=`.
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                batch_json_of_len(OsvClient::MAX_RESPONSE_BYTES),
                "application/json",
            ))
            .mount(&mock_server)
            .await;

        let client = OsvClient::new_with_base_url(mock_server.uri(), Locale::En).unwrap();
        let results = client.fetch_batch(&[test_package()]).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vulns.len(), 1);
    }

    #[tokio::test]
    async fn test_fetch_vulnerability_details_rejects_oversized_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/vulns/CVE-2024-0001"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                vuln_json_of_len(OsvClient::MAX_RESPONSE_BYTES + 1),
                "application/json",
            ))
            .mount(&mock_server)
            .await;

        let client = OsvClient::new_with_base_url(mock_server.uri(), Locale::En).unwrap();
        let err = client
            .fetch_vulnerability_details("CVE-2024-0001")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("too large"), "unexpected error: {msg}");
        // Proves the "OSV vulnerability {id}" context is actually threaded
        // through to the shared guard, not silently dropped at the call site.
        assert!(
            msg.contains("OSV vulnerability CVE-2024-0001"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn test_fetch_vulnerability_details_accepts_response_at_limit() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/vulns/CVE-2024-0001"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                vuln_json_of_len(OsvClient::MAX_RESPONSE_BYTES),
                "application/json",
            ))
            .mount(&mock_server)
            .await;

        let client = OsvClient::new_with_base_url(mock_server.uri(), Locale::En).unwrap();
        let vuln = client
            .fetch_vulnerability_details("CVE-2024-0001")
            .await
            .unwrap();
        assert_eq!(vuln.id, "CVE-2024-0001");
    }
}
