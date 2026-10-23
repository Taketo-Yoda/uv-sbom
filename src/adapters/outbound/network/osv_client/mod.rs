mod cvss;
mod dto;

use self::cvss::{parse_cvss_score, parse_severity_string};
use crate::i18n::{Locale, Messages};
use crate::ports::outbound::{AdvisoryRepository, ProgressCallback, VulnerabilityRepository};
use crate::sbom_generation::domain::advisory::{Advisory, AffectedPackage, AffectedRange};
use crate::sbom_generation::domain::vulnerability::{
    CvssScore, PackageVulnerabilities, Severity, Vulnerability,
};
use crate::sbom_generation::domain::Package;
use crate::shared::response_size_guard;
use crate::shared::Result;
use async_trait::async_trait;
use dto::{
    OsvAffected, OsvBatchQuery, OsvBatchResponse, OsvEvent, OsvPackage, OsvQuery, OsvResult,
    OsvVulnerability,
};
use reqwest::{Client, StatusCode};
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
    /// OSV's spelling of the PyPI ecosystem in `affected[].package.ecosystem`.
    const ECOSYSTEM_PYPI: &'static str = "PyPI";
    /// The only range type evaluated by `--incident` (GIT/SEMVER are dropped).
    const RANGE_TYPE_ECOSYSTEM: &'static str = "ECOSYSTEM";

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
        self.fetch_vulnerability_details_opt(vuln_id)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "OSV API returned status code {} for vulnerability {}",
                    StatusCode::NOT_FOUND,
                    vuln_id
                )
            })
    }

    /// Same as [`Self::fetch_vulnerability_details`], but maps HTTP 404 to
    /// `Ok(None)` so the advisory path can distinguish "no such advisory" from
    /// a failure. Shared by both paths so they cannot drift apart.
    async fn fetch_vulnerability_details_opt(
        &self,
        vuln_id: &str,
    ) -> Result<Option<OsvVulnerability>> {
        let url = format!("{}/v1/vulns/{}", self.base_url, vuln_id);
        let response = self.client.get(&url).send().await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
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
        Ok(Some(vuln))
    }

    /// Derives the CVSS score and severity of an OSV record.
    ///
    /// Shared by the batch path ([`Self::convert_to_vulnerability`]) and the
    /// advisory path ([`Self::to_advisory`]) so the two cannot diverge.
    fn compute_severity(osv_vuln: &OsvVulnerability) -> (Option<CvssScore>, Severity) {
        // Extract CVSS score - first parseable V3 entry wins, then V4
        // (an unparseable V3 entry falls through to V4 rather than to
        // database_specific.severity)
        let cvss_score = osv_vuln.severity.as_ref().and_then(|severities| {
            let first_scored = |severity_type: &str| {
                severities
                    .iter()
                    .filter(|s| s.severity_type == severity_type)
                    .find_map(|s| parse_cvss_score(&s.score))
            };
            first_scored("CVSS_V3").or_else(|| first_scored("CVSS_V4"))
        });

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

        (cvss_score, severity)
    }

    /// Converts a single OSV vulnerability to domain model
    fn convert_to_vulnerability(&self, osv_vuln: &OsvVulnerability) -> Result<Vulnerability> {
        let (cvss_score, severity) = Self::compute_severity(osv_vuln);

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
            osv_vuln.aliases.clone(),
        )
    }

    /// Maps an OSV record to the domain `Advisory` used by `--incident` mode.
    ///
    /// Keeps only `affected` entries whose ecosystem is exactly `"PyPI"` (the
    /// spelling OSV uses for every PyPI record) and, within them, only
    /// `ECOSYSTEM` ranges. CVE-sourced records carry no `package` and only GIT
    /// ranges, so they map to an advisory with no affected packages but with
    /// their aliases intact. Package names are kept as published; PEP 503
    /// normalization is the domain matcher's job.
    fn to_advisory(osv_vuln: OsvVulnerability) -> Advisory {
        let severity = match Self::compute_severity(&osv_vuln).1 {
            Severity::None => None,
            s => Some(s),
        };
        let affected = osv_vuln
            .affected
            .unwrap_or_default()
            .into_iter()
            .filter_map(Self::to_affected_package)
            .collect();

        Advisory {
            id: osv_vuln.id,
            aliases: osv_vuln.aliases,
            summary: osv_vuln.summary,
            severity,
            affected,
        }
    }

    /// Maps one `affected` entry, or `None` when it has no `package` (CVE-sourced
    /// records) or belongs to an ecosystem other than PyPI.
    fn to_affected_package(affected: OsvAffected) -> Option<AffectedPackage> {
        let package = affected.package?;
        if package.ecosystem != Self::ECOSYSTEM_PYPI {
            return None;
        }
        let ranges = affected
            .ranges
            .unwrap_or_default()
            .iter()
            .filter(|r| r.range_type == Self::RANGE_TYPE_ECOSYSTEM)
            .flat_map(|r| Self::fold_events(&r.events))
            .collect();

        Some(AffectedPackage {
            name: package.name,
            ranges,
            versions: affected.versions,
        })
    }

    /// Folds one OSV range's events into flattened intervals, in event order.
    ///
    /// An `introduced` opens an interval; the next `fixed` or `last_affected`
    /// closes it. An interval still open at the end is emitted with no upper
    /// bound. A closer with nothing open is emitted with `introduced: None`
    /// ("from the beginning"). A second `introduced` while one is open emits
    /// the first as unbounded — over-reporting is the safe direction here.
    /// Other event kinds (e.g. `limit`) are ignored.
    fn fold_events(events: &[OsvEvent]) -> Vec<AffectedRange> {
        let unbounded = |introduced| AffectedRange {
            introduced,
            fixed: None,
            last_affected: None,
        };
        let mut ranges = Vec::new();
        let mut open: Option<Option<String>> = None;

        for event in events {
            if let Some(introduced) = &event.introduced {
                if let Some(prev) = open.replace(Some(introduced.clone())) {
                    ranges.push(unbounded(prev));
                }
            } else if event.fixed.is_some() || event.last_affected.is_some() {
                ranges.push(AffectedRange {
                    introduced: open.take().flatten(),
                    fixed: event.fixed.clone(),
                    last_affected: event.last_affected.clone(),
                });
            }
        }
        if let Some(prev) = open {
            ranges.push(unbounded(prev));
        }
        ranges
    }
}

#[async_trait]
impl AdvisoryRepository for OsvClient {
    /// Does not retry, matching the batch path's fail-fast contract.
    async fn fetch_advisory(&self, advisory_id: &str) -> Result<Option<Advisory>> {
        // The ID is user input here (unlike the batch path, where IDs come
        // from OSV itself), so validate and encode it before building the URL.
        crate::shared::security::validate_url_component(advisory_id, "Advisory ID")?;
        let encoded = urlencoding::encode(advisory_id);
        Ok(self
            .fetch_vulnerability_details_opt(&encoded)
            .await?
            .map(Self::to_advisory))
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

    const V3_CRITICAL: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    const V4_CRITICAL: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";

    fn convert(osv_json: serde_json::Value) -> Vulnerability {
        let osv_vuln: OsvVulnerability = serde_json::from_value(osv_json).unwrap();
        OsvClient::new(Locale::En)
            .unwrap()
            .convert_to_vulnerability(&osv_vuln)
            .unwrap()
    }

    #[test]
    fn test_convert_v4_only_scores_critical() {
        // Regression test for #958: a v4-only record used to get no score.
        let vuln = convert(serde_json::json!({
            "id": "GHSA-v4only",
            "severity": [{ "type": "CVSS_V4", "score": V4_CRITICAL }]
        }));
        assert_eq!(vuln.cvss_score().map(|s| s.value()), Some(9.3));
        assert_eq!(vuln.severity(), Severity::Critical);
    }

    #[test]
    fn test_convert_prefers_v3_when_both_present() {
        let vuln = convert(serde_json::json!({
            "id": "GHSA-both",
            "severity": [
                { "type": "CVSS_V4", "score": V4_CRITICAL },
                { "type": "CVSS_V3", "score": V3_CRITICAL }
            ]
        }));
        assert_eq!(vuln.cvss_score().map(|s| s.value()), Some(9.8));
    }

    #[test]
    fn test_convert_falls_back_to_v4_when_v3_malformed() {
        let vuln = convert(serde_json::json!({
            "id": "GHSA-badv3",
            "severity": [
                { "type": "CVSS_V3", "score": "CVSS:3.1/garbage" },
                { "type": "CVSS_V4", "score": V4_CRITICAL }
            ]
        }));
        assert_eq!(vuln.cvss_score().map(|s| s.value()), Some(9.3));
    }

    #[test]
    fn test_convert_unparseable_v4_uses_db_severity() {
        let vuln = convert(serde_json::json!({
            "id": "GHSA-badv4",
            "severity": [{ "type": "CVSS_V4", "score": "CVSS:4.0/garbage" }],
            "database_specific": { "severity": "HIGH" }
        }));
        assert!(vuln.cvss_score().is_none());
        assert_eq!(vuln.severity(), Severity::High);
    }

    // ---- AdvisoryRepository (#965) ----

    /// Shaped like the real OSV record for GHSA-j8r2-6x86-q33q (requests
    /// Proxy-Authorization leak), trimmed to the fields the mapping reads.
    fn ghsa_requests_fixture() -> serde_json::Value {
        serde_json::json!({
            "id": "GHSA-j8r2-6x86-q33q",
            "summary": "Unintended leak of Proxy-Authorization header in requests",
            "aliases": ["CVE-2023-32681", "PYSEC-2023-74"],
            "severity": [
                { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N" }
            ],
            "affected": [{
                "package": { "name": "requests", "ecosystem": "PyPI", "purl": "pkg:pypi/requests" },
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [ { "introduced": "2.3.0" }, { "fixed": "2.31.0" } ]
                }],
                "versions": ["2.3.0", "2.30.0"]
            }]
        })
    }

    /// Shaped like a cvelistV5-generated CVE record: no `package`, GIT ranges only.
    fn cve_sourced_fixture() -> serde_json::Value {
        serde_json::json!({
            "id": "CVE-2023-32681",
            "aliases": ["GHSA-j8r2-6x86-q33q", "PYSEC-2023-74"],
            "summary": "Requests leaks Proxy-Authorization headers",
            "affected": [{
                "ranges": [{
                    "type": "GIT",
                    "repo": "https://github.com/psf/requests",
                    "events": [ { "introduced": "0" }, { "fixed": "74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5" } ]
                }]
            }]
        })
    }

    async fn fetch_advisory_from(id: &str, response: ResponseTemplate) -> Result<Option<Advisory>> {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{id}")))
            .respond_with(response)
            .mount(&mock_server)
            .await;
        let client = OsvClient::new_with_base_url(mock_server.uri(), Locale::En).unwrap();
        client.fetch_advisory(id).await
    }

    fn range(introduced: Option<&str>, fixed: Option<&str>, last: Option<&str>) -> AffectedRange {
        AffectedRange {
            introduced: introduced.map(String::from),
            fixed: fixed.map(String::from),
            last_affected: last.map(String::from),
        }
    }

    fn advisory(osv_json: serde_json::Value) -> Advisory {
        OsvClient::to_advisory(serde_json::from_value(osv_json).unwrap())
    }

    #[tokio::test]
    async fn test_fetch_advisory_ghsa_maps_pypi_package_and_range() {
        let advisory = fetch_advisory_from(
            "GHSA-j8r2-6x86-q33q",
            ResponseTemplate::new(200).set_body_json(ghsa_requests_fixture()),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(advisory.id, "GHSA-j8r2-6x86-q33q");
        assert!(advisory.aliases.contains(&"CVE-2023-32681".to_string()));
        assert_eq!(advisory.severity, Some(Severity::Medium));
        assert_eq!(advisory.affected.len(), 1);
        let package = &advisory.affected[0];
        assert_eq!(package.name, "requests");
        assert_eq!(
            package.ranges,
            vec![range(Some("2.3.0"), Some("2.31.0"), None)]
        );
        assert_eq!(package.versions, vec!["2.3.0", "2.30.0"]);
    }

    #[tokio::test]
    async fn test_fetch_advisory_cve_sourced_has_no_packages_but_keeps_aliases() {
        let advisory = fetch_advisory_from(
            "CVE-2023-32681",
            ResponseTemplate::new(200).set_body_json(cve_sourced_fixture()),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(advisory.affected.is_empty());
        assert_eq!(
            advisory.aliases,
            vec!["GHSA-j8r2-6x86-q33q", "PYSEC-2023-74"]
        );
        assert_eq!(advisory.severity, None);
    }

    #[tokio::test]
    async fn test_fetch_advisory_not_found_is_none() {
        let result = fetch_advisory_from("GHSA-xxxx-xxxx-xxxx", ResponseTemplate::new(404))
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_fetch_advisory_server_error_is_err() {
        let err = fetch_advisory_from("GHSA-xxxx-xxxx-xxxx", ResponseTemplate::new(500))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("500"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn test_fetch_advisory_network_error_is_err() {
        // Nothing listens on port 1, so the connection is refused.
        let client = OsvClient::new_with_base_url("http://127.0.0.1:1", Locale::En).unwrap();
        assert!(client.fetch_advisory("GHSA-j8r2-6x86-q33q").await.is_err());
    }

    #[tokio::test]
    async fn test_fetch_advisory_rejects_invalid_id() {
        let client = OsvClient::new_with_base_url("http://127.0.0.1:1", Locale::En).unwrap();
        assert!(client.fetch_advisory("../v1/querybatch").await.is_err());
    }

    #[tokio::test]
    async fn test_fetch_vulnerability_details_404_is_still_err() {
        // The batch path's contract is unchanged: a 404 there is an error.
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/vulns/CVE-2024-0001"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;
        let client = OsvClient::new_with_base_url(mock_server.uri(), Locale::En).unwrap();
        let err = client
            .fetch_vulnerability_details("CVE-2024-0001")
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "OSV API returned status code 404 Not Found for vulnerability CVE-2024-0001"
        );
    }

    #[test]
    fn test_to_advisory_multi_range_and_last_affected() {
        let advisory = advisory(serde_json::json!({
            "id": "PYSEC-multi",
            "affected": [{
                "package": { "name": "Django", "ecosystem": "PyPI" },
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [
                        { "introduced": "0" }, { "fixed": "3.2.20" },
                        { "introduced": "4.0" }, { "fixed": "4.1.10" },
                        { "introduced": "4.2" }, { "last_affected": "4.2.2" }
                    ]
                }]
            }]
        }));
        assert_eq!(advisory.affected[0].name, "Django");
        assert_eq!(
            advisory.affected[0].ranges,
            vec![
                range(Some("0"), Some("3.2.20"), None),
                range(Some("4.0"), Some("4.1.10"), None),
                range(Some("4.2"), None, Some("4.2.2")),
            ]
        );
    }

    #[test]
    fn test_to_advisory_no_fixed_event_is_unbounded() {
        let advisory = advisory(serde_json::json!({
            "id": "GHSA-nofix",
            "affected": [{
                "package": { "name": "abandoned-pkg", "ecosystem": "PyPI" },
                "ranges": [{ "type": "ECOSYSTEM", "events": [ { "introduced": "1.0" } ] }]
            }]
        }));
        assert_eq!(
            advisory.affected[0].ranges,
            vec![range(Some("1.0"), None, None)]
        );
    }

    #[test]
    fn test_to_advisory_filters_non_pypi_and_non_ecosystem() {
        let advisory = advisory(serde_json::json!({
            "id": "GHSA-mixed",
            "affected": [
                {
                    "package": { "name": "lodash", "ecosystem": "npm" },
                    "ranges": [{ "type": "SEMVER", "events": [ { "introduced": "0" }, { "fixed": "4.17.21" } ] }]
                },
                {
                    "package": { "name": "pillow", "ecosystem": "PyPI" },
                    "ranges": [
                        { "type": "GIT", "repo": "https://example.invalid", "events": [ { "introduced": "0" }, { "fixed": "abc123" } ] },
                        { "type": "ECOSYSTEM", "events": [ { "introduced": "0" }, { "fixed": "10.0.1" } ] }
                    ]
                }
            ]
        }));
        assert_eq!(advisory.affected.len(), 1);
        assert_eq!(advisory.affected[0].name, "pillow");
        assert_eq!(
            advisory.affected[0].ranges,
            vec![range(Some("0"), Some("10.0.1"), None)]
        );
    }

    #[test]
    fn test_fold_events_edge_cases() {
        let events: Vec<OsvEvent> = serde_json::from_value(serde_json::json!([
            { "fixed": "1.0" },
            { "introduced": "2.0" },
            { "introduced": "3.0" },
            { "limit": "9.9" },
            { "fixed": "3.5" }
        ]))
        .unwrap();
        assert_eq!(
            OsvClient::fold_events(&events),
            vec![
                // A closer with nothing open means "from the beginning".
                range(None, Some("1.0"), None),
                // A second `introduced` emits the first one unbounded.
                range(Some("2.0"), None, None),
                range(Some("3.0"), Some("3.5"), None),
            ]
        );
    }
}
