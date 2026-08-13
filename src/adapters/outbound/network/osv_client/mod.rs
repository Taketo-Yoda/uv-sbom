mod cvss;
mod dto;

use crate::ports::outbound::{ProgressCallback, VulnerabilityRepository};
use crate::sbom_generation::domain::vulnerability::{
    PackageVulnerabilities, Severity, Vulnerability,
};
use crate::sbom_generation::domain::Package;
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
    api_url: String,
}

impl OsvClient {
    const API_ENDPOINT: &'static str = "https://api.osv.dev/v1/querybatch";
    const TIMEOUT_SECONDS: u64 = 30;
    const RATE_LIMIT_MS: u64 = 100; // 10 req/sec
    const MAX_BATCH_SIZE: usize = 100; // OSV API limit

    /// Creates a new OSV API client with default configuration
    pub fn new() -> Result<Self> {
        let version = env!("CARGO_PKG_VERSION");
        let user_agent = format!("uv-sbom/{}", version);
        let client = Client::builder()
            .timeout(Duration::from_secs(Self::TIMEOUT_SECONDS))
            .user_agent(user_agent)
            .build()?;

        Ok(Self {
            client,
            api_url: Self::API_ENDPOINT.to_string(),
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
        let response = self
            .client
            .post(&self.api_url)
            .json(&batch_query)
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("OSV API returned status code {}", response.status());
        }

        let batch_response: OsvBatchResponse = response.json().await?;
        Ok(batch_response.results)
    }

    /// Fetches detailed vulnerability information by ID (async)
    ///
    /// The batch API returns minimal information. To get severity and other details,
    /// we need to query each vulnerability individually.
    async fn fetch_vulnerability_details(&self, vuln_id: &str) -> Result<OsvVulnerability> {
        let url = format!("https://api.osv.dev/v1/vulns/{}", vuln_id);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            anyhow::bail!(
                "OSV API returned status code {} for vulnerability {}",
                response.status(),
                vuln_id
            );
        }

        let vuln: OsvVulnerability = response.json().await?;
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
                        eprintln!(
                            "Warning: Failed to fetch details for {}: {}",
                            osv_vuln.id, e
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

    #[test]
    fn test_osv_client_creation() {
        let client = OsvClient::new();
        assert!(client.is_ok());
    }

    // Integration test - requires network access
    // Uncomment to run with real OSV API
    // #[test]
    // fn test_fetch_vulnerabilities_real() {
    //     let client = OsvClient::new().unwrap();
    //     let packages = vec![
    //         Package::new("requests".to_string(), "2.3.0".to_string()).unwrap(),
    //     ];
    //     let result = client.fetch_vulnerabilities(packages);
    //     assert!(result.is_ok());
    // }
}
