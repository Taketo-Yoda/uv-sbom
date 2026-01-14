// Note: This module will be used in subsequent subtasks for CVE check feature
#![allow(dead_code)]

use crate::ports::outbound::{VulnerabilityProgressCallback, VulnerabilityRepository};
use crate::sbom_generation::domain::vulnerability::{
    CvssScore, PackageVulnerabilities, Severity, Vulnerability,
};
use crate::sbom_generation::domain::Package;
use crate::shared::Result;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// OSV API client for fetching vulnerability data
///
/// Uses the OSV.dev Batch Query API to efficiently check multiple packages.
///
/// # Security
/// - Implements rate limiting (10 req/sec)
/// - Implements timeout (30 seconds)
/// - Does not retry failed requests (fail fast for CVE checks)
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

    /// Fetches vulnerabilities for a batch of packages
    fn fetch_batch(&self, packages: &[Package]) -> Result<Vec<OsvResult>> {
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

        // Send request
        let response = self.client.post(&self.api_url).json(&batch_query).send()?;

        if !response.status().is_success() {
            anyhow::bail!("OSV API returned status code {}", response.status());
        }

        let batch_response: OsvBatchResponse = response.json()?;
        Ok(batch_response.results)
    }

    /// Fetches detailed vulnerability information by ID
    ///
    /// The batch API returns minimal information. To get severity and other details,
    /// we need to query each vulnerability individually.
    fn fetch_vulnerability_details(&self, vuln_id: &str) -> Result<OsvVulnerability> {
        let url = format!("https://api.osv.dev/v1/vulns/{}", vuln_id);
        let response = self.client.get(&url).send()?;

        if !response.status().is_success() {
            anyhow::bail!(
                "OSV API returned status code {} for vulnerability {}",
                response.status(),
                vuln_id
            );
        }

        let vuln: OsvVulnerability = response.json()?;
        Ok(vuln)
    }

    /// Converts OSV vulnerabilities to domain model
    ///
    /// For each vulnerability ID in the batch result, fetches detailed information
    /// to get severity and other metadata that's not included in batch responses.
    fn convert_to_package_vulnerabilities(
        &self,
        package: &Package,
        osv_result: &OsvResult,
    ) -> Result<Option<PackageVulnerabilities>> {
        if osv_result.vulns.is_empty() {
            return Ok(None);
        }

        let mut vulnerabilities: Vec<Vulnerability> = Vec::new();

        for osv_vuln in &osv_result.vulns {
            // Fetch detailed vulnerability information
            // Batch API only returns minimal data (id, summary), we need full details for severity
            match self.fetch_vulnerability_details(&osv_vuln.id) {
                Ok(detailed_vuln) => {
                    if let Ok(vuln) = self.convert_to_vulnerability(&detailed_vuln) {
                        vulnerabilities.push(vuln);
                    }
                }
                Err(e) => {
                    // Log error but continue processing other vulnerabilities
                    eprintln!(
                        "Warning: Failed to fetch details for {}: {}",
                        osv_vuln.id, e
                    );
                }
            }

            // Rate limiting: small delay between detail requests
            std::thread::sleep(Duration::from_millis(Self::RATE_LIMIT_MS));
        }

        if vulnerabilities.is_empty() {
            return Ok(None);
        }

        Ok(Some(PackageVulnerabilities::new(
            package.name().to_string(),
            package.version().to_string(),
            vulnerabilities,
        )))
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

impl VulnerabilityRepository for OsvClient {
    fn fetch_vulnerabilities(&self, packages: Vec<Package>) -> Result<Vec<PackageVulnerabilities>> {
        // Call the version with progress but with a no-op callback
        self.fetch_vulnerabilities_with_progress(packages, Box::new(|_, _| {}))
    }

    fn fetch_vulnerabilities_with_progress(
        &self,
        packages: Vec<Package>,
        progress_callback: VulnerabilityProgressCallback,
    ) -> Result<Vec<PackageVulnerabilities>> {
        // Step 1: Fetch batch results and count total vulnerabilities
        let mut batch_results: Vec<(Package, OsvResult)> = Vec::new();
        let mut total_vulns = 0;

        for chunk in packages.chunks(Self::MAX_BATCH_SIZE) {
            if !batch_results.is_empty() {
                std::thread::sleep(Duration::from_millis(Self::RATE_LIMIT_MS));
            }

            let osv_results = self.fetch_batch(chunk)?;

            for (package, osv_result) in chunk.iter().zip(osv_results.into_iter()) {
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

                // Fetch detailed vulnerability information
                match self.fetch_vulnerability_details(&osv_vuln.id) {
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

                // Rate limiting: small delay between detail requests
                std::thread::sleep(Duration::from_millis(Self::RATE_LIMIT_MS));
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

// OSV API request/response structures

#[derive(Debug, Serialize)]
struct OsvBatchQuery {
    queries: Vec<OsvQuery>,
}

#[derive(Debug, Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Debug, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String, // "PyPI"
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvResult>,
}

#[derive(Debug, Deserialize)]
struct OsvResult {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    severity: Option<Vec<OsvSeverity>>,
    #[serde(default)]
    database_specific: Option<DatabaseSpecific>,
    #[serde(default)]
    affected: Option<Vec<OsvAffected>>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: String, // "CVSS_V3"
    score: String, // e.g., "CVSS:3.1/AV:N/AC:L/..."
}

#[derive(Debug, Deserialize)]
struct DatabaseSpecific {
    #[serde(default)]
    severity: Option<String>, // "CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Option<Vec<OsvRange>>,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    range_type: String,
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    #[serde(default)]
    #[allow(dead_code)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
}

/// Extracts numeric CVSS score from CVSS vector string
///
/// Example: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" -> Some(9.8)
///
/// Note: This is a simplified implementation that extracts the score from
/// the vector components. For the initial implementation, we calculate
/// the score based on the metrics in the vector string.
fn parse_cvss_score(cvss_vector: &str) -> Option<CvssScore> {
    // CVSS v3.1 metric values and their scores
    // This is a simplified scoring algorithm based on the Base Score formula

    // Parse metrics from vector string
    let metrics: std::collections::HashMap<&str, &str> = cvss_vector
        .split('/')
        .skip(1) // Skip "CVSS:3.1" or "CVSS:3.0"
        .filter_map(|part| {
            let mut split = part.split(':');
            Some((split.next()?, split.next()?))
        })
        .collect();

    // Extract metric values
    let av = metrics.get("AV")?;
    let ac = metrics.get("AC")?;
    let pr = metrics.get("PR")?;
    let ui = metrics.get("UI")?;
    let s = metrics.get("S")?;
    let c = metrics.get("C")?;
    let i = metrics.get("I")?;
    let a = metrics.get("A")?;

    // Calculate exploitability sub-score
    let av_score = match *av {
        "N" => 0.85, // Network
        "A" => 0.62, // Adjacent
        "L" => 0.55, // Local
        "P" => 0.2,  // Physical
        _ => return None,
    };

    let ac_score = match *ac {
        "L" => 0.77, // Low
        "H" => 0.44, // High
        _ => return None,
    };

    let pr_score = match (*pr, *s) {
        ("N", _) => 0.85,   // None
        ("L", "U") => 0.62, // Low, Unchanged
        ("L", "C") => 0.68, // Low, Changed
        ("H", "U") => 0.27, // High, Unchanged
        ("H", "C") => 0.5,  // High, Changed
        _ => return None,
    };

    let ui_score = match *ui {
        "N" => 0.85, // None
        "R" => 0.62, // Required
        _ => return None,
    };

    // Calculate impact sub-score
    let c_score = match *c {
        "N" => 0.0,  // None
        "L" => 0.22, // Low
        "H" => 0.56, // High
        _ => return None,
    };

    let i_score = match *i {
        "N" => 0.0,  // None
        "L" => 0.22, // Low
        "H" => 0.56, // High
        _ => return None,
    };

    let a_score = match *a {
        "N" => 0.0,  // None
        "L" => 0.22, // Low
        "H" => 0.56, // High
        _ => return None,
    };

    // Calculate ISS (Impact Sub-Score)
    let iss = 1.0_f64 - ((1.0 - c_score) * (1.0 - i_score) * (1.0 - a_score));

    // Calculate Impact
    let impact = if *s == "U" {
        6.42 * iss
    } else {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02_f64).powi(15)
    };

    // Calculate Exploitability
    let exploitability = 8.22 * av_score * ac_score * pr_score * ui_score;

    // Calculate Base Score
    let base_score = if impact <= 0.0 {
        0.0
    } else if *s == "U" {
        f64::min(impact + exploitability, 10.0)
    } else {
        f64::min(1.08 * (impact + exploitability), 10.0)
    };

    // Round up to one decimal place
    let rounded_score = (base_score * 10.0).ceil() / 10.0;

    CvssScore::new(rounded_score as f32).ok()
}

/// Parses severity string from OSV database_specific field
///
/// Maps OSV severity strings to our Severity enum:
/// - "CRITICAL" -> Severity::Critical
/// - "HIGH" -> Severity::High
/// - "MODERATE" or "MEDIUM" -> Severity::Medium
/// - "LOW" -> Severity::Low
/// - Unknown values -> Severity::None
fn parse_severity_string(severity: &str) -> Severity {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MODERATE" | "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::None,
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

    #[test]
    fn test_parse_cvss_score_critical() {
        // High severity example (network, low complexity, no privileges, no interaction)
        let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        let score = parse_cvss_score(vector);
        assert!(score.is_some());
        let score = score.unwrap();
        // This should be around 9.8 (Critical)
        assert!(score.value() >= 9.0 && score.value() <= 10.0);
    }

    #[test]
    fn test_parse_cvss_score_high() {
        // High severity example
        let vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
        let score = parse_cvss_score(vector);
        assert!(score.is_some());
        let score = score.unwrap();
        // This should be around 8.8 (High)
        assert!(score.value() >= 7.0 && score.value() < 9.0);
    }

    #[test]
    fn test_parse_cvss_score_medium() {
        // Medium severity example
        let vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L";
        let score = parse_cvss_score(vector);
        assert!(score.is_some());
        let score = score.unwrap();
        // This should be in the Medium range (4.0-6.9)
        assert!(score.value() >= 4.0 && score.value() < 7.0);
    }

    #[test]
    fn test_parse_cvss_score_low() {
        // Low severity example
        let vector = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N";
        let score = parse_cvss_score(vector);
        assert!(score.is_some());
        let score = score.unwrap();
        // This should be in the Low range (0.1-3.9)
        assert!(score.value() > 0.0 && score.value() < 4.0);
    }

    #[test]
    fn test_parse_cvss_score_none() {
        // No impact
        let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
        let score = parse_cvss_score(vector);
        assert!(score.is_some());
        let score = score.unwrap();
        assert_eq!(score.value(), 0.0);
    }

    #[test]
    fn test_parse_cvss_score_invalid() {
        let vector = "invalid vector";
        let score = parse_cvss_score(vector);
        assert!(score.is_none());
    }

    #[test]
    fn test_osv_result_deserialize_empty() {
        let json = r#"{"vulns": []}"#;
        let result = serde_json::from_str::<OsvResult>(json);
        assert!(result.is_ok());
        assert!(result.unwrap().vulns.is_empty());
    }

    #[test]
    fn test_osv_result_deserialize_with_vulns() {
        let json = r#"{
            "vulns": [
                {
                    "id": "CVE-2024-1234",
                    "summary": "Test vulnerability",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        }
                    ],
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "2.0.0"}
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;
        let result = serde_json::from_str::<OsvResult>(json);
        assert!(result.is_ok());
        let osv_result = result.unwrap();
        assert_eq!(osv_result.vulns.len(), 1);
        assert_eq!(osv_result.vulns[0].id, "CVE-2024-1234");
    }

    #[test]
    fn test_osv_batch_query_serialize() {
        let query = OsvBatchQuery {
            queries: vec![OsvQuery {
                package: OsvPackage {
                    name: "requests".to_string(),
                    ecosystem: "PyPI".to_string(),
                },
                version: "2.31.0".to_string(),
            }],
        };

        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("requests"));
        assert!(json.contains("PyPI"));
        assert!(json.contains("2.31.0"));
    }

    #[test]
    fn test_parse_severity_string() {
        assert_eq!(parse_severity_string("CRITICAL"), Severity::Critical);
        assert_eq!(parse_severity_string("critical"), Severity::Critical);
        assert_eq!(parse_severity_string("HIGH"), Severity::High);
        assert_eq!(parse_severity_string("high"), Severity::High);
        assert_eq!(parse_severity_string("MODERATE"), Severity::Medium);
        assert_eq!(parse_severity_string("moderate"), Severity::Medium);
        assert_eq!(parse_severity_string("MEDIUM"), Severity::Medium);
        assert_eq!(parse_severity_string("medium"), Severity::Medium);
        assert_eq!(parse_severity_string("LOW"), Severity::Low);
        assert_eq!(parse_severity_string("low"), Severity::Low);
        assert_eq!(parse_severity_string("UNKNOWN"), Severity::None);
        assert_eq!(parse_severity_string(""), Severity::None);
    }

    #[test]
    fn test_osv_vulnerability_with_database_specific() {
        let json = r#"{
            "id": "GHSA-2xpw-w6gg-jr37",
            "summary": "Test vulnerability",
            "database_specific": {
                "severity": "HIGH"
            },
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0"},
                                {"fixed": "2.6.0"}
                            ]
                        }
                    ]
                }
            ]
        }"#;
        let result = serde_json::from_str::<OsvVulnerability>(json);
        assert!(result.is_ok());
        let vuln = result.unwrap();
        assert_eq!(vuln.id, "GHSA-2xpw-w6gg-jr37");
        assert!(vuln.database_specific.is_some());
        let db_specific = vuln.database_specific.unwrap();
        assert_eq!(db_specific.severity, Some("HIGH".to_string()));
    }

    #[test]
    fn test_osv_vulnerability_without_database_specific() {
        let json = r#"{
            "id": "CVE-2024-1234",
            "summary": "Test vulnerability",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            ]
        }"#;
        let result = serde_json::from_str::<OsvVulnerability>(json);
        assert!(result.is_ok());
        let vuln = result.unwrap();
        assert_eq!(vuln.id, "CVE-2024-1234");
        assert!(vuln.database_specific.is_none());
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
