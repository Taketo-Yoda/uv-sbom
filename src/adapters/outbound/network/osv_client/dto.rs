// OSV API request/response structures

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub(super) struct OsvBatchQuery {
    pub(super) queries: Vec<OsvQuery>,
}

#[derive(Debug, Serialize)]
pub(super) struct OsvQuery {
    pub(super) package: OsvPackage,
    pub(super) version: String,
}

#[derive(Debug, Serialize)]
pub(super) struct OsvPackage {
    pub(super) name: String,
    pub(super) ecosystem: String, // "PyPI"
}

#[derive(Debug, Deserialize)]
pub(super) struct OsvBatchResponse {
    pub(super) results: Vec<OsvResult>,
}

#[derive(Debug, Deserialize)]
pub(super) struct OsvResult {
    #[serde(default)]
    pub(super) vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Deserialize)]
pub(super) struct OsvVulnerability {
    pub(super) id: String,
    #[serde(default)]
    pub(super) summary: Option<String>,
    #[serde(default)]
    pub(super) severity: Option<Vec<OsvSeverity>>,
    #[serde(default)]
    pub(super) database_specific: Option<DatabaseSpecific>,
    #[serde(default)]
    pub(super) affected: Option<Vec<OsvAffected>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct OsvSeverity {
    #[serde(rename = "type")]
    pub(super) severity_type: String, // "CVSS_V3"
    pub(super) score: String, // e.g., "CVSS:3.1/AV:N/AC:L/..."
}

#[derive(Debug, Deserialize)]
pub(super) struct DatabaseSpecific {
    #[serde(default)]
    pub(super) severity: Option<String>, // "CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"
}

#[derive(Debug, Deserialize)]
pub(super) struct OsvAffected {
    #[serde(default)]
    pub(super) ranges: Option<Vec<OsvRange>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct OsvRange {
    pub(super) events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
pub(super) struct OsvEvent {
    #[serde(default)]
    pub(super) fixed: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
