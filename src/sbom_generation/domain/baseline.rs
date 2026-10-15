use std::collections::HashSet;

use super::vulnerability::PackageVulnerabilities;

/// A single entry in a vulnerability baseline: an exact (package, version, vulnerability_id) tuple.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(dead_code)] // WIRE(#938): remove when --baseline is wired into GenerateSbomUseCase
pub struct BaselineEntry {
    pub package: String,
    pub version: String,
    pub id: String,
}

/// A set of previously-accepted vulnerability findings.
///
/// A finding is suppressed only when all three fields — package name, version,
/// and vulnerability ID — match exactly. Bumping the package version makes its
/// previously-baselined findings count as new.
///
/// Name matching uses the package name exactly as it appears in
/// `PackageVulnerabilities` (no PEP 503 normalization in v1).
#[derive(Debug, Clone)]
#[allow(dead_code)] // WIRE(#938): remove when --baseline is wired into GenerateSbomUseCase
pub struct VulnerabilityBaseline {
    entries: HashSet<BaselineEntry>,
}

#[allow(dead_code)] // WIRE(#938): remove when --baseline is wired into GenerateSbomUseCase
impl VulnerabilityBaseline {
    pub fn new() -> Self {
        Self {
            entries: HashSet::new(),
        }
    }

    pub fn from_entries(entries: impl IntoIterator<Item = BaselineEntry>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }

    /// Builds a baseline from a full (unfiltered) vulnerability report.
    ///
    /// Collects every `(package_name, current_version, vulnerability_id)` tuple
    /// present in the report. This is the data source for `--update-baseline`,
    /// which must save the **unfiltered** list.
    pub fn from_report(report: &[PackageVulnerabilities]) -> Self {
        let entries = report
            .iter()
            .flat_map(|pkg| {
                pkg.vulnerabilities().iter().map(move |vuln| BaselineEntry {
                    package: pkg.package_name().to_string(),
                    version: pkg.current_version().to_string(),
                    id: vuln.id().to_string(),
                })
            })
            .collect();
        Self { entries }
    }

    pub fn contains(&self, package: &str, version: &str, id: &str) -> bool {
        self.entries.contains(&BaselineEntry {
            package: package.to_string(),
            version: version.to_string(),
            id: id.to_string(),
        })
    }

    /// Returns the entries in sorted, deterministic order so the adapter's
    /// saved file is stable across runs.
    pub fn entries(&self) -> Vec<&BaselineEntry> {
        let mut sorted: Vec<&BaselineEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| {
            a.package
                .cmp(&b.package)
                .then(a.version.cmp(&b.version))
                .then(a.id.cmp(&b.id))
        });
        sorted
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Default for VulnerabilityBaseline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom_generation::domain::vulnerability::{
        PackageVulnerabilities, Severity, Vulnerability,
    };

    fn make_vuln(id: &str) -> Vulnerability {
        Vulnerability::new(id.to_string(), None, Severity::High, None, None, vec![]).unwrap()
    }

    fn make_pkg(name: &str, version: &str, vulns: Vec<Vulnerability>) -> PackageVulnerabilities {
        PackageVulnerabilities::new(name.to_string(), version.to_string(), vulns)
    }

    #[test]
    fn test_new_baseline_is_empty() {
        let baseline = VulnerabilityBaseline::new();
        assert!(baseline.is_empty());
        assert_eq!(baseline.len(), 0);
    }

    #[test]
    fn test_from_entries() {
        let entries = vec![
            BaselineEntry {
                package: "requests".into(),
                version: "2.31.0".into(),
                id: "CVE-2024-001".into(),
            },
            BaselineEntry {
                package: "flask".into(),
                version: "2.3.0".into(),
                id: "CVE-2024-002".into(),
            },
        ];
        let baseline = VulnerabilityBaseline::from_entries(entries);
        assert_eq!(baseline.len(), 2);
        assert!(!baseline.is_empty());
    }

    #[test]
    fn test_contains_exact_match() {
        let baseline = VulnerabilityBaseline::from_entries(vec![BaselineEntry {
            package: "requests".into(),
            version: "2.31.0".into(),
            id: "CVE-2024-001".into(),
        }]);

        assert!(baseline.contains("requests", "2.31.0", "CVE-2024-001"));
    }

    #[test]
    fn test_contains_version_mismatch() {
        let baseline = VulnerabilityBaseline::from_entries(vec![BaselineEntry {
            package: "requests".into(),
            version: "2.31.0".into(),
            id: "CVE-2024-001".into(),
        }]);

        assert!(!baseline.contains("requests", "2.32.0", "CVE-2024-001"));
    }

    #[test]
    fn test_contains_id_mismatch() {
        let baseline = VulnerabilityBaseline::from_entries(vec![BaselineEntry {
            package: "requests".into(),
            version: "2.31.0".into(),
            id: "CVE-2024-001".into(),
        }]);

        assert!(!baseline.contains("requests", "2.31.0", "CVE-2024-999"));
    }

    #[test]
    fn test_contains_package_mismatch() {
        let baseline = VulnerabilityBaseline::from_entries(vec![BaselineEntry {
            package: "requests".into(),
            version: "2.31.0".into(),
            id: "CVE-2024-001".into(),
        }]);

        assert!(!baseline.contains("flask", "2.31.0", "CVE-2024-001"));
    }

    #[test]
    fn test_from_report() {
        let report = vec![
            make_pkg(
                "requests",
                "2.31.0",
                vec![make_vuln("CVE-2024-001"), make_vuln("CVE-2024-002")],
            ),
            make_pkg("flask", "2.3.0", vec![make_vuln("CVE-2024-003")]),
        ];

        let baseline = VulnerabilityBaseline::from_report(&report);
        assert_eq!(baseline.len(), 3);
        assert!(baseline.contains("requests", "2.31.0", "CVE-2024-001"));
        assert!(baseline.contains("requests", "2.31.0", "CVE-2024-002"));
        assert!(baseline.contains("flask", "2.3.0", "CVE-2024-003"));
    }

    #[test]
    fn test_from_report_round_trip() {
        let report = vec![make_pkg(
            "requests",
            "2.31.0",
            vec![make_vuln("CVE-2024-001")],
        )];

        let baseline = VulnerabilityBaseline::from_report(&report);
        assert!(baseline.contains("requests", "2.31.0", "CVE-2024-001"));
        assert!(!baseline.contains("requests", "2.32.0", "CVE-2024-001"));
    }

    #[test]
    fn test_entries_deterministic_order() {
        let entries = vec![
            BaselineEntry {
                package: "zlib".into(),
                version: "1.0.0".into(),
                id: "CVE-2024-002".into(),
            },
            BaselineEntry {
                package: "aiohttp".into(),
                version: "3.9.0".into(),
                id: "CVE-2024-001".into(),
            },
            BaselineEntry {
                package: "aiohttp".into(),
                version: "3.9.0".into(),
                id: "CVE-2024-003".into(),
            },
        ];
        let baseline = VulnerabilityBaseline::from_entries(entries);
        let sorted = baseline.entries();

        assert_eq!(sorted[0].package, "aiohttp");
        assert_eq!(sorted[0].id, "CVE-2024-001");
        assert_eq!(sorted[1].package, "aiohttp");
        assert_eq!(sorted[1].id, "CVE-2024-003");
        assert_eq!(sorted[2].package, "zlib");
    }

    #[test]
    fn test_default_is_empty() {
        let baseline = VulnerabilityBaseline::default();
        assert!(baseline.is_empty());
    }
}
