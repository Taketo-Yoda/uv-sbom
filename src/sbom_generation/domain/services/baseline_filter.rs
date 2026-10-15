use crate::sbom_generation::domain::baseline::VulnerabilityBaseline;
use crate::sbom_generation::domain::vulnerability::PackageVulnerabilities;

/// Domain service for filtering previously-baselined findings from vulnerability results.
///
/// Mirrors `CveFilter`: a unit struct with a stateless associated function that
/// returns data only (no `eprintln!`, no i18n).
#[allow(dead_code)] // WIRE(#938): remove when --baseline is wired into GenerateSbomUseCase
pub struct BaselineFilter;

impl BaselineFilter {
    /// Partitions vulnerability findings into new and previously-baselined ones.
    ///
    /// A finding is suppressed only when the package name, version, **and**
    /// vulnerability ID all match a baseline entry exactly. Bumping the package
    /// version makes its previously-baselined findings count as new.
    ///
    /// # Returns
    /// A tuple of:
    /// * Filtered list with baselined findings removed (packages with no
    ///   remaining vulns are dropped entirely, same as `CveFilter`)
    /// * The count of individual vulnerabilities that were suppressed
    #[allow(dead_code)] // WIRE(#938): remove when --baseline is wired into GenerateSbomUseCase
    pub fn apply(
        vulnerabilities: Vec<PackageVulnerabilities>,
        baseline: &VulnerabilityBaseline,
    ) -> (Vec<PackageVulnerabilities>, usize) {
        if baseline.is_empty() {
            return (vulnerabilities, 0);
        }

        let mut result = Vec::new();
        let mut known_count = 0usize;

        for pkg_vulns in vulnerabilities {
            let mut kept = Vec::new();

            for vuln in pkg_vulns.vulnerabilities() {
                if baseline.contains(
                    pkg_vulns.package_name(),
                    pkg_vulns.current_version(),
                    vuln.id(),
                ) {
                    known_count += 1;
                } else {
                    kept.push(vuln.clone());
                }
            }

            if !kept.is_empty() {
                result.push(PackageVulnerabilities::new(
                    pkg_vulns.package_name().to_string(),
                    pkg_vulns.current_version().to_string(),
                    kept,
                ));
            }
        }

        (result, known_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom_generation::domain::baseline::BaselineEntry;
    use crate::sbom_generation::domain::vulnerability::{
        PackageVulnerabilities, Severity, Vulnerability,
    };

    fn make_vuln(id: &str) -> Vulnerability {
        Vulnerability::new(id.to_string(), None, Severity::High, None, None, vec![]).unwrap()
    }

    fn make_pkg(name: &str, version: &str, vulns: Vec<Vulnerability>) -> PackageVulnerabilities {
        PackageVulnerabilities::new(name.to_string(), version.to_string(), vulns)
    }

    fn entry(package: &str, version: &str, id: &str) -> BaselineEntry {
        BaselineEntry {
            package: package.into(),
            version: version.into(),
            id: id.into(),
        }
    }

    #[test]
    fn test_empty_baseline_returns_input_unchanged() {
        let pkg = make_pkg("pkg-a", "1.0.0", vec![make_vuln("CVE-2024-001")]);
        let baseline = VulnerabilityBaseline::new();
        let (kept, count) = BaselineFilter::apply(vec![pkg], &baseline);

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].vulnerabilities().len(), 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_exact_match_suppressed() {
        let pkg = make_pkg(
            "requests",
            "2.31.0",
            vec![make_vuln("CVE-2024-001"), make_vuln("CVE-2024-002")],
        );
        let baseline =
            VulnerabilityBaseline::from_entries(vec![entry("requests", "2.31.0", "CVE-2024-001")]);

        let (kept, count) = BaselineFilter::apply(vec![pkg], &baseline);

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].vulnerabilities().len(), 1);
        assert_eq!(kept[0].vulnerabilities()[0].id(), "CVE-2024-002");
        assert_eq!(count, 1);
    }

    #[test]
    fn test_version_mismatch_kept() {
        let pkg = make_pkg("requests", "2.32.0", vec![make_vuln("CVE-2024-001")]);
        let baseline =
            VulnerabilityBaseline::from_entries(vec![entry("requests", "2.31.0", "CVE-2024-001")]);

        let (kept, count) = BaselineFilter::apply(vec![pkg], &baseline);

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].vulnerabilities()[0].id(), "CVE-2024-001");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_id_mismatch_kept() {
        let pkg = make_pkg("requests", "2.31.0", vec![make_vuln("CVE-2024-999")]);
        let baseline =
            VulnerabilityBaseline::from_entries(vec![entry("requests", "2.31.0", "CVE-2024-001")]);

        let (kept, count) = BaselineFilter::apply(vec![pkg], &baseline);

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].vulnerabilities()[0].id(), "CVE-2024-999");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_package_mismatch_kept() {
        let pkg = make_pkg("flask", "2.31.0", vec![make_vuln("CVE-2024-001")]);
        let baseline =
            VulnerabilityBaseline::from_entries(vec![entry("requests", "2.31.0", "CVE-2024-001")]);

        let (kept, count) = BaselineFilter::apply(vec![pkg], &baseline);

        assert_eq!(kept.len(), 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_partially_suppressed_package_keeps_remaining() {
        let pkg = make_pkg(
            "requests",
            "2.31.0",
            vec![
                make_vuln("CVE-2024-001"),
                make_vuln("CVE-2024-002"),
                make_vuln("CVE-2024-003"),
            ],
        );
        let baseline = VulnerabilityBaseline::from_entries(vec![
            entry("requests", "2.31.0", "CVE-2024-001"),
            entry("requests", "2.31.0", "CVE-2024-003"),
        ]);

        let (kept, count) = BaselineFilter::apply(vec![pkg], &baseline);

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].vulnerabilities().len(), 1);
        assert_eq!(kept[0].vulnerabilities()[0].id(), "CVE-2024-002");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_fully_suppressed_package_removed() {
        let pkg = make_pkg(
            "requests",
            "2.31.0",
            vec![make_vuln("CVE-2024-001"), make_vuln("CVE-2024-002")],
        );
        let baseline = VulnerabilityBaseline::from_entries(vec![
            entry("requests", "2.31.0", "CVE-2024-001"),
            entry("requests", "2.31.0", "CVE-2024-002"),
        ]);

        let (kept, count) = BaselineFilter::apply(vec![pkg], &baseline);

        assert!(kept.is_empty());
        assert_eq!(count, 2);
    }

    #[test]
    fn test_multiple_packages() {
        let pkgs = vec![
            make_pkg("requests", "2.31.0", vec![make_vuln("CVE-2024-001")]),
            make_pkg(
                "flask",
                "2.3.0",
                vec![make_vuln("CVE-2024-002"), make_vuln("CVE-2024-003")],
            ),
        ];
        let baseline = VulnerabilityBaseline::from_entries(vec![
            entry("requests", "2.31.0", "CVE-2024-001"),
            entry("flask", "2.3.0", "CVE-2024-002"),
        ]);

        let (kept, count) = BaselineFilter::apply(pkgs, &baseline);

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].package_name(), "flask");
        assert_eq!(kept[0].vulnerabilities().len(), 1);
        assert_eq!(kept[0].vulnerabilities()[0].id(), "CVE-2024-003");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_from_report_round_trip_suppresses_all() {
        let report = vec![
            make_pkg("requests", "2.31.0", vec![make_vuln("CVE-2024-001")]),
            make_pkg("flask", "2.3.0", vec![make_vuln("CVE-2024-002")]),
        ];

        let baseline = VulnerabilityBaseline::from_report(&report);
        let (kept, count) = BaselineFilter::apply(report, &baseline);

        assert!(kept.is_empty());
        assert_eq!(count, 2);
    }
}
