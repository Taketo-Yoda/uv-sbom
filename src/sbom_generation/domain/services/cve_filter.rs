use super::super::vulnerability::PackageVulnerabilities;
use crate::config::IgnoreCve;

/// Domain service for filtering ignored CVEs from vulnerability results
pub struct CveFilter;

impl CveFilter {
    /// Filters out ignored CVEs from vulnerability results
    ///
    /// Removes vulnerabilities whose IDs match the ignore list (exact, case-sensitive).
    /// Logs each ignored CVE to stderr for transparency.
    ///
    /// # Arguments
    /// * `vulnerabilities` - List of package vulnerabilities to filter
    /// * `ignore_cves` - List of CVE entries to ignore
    ///
    /// # Returns
    /// Filtered list with ignored CVEs removed (packages with no remaining vulns are dropped)
    pub fn apply(
        vulnerabilities: Vec<PackageVulnerabilities>,
        ignore_cves: &[IgnoreCve],
    ) -> Vec<PackageVulnerabilities> {
        if ignore_cves.is_empty() {
            return vulnerabilities;
        }

        let ignore_ids: std::collections::HashSet<&str> =
            ignore_cves.iter().map(|c| c.id.as_str()).collect();

        let mut result = Vec::new();

        for pkg_vulns in vulnerabilities {
            let mut kept = Vec::new();

            for vuln in pkg_vulns.vulnerabilities() {
                if ignore_ids.contains(vuln.id()) {
                    let reason = ignore_cves
                        .iter()
                        .find(|c| c.id == vuln.id())
                        .and_then(|c| c.reason());

                    match reason {
                        Some(r) => eprintln!(
                            "⚠ Ignored {} for package {} (reason: {})",
                            vuln.id(),
                            pkg_vulns.package_name(),
                            r
                        ),
                        None => eprintln!(
                            "⚠ Ignored {} for package {} (no reason provided)",
                            vuln.id(),
                            pkg_vulns.package_name()
                        ),
                    }
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

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IgnoreCve;
    use crate::sbom_generation::domain::vulnerability::{
        PackageVulnerabilities, Severity, Vulnerability,
    };

    fn make_vuln(id: &str) -> Vulnerability {
        Vulnerability::new(id.to_string(), None, Severity::High, None, None).unwrap()
    }

    fn make_pkg(name: &str, vulns: Vec<Vulnerability>) -> PackageVulnerabilities {
        PackageVulnerabilities::new(name.to_string(), "1.0.0".to_string(), vulns)
    }

    fn ignore(id: &str) -> IgnoreCve {
        IgnoreCve {
            id: id.to_string(),
            reason: None,
        }
    }

    fn ignore_with_reason(id: &str, reason: &str) -> IgnoreCve {
        IgnoreCve {
            id: id.to_string(),
            reason: Some(reason.to_string()),
        }
    }

    #[test]
    fn test_empty_ignore_list_returns_input_unchanged() {
        let pkg = make_pkg("pkg-a", vec![make_vuln("CVE-2024-001")]);
        let result = CveFilter::apply(vec![pkg], &[]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].vulnerabilities().len(), 1);
        assert_eq!(result[0].vulnerabilities()[0].id(), "CVE-2024-001");
    }

    #[test]
    fn test_matching_cve_is_removed() {
        let pkg = make_pkg(
            "pkg-a",
            vec![make_vuln("CVE-2024-001"), make_vuln("CVE-2024-002")],
        );
        let result = CveFilter::apply(vec![pkg], &[ignore("CVE-2024-001")]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].vulnerabilities().len(), 1);
        assert_eq!(result[0].vulnerabilities()[0].id(), "CVE-2024-002");
    }

    #[test]
    fn test_non_matching_cve_is_kept() {
        let pkg = make_pkg("pkg-a", vec![make_vuln("CVE-2024-001")]);
        let result = CveFilter::apply(vec![pkg], &[ignore("CVE-9999-999")]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].vulnerabilities()[0].id(), "CVE-2024-001");
    }

    #[test]
    fn test_matching_is_case_sensitive() {
        let pkg = make_pkg("pkg-a", vec![make_vuln("CVE-2024-001")]);
        // Lowercase should NOT match
        let result = CveFilter::apply(vec![pkg], &[ignore("cve-2024-001")]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].vulnerabilities()[0].id(), "CVE-2024-001");
    }

    #[test]
    fn test_package_with_all_cves_ignored_is_dropped() {
        let pkg = make_pkg(
            "pkg-a",
            vec![make_vuln("CVE-2024-001"), make_vuln("CVE-2024-002")],
        );
        let result = CveFilter::apply(vec![pkg], &[ignore("CVE-2024-001"), ignore("CVE-2024-002")]);

        assert!(result.is_empty());
    }

    #[test]
    fn test_cve_ignored_across_multiple_packages() {
        let pkg1 = make_pkg("pkg-a", vec![make_vuln("CVE-2024-001")]);
        let pkg2 = make_pkg(
            "pkg-b",
            vec![make_vuln("CVE-2024-001"), make_vuln("CVE-2024-002")],
        );
        let result = CveFilter::apply(vec![pkg1, pkg2], &[ignore("CVE-2024-001")]);

        // pkg-a had only CVE-2024-001 → dropped entirely
        // pkg-b retains CVE-2024-002
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].package_name(), "pkg-b");
        assert_eq!(result[0].vulnerabilities()[0].id(), "CVE-2024-002");
    }

    #[test]
    fn test_ignore_with_reason_does_not_panic() {
        let pkg = make_pkg("pkg-a", vec![make_vuln("CVE-2024-001")]);
        let result = CveFilter::apply(
            vec![pkg],
            &[ignore_with_reason("CVE-2024-001", "False positive")],
        );

        assert!(result.is_empty());
    }

    #[test]
    fn test_ignore_without_reason_does_not_panic() {
        let pkg = make_pkg("pkg-a", vec![make_vuln("CVE-2024-001")]);
        let result = CveFilter::apply(vec![pkg], &[ignore("CVE-2024-001")]);

        assert!(result.is_empty());
    }
}
