use super::super::vulnerability::PackageVulnerabilities;
use crate::config::IgnoreCve;

/// A single CVE that was excluded from a vulnerability report by the ignore list.
///
/// Pure data, no I/O: rendering/localizing this record (e.g. printing a warning)
/// is the responsibility of the application or CLI layer, which has `Locale`/
/// `Messages` in scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoredCveRecord {
    /// The CVE/vulnerability identifier that was ignored (e.g. "CVE-2024-001")
    pub cve_id: String,
    /// The name of the package the ignored vulnerability was reported against
    pub package_name: String,
    /// The reason the CVE was ignored, if one was provided in the config
    pub reason: Option<String>,
}

/// Domain service for filtering ignored CVEs from vulnerability results
pub struct CveFilter;

impl CveFilter {
    /// Filters out ignored CVEs from vulnerability results
    ///
    /// Removes vulnerabilities whose IDs match the ignore list (exact, case-sensitive).
    /// Returns the ignored CVEs as data (`IgnoredCveRecord`) rather than printing
    /// anything — the domain layer performs no I/O; the caller decides whether and how
    /// to report them.
    ///
    /// # Arguments
    /// * `vulnerabilities` - List of package vulnerabilities to filter
    /// * `ignore_cves` - List of CVE entries to ignore
    ///
    /// # Returns
    /// A tuple of:
    /// * Filtered list with ignored CVEs removed (packages with no remaining vulns are dropped)
    /// * The list of `IgnoredCveRecord`s describing every CVE that was ignored
    pub fn apply(
        vulnerabilities: Vec<PackageVulnerabilities>,
        ignore_cves: &[IgnoreCve],
    ) -> (Vec<PackageVulnerabilities>, Vec<IgnoredCveRecord>) {
        if ignore_cves.is_empty() {
            return (vulnerabilities, Vec::new());
        }

        let ignore_ids: std::collections::HashSet<&str> =
            ignore_cves.iter().map(|c| c.id.as_str()).collect();

        let mut result = Vec::new();
        let mut ignored_records = Vec::new();

        for pkg_vulns in vulnerabilities {
            let mut kept = Vec::new();

            for vuln in pkg_vulns.vulnerabilities() {
                if ignore_ids.contains(vuln.id()) {
                    let reason = ignore_cves
                        .iter()
                        .find(|c| c.id == vuln.id())
                        .and_then(|c| c.reason());

                    ignored_records.push(IgnoredCveRecord {
                        cve_id: vuln.id().to_string(),
                        package_name: pkg_vulns.package_name().to_string(),
                        reason: reason.map(str::to_string),
                    });
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

        (result, ignored_records)
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
        let (kept, ignored) = CveFilter::apply(vec![pkg], &[]);

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].vulnerabilities().len(), 1);
        assert_eq!(kept[0].vulnerabilities()[0].id(), "CVE-2024-001");
        assert!(ignored.is_empty());
    }

    #[test]
    fn test_matching_cve_is_removed() {
        let pkg = make_pkg(
            "pkg-a",
            vec![make_vuln("CVE-2024-001"), make_vuln("CVE-2024-002")],
        );
        let (kept, ignored) = CveFilter::apply(vec![pkg], &[ignore("CVE-2024-001")]);

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].vulnerabilities().len(), 1);
        assert_eq!(kept[0].vulnerabilities()[0].id(), "CVE-2024-002");
        assert_eq!(ignored.len(), 1);
        assert_eq!(ignored[0].cve_id, "CVE-2024-001");
        assert_eq!(ignored[0].package_name, "pkg-a");
        assert_eq!(ignored[0].reason, None);
    }

    #[test]
    fn test_non_matching_cve_is_kept() {
        let pkg = make_pkg("pkg-a", vec![make_vuln("CVE-2024-001")]);
        let (kept, ignored) = CveFilter::apply(vec![pkg], &[ignore("CVE-9999-999")]);

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].vulnerabilities()[0].id(), "CVE-2024-001");
        assert!(ignored.is_empty());
    }

    #[test]
    fn test_matching_is_case_sensitive() {
        let pkg = make_pkg("pkg-a", vec![make_vuln("CVE-2024-001")]);
        // Lowercase should NOT match
        let (kept, ignored) = CveFilter::apply(vec![pkg], &[ignore("cve-2024-001")]);

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].vulnerabilities()[0].id(), "CVE-2024-001");
        assert!(ignored.is_empty());
    }

    #[test]
    fn test_package_with_all_cves_ignored_is_dropped() {
        let pkg = make_pkg(
            "pkg-a",
            vec![make_vuln("CVE-2024-001"), make_vuln("CVE-2024-002")],
        );
        let (kept, ignored) =
            CveFilter::apply(vec![pkg], &[ignore("CVE-2024-001"), ignore("CVE-2024-002")]);

        assert!(kept.is_empty());
        assert_eq!(ignored.len(), 2);
    }

    #[test]
    fn test_cve_ignored_across_multiple_packages() {
        let pkg1 = make_pkg("pkg-a", vec![make_vuln("CVE-2024-001")]);
        let pkg2 = make_pkg(
            "pkg-b",
            vec![make_vuln("CVE-2024-001"), make_vuln("CVE-2024-002")],
        );
        let (kept, ignored) = CveFilter::apply(vec![pkg1, pkg2], &[ignore("CVE-2024-001")]);

        // pkg-a had only CVE-2024-001 → dropped entirely
        // pkg-b retains CVE-2024-002
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].package_name(), "pkg-b");
        assert_eq!(kept[0].vulnerabilities()[0].id(), "CVE-2024-002");

        // Both packages' ignored CVE-2024-001 are recorded, one per package
        assert_eq!(ignored.len(), 2);
        assert_eq!(ignored[0].package_name, "pkg-a");
        assert_eq!(ignored[0].cve_id, "CVE-2024-001");
        assert_eq!(ignored[1].package_name, "pkg-b");
        assert_eq!(ignored[1].cve_id, "CVE-2024-001");
    }

    #[test]
    fn test_ignored_record_carries_reason() {
        let pkg = make_pkg("pkg-a", vec![make_vuln("CVE-2024-001")]);
        let (kept, ignored) = CveFilter::apply(
            vec![pkg],
            &[ignore_with_reason("CVE-2024-001", "False positive")],
        );

        assert!(kept.is_empty());
        assert_eq!(ignored.len(), 1);
        assert_eq!(ignored[0].cve_id, "CVE-2024-001");
        assert_eq!(ignored[0].package_name, "pkg-a");
        assert_eq!(ignored[0].reason.as_deref(), Some("False positive"));
    }

    #[test]
    fn test_ignored_record_has_no_reason() {
        let pkg = make_pkg("pkg-a", vec![make_vuln("CVE-2024-001")]);
        let (kept, ignored) = CveFilter::apply(vec![pkg], &[ignore("CVE-2024-001")]);

        assert!(kept.is_empty());
        assert_eq!(ignored.len(), 1);
        assert_eq!(ignored[0].cve_id, "CVE-2024-001");
        assert_eq!(ignored[0].package_name, "pkg-a");
        assert_eq!(ignored[0].reason, None);
    }
}
