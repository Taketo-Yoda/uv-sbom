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
