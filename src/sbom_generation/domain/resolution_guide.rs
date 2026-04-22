use super::vulnerability::Severity;

/// Represents a resolution entry for a single vulnerable transitive dependency
#[derive(Debug, Clone)]
pub struct ResolutionEntry {
    /// Name of the vulnerable transitive package
    vulnerable_package: String,
    /// Current installed version of the vulnerable package
    current_version: String,
    /// Version that fixes the vulnerability (from OSV)
    fixed_version: Option<String>,
    /// Severity of the vulnerability
    severity: Severity,
    /// Vulnerability ID (e.g., CVE-2024-XXXXX)
    vulnerability_id: String,
    /// List of direct dependencies that introduce this vulnerable package
    introduced_by: Vec<IntroducedBy>,
    /// Full dependency chains from direct deps to the vulnerable package.
    /// Each inner Vec is [direct_dep, ..., vulnerable_package].
    /// Empty if introduced directly (one-hop) or if the target is a direct dependency.
    dependency_chains: Vec<Vec<String>>,
}

impl ResolutionEntry {
    pub fn new(
        vulnerable_package: String,
        current_version: String,
        fixed_version: Option<String>,
        severity: Severity,
        vulnerability_id: String,
        introduced_by: Vec<IntroducedBy>,
        dependency_chains: Vec<Vec<String>>,
    ) -> Self {
        Self {
            vulnerable_package,
            current_version,
            fixed_version,
            severity,
            vulnerability_id,
            introduced_by,
            dependency_chains,
        }
    }

    pub fn vulnerable_package(&self) -> &str {
        &self.vulnerable_package
    }

    pub fn current_version(&self) -> &str {
        &self.current_version
    }

    pub fn fixed_version(&self) -> Option<&str> {
        self.fixed_version.as_deref()
    }

    pub fn severity(&self) -> Severity {
        self.severity
    }

    pub fn vulnerability_id(&self) -> &str {
        &self.vulnerability_id
    }

    pub fn introduced_by(&self) -> &[IntroducedBy] {
        &self.introduced_by
    }

    pub fn dependency_chains(&self) -> &[Vec<String>] {
        &self.dependency_chains
    }
}

/// Represents a direct dependency that introduces a vulnerable transitive dep
#[derive(Debug, Clone)]
pub struct IntroducedBy {
    /// Name of the direct dependency
    package_name: String,
    /// Current version of the direct dependency
    version: String,
}

impl IntroducedBy {
    pub fn new(package_name: String, version: String) -> Self {
        Self {
            package_name,
            version,
        }
    }

    pub fn package_name(&self) -> &str {
        &self.package_name
    }

    pub fn version(&self) -> &str {
        &self.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_introduced_by_new() {
        let entry = IntroducedBy::new("requests".to_string(), "2.28.0".to_string());

        assert_eq!(entry.package_name(), "requests");
        assert_eq!(entry.version(), "2.28.0");
    }

    #[test]
    fn test_resolution_entry_new() {
        let introduced = vec![
            IntroducedBy::new("requests".to_string(), "2.28.0".to_string()),
            IntroducedBy::new("httpx".to_string(), "0.23.0".to_string()),
        ];
        let chains = vec![
            vec!["requests".to_string(), "urllib3".to_string()],
            vec!["httpx".to_string(), "urllib3".to_string()],
        ];

        let entry = ResolutionEntry::new(
            "urllib3".to_string(),
            "1.26.5".to_string(),
            Some("1.26.18".to_string()),
            Severity::High,
            "CVE-2023-43804".to_string(),
            introduced,
            chains,
        );

        assert_eq!(entry.vulnerable_package(), "urllib3");
        assert_eq!(entry.current_version(), "1.26.5");
        assert_eq!(entry.fixed_version(), Some("1.26.18"));
        assert_eq!(entry.severity(), Severity::High);
        assert_eq!(entry.vulnerability_id(), "CVE-2023-43804");
        assert_eq!(entry.introduced_by().len(), 2);
        assert_eq!(entry.introduced_by()[0].package_name(), "requests");
        assert_eq!(entry.introduced_by()[1].package_name(), "httpx");
        assert_eq!(entry.dependency_chains().len(), 2);
        assert_eq!(entry.dependency_chains()[0], ["requests", "urllib3"]);
        assert_eq!(entry.dependency_chains()[1], ["httpx", "urllib3"]);
    }

    #[test]
    fn test_resolution_entry_without_fixed_version() {
        let entry = ResolutionEntry::new(
            "vulnerable-pkg".to_string(),
            "0.1.0".to_string(),
            None,
            Severity::Critical,
            "CVE-2024-0001".to_string(),
            vec![IntroducedBy::new(
                "parent-pkg".to_string(),
                "1.0.0".to_string(),
            )],
            vec![],
        );

        assert_eq!(entry.fixed_version(), None);
        assert_eq!(entry.severity(), Severity::Critical);
    }

    #[test]
    fn test_resolution_entry_empty_introduced_by() {
        let entry = ResolutionEntry::new(
            "some-pkg".to_string(),
            "1.0.0".to_string(),
            Some("1.0.1".to_string()),
            Severity::Medium,
            "GHSA-xxxx-yyyy-zzzz".to_string(),
            vec![],
            vec![],
        );

        assert!(entry.introduced_by().is_empty());
        assert!(entry.dependency_chains().is_empty());
    }

    #[test]
    fn test_resolution_entry_dependency_chains_accessor() {
        let chains = vec![
            vec!["a".to_string(), "b".to_string(), "vuln".to_string()],
            vec!["c".to_string(), "vuln".to_string()],
        ];
        let entry = ResolutionEntry::new(
            "vuln".to_string(),
            "1.0.0".to_string(),
            None,
            Severity::Low,
            "CVE-2024-0002".to_string(),
            vec![],
            chains.clone(),
        );

        assert_eq!(entry.dependency_chains(), chains.as_slice());
    }
}
