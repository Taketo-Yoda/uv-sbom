use crate::application::dto::{VulnerabilityCheckRequest, VulnerabilityCheckResponse};
use crate::ports::outbound::{ProgressCallback, VulnerabilityRepository};
use crate::sbom_generation::domain::services::VulnerabilityChecker;
use crate::sbom_generation::domain::{Package, PackageVulnerabilities};
use crate::shared::Result;

/// CheckVulnerabilitiesUseCase - Use case for checking vulnerabilities with threshold support
///
/// This use case orchestrates the vulnerability checking workflow:
/// 1. Filters out excluded packages
/// 2. Fetches vulnerabilities from the repository
/// 3. Applies threshold evaluation using VulnerabilityChecker
/// 4. Returns a structured response
///
/// # Type Parameters
/// * `R` - VulnerabilityRepository implementation
pub struct CheckVulnerabilitiesUseCase<R: VulnerabilityRepository> {
    vulnerability_repository: R,
}

impl<R: VulnerabilityRepository> CheckVulnerabilitiesUseCase<R> {
    /// Creates a new CheckVulnerabilitiesUseCase with injected repository
    ///
    /// # Arguments
    /// * `vulnerability_repository` - Repository for fetching vulnerability data
    pub fn new(vulnerability_repository: R) -> Self {
        Self {
            vulnerability_repository,
        }
    }

    /// Executes the vulnerability check use case
    ///
    /// # Arguments
    /// * `request` - Request containing packages, threshold, and exclusions
    ///
    /// # Returns
    /// VulnerabilityCheckResponse with check results and threshold exceeded flag
    #[allow(dead_code)]
    pub async fn execute(
        &self,
        request: VulnerabilityCheckRequest,
    ) -> Result<VulnerabilityCheckResponse> {
        // Step 1: Filter out excluded packages
        let filtered_packages =
            self.filter_excluded_packages(request.packages, &request.excluded_packages);

        // Step 2: Fetch vulnerabilities from repository
        let vulnerabilities = self
            .vulnerability_repository
            .fetch_vulnerabilities(filtered_packages)
            .await?;

        // Step 3: Apply threshold evaluation using VulnerabilityChecker
        let check_result = VulnerabilityChecker::check(vulnerabilities, request.threshold);

        // Step 4: Build and return response
        Ok(VulnerabilityCheckResponse::from_result(check_result))
    }

    /// Fetches vulnerabilities for packages without threshold evaluation
    ///
    /// This method is used when only the raw vulnerability data is needed,
    /// without applying threshold evaluation. It delegates to the repository
    /// for the actual vulnerability fetching.
    ///
    /// # Arguments
    /// * `packages` - Packages to check for vulnerabilities
    ///
    /// # Returns
    /// Vector of PackageVulnerabilities for packages that have vulnerabilities
    #[allow(dead_code)]
    pub async fn fetch_vulnerabilities(
        &self,
        packages: Vec<Package>,
    ) -> Result<Vec<PackageVulnerabilities>> {
        self.vulnerability_repository
            .fetch_vulnerabilities(packages)
            .await
    }

    /// Fetches vulnerabilities with progress reporting
    ///
    /// This method is used when progress feedback is needed (e.g., CLI with progress bar).
    /// It delegates to the repository's progress-aware method.
    ///
    /// # Arguments
    /// * `packages` - Packages to check for vulnerabilities
    /// * `progress_callback` - Callback for progress updates (current, total)
    ///
    /// # Returns
    /// Vector of PackageVulnerabilities for packages that have vulnerabilities
    pub async fn fetch_vulnerabilities_with_progress(
        &self,
        packages: Vec<Package>,
        progress_callback: ProgressCallback<'static>,
    ) -> Result<Vec<PackageVulnerabilities>> {
        self.vulnerability_repository
            .fetch_vulnerabilities_with_progress(packages, progress_callback)
            .await
    }

    /// Filters out packages that are in the exclusion list
    ///
    /// # Arguments
    /// * `packages` - Original list of packages
    /// * `excluded_packages` - List of package names to exclude
    ///
    /// # Returns
    /// Filtered list of packages
    #[allow(dead_code)]
    fn filter_excluded_packages(
        &self,
        packages: Vec<Package>,
        excluded_packages: &[String],
    ) -> Vec<Package> {
        if excluded_packages.is_empty() {
            return packages;
        }

        packages
            .into_iter()
            .filter(|pkg| !excluded_packages.contains(&pkg.name().to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom_generation::domain::services::ThresholdConfig;
    use crate::sbom_generation::domain::vulnerability::{CvssScore, Severity};
    use crate::sbom_generation::domain::{PackageVulnerabilities, Vulnerability};
    use async_trait::async_trait;

    struct MockVulnerabilityRepository {
        vulnerabilities: Vec<PackageVulnerabilities>,
    }

    #[async_trait]
    impl VulnerabilityRepository for MockVulnerabilityRepository {
        async fn fetch_vulnerabilities(
            &self,
            _packages: Vec<Package>,
        ) -> Result<Vec<PackageVulnerabilities>> {
            Ok(self.vulnerabilities.clone())
        }
    }

    fn create_test_package(name: &str, version: &str) -> Package {
        Package::new(name.to_string(), version.to_string()).unwrap()
    }

    fn create_test_vulnerability(id: &str, severity: Severity, cvss: Option<f32>) -> Vulnerability {
        let cvss_score = cvss.map(|score| CvssScore::new(score).unwrap());
        Vulnerability::new(
            id.to_string(),
            cvss_score,
            severity,
            None, // fixed_version
            Some(format!("Test vulnerability {}", id)),
        )
        .unwrap()
    }

    fn create_test_pkg_vulns(
        name: &str,
        version: &str,
        vulns: Vec<Vulnerability>,
    ) -> PackageVulnerabilities {
        PackageVulnerabilities::new(name.to_string(), version.to_string(), vulns)
    }

    #[tokio::test]
    async fn test_execute_with_no_vulnerabilities() {
        let repo = MockVulnerabilityRepository {
            vulnerabilities: vec![],
        };
        let use_case = CheckVulnerabilitiesUseCase::new(repo);

        let request = VulnerabilityCheckRequest::new(
            vec![create_test_package("requests", "2.31.0")],
            ThresholdConfig::None,
            vec![],
        );

        let response = use_case.execute(request).await.unwrap();

        assert!(!response.has_threshold_exceeded);
        assert!(response.result.above_threshold.is_empty());
        assert!(response.result.below_threshold.is_empty());
    }

    #[tokio::test]
    async fn test_execute_with_vulnerabilities_above_threshold() {
        let vuln = create_test_vulnerability("CVE-2024-0001", Severity::Critical, Some(9.8));
        let pkg_vulns = create_test_pkg_vulns("requests", "2.31.0", vec![vuln]);

        let repo = MockVulnerabilityRepository {
            vulnerabilities: vec![pkg_vulns],
        };
        let use_case = CheckVulnerabilitiesUseCase::new(repo);

        let request = VulnerabilityCheckRequest::new(
            vec![create_test_package("requests", "2.31.0")],
            ThresholdConfig::Severity(Severity::High),
            vec![],
        );

        let response = use_case.execute(request).await.unwrap();

        assert!(response.has_threshold_exceeded);
        assert_eq!(response.result.above_threshold.len(), 1);
    }

    #[tokio::test]
    async fn test_execute_with_vulnerabilities_below_threshold() {
        let vuln = create_test_vulnerability("CVE-2024-0002", Severity::Low, Some(2.0));
        let pkg_vulns = create_test_pkg_vulns("urllib3", "1.26.0", vec![vuln]);

        let repo = MockVulnerabilityRepository {
            vulnerabilities: vec![pkg_vulns],
        };
        let use_case = CheckVulnerabilitiesUseCase::new(repo);

        let request = VulnerabilityCheckRequest::new(
            vec![create_test_package("urllib3", "1.26.0")],
            ThresholdConfig::Severity(Severity::High),
            vec![],
        );

        let response = use_case.execute(request).await.unwrap();

        assert!(!response.has_threshold_exceeded);
        assert!(response.result.above_threshold.is_empty());
        assert_eq!(response.result.below_threshold.len(), 1);
    }

    #[tokio::test]
    async fn test_execute_with_cvss_threshold() {
        let vuln = create_test_vulnerability("CVE-2024-0003", Severity::High, Some(7.5));
        let pkg_vulns = create_test_pkg_vulns("certifi", "2024.8.30", vec![vuln]);

        let repo = MockVulnerabilityRepository {
            vulnerabilities: vec![pkg_vulns],
        };
        let use_case = CheckVulnerabilitiesUseCase::new(repo);

        let request = VulnerabilityCheckRequest::new(
            vec![create_test_package("certifi", "2024.8.30")],
            ThresholdConfig::Cvss(7.0),
            vec![],
        );

        let response = use_case.execute(request).await.unwrap();

        assert!(response.has_threshold_exceeded);
        assert_eq!(response.result.above_threshold.len(), 1);
    }

    #[tokio::test]
    async fn test_execute_filters_excluded_packages() {
        let repo = MockVulnerabilityRepository {
            vulnerabilities: vec![],
        };
        let use_case = CheckVulnerabilitiesUseCase::new(repo);

        let request = VulnerabilityCheckRequest::new(
            vec![
                create_test_package("requests", "2.31.0"),
                create_test_package("urllib3", "1.26.0"),
                create_test_package("certifi", "2024.8.30"),
            ],
            ThresholdConfig::None,
            vec!["urllib3".to_string()],
        );

        let response = use_case.execute(request).await.unwrap();

        // The repository receives filtered packages (without urllib3)
        assert!(!response.has_threshold_exceeded);
    }

    #[test]
    fn test_filter_excluded_packages_empty_exclusions() {
        let repo = MockVulnerabilityRepository {
            vulnerabilities: vec![],
        };
        let use_case = CheckVulnerabilitiesUseCase::new(repo);

        let packages = vec![
            create_test_package("pkg1", "1.0.0"),
            create_test_package("pkg2", "2.0.0"),
        ];

        let filtered = use_case.filter_excluded_packages(packages.clone(), &[]);

        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filter_excluded_packages_with_exclusions() {
        let repo = MockVulnerabilityRepository {
            vulnerabilities: vec![],
        };
        let use_case = CheckVulnerabilitiesUseCase::new(repo);

        let packages = vec![
            create_test_package("pkg1", "1.0.0"),
            create_test_package("pkg2", "2.0.0"),
            create_test_package("pkg3", "3.0.0"),
        ];

        let filtered = use_case.filter_excluded_packages(packages, &["pkg2".to_string()]);

        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|p| p.name() != "pkg2"));
    }

    #[test]
    fn test_filter_excluded_packages_all_excluded() {
        let repo = MockVulnerabilityRepository {
            vulnerabilities: vec![],
        };
        let use_case = CheckVulnerabilitiesUseCase::new(repo);

        let packages = vec![create_test_package("pkg1", "1.0.0")];

        let filtered = use_case.filter_excluded_packages(packages, &["pkg1".to_string()]);

        assert!(filtered.is_empty());
    }
}
