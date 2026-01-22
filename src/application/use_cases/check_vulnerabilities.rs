use crate::ports::outbound::VulnerabilityRepository;
use crate::sbom_generation::domain::{Package, PackageVulnerabilities};
use crate::shared::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// CheckVulnerabilitiesUseCase - Use case for checking vulnerabilities
///
/// This use case provides vulnerability fetching functionality with progress reporting.
/// It encapsulates the progress bar display logic and delegates to the VulnerabilityRepository
/// for the actual fetching.
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

    /// Fetches vulnerabilities for packages with progress bar display
    ///
    /// This method handles the progress bar UI and delegates to the repository
    /// for actual vulnerability fetching. The progress bar shows:
    /// - A spinner during the batch query phase
    /// - A progress bar during individual vulnerability detail fetching
    ///
    /// # Arguments
    /// * `packages` - Packages to check for vulnerabilities
    ///
    /// # Returns
    /// Vector of PackageVulnerabilities for packages that have vulnerabilities
    pub async fn check_with_progress(
        &self,
        packages: Vec<Package>,
    ) -> Result<Vec<PackageVulnerabilities>> {
        // Create atomic counters for thread-safe progress sharing
        let progress_current = Arc::new(AtomicUsize::new(0));
        let progress_total = Arc::new(AtomicUsize::new(0));
        let is_done = Arc::new(AtomicBool::new(false));

        // Clone references for the progress bar update thread
        let current_clone = progress_current.clone();
        let total_clone = progress_total.clone();
        let done_clone = is_done.clone();

        // Spawn a thread to update the progress bar
        let progress_handle = thread::spawn(move || {
            let pb = ProgressBar::new(0);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("   {spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} - {msg}")
                    .expect("Failed to set progress bar template")
                    .progress_chars("=>-"),
            );
            pb.set_message("Fetching vulnerability details...");

            // Poll for updates until done
            while !done_clone.load(Ordering::Relaxed) {
                let current = current_clone.load(Ordering::Relaxed);
                let total = total_clone.load(Ordering::Relaxed);

                if total > 0 {
                    pb.set_length(total as u64);
                    pb.set_position(current as u64);
                } else {
                    // Still in batch query phase - show spinner
                    pb.tick();
                }

                thread::sleep(Duration::from_millis(50));
            }

            pb.finish_and_clear();
        });

        // Create progress callback that updates atomic counters
        let progress_callback: Box<dyn Fn(usize, usize) + Send> =
            Box::new(move |current: usize, total: usize| {
                progress_current.store(current, Ordering::Relaxed);
                progress_total.store(total, Ordering::Relaxed);
            });

        // Fetch vulnerabilities with progress reporting
        let vulnerabilities = self
            .vulnerability_repository
            .fetch_vulnerabilities_with_progress(packages, progress_callback)
            .await?;

        // Signal completion and wait for progress bar thread
        is_done.store(true, Ordering::Relaxed);
        let _ = progress_handle.join();

        Ok(vulnerabilities)
    }

    /// Returns a summary of vulnerabilities found
    ///
    /// # Arguments
    /// * `vulnerabilities` - List of package vulnerabilities
    ///
    /// # Returns
    /// Tuple of (total_vulnerabilities, affected_packages_count)
    pub fn summarize(vulnerabilities: &[PackageVulnerabilities]) -> (usize, usize) {
        let total_vulns: usize = vulnerabilities
            .iter()
            .map(|v| v.vulnerabilities().len())
            .sum();
        let affected_packages = vulnerabilities.len();
        (total_vulns, affected_packages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::outbound::ProgressCallback;
    use crate::sbom_generation::domain::vulnerability::{CvssScore, Severity, Vulnerability};
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

        async fn fetch_vulnerabilities_with_progress(
            &self,
            _packages: Vec<Package>,
            _progress_callback: ProgressCallback<'static>,
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
            None,
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

    // ========== summarize() tests ==========

    #[test]
    fn test_summarize_empty() {
        let (total, packages) =
            CheckVulnerabilitiesUseCase::<MockVulnerabilityRepository>::summarize(&[]);
        assert_eq!(total, 0);
        assert_eq!(packages, 0);
    }

    #[test]
    fn test_summarize_single_package_single_vuln() {
        let vuln = create_test_vulnerability("CVE-2024-0001", Severity::High, Some(7.5));
        let pkg_vulns = create_test_pkg_vulns("requests", "2.31.0", vec![vuln]);

        let (total, packages) =
            CheckVulnerabilitiesUseCase::<MockVulnerabilityRepository>::summarize(&[pkg_vulns]);
        assert_eq!(total, 1);
        assert_eq!(packages, 1);
    }

    #[test]
    fn test_summarize_single_package_multiple_vulns() {
        let vuln1 = create_test_vulnerability("CVE-2024-0001", Severity::High, Some(7.5));
        let vuln2 = create_test_vulnerability("CVE-2024-0002", Severity::Critical, Some(9.8));
        let vuln3 = create_test_vulnerability("CVE-2024-0003", Severity::Low, Some(2.0));
        let pkg_vulns = create_test_pkg_vulns("requests", "2.31.0", vec![vuln1, vuln2, vuln3]);

        let (total, packages) =
            CheckVulnerabilitiesUseCase::<MockVulnerabilityRepository>::summarize(&[pkg_vulns]);
        assert_eq!(total, 3);
        assert_eq!(packages, 1);
    }

    #[test]
    fn test_summarize_multiple_packages() {
        let vuln1 = create_test_vulnerability("CVE-2024-0001", Severity::High, Some(7.5));
        let vuln2 = create_test_vulnerability("CVE-2024-0002", Severity::Critical, Some(9.8));
        let pkg_vulns1 = create_test_pkg_vulns("requests", "2.31.0", vec![vuln1]);
        let pkg_vulns2 = create_test_pkg_vulns("urllib3", "1.26.0", vec![vuln2]);

        let (total, packages) =
            CheckVulnerabilitiesUseCase::<MockVulnerabilityRepository>::summarize(&[
                pkg_vulns1, pkg_vulns2,
            ]);
        assert_eq!(total, 2);
        assert_eq!(packages, 2);
    }

    // ========== check_with_progress() tests ==========

    #[tokio::test]
    async fn test_check_with_progress_no_vulnerabilities() {
        let repo = MockVulnerabilityRepository {
            vulnerabilities: vec![],
        };
        let use_case = CheckVulnerabilitiesUseCase::new(repo);

        let packages = vec![create_test_package("requests", "2.31.0")];
        let result = use_case.check_with_progress(packages).await.unwrap();

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_check_with_progress_with_vulnerabilities() {
        let vuln = create_test_vulnerability("CVE-2024-0001", Severity::Critical, Some(9.8));
        let pkg_vulns = create_test_pkg_vulns("requests", "2.31.0", vec![vuln]);

        let repo = MockVulnerabilityRepository {
            vulnerabilities: vec![pkg_vulns],
        };
        let use_case = CheckVulnerabilitiesUseCase::new(repo);

        let packages = vec![create_test_package("requests", "2.31.0")];
        let result = use_case.check_with_progress(packages).await.unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].package_name(), "requests");
        assert_eq!(result[0].vulnerabilities().len(), 1);
    }

    #[tokio::test]
    async fn test_check_with_progress_multiple_packages() {
        let vuln1 = create_test_vulnerability("CVE-2024-0001", Severity::High, Some(7.5));
        let vuln2 = create_test_vulnerability("CVE-2024-0002", Severity::Critical, Some(9.8));
        let pkg_vulns1 = create_test_pkg_vulns("requests", "2.31.0", vec![vuln1]);
        let pkg_vulns2 = create_test_pkg_vulns("urllib3", "1.26.0", vec![vuln2]);

        let repo = MockVulnerabilityRepository {
            vulnerabilities: vec![pkg_vulns1, pkg_vulns2],
        };
        let use_case = CheckVulnerabilitiesUseCase::new(repo);

        let packages = vec![
            create_test_package("requests", "2.31.0"),
            create_test_package("urllib3", "1.26.0"),
        ];
        let result = use_case.check_with_progress(packages).await.unwrap();

        assert_eq!(result.len(), 2);
    }
}
