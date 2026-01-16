use crate::application::dto::{SbomRequest, SbomResponse};
use crate::ports::outbound::{
    EnrichedPackage, LicenseRepository, LockfileReader, ProgressReporter, ProjectConfigReader,
    VulnerabilityRepository,
};
use crate::sbom_generation::domain::{Package, PackageName};
use crate::sbom_generation::services::{DependencyAnalyzer, PackageFilter, SbomGenerator};
use crate::shared::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::runtime::Runtime;

/// Type alias for package list with dependency map
/// Used to simplify complex return types and satisfy clippy::type_complexity
type PackagesWithDependencyMap = (Vec<Package>, std::collections::HashMap<String, Vec<String>>);

/// Rate limiting: Delay between license fetch requests to prevent DoS (milliseconds)
/// This limits requests to ~10 per second (100ms delay = 10 requests/second)
const LICENSE_FETCH_DELAY_MS: u64 = 100;

/// GenerateSbomUseCase - Core use case for SBOM generation
///
/// This use case orchestrates the SBOM generation workflow using
/// generic dependency injection for all infrastructure dependencies.
///
/// # Type Parameters
/// * `LR` - LockfileReader implementation
/// * `PCR` - ProjectConfigReader implementation
/// * `LREPO` - LicenseRepository implementation
/// * `PR` - ProgressReporter implementation
/// * `VREPO` - VulnerabilityRepository implementation (optional)
pub struct GenerateSbomUseCase<LR, PCR, LREPO, PR, VREPO> {
    lockfile_reader: LR,
    project_config_reader: PCR,
    license_repository: LREPO,
    progress_reporter: PR,
    vulnerability_repository: Option<VREPO>,
}

impl<LR, PCR, LREPO, PR, VREPO> GenerateSbomUseCase<LR, PCR, LREPO, PR, VREPO>
where
    LR: LockfileReader,
    PCR: ProjectConfigReader,
    LREPO: LicenseRepository,
    PR: ProgressReporter,
    VREPO: VulnerabilityRepository,
{
    /// Creates a new GenerateSbomUseCase with injected dependencies
    pub fn new(
        lockfile_reader: LR,
        project_config_reader: PCR,
        license_repository: LREPO,
        progress_reporter: PR,
        vulnerability_repository: Option<VREPO>,
    ) -> Self {
        Self {
            lockfile_reader,
            project_config_reader,
            license_repository,
            progress_reporter,
            vulnerability_repository,
        }
    }

    /// Executes the SBOM generation use case
    ///
    /// # Arguments
    /// * `request` - SBOM generation request containing project path and options
    ///
    /// # Returns
    /// SbomResponse containing enriched packages, optional dependency graph, and metadata
    pub fn execute(&self, request: SbomRequest) -> Result<SbomResponse> {
        // Step 1: Read and parse lockfile
        let (packages, dependency_map) = self.read_and_report_lockfile(&request)?;

        // Step 2: Apply exclusion filters
        let (filtered_packages, filtered_dependency_map) =
            self.apply_exclusion_filters(packages, dependency_map, &request)?;

        // Early return for dry-run mode (validation only)
        if request.dry_run {
            return self.build_dry_run_response();
        }

        // Step 3: Analyze dependencies if requested
        let dependency_graph =
            self.analyze_dependencies_if_requested(&request, &filtered_dependency_map)?;

        // Step 4: Enrich packages with license information
        let enriched_packages = self.fetch_license_info(filtered_packages.clone())?;

        // Step 5: CVE check if requested
        let vulnerability_report =
            self.check_vulnerabilities_if_requested(&request, &filtered_packages)?;

        // Step 6: Build and return response
        Ok(self.build_response(enriched_packages, dependency_graph, vulnerability_report))
    }

    /// Reads and parses the lockfile, reporting progress
    ///
    /// # Arguments
    /// * `request` - The SBOM request containing project path
    ///
    /// # Returns
    /// Tuple of (packages, dependency_map)
    fn read_and_report_lockfile(&self, request: &SbomRequest) -> Result<PackagesWithDependencyMap> {
        self.progress_reporter.report(&format!(
            "📖 Loading uv.lock file from: {}",
            request.project_path.display()
        ));

        let (packages, dependency_map) = self
            .lockfile_reader
            .read_and_parse_lockfile(&request.project_path)?;

        self.progress_reporter
            .report(&format!("✅ Detected {} package(s)", packages.len()));

        Ok((packages, dependency_map))
    }

    /// Applies exclusion filters to packages and dependency map
    ///
    /// # Arguments
    /// * `packages` - Original packages from lockfile
    /// * `dependency_map` - Original dependency map
    /// * `request` - The SBOM request containing exclusion patterns
    ///
    /// # Returns
    /// Tuple of (filtered_packages, filtered_dependency_map)
    ///
    /// # Errors
    /// Returns an error if all packages are excluded
    fn apply_exclusion_filters(
        &self,
        packages: Vec<Package>,
        dependency_map: std::collections::HashMap<String, Vec<String>>,
        request: &SbomRequest,
    ) -> Result<PackagesWithDependencyMap> {
        if request.exclude_patterns.is_empty() {
            return Ok((packages, dependency_map));
        }

        let filter = PackageFilter::new(request.exclude_patterns.clone())?;
        let original_count = packages.len();
        let filtered_pkgs = filter.filter_packages(packages);
        let filtered_deps = filter.filter_dependency_map(dependency_map);

        let excluded_count = original_count - filtered_pkgs.len();
        if excluded_count > 0 {
            self.progress_reporter.report(&format!(
                "🚫 Excluded {} package(s) based on filters",
                excluded_count
            ));
        }

        // Check if all packages were excluded
        if filtered_pkgs.is_empty() {
            anyhow::bail!(
                "All {} package(s) were excluded by the provided filters. \
                     The SBOM would be empty. Please adjust your exclusion patterns.",
                original_count
            );
        }

        // Warn about unmatched patterns
        let unmatched_patterns = filter.get_unmatched_patterns();
        for pattern in unmatched_patterns {
            self.progress_reporter.report_error(&format!(
                "⚠️  Warning: Exclude pattern '{}' did not match any dependencies.",
                pattern
            ));
        }

        Ok((filtered_pkgs, filtered_deps))
    }

    /// Builds a response for dry-run mode (validation only)
    fn build_dry_run_response(&self) -> Result<SbomResponse> {
        self.progress_reporter
            .report_completion("Success: Configuration validated. No issues found.");
        let metadata = SbomGenerator::generate_default_metadata(false);
        Ok(SbomResponse::new(vec![], None, metadata, None))
    }

    /// Analyzes dependencies if requested in the SBOM request
    ///
    /// # Arguments
    /// * `request` - The SBOM request
    /// * `dependency_map` - Map of package dependencies
    ///
    /// # Returns
    /// Optional DependencyGraph if analysis was requested
    fn analyze_dependencies_if_requested(
        &self,
        request: &SbomRequest,
        dependency_map: &std::collections::HashMap<String, Vec<String>>,
    ) -> Result<Option<crate::sbom_generation::domain::DependencyGraph>> {
        if !request.include_dependency_info {
            return Ok(None);
        }

        self.progress_reporter
            .report("📊 Parsing dependency information...");

        let project_name = self
            .project_config_reader
            .read_project_name(&request.project_path)?;
        let project_package_name = PackageName::new(project_name)?;

        let graph = DependencyAnalyzer::analyze(&project_package_name, dependency_map)?;

        self.progress_reporter.report(&format!(
            "   - Direct dependencies: {}",
            graph.direct_dependency_count()
        ));
        self.progress_reporter.report(&format!(
            "   - Transitive dependencies: {}",
            graph.transitive_dependency_count()
        ));

        Ok(Some(graph))
    }

    /// Fetches license information for packages
    ///
    /// # Arguments
    /// * `packages` - Packages to enrich with license info
    ///
    /// # Returns
    /// Vector of EnrichedPackage with license information
    fn fetch_license_info(&self, packages: Vec<Package>) -> Result<Vec<EnrichedPackage>> {
        self.progress_reporter
            .report("🔍 Fetching license information...");

        self.enrich_packages_with_licenses(packages)
    }

    /// Checks vulnerabilities if CVE check is requested
    ///
    /// # Arguments
    /// * `request` - The SBOM request
    /// * `packages` - Packages to check for vulnerabilities
    ///
    /// # Returns
    /// Optional vulnerability report
    fn check_vulnerabilities_if_requested(
        &self,
        request: &SbomRequest,
        packages: &[Package],
    ) -> Result<Option<Vec<crate::sbom_generation::domain::PackageVulnerabilities>>> {
        if !request.check_cve {
            return Ok(None);
        }
        self.check_vulnerabilities(packages)
    }

    /// Builds the final SBOM response
    ///
    /// # Arguments
    /// * `enriched_packages` - Packages with license information
    /// * `dependency_graph` - Optional dependency graph
    /// * `vulnerability_report` - Optional vulnerability report
    ///
    /// # Returns
    /// Complete SbomResponse
    fn build_response(
        &self,
        enriched_packages: Vec<EnrichedPackage>,
        dependency_graph: Option<crate::sbom_generation::domain::DependencyGraph>,
        vulnerability_report: Option<Vec<crate::sbom_generation::domain::PackageVulnerabilities>>,
    ) -> SbomResponse {
        let metadata = SbomGenerator::generate_default_metadata(vulnerability_report.is_some());
        SbomResponse::new(
            enriched_packages,
            dependency_graph,
            metadata,
            vulnerability_report,
        )
    }

    /// Enriches packages with license information from the repository
    ///
    /// Security: This method implements rate limiting to prevent DoS attacks
    /// via unbounded PyPI API requests. A delay is added between requests
    /// to limit the rate to approximately 10 requests per second.
    ///
    /// # Note
    /// This method uses a tokio runtime to call async LicenseRepository methods.
    /// This is a temporary bridge until GenerateSbomUseCase is fully async (Issue #59).
    fn enrich_packages_with_licenses(
        &self,
        packages: Vec<Package>,
    ) -> Result<Vec<EnrichedPackage>> {
        let total = packages.len();

        // Create atomic counters for thread-safe progress sharing
        let progress_current = Arc::new(AtomicUsize::new(0));
        let progress_total = Arc::new(AtomicUsize::new(total));
        let is_done = Arc::new(AtomicBool::new(false));

        // Clone references for the progress bar update thread
        let current_clone = progress_current.clone();
        let total_clone = progress_total.clone();
        let done_clone = is_done.clone();

        // Spawn a thread to update the progress bar
        let progress_handle = thread::spawn(move || {
            let pb = ProgressBar::new(total_clone.load(Ordering::Relaxed) as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("   {spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} - {msg}")
                    .expect("Failed to set progress bar template")
                    .progress_chars("=>-"),
            );
            pb.set_message("Fetching license information...");

            // Poll for updates until done
            while !done_clone.load(Ordering::Relaxed) {
                let current = current_clone.load(Ordering::Relaxed);
                pb.set_position(current as u64);
                thread::sleep(Duration::from_millis(50));
            }

            pb.finish_and_clear();
        });

        // Create a tokio runtime to call async methods
        // This is a temporary bridge until GenerateSbomUseCase is fully async (Issue #59)
        let rt = Runtime::new()?;

        // Fetch licenses sequentially with rate limiting (async via block_on)
        // Collect errors to report after async block (since progress_reporter may not be Send)
        let result = rt.block_on(async {
            let mut enriched = Vec::new();
            let mut successful = 0;
            let mut failed = 0;
            let mut errors: Vec<(String, String)> = Vec::new(); // (package_name, error_message)

            for (idx, package) in packages.into_iter().enumerate() {
                let package_name = package.name().to_string();
                match self
                    .license_repository
                    .enrich_with_license(package.name(), package.version())
                    .await
                {
                    Ok(license_info) => {
                        enriched.push(EnrichedPackage::new(
                            package,
                            license_info.license_text().map(String::from),
                            license_info.description().map(String::from),
                        ));
                        successful += 1;
                    }
                    Err(e) => {
                        // Collect error for reporting after async block
                        errors.push((package_name, e.to_string()));
                        // Include package without license information
                        enriched.push(EnrichedPackage::new(package, None, None));
                        failed += 1;
                    }
                }

                // Update progress
                progress_current.store(idx + 1, Ordering::Relaxed);

                // Security: Rate limiting to prevent DoS via unbounded API requests
                // Add delay between requests (except after the last one)
                if idx < total - 1 {
                    tokio::time::sleep(Duration::from_millis(LICENSE_FETCH_DELAY_MS)).await;
                }
            }

            (enriched, successful, failed, errors)
        });

        // Signal completion and wait for progress bar thread
        is_done.store(true, Ordering::Relaxed);
        let _ = progress_handle.join();

        let (enriched, successful, failed, errors) = result;
        eprintln!(); // Add newline after progress bar

        // Report errors collected during async execution
        for (package_name, error_msg) in errors {
            self.progress_reporter.report_error(&format!(
                "⚠️  Warning: Error: Failed to fetch license information for {}: {}",
                package_name, error_msg
            ));
        }

        self.progress_reporter.report_completion(&format!(
            "✅ License information retrieval complete: {} succeeded out of {}, {} failed",
            successful, total, failed
        ));

        Ok(enriched)
    }

    /// Checks vulnerabilities for the given packages
    ///
    /// # Arguments
    /// * `packages` - List of packages to check
    ///
    /// # Returns
    /// Option containing vulnerability report, or None if repository not available
    ///
    /// # Note
    /// This method uses a tokio runtime to call async VulnerabilityRepository methods.
    /// This is a temporary bridge until GenerateSbomUseCase is fully async (Issue #59).
    /// Uses indicatif directly for progress bar updates via atomic counters.
    fn check_vulnerabilities(
        &self,
        packages: &[Package],
    ) -> Result<Option<Vec<crate::sbom_generation::domain::PackageVulnerabilities>>> {
        let Some(repo) = &self.vulnerability_repository else {
            // No repository configured - skip CVE check
            return Ok(None);
        };

        // Report start of vulnerability check
        self.progress_reporter
            .report("🔐 Checking for vulnerabilities...");

        // Prepare package list for batch query
        let package_list: Vec<crate::sbom_generation::domain::Package> = packages.to_vec();

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

        // Create a tokio runtime to call async methods
        // This is a temporary bridge until GenerateSbomUseCase is fully async (Issue #59)
        let rt = Runtime::new()?;

        // Fetch vulnerabilities with progress reporting (async via block_on)
        let vulnerabilities = rt.block_on(async {
            repo.fetch_vulnerabilities_with_progress(package_list, progress_callback)
                .await
        })?;

        // Signal completion and wait for progress bar thread
        is_done.store(true, Ordering::Relaxed);
        let _ = progress_handle.join();

        // Report completion based on results
        let total_vulns: usize = vulnerabilities
            .iter()
            .map(|v| v.vulnerabilities().len())
            .sum();
        eprintln!(); // Add newline after progress bar
        if total_vulns > 0 {
            self.progress_reporter.report_completion(&format!(
                "✅ Vulnerability check complete: {} vulnerabilities found in {} packages",
                total_vulns,
                vulnerabilities.len()
            ));
        } else {
            self.progress_reporter.report_completion(
                "✅ Vulnerability check complete: No known vulnerabilities found",
            );
        }

        // Return Some even if empty (indicates check was performed)
        Ok(Some(vulnerabilities))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::outbound::LockfileParseResult;
    use crate::sbom_generation::domain::Package;
    use std::collections::HashMap;
    use std::path::Path;

    // Mock implementations for testing
    struct MockLockfileReader {
        content: String,
    }

    impl LockfileReader for MockLockfileReader {
        fn read_lockfile(&self, _path: &Path) -> Result<String> {
            Ok(self.content.clone())
        }

        fn read_and_parse_lockfile(&self, _path: &Path) -> Result<LockfileParseResult> {
            // Parse the mock content
            use serde::Deserialize;

            #[derive(Debug, Deserialize)]
            struct UvLock {
                package: Vec<UvPackage>,
            }

            #[derive(Debug, Deserialize)]
            struct UvPackage {
                name: String,
                version: String,
                #[serde(default)]
                dependencies: Vec<UvDependency>,
                #[serde(default, rename = "dev-dependencies")]
                dev_dependencies: Option<DevDependencies>,
            }

            #[derive(Debug, Deserialize)]
            struct UvDependency {
                name: String,
            }

            #[derive(Debug, Deserialize)]
            struct DevDependencies {
                #[serde(default)]
                dev: Vec<UvDependency>,
            }

            let lockfile: UvLock = toml::from_str(&self.content)?;

            let mut packages = Vec::new();
            let mut dependency_map = HashMap::new();

            for pkg in lockfile.package {
                packages.push(Package::new(pkg.name.clone(), pkg.version.clone())?);

                let mut deps = Vec::new();
                for dep in &pkg.dependencies {
                    deps.push(dep.name.clone());
                }
                if let Some(dev_deps) = &pkg.dev_dependencies {
                    for dep in &dev_deps.dev {
                        deps.push(dep.name.clone());
                    }
                }
                dependency_map.insert(pkg.name, deps);
            }

            Ok((packages, dependency_map))
        }
    }

    struct MockProjectConfigReader {
        project_name: String,
    }

    impl ProjectConfigReader for MockProjectConfigReader {
        fn read_project_name(&self, _path: &Path) -> Result<String> {
            Ok(self.project_name.clone())
        }
    }

    use crate::ports::outbound::PyPiMetadata;

    struct MockLicenseRepository;

    #[async_trait::async_trait]
    impl LicenseRepository for MockLicenseRepository {
        async fn fetch_license_info(
            &self,
            _package_name: &str,
            _version: &str,
        ) -> Result<PyPiMetadata> {
            Ok((
                Some("MIT".to_string()),
                None,
                vec![],
                Some("A test package".to_string()),
            ))
        }
    }

    struct MockProgressReporter;

    impl ProgressReporter for MockProgressReporter {
        fn report(&self, _message: &str) {}
        fn report_progress(&self, _current: usize, _total: usize, _message: Option<&str>) {}
        fn report_error(&self, _message: &str) {}
        fn report_completion(&self, _message: &str) {}
    }

    #[test]
    fn test_execute_without_dependencies() {
        let lockfile_content = r#"
[[package]]
name = "certifi"
version = "2024.8.30"

[[package]]
name = "charset-normalizer"
version = "3.4.0"
"#;

        let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
            GenerateSbomUseCase::new(
                MockLockfileReader {
                    content: lockfile_content.to_string(),
                },
                MockProjectConfigReader {
                    project_name: "test-project".to_string(),
                },
                MockLicenseRepository,
                MockProgressReporter,
                None,
            );

        let request = SbomRequest::new(
            std::path::PathBuf::from("/test/project"),
            false,  // no dependency info
            vec![], // no exclusion patterns
            false,  // not dry-run
            false,  // no CVE check
        );

        let response = use_case.execute(request).unwrap();

        assert_eq!(response.enriched_packages.len(), 2);
        assert!(response.dependency_graph.is_none());
        assert!(!response.metadata.serial_number().is_empty());
    }

    #[test]
    fn test_execute_with_dependencies() {
        let lockfile_content = r#"
[[package]]
name = "myproject"
version = "1.0.0"
dependencies = [
    { name = "requests" }
]

[[package]]
name = "requests"
version = "2.31.0"
dependencies = [
    { name = "urllib3" }
]

[[package]]
name = "urllib3"
version = "1.26.0"
"#;

        let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
            GenerateSbomUseCase::new(
                MockLockfileReader {
                    content: lockfile_content.to_string(),
                },
                MockProjectConfigReader {
                    project_name: "myproject".to_string(),
                },
                MockLicenseRepository,
                MockProgressReporter,
                None,
            );

        let request = SbomRequest::new(
            std::path::PathBuf::from("/test/project"),
            true,   // with dependency info
            vec![], // no exclusion patterns
            false,  // not dry-run
            false,  // no CVE check
        );

        let response = use_case.execute(request).unwrap();

        assert_eq!(response.enriched_packages.len(), 3);
        assert!(response.dependency_graph.is_some());

        let graph = response.dependency_graph.unwrap();
        assert_eq!(graph.direct_dependency_count(), 1);
        assert_eq!(graph.transitive_dependency_count(), 1);
    }

    struct MockVulnerabilityRepository;

    #[async_trait::async_trait]
    impl VulnerabilityRepository for MockVulnerabilityRepository {
        async fn fetch_vulnerabilities(
            &self,
            _packages: Vec<Package>,
        ) -> Result<Vec<crate::sbom_generation::domain::PackageVulnerabilities>> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_execute_with_cve_check_enabled() {
        let lockfile_content = r#"
[[package]]
name = "certifi"
version = "2024.8.30"

[[package]]
name = "charset-normalizer"
version = "3.4.0"
"#;

        let use_case = GenerateSbomUseCase::new(
            MockLockfileReader {
                content: lockfile_content.to_string(),
            },
            MockProjectConfigReader {
                project_name: "test-project".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            Some(MockVulnerabilityRepository),
        );

        let request = SbomRequest::new(
            std::path::PathBuf::from("/test/project"),
            false,  // no dependency info
            vec![], // no exclusion patterns
            false,  // not dry-run
            true,   // CVE check enabled
        );

        let response = use_case.execute(request).unwrap();

        assert_eq!(response.enriched_packages.len(), 2);
        assert!(response.vulnerability_report.is_some());
    }

    #[test]
    fn test_execute_with_cve_check_but_no_repository() {
        let lockfile_content = r#"
[[package]]
name = "certifi"
version = "2024.8.30"
"#;

        let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
            GenerateSbomUseCase::new(
                MockLockfileReader {
                    content: lockfile_content.to_string(),
                },
                MockProjectConfigReader {
                    project_name: "test-project".to_string(),
                },
                MockLicenseRepository,
                MockProgressReporter,
                None, // No vulnerability repository
            );

        let request = SbomRequest::new(
            std::path::PathBuf::from("/test/project"),
            false,  // no dependency info
            vec![], // no exclusion patterns
            false,  // not dry-run
            true,   // CVE check enabled
        );

        let response = use_case.execute(request).unwrap();

        assert_eq!(response.enriched_packages.len(), 1);
        assert!(response.vulnerability_report.is_none());
    }

    #[test]
    fn test_execute_with_cve_check_disabled() {
        let lockfile_content = r#"
[[package]]
name = "certifi"
version = "2024.8.30"
"#;

        let use_case = GenerateSbomUseCase::new(
            MockLockfileReader {
                content: lockfile_content.to_string(),
            },
            MockProjectConfigReader {
                project_name: "test-project".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            Some(MockVulnerabilityRepository),
        );

        let request = SbomRequest::new(
            std::path::PathBuf::from("/test/project"),
            false,  // no dependency info
            vec![], // no exclusion patterns
            false,  // not dry-run
            false,  // CVE check disabled
        );

        let response = use_case.execute(request).unwrap();

        assert_eq!(response.enriched_packages.len(), 1);
        assert!(response.vulnerability_report.is_none());
    }

    #[test]
    fn test_execute_with_cve_check_in_dry_run_mode() {
        let lockfile_content = r#"
[[package]]
name = "certifi"
version = "2024.8.30"
"#;

        let use_case = GenerateSbomUseCase::new(
            MockLockfileReader {
                content: lockfile_content.to_string(),
            },
            MockProjectConfigReader {
                project_name: "test-project".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            Some(MockVulnerabilityRepository),
        );

        let request = SbomRequest::new(
            std::path::PathBuf::from("/test/project"),
            false,  // no dependency info
            vec![], // no exclusion patterns
            true,   // dry-run mode
            true,   // CVE check enabled (but should be skipped due to dry-run)
        );

        let response = use_case.execute(request).unwrap();

        assert_eq!(response.enriched_packages.len(), 0); // dry-run returns empty
        assert!(response.vulnerability_report.is_none()); // CVE check skipped
    }

    // ===== Tests for extracted methods =====

    #[test]
    fn test_apply_exclusion_filters_empty_patterns() {
        let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
            GenerateSbomUseCase::new(
                MockLockfileReader {
                    content: String::new(),
                },
                MockProjectConfigReader {
                    project_name: "test".to_string(),
                },
                MockLicenseRepository,
                MockProgressReporter,
                None,
            );

        let packages = vec![
            Package::new("pkg1".to_string(), "1.0.0".to_string()).unwrap(),
            Package::new("pkg2".to_string(), "2.0.0".to_string()).unwrap(),
        ];
        let dependency_map: HashMap<String, Vec<String>> = HashMap::new();
        let request = SbomRequest::new(
            std::path::PathBuf::from("/test/project"),
            false,
            vec![], // empty patterns
            false,
            false,
        );

        let (filtered_pkgs, _filtered_deps) = use_case
            .apply_exclusion_filters(packages.clone(), dependency_map, &request)
            .unwrap();

        assert_eq!(filtered_pkgs.len(), 2);
    }

    #[test]
    fn test_apply_exclusion_filters_with_patterns() {
        let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
            GenerateSbomUseCase::new(
                MockLockfileReader {
                    content: String::new(),
                },
                MockProjectConfigReader {
                    project_name: "test".to_string(),
                },
                MockLicenseRepository,
                MockProgressReporter,
                None,
            );

        let packages = vec![
            Package::new("requests".to_string(), "1.0.0".to_string()).unwrap(),
            Package::new("urllib3".to_string(), "2.0.0".to_string()).unwrap(),
            Package::new("certifi".to_string(), "3.0.0".to_string()).unwrap(),
        ];
        let dependency_map: HashMap<String, Vec<String>> = HashMap::new();
        let request = SbomRequest::new(
            std::path::PathBuf::from("/test/project"),
            false,
            vec!["requests".to_string()],
            false,
            false,
        );

        let (filtered_pkgs, _filtered_deps) = use_case
            .apply_exclusion_filters(packages, dependency_map, &request)
            .unwrap();

        assert_eq!(filtered_pkgs.len(), 2);
        assert!(!filtered_pkgs.iter().any(|p| p.name() == "requests"));
    }

    #[test]
    fn test_apply_exclusion_filters_all_excluded_error() {
        let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
            GenerateSbomUseCase::new(
                MockLockfileReader {
                    content: String::new(),
                },
                MockProjectConfigReader {
                    project_name: "test".to_string(),
                },
                MockLicenseRepository,
                MockProgressReporter,
                None,
            );

        let packages = vec![Package::new("pkg1".to_string(), "1.0.0".to_string()).unwrap()];
        let dependency_map: HashMap<String, Vec<String>> = HashMap::new();
        let request = SbomRequest::new(
            std::path::PathBuf::from("/test/project"),
            false,
            vec!["pkg1".to_string()],
            false,
            false,
        );

        let result = use_case.apply_exclusion_filters(packages, dependency_map, &request);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("All 1 package(s) were excluded"));
    }

    #[test]
    fn test_analyze_dependencies_disabled() {
        let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
            GenerateSbomUseCase::new(
                MockLockfileReader {
                    content: String::new(),
                },
                MockProjectConfigReader {
                    project_name: "test".to_string(),
                },
                MockLicenseRepository,
                MockProgressReporter,
                None,
            );

        let request = SbomRequest::new(
            std::path::PathBuf::from("/test/project"),
            false, // dependency info disabled
            vec![],
            false,
            false,
        );
        let dependency_map: HashMap<String, Vec<String>> = HashMap::new();

        let result = use_case
            .analyze_dependencies_if_requested(&request, &dependency_map)
            .unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_analyze_dependencies_enabled() {
        let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
            GenerateSbomUseCase::new(
                MockLockfileReader {
                    content: String::new(),
                },
                MockProjectConfigReader {
                    project_name: "myproject".to_string(),
                },
                MockLicenseRepository,
                MockProgressReporter,
                None,
            );

        let request = SbomRequest::new(
            std::path::PathBuf::from("/test/project"),
            true, // dependency info enabled
            vec![],
            false,
            false,
        );
        let mut dependency_map: HashMap<String, Vec<String>> = HashMap::new();
        dependency_map.insert("myproject".to_string(), vec!["requests".to_string()]);
        dependency_map.insert("requests".to_string(), vec![]);

        let result = use_case
            .analyze_dependencies_if_requested(&request, &dependency_map)
            .unwrap();

        assert!(result.is_some());
        let graph = result.unwrap();
        assert_eq!(graph.direct_dependency_count(), 1);
    }

    #[test]
    fn test_build_response() {
        let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
            GenerateSbomUseCase::new(
                MockLockfileReader {
                    content: String::new(),
                },
                MockProjectConfigReader {
                    project_name: "test".to_string(),
                },
                MockLicenseRepository,
                MockProgressReporter,
                None,
            );

        let package = Package::new("test-pkg".to_string(), "1.0.0".to_string()).unwrap();
        let enriched_packages = vec![EnrichedPackage::new(
            package,
            Some("MIT".to_string()),
            Some("Test description".to_string()),
        )];

        let response = use_case.build_response(enriched_packages.clone(), None, None);

        assert_eq!(response.enriched_packages.len(), 1);
        assert!(response.dependency_graph.is_none());
        assert!(response.vulnerability_report.is_none());
        assert!(!response.metadata.serial_number().is_empty());
        assert!(!response.metadata.timestamp().is_empty());
    }

    #[test]
    fn test_fetch_license_info() {
        let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
            GenerateSbomUseCase::new(
                MockLockfileReader {
                    content: String::new(),
                },
                MockProjectConfigReader {
                    project_name: "test".to_string(),
                },
                MockLicenseRepository,
                MockProgressReporter,
                None,
            );

        let packages = vec![
            Package::new("pkg1".to_string(), "1.0.0".to_string()).unwrap(),
            Package::new("pkg2".to_string(), "2.0.0".to_string()).unwrap(),
        ];

        let enriched = use_case.fetch_license_info(packages).unwrap();

        assert_eq!(enriched.len(), 2);
        // MockLicenseRepository always returns MIT license
        assert!(enriched[0].license.is_some());
        assert_eq!(enriched[0].license.as_ref().unwrap(), "MIT");
    }

    #[test]
    fn test_check_vulnerabilities_if_requested_disabled() {
        let use_case = GenerateSbomUseCase::new(
            MockLockfileReader {
                content: String::new(),
            },
            MockProjectConfigReader {
                project_name: "test".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            Some(MockVulnerabilityRepository),
        );

        let request = SbomRequest::new(
            std::path::PathBuf::from("/test/project"),
            false,
            vec![],
            false,
            false, // CVE check disabled
        );
        let packages = vec![Package::new("pkg1".to_string(), "1.0.0".to_string()).unwrap()];

        let result = use_case
            .check_vulnerabilities_if_requested(&request, &packages)
            .unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_check_vulnerabilities_if_requested_enabled() {
        let use_case = GenerateSbomUseCase::new(
            MockLockfileReader {
                content: String::new(),
            },
            MockProjectConfigReader {
                project_name: "test".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            Some(MockVulnerabilityRepository),
        );

        let request = SbomRequest::new(
            std::path::PathBuf::from("/test/project"),
            false,
            vec![],
            false,
            true, // CVE check enabled
        );
        let packages = vec![Package::new("pkg1".to_string(), "1.0.0".to_string()).unwrap()];

        let result = use_case
            .check_vulnerabilities_if_requested(&request, &packages)
            .unwrap();

        assert!(result.is_some());
    }
}
