use crate::application::dto::{SbomRequest, SbomResponse};
use crate::ports::outbound::{
    EnrichedPackage, LicenseRepository, LockfileReader, ProgressReporter, ProjectConfigReader,
    VulnerabilityRepository,
};
use crate::sbom_generation::domain::{Package, PackageName};
use crate::sbom_generation::services::{DependencyAnalyzer, PackageFilter, SbomGenerator};
use crate::shared::Result;
use std::thread;
use std::time::Duration;

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
        self.progress_reporter.report(&format!(
            "📖 Loading uv.lock file from: {}",
            request.project_path.display()
        ));

        let (packages, dependency_map) = self
            .lockfile_reader
            .read_and_parse_lockfile(&request.project_path)?;

        self.progress_reporter
            .report(&format!("✅ Detected {} package(s)", packages.len()));

        // Step 2: Apply exclusion filters
        let (filtered_packages, filtered_dependency_map) = if !request.exclude_patterns.is_empty() {
            let filter = PackageFilter::new(request.exclude_patterns)?;
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

            (filtered_pkgs, filtered_deps)
        } else {
            (packages, dependency_map)
        };

        // Early return for dry-run mode (validation only)
        if request.dry_run {
            self.progress_reporter
                .report_completion("Success: Configuration validated. No issues found.");
            // Return empty response for dry-run
            let metadata = SbomGenerator::generate_default_metadata(false);
            return Ok(SbomResponse::new(vec![], None, metadata, None));
        }

        // Step 3: Analyze dependencies if requested
        let dependency_graph = if request.include_dependency_info {
            self.progress_reporter
                .report("📊 Parsing dependency information...");

            let project_name = self
                .project_config_reader
                .read_project_name(&request.project_path)?;
            let project_package_name = PackageName::new(project_name)?;

            let graph =
                DependencyAnalyzer::analyze(&project_package_name, &filtered_dependency_map)?;

            self.progress_reporter.report(&format!(
                "   - Direct dependencies: {}",
                graph.direct_dependency_count()
            ));
            self.progress_reporter.report(&format!(
                "   - Transitive dependencies: {}",
                graph.transitive_dependency_count()
            ));

            Some(graph)
        } else {
            None
        };

        // Step 4: Enrich packages with license information
        self.progress_reporter
            .report("🔍 Fetching license information...");

        let enriched_packages = self.enrich_packages_with_licenses(filtered_packages.clone())?;

        // Step 4.5: CVE check if requested and not in dry-run mode
        let vulnerability_report = if request.check_cve && !request.dry_run {
            self.check_vulnerabilities(&filtered_packages)?
        } else {
            None
        };

        // Step 5: Generate SBOM metadata with OSV attribution if CVE check was performed
        let metadata = SbomGenerator::generate_default_metadata(vulnerability_report.is_some());

        // Step 6: Create response
        Ok(SbomResponse::new(
            enriched_packages,
            dependency_graph,
            metadata,
            vulnerability_report,
        ))
    }

    /// Enriches packages with license information from the repository
    ///
    /// Security: This method implements rate limiting to prevent DoS attacks
    /// via unbounded PyPI API requests. A delay is added between requests
    /// to limit the rate to approximately 10 requests per second.
    fn enrich_packages_with_licenses(
        &self,
        packages: Vec<Package>,
    ) -> Result<Vec<EnrichedPackage>> {
        let total = packages.len();
        let mut enriched = Vec::new();
        let mut successful = 0;
        let mut failed = 0;

        for (idx, package) in packages.into_iter().enumerate() {
            self.progress_reporter
                .report_progress(idx + 1, total, Some(package.name()));

            match self
                .license_repository
                .enrich_with_license(package.name(), package.version())
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
                    self.progress_reporter.report_error(&format!(
                        "⚠️  Warning: Failed to fetch license information for {}: {}",
                        package.name(),
                        e
                    ));
                    // Include package without license information
                    enriched.push(EnrichedPackage::new(package, None, None));
                    failed += 1;
                }
            }

            // Security: Rate limiting to prevent DoS via unbounded API requests
            // Add delay between requests (except after the last one)
            if idx < total - 1 {
                thread::sleep(Duration::from_millis(LICENSE_FETCH_DELAY_MS));
            }
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
    fn check_vulnerabilities(
        &self,
        packages: &[Package],
    ) -> Result<Option<Vec<crate::sbom_generation::domain::PackageVulnerabilities>>> {
        let Some(repo) = &self.vulnerability_repository else {
            // No repository configured - skip CVE check
            return Ok(None);
        };

        // Prepare package list for batch query
        let package_list: Vec<crate::sbom_generation::domain::Package> = packages.to_vec();

        // Fetch vulnerabilities
        let vulnerabilities = repo.fetch_vulnerabilities(package_list)?;

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

    impl LicenseRepository for MockLicenseRepository {
        fn fetch_license_info(&self, _package_name: &str, _version: &str) -> Result<PyPiMetadata> {
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

    impl VulnerabilityRepository for MockVulnerabilityRepository {
        fn fetch_vulnerabilities(
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
}
