use crate::application::dto::{SbomRequest, SbomResponse};
use crate::ports::outbound::{
    EnrichedPackage, LicenseRepository, LockfileReader, ProgressReporter, ProjectConfigReader,
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
pub struct GenerateSbomUseCase<LR, PCR, LREPO, PR> {
    lockfile_reader: LR,
    project_config_reader: PCR,
    license_repository: LREPO,
    progress_reporter: PR,
}

impl<LR, PCR, LREPO, PR> GenerateSbomUseCase<LR, PCR, LREPO, PR>
where
    LR: LockfileReader,
    PCR: ProjectConfigReader,
    LREPO: LicenseRepository,
    PR: ProgressReporter,
{
    /// Creates a new GenerateSbomUseCase with injected dependencies
    pub fn new(
        lockfile_reader: LR,
        project_config_reader: PCR,
        license_repository: LREPO,
        progress_reporter: PR,
    ) -> Self {
        Self {
            lockfile_reader,
            project_config_reader,
            license_repository,
            progress_reporter,
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

        let enriched_packages = self.enrich_packages_with_licenses(filtered_packages)?;

        // Step 5: Generate SBOM metadata
        let metadata = SbomGenerator::generate_default_metadata();

        // Step 6: Create response
        Ok(SbomResponse::new(
            enriched_packages,
            dependency_graph,
            metadata,
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

        let use_case = GenerateSbomUseCase::new(
            MockLockfileReader {
                content: lockfile_content.to_string(),
            },
            MockProjectConfigReader {
                project_name: "test-project".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
        );

        let request = SbomRequest::new(
            std::path::PathBuf::from("/test/project"),
            false,  // no dependency info
            vec![], // no exclusion patterns
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

        let use_case = GenerateSbomUseCase::new(
            MockLockfileReader {
                content: lockfile_content.to_string(),
            },
            MockProjectConfigReader {
                project_name: "myproject".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
        );

        let request = SbomRequest::new(
            std::path::PathBuf::from("/test/project"),
            true,   // with dependency info
            vec![], // no exclusion patterns
        );

        let response = use_case.execute(request).unwrap();

        assert_eq!(response.enriched_packages.len(), 3);
        assert!(response.dependency_graph.is_some());

        let graph = response.dependency_graph.unwrap();
        assert_eq!(graph.direct_dependency_count(), 1);
        assert_eq!(graph.transitive_dependency_count(), 1);
    }
}
