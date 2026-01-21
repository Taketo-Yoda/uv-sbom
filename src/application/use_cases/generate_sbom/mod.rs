use crate::application::dto::{SbomRequest, SbomResponse};
use crate::application::use_cases::CheckVulnerabilitiesUseCase;
use crate::ports::outbound::{
    EnrichedPackage, LicenseRepository, LockfileReader, ProgressReporter, ProjectConfigReader,
    VulnerabilityRepository,
};
use crate::sbom_generation::domain::services::{
    ThresholdConfig, VulnerabilityCheckResult, VulnerabilityChecker,
};
use crate::sbom_generation::domain::{Package, PackageName};
use crate::sbom_generation::services::{DependencyAnalyzer, PackageFilter, SbomGenerator};
use crate::shared::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

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
    VREPO: VulnerabilityRepository + Clone,
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
    pub async fn execute(&self, request: SbomRequest) -> Result<SbomResponse> {
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
        let enriched_packages = self.fetch_license_info(filtered_packages.clone()).await?;

        // Step 5: CVE check if requested
        let vulnerability_report = self
            .check_vulnerabilities_if_requested(&request, &filtered_packages)
            .await?;

        // Step 6: Apply threshold evaluation if vulnerabilities were found
        let vulnerability_check_result = vulnerability_report.as_ref().map(|report| {
            let threshold_config = Self::build_threshold_config(&request);
            VulnerabilityChecker::check(report.clone(), threshold_config)
        });

        // Step 7: Build and return response
        Ok(self.build_response(
            enriched_packages,
            dependency_graph,
            vulnerability_report,
            vulnerability_check_result,
        ))
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
        Ok(SbomResponse::new(vec![], None, metadata, None, false, None))
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
    async fn fetch_license_info(&self, packages: Vec<Package>) -> Result<Vec<EnrichedPackage>> {
        self.progress_reporter
            .report("🔍 Fetching license information...");

        self.enrich_packages_with_licenses(packages).await
    }

    /// Checks vulnerabilities if CVE check is requested
    ///
    /// This method delegates to CheckVulnerabilitiesUseCase for the actual
    /// vulnerability fetching, ensuring single source of truth for vulnerability
    /// checking logic.
    ///
    /// # Arguments
    /// * `request` - The SBOM request
    /// * `packages` - Packages to check for vulnerabilities
    ///
    /// # Returns
    /// Optional vulnerability report
    async fn check_vulnerabilities_if_requested(
        &self,
        request: &SbomRequest,
        packages: &[Package],
    ) -> Result<Option<Vec<crate::sbom_generation::domain::PackageVulnerabilities>>> {
        if !request.check_cve {
            return Ok(None);
        }

        let Some(repo) = &self.vulnerability_repository else {
            // No repository configured - skip CVE check
            return Ok(None);
        };

        // Report start of vulnerability check
        self.progress_reporter
            .report("🔐 Checking for vulnerabilities...");

        // Delegate to CheckVulnerabilitiesUseCase for vulnerability fetching
        let vulnerabilities = self
            .fetch_vulnerabilities_with_progress(repo, packages)
            .await?;

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

    /// Fetches vulnerabilities with progress reporting using CheckVulnerabilitiesUseCase
    ///
    /// This method creates a CheckVulnerabilitiesUseCase internally and delegates
    /// the vulnerability fetching to it, while handling progress bar display.
    ///
    /// # Arguments
    /// * `repo` - The vulnerability repository to use
    /// * `packages` - Packages to check for vulnerabilities
    ///
    /// # Returns
    /// Vector of PackageVulnerabilities
    async fn fetch_vulnerabilities_with_progress(
        &self,
        repo: &VREPO,
        packages: &[Package],
    ) -> Result<Vec<crate::sbom_generation::domain::PackageVulnerabilities>> {
        let package_list: Vec<Package> = packages.to_vec();

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

        // Create CheckVulnerabilitiesUseCase and delegate
        let vuln_use_case = CheckVulnerabilitiesUseCase::new(repo.clone());
        let vulnerabilities = vuln_use_case
            .fetch_vulnerabilities_with_progress(package_list, progress_callback)
            .await?;

        // Signal completion and wait for progress bar thread
        is_done.store(true, Ordering::Relaxed);
        let _ = progress_handle.join();

        Ok(vulnerabilities)
    }

    /// Builds ThresholdConfig from SbomRequest options
    ///
    /// # Arguments
    /// * `request` - The SBOM request containing threshold options
    ///
    /// # Returns
    /// ThresholdConfig based on request options
    fn build_threshold_config(request: &SbomRequest) -> ThresholdConfig {
        match (&request.severity_threshold, &request.cvss_threshold) {
            (Some(severity), None) => ThresholdConfig::Severity(*severity),
            (None, Some(cvss)) => ThresholdConfig::Cvss(*cvss),
            // Both None or unreachable (clap group prevents both being set)
            _ => ThresholdConfig::None,
        }
    }

    /// Builds the final SBOM response
    ///
    /// # Arguments
    /// * `enriched_packages` - Packages with license information
    /// * `dependency_graph` - Optional dependency graph
    /// * `vulnerability_report` - Optional vulnerability report
    /// * `vulnerability_check_result` - Optional threshold evaluation result
    ///
    /// # Returns
    /// Complete SbomResponse
    fn build_response(
        &self,
        enriched_packages: Vec<EnrichedPackage>,
        dependency_graph: Option<crate::sbom_generation::domain::DependencyGraph>,
        vulnerability_report: Option<Vec<crate::sbom_generation::domain::PackageVulnerabilities>>,
        vulnerability_check_result: Option<VulnerabilityCheckResult>,
    ) -> SbomResponse {
        let metadata = SbomGenerator::generate_default_metadata(vulnerability_report.is_some());

        // Use threshold check result if available, otherwise check if any vulnerabilities exist
        let has_vulnerabilities_above_threshold = vulnerability_check_result
            .as_ref()
            .map(|result| result.threshold_exceeded)
            .unwrap_or(false);

        SbomResponse::new(
            enriched_packages,
            dependency_graph,
            metadata,
            vulnerability_report,
            has_vulnerabilities_above_threshold,
            vulnerability_check_result,
        )
    }

    /// Enriches packages with license information from the repository
    ///
    /// Security: This method implements rate limiting to prevent DoS attacks
    /// via unbounded PyPI API requests. A delay is added between requests
    /// to limit the rate to approximately 10 requests per second.
    async fn enrich_packages_with_licenses(
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

        // Fetch licenses sequentially with rate limiting
        // Collect errors to report after async loop (since progress_reporter may not be Send)
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
                    // Collect error for reporting after async loop
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

        // Signal completion and wait for progress bar thread
        is_done.store(true, Ordering::Relaxed);
        let _ = progress_handle.join();

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
}

#[cfg(test)]
mod tests;
