use crate::application::dto::{SbomRequest, SbomResponse};
use crate::application::use_cases::CheckVulnerabilitiesUseCase;
use crate::ports::outbound::{
    EnrichedPackage, LicenseRepository, LockfileReader, ProgressReporter, ProjectConfigReader,
    VulnerabilityRepository,
};
use crate::sbom_generation::domain::license_policy::LicenseComplianceResult;
use crate::sbom_generation::domain::services::{
    LicenseComplianceChecker, ThresholdConfig, VulnerabilityCheckResult, VulnerabilityChecker,
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

        // Step 2: Apply exclusion filters to packages only
        // Note: We pass dependency_map by reference to preserve it for dependency analysis.
        // The root project may be excluded from packages but we still need its entry
        // in dependency_map to correctly identify direct vs transitive dependencies.
        let filtered_packages = self.apply_exclusion_filters(packages, &request)?;

        // Early return for dry-run mode (validation only)
        if request.dry_run {
            return self.build_dry_run_response();
        }

        // Step 3: Analyze dependencies if requested
        // Use original dependency_map to preserve dependency classification even when
        // root project is excluded from the package list (fixes #206)
        let dependency_graph = self.analyze_dependencies_if_requested(&request, &dependency_map)?;

        // Step 4: Enrich packages with license information
        let enriched_packages = self.fetch_license_info(filtered_packages.clone()).await?;

        // Step 5: CVE check if requested
        let vulnerability_report = self
            .check_vulnerabilities_if_requested(&request, &filtered_packages)
            .await?;

        // Step 6: Apply threshold evaluation if vulnerabilities were found
        let vulnerability_check_result = vulnerability_report.as_ref().map(|report| {
            let threshold_config = Self::build_threshold_config(&request);
            VulnerabilityChecker::check(report.clone(), threshold_config, &request.ignore_cves)
        });

        // Step 7: License compliance check if requested
        let license_compliance_result =
            self.check_license_compliance_if_requested(&request, &enriched_packages);

        // Step 8: Build and return response
        Ok(self.build_response(
            enriched_packages,
            dependency_graph,
            vulnerability_report,
            vulnerability_check_result,
            license_compliance_result,
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

    /// Applies exclusion filters to packages
    ///
    /// Note: This method intentionally does NOT filter the dependency_map.
    /// The dependency_map is preserved to maintain correct dependency classification
    /// (direct vs transitive) even when the root project is excluded from the package list.
    /// See issue #206 for details.
    ///
    /// # Arguments
    /// * `packages` - Original packages from lockfile
    /// * `request` - The SBOM request containing exclusion patterns
    ///
    /// # Returns
    /// Filtered packages list
    ///
    /// # Errors
    /// Returns an error if all packages are excluded
    fn apply_exclusion_filters(
        &self,
        packages: Vec<Package>,
        request: &SbomRequest,
    ) -> Result<Vec<Package>> {
        if request.exclude_patterns.is_empty() {
            return Ok(packages);
        }

        let filter = PackageFilter::new(request.exclude_patterns.clone())?;
        let original_count = packages.len();
        let filtered_pkgs = filter.filter_packages(packages);

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

        Ok(filtered_pkgs)
    }

    /// Builds a response for dry-run mode (validation only)
    fn build_dry_run_response(&self) -> Result<SbomResponse> {
        self.progress_reporter
            .report_completion("Success: Configuration validated. No issues found.");
        let metadata = SbomGenerator::generate_default_metadata();
        Ok(SbomResponse::new(
            vec![],
            None,
            metadata,
            None,
            false,
            None,
            None,
            false,
        ))
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
        let vuln_use_case = CheckVulnerabilitiesUseCase::new(repo.clone());
        let vulnerabilities = vuln_use_case.check_with_progress(packages.to_vec()).await?;

        // Report completion based on results
        let (total_vulns, affected_packages) =
            CheckVulnerabilitiesUseCase::<VREPO>::summarize(&vulnerabilities);
        eprintln!(); // Add newline after progress bar
        if total_vulns > 0 {
            self.progress_reporter.report_completion(&format!(
                "✅ Vulnerability check complete: {} vulnerabilities found in {} packages",
                total_vulns, affected_packages
            ));
        } else {
            self.progress_reporter.report_completion(
                "✅ Vulnerability check complete: No known vulnerabilities found",
            );
        }

        // Return Some even if empty (indicates check was performed)
        Ok(Some(vulnerabilities))
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

    /// Checks license compliance if requested
    fn check_license_compliance_if_requested(
        &self,
        request: &SbomRequest,
        enriched_packages: &[EnrichedPackage],
    ) -> Option<LicenseComplianceResult> {
        if !request.check_license {
            return None;
        }
        let policy = request.license_policy.as_ref()?;

        let packages: Vec<(String, String, Option<String>)> = enriched_packages
            .iter()
            .map(|ep| {
                (
                    ep.package.name().to_string(),
                    ep.package.version().to_string(),
                    ep.license.clone(),
                )
            })
            .collect();

        let result = LicenseComplianceChecker::check(&packages, policy);

        // Report results
        if result.has_violations() {
            self.progress_reporter.report(&format!(
                "⚠️  License compliance: {} violation(s) found",
                result.violations.len()
            ));
        } else {
            self.progress_reporter
                .report("✅ License compliance: No violations found");
        }

        if !result.warnings.is_empty() {
            self.progress_reporter.report(&format!(
                "⚠️  License compliance: {} package(s) with unknown license",
                result.warnings.len()
            ));
        }

        Some(result)
    }

    /// Builds the final SBOM response
    fn build_response(
        &self,
        enriched_packages: Vec<EnrichedPackage>,
        dependency_graph: Option<crate::sbom_generation::domain::DependencyGraph>,
        vulnerability_report: Option<Vec<crate::sbom_generation::domain::PackageVulnerabilities>>,
        vulnerability_check_result: Option<VulnerabilityCheckResult>,
        license_compliance_result: Option<LicenseComplianceResult>,
    ) -> SbomResponse {
        let metadata = SbomGenerator::generate_default_metadata();

        // Use threshold check result if available, otherwise check if any vulnerabilities exist
        let has_vulnerabilities_above_threshold = vulnerability_check_result
            .as_ref()
            .map(|result| result.threshold_exceeded)
            .unwrap_or(false);

        let has_license_violations = license_compliance_result
            .as_ref()
            .map(|result| result.has_violations())
            .unwrap_or(false);

        SbomResponse::new(
            enriched_packages,
            dependency_graph,
            metadata,
            vulnerability_report,
            has_vulnerabilities_above_threshold,
            vulnerability_check_result,
            license_compliance_result,
            has_license_violations,
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
