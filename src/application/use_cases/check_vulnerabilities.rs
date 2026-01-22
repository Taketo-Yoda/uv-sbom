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
