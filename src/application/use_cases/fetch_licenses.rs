use crate::ports::outbound::{EnrichedPackage, LicenseRepository};
use crate::sbom_generation::domain::Package;
use crate::shared::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Rate limiting: delay between license fetch requests (ms)
const LICENSE_FETCH_DELAY_MS: u64 = 100;

/// Use case for fetching license information for a list of packages.
///
/// Handles progress bar display and rate limiting, delegating the actual
/// license retrieval to the injected `LicenseRepository`.
///
/// # Type Parameters
/// * `LREPO` - `LicenseRepository` implementation
pub struct FetchLicensesUseCase<LREPO: LicenseRepository> {
    license_repository: LREPO,
}

impl<LREPO: LicenseRepository> FetchLicensesUseCase<LREPO> {
    /// Creates a new `FetchLicensesUseCase` with the given repository.
    pub fn new(license_repository: LREPO) -> Self {
        Self { license_repository }
    }

    /// Fetches license information for all packages with a progress bar.
    ///
    /// Returns `(enriched_packages, errors)` where errors is a list of
    /// `(package_name, error_message)` pairs for packages whose fetch failed.
    /// Failed packages are included in `enriched_packages` with `license: None`.
    pub async fn fetch_with_progress(
        &self,
        packages: Vec<Package>,
    ) -> Result<(Vec<EnrichedPackage>, Vec<(String, String)>)> {
        let total = packages.len();
        let progress_current = Arc::new(AtomicUsize::new(0));
        let is_done = Arc::new(AtomicBool::new(false));

        let progress_handle = {
            let cur = progress_current.clone();
            let done = is_done.clone();
            thread::spawn(move || {
                let pb = ProgressBar::new(total as u64);
                pb.set_style(
                    ProgressStyle::default_bar()
                        .template("   {spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} - {msg}")
                        .expect("Failed to set progress bar template")
                        .progress_chars("=>-"),
                );
                pb.set_message("Fetching license information..."); // i18n-ok: internal progress bar label, consistent with CheckVulnerabilitiesUseCase
                while !done.load(Ordering::Relaxed) {
                    pb.set_position(cur.load(Ordering::Relaxed) as u64);
                    thread::sleep(Duration::from_millis(50));
                }
                pb.finish_and_clear();
            })
        };

        let mut enriched = Vec::new();
        let mut errors: Vec<(String, String)> = Vec::new();

        for (idx, package) in packages.into_iter().enumerate() {
            let name = package.name().to_string();
            match self
                .license_repository
                .enrich_with_license(&name, package.version())
                .await
            {
                Ok(info) => enriched.push(
                    EnrichedPackage::new(
                        package,
                        info.license_text().map(String::from),
                        info.description().map(String::from),
                    )
                    .with_sha256_hash(info.sha256_hash().map(String::from)),
                ),
                Err(e) => {
                    errors.push((name, e.to_string()));
                    enriched.push(EnrichedPackage::new(package, None, None));
                }
            }
            progress_current.store(idx + 1, Ordering::Relaxed);
            if idx < total - 1 {
                tokio::time::sleep(Duration::from_millis(LICENSE_FETCH_DELAY_MS)).await;
            }
        }

        is_done.store(true, Ordering::Relaxed);
        let _ = progress_handle.join();

        Ok((enriched, errors))
    }

    /// Returns a summary of the fetch results: (successful_count, total_count, failed_count)
    pub fn summarize(
        enriched: &[EnrichedPackage],
        errors: &[(String, String)],
    ) -> (usize, usize, usize) {
        let total = enriched.len();
        let failed = errors.len();
        let successful = total - failed;
        (successful, total, failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
                None,
            ))
        }
    }

    struct FailingLicenseRepository;

    #[async_trait::async_trait]
    impl LicenseRepository for FailingLicenseRepository {
        async fn fetch_license_info(
            &self,
            _package_name: &str,
            _version: &str,
        ) -> Result<PyPiMetadata> {
            Err(anyhow::anyhow!("network error"))
        }
    }

    fn make_package(name: &str, version: &str) -> Package {
        Package::new(name.to_string(), version.to_string()).unwrap()
    }

    // ========== summarize() tests ==========

    #[test]
    fn test_summarize_empty() {
        let (successful, total, failed) =
            FetchLicensesUseCase::<MockLicenseRepository>::summarize(&[], &[]);
        assert_eq!(successful, 0);
        assert_eq!(total, 0);
        assert_eq!(failed, 0);
    }

    #[test]
    fn test_summarize_all_successful() {
        let pkg = make_package("requests", "2.31.0");
        let enriched = vec![EnrichedPackage::new(pkg, Some("MIT".to_string()), None)];
        let errors: Vec<(String, String)> = vec![];

        let (successful, total, failed) =
            FetchLicensesUseCase::<MockLicenseRepository>::summarize(&enriched, &errors);
        assert_eq!(successful, 1);
        assert_eq!(total, 1);
        assert_eq!(failed, 0);
    }

    #[test]
    fn test_summarize_with_failures() {
        let pkg1 = make_package("requests", "2.31.0");
        let pkg2 = make_package("urllib3", "1.26.0");
        let enriched = vec![
            EnrichedPackage::new(pkg1, Some("MIT".to_string()), None),
            EnrichedPackage::new(pkg2, None, None),
        ];
        let errors = vec![("urllib3".to_string(), "network error".to_string())];

        let (successful, total, failed) =
            FetchLicensesUseCase::<MockLicenseRepository>::summarize(&enriched, &errors);
        assert_eq!(successful, 1);
        assert_eq!(total, 2);
        assert_eq!(failed, 1);
    }

    // ========== fetch_with_progress() tests ==========

    #[tokio::test]
    async fn test_fetch_with_progress_success() {
        let use_case = FetchLicensesUseCase::new(MockLicenseRepository);
        let packages = vec![make_package("requests", "2.31.0")];

        let (enriched, errors) = use_case.fetch_with_progress(packages).await.unwrap();

        assert_eq!(enriched.len(), 1);
        assert!(errors.is_empty());
        assert_eq!(enriched[0].license.as_deref(), Some("MIT"));
        assert_eq!(enriched[0].description.as_deref(), Some("A test package"));
    }

    #[tokio::test]
    async fn test_fetch_with_progress_failure() {
        let use_case = FetchLicensesUseCase::new(FailingLicenseRepository);
        let packages = vec![make_package("requests", "2.31.0")];

        let (enriched, errors) = use_case.fetch_with_progress(packages).await.unwrap();

        assert_eq!(enriched.len(), 1);
        assert_eq!(errors.len(), 1);
        assert!(enriched[0].license.is_none());
        assert_eq!(errors[0].0, "requests");
        assert!(errors[0].1.contains("network error"));
    }

    #[tokio::test]
    async fn test_fetch_with_progress_empty() {
        let use_case = FetchLicensesUseCase::new(MockLicenseRepository);

        let (enriched, errors) = use_case.fetch_with_progress(vec![]).await.unwrap();

        assert!(enriched.is_empty());
        assert!(errors.is_empty());
    }
}
