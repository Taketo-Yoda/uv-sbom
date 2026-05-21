use crate::ports::outbound::{MaintenanceInfo, MaintenanceRepository};
use crate::sbom_generation::domain::Package;
use crate::shared::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Delay between maintenance info fetch requests (ms)
const MAINTENANCE_FETCH_DELAY_MS: u64 = 100;

/// Use case for fetching package maintenance information for a list of packages.
///
/// Handles progress bar display and sequential fetching, delegating the actual
/// retrieval to the injected `MaintenanceRepository`. Errors per package are
/// collected and surfaced as warnings rather than aborting the whole check.
///
/// # Type Parameters
/// * `MR` - `MaintenanceRepository` implementation
pub struct CheckAbandonedPackagesUseCase<MR: MaintenanceRepository> {
    maintenance_repository: MR,
}

impl<MR: MaintenanceRepository> CheckAbandonedPackagesUseCase<MR> {
    /// Creates a new `CheckAbandonedPackagesUseCase` with the given repository.
    pub fn new(maintenance_repository: MR) -> Self {
        Self {
            maintenance_repository,
        }
    }

    /// Fetches maintenance information for all packages with a progress bar.
    ///
    /// Returns `(results, errors)` where:
    /// - `results` is `(Package, MaintenanceInfo)` pairs for successful fetches
    /// - `errors` is `(package_name, error_message)` pairs for failed fetches
    ///
    /// Failed packages are omitted from `results` (no entry with `None` — callers
    /// skip packages with unknown release dates anyway).
    pub async fn fetch_with_progress(
        &self,
        packages: Vec<Package>,
    ) -> Result<(Vec<(Package, MaintenanceInfo)>, Vec<(String, String)>)> {
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
                pb.set_message("Fetching maintenance information..."); // i18n-ok: internal progress bar label
                while !done.load(Ordering::Relaxed) {
                    pb.set_position(cur.load(Ordering::Relaxed) as u64);
                    thread::sleep(Duration::from_millis(50));
                }
                pb.finish_and_clear();
            })
        };

        let mut results: Vec<(Package, MaintenanceInfo)> = Vec::new();
        let mut errors: Vec<(String, String)> = Vec::new();

        for (idx, package) in packages.into_iter().enumerate() {
            let name = package.name().to_string();
            match self
                .maintenance_repository
                .fetch_maintenance_info(&name)
                .await
            {
                Ok(info) => results.push((package, info)),
                Err(e) => errors.push((name, e.to_string())),
            }
            progress_current.store(idx + 1, Ordering::Relaxed);
            if idx < total - 1 {
                tokio::time::sleep(Duration::from_millis(MAINTENANCE_FETCH_DELAY_MS)).await;
            }
        }

        is_done.store(true, Ordering::Relaxed);
        let _ = progress_handle.join();

        Ok((results, errors))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::use_cases::test_doubles::MockMaintenanceRepository;
    use chrono::NaiveDate;

    fn pkg(name: &str, version: &str) -> Package {
        Package::new(name.to_string(), version.to_string()).unwrap()
    }

    fn info(date: Option<NaiveDate>) -> MaintenanceInfo {
        MaintenanceInfo {
            last_release_date: date,
        }
    }

    #[tokio::test]
    async fn test_fetch_with_progress_success() {
        let repo = MockMaintenanceRepository::with_responses([Ok(info(Some(
            NaiveDate::from_ymd_opt(2022, 1, 1).unwrap(),
        )))]);
        let use_case = CheckAbandonedPackagesUseCase::new(repo);

        let (results, errors) = use_case
            .fetch_with_progress(vec![pkg("requests", "2.31.0")])
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert!(errors.is_empty());
        assert_eq!(results[0].0.name(), "requests");
    }

    #[tokio::test]
    async fn test_fetch_with_progress_error_collected() {
        let repo = MockMaintenanceRepository::with_responses([Err("network error".to_string())]);
        let use_case = CheckAbandonedPackagesUseCase::new(repo);

        let (results, errors) = use_case
            .fetch_with_progress(vec![pkg("requests", "2.31.0")])
            .await
            .unwrap();

        assert!(results.is_empty());
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, "requests");
        assert!(errors[0].1.contains("network error"));
    }

    #[tokio::test]
    async fn test_fetch_with_progress_empty() {
        let repo = MockMaintenanceRepository::new();
        let use_case = CheckAbandonedPackagesUseCase::new(repo);

        let (results, errors) = use_case.fetch_with_progress(vec![]).await.unwrap();

        assert!(results.is_empty());
        assert!(errors.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_with_progress_mixed_success_and_error() {
        let repo = MockMaintenanceRepository::with_responses([
            Ok(info(Some(NaiveDate::from_ymd_opt(2021, 6, 1).unwrap()))),
            Err("not found".to_string()),
            Ok(info(None)),
        ]);
        let use_case = CheckAbandonedPackagesUseCase::new(repo);

        let packages = vec![
            pkg("requests", "2.31.0"),
            pkg("unknown-pkg", "1.0.0"),
            pkg("certifi", "2024.1.1"),
        ];

        let (results, errors) = use_case.fetch_with_progress(packages).await.unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, "unknown-pkg");
    }
}
