use super::progress_bar::ProgressBarHandle;
use crate::application::read_models::{PythonCompatibilityReport, PythonIncompatibilityView};
use crate::ports::outbound::{PythonCompatibilityInfo, PythonCompatibilityRepository};
use crate::sbom_generation::domain::Package;
use crate::shared::Result;
use futures::stream::{self, StreamExt};
use std::collections::HashSet;
use std::sync::atomic::Ordering;

/// Max number of concurrent `requires_python` fetches, matching the concurrency
/// limit used by `PyPiLicenseRepository::verify_packages`.
const MAX_CONCURRENT: usize = 10;

/// Raw fetch outcome for a single package: the package paired with either its
/// compatibility info or a stringified fetch error.
type FetchOutcome = (
    Package,
    std::result::Result<PythonCompatibilityInfo, String>,
);

/// Use case for checking package compatibility against a target Python version.
///
/// Fetches `requires_python` metadata for all packages in parallel, evaluates
/// each against `target_python`, and builds a `PythonCompatibilityReport`
/// containing only the incompatible packages. Per-package fetch failures are
/// soft-failed: the package is skipped and the run continues.
///
/// # Type Parameters
/// * `PR` - `PythonCompatibilityRepository` implementation
#[allow(dead_code)] // WIRE(#681): remove when wired into GenerateSbomUseCase and main.rs
pub struct CheckPythonCompatibilityUseCase<PR: PythonCompatibilityRepository> {
    compatibility_repository: PR,
}

#[allow(dead_code)] // WIRE(#681): remove when wired into GenerateSbomUseCase and main.rs
impl<PR: PythonCompatibilityRepository> CheckPythonCompatibilityUseCase<PR> {
    /// Creates a new `CheckPythonCompatibilityUseCase` with the given repository.
    pub fn new(compatibility_repository: PR) -> Self {
        Self {
            compatibility_repository,
        }
    }

    /// Fetches `requires_python` for all packages in parallel with a progress
    /// bar, and returns a report of packages incompatible with `target_python`.
    ///
    /// `direct_names` is the set of package names that are direct dependencies
    /// of the current project; every other package is treated as transitive.
    ///
    /// # Errors
    /// This method itself never fails: per-package fetch errors are soft-failed
    /// (the package is skipped, not surfaced). The `Result` wrapper exists for
    /// consistency with other use cases in this module and to leave room for a
    /// future fatal error path (e.g. all fetches failing) without a signature
    /// change.
    pub async fn check_with_progress(
        &self,
        packages: Vec<Package>,
        target_python: &str,
        direct_names: &HashSet<&str>,
    ) -> Result<PythonCompatibilityReport> {
        let fetched = self.fetch_all(packages).await;
        Ok(Self::build_report(fetched, target_python, direct_names))
    }

    /// Fetches `requires_python` for every package concurrently (bounded by
    /// `MAX_CONCURRENT`), driving a progress bar as fetches complete.
    async fn fetch_all(&self, packages: Vec<Package>) -> Vec<FetchOutcome> {
        let total = packages.len();
        // i18n-ok: internal progress bar label
        let progress = ProgressBarHandle::spawn(total, "Checking Python compatibility...");
        let progress_current = progress.counter();

        let fetched: Vec<FetchOutcome> = stream::iter(packages)
            .map(|package| {
                let cur = progress_current.clone();
                async move {
                    let result = self
                        .compatibility_repository
                        .fetch_python_compatibility(package.name(), package.version())
                        .await
                        .map_err(|e| e.to_string());
                    cur.fetch_add(1, Ordering::Relaxed);
                    (package, result)
                }
            })
            .buffer_unordered(MAX_CONCURRENT)
            .collect()
            .await;

        progress.finish();
        fetched
    }

    /// Classifies fetch outcomes against `target_python` and assembles the
    /// report. Fetch errors are soft-failed (the package is silently skipped).
    fn build_report(
        fetched: Vec<FetchOutcome>,
        target_python: &str,
        direct_names: &HashSet<&str>,
    ) -> PythonCompatibilityReport {
        let mut incompatible: Vec<PythonIncompatibilityView> = fetched
            .into_iter()
            .filter_map(|(package, result)| {
                let info = result.ok()?;
                if !info.is_incompatible_with(target_python) {
                    return None;
                }
                Some(PythonIncompatibilityView {
                    name: package.name().to_string(),
                    version: package.version().to_string(),
                    requires_python: info.requires_python,
                    is_direct: direct_names.contains(package.name()),
                })
            })
            .collect();

        // `buffer_unordered` completes in nondeterministic order; sort for
        // stable, reproducible report output.
        incompatible.sort_by(|a, b| a.name.cmp(&b.name));

        let report = PythonCompatibilityReport {
            target_python: target_python.to_string(),
            incompatible,
        };
        // `target_python` is always caller-supplied and non-empty (validated
        // upstream when the `--target-python` value is parsed); this guards
        // the invariant rather than handling a real runtime case.
        debug_assert!(!report.target_python.is_empty());

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::use_cases::test_doubles::MockPythonCompatibilityRepository;

    fn pkg(name: &str, version: &str) -> Package {
        Package::new(name.to_string(), version.to_string()).unwrap()
    }

    fn info(requires_python: Option<&str>) -> PythonCompatibilityInfo {
        PythonCompatibilityInfo {
            requires_python: requires_python.map(|s| s.to_string()),
        }
    }

    #[tokio::test]
    async fn test_all_compatible() {
        let repo = MockPythonCompatibilityRepository::with_responses([
            ("requests".to_string(), Ok(info(Some(">=3.7")))),
            ("certifi".to_string(), Ok(info(None))),
        ]);
        let use_case = CheckPythonCompatibilityUseCase::new(repo);

        let packages = vec![pkg("requests", "2.31.0"), pkg("certifi", "2024.1.1")];
        let direct_names = HashSet::new();
        let report = use_case
            .check_with_progress(packages, "3.13", &direct_names)
            .await
            .unwrap();

        assert!(report.is_empty());
        assert_eq!(report.total_count(), 0);
        assert_eq!(report.target_python, "3.13");
    }

    #[tokio::test]
    async fn test_some_incompatible() {
        let repo = MockPythonCompatibilityRepository::with_responses([
            ("requests".to_string(), Ok(info(Some(">=3.7")))),
            ("legacy-lib".to_string(), Ok(info(Some(">=3.8,<3.12")))),
        ]);
        let use_case = CheckPythonCompatibilityUseCase::new(repo);

        let packages = vec![pkg("requests", "2.31.0"), pkg("legacy-lib", "1.0.0")];
        let direct_names = HashSet::new();
        let report = use_case
            .check_with_progress(packages, "3.13", &direct_names)
            .await
            .unwrap();

        assert_eq!(report.total_count(), 1);
        assert_eq!(report.incompatible[0].name, "legacy-lib");
        assert_eq!(report.incompatible[0].version, "1.0.0");
        assert_eq!(
            report.incompatible[0].requires_python,
            Some(">=3.8,<3.12".to_string())
        );
    }

    #[tokio::test]
    async fn test_fetch_failure_soft_failed() {
        let repo = MockPythonCompatibilityRepository::with_responses([
            ("requests".to_string(), Ok(info(Some(">=3.7")))),
            ("broken-pkg".to_string(), Err("network error".to_string())),
            ("legacy-lib".to_string(), Ok(info(Some(">=3.8,<3.12")))),
        ]);
        let use_case = CheckPythonCompatibilityUseCase::new(repo);

        let packages = vec![
            pkg("requests", "2.31.0"),
            pkg("broken-pkg", "0.1.0"),
            pkg("legacy-lib", "1.0.0"),
        ];
        let direct_names = HashSet::new();
        let report = use_case
            .check_with_progress(packages, "3.13", &direct_names)
            .await
            .unwrap();

        // broken-pkg is skipped (soft-failed), the run continues, legacy-lib
        // is still correctly classified as incompatible.
        assert_eq!(report.total_count(), 1);
        assert_eq!(report.incompatible[0].name, "legacy-lib");
    }

    #[tokio::test]
    async fn test_unconfigured_package_is_soft_failed_as_404() {
        let repo = MockPythonCompatibilityRepository::with_responses([]);
        let use_case = CheckPythonCompatibilityUseCase::new(repo);

        let packages = vec![pkg("unknown-pkg", "1.0.0")];
        let direct_names = HashSet::new();
        let report = use_case
            .check_with_progress(packages, "3.13", &direct_names)
            .await
            .unwrap();

        assert!(report.is_empty());
    }

    #[tokio::test]
    async fn test_mixed_direct_and_transitive() {
        let repo = MockPythonCompatibilityRepository::with_responses([
            ("direct-legacy".to_string(), Ok(info(Some(">=3.8,<3.12")))),
            (
                "transitive-legacy".to_string(),
                Ok(info(Some(">=3.9,<3.12"))),
            ),
        ]);
        let use_case = CheckPythonCompatibilityUseCase::new(repo);

        let packages = vec![
            pkg("direct-legacy", "1.0.0"),
            pkg("transitive-legacy", "2.0.0"),
        ];
        let mut direct_names = HashSet::new();
        direct_names.insert("direct-legacy");
        let report = use_case
            .check_with_progress(packages, "3.13", &direct_names)
            .await
            .unwrap();

        assert_eq!(report.total_count(), 2);
        assert_eq!(report.direct_count(), 1);
        assert_eq!(report.transitive_count(), 1);

        let direct_view = report
            .incompatible
            .iter()
            .find(|v| v.name == "direct-legacy")
            .unwrap();
        assert!(direct_view.is_direct);
        let transitive_view = report
            .incompatible
            .iter()
            .find(|v| v.name == "transitive-legacy")
            .unwrap();
        assert!(!transitive_view.is_direct);
    }

    #[tokio::test]
    async fn test_empty_package_list() {
        let repo = MockPythonCompatibilityRepository::with_responses([]);
        let use_case = CheckPythonCompatibilityUseCase::new(repo);

        let direct_names = HashSet::new();
        let report = use_case
            .check_with_progress(vec![], "3.13", &direct_names)
            .await
            .unwrap();

        assert!(report.is_empty());
        assert_eq!(report.total_count(), 0);
    }

    #[tokio::test]
    async fn test_all_fetches_fail() {
        let repo = MockPythonCompatibilityRepository::with_responses([
            ("pkg-a".to_string(), Err("timeout".to_string())),
            ("pkg-b".to_string(), Err("timeout".to_string())),
        ]);
        let use_case = CheckPythonCompatibilityUseCase::new(repo);

        let packages = vec![pkg("pkg-a", "1.0.0"), pkg("pkg-b", "1.0.0")];
        let direct_names = HashSet::new();
        let report = use_case
            .check_with_progress(packages, "3.13", &direct_names)
            .await
            .unwrap();

        assert!(report.is_empty());
    }
}
