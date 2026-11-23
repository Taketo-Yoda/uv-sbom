use super::progress_bar::ProgressBarHandle;
use crate::application::read_models::{YankedPackageView, YankedPackagesReport};
use crate::ports::outbound::yanked_status_repository::{YankedStatus, YankedStatusRepository};
use crate::ports::outbound::{PackageSourceKind, PackageSourceMap};
use crate::sbom_generation::domain::Package;
use crate::shared::Result;
use futures::stream::{self, StreamExt};
use std::collections::HashSet;
use std::sync::atomic::Ordering;

const MAX_CONCURRENT: usize = 10;

type FetchOutcome = (Package, std::result::Result<YankedStatus, String>);

/// Use case for checking whether locked package versions have been yanked on PyPI.
///
/// Fetches yanked status for all PyPI-sourced packages in parallel, filters for
/// yanked ones, and builds a sorted `YankedPackagesReport`. Per-package fetch
/// failures are soft-failed: the package is skipped and the run continues.
///
/// # Type Parameters
/// * `YR` - `YankedStatusRepository` implementation
#[allow(dead_code)] // WIRE(#1155): remove when GenerateSbomUseCase calls CheckYankedPackagesUseCase
pub struct CheckYankedPackagesUseCase<YR: YankedStatusRepository> {
    yanked_repository: YR,
}

#[allow(dead_code)] // WIRE(#1155): remove when GenerateSbomUseCase calls CheckYankedPackagesUseCase
impl<YR: YankedStatusRepository> CheckYankedPackagesUseCase<YR> {
    pub fn new(yanked_repository: YR) -> Self {
        Self { yanked_repository }
    }

    /// Fetches yanked status for all PyPI-sourced packages in parallel with a
    /// progress bar, and returns a report of packages whose locked versions are
    /// yanked.
    ///
    /// `source_map` classifies each package's origin; non-PyPI packages are
    /// never sent to the repository. `direct_names` is the set of package names
    /// that are direct dependencies of the current project.
    pub async fn check_with_progress(
        &self,
        packages: Vec<Package>,
        source_map: &PackageSourceMap,
        direct_names: &HashSet<&str>,
    ) -> Result<YankedPackagesReport> {
        let pypi_packages: Vec<Package> = packages
            .into_iter()
            .filter(|p| {
                source_map
                    .get(p.name())
                    .is_none_or(|kind| matches!(kind, PackageSourceKind::PyPi))
            })
            .collect();

        let fetched = self.fetch_all(pypi_packages).await;
        Ok(Self::build_report(fetched, direct_names))
    }

    async fn fetch_all(&self, packages: Vec<Package>) -> Vec<FetchOutcome> {
        let total = packages.len();
        let progress = ProgressBarHandle::spawn(total, "Checking for yanked versions...");
        let progress_current = progress.counter();

        let fetched: Vec<FetchOutcome> = stream::iter(packages)
            .map(|package| {
                let cur = progress_current.clone();
                async move {
                    let result = self
                        .yanked_repository
                        .fetch_yanked_status(package.name(), package.version())
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

    fn build_report(
        fetched: Vec<FetchOutcome>,
        direct_names: &HashSet<&str>,
    ) -> YankedPackagesReport {
        let mut yanked: Vec<YankedPackageView> = fetched
            .into_iter()
            .filter_map(|(package, result)| {
                let status = result.ok()?;
                if !status.yanked {
                    return None;
                }
                Some(YankedPackageView {
                    name: package.name().to_string(),
                    version: package.version().to_string(),
                    reason: status.reason,
                    is_direct: direct_names.contains(package.name()),
                })
            })
            .collect();

        yanked.sort_by(|a, b| b.is_direct.cmp(&a.is_direct).then(a.name.cmp(&b.name)));

        YankedPackagesReport { packages: yanked }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct MockYankedStatusRepository {
        responses: Arc<HashMap<String, std::result::Result<YankedStatus, String>>>,
    }

    impl MockYankedStatusRepository {
        fn with_responses(
            pairs: impl IntoIterator<Item = (String, std::result::Result<YankedStatus, String>)>,
        ) -> Self {
            Self {
                responses: Arc::new(pairs.into_iter().collect()),
            }
        }
    }

    #[async_trait]
    impl YankedStatusRepository for MockYankedStatusRepository {
        async fn fetch_yanked_status(
            &self,
            package_name: &str,
            _version: &str,
        ) -> Result<YankedStatus> {
            match self.responses.get(package_name) {
                Some(Ok(status)) => Ok(status.clone()),
                Some(Err(msg)) => Err(anyhow::anyhow!("{}", msg)),
                None => Err(anyhow::anyhow!("404 Not Found: {}", package_name)),
            }
        }
    }

    fn pkg(name: &str, version: &str) -> Package {
        Package::new(name.to_string(), version.to_string()).unwrap()
    }

    fn yanked(reason: Option<&str>) -> YankedStatus {
        YankedStatus {
            yanked: true,
            reason: reason.map(|s| s.to_string()),
        }
    }

    fn not_yanked() -> YankedStatus {
        YankedStatus {
            yanked: false,
            reason: None,
        }
    }

    #[tokio::test]
    async fn test_only_yanked_kept() {
        let repo = MockYankedStatusRepository::with_responses([
            ("requests".to_string(), Ok(yanked(Some("CVE fix")))),
            ("certifi".to_string(), Ok(not_yanked())),
        ]);
        let uc = CheckYankedPackagesUseCase::new(repo);
        let packages = vec![pkg("requests", "2.32.0"), pkg("certifi", "2024.1.1")];
        let report = uc
            .check_with_progress(packages, &PackageSourceMap::new(), &HashSet::new())
            .await
            .unwrap();
        assert_eq!(report.total_count(), 1);
        assert_eq!(report.packages[0].name, "requests");
        assert_eq!(report.packages[0].reason.as_deref(), Some("CVE fix"));
    }

    #[tokio::test]
    async fn test_sort_order_direct_first_then_name() {
        let repo = MockYankedStatusRepository::with_responses([
            ("zzz-lib".to_string(), Ok(yanked(None))),
            ("aaa-lib".to_string(), Ok(yanked(None))),
            ("direct-lib".to_string(), Ok(yanked(None))),
        ]);
        let uc = CheckYankedPackagesUseCase::new(repo);
        let packages = vec![
            pkg("zzz-lib", "1.0.0"),
            pkg("aaa-lib", "1.0.0"),
            pkg("direct-lib", "1.0.0"),
        ];
        let mut direct_names = HashSet::new();
        direct_names.insert("direct-lib");
        let report = uc
            .check_with_progress(packages, &PackageSourceMap::new(), &direct_names)
            .await
            .unwrap();
        assert_eq!(report.packages[0].name, "direct-lib");
        assert!(report.packages[0].is_direct);
        assert_eq!(report.packages[1].name, "aaa-lib");
        assert_eq!(report.packages[2].name, "zzz-lib");
    }

    #[tokio::test]
    async fn test_soft_fail_on_per_package_error() {
        let repo = MockYankedStatusRepository::with_responses([
            ("good-pkg".to_string(), Ok(yanked(None))),
            ("broken-pkg".to_string(), Err("network error".to_string())),
        ]);
        let uc = CheckYankedPackagesUseCase::new(repo);
        let packages = vec![pkg("good-pkg", "1.0.0"), pkg("broken-pkg", "1.0.0")];
        let report = uc
            .check_with_progress(packages, &PackageSourceMap::new(), &HashSet::new())
            .await
            .unwrap();
        assert_eq!(report.total_count(), 1);
        assert_eq!(report.packages[0].name, "good-pkg");
    }

    #[tokio::test]
    async fn test_non_pypi_packages_never_looked_up() {
        let repo = MockYankedStatusRepository::with_responses([]);
        let uc = CheckYankedPackagesUseCase::new(repo);
        let mut source_map = PackageSourceMap::new();
        source_map.insert(
            "git-pkg".to_string(),
            PackageSourceKind::Git("https://github.com/x/y".to_string()),
        );
        source_map.insert(
            "url-pkg".to_string(),
            PackageSourceKind::DirectUrl("https://example.com/a.whl".to_string()),
        );
        source_map.insert(
            "private-pkg".to_string(),
            PackageSourceKind::PrivateRegistry("https://private.index/".to_string()),
        );
        source_map.insert(
            "local-pkg".to_string(),
            PackageSourceKind::LocalPath("./lib".to_string()),
        );
        let packages = vec![
            pkg("git-pkg", "1.0.0"),
            pkg("url-pkg", "1.0.0"),
            pkg("private-pkg", "1.0.0"),
            pkg("local-pkg", "1.0.0"),
        ];
        let report = uc
            .check_with_progress(packages, &source_map, &HashSet::new())
            .await
            .unwrap();
        assert!(report.is_empty());
    }

    #[tokio::test]
    async fn test_empty_input() {
        let repo = MockYankedStatusRepository::with_responses([]);
        let uc = CheckYankedPackagesUseCase::new(repo);
        let report = uc
            .check_with_progress(vec![], &PackageSourceMap::new(), &HashSet::new())
            .await
            .unwrap();
        assert!(report.is_empty());
        assert_eq!(report.total_count(), 0);
    }

    #[tokio::test]
    async fn test_all_fetches_fail() {
        let repo = MockYankedStatusRepository::with_responses([
            ("a".to_string(), Err("timeout".to_string())),
            ("b".to_string(), Err("timeout".to_string())),
        ]);
        let uc = CheckYankedPackagesUseCase::new(repo);
        let packages = vec![pkg("a", "1.0.0"), pkg("b", "1.0.0")];
        let report = uc
            .check_with_progress(packages, &PackageSourceMap::new(), &HashSet::new())
            .await
            .unwrap();
        assert!(report.is_empty());
    }

    #[tokio::test]
    async fn test_pypi_packages_looked_up() {
        let repo = MockYankedStatusRepository::with_responses([(
            "pypi-pkg".to_string(),
            Ok(yanked(Some("bad release"))),
        )]);
        let uc = CheckYankedPackagesUseCase::new(repo);
        let mut source_map = PackageSourceMap::new();
        source_map.insert("pypi-pkg".to_string(), PackageSourceKind::PyPi);
        let packages = vec![pkg("pypi-pkg", "1.0.0")];
        let report = uc
            .check_with_progress(packages, &source_map, &HashSet::new())
            .await
            .unwrap();
        assert_eq!(report.total_count(), 1);
        assert_eq!(report.packages[0].name, "pypi-pkg");
    }

    #[tokio::test]
    async fn test_mixed_direct_and_transitive() {
        let repo = MockYankedStatusRepository::with_responses([
            ("direct-yanked".to_string(), Ok(yanked(None))),
            ("transitive-yanked".to_string(), Ok(yanked(None))),
        ]);
        let uc = CheckYankedPackagesUseCase::new(repo);
        let packages = vec![
            pkg("direct-yanked", "1.0.0"),
            pkg("transitive-yanked", "2.0.0"),
        ];
        let mut direct_names = HashSet::new();
        direct_names.insert("direct-yanked");
        let report = uc
            .check_with_progress(packages, &PackageSourceMap::new(), &direct_names)
            .await
            .unwrap();
        assert_eq!(report.total_count(), 2);
        assert_eq!(report.direct_count(), 1);
        assert_eq!(report.transitive_count(), 1);
    }
}
