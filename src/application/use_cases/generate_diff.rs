use crate::application::dto::{DiffRequest, DiffResult};
use crate::application::read_models::cve_delta_view::{CveDeltaEntry, CveDeltaView};
use crate::application::read_models::vulnerability_view::SeverityView;
use crate::ports::outbound::{
    DiffLockfileReader, DiffSource, LockfileReader, VulnerabilityRepository,
};
use crate::sbom_generation::domain::services::DependencyDiffAnalyzer;
use crate::sbom_generation::domain::vulnerability::PackageVulnerabilities;
use crate::sbom_generation::domain::Package;
use crate::shared::Result;
use std::collections::{HashMap, HashSet};

/// Orchestrates dependency diff generation between two lockfile snapshots.
///
/// `LR` reads the current `uv.lock`, `DLR` reads the base lockfile (git ref or
/// file path), and `VR` fetches OSV vulnerability data. `VR` defaults to `()`
/// (the Null Object implementation) when CVE checking is not needed.
pub struct GenerateDiffUseCase<LR, DLR, VR = ()>
where
    LR: LockfileReader,
    DLR: DiffLockfileReader,
    VR: VulnerabilityRepository,
{
    lockfile_reader: LR,
    diff_reader: DLR,
    vulnerability_repository: Option<VR>,
}

impl<LR, DLR, VR> GenerateDiffUseCase<LR, DLR, VR>
where
    LR: LockfileReader,
    DLR: DiffLockfileReader,
    VR: VulnerabilityRepository,
{
    /// Creates a new [`GenerateDiffUseCase`] with the given readers and optional vulnerability repository.
    pub fn new(
        lockfile_reader: LR,
        diff_reader: DLR,
        vulnerability_repository: Option<VR>,
    ) -> Self {
        Self {
            lockfile_reader,
            diff_reader,
            vulnerability_repository,
        }
    }

    /// Execute the diff use case.
    ///
    /// Reads the current `uv.lock` via `lockfile_reader`, reads the base packages
    /// via `diff_reader`, and returns a `DiffResult` with `diff.base_ref` set to
    /// the string representation of the source. Non-UTF-8 path bytes are replaced
    /// with U+FFFD (display use only — the string is never round-tripped to the FS).
    ///
    /// When `request.check_cve` is true and a `VulnerabilityRepository` was supplied,
    /// runs OSV checks on both the base and current package sets and populates
    /// `cve_delta` with newly introduced and resolved CVEs. When `check_cve` is false
    /// or no repository was supplied, `cve_delta` is `None`.
    pub async fn execute(&self, request: DiffRequest) -> Result<DiffResult> {
        let (current, _deps) = self
            .lockfile_reader
            .read_and_parse_lockfile(&request.project_path)?;

        let base = self
            .diff_reader
            .read_base_packages(&request.source, &request.project_path)?;

        let mut diff = DependencyDiffAnalyzer::analyze(&base, &current);

        diff.base_ref = match &request.source {
            DiffSource::GitRef(r) => r.clone(),
            DiffSource::FilePath(p) => p.to_string_lossy().into_owned(),
        };

        let cve_delta = if request.check_cve {
            match &self.vulnerability_repository {
                Some(repo) => Some(compute_cve_delta(repo, &base, &current).await?),
                None => None,
            }
        } else {
            None
        };

        Ok(DiffResult { diff, cve_delta })
    }
}

/// Fetches OSV vulnerability data for `base` and `current` package sets sequentially,
/// then computes the set difference keyed on `(package_name, version, cve_id)`.
/// Sequential fetching is intentional: OSV API rate limits make parallel calls
/// counter-productive, and it simplifies mock ordering in tests.
async fn compute_cve_delta<VR: VulnerabilityRepository>(
    repo: &VR,
    base: &[Package],
    current: &[Package],
) -> Result<CveDeltaView> {
    let base_vulns = repo.fetch_vulnerabilities(base.to_vec()).await?;
    let current_vulns = repo.fetch_vulnerabilities(current.to_vec()).await?;

    let base_map = flatten_to_entries(&base_vulns);
    let current_map = flatten_to_entries(&current_vulns);

    let base_keys: HashSet<_> = base_map.keys().cloned().collect();
    let current_keys: HashSet<_> = current_map.keys().cloned().collect();

    let new: Vec<CveDeltaEntry> = current_keys
        .difference(&base_keys)
        .filter_map(|k| current_map.get(k).cloned())
        .collect();

    let resolved: Vec<CveDeltaEntry> = base_keys
        .difference(&current_keys)
        .filter_map(|k| base_map.get(k).cloned())
        .collect();

    Ok(CveDeltaView { new, resolved })
}

/// Converts a flat list of `PackageVulnerabilities` into a map keyed by
/// `(package_name, version, cve_id)`. This three-part key ensures that the same
/// CVE ID on different package versions is treated as distinct entries.
fn flatten_to_entries(
    pkg_vulns: &[PackageVulnerabilities],
) -> HashMap<(String, String, String), CveDeltaEntry> {
    let mut map = HashMap::new();
    for pv in pkg_vulns {
        for vuln in pv.vulnerabilities() {
            let key = (
                pv.package_name().to_string(),
                pv.current_version().to_string(),
                vuln.id().to_string(),
            );
            let entry = CveDeltaEntry::new(
                pv.package_name().to_string(),
                pv.current_version().to_string(),
                vuln.id().to_string(),
                Some(SeverityView::from(vuln.severity())),
                vuln.summary().unwrap_or("").to_string(),
            );
            map.insert(key, entry);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::use_cases::test_doubles::PairedMockVulnerabilityRepository;
    use crate::ports::outbound::lockfile_reader::LockfileParseResult;
    use crate::sbom_generation::domain::dependency_diff::ChangeType;
    use crate::sbom_generation::domain::vulnerability::{Severity, Vulnerability};
    use crate::sbom_generation::domain::Package;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    fn pkg(name: &str, version: &str) -> Package {
        Package::new(name.to_string(), version.to_string()).unwrap()
    }

    fn make_vuln(id: &str, severity: Severity) -> Vulnerability {
        Vulnerability::new(id.to_string(), None, severity, None, None).unwrap()
    }

    fn make_pkg_vulns(
        name: &str,
        version: &str,
        vulns: Vec<Vulnerability>,
    ) -> PackageVulnerabilities {
        PackageVulnerabilities::new(name.to_string(), version.to_string(), vulns)
    }

    struct StubLockfileReader {
        packages: Vec<Package>,
    }

    impl LockfileReader for StubLockfileReader {
        fn read_lockfile(&self, _project_path: &Path) -> Result<String> {
            Ok(String::new())
        }

        fn read_and_parse_lockfile(&self, _project_path: &Path) -> Result<LockfileParseResult> {
            Ok((self.packages.clone(), HashMap::new()))
        }

        fn read_and_parse_lockfile_for_member(
            &self,
            _project_path: &Path,
            _member_name: &str,
        ) -> Result<LockfileParseResult> {
            Ok((self.packages.clone(), HashMap::new()))
        }
    }

    struct StubDiffLockfileReader {
        packages: Vec<Package>,
    }

    impl DiffLockfileReader for StubDiffLockfileReader {
        fn read_base_packages(
            &self,
            _source: &DiffSource,
            _project_path: &Path,
        ) -> Result<Vec<Package>> {
            Ok(self.packages.clone())
        }
    }

    fn make_use_case(
        current: Vec<Package>,
        base: Vec<Package>,
    ) -> GenerateDiffUseCase<StubLockfileReader, StubDiffLockfileReader, ()> {
        GenerateDiffUseCase::new(
            StubLockfileReader { packages: current },
            StubDiffLockfileReader { packages: base },
            None,
        )
    }

    fn make_use_case_with_vuln_repo(
        current: Vec<Package>,
        base: Vec<Package>,
        repo: PairedMockVulnerabilityRepository,
    ) -> GenerateDiffUseCase<
        StubLockfileReader,
        StubDiffLockfileReader,
        PairedMockVulnerabilityRepository,
    > {
        GenerateDiffUseCase::new(
            StubLockfileReader { packages: current },
            StubDiffLockfileReader { packages: base },
            Some(repo),
        )
    }

    fn git_ref_request(ref_name: &str) -> DiffRequest {
        DiffRequest {
            source: DiffSource::GitRef(ref_name.to_string()),
            project_path: PathBuf::from("/project"),
            check_cve: false,
        }
    }

    fn git_ref_request_with_cve(ref_name: &str) -> DiffRequest {
        DiffRequest {
            source: DiffSource::GitRef(ref_name.to_string()),
            project_path: PathBuf::from("/project"),
            check_cve: true,
        }
    }

    #[tokio::test]
    async fn test_execute_detects_added_package() {
        let uc = make_use_case(vec![pkg("requests", "2.31.0")], vec![]);
        let result = uc.execute(git_ref_request("main")).await.unwrap();
        assert_eq!(result.diff.changes.len(), 1);
        assert_eq!(result.diff.changes[0].change_type, ChangeType::Added);
        assert_eq!(result.diff.changes[0].package_name, "requests");
        assert_eq!(result.diff.summary.added, 1);
    }

    #[tokio::test]
    async fn test_execute_detects_removed_package() {
        let uc = make_use_case(vec![], vec![pkg("requests", "2.31.0")]);
        let result = uc.execute(git_ref_request("main")).await.unwrap();
        assert_eq!(result.diff.changes.len(), 1);
        assert_eq!(result.diff.changes[0].change_type, ChangeType::Removed);
        assert_eq!(result.diff.summary.removed, 1);
    }

    #[tokio::test]
    async fn test_execute_detects_updated_package() {
        let uc = make_use_case(
            vec![pkg("urllib3", "2.0.7")],
            vec![pkg("urllib3", "1.26.5")],
        );
        let result = uc.execute(git_ref_request("main")).await.unwrap();
        assert_eq!(result.diff.changes.len(), 1);
        assert_eq!(result.diff.changes[0].change_type, ChangeType::Updated);
        assert_eq!(
            result.diff.changes[0].old_version,
            Some("1.26.5".to_string())
        );
        assert_eq!(
            result.diff.changes[0].new_version,
            Some("2.0.7".to_string())
        );
        assert_eq!(result.diff.summary.updated, 1);
    }

    #[tokio::test]
    async fn test_execute_mixed_changes() {
        let base = vec![pkg("a", "1.0"), pkg("b", "1.0"), pkg("c", "1.0")];
        let current = vec![pkg("a", "1.0"), pkg("b", "2.0"), pkg("d", "1.0")];
        let uc = make_use_case(current, base);
        let result = uc.execute(git_ref_request("main")).await.unwrap();
        assert_eq!(result.diff.summary.added, 1);
        assert_eq!(result.diff.summary.updated, 1);
        assert_eq!(result.diff.summary.removed, 1);
        assert_eq!(result.diff.summary.unchanged, 1);
    }

    #[tokio::test]
    async fn test_execute_base_ref_uses_git_ref_string() {
        let uc = make_use_case(vec![], vec![]);
        let result = uc.execute(git_ref_request("main")).await.unwrap();
        assert_eq!(result.diff.base_ref, "main");
    }

    #[tokio::test]
    async fn test_execute_base_ref_uses_file_path_string() {
        let uc = make_use_case(vec![], vec![]);
        let req = DiffRequest {
            source: DiffSource::FilePath(PathBuf::from("/tmp/uv.lock")),
            project_path: PathBuf::from("/project"),
            check_cve: false,
        };
        let result = uc.execute(req).await.unwrap();
        assert_eq!(result.diff.base_ref, "/tmp/uv.lock");
    }

    #[tokio::test]
    async fn test_execute_check_cve_false_skips_osv_and_cve_delta_is_none() {
        let uc = make_use_case(vec![pkg("a", "1.0")], vec![pkg("a", "2.0")]);
        let result = uc.execute(git_ref_request("main")).await.unwrap();
        assert!(result.cve_delta.is_none());
    }

    #[tokio::test]
    async fn test_execute_check_cve_true_no_repo_returns_none() {
        let uc = make_use_case(vec![pkg("a", "1.0")], vec![]);
        let result = uc.execute(git_ref_request_with_cve("main")).await.unwrap();
        assert!(result.cve_delta.is_none());
    }

    #[tokio::test]
    async fn test_execute_cve_delta_new_cve_appears_in_current() {
        let repo = PairedMockVulnerabilityRepository::new(
            vec![],
            vec![make_pkg_vulns(
                "requests",
                "2.31.0",
                vec![make_vuln("CVE-2024-1234", Severity::High)],
            )],
        );
        let uc = make_use_case_with_vuln_repo(
            vec![pkg("requests", "2.31.0")],
            vec![pkg("requests", "2.30.0")],
            repo,
        );
        let result = uc.execute(git_ref_request_with_cve("main")).await.unwrap();
        let delta = result.cve_delta.unwrap();
        assert_eq!(delta.new.len(), 1);
        assert_eq!(delta.new[0].cve_id, "CVE-2024-1234");
        assert!(delta.resolved.is_empty());
    }

    #[tokio::test]
    async fn test_execute_cve_delta_resolved_cve_absent_in_current() {
        let repo = PairedMockVulnerabilityRepository::new(
            vec![make_pkg_vulns(
                "requests",
                "2.30.0",
                vec![make_vuln("CVE-2023-9999", Severity::Medium)],
            )],
            vec![],
        );
        let uc = make_use_case_with_vuln_repo(
            vec![pkg("requests", "2.31.0")],
            vec![pkg("requests", "2.30.0")],
            repo,
        );
        let result = uc.execute(git_ref_request_with_cve("main")).await.unwrap();
        let delta = result.cve_delta.unwrap();
        assert!(delta.new.is_empty());
        assert_eq!(delta.resolved.len(), 1);
        assert_eq!(delta.resolved[0].cve_id, "CVE-2023-9999");
    }

    #[tokio::test]
    async fn test_execute_cve_delta_no_change_produces_empty_lists() {
        let shared_vuln = make_pkg_vulns(
            "requests",
            "2.31.0",
            vec![make_vuln("CVE-2024-0001", Severity::Low)],
        );
        let repo =
            PairedMockVulnerabilityRepository::new(vec![shared_vuln.clone()], vec![shared_vuln]);
        let uc = make_use_case_with_vuln_repo(
            vec![pkg("requests", "2.31.0")],
            vec![pkg("requests", "2.31.0")],
            repo,
        );
        let result = uc.execute(git_ref_request_with_cve("main")).await.unwrap();
        let delta = result.cve_delta.unwrap();
        assert!(delta.new.is_empty());
        assert!(delta.resolved.is_empty());
    }

    #[tokio::test]
    async fn test_execute_cve_delta_same_cve_id_different_version_counts_separately() {
        let repo = PairedMockVulnerabilityRepository::new(
            vec![make_pkg_vulns(
                "requests",
                "2.30.0",
                vec![make_vuln("CVE-2024-0001", Severity::High)],
            )],
            vec![make_pkg_vulns(
                "requests",
                "2.31.0",
                vec![make_vuln("CVE-2024-0001", Severity::High)],
            )],
        );
        let uc = make_use_case_with_vuln_repo(
            vec![pkg("requests", "2.31.0")],
            vec![pkg("requests", "2.30.0")],
            repo,
        );
        let result = uc.execute(git_ref_request_with_cve("main")).await.unwrap();
        let delta = result.cve_delta.unwrap();
        // (requests, 2.30.0, CVE-2024-0001) resolved; (requests, 2.31.0, CVE-2024-0001) is new
        assert_eq!(delta.new.len(), 1);
        assert_eq!(delta.resolved.len(), 1);
        assert_eq!(delta.new[0].version, "2.31.0");
        assert_eq!(delta.resolved[0].version, "2.30.0");
    }
}
