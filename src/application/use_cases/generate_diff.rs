use crate::application::dto::DiffRequest;
use crate::ports::outbound::{DiffLockfileReader, DiffSource, LockfileReader};
use crate::sbom_generation::domain::dependency_diff::DependencyDiff;
use crate::sbom_generation::domain::services::DependencyDiffAnalyzer;
use crate::shared::Result;

// Wired to the binary in a subsequent CLI integration subtask of #224.
#[allow(dead_code)]
pub struct GenerateDiffUseCase<LR, DLR>
where
    LR: LockfileReader,
    DLR: DiffLockfileReader,
{
    lockfile_reader: LR,
    diff_reader: DLR,
}

#[allow(dead_code)]
impl<LR, DLR> GenerateDiffUseCase<LR, DLR>
where
    LR: LockfileReader,
    DLR: DiffLockfileReader,
{
    pub fn new(lockfile_reader: LR, diff_reader: DLR) -> Self {
        Self {
            lockfile_reader,
            diff_reader,
        }
    }

    /// Execute the diff use case.
    ///
    /// Reads the current `uv.lock` via `lockfile_reader`, reads the base packages
    /// via `diff_reader`, and returns a `DependencyDiff` with `base_ref` set to
    /// the string representation of the source. Non-UTF-8 path bytes are replaced
    /// with U+FFFD (display use only — the string is never round-tripped to the FS).
    ///
    /// CVE enrichment (`check_cve`) is accepted but currently a no-op; it will be
    /// wired in a follow-up issue.
    pub fn execute(&self, request: DiffRequest) -> Result<DependencyDiff> {
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

        // CVE enrichment deferred to a follow-up issue.
        let _ = request.check_cve;

        Ok(diff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::outbound::lockfile_reader::LockfileParseResult;
    use crate::sbom_generation::domain::dependency_diff::ChangeType;
    use crate::sbom_generation::domain::Package;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    fn pkg(name: &str, version: &str) -> Package {
        Package::new(name.to_string(), version.to_string()).unwrap()
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
    ) -> GenerateDiffUseCase<StubLockfileReader, StubDiffLockfileReader> {
        GenerateDiffUseCase::new(
            StubLockfileReader { packages: current },
            StubDiffLockfileReader { packages: base },
        )
    }

    fn git_ref_request(ref_name: &str) -> DiffRequest {
        DiffRequest {
            source: DiffSource::GitRef(ref_name.to_string()),
            project_path: PathBuf::from("/project"),
            format: crate::application::dto::OutputFormat::Json,
            check_cve: false,
        }
    }

    #[test]
    fn test_execute_detects_added_package() {
        let uc = make_use_case(vec![pkg("requests", "2.31.0")], vec![]);
        let diff = uc.execute(git_ref_request("main")).unwrap();
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].change_type, ChangeType::Added);
        assert_eq!(diff.changes[0].package_name, "requests");
        assert_eq!(diff.summary.added, 1);
    }

    #[test]
    fn test_execute_detects_removed_package() {
        let uc = make_use_case(vec![], vec![pkg("requests", "2.31.0")]);
        let diff = uc.execute(git_ref_request("main")).unwrap();
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].change_type, ChangeType::Removed);
        assert_eq!(diff.summary.removed, 1);
    }

    #[test]
    fn test_execute_detects_updated_package() {
        let uc = make_use_case(
            vec![pkg("urllib3", "2.0.7")],
            vec![pkg("urllib3", "1.26.5")],
        );
        let diff = uc.execute(git_ref_request("main")).unwrap();
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].change_type, ChangeType::Updated);
        assert_eq!(diff.changes[0].old_version, Some("1.26.5".to_string()));
        assert_eq!(diff.changes[0].new_version, Some("2.0.7".to_string()));
        assert_eq!(diff.summary.updated, 1);
    }

    #[test]
    fn test_execute_mixed_changes() {
        let base = vec![pkg("a", "1.0"), pkg("b", "1.0"), pkg("c", "1.0")];
        let current = vec![pkg("a", "1.0"), pkg("b", "2.0"), pkg("d", "1.0")];
        let uc = make_use_case(current, base);
        let diff = uc.execute(git_ref_request("main")).unwrap();
        assert_eq!(diff.summary.added, 1);
        assert_eq!(diff.summary.updated, 1);
        assert_eq!(diff.summary.removed, 1);
        assert_eq!(diff.summary.unchanged, 1);
    }

    #[test]
    fn test_execute_base_ref_uses_git_ref_string() {
        let uc = make_use_case(vec![], vec![]);
        let diff = uc.execute(git_ref_request("main")).unwrap();
        assert_eq!(diff.base_ref, "main");
    }

    #[test]
    fn test_execute_base_ref_uses_file_path_string() {
        let uc = make_use_case(vec![], vec![]);
        let req = DiffRequest {
            source: DiffSource::FilePath(PathBuf::from("/tmp/uv.lock")),
            project_path: PathBuf::from("/project"),
            format: crate::application::dto::OutputFormat::Json,
            check_cve: false,
        };
        let diff = uc.execute(req).unwrap();
        assert_eq!(diff.base_ref, "/tmp/uv.lock");
    }

    #[test]
    fn test_execute_check_cve_flag_is_currently_a_noop() {
        let base = vec![pkg("a", "1.0")];
        let current = vec![pkg("a", "2.0")];
        let uc_false = make_use_case(current.clone(), base.clone());
        let uc_true = make_use_case(current, base);
        let diff_false = uc_false.execute(git_ref_request("main")).unwrap();
        let mut req_cve = git_ref_request("main");
        req_cve.check_cve = true;
        let diff_true = uc_true.execute(req_cve).unwrap();
        assert_eq!(diff_false.changes, diff_true.changes);
        assert_eq!(diff_false.summary, diff_true.summary);
    }
}
