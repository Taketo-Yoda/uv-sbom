use crate::ports::outbound::DiffSource;
use std::path::PathBuf;

/// DiffRequest - Internal request DTO for dependency diff generation use case.
///
/// Carries everything `GenerateDiffUseCase::execute` needs: where to read the
/// "base" lockfile from, the project root holding the "current" `uv.lock`,
/// and whether to enrich with CVE data.
#[derive(Debug, Clone)]
pub struct DiffRequest {
    pub source: DiffSource,
    pub project_path: PathBuf,
    /// Whether to enrich results with CVE data. Currently a no-op; enrichment
    /// will be implemented in a follow-up issue.
    pub check_cve: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_request_with_git_ref() {
        let req = DiffRequest {
            source: DiffSource::GitRef("main".to_string()),
            project_path: PathBuf::from("/project"),
            check_cve: false,
        };
        assert_eq!(req.source, DiffSource::GitRef("main".to_string()));
        assert_eq!(req.project_path, PathBuf::from("/project"));
        assert!(!req.check_cve);
    }

    #[test]
    fn test_diff_request_with_file_path() {
        let req = DiffRequest {
            source: DiffSource::FilePath(PathBuf::from("/tmp/uv.lock")),
            project_path: PathBuf::from("/project"),
            check_cve: true,
        };
        assert_eq!(
            req.source,
            DiffSource::FilePath(PathBuf::from("/tmp/uv.lock"))
        );
        assert!(req.check_cve);
    }
}
