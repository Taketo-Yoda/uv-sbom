use crate::ports::outbound::DiffSource;
use crate::sbom_generation::domain::vulnerability::Severity;
use std::path::PathBuf;

/// DiffRequest - Internal request DTO for dependency diff generation use case.
///
/// Carries everything `GenerateDiffUseCase::execute` needs: where to read the
/// "base" lockfile from, the project root holding the "current" `uv.lock`,
/// whether to enrich with CVE data, and optional threshold configuration.
#[derive(Debug, Clone)]
pub struct DiffRequest {
    pub source: DiffSource,
    pub project_path: PathBuf,
    /// Whether to enrich results with CVE data.
    pub check_cve: bool,
    /// Minimum severity level for CVE delta entries; entries below this are omitted.
    pub severity_threshold: Option<Severity>,
    /// Minimum CVSS score for CVE delta entries; entries below this are omitted.
    pub cvss_threshold: Option<f32>,
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
            severity_threshold: None,
            cvss_threshold: None,
        };
        assert_eq!(req.source, DiffSource::GitRef("main".to_string()));
        assert_eq!(req.project_path, PathBuf::from("/project"));
        assert!(!req.check_cve);
        assert!(req.severity_threshold.is_none());
        assert!(req.cvss_threshold.is_none());
    }

    #[test]
    fn test_diff_request_with_file_path() {
        let req = DiffRequest {
            source: DiffSource::FilePath(PathBuf::from("/tmp/uv.lock")),
            project_path: PathBuf::from("/project"),
            check_cve: true,
            severity_threshold: None,
            cvss_threshold: None,
        };
        assert_eq!(
            req.source,
            DiffSource::FilePath(PathBuf::from("/tmp/uv.lock"))
        );
        assert!(req.check_cve);
    }

    #[test]
    fn test_diff_request_with_severity_threshold() {
        use crate::sbom_generation::domain::vulnerability::Severity;
        let req = DiffRequest {
            source: DiffSource::GitRef("main".to_string()),
            project_path: PathBuf::from("/project"),
            check_cve: true,
            severity_threshold: Some(Severity::High),
            cvss_threshold: None,
        };
        assert_eq!(req.severity_threshold, Some(Severity::High));
        assert!(req.cvss_threshold.is_none());
    }

    #[test]
    fn test_diff_request_with_cvss_threshold() {
        let req = DiffRequest {
            source: DiffSource::GitRef("main".to_string()),
            project_path: PathBuf::from("/project"),
            check_cve: true,
            severity_threshold: None,
            cvss_threshold: Some(7.0),
        };
        assert!(req.severity_threshold.is_none());
        assert_eq!(req.cvss_threshold, Some(7.0));
    }
}
