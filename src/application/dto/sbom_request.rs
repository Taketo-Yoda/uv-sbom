use std::path::PathBuf;

/// SbomRequest - Internal request DTO for SBOM generation use case
///
/// This DTO represents the internal request structure used within
/// the application layer. It may differ from the external API request.
#[derive(Debug, Clone)]
pub struct SbomRequest {
    /// Path to the project directory containing uv.lock
    pub project_path: PathBuf,
    /// Whether to include dependency graph information
    pub include_dependency_info: bool,
    /// Patterns for excluding packages from the SBOM
    pub exclude_patterns: Vec<String>,
    /// Whether to perform dry-run validation only (skip network operations and output generation)
    pub dry_run: bool,
    /// Whether to check for vulnerabilities using OSV API
    pub check_cve: bool,
}

impl SbomRequest {
    pub fn new(
        project_path: PathBuf,
        include_dependency_info: bool,
        exclude_patterns: Vec<String>,
        dry_run: bool,
        check_cve: bool,
    ) -> Self {
        Self {
            project_path,
            include_dependency_info,
            exclude_patterns,
            dry_run,
            check_cve,
        }
    }
}
