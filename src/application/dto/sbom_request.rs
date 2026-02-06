use crate::config::IgnoreCve;
use crate::sbom_generation::domain::vulnerability::Severity;
use crate::shared::error::SbomError;
use crate::shared::Result;
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
    /// Severity threshold for vulnerability filtering
    pub severity_threshold: Option<Severity>,
    /// CVSS threshold for vulnerability filtering
    pub cvss_threshold: Option<f32>,
    /// CVE IDs to ignore during vulnerability checks
    pub ignore_cves: Vec<IgnoreCve>,
}

impl SbomRequest {
    /// Creates a new SbomRequestBuilder for constructing SbomRequest instances.
    ///
    /// This is the recommended way to create SbomRequest instances.
    ///
    /// # Example
    ///
    /// ```
    /// use uv_sbom::application::dto::SbomRequest;
    ///
    /// let request = SbomRequest::builder()
    ///     .project_path(".")
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder() -> SbomRequestBuilder {
        SbomRequestBuilder::new()
    }
}

/// Builder for SbomRequest that enables stepwise construction of request objects.
///
/// This implements the Builder pattern for creating SbomRequest instances
/// with sensible defaults and a fluent API.
///
/// # Example
///
/// ```
/// use uv_sbom::application::dto::SbomRequest;
///
/// // Simple usage - only project_path is required
/// let request = SbomRequest::builder()
///     .project_path(".")
///     .build()
///     .unwrap();
///
/// // With options
/// let request = SbomRequest::builder()
///     .project_path("/path/to/project")
///     .include_dependency_info(true)
///     .check_cve(true)
///     .add_exclude_pattern("test-*")
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct SbomRequestBuilder {
    project_path: Option<PathBuf>,
    include_dependency_info: bool,
    exclude_patterns: Vec<String>,
    dry_run: bool,
    check_cve: bool,
    severity_threshold: Option<Severity>,
    cvss_threshold: Option<f32>,
    ignore_cves: Vec<IgnoreCve>,
}

impl SbomRequestBuilder {
    /// Creates a new SbomRequestBuilder with default values.
    ///
    /// Default values:
    /// - project_path: None (required)
    /// - include_dependency_info: false
    /// - exclude_patterns: empty Vec
    /// - dry_run: false
    /// - check_cve: false
    /// - severity_threshold: None
    /// - cvss_threshold: None
    pub fn new() -> Self {
        Self {
            project_path: None,
            include_dependency_info: false,
            exclude_patterns: Vec::new(),
            dry_run: false,
            check_cve: false,
            severity_threshold: None,
            cvss_threshold: None,
            ignore_cves: Vec::new(),
        }
    }

    /// Sets the project path (required).
    ///
    /// This is the path to the project directory containing uv.lock.
    pub fn project_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.project_path = Some(path.into());
        self
    }

    /// Sets whether to include dependency graph information.
    pub fn include_dependency_info(mut self, include: bool) -> Self {
        self.include_dependency_info = include;
        self
    }

    /// Sets the exclusion patterns for filtering packages.
    pub fn exclude_patterns(mut self, patterns: Vec<String>) -> Self {
        self.exclude_patterns = patterns;
        self
    }

    /// Adds a single exclusion pattern.
    #[allow(dead_code)] // Used by library consumers and tests
    pub fn add_exclude_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.exclude_patterns.push(pattern.into());
        self
    }

    /// Sets whether to perform dry-run validation only.
    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Sets whether to check for vulnerabilities.
    pub fn check_cve(mut self, check: bool) -> Self {
        self.check_cve = check;
        self
    }

    /// Sets the severity threshold for vulnerability filtering.
    #[allow(dead_code)] // Used by library consumers and tests
    pub fn severity_threshold(mut self, severity: Severity) -> Self {
        self.severity_threshold = Some(severity);
        self
    }

    /// Sets the severity threshold from an Option value.
    ///
    /// This is useful when the threshold comes from CLI arguments
    /// which may or may not be specified.
    pub fn severity_threshold_opt(mut self, severity: Option<Severity>) -> Self {
        self.severity_threshold = severity;
        self
    }

    /// Sets the CVSS threshold for vulnerability filtering.
    #[allow(dead_code)] // Used by library consumers and tests
    pub fn cvss_threshold(mut self, cvss: f32) -> Self {
        self.cvss_threshold = Some(cvss);
        self
    }

    /// Sets the CVSS threshold from an Option value.
    ///
    /// This is useful when the threshold comes from CLI arguments
    /// which may or may not be specified.
    pub fn cvss_threshold_opt(mut self, cvss: Option<f32>) -> Self {
        self.cvss_threshold = cvss;
        self
    }

    /// Sets the CVE IDs to ignore during vulnerability checks.
    pub fn ignore_cves(mut self, cves: Vec<IgnoreCve>) -> Self {
        self.ignore_cves = cves;
        self
    }

    /// Builds the SbomRequest, validating that all required fields are set.
    ///
    /// # Errors
    ///
    /// Returns an error if project_path is not set.
    pub fn build(self) -> Result<SbomRequest> {
        let project_path = self.project_path.ok_or_else(|| SbomError::Validation {
            message: "project_path is required".into(),
        })?;

        Ok(SbomRequest {
            project_path,
            include_dependency_info: self.include_dependency_info,
            exclude_patterns: self.exclude_patterns,
            dry_run: self.dry_run,
            check_cve: self.check_cve,
            severity_threshold: self.severity_threshold,
            cvss_threshold: self.cvss_threshold,
            ignore_cves: self.ignore_cves,
        })
    }
}

impl Default for SbomRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IgnoreCve;

    #[test]
    fn test_builder_with_only_project_path() {
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .build()
            .unwrap();

        assert_eq!(request.project_path, PathBuf::from("/test/project"));
        assert!(!request.include_dependency_info);
        assert!(request.exclude_patterns.is_empty());
        assert!(!request.dry_run);
        assert!(!request.check_cve);
        assert!(request.severity_threshold.is_none());
        assert!(request.cvss_threshold.is_none());
        assert!(request.ignore_cves.is_empty());
    }

    #[test]
    fn test_builder_without_project_path_fails() {
        let result = SbomRequest::builder().build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("project_path is required"));
    }

    #[test]
    fn test_builder_with_all_options() {
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .include_dependency_info(true)
            .exclude_patterns(vec!["test-*".to_string()])
            .dry_run(true)
            .check_cve(true)
            .severity_threshold(Severity::High)
            .cvss_threshold(7.5)
            .ignore_cves(vec![IgnoreCve {
                id: "CVE-2024-1234".to_string(),
                reason: Some("test".to_string()),
            }])
            .build()
            .unwrap();

        assert_eq!(request.project_path, PathBuf::from("/test/project"));
        assert!(request.include_dependency_info);
        assert_eq!(request.exclude_patterns, vec!["test-*".to_string()]);
        assert!(request.dry_run);
        assert!(request.check_cve);
        assert_eq!(request.severity_threshold, Some(Severity::High));
        assert_eq!(request.cvss_threshold, Some(7.5));
        assert_eq!(request.ignore_cves.len(), 1);
        assert_eq!(request.ignore_cves[0].id, "CVE-2024-1234");
    }

    #[test]
    fn test_add_exclude_pattern_accumulates() {
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .add_exclude_pattern("pattern1")
            .add_exclude_pattern("pattern2")
            .add_exclude_pattern("pattern3")
            .build()
            .unwrap();

        assert_eq!(request.exclude_patterns.len(), 3);
        assert_eq!(
            request.exclude_patterns,
            vec!["pattern1", "pattern2", "pattern3"]
        );
    }

    #[test]
    fn test_exclude_patterns_replaces_previous() {
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .add_exclude_pattern("old-pattern")
            .exclude_patterns(vec!["new-pattern".to_string()])
            .build()
            .unwrap();

        assert_eq!(request.exclude_patterns, vec!["new-pattern".to_string()]);
    }

    #[test]
    fn test_severity_threshold_opt_with_some() {
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .severity_threshold_opt(Some(Severity::Critical))
            .build()
            .unwrap();

        assert_eq!(request.severity_threshold, Some(Severity::Critical));
    }

    #[test]
    fn test_severity_threshold_opt_with_none() {
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .severity_threshold_opt(None)
            .build()
            .unwrap();

        assert!(request.severity_threshold.is_none());
    }

    #[test]
    fn test_cvss_threshold_opt_with_some() {
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .cvss_threshold_opt(Some(8.0))
            .build()
            .unwrap();

        assert_eq!(request.cvss_threshold, Some(8.0));
    }

    #[test]
    fn test_cvss_threshold_opt_with_none() {
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .cvss_threshold_opt(None)
            .build()
            .unwrap();

        assert!(request.cvss_threshold.is_none());
    }

    #[test]
    fn test_builder_default_trait() {
        let builder = SbomRequestBuilder::default();
        let builder_new = SbomRequestBuilder::new();

        // Both should have same default state
        assert!(builder.project_path.is_none());
        assert!(builder_new.project_path.is_none());
        assert!(!builder.include_dependency_info);
        assert!(!builder_new.include_dependency_info);
    }

    #[test]
    fn test_project_path_accepts_string() {
        let request = SbomRequest::builder()
            .project_path("./relative/path")
            .build()
            .unwrap();

        assert_eq!(request.project_path, PathBuf::from("./relative/path"));
    }

    #[test]
    fn test_project_path_accepts_pathbuf() {
        let path = PathBuf::from("/absolute/path");
        let request = SbomRequest::builder()
            .project_path(path.clone())
            .build()
            .unwrap();

        assert_eq!(request.project_path, path);
    }
}
