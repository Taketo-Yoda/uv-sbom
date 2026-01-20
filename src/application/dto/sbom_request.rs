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
        })
    }
}

impl Default for SbomRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}
