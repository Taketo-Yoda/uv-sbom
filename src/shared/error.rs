use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum SbomError {
    LockfileNotFound {
        path: PathBuf,
        suggestion: String,
    },
    LockfileParseError {
        path: PathBuf,
        details: String,
    },
    /// Error when fetching license information fails
    ///
    /// Note: Currently not used by the CLI implementation, but available for library consumers
    /// implementing custom license repositories or error handling strategies.
    #[allow(dead_code)]
    LicenseFetchError {
        package_name: String,
        details: String,
    },
    /// Error when SBOM output generation fails
    ///
    /// Note: Currently not used by the CLI implementation, but available for library consumers
    /// implementing custom formatters or error handling strategies.
    #[allow(dead_code)]
    OutputGenerationError {
        format: String,
        details: String,
    },
    FileWriteError {
        path: PathBuf,
        details: String,
    },
    InvalidProjectPath {
        path: PathBuf,
        reason: String,
    },
}

impl fmt::Display for SbomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SbomError::LockfileNotFound { path, suggestion } => {
                write!(
                    f,
                    "uv.lock file not found: {}\n\n💡 Hint: {}",
                    path.display(),
                    suggestion
                )
            }
            SbomError::LockfileParseError { path, details } => {
                write!(
                    f,
                    "Failed to parse uv.lock file: {}\nDetails: {}\n\n💡 Hint: Please verify that the uv.lock file is in the correct format",
                    path.display(),
                    details
                )
            }
            SbomError::LicenseFetchError {
                package_name,
                details,
            } => {
                write!(
                    f,
                    "Failed to fetch license information for package \"{}\"\nDetails: {}\n\n💡 Hint: Please check your internet connection",
                    package_name, details
                )
            }
            SbomError::OutputGenerationError { format, details } => {
                write!(
                    f,
                    "Failed to generate {} format output\nDetails: {}",
                    format, details
                )
            }
            SbomError::FileWriteError { path, details } => {
                write!(
                    f,
                    "Failed to write to file: {}\nDetails: {}\n\n💡 Hint: Please verify that the directory exists and you have write permissions",
                    path.display(),
                    details
                )
            }
            SbomError::InvalidProjectPath { path, reason } => {
                write!(
                    f,
                    "Invalid project path: {}\nReason: {}\n\n💡 Hint: Please specify a valid project directory",
                    path.display(),
                    reason
                )
            }
        }
    }
}

impl std::error::Error for SbomError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_lockfile_not_found_display() {
        let error = SbomError::LockfileNotFound {
            path: PathBuf::from("/test/path/uv.lock"),
            suggestion: "Test suggestion".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("uv.lock file not found"));
        assert!(display.contains("/test/path/uv.lock"));
        assert!(display.contains("💡 Hint:"));
        assert!(display.contains("Test suggestion"));
    }

    #[test]
    fn test_lockfile_parse_error_display() {
        let error = SbomError::LockfileParseError {
            path: PathBuf::from("/test/uv.lock"),
            details: "Invalid TOML syntax".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("Failed to parse uv.lock file"));
        assert!(display.contains("/test/uv.lock"));
        assert!(display.contains("Invalid TOML syntax"));
        assert!(display.contains("💡 Hint:"));
    }

    #[test]
    fn test_license_fetch_error_display() {
        let error = SbomError::LicenseFetchError {
            package_name: "test-package".to_string(),
            details: "Network timeout".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("Failed to fetch license information"));
        assert!(display.contains("test-package"));
        assert!(display.contains("Network timeout"));
        assert!(display.contains("💡 Hint:"));
        assert!(display.contains("internet connection"));
    }

    #[test]
    fn test_output_generation_error_display() {
        let error = SbomError::OutputGenerationError {
            format: "JSON".to_string(),
            details: "Serialization failed".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("Failed to generate JSON format output"));
        assert!(display.contains("Serialization failed"));
    }

    #[test]
    fn test_file_write_error_display() {
        let error = SbomError::FileWriteError {
            path: PathBuf::from("/test/output.json"),
            details: "Permission denied".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("Failed to write to file"));
        assert!(display.contains("/test/output.json"));
        assert!(display.contains("Permission denied"));
        assert!(display.contains("💡 Hint:"));
    }

    #[test]
    fn test_invalid_project_path_display() {
        let error = SbomError::InvalidProjectPath {
            path: PathBuf::from("/invalid/path"),
            reason: "Directory does not exist".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("Invalid project path"));
        assert!(display.contains("/invalid/path"));
        assert!(display.contains("Directory does not exist"));
        assert!(display.contains("💡 Hint:"));
    }
}
