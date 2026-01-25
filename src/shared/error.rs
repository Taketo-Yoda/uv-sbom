use std::fmt;
use std::path::PathBuf;
use thiserror::Error;

/// Exit codes for the CLI application.
///
/// These codes allow CI systems to distinguish between different
/// types of failures and successes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// Success - no vulnerabilities detected, or all below threshold
    Success = 0,
    /// Vulnerabilities were detected above the configured threshold
    VulnerabilitiesDetected = 1,
    /// Invalid command-line arguments (clap parsing errors)
    InvalidArguments = 2,
    /// Application error (API error, network error, file I/O error, etc.)
    ApplicationError = 3,
}

impl ExitCode {
    /// Convert to i32 for use with std::process::exit
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

impl fmt::Display for ExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExitCode::Success => write!(f, "Success (0)"),
            ExitCode::VulnerabilitiesDetected => write!(f, "Vulnerabilities Detected (1)"),
            ExitCode::InvalidArguments => write!(f, "Invalid Arguments (2)"),
            ExitCode::ApplicationError => write!(f, "Application Error (3)"),
        }
    }
}

/// Application-specific errors for SBOM generation.
///
/// Uses thiserror to derive Display and Error traits automatically,
/// reducing boilerplate while maintaining user-friendly error messages.
#[derive(Debug, Error)]
pub enum SbomError {
    #[error("uv.lock file not found: {path}\n\n💡 Hint: {suggestion}")]
    LockfileNotFound { path: PathBuf, suggestion: String },

    #[error("Failed to parse uv.lock file: {path}\nDetails: {details}\n\n💡 Hint: Please verify that the uv.lock file is in the correct format")]
    LockfileParseError { path: PathBuf, details: String },

    #[error("Failed to write to file: {path}\nDetails: {details}\n\n💡 Hint: Please verify that the directory exists and you have write permissions")]
    FileWriteError { path: PathBuf, details: String },

    #[error("Invalid project path: {path}\nReason: {reason}\n\n💡 Hint: Please specify a valid project directory")]
    InvalidProjectPath { path: PathBuf, reason: String },

    /// Validation error for builder patterns
    #[error("Validation error: {message}")]
    Validation { message: String },

    #[error("Failed to read file: {path}\nDetails: {details}\n\n💡 Hint: Please verify that the file exists and you have read permissions")]
    FileReadError { path: PathBuf, details: String },

    #[error("Security violation: {path}\nReason: {reason}\n\n💡 Hint: {hint}")]
    SecurityError {
        path: PathBuf,
        reason: String,
        hint: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ExitCode tests
    #[test]
    fn test_exit_code_values() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::VulnerabilitiesDetected.as_i32(), 1);
        assert_eq!(ExitCode::InvalidArguments.as_i32(), 2);
        assert_eq!(ExitCode::ApplicationError.as_i32(), 3);
    }

    #[test]
    fn test_exit_code_display() {
        assert_eq!(format!("{}", ExitCode::Success), "Success (0)");
        assert_eq!(
            format!("{}", ExitCode::VulnerabilitiesDetected),
            "Vulnerabilities Detected (1)"
        );
        assert_eq!(
            format!("{}", ExitCode::InvalidArguments),
            "Invalid Arguments (2)"
        );
        assert_eq!(
            format!("{}", ExitCode::ApplicationError),
            "Application Error (3)"
        );
    }

    #[test]
    fn test_exit_code_equality() {
        assert_eq!(ExitCode::Success, ExitCode::Success);
        assert_ne!(ExitCode::Success, ExitCode::ApplicationError);
    }

    #[test]
    fn test_exit_code_clone() {
        let code = ExitCode::VulnerabilitiesDetected;
        let cloned = code;
        assert_eq!(code, cloned);
    }

    // SbomError tests
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

    #[test]
    fn test_file_read_error_display() {
        let error = SbomError::FileReadError {
            path: PathBuf::from("/test/file.txt"),
            details: "File not found".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("Failed to read file"));
        assert!(display.contains("/test/file.txt"));
        assert!(display.contains("File not found"));
        assert!(display.contains("💡 Hint:"));
    }

    #[test]
    fn test_security_error_display() {
        let error = SbomError::SecurityError {
            path: PathBuf::from("/test/symlink"),
            reason: "Symbolic links are not allowed".to_string(),
            hint: "Use a regular file instead".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("Security violation"));
        assert!(display.contains("/test/symlink"));
        assert!(display.contains("Symbolic links are not allowed"));
        assert!(display.contains("Use a regular file instead"));
    }
}
