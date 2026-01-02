use crate::ports::outbound::{LockfileReader, ProjectConfigReader};
use crate::shared::error::SbomError;
use crate::shared::Result;
use std::fs;
use std::path::Path;

/// Maximum file size for security (100 MB)
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// FileSystemReader adapter for reading files from the file system
///
/// This adapter implements both LockfileReader and ProjectConfigReader ports,
/// providing file system access for reading lockfiles and project configuration.
pub struct FileSystemReader;

impl FileSystemReader {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FileSystemReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FileSystemReader {
    /// Safely read a file with security checks:
    /// - Reject symbolic links
    /// - Check file size limits
    /// - Validate file is a regular file
    fn safe_read_file(&self, path: &Path, file_type: &str) -> Result<String> {
        // Get file metadata without following symlinks
        let metadata = fs::symlink_metadata(path).map_err(|e| {
            anyhow::anyhow!("Failed to read {} metadata: {}", file_type, e)
        })?;

        // Security check: Reject symbolic links
        if metadata.is_symlink() {
            anyhow::bail!(
                "Security: {} is a symbolic link. For security reasons, symbolic links are not allowed.",
                path.display()
            );
        }

        // Security check: Ensure it's a regular file
        if !metadata.is_file() {
            anyhow::bail!(
                "{} is not a regular file",
                path.display()
            );
        }

        // Security check: File size limit (prevent DoS via huge files)
        let file_size = metadata.len();
        if file_size > MAX_FILE_SIZE {
            anyhow::bail!(
                "Security: {} is too large ({} bytes). Maximum allowed size is {} bytes.",
                path.display(),
                file_size,
                MAX_FILE_SIZE
            );
        }

        // Safe to read the file now
        fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!("Failed to read {}: {}", file_type, e)
        })
    }
}

impl LockfileReader for FileSystemReader {
    fn read_lockfile(&self, project_path: &Path) -> Result<String> {
        let lockfile_path = project_path.join("uv.lock");

        // Check if uv.lock file exists
        if !lockfile_path.exists() {
            return Err(SbomError::LockfileNotFound {
                path: lockfile_path.clone(),
                suggestion: format!(
                    "uv.lock file does not exist in project directory \"{}\".\n   \
                     Please run in the root directory of a uv project, or specify the correct path with the --path option.",
                    project_path.display()
                ),
            }
            .into());
        }

        // Read lockfile content with security checks
        self.safe_read_file(&lockfile_path, "uv.lock").map_err(|e| {
            SbomError::LockfileParseError {
                path: lockfile_path,
                details: e.to_string(),
            }
            .into()
        })
    }
}

impl ProjectConfigReader for FileSystemReader {
    fn read_project_name(&self, project_path: &Path) -> Result<String> {
        let pyproject_path = project_path.join("pyproject.toml");

        if !pyproject_path.exists() {
            anyhow::bail!("pyproject.toml not found in project directory");
        }

        // Read with security checks
        let pyproject_content = self.safe_read_file(&pyproject_path, "pyproject.toml")?;

        let pyproject: toml::Value = toml::from_str(&pyproject_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse pyproject.toml: {}", e))?;

        let project_name = pyproject
            .get("project")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .ok_or_else(|| anyhow::anyhow!("Project name not found in pyproject.toml"))?;

        Ok(project_name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_read_lockfile_success() {
        let temp_dir = TempDir::new().unwrap();
        let lockfile_path = temp_dir.path().join("uv.lock");
        fs::write(&lockfile_path, "test content").unwrap();

        let reader = FileSystemReader::new();
        let content = reader.read_lockfile(temp_dir.path()).unwrap();

        assert_eq!(content, "test content");
    }

    #[test]
    fn test_read_lockfile_not_found() {
        let temp_dir = TempDir::new().unwrap();

        let reader = FileSystemReader::new();
        let result = reader.read_lockfile(temp_dir.path());

        assert!(result.is_err());
        let err_string = format!("{}", result.unwrap_err());
        assert!(err_string.contains("uv.lock file does not exist"));
    }

    #[test]
    fn test_read_project_name_success() {
        let temp_dir = TempDir::new().unwrap();
        let pyproject_path = temp_dir.path().join("pyproject.toml");
        fs::write(
            &pyproject_path,
            r#"
[project]
name = "test-project"
version = "1.0.0"
"#,
        )
        .unwrap();

        let reader = FileSystemReader::new();
        let project_name = reader.read_project_name(temp_dir.path()).unwrap();

        assert_eq!(project_name, "test-project");
    }

    #[test]
    fn test_read_project_name_file_not_found() {
        let temp_dir = TempDir::new().unwrap();

        let reader = FileSystemReader::new();
        let result = reader.read_project_name(temp_dir.path());

        assert!(result.is_err());
        let err_string = format!("{}", result.unwrap_err());
        assert!(err_string.contains("pyproject.toml not found"));
    }

    #[test]
    fn test_read_project_name_invalid_toml() {
        let temp_dir = TempDir::new().unwrap();
        let pyproject_path = temp_dir.path().join("pyproject.toml");
        fs::write(&pyproject_path, "invalid toml [[[").unwrap();

        let reader = FileSystemReader::new();
        let result = reader.read_project_name(temp_dir.path());

        assert!(result.is_err());
        let err_string = format!("{}", result.unwrap_err());
        assert!(err_string.contains("Failed to parse pyproject.toml"));
    }

    #[test]
    fn test_read_project_name_missing_name_field() {
        let temp_dir = TempDir::new().unwrap();
        let pyproject_path = temp_dir.path().join("pyproject.toml");
        fs::write(
            &pyproject_path,
            r#"
[project]
version = "1.0.0"
"#,
        )
        .unwrap();

        let reader = FileSystemReader::new();
        let result = reader.read_project_name(temp_dir.path());

        assert!(result.is_err());
        let err_string = format!("{}", result.unwrap_err());
        assert!(err_string.contains("Project name not found"));
    }
}
