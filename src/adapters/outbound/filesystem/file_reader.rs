use super::lockfile_parser::{
    parse_group_roots, parse_lockfile_content, parse_lockfile_content_for_member,
    parse_package_sources,
};
use crate::ports::outbound::{
    GroupRoots, LockfileParseResult, LockfileReader, PackageSourceMap, ProjectConfigReader,
};
use crate::shared::error::SbomError;
use crate::shared::security::{read_file_with_security, MAX_FILE_SIZE};
use crate::shared::Result;
use std::path::Path;

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
    /// Safely read a file with security checks.
    ///
    /// Delegates to the consolidated `read_file_with_security` function in `shared::security`,
    /// which provides:
    /// - Symlink rejection
    /// - File type validation
    /// - File size limits
    /// - TOCTOU mitigation
    fn safe_read_file(&self, path: &Path, file_type: &str) -> Result<String> {
        read_file_with_security(path, file_type, MAX_FILE_SIZE)
    }
}

impl LockfileReader for FileSystemReader {
    fn read_and_parse_lockfile_for_member(
        &self,
        project_path: &Path,
        member_name: &str,
    ) -> Result<LockfileParseResult> {
        let lockfile_content = self.read_lockfile(project_path)?;
        parse_lockfile_content_for_member(&lockfile_content, project_path, member_name)
    }

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

    fn read_and_parse_lockfile(&self, project_path: &Path) -> Result<LockfileParseResult> {
        let lockfile_content = self.read_lockfile(project_path)?;
        parse_lockfile_content(&lockfile_content, project_path)
    }

    fn read_and_parse_group_roots(&self, project_path: &Path) -> Result<GroupRoots> {
        let lockfile_content = self.read_lockfile(project_path)?;
        parse_group_roots(&lockfile_content, project_path)
    }

    fn read_and_parse_package_sources(&self, project_path: &Path) -> Result<PackageSourceMap> {
        let lockfile_content = self.read_lockfile(project_path)?;
        parse_package_sources(&lockfile_content, project_path)
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
    use std::collections::HashSet;
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

    const LOCK_WITH_GROUPS: &str = r#"
version = 1
requires-python = ">=3.11"

[manifest]
members = ["my-app"]

[manifest.dependency-groups]
dev = [{ name = "pytest" }, { name = "mypy" }]
lint = [{ name = "ruff" }]

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }
"#;

    #[test]
    fn test_read_and_parse_group_roots_reads_from_file() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(temp_dir.path().join("uv.lock"), LOCK_WITH_GROUPS).unwrap();

        let reader = FileSystemReader::new();
        let roots = reader.read_and_parse_group_roots(temp_dir.path()).unwrap();

        assert_eq!(roots.len(), 2);
        assert!(roots["dev"].contains(&"pytest".to_string()));
        assert!(roots["dev"].contains(&"mypy".to_string()));
        assert_eq!(roots["lint"], vec!["ruff"]);
    }

    #[test]
    fn test_read_and_parse_group_roots_returns_error_when_lockfile_missing() {
        let temp_dir = TempDir::new().unwrap();

        let reader = FileSystemReader::new();
        let result = reader.read_and_parse_group_roots(temp_dir.path());
        assert!(result.is_err());
    }

    // Integration test: verifies FileSystemReader reads from disk and delegates
    // parsing correctly to the lockfile_parser module.
    const WORKSPACE_LOCK_FOR_MEMBER: &str = r#"
version = 1
requires-python = ">=3.11"

[manifest]
members = [
    "packages/alpha",
    "packages/beta",
]

[[package]]
name = "alpha"
version = "0.1.0"
source = { editable = "packages/alpha" }
dependencies = [
  { name = "certifi" },
  { name = "requests" },
]

[[package]]
name = "beta"
version = "0.2.0"
source = { editable = "packages/beta" }
dependencies = [
  { name = "urllib3" },
]

[[package]]
name = "certifi"
version = "2024.1.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
  { name = "urllib3" },
]

[[package]]
name = "shared-lib"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
  { name = "certifi" },
]

[[package]]
name = "urllib3"
version = "2.0.7"
source = { registry = "https://pypi.org/simple" }
"#;

    #[test]
    fn test_read_and_parse_lockfile_for_member_reads_from_file() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(temp_dir.path().join("uv.lock"), WORKSPACE_LOCK_FOR_MEMBER).unwrap();

        let reader = FileSystemReader::new();
        let (packages, _) = reader
            .read_and_parse_lockfile_for_member(temp_dir.path(), "alpha")
            .unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();
        assert!(names.contains("requests"));
        assert!(names.contains("urllib3"));
        assert!(names.contains("certifi"));
        assert!(!names.contains("alpha"));
    }

    const MIXED_SOURCES_LOCK: &str = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "git-pkg"
version = "0.1.0"
source = { git = "https://github.com/user/repo?rev=abc123" }

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }
"#;

    #[test]
    fn test_read_and_parse_package_sources_reads_from_file() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(temp_dir.path().join("uv.lock"), MIXED_SOURCES_LOCK).unwrap();

        let reader = FileSystemReader::new();
        let map = reader
            .read_and_parse_package_sources(temp_dir.path())
            .unwrap();

        use crate::ports::outbound::PackageSourceKind;
        assert_eq!(map["requests"], PackageSourceKind::PyPi);
        assert_eq!(
            map["git-pkg"],
            PackageSourceKind::Git("https://github.com/user/repo?rev=abc123".to_string())
        );
        assert_eq!(map["my-app"], PackageSourceKind::WorkspaceMember);
    }

    #[test]
    fn test_read_and_parse_package_sources_returns_error_when_lockfile_missing() {
        let temp_dir = TempDir::new().unwrap();

        let reader = FileSystemReader::new();
        let result = reader.read_and_parse_package_sources(temp_dir.path());
        assert!(result.is_err());
    }
}
