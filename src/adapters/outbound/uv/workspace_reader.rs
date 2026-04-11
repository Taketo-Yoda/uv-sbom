use crate::ports::outbound::workspace_reader::{WorkspaceMember, WorkspaceReader};
use crate::shared::security::{read_file_with_security, MAX_FILE_SIZE};
use crate::shared::Result;
use anyhow::Context;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Adapter that reads uv workspace members by parsing `uv.lock`.
#[allow(dead_code)]
pub struct UvWorkspaceReader;

#[allow(dead_code)]
impl UvWorkspaceReader {
    /// Creates a new `UvWorkspaceReader` instance.
    pub fn new() -> Self {
        Self
    }

    /// Parse the raw TOML content of a `uv.lock` file and extract workspace members.
    ///
    /// Looks for a `[manifest].members` array in the lock file. For each member path,
    /// finds the matching `[[package]]` entry where `source.editable` equals the member
    /// path to resolve the package name. Falls back to the last path component if no
    /// matching package is found.
    ///
    /// # Arguments
    /// * `content` - The raw TOML content of the `uv.lock` file.
    /// * `workspace_root` - The workspace root path used to compute absolute paths.
    ///
    /// # Returns
    /// A vector of [`WorkspaceMember`] entries. Returns an empty `Vec` if the lock file
    /// has no `[manifest]` section or the `members` array is empty.
    ///
    /// # Errors
    /// Returns an error if the content cannot be parsed as valid TOML.
    fn parse_members(content: &str, workspace_root: &Path) -> Result<Vec<WorkspaceMember>> {
        #[derive(Deserialize, Default)]
        struct Manifest {
            members: Option<Vec<String>>,
        }

        #[derive(Deserialize)]
        struct PackageSource {
            editable: Option<String>,
        }

        #[derive(Deserialize)]
        struct UvPackage {
            name: String,
            source: Option<PackageSource>,
        }

        #[derive(Deserialize)]
        struct UvLock {
            manifest: Option<Manifest>,
            #[serde(default)]
            package: Vec<UvPackage>,
        }

        let lock: UvLock = toml::from_str(content).context("Failed to parse uv.lock")?;

        let member_paths = match lock.manifest.and_then(|m| m.members) {
            Some(paths) if !paths.is_empty() => paths,
            _ => return Ok(vec![]),
        };

        let members = member_paths
            .into_iter()
            .map(|relative_path| {
                // Find the matching [[package]] entry where source.editable == relative_path
                let name = lock
                    .package
                    .iter()
                    .find(|p| {
                        p.source
                            .as_ref()
                            .and_then(|s| s.editable.as_deref())
                            .map(|e| e == relative_path)
                            .unwrap_or(false)
                    })
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| {
                        // Fallback: derive name from the last path component
                        PathBuf::from(&relative_path)
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| relative_path.clone())
                    });

                let absolute_path = workspace_root.join(&relative_path);

                WorkspaceMember {
                    name,
                    relative_path,
                    absolute_path,
                }
            })
            .collect();

        Ok(members)
    }
}

impl Default for UvWorkspaceReader {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkspaceReader for UvWorkspaceReader {
    fn read_workspace_members(&self, workspace_root: &Path) -> Result<Vec<WorkspaceMember>> {
        let lock_path = workspace_root.join("uv.lock");
        let content = read_file_with_security(&lock_path, "uv.lock", MAX_FILE_SIZE)
            .with_context(|| format!("Failed to read uv.lock at: {}", lock_path.display()))?;
        Self::parse_members(&content, workspace_root)
    }

    fn is_workspace_root(&self, path: &Path) -> bool {
        self.read_workspace_members(path)
            .map(|members| !members.is_empty())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

    const WORKSPACE_LOCK: &str = r#"
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

[[package]]
name = "beta"
version = "0.2.0"
source = { editable = "packages/beta" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

    const NON_WORKSPACE_LOCK: &str = r#"
version = 1
requires-python = ">=3.8"

[[package]]
name = "sample-project"
version = "1.0.0"
source = { virtual = "." }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

    const EMPTY_MEMBERS_LOCK: &str = r#"
version = 1
requires-python = ">=3.11"

[manifest]
members = []

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

    #[test]
    fn test_parse_members_returns_correct_members_for_workspace_lock() {
        let root = Path::new("/workspace");
        let members = UvWorkspaceReader::parse_members(WORKSPACE_LOCK, root).unwrap();

        assert_eq!(members.len(), 2);

        let alpha = members
            .iter()
            .find(|m| m.relative_path == "packages/alpha")
            .unwrap();
        assert_eq!(alpha.name, "alpha");
        assert_eq!(alpha.absolute_path, root.join("packages/alpha"));

        let beta = members
            .iter()
            .find(|m| m.relative_path == "packages/beta")
            .unwrap();
        assert_eq!(beta.name, "beta");
        assert_eq!(beta.absolute_path, root.join("packages/beta"));
    }

    #[test]
    fn test_parse_members_returns_empty_for_non_workspace_lock() {
        let root = Path::new("/project");
        let members = UvWorkspaceReader::parse_members(NON_WORKSPACE_LOCK, root).unwrap();
        assert!(members.is_empty());
    }

    #[test]
    fn test_parse_members_returns_empty_for_empty_members_array() {
        let root = Path::new("/project");
        let members = UvWorkspaceReader::parse_members(EMPTY_MEMBERS_LOCK, root).unwrap();
        assert!(members.is_empty());
    }

    #[test]
    fn test_parse_members_falls_back_to_path_component_when_no_matching_package() {
        let content = r#"
version = 1

[manifest]
members = [
    "packages/gamma",
]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let root = Path::new("/workspace");
        let members = UvWorkspaceReader::parse_members(content, root).unwrap();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].name, "gamma");
        assert_eq!(members[0].relative_path, "packages/gamma");
    }

    #[test]
    fn test_parse_members_invalid_toml_returns_error() {
        let root = Path::new("/workspace");
        let result = UvWorkspaceReader::parse_members("invalid [[[ toml", root);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse uv.lock"));
    }

    #[test]
    fn test_is_workspace_root_returns_true_for_workspace_lock_file() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join("uv.lock"), WORKSPACE_LOCK).unwrap();

        let reader = UvWorkspaceReader::new();
        assert!(reader.is_workspace_root(temp_dir.path()));
    }

    #[test]
    fn test_is_workspace_root_returns_false_for_non_workspace_lock_file() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join("uv.lock"), NON_WORKSPACE_LOCK).unwrap();

        let reader = UvWorkspaceReader::new();
        assert!(!reader.is_workspace_root(temp_dir.path()));
    }

    #[test]
    fn test_is_workspace_root_returns_false_when_no_lock_file() {
        let reader = UvWorkspaceReader::new();
        // Use a path that definitely does not have a uv.lock
        let result = reader.is_workspace_root(Path::new("/nonexistent/path/that/does/not/exist"));
        assert!(!result);
    }

    #[test]
    fn test_read_workspace_members_returns_members_from_real_file() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join("uv.lock"), WORKSPACE_LOCK).unwrap();

        let reader = UvWorkspaceReader::new();
        let members = reader.read_workspace_members(temp_dir.path()).unwrap();

        assert_eq!(members.len(), 2);
        assert!(members.iter().any(|m| m.name == "alpha"));
        assert!(members.iter().any(|m| m.name == "beta"));
    }
}
