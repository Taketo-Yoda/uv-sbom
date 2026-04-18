use crate::ports::outbound::workspace_reader::{WorkspaceMember, WorkspaceReader};
use crate::shared::security::{read_file_with_security, MAX_FILE_SIZE};
use crate::shared::Result;
use anyhow::Context;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Adapter that reads uv workspace members by parsing `uv.lock`.
pub struct UvWorkspaceReader;

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
            #[serde(rename = "virtual")]
            virtual_path: Option<String>,
        }

        impl PackageSource {
            /// Returns the local path recorded in this source entry, regardless of whether
            /// it is an `editable` install or a `virtual` (no-build-system) package.
            fn local_path(&self) -> Option<&str> {
                self.editable.as_deref().or(self.virtual_path.as_deref())
            }
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

        let member_ids = match lock.manifest.and_then(|m| m.members) {
            Some(ids) if !ids.is_empty() => ids,
            _ => return Ok(vec![]),
        };

        let members = member_ids
            .into_iter()
            .map(|member_id| {
                // Strategy 1 (old uv format): member_id is a relative path such as
                // "packages/alpha". Look for a package whose source.editable or
                // source.virtual matches that path exactly.
                if let Some(pkg) = lock.package.iter().find(|p| {
                    p.source
                        .as_ref()
                        .and_then(|s| s.local_path())
                        .map(|path| path == member_id)
                        .unwrap_or(false)
                }) {
                    let absolute_path = workspace_root.join(&member_id);
                    return WorkspaceMember {
                        name: pkg.name.clone(),
                        absolute_path,
                    };
                }

                // Strategy 2 (new uv format ≥ 0.5): member_id is the package *name*
                // such as "api". Look for a package whose name matches and derive the
                // relative path from its source.editable / source.virtual field.
                if let Some(pkg) = lock.package.iter().find(|p| p.name == member_id) {
                    let rel = pkg
                        .source
                        .as_ref()
                        .and_then(|s| s.local_path())
                        .map(|p| p.to_owned())
                        .unwrap_or_else(|| member_id.clone());
                    let absolute_path = workspace_root.join(&rel);
                    return WorkspaceMember {
                        name: pkg.name.clone(),
                        absolute_path,
                    };
                }

                // Fallback: treat member_id as a relative path and derive name from
                // its last path component.
                let name = PathBuf::from(&member_id)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| member_id.clone());
                let absolute_path = workspace_root.join(&member_id);
                WorkspaceMember {
                    name,
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
            .find(|m| m.absolute_path == root.join("packages/alpha"))
            .unwrap();
        assert_eq!(alpha.name, "alpha");

        let beta = members
            .iter()
            .find(|m| m.absolute_path == root.join("packages/beta"))
            .unwrap();
        assert_eq!(beta.name, "beta");
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
        assert_eq!(members[0].absolute_path, root.join("packages/gamma"));
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
    fn test_read_workspace_members_returns_members_from_real_file() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join("uv.lock"), WORKSPACE_LOCK).unwrap();

        let reader = UvWorkspaceReader::new();
        let members = reader.read_workspace_members(temp_dir.path()).unwrap();

        assert_eq!(members.len(), 2);
        assert!(members.iter().any(|m| m.name == "alpha"));
        assert!(members.iter().any(|m| m.name == "beta"));
    }

    /// uv >= 0.5 generates `[manifest].members` as package *names* (e.g. "api")
    /// instead of relative paths (e.g. "packages/api"). The package source uses
    /// `virtual = "packages/api"` instead of `editable = "packages/api"`.
    /// This test verifies that Strategy 2 correctly resolves the absolute path
    /// from the `virtual` source field.
    #[test]
    fn test_parse_members_handles_new_uv_format_with_name_ids_and_virtual_source() {
        let content = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[manifest]
members = [
    "api",
    "worker",
]

[[package]]
name = "api"
version = "0.1.0"
source = { virtual = "packages/api" }

[[package]]
name = "worker"
version = "0.1.0"
source = { virtual = "packages/worker" }

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
"#;
        let root = Path::new("/workspace");
        let members = UvWorkspaceReader::parse_members(content, root).unwrap();

        assert_eq!(members.len(), 2);

        let api = members.iter().find(|m| m.name == "api").unwrap();
        assert_eq!(api.absolute_path, root.join("packages/api"));

        let worker = members.iter().find(|m| m.name == "worker").unwrap();
        assert_eq!(worker.absolute_path, root.join("packages/worker"));
    }

    #[test]
    fn test_parse_members_handles_old_uv_format_with_path_ids_and_editable_source() {
        let root = Path::new("/workspace");
        let members = UvWorkspaceReader::parse_members(WORKSPACE_LOCK, root).unwrap();

        assert_eq!(members.len(), 2);

        let alpha = members
            .iter()
            .find(|m| m.absolute_path == root.join("packages/alpha"))
            .unwrap();
        assert_eq!(alpha.name, "alpha");
    }
}
