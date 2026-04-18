use crate::shared::Result;
use std::path::{Path, PathBuf};

/// Represents a member of a uv workspace.
#[derive(Debug, Clone)]
pub struct WorkspaceMember {
    /// The package name as declared in the `[[package]]` entry.
    pub name: String,
    /// The absolute path to the workspace member, resolved from the workspace root.
    pub absolute_path: PathBuf,
}

/// Port for reading uv workspace members from a `uv.lock` file.
pub trait WorkspaceReader {
    /// Reads workspace members from `uv.lock` in the given workspace root directory.
    ///
    /// # Arguments
    /// * `workspace_root` - Path to the workspace root directory containing `uv.lock`.
    ///
    /// # Returns
    /// A vector of [`WorkspaceMember`] objects. Returns an empty `Vec` if the lock file
    /// has no `[manifest]` section (i.e., not a workspace project).
    ///
    /// # Postconditions
    /// Each returned [`WorkspaceMember`]'s `absolute_path` is always formed by joining
    /// `workspace_root` with the member's `relative_path`.
    ///
    /// # Errors
    /// Returns an error if the `uv.lock` file cannot be read or parsed.
    fn read_workspace_members(&self, workspace_root: &Path) -> Result<Vec<WorkspaceMember>>;
}
