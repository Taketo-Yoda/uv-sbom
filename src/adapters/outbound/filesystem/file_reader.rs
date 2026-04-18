use crate::ports::outbound::{LockfileParseResult, LockfileReader, ProjectConfigReader};
use crate::sbom_generation::domain::Package;
use crate::shared::error::SbomError;
use crate::shared::security::{read_file_with_security, MAX_FILE_SIZE};
use crate::shared::Result;
use std::collections::{HashMap, HashSet, VecDeque};
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
        self.parse_lockfile_content_for_member(&lockfile_content, project_path, member_name)
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
        // Read the lockfile content
        let lockfile_content = self.read_lockfile(project_path)?;

        // Parse TOML content
        self.parse_lockfile_content(&lockfile_content, project_path)
    }
}

impl FileSystemReader {
    /// Parses lockfile content to extract packages and dependency map
    ///
    /// This method handles the TOML parsing logic which is an infrastructure concern.
    /// It was moved from the application layer to properly separate concerns.
    fn parse_lockfile_content(
        &self,
        content: &str,
        project_path: &Path,
    ) -> Result<LockfileParseResult> {
        use serde::Deserialize;

        #[derive(Debug, Deserialize)]
        struct UvLock {
            package: Vec<UvPackage>,
        }

        #[derive(Debug, Deserialize)]
        struct UvPackage {
            name: String,
            version: String,
            #[serde(default)]
            dependencies: Vec<UvDependency>,
            #[serde(default, rename = "dev-dependencies")]
            dev_dependencies: Option<DevDependencies>,
        }

        #[derive(Debug, Deserialize)]
        struct UvDependency {
            name: String,
        }

        #[derive(Debug, Deserialize)]
        struct DevDependencies {
            #[serde(default)]
            dev: Vec<UvDependency>,
        }

        let lockfile: UvLock =
            toml::from_str(content).map_err(|e| SbomError::LockfileParseError {
                path: project_path.join("uv.lock"),
                details: e.to_string(),
            })?;

        let mut packages = Vec::new();
        let mut dependency_map = HashMap::new();

        for pkg in lockfile.package {
            packages.push(Package::new(pkg.name.clone(), pkg.version.clone())?);

            // Build dependency map
            let mut deps = Vec::new();
            for dep in &pkg.dependencies {
                deps.push(dep.name.clone());
            }
            if let Some(dev_deps) = &pkg.dev_dependencies {
                for dep in &dev_deps.dev {
                    deps.push(dep.name.clone());
                }
            }
            dependency_map.insert(pkg.name, deps);
        }

        Ok((packages, dependency_map))
    }

    /// Parse lockfile content and return only packages reachable from the given member.
    ///
    /// Identifies the member root package by matching `name == member_name` with either
    /// `source.editable` or `source.virtual` set (uv < 0.5 uses `editable`; uv >= 0.5
    /// uses `virtual` for packages without a build system), then performs BFS over the
    /// dependency graph to collect all transitively reachable packages. The member root
    /// itself is excluded.
    fn parse_lockfile_content_for_member(
        &self,
        content: &str,
        project_path: &Path,
        member_name: &str,
    ) -> Result<LockfileParseResult> {
        use serde::Deserialize;

        #[derive(Debug, Deserialize)]
        struct PackageSource {
            editable: Option<String>,
            #[serde(rename = "virtual")]
            virtual_path: Option<String>,
        }

        impl PackageSource {
            fn is_local(&self) -> bool {
                self.editable.is_some() || self.virtual_path.is_some()
            }
        }

        #[derive(Debug, Deserialize)]
        struct UvPackage {
            name: String,
            version: String,
            #[serde(default)]
            dependencies: Vec<UvDependency>,
            #[serde(default, rename = "dev-dependencies")]
            dev_dependencies: Option<DevDependencies>,
            source: Option<PackageSource>,
        }

        #[derive(Debug, Deserialize)]
        struct UvDependency {
            name: String,
        }

        #[derive(Debug, Deserialize)]
        struct DevDependencies {
            #[serde(default)]
            dev: Vec<UvDependency>,
        }

        #[derive(Debug, Deserialize)]
        struct UvLock {
            package: Vec<UvPackage>,
        }

        let lockfile: UvLock =
            toml::from_str(content).map_err(|e| SbomError::LockfileParseError {
                path: project_path.join("uv.lock"),
                details: e.to_string(),
            })?;

        // Build dependency map (name -> list of dependency names) and package lookup
        let mut full_dep_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut pkg_lookup: HashMap<String, (String, String)> = HashMap::new(); // name -> (name, version)
        let mut member_direct_deps: Option<Vec<String>> = None;

        for pkg in &lockfile.package {
            let mut deps: Vec<String> = pkg.dependencies.iter().map(|d| d.name.clone()).collect();
            if let Some(dev_deps) = &pkg.dev_dependencies {
                for dep in &dev_deps.dev {
                    deps.push(dep.name.clone());
                }
            }

            // Detect member root: name matches AND source is a local path
            // (editable for uv < 0.5, virtual for uv >= 0.5)
            let is_member_root = pkg.name == member_name
                && pkg.source.as_ref().map(|s| s.is_local()).unwrap_or(false);

            if is_member_root {
                member_direct_deps = Some(deps.clone());
            }

            full_dep_map.insert(pkg.name.clone(), deps);
            pkg_lookup.insert(pkg.name.clone(), (pkg.name.clone(), pkg.version.clone()));
        }

        let direct_deps = member_direct_deps.ok_or_else(|| {
            anyhow::anyhow!(
                "Workspace member '{}' not found in uv.lock (no package with source.editable or source.virtual set)",
                member_name
            )
        })?;

        // BFS traversal from direct dependencies of the member root
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();

        for dep in direct_deps {
            if !visited.contains(&dep) {
                visited.insert(dep.clone());
                queue.push_back(dep);
            }
        }

        while let Some(current) = queue.pop_front() {
            if let Some(deps) = full_dep_map.get(&current) {
                for dep in deps {
                    if !visited.contains(dep) {
                        visited.insert(dep.clone());
                        queue.push_back(dep.clone());
                    }
                }
            }
        }

        // Build result from visited set (excluding member root itself)
        let mut packages = Vec::new();
        let mut dependency_map = HashMap::new();

        for name in &visited {
            if let Some((pkg_name, pkg_version)) = pkg_lookup.get(name) {
                packages.push(Package::new(pkg_name.clone(), pkg_version.clone())?);
                if let Some(deps) = full_dep_map.get(name) {
                    dependency_map.insert(pkg_name.clone(), deps.clone());
                }
            }
        }

        Ok((packages, dependency_map))
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
    use std::path::Path;
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

    // Workspace lock fixture used by member-scoped filtering tests.
    //
    // Dependency graph:
    //   alpha (editable) -> requests, certifi
    //   beta  (editable) -> urllib3
    //   requests         -> urllib3
    //   urllib3          -> (none)
    //   certifi          -> (none)
    //   shared-lib       -> certifi
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
    fn test_parse_lockfile_for_member_returns_correct_subtree_for_alpha() {
        let reader = FileSystemReader::new();
        let (packages, dep_map) = reader
            .parse_lockfile_content_for_member(
                WORKSPACE_LOCK_FOR_MEMBER,
                Path::new("/workspace"),
                "alpha",
            )
            .unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();

        // alpha itself must NOT appear
        assert!(!names.contains("alpha"), "member root must be excluded");
        // beta is not reachable from alpha
        assert!(!names.contains("beta"), "sibling member must be excluded");
        // shared-lib is not reachable from alpha
        assert!(
            !names.contains("shared-lib"),
            "unreachable package must be excluded"
        );

        // alpha -> requests -> urllib3, alpha -> certifi
        assert!(names.contains("requests"));
        assert!(names.contains("urllib3"));
        assert!(names.contains("certifi"));

        // dependency_map must contain entries for all returned packages
        assert!(dep_map.contains_key("requests"));
        assert!(dep_map.contains_key("urllib3"));
        assert!(dep_map.contains_key("certifi"));
    }

    #[test]
    fn test_parse_lockfile_for_member_returns_correct_subtree_for_beta() {
        let reader = FileSystemReader::new();
        let (packages, _dep_map) = reader
            .parse_lockfile_content_for_member(
                WORKSPACE_LOCK_FOR_MEMBER,
                Path::new("/workspace"),
                "beta",
            )
            .unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();

        assert!(!names.contains("beta"), "member root must be excluded");
        assert!(!names.contains("alpha"), "sibling member must be excluded");
        assert!(!names.contains("requests"), "unreachable from beta");
        assert!(!names.contains("certifi"), "unreachable from beta");
        assert!(!names.contains("shared-lib"), "unreachable from beta");

        assert!(names.contains("urllib3"));
    }

    #[test]
    fn test_parse_lockfile_for_member_member_root_excluded() {
        let reader = FileSystemReader::new();
        let (packages, _) = reader
            .parse_lockfile_content_for_member(
                WORKSPACE_LOCK_FOR_MEMBER,
                Path::new("/workspace"),
                "alpha",
            )
            .unwrap();

        let names: Vec<String> = packages.iter().map(|p| p.name().to_string()).collect();
        assert!(
            !names.contains(&"alpha".to_string()),
            "member root must not appear in result"
        );
    }

    #[test]
    fn test_parse_lockfile_for_member_nonexistent_member_returns_error() {
        let reader = FileSystemReader::new();
        let result = reader.parse_lockfile_content_for_member(
            WORKSPACE_LOCK_FOR_MEMBER,
            Path::new("/workspace"),
            "nonexistent-member",
        );

        assert!(result.is_err());
        let err_string = result.unwrap_err().to_string();
        assert!(
            err_string.contains("nonexistent-member"),
            "error must mention the missing member name"
        );
    }

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

    // uv >= 0.5 workspace lock fixture using `source.virtual` instead of `source.editable`.
    //
    // Dependency graph:
    //   api    (virtual at packages/api)    -> requests, fastapi
    //   worker (virtual at packages/worker) -> celery
    const WORKSPACE_LOCK_VIRTUAL_FORMAT: &str = r#"
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
dependencies = [
  { name = "fastapi" },
  { name = "requests" },
]

[[package]]
name = "celery"
version = "5.4.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "fastapi"
version = "0.115.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "worker"
version = "0.1.0"
source = { virtual = "packages/worker" }
dependencies = [
  { name = "celery" },
]
"#;

    #[test]
    fn test_parse_lockfile_for_member_handles_virtual_source_for_api() {
        let reader = FileSystemReader::new();
        let (packages, _) = reader
            .parse_lockfile_content_for_member(
                WORKSPACE_LOCK_VIRTUAL_FORMAT,
                Path::new("/workspace"),
                "api",
            )
            .unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();

        assert!(!names.contains("api"), "member root must be excluded");
        assert!(!names.contains("worker"), "sibling member must be excluded");
        assert!(names.contains("requests"));
        assert!(names.contains("fastapi"));
        assert!(!names.contains("celery"), "unreachable from api");
    }

    #[test]
    fn test_parse_lockfile_for_member_handles_virtual_source_for_worker() {
        let reader = FileSystemReader::new();
        let (packages, _) = reader
            .parse_lockfile_content_for_member(
                WORKSPACE_LOCK_VIRTUAL_FORMAT,
                Path::new("/workspace"),
                "worker",
            )
            .unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();

        assert!(!names.contains("worker"), "member root must be excluded");
        assert!(!names.contains("api"), "sibling member must be excluded");
        assert!(names.contains("celery"));
        assert!(!names.contains("requests"), "unreachable from worker");
        assert!(!names.contains("fastapi"), "unreachable from worker");
    }
}
