use std::collections::HashMap;
use std::path::Path;
use uv_sbom::prelude::*;

/// Mock LockfileReader for testing
pub struct MockLockfileReader {
    pub content: String,
    pub should_fail: bool,
}

impl MockLockfileReader {
    pub fn new(content: String) -> Self {
        Self {
            content,
            should_fail: false,
        }
    }

    pub fn with_failure() -> Self {
        Self {
            content: String::new(),
            should_fail: true,
        }
    }
}

impl LockfileReader for MockLockfileReader {
    fn read_lockfile(&self, _project_path: &Path) -> Result<String> {
        if self.should_fail {
            anyhow::bail!("Mock lockfile read failure");
        }
        Ok(self.content.clone())
    }

    fn read_and_parse_lockfile(&self, _project_path: &Path) -> Result<LockfileParseResult> {
        if self.should_fail {
            anyhow::bail!("Mock lockfile read failure");
        }

        // Parse the mock content
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

        let lockfile: UvLock = toml::from_str(&self.content)?;

        let mut packages = Vec::new();
        let mut dependency_map = HashMap::new();

        for pkg in lockfile.package {
            packages.push(Package::new(pkg.name.clone(), pkg.version.clone())?);

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
}
