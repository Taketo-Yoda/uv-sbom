use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub license: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DependencyInfo {
    pub all_packages: Vec<Package>,
    pub direct_dependencies: Vec<String>,
    pub transitive_dependencies: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct UvLock {
    package: Vec<UvPackage>,
}

#[derive(Debug, Deserialize)]
struct UvPackage {
    name: String,
    version: String,
    #[serde(default)]
    #[allow(dead_code)]
    source: Option<UvSource>,
    #[serde(default)]
    dependencies: Vec<UvDependency>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: Option<DevDependencies>,
}

#[derive(Debug, Deserialize)]
struct UvSource {
    #[serde(default)]
    #[allow(dead_code)]
    registry: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    editable: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UvDependency {
    name: String,
    #[serde(default)]
    #[allow(dead_code)]
    marker: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DevDependencies {
    #[serde(default)]
    dev: Vec<UvDependency>,
}

pub fn parse_lockfile(content: &str) -> Result<Vec<Package>> {
    let lockfile: UvLock =
        toml::from_str(content).context("Failed to parse uv.lock file")?;

    let packages = lockfile
        .package
        .into_iter()
        .map(|pkg| Package {
            name: pkg.name,
            version: pkg.version,
            description: None, // Set later when fetching license information
            license: None,     // Set later when fetching license information
        })
        .collect();

    Ok(packages)
}

pub fn parse_lockfile_with_deps(content: &str, project_name: &str) -> Result<DependencyInfo> {
    let lockfile: UvLock =
        toml::from_str(content).context("Failed to parse uv.lock file")?;

    // Create package map for lookup
    let mut package_map: HashMap<String, UvPackage> = HashMap::new();
    let mut all_packages = Vec::new();

    for pkg in lockfile.package {
        all_packages.push(Package {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            description: None,
            license: None,
        });
        package_map.insert(pkg.name.clone(), pkg);
    }

    // Find project package and extract direct dependencies
    let project_pkg = package_map
        .get(project_name)
        .context("Project package not found in lockfile")?;

    let mut direct_deps = Vec::new();

    // Add runtime dependencies
    for dep in &project_pkg.dependencies {
        direct_deps.push(dep.name.clone());
    }

    // Add dev dependencies
    if let Some(dev_deps) = &project_pkg.dev_dependencies {
        for dep in &dev_deps.dev {
            direct_deps.push(dep.name.clone());
        }
    }

    // Build transitive dependency map
    let mut transitive_dependencies: HashMap<String, Vec<String>> = HashMap::new();
    let direct_deps_set: HashSet<String> = direct_deps.iter().cloned().collect();

    for direct_dep in &direct_deps {
        let mut trans_deps = Vec::new();
        let mut visited = HashSet::new();
        collect_transitive_deps(
            direct_dep,
            &package_map,
            &mut trans_deps,
            &mut visited,
            &direct_deps_set,
        );
        if !trans_deps.is_empty() {
            transitive_dependencies.insert(direct_dep.clone(), trans_deps);
        }
    }

    Ok(DependencyInfo {
        all_packages,
        direct_dependencies: direct_deps,
        transitive_dependencies,
    })
}

fn collect_transitive_deps(
    package_name: &str,
    package_map: &HashMap<String, UvPackage>,
    trans_deps: &mut Vec<String>,
    visited: &mut HashSet<String>,
    direct_deps: &HashSet<String>,
) {
    if visited.contains(package_name) {
        return;
    }
    visited.insert(package_name.to_string());

    if let Some(pkg) = package_map.get(package_name) {
        for dep in &pkg.dependencies {
            // Only include as transitive if not a direct dependency
            if !direct_deps.contains(&dep.name) && !trans_deps.contains(&dep.name) {
                trans_deps.push(dep.name.clone());
            }
            // Recursively collect transitive dependencies
            collect_transitive_deps(&dep.name, package_map, trans_deps, visited, direct_deps);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lockfile() {
        let lockfile_content = r#"
[[package]]
name = "certifi"
version = "2024.8.30"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "charset-normalizer"
version = "3.4.0"
source = { registry = "https://pypi.org/simple" }
"#;

        let packages = parse_lockfile(lockfile_content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "certifi");
        assert_eq!(packages[0].version, "2024.8.30");
        assert_eq!(packages[1].name, "charset-normalizer");
        assert_eq!(packages[1].version, "3.4.0");
    }

    #[test]
    fn test_parse_lockfile_empty_packages() {
        let lockfile_content = r#"
[[package]]
"#;
        // This should fail because name and version are required fields
        let result = parse_lockfile(lockfile_content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_lockfile_invalid_toml() {
        let lockfile_content = "invalid toml content [[[";
        let result = parse_lockfile(lockfile_content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_lockfile_no_packages() {
        let lockfile_content = r#"
# Some other content
version = "1.0.0"
"#;
        // This should fail because the package field is missing
        let result = parse_lockfile(lockfile_content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_lockfile_without_source() {
        let lockfile_content = r#"
[[package]]
name = "local-package"
version = "1.0.0"
"#;

        let packages = parse_lockfile(lockfile_content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "local-package");
        assert_eq!(packages[0].version, "1.0.0");
        assert!(packages[0].license.is_none());
        assert!(packages[0].description.is_none());
    }

    #[test]
    fn test_parse_lockfile_special_characters_in_name() {
        let lockfile_content = r#"
[[package]]
name = "package-with-dashes_and_underscores"
version = "1.2.3"
"#;

        let packages = parse_lockfile(lockfile_content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "package-with-dashes_and_underscores");
    }
}
