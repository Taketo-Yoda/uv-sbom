use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub license: Option<String>,
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
    source: Option<UvSource>,
}

#[derive(Debug, Deserialize)]
struct UvSource {
    #[serde(default)]
    registry: Option<String>,
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
