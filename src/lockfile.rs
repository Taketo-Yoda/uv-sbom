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
        toml::from_str(content).context("uv.lockファイルのパースに失敗しました")?;

    let packages = lockfile
        .package
        .into_iter()
        .map(|pkg| Package {
            name: pkg.name,
            version: pkg.version,
            description: None, // 後でライセンス取得時に設定
            license: None,     // 後でライセンス取得時に設定
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
}
