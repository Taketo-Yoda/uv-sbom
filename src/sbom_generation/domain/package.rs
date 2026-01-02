use crate::shared::Result;

/// Maximum length for package names (security limit)
const MAX_PACKAGE_NAME_LENGTH: usize = 255;

/// Maximum length for package versions (security limit)
const MAX_VERSION_LENGTH: usize = 100;

/// NewType wrapper for package name with validation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackageName(String);

impl PackageName {
    pub fn new(name: String) -> Result<Self> {
        // Basic validation
        if name.is_empty() {
            anyhow::bail!("Package name cannot be empty");
        }

        // Security: Length limit to prevent DoS
        if name.len() > MAX_PACKAGE_NAME_LENGTH {
            anyhow::bail!(
                "Package name is too long ({} bytes). Maximum allowed: {} bytes",
                name.len(),
                MAX_PACKAGE_NAME_LENGTH
            );
        }

        // Security: Validate characters (allow alphanumeric, hyphens, underscores, dots, and common package chars)
        // This prevents injection attacks and special characters that could cause issues
        if !name.chars().all(|c| {
            c.is_alphanumeric()
                || c == '-'
                || c == '_'
                || c == '.'
                || c == '['
                || c == ']'  // For extras like package[extra]
        }) {
            anyhow::bail!(
                "Package name contains invalid characters. Only alphanumeric, hyphens, underscores, dots, and brackets are allowed."
            );
        }

        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PackageName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// NewType wrapper for package version with validation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Version(String);

impl Version {
    pub fn new(version: String) -> Result<Self> {
        // Basic validation
        if version.is_empty() {
            anyhow::bail!("Package version cannot be empty");
        }

        // Security: Length limit to prevent DoS
        if version.len() > MAX_VERSION_LENGTH {
            anyhow::bail!(
                "Package version is too long ({} bytes). Maximum allowed: {} bytes",
                version.len(),
                MAX_VERSION_LENGTH
            );
        }

        // Security: Validate characters (allow alphanumeric, dots, hyphens, plus, and common version chars)
        // This prevents injection attacks
        if !version.chars().all(|c| {
            c.is_alphanumeric()
                || c == '.'
                || c == '-'
                || c == '+'
                || c == '*'  // For wildcards
        }) {
            anyhow::bail!(
                "Package version contains invalid characters. Only alphanumeric, dots, hyphens, plus, and asterisks are allowed."
            );
        }

        Ok(Self(version))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Package value object representing a software package
#[derive(Debug, Clone, PartialEq)]
pub struct Package {
    name: PackageName,
    version: Version,
}

impl Package {
    pub fn new(name: String, version: String) -> Result<Self> {
        Ok(Self {
            name: PackageName::new(name)?,
            version: Version::new(version)?,
        })
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn version(&self) -> &str {
        self.version.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_name_new_valid() {
        let name = PackageName::new("requests".to_string()).unwrap();
        assert_eq!(name.as_str(), "requests");
    }

    #[test]
    fn test_package_name_new_empty() {
        let result = PackageName::new("".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_version_new_valid() {
        let version = Version::new("1.0.0".to_string()).unwrap();
        assert_eq!(version.as_str(), "1.0.0");
    }

    #[test]
    fn test_version_new_empty() {
        let result = Version::new("".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_package_new_valid() {
        let package = Package::new("requests".to_string(), "2.31.0".to_string()).unwrap();
        assert_eq!(package.name(), "requests");
        assert_eq!(package.version(), "2.31.0");
    }

    #[test]
    fn test_package_new_empty_name() {
        let result = Package::new("".to_string(), "1.0.0".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_package_new_empty_version() {
        let result = Package::new("requests".to_string(), "".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_package_equality() {
        let pkg1 = Package::new("requests".to_string(), "2.31.0".to_string()).unwrap();
        let pkg2 = Package::new("requests".to_string(), "2.31.0".to_string()).unwrap();
        assert_eq!(pkg1, pkg2);
    }

    #[test]
    fn test_package_name_display() {
        let name = PackageName::new("requests".to_string()).unwrap();
        assert_eq!(format!("{}", name), "requests");
    }

    #[test]
    fn test_version_display() {
        let version = Version::new("1.0.0".to_string()).unwrap();
        assert_eq!(format!("{}", version), "1.0.0");
    }
}
