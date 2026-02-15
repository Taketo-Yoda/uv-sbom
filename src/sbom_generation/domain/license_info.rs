/// LicenseInfo value object representing license, description, and hash information
#[derive(Debug, Clone, PartialEq)]
pub struct LicenseInfo {
    license_text: Option<String>,
    description: Option<String>,
    sha256_hash: Option<String>,
}

impl LicenseInfo {
    pub fn new(license_text: Option<String>, description: Option<String>) -> Self {
        Self {
            license_text,
            description,
            sha256_hash: None,
        }
    }

    pub fn with_sha256_hash(mut self, sha256_hash: Option<String>) -> Self {
        self.sha256_hash = sha256_hash;
        self
    }

    pub fn license_text(&self) -> Option<&str> {
        self.license_text.as_deref()
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn sha256_hash(&self) -> Option<&str> {
        self.sha256_hash.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_info_new() {
        let info = LicenseInfo::new(Some("MIT".to_string()), Some("A library".to_string()));
        assert_eq!(info.license_text(), Some("MIT"));
        assert_eq!(info.description(), Some("A library"));
    }

    #[test]
    fn test_license_info_no_license() {
        let info = LicenseInfo::new(None, Some("A library".to_string()));
        assert_eq!(info.license_text(), None);
        assert_eq!(info.description(), Some("A library"));
    }

    #[test]
    fn test_license_info_empty() {
        let info = LicenseInfo::new(None, None);
        assert_eq!(info.license_text(), None);
        assert_eq!(info.description(), None);
        assert_eq!(info.sha256_hash(), None);
    }

    #[test]
    fn test_license_info_with_sha256_hash() {
        let info = LicenseInfo::new(Some("MIT".to_string()), None)
            .with_sha256_hash(Some("abc123".to_string()));
        assert_eq!(info.sha256_hash(), Some("abc123"));
    }

    #[test]
    fn test_license_info_without_sha256_hash() {
        let info = LicenseInfo::new(Some("MIT".to_string()), None);
        assert_eq!(info.sha256_hash(), None);
    }
}
