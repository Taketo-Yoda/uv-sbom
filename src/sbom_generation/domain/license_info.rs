/// LicenseInfo value object representing license and description information
#[derive(Debug, Clone, PartialEq)]
pub struct LicenseInfo {
    license_text: Option<String>,
    description: Option<String>,
}

impl LicenseInfo {
    pub fn new(license_text: Option<String>, description: Option<String>) -> Self {
        Self {
            license_text,
            description,
        }
    }

    pub fn license_text(&self) -> Option<&str> {
        self.license_text.as_deref()
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
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
    }
}
