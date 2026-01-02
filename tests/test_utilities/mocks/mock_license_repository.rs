use std::collections::HashMap;
use uv_sbom::prelude::*;

/// Mock LicenseRepository for testing
pub struct MockLicenseRepository {
    pub licenses: HashMap<String, (Option<String>, Option<String>, Vec<String>, Option<String>)>,
    pub should_fail: bool,
}

impl MockLicenseRepository {
    pub fn new() -> Self {
        Self {
            licenses: HashMap::new(),
            should_fail: false,
        }
    }

    pub fn with_license(mut self, package: &str, version: &str, license: &str, description: &str) -> Self {
        self.licenses.insert(
            format!("{}@{}", package, version),
            (Some(license.to_string()), None, vec![], Some(description.to_string())),
        );
        self
    }

    pub fn with_no_license(mut self, package: &str, version: &str) -> Self {
        self.licenses.insert(
            format!("{}@{}", package, version),
            (None, None, vec![], None),
        );
        self
    }

    pub fn with_failure() -> Self {
        Self {
            licenses: HashMap::new(),
            should_fail: true,
        }
    }
}

impl Default for MockLicenseRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl LicenseRepository for MockLicenseRepository {
    fn fetch_license_info(
        &self,
        package_name: &str,
        version: &str,
    ) -> Result<(Option<String>, Option<String>, Vec<String>, Option<String>)> {
        if self.should_fail {
            anyhow::bail!("Mock license repository failure");
        }

        let key = format!("{}@{}", package_name, version);
        Ok(self.licenses.get(&key).cloned().unwrap_or((None, None, vec![], None)))
    }
}
