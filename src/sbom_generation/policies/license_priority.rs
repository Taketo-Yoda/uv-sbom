use crate::sbom_generation::domain::LicenseInfo;

/// LicensePriority policy for determining license information precedence
///
/// This policy encodes the business rules for selecting license information
/// when multiple sources are available (license field, license_expression, classifiers).
///
/// Priority order:
/// 1. license field (if non-empty and not "UNKNOWN")
/// 2. license_expression field (if non-empty)
/// 3. OSI Approved license from classifiers
pub struct LicensePriority;

impl LicensePriority {
    /// Selects the most appropriate license text based on priority rules
    ///
    /// # Arguments
    /// * `license` - License field from package metadata
    /// * `license_expression` - License expression field from package metadata
    /// * `classifiers` - List of classifier strings from package metadata
    ///
    /// # Returns
    /// The selected license text, or None if no valid license found
    pub fn select_license(
        license: Option<String>,
        license_expression: Option<String>,
        classifiers: &[String],
    ) -> Option<String> {
        // Priority 1: license field (non-empty and not "UNKNOWN")
        license
            .filter(|l| !l.is_empty() && l != "UNKNOWN")
            // Priority 2: license_expression field
            .or_else(|| license_expression.filter(|l| !l.is_empty()))
            // Priority 3: Extract from classifiers
            .or_else(|| Self::extract_license_from_classifiers(classifiers))
    }

    /// Creates a LicenseInfo from PyPI package metadata
    ///
    /// # Arguments
    /// * `license` - License field from PyPI API
    /// * `license_expression` - License expression field from PyPI API
    /// * `classifiers` - Classifier list from PyPI API
    /// * `summary` - Package summary/description from PyPI API
    ///
    /// # Returns
    /// LicenseInfo with selected license and description
    pub fn create_license_info(
        license: Option<String>,
        license_expression: Option<String>,
        classifiers: &[String],
        summary: Option<String>,
    ) -> LicenseInfo {
        let selected_license = Self::select_license(license, license_expression, classifiers);
        LicenseInfo::new(selected_license, summary)
    }

    /// Extracts license information from classifier strings
    ///
    /// Looks for classifiers with the prefix "License :: OSI Approved :: "
    /// and extracts the license name.
    ///
    /// # Arguments
    /// * `classifiers` - List of classifier strings
    ///
    /// # Returns
    /// The first OSI Approved license found, or None
    fn extract_license_from_classifiers(classifiers: &[String]) -> Option<String> {
        for classifier in classifiers {
            if let Some(license) = classifier.strip_prefix("License :: OSI Approved :: ") {
                return Some(license.to_string());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_license_prefers_license_field() {
        let license = Some("MIT".to_string());
        let license_expression = Some("Apache-2.0".to_string());
        let classifiers = vec!["License :: OSI Approved :: BSD License".to_string()];

        let result = LicensePriority::select_license(license, license_expression, &classifiers);
        assert_eq!(result, Some("MIT".to_string()));
    }

    #[test]
    fn test_select_license_falls_back_to_expression() {
        let license = None;
        let license_expression = Some("Apache-2.0".to_string());
        let classifiers = vec!["License :: OSI Approved :: BSD License".to_string()];

        let result = LicensePriority::select_license(license, license_expression, &classifiers);
        assert_eq!(result, Some("Apache-2.0".to_string()));
    }

    #[test]
    fn test_select_license_falls_back_to_classifiers() {
        let license = None;
        let license_expression = None;
        let classifiers = vec![
            "Programming Language :: Python :: 3".to_string(),
            "License :: OSI Approved :: MIT License".to_string(),
        ];

        let result = LicensePriority::select_license(license, license_expression, &classifiers);
        assert_eq!(result, Some("MIT License".to_string()));
    }

    #[test]
    fn test_select_license_ignores_unknown() {
        let license = Some("UNKNOWN".to_string());
        let license_expression = Some("MIT".to_string());
        let classifiers = vec![];

        let result = LicensePriority::select_license(license, license_expression, &classifiers);
        assert_eq!(result, Some("MIT".to_string()));
    }

    #[test]
    fn test_select_license_ignores_empty_string() {
        let license = Some("".to_string());
        let license_expression = Some("GPL-3.0".to_string());
        let classifiers = vec![];

        let result = LicensePriority::select_license(license, license_expression, &classifiers);
        assert_eq!(result, Some("GPL-3.0".to_string()));
    }

    #[test]
    fn test_select_license_no_license_found() {
        let license = None;
        let license_expression = None;
        let classifiers = vec!["Programming Language :: Python :: 3".to_string()];

        let result = LicensePriority::select_license(license, license_expression, &classifiers);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_license_from_classifiers() {
        let classifiers = vec![
            "Development Status :: 5 - Production/Stable".to_string(),
            "License :: OSI Approved :: Apache Software License".to_string(),
            "Programming Language :: Python :: 3".to_string(),
        ];

        let result = LicensePriority::extract_license_from_classifiers(&classifiers);
        assert_eq!(result, Some("Apache Software License".to_string()));
    }

    #[test]
    fn test_extract_license_from_classifiers_not_found() {
        let classifiers = vec![
            "Development Status :: 5 - Production/Stable".to_string(),
            "Programming Language :: Python :: 3".to_string(),
        ];

        let result = LicensePriority::extract_license_from_classifiers(&classifiers);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_license_from_classifiers_empty() {
        let classifiers: Vec<String> = vec![];
        let result = LicensePriority::extract_license_from_classifiers(&classifiers);
        assert_eq!(result, None);
    }

    #[test]
    fn test_create_license_info() {
        let license = Some("MIT".to_string());
        let license_expression = None;
        let classifiers = vec![];
        let summary = Some("A great library".to_string());

        let info = LicensePriority::create_license_info(
            license,
            license_expression,
            &classifiers,
            summary.clone(),
        );

        assert_eq!(info.license_text(), Some("MIT"));
        assert_eq!(info.description(), summary.as_deref());
    }

    #[test]
    fn test_create_license_info_no_license() {
        let license = None;
        let license_expression = None;
        let classifiers = vec![];
        let summary = Some("A library without license".to_string());

        let info = LicensePriority::create_license_info(
            license,
            license_expression,
            &classifiers,
            summary,
        );

        assert_eq!(info.license_text(), None);
    }

    #[test]
    fn test_select_license_complex_priority() {
        // Test that empty license field falls through to expression
        let license = Some("".to_string());
        let license_expression = Some("MIT OR Apache-2.0".to_string());
        let classifiers = vec!["License :: OSI Approved :: BSD License".to_string()];

        let result = LicensePriority::select_license(license, license_expression, &classifiers);
        assert_eq!(result, Some("MIT OR Apache-2.0".to_string()));
    }
}
