use crate::sbom_generation::domain::license_policy::{
    LicenseComplianceResult, LicensePolicy, LicenseViolation, LicenseWarning,
    UnknownLicenseHandling, ViolationReason,
};

/// Stateless domain service for evaluating packages against a license policy.
pub struct LicenseComplianceChecker;

impl LicenseComplianceChecker {
    /// Checks all packages against the given policy.
    ///
    /// # Arguments
    /// * `packages` - Tuples of (name, version, license) where license may be None.
    /// * `policy` - The license compliance policy to evaluate against.
    ///
    /// # Logic per package
    /// 1. If license is `None` → handle based on `policy.unknown`
    /// 2. If license matches any deny pattern → violation (`Denied`)
    /// 3. If allow list is non-empty and license doesn't match any → violation (`NotAllowed`)
    /// 4. Otherwise → compliant
    ///
    /// **Deny takes precedence over allow.**
    pub fn check(
        packages: &[(String, String, Option<String>)],
        policy: &LicensePolicy,
    ) -> LicenseComplianceResult {
        let mut violations = Vec::new();
        let mut warnings = Vec::new();

        for (name, version, license) in packages {
            match license {
                None => match policy.unknown {
                    UnknownLicenseHandling::Deny => {
                        violations.push(LicenseViolation {
                            package_name: name.clone(),
                            package_version: version.clone(),
                            license: None,
                            reason: ViolationReason::UnknownLicense,
                            matched_pattern: None,
                        });
                    }
                    UnknownLicenseHandling::Warn => {
                        warnings.push(LicenseWarning {
                            package_name: name.clone(),
                            package_version: version.clone(),
                        });
                    }
                    UnknownLicenseHandling::Allow => {}
                },
                Some(lic) => {
                    // Check deny list first (deny takes precedence)
                    if let Some(pattern) = policy.deny.iter().find(|p| p.matches(lic)) {
                        violations.push(LicenseViolation {
                            package_name: name.clone(),
                            package_version: version.clone(),
                            license: Some(lic.clone()),
                            reason: ViolationReason::Denied,
                            matched_pattern: Some(pattern.as_str().to_string()),
                        });
                        continue;
                    }

                    // Check allow list
                    if !policy.allow.is_empty() && !policy.allow.iter().any(|p| p.matches(lic)) {
                        violations.push(LicenseViolation {
                            package_name: name.clone(),
                            package_version: version.clone(),
                            license: Some(lic.clone()),
                            reason: ViolationReason::NotAllowed,
                            matched_pattern: None,
                        });
                    }
                }
            }
        }

        LicenseComplianceResult {
            violations,
            warnings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom_generation::domain::license_policy::UnknownLicenseHandling;

    fn pkg(name: &str, version: &str, license: Option<&str>) -> (String, String, Option<String>) {
        (
            name.to_string(),
            version.to_string(),
            license.map(|l| l.to_string()),
        )
    }

    #[test]
    fn test_empty_policy_no_violations() {
        let policy = LicensePolicy::new(&[], &[], UnknownLicenseHandling::Warn);
        let packages = vec![pkg("a", "1.0", Some("MIT"))];
        let result = LicenseComplianceChecker::check(&packages, &policy);
        assert!(!result.has_violations());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_deny_only() {
        let policy = LicensePolicy::new(&[], &["GPL-*".to_string()], UnknownLicenseHandling::Warn);
        let packages = vec![
            pkg("a", "1.0", Some("MIT")),
            pkg("b", "2.0", Some("GPL-3.0")),
        ];
        let result = LicenseComplianceChecker::check(&packages, &policy);
        assert!(result.has_violations());
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].package_name, "b");
        assert_eq!(result.violations[0].reason, ViolationReason::Denied);
        assert_eq!(
            result.violations[0].matched_pattern.as_deref(),
            Some("GPL-*")
        );
    }

    #[test]
    fn test_allow_only() {
        let policy = LicensePolicy::new(
            &["MIT".to_string(), "Apache-2.0".to_string()],
            &[],
            UnknownLicenseHandling::Warn,
        );
        let packages = vec![
            pkg("a", "1.0", Some("MIT")),
            pkg("b", "2.0", Some("GPL-3.0")),
        ];
        let result = LicenseComplianceChecker::check(&packages, &policy);
        assert!(result.has_violations());
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].package_name, "b");
        assert_eq!(result.violations[0].reason, ViolationReason::NotAllowed);
    }

    #[test]
    fn test_deny_overrides_allow() {
        let policy = LicensePolicy::new(
            &["*GPL*".to_string()],
            &["AGPL-*".to_string()],
            UnknownLicenseHandling::Warn,
        );
        let packages = vec![
            pkg("a", "1.0", Some("GPL-3.0")),
            pkg("b", "2.0", Some("AGPL-3.0")),
        ];
        let result = LicenseComplianceChecker::check(&packages, &policy);
        assert!(result.has_violations());
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].package_name, "b");
        assert_eq!(result.violations[0].reason, ViolationReason::Denied);
    }

    #[test]
    fn test_unknown_license_warn() {
        let policy = LicensePolicy::new(&[], &[], UnknownLicenseHandling::Warn);
        let packages = vec![pkg("a", "1.0", None)];
        let result = LicenseComplianceChecker::check(&packages, &policy);
        assert!(!result.has_violations());
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.warnings[0].package_name, "a");
    }

    #[test]
    fn test_unknown_license_deny() {
        let policy = LicensePolicy::new(&[], &[], UnknownLicenseHandling::Deny);
        let packages = vec![pkg("a", "1.0", None)];
        let result = LicenseComplianceChecker::check(&packages, &policy);
        assert!(result.has_violations());
        assert_eq!(result.violations[0].reason, ViolationReason::UnknownLicense);
    }

    #[test]
    fn test_unknown_license_allow() {
        let policy = LicensePolicy::new(&[], &[], UnknownLicenseHandling::Allow);
        let packages = vec![pkg("a", "1.0", None)];
        let result = LicenseComplianceChecker::check(&packages, &policy);
        assert!(!result.has_violations());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_case_insensitive_matching() {
        let policy = LicensePolicy::new(&["mit".to_string()], &[], UnknownLicenseHandling::Warn);
        let packages = vec![pkg("a", "1.0", Some("MIT"))];
        let result = LicenseComplianceChecker::check(&packages, &policy);
        assert!(!result.has_violations());
    }

    #[test]
    fn test_multiple_violations() {
        let policy = LicensePolicy::new(
            &["MIT".to_string()],
            &["AGPL-*".to_string()],
            UnknownLicenseHandling::Deny,
        );
        let packages = vec![
            pkg("a", "1.0", Some("GPL-3.0")),  // not in allow
            pkg("b", "2.0", Some("AGPL-3.0")), // denied
            pkg("c", "3.0", None),             // unknown → denied
            pkg("d", "4.0", Some("MIT")),      // ok
        ];
        let result = LicenseComplianceChecker::check(&packages, &policy);
        assert_eq!(result.violations.len(), 3);
    }

    #[test]
    fn test_wildcard_deny_pattern() {
        let policy = LicensePolicy::new(&[], &["*GPL*".to_string()], UnknownLicenseHandling::Warn);
        let packages = vec![
            pkg("a", "1.0", Some("LGPL-2.1")),
            pkg("b", "2.0", Some("MIT")),
        ];
        let result = LicenseComplianceChecker::check(&packages, &policy);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].package_name, "a");
    }
}
