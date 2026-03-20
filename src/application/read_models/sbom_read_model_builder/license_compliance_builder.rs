use super::super::license_compliance_view::{
    LicenseComplianceSummary, LicenseComplianceView, LicenseViolationView, LicenseWarningView,
};
use crate::sbom_generation::domain::license_policy::LicenseComplianceResult;

pub(super) fn build_license_compliance(result: &LicenseComplianceResult) -> LicenseComplianceView {
    let violations: Vec<LicenseViolationView> = result
        .violations
        .iter()
        .map(|v| LicenseViolationView {
            package_name: v.package_name.clone(),
            package_version: v.package_version.clone(),
            license: v.license.clone().unwrap_or_else(|| "N/A".to_string()),
            reason: v.reason.as_str().to_string(),
            matched_pattern: v.matched_pattern.clone(),
        })
        .collect();

    let warnings: Vec<LicenseWarningView> = result
        .warnings
        .iter()
        .map(|w| LicenseWarningView {
            package_name: w.package_name.clone(),
            package_version: w.package_version.clone(),
        })
        .collect();

    let summary = LicenseComplianceSummary {
        violation_count: violations.len(),
        warning_count: warnings.len(),
    };

    LicenseComplianceView {
        has_violations: result.has_violations(),
        violations,
        warnings,
        summary,
    }
}
