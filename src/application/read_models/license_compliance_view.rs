/// View representation of a license policy violation.
#[derive(Debug, Clone)]
pub struct LicenseViolationView {
    pub package_name: String,
    pub package_version: String,
    /// The license string, or "N/A" for unknown.
    pub license: String,
    /// Human-readable reason for the violation.
    pub reason: String,
    /// The policy pattern that triggered the violation, if applicable.
    pub matched_pattern: Option<String>,
}

/// View representation of a license warning (unknown license, warn mode).
#[derive(Debug, Clone)]
pub struct LicenseWarningView {
    pub package_name: String,
    pub package_version: String,
}

/// Summary statistics for the license compliance check.
#[derive(Debug, Clone)]
pub struct LicenseComplianceSummary {
    pub violation_count: usize,
    pub warning_count: usize,
}

/// Top-level view for the license compliance section of the report.
#[derive(Debug, Clone)]
pub struct LicenseComplianceView {
    pub violations: Vec<LicenseViolationView>,
    pub warnings: Vec<LicenseWarningView>,
    pub has_violations: bool,
    pub summary: LicenseComplianceSummary,
}
