//! Internationalization (i18n) module for multilingual output support.
//!
//! Provides a zero-dependency locale system using static message tables
//! for English and Japanese. No external i18n crates are used.

/// Supported output locales.
///
/// Marked `#[non_exhaustive]` so that adding new variants in future releases
/// does not constitute a breaking change for downstream consumers.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Locale {
    #[default]
    En,
    Ja,
}

impl Locale {
    /// Parse a locale from a BCP 47 language tag string.
    ///
    /// Returns `None` for unsupported locales.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "en" => Some(Self::En),
            "ja" => Some(Self::Ja),
            _ => None,
        }
    }
}

/// All translatable strings used in formatted output.
///
/// Adding a field? Also add it to `all_message_fields!` in `mod tests`
/// (compile-enforced), which checks EN/JA `{}` placeholder-count parity.
pub struct Messages {
    // Section headers
    pub section_sbom_title: &'static str,
    pub section_component_inventory: &'static str,
    pub section_direct_deps: &'static str,
    pub section_transitive_deps: &'static str,
    pub section_vuln_report: &'static str,
    pub section_license_compliance: &'static str,
    pub section_resolution_guide: &'static str,
    pub section_dependency_chains: &'static str,

    // Table column headers
    pub col_package: &'static str,
    pub col_version: &'static str,
    pub col_license: &'static str,
    pub col_description: &'static str,
    pub col_current_version: &'static str,
    pub col_fixed_version: &'static str,
    pub col_severity: &'static str,
    pub col_vuln_id: &'static str,
    pub col_cvss: &'static str,

    // Progress messages (formatter/main layer)
    pub progress_generating_json: &'static str,
    pub progress_generating_markdown: &'static str,
    pub progress_verifying_links: &'static str,
    pub progress_fetching_license: &'static str,
    pub progress_fetching_vulns: &'static str,
    pub progress_diff_checking_base: &'static str,
    pub progress_diff_checking_current: &'static str,

    // Config loading messages (CLI layer)
    pub info_config_loaded_from: &'static str,
    pub info_config_auto_discovered: &'static str,
    pub warn_unknown_config_field: &'static str,

    // Error reporting and --init messages (CLI layer)
    pub error_header: &'static str,
    pub error_caused_by: &'static str,
    pub info_config_template_created: &'static str,
    pub error_init_failed: &'static str,
    pub error_no_workspace_members: &'static str,
    pub error_incident_advisory_not_found: &'static str,
    pub error_incident_invalid_target: &'static str,
    pub error_incident_target_hint: &'static str,
    pub error_incident_spec_empty: &'static str,
    pub error_incident_spec_missing_name: &'static str,
    pub error_incident_spec_invalid_name: &'static str,
    pub error_incident_spec_missing_specifier: &'static str,
    pub error_incident_spec_invalid_specifiers: &'static str,
    pub error_incident_spec_unsupported_operator: &'static str,
    pub error_incident_spec_multiple_lower: &'static str,
    pub error_incident_spec_multiple_upper: &'static str,
    pub error_incident_spec_empty_range: &'static str,

    // SBOM generation error messages (application layer, GenerateSbomUseCase)
    pub error_all_packages_excluded: &'static str,
    pub error_pyproject_not_found: &'static str,

    // Config error messages (CLI layer, rendered by src/cli/error_display.rs)
    pub error_config_already_exists: &'static str,
    pub error_config_template_write_failed: &'static str,
    pub error_config_read_failed: &'static str,
    pub error_config_parse_failed: &'static str,
    pub error_config_empty_ignore_cve_id: &'static str,
    pub error_config_invalid_unknown_license_handling: &'static str,

    // Progress messages (use case layer)
    pub progress_loading_lockfile: &'static str,
    pub progress_detected_packages: &'static str,
    pub progress_parsing_deps: &'static str,
    pub progress_direct_deps: &'static str,
    pub progress_transitive_deps: &'static str,
    pub warn_license_fetch_failed: &'static str,
    pub progress_license_complete: &'static str,
    pub progress_vuln_found: &'static str,
    pub progress_vuln_none: &'static str,

    // License compliance progress messages (use case layer)
    pub progress_license_violations_found: &'static str,
    pub progress_license_no_violations: &'static str,
    pub progress_license_unknown_packages: &'static str,

    // Upgrade advisor progress messages (use case layer)
    pub progress_analyzing_upgrade_paths: &'static str,
    pub progress_upgrade_resolves: &'static str,
    pub progress_upgrade_unresolvable: &'static str,
    pub progress_upgrade_simulation_failed: &'static str,

    // Singular/plural unit labels for direct dependency count
    pub label_dependency_singular: &'static str,
    pub label_dependency_plural: &'static str,

    // Warning messages
    pub warn_check_license_no_effect: &'static str,
    pub warn_check_license_json_detail: &'static str,
    pub warn_check_license_json_hint: &'static str,
    pub warn_verify_links_no_effect: &'static str,
    pub warn_verify_links_json_detail: &'static str,
    pub warn_verify_links_json_hint: &'static str,
    pub warn_abandoned_fetch_failed: &'static str,
    pub warn_vuln_detail_fetch_failed: &'static str,
    pub warn_epss_fetch_failed: &'static str,
    pub warn_kev_fetch_failed: &'static str,
    pub warn_ignored_cve_with_reason: &'static str,
    pub warn_ignored_cve_no_reason: &'static str,
    pub warn_dependency_chain_truncated: &'static str,
    pub warn_exclude_pattern_unmatched: &'static str,
    pub warn_suggest_fix_requires_uv: &'static str,
    pub warn_suggest_fix_requires_pyproject: &'static str,
    pub progress_baseline_loaded: &'static str,
    pub warn_baseline_not_found: &'static str,
    pub progress_baseline_suppressed: &'static str,
    pub progress_baseline_updated: &'static str,
    pub footnote_baseline_suppressed: &'static str,
    pub progress_fetching_abandoned: &'static str,
    pub progress_abandoned_found: &'static str,
    pub progress_abandoned_none: &'static str,
    pub progress_excluded_groups: &'static str,
    pub progress_packages_excluded: &'static str,
    pub progress_fetching_python_compat: &'static str,
    pub progress_python_compat_found: &'static str,
    pub progress_python_compat_none: &'static str,

    // Section description paragraphs
    pub desc_sbom_report: &'static str,
    pub desc_direct_deps: &'static str,
    pub desc_transitive_deps: &'static str,
    pub desc_transitive_vuln_table: &'static str,

    // Empty-state labels
    pub label_no_direct_deps: &'static str,
    pub label_no_transitive_deps: &'static str,
    pub label_no_license_violations: &'static str,
    pub label_osv_attribution: &'static str,
    pub label_epss_kev_attribution: &'static str,

    // Vulnerability count templates (4 placeholders: count, unit, count, unit)
    pub warn_no_vuln_above_threshold: &'static str,
    pub warn_vuln_found: &'static str,
    pub info_vuln_found: &'static str,

    // Singular/plural unit labels for vulnerability count templates
    pub label_vulnerability_singular: &'static str,
    pub label_vulnerability_plural: &'static str,
    pub label_package_singular: &'static str,
    pub label_package_plural: &'static str,

    // License violation count summary (singular/plural)
    pub label_license_violation_singular: &'static str,
    pub label_license_violation_plural: &'static str,

    // License compliance section strings
    pub section_violations: &'static str,
    pub section_warnings: &'static str,
    pub col_reason: &'static str,
    pub col_matched_pattern: &'static str,
    // template: count + unit word (EN uses both {}, JA only first {})
    pub warn_unknown_license_packages: &'static str,

    // Resolution guide column headers
    pub col_vulnerable_package: &'static str,
    pub col_current: &'static str,
    pub col_introduced_by: &'static str,
    pub col_recommended_action: &'static str,

    // Resolution guide action strings
    pub action_upgrade: &'static str,
    pub action_cannot_resolve: &'static str,
    pub action_could_not_analyze: &'static str,

    // Transitive dependency sub-header (1 placeholder: package name)
    pub deps_for_header: &'static str,

    // Vulnerability summary line (4 placeholders: count, unit, count, unit)
    pub summary_vuln_found: &'static str,

    // Workspace output messages
    pub output_complete: &'static str,
    pub workspace_mode_members_found: &'static str,
    pub workspace_processing_member: &'static str,
    pub workspace_summary_header: &'static str,
    pub workspace_col_member: &'static str,
    pub workspace_col_output_file: &'static str,
    pub workspace_aggregate_header: &'static str,
    pub workspace_aggregate_total_cves: &'static str,
    pub workspace_aggregate_license_violations: &'static str,
    pub workspace_aggregate_abandoned: &'static str,
    pub workspace_aggregate_non_pypi: &'static str,
    pub workspace_aggregate_python_incompatible: &'static str,
    pub workspace_aggregate_none: &'static str,

    // Executive summary section
    pub section_summary: &'static str,
    pub col_item: &'static str,
    pub col_count: &'static str,
    pub col_status: &'static str,
    pub label_direct_deps: &'static str,
    pub label_transitive_deps: &'static str,
    pub label_group_filter: &'static str,
    pub label_vuln_critical: &'static str,
    pub label_vuln_high: &'static str,
    pub label_vuln_medium: &'static str,
    pub label_vuln_low: &'static str,
    pub label_license_violations: &'static str,
    pub label_vuln_check_skipped: &'static str,
    pub overall_action_required: &'static str,
    pub overall_attention_recommended: &'static str,
    pub overall_no_issues: &'static str,

    // Abandoned packages section
    pub section_abandoned_packages: &'static str,
    pub desc_abandoned_packages: &'static str,
    pub label_abandoned_packages: &'static str,
    pub label_abandoned_check_skipped: &'static str,
    pub label_no_abandoned_packages: &'static str,
    pub col_last_release: &'static str,
    pub col_days_inactive: &'static str,
    pub col_type: &'static str,

    // Non-PyPI packages section
    pub section_non_pypi_packages: &'static str,
    pub summary_non_pypi_packages: &'static str,
    pub note_non_pypi_packages: &'static str,
    pub col_source_type: &'static str,
    pub col_source: &'static str,

    // Python compatibility section
    pub section_python_compat_issues: &'static str,
    pub section_python_compat_ok: &'static str,
    pub summary_python_compat_issues: &'static str,
    pub label_python_compat_all_clear: &'static str,
    pub col_requires_python: &'static str,

    // Dependency explanation section
    pub section_explain: &'static str,
    pub summary_explain_paths: &'static str,
    pub summary_explain_direct: &'static str,
    pub summary_explain_also_transitive: &'static str,
    pub summary_explain_not_found: &'static str,

    // Exploitability columns (conditional on --check-exploitability)
    pub col_exploited_kev: &'static str,
    pub col_epss: &'static str,
    pub progress_fetching_exploitability: &'static str,

    // Dependency tree section
    pub section_dependency_tree: &'static str,
    pub label_dependency_tree_truncated: &'static str,
    pub note_dependency_tree_truncated: &'static str,
    pub label_dependency_tree_empty: &'static str,

    // Diff Markdown formatter strings
    pub diff_section_title: &'static str,
    pub diff_compared_line: &'static str,
    pub diff_section_summary: &'static str,
    pub diff_col_metric: &'static str,
    pub diff_col_count: &'static str,
    pub diff_label_added: &'static str,
    pub diff_label_removed: &'static str,
    pub diff_label_updated: &'static str,
    pub diff_label_unchanged: &'static str,
    pub diff_section_changes: &'static str,
    pub diff_col_change: &'static str,
    pub diff_col_old_version: &'static str,
    pub diff_col_new_version: &'static str,
    pub diff_col_vulnerabilities: &'static str,
    pub diff_vuln_none: &'static str,
    pub diff_section_cve_delta: &'static str,
    pub diff_new_vulns_header: &'static str,
    pub diff_resolved_vulns_header: &'static str,
    pub diff_no_new_vulns: &'static str,
    pub diff_no_resolved_vulns: &'static str,

    // Incident report formatter strings (#967)
    pub incident_title: &'static str,
    pub incident_resolved_from: &'static str,
    pub incident_label_aliases: &'static str,
    pub incident_label_severity: &'static str,
    pub incident_label_summary: &'static str,
    pub incident_label_overall: &'static str,
    pub incident_section_impact: &'static str,
    pub incident_section_patch_status: &'static str,
    pub incident_section_next_action: &'static str,
    pub incident_verdict_not_affected: &'static str,
    pub incident_verdict_fix_released: &'static str,
    pub incident_verdict_fix_unreleased: &'static str,
    pub incident_verdict_no_fix: &'static str,
    pub incident_dependency_direct: &'static str,
    pub incident_dependency_transitive: &'static str,
    pub incident_paths_label: &'static str,
    pub incident_no_path: &'static str,
    pub incident_no_pypi_package: &'static str,
    pub incident_packages_not_in_project: &'static str,
    pub incident_status_fixed_in: &'static str,
    pub incident_status_released: &'static str,
    pub incident_status_yanked: &'static str,
    pub incident_status_not_found: &'static str,
    pub incident_status_unknown: &'static str,
    pub incident_status_no_fixed_version: &'static str,
    pub incident_status_not_applicable: &'static str,
    pub incident_action_verified: &'static str,
    pub incident_action_not_verified: &'static str,
    pub incident_guidance_resolution_blocked: &'static str,
    pub incident_guidance_no_released_fix: &'static str,
    pub incident_guidance_simulation_error: &'static str,
    pub incident_status_not_from_pypi: &'static str,
    pub incident_guidance_release_lookup_failed: &'static str,
    pub incident_guidance_not_from_pypi: &'static str,
    pub warn_incident_release_lookup_failed: &'static str,
    // Workspace incident report strings (#969)
    pub incident_member_heading: &'static str,
    pub incident_label_member_verdict: &'static str,
    pub incident_packages_not_in_member: &'static str,
    pub incident_status_not_applicable_workspace: &'static str,
    pub incident_workspace_aggregate: &'static str,

    // Manual range spec strings (#963)
    pub incident_title_manual: &'static str,
    pub incident_manual_notice: &'static str,
    pub incident_status_no_fixed_version_manual: &'static str,
}

impl Messages {
    /// Return the static message table for the given locale.
    pub fn for_locale(locale: Locale) -> &'static Self {
        match locale {
            Locale::En => &EN_MESSAGES,
            Locale::Ja => &JA_MESSAGES,
        }
    }

    /// Substitute positional `{}` placeholders in a message template with the given arguments.
    ///
    /// Replaces each `{}` in order with the corresponding element of `args`.
    /// Extra args are ignored; unmatched `{}` remain as-is.
    ///
    /// # Example
    /// ```
    /// use uv_sbom::i18n::Messages;
    /// assert_eq!(Messages::format("Found {} of {} packages", &["3", "10"]), "Found 3 of 10 packages");
    /// ```
    pub fn format(template: &str, args: &[&str]) -> String {
        let mut result = template.to_string();
        for arg in args {
            match result.find("{}") {
                Some(pos) => result.replace_range(pos..pos + 2, arg),
                None => break,
            }
        }
        result
    }
}

static EN_MESSAGES: Messages = Messages {
    // Section headers
    section_sbom_title: "# Software Bill of Materials (SBOM)",
    section_component_inventory: "## Component Inventory",
    section_direct_deps: "## Direct Dependencies",
    section_transitive_deps: "## Transitive Dependencies",
    section_vuln_report: "## Vulnerability Report",
    section_license_compliance: "## License Compliance Report",
    section_resolution_guide: "## Vulnerability Resolution Guide",
    section_dependency_chains: "### Dependency Chains",

    // Table column headers
    col_package: "Package",
    col_version: "Version",
    col_license: "License",
    col_description: "Description",
    col_current_version: "Current Version",
    col_fixed_version: "Fixed Version",
    col_severity: "Severity",
    col_vuln_id: "Vulnerability ID",
    col_cvss: "CVSS",

    // Progress messages
    progress_generating_json: "📝 Generating CycloneDX JSON format output...",
    progress_generating_markdown: "📝 Generating Markdown format output...",
    progress_verifying_links: "🔗 Verifying PyPI links...",
    progress_fetching_license: "🔍 Fetching license information...",
    progress_fetching_vulns: "🔍 Fetching vulnerability information...",
    progress_diff_checking_base: "🔍 Checking vulnerabilities in base lockfile...",
    progress_diff_checking_current: "🔍 Checking vulnerabilities in current lockfile...",

    // Config loading messages (CLI layer)
    info_config_loaded_from: "📄 Loaded config from: {}",
    info_config_auto_discovered: "📄 Auto-discovered config file in project directory.",
    warn_unknown_config_field: "⚠️  Warning: Unknown config field '{}' will be ignored.",

    // Error reporting and --init messages (CLI layer)
    error_header: "❌ An error occurred:",
    error_caused_by: "Caused by: {}",
    info_config_template_created: "Created {} in {}",
    error_init_failed: "Error: {}",
    error_no_workspace_members: "No workspace members found. Is this a uv workspace?",
    error_incident_advisory_not_found: "Advisory {} was not found in the OSV database. Check the ID, or search for it at https://osv.dev",
    error_incident_invalid_target: "Invalid advisory ID or version-range spec: '{}'. {}",
    error_incident_target_hint: "Expected an advisory ID starting with GHSA-, PYSEC-, CVE-, OSV-, or MAL-, or a package range such as \"foo<2.3.2\" or \"foo>=2.0,<2.3.2\" (operators >=, <, and <= only). Quote the range in the shell, because < is a redirection.",
    error_incident_spec_empty: "The value is empty.",
    error_incident_spec_missing_name: "No package name was given.",
    error_incident_spec_invalid_name: "'{}' is not a valid package name.",
    error_incident_spec_missing_specifier: "No version range was given for '{}'.",
    error_incident_spec_invalid_specifiers: "Could not parse the version range '{}'.",
    error_incident_spec_unsupported_operator: "'{}' uses an unsupported operator; only >=, <, and <= are allowed.",
    error_incident_spec_multiple_lower: "Only one lower bound (>=) is allowed.",
    error_incident_spec_multiple_upper: "Only one upper bound is allowed: use < for the fixed version, or <= for the last affected version.",
    error_incident_spec_empty_range: "The range '{}' contains no versions.",

    // SBOM generation error messages (application layer, GenerateSbomUseCase)
    error_all_packages_excluded: "All {} package(s) were excluded by the provided filters. The SBOM would be empty. Please adjust your exclusion patterns.",
    error_pyproject_not_found: "pyproject.toml not found in project directory",

    // Config error messages (CLI layer, rendered by src/cli/error_display.rs)
    error_config_already_exists: "{} already exists in {}. Use a different directory or remove the existing file.",
    error_config_template_write_failed: "Failed to write config template to: {}",
    error_config_read_failed: "Failed to read config file: {}\n\n💡 Hint: Check that the file exists and is readable.",
    error_config_parse_failed: "Failed to parse config file: {}\n\n💡 Hint: Ensure the file contains valid YAML syntax.",
    error_config_empty_ignore_cve_id: "Invalid config: ignore_cves[{}].id must not be empty.\n\n💡 Hint: Each ignore_cves entry must have a non-empty 'id' field (e.g., \"CVE-2024-1234\").",
    error_config_invalid_unknown_license_handling: "Invalid config: license_policy.unknown must be one of: warn, deny, allow. Got: \"{}\"",

    // Progress messages (use case layer)
    progress_loading_lockfile: "📖 Loading uv.lock file from: {}",
    progress_detected_packages: "✅ Detected {} package(s)",
    progress_parsing_deps: "📊 Parsing dependency information...",
    progress_direct_deps: "   - Direct dependencies: {}",
    progress_transitive_deps: "   - Transitive dependencies: {}",
    warn_license_fetch_failed: "⚠️  Warning: Error: Failed to fetch license information for {}: {}",
    progress_license_complete:
        "✅ License information retrieval complete: {} succeeded out of {}, {} failed",
    progress_vuln_found: "✅ Vulnerability check complete: {} vulnerabilities found in {} packages",
    progress_vuln_none: "✅ Vulnerability check complete: No known vulnerabilities found",

    // License compliance progress messages (use case layer)
    progress_license_violations_found: "⚠️  License compliance: {} violation(s) found",
    progress_license_no_violations: "✅ License compliance: No violations found",
    progress_license_unknown_packages: "⚠️  License compliance: {} package(s) with unknown license",

    // Upgrade advisor progress messages (use case layer)
    progress_analyzing_upgrade_paths: "🔍 Analyzing upgrade paths for {} direct {}...",
    progress_upgrade_resolves: "  ✓ Upgrade {} → {} resolves {} to {} ({})",
    progress_upgrade_unresolvable: "  ✗ Cannot resolve via {}: {} ({})",
    progress_upgrade_simulation_failed: "  ❓ Simulation failed for {}: {}",

    // Singular/plural unit labels for direct dependency count
    label_dependency_singular: "dependency",
    label_dependency_plural: "dependencies",

    // Warning messages
    warn_check_license_no_effect: "⚠️  Warning: --check-license has no effect with JSON format.",
    warn_check_license_json_detail: "   License compliance data is not included in JSON output.",
    warn_check_license_json_hint: "   Use --format markdown to see license compliance report.",
    warn_verify_links_no_effect: "⚠️  Warning: --verify-links has no effect with JSON format.",
    warn_verify_links_json_detail: "   PyPI link verification only applies to Markdown output.",
    warn_verify_links_json_hint: "   Use --format markdown to use link verification.",
    warn_abandoned_fetch_failed: "⚠️  Warning: Failed to fetch maintenance info for {}: {}",
    warn_vuln_detail_fetch_failed: "⚠️  Warning: Failed to fetch details for {}: {}",
    warn_epss_fetch_failed: "Warning: EPSS fetch failed for batch {}: {}",
    warn_kev_fetch_failed: "Warning: KEV catalog fetch failed: {}",
    warn_ignored_cve_with_reason: "⚠ Ignored {} for package {} (reason: {})",
    warn_ignored_cve_no_reason: "⚠ Ignored {} for package {} (no reason provided)",
    warn_dependency_chain_truncated: "⚠️  Warning: Maximum recursion depth ({}) reached for package '{}'. Dependency chain may be truncated.",
    warn_exclude_pattern_unmatched: "⚠️  Warning: Exclude pattern '{}' did not match any dependencies.",
    warn_suggest_fix_requires_uv: "⚠ --suggest-fix requires `uv` CLI. Install it with: curl -LsSf https://astral.sh/uv/install.sh | sh",
    warn_suggest_fix_requires_pyproject: "⚠ --suggest-fix requires pyproject.toml in the project directory.",
    progress_baseline_loaded: "📋 Loaded vulnerability baseline from {}",
    warn_baseline_not_found: "⚠ Baseline file not found: {}. Running without baseline filtering.",
    progress_baseline_suppressed: "📋 Suppressed {} finding(s) via vulnerability baseline",
    progress_baseline_updated: "📋 Updated vulnerability baseline: {} ({} entries)",
    footnote_baseline_suppressed: "_Note: {} previously-baselined finding(s) suppressed._",
    progress_fetching_abandoned: "🔍 Fetching package maintenance information...",
    progress_abandoned_found: "✅ Abandoned check complete: {} package(s) abandoned ({} direct, {} transitive), threshold: {} days",
    progress_abandoned_none: "✅ Abandoned check complete: No packages exceed {} day threshold",
    progress_excluded_groups: "🚫 Excluded {} package(s) from dependency group(s): {}",
    progress_packages_excluded: "🚫 Excluded {} package(s) based on filters",
    progress_fetching_python_compat: "🔍 Checking Python version compatibility...",
    progress_python_compat_found: "✅ Python compatibility check complete: {} package(s) incompatible with Python {} ({} direct, {} transitive)",
    progress_python_compat_none: "✅ Python compatibility check complete: All packages compatible with Python {}",

    // Section description paragraphs
    desc_sbom_report: "A comprehensive list of all software components and libraries included in this project.",
    desc_direct_deps: "Primary packages explicitly defined in the project configuration(e.g., pyproject.toml).",
    desc_transitive_deps: "Secondary dependencies introduced by the primary packages.",
    desc_transitive_vuln_table: "The following transitive dependencies have known vulnerabilities. The table shows which direct dependency introduces each vulnerable package.",

    // Empty-state labels
    label_no_direct_deps: "*No direct dependencies*",
    label_no_transitive_deps: "*No transitive dependencies*",
    label_no_license_violations: "**No license violations found.**",
    label_osv_attribution: "*Vulnerability data provided by [OSV](https://osv.dev) under CC-BY 4.0*",
    label_epss_kev_attribution: "*Exploitability data: [EPSS](https://www.first.org/epss) by FIRST.org; [KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) by CISA*",

    // Vulnerability count templates (4 placeholders: count, unit, count, unit)
    warn_no_vuln_above_threshold: "### ⚠️Warning No vulnerabilities found above threshold.",
    warn_vuln_found: "### ⚠️Warning Found {} {} in {} {}.",
    info_vuln_found: "### ℹ️Info Found {} {} in {} {}.",

    // Singular/plural unit labels for vulnerability count templates
    label_vulnerability_singular: "vulnerability",
    label_vulnerability_plural: "vulnerabilities",
    label_package_singular: "package",
    label_package_plural: "packages",

    // License violation count summary (singular/plural)
    label_license_violation_singular: "license violation found.",
    label_license_violation_plural: "license violations found.",

    // License compliance section strings
    section_violations: "### Violations",
    section_warnings: "### Warnings",
    col_reason: "Reason",
    col_matched_pattern: "Matched Pattern",
    warn_unknown_license_packages: "**{} {} with unknown license.**",

    // Resolution guide column headers
    col_vulnerable_package: "Vulnerable Package",
    col_current: "Current",
    col_introduced_by: "Introduced By (Direct Dep)",
    col_recommended_action: "Recommended Action",

    // Resolution guide action strings
    action_upgrade: "⬆️ Upgrade {} → {} (resolves {} to {})",
    action_cannot_resolve: "⚠️ Cannot resolve: {}",
    action_could_not_analyze: "❓ Could not analyze: {}",

    // Transitive dependency sub-header
    deps_for_header: "### Dependencies for {}",

    // Vulnerability summary line
    summary_vuln_found: "**Found {} {} in {} {}.**",

    // Workspace output messages
    output_complete: "✅ Output complete: {}",
    workspace_mode_members_found: "Workspace mode: {} members found",
    workspace_processing_member: "  Processing: {}",
    workspace_summary_header: "📦 Workspace SBOM Summary",
    workspace_col_member: "Member",
    workspace_col_output_file: "Output File",
    workspace_aggregate_header: "📊 Workspace Aggregate Summary",
    workspace_aggregate_total_cves: "Total actionable CVEs: {}",
    workspace_aggregate_license_violations: "Members with license policy violations: {}",
    workspace_aggregate_abandoned: "Members with abandoned packages: {}",
    workspace_aggregate_non_pypi: "Members with non-PyPI packages: {}",
    workspace_aggregate_python_incompatible: "Members with Python-incompatible packages: {}",
    workspace_aggregate_none: "none",

    // Executive summary section
    section_summary: "## Summary",
    col_item: "Item",
    col_count: "Count",
    col_status: "Status",
    label_direct_deps: "Direct dependencies",
    label_transitive_deps: "Transitive dependencies",
    label_group_filter: "Dependency group filter",
    label_vuln_critical: "Vulnerabilities (CRITICAL)",
    label_vuln_high: "Vulnerabilities (HIGH)",
    label_vuln_medium: "Vulnerabilities (MEDIUM)",
    label_vuln_low: "Vulnerabilities (LOW)",
    label_license_violations: "License violations",
    label_vuln_check_skipped: "_Vulnerability check skipped._",
    overall_action_required: "**Overall: Action required**",
    overall_attention_recommended: "**Overall: Attention recommended**",
    overall_no_issues: "**Overall: No issues found** ✅",

    // Abandoned packages section
    section_abandoned_packages: "## Abandoned Packages",
    desc_abandoned_packages: "Packages whose most recent upstream release exceeds the configured inactivity threshold. Inactive projects may carry unpatched vulnerabilities and pose long-term maintenance risk.",
    label_abandoned_packages: "Abandoned packages",
    label_abandoned_check_skipped: "_Abandoned package check skipped._",
    label_no_abandoned_packages: "No abandoned packages detected.",
    col_last_release: "Last Release",
    col_days_inactive: "Days Inactive",
    col_type: "Type",

    // Non-PyPI packages section
    section_non_pypi_packages: "## ⚠️ Non-PyPI Package Sources",
    summary_non_pypi_packages: "{} packages are sourced from outside the official PyPI registry ({} direct, {} transitive).",
    note_non_pypi_packages: "> Packages from non-PyPI sources may not be subject to PyPI's security policies. Review each package's origin before production deployment.",
    col_source_type: "Source Type",
    col_source: "Source",

    // Python compatibility section
    section_python_compat_issues: "## ⚠️ Python {} Compatibility Issues",
    section_python_compat_ok: "## ✅ Python {} Compatibility",
    summary_python_compat_issues: "{} package(s) incompatible with the target Python version ({} direct, {} transitive).",
    label_python_compat_all_clear: "All packages are compatible with the target Python version.",
    col_requires_python: "Requires-Python",

    // Dependency explanation section
    section_explain: "## Dependency Explanation",
    summary_explain_paths: "**{}** is included via {} path(s):",
    summary_explain_direct: "**{}** is a direct dependency of this project.",
    summary_explain_also_transitive: "It is also reachable through {} transitive path(s):",
    summary_explain_not_found: "Package **{}** was not found in this project's dependencies.",

    // Exploitability columns
    col_exploited_kev: "Exploited (KEV)",
    col_epss: "EPSS",
    progress_fetching_exploitability: "🔍 Fetching exploitability data (EPSS/KEV)...",

    // Dependency tree section
    section_dependency_tree: "## Dependency Tree",
    label_dependency_tree_truncated: "... (truncated)",
    note_dependency_tree_truncated: "_Tree truncated at depth {}. Use `--dependency-tree-depth <DEPTH>` to show more levels._",
    label_dependency_tree_empty: "_No direct dependencies found._",

    // Diff Markdown formatter strings
    diff_section_title: "## Dependency Diff Report",
    diff_compared_line: "Compared: `{}` vs current `uv.lock`",
    diff_section_summary: "### Summary",
    diff_col_metric: "Metric",
    diff_col_count: "Count",
    diff_label_added: "Added",
    diff_label_removed: "Removed",
    diff_label_updated: "Updated",
    diff_label_unchanged: "Unchanged",
    diff_section_changes: "### Changes",
    diff_col_change: "Change",
    diff_col_old_version: "Old Version",
    diff_col_new_version: "New Version",
    diff_col_vulnerabilities: "Vulnerabilities",
    diff_vuln_none: "None",
    diff_section_cve_delta: "## CVE Delta",
    diff_new_vulns_header: "### 🔴 New Vulnerabilities ({})",
    diff_resolved_vulns_header: "### ✅ Resolved Vulnerabilities ({})",
    diff_no_new_vulns: "No new vulnerabilities",
    diff_no_resolved_vulns: "No resolved vulnerabilities",

    // Incident report formatter strings (#967)
    incident_title: "## Incident Report: {}",
    incident_resolved_from: "(resolved from {})",
    incident_label_aliases: "Aliases",
    incident_label_severity: "Severity",
    incident_label_summary: "Summary",
    incident_label_overall: "Overall verdict",
    incident_section_impact: "### 1. Impact",
    incident_section_patch_status: "### 2. Patch status",
    incident_section_next_action: "### 3. Next action",
    incident_verdict_not_affected: "Not affected",
    incident_verdict_fix_released: "Affected — fix released",
    incident_verdict_fix_unreleased: "Affected — fix not yet released",
    incident_verdict_no_fix: "Affected — no fix available",
    incident_dependency_direct: "direct dependency",
    incident_dependency_transitive: "transitive dependency",
    incident_paths_label: "Dependency path(s):",
    incident_no_path: "No path from the project's main dependencies (likely a dependency-group package)",
    incident_no_pypi_package: "This advisory does not affect any PyPI package.",
    incident_packages_not_in_project: "None of the affected packages ({}) are in this project.",
    incident_status_fixed_in: "fixed in {}",
    incident_status_released: "released",
    incident_status_yanked: "yanked",
    incident_status_not_found: "not published on PyPI",
    incident_status_unknown: "release status unknown (lookup failed)",
    incident_status_no_fixed_version: "the advisory names no fixed version",
    incident_status_not_applicable: "Not applicable — this project is not affected.",
    incident_action_verified: "Verified by a dry-run resolution (your uv.lock was not modified):",
    incident_action_not_verified: "⚠️ Not verified (uv is not available) — review before running:",
    incident_guidance_resolution_blocked: "Upgrading **{}** to {} could not be resolved. The blocking constraint is likely held by: {}. Run `uv-sbom --suggest-fix` to find compatible upgrades.",
    incident_guidance_no_released_fix: "No released fix is available for **{}** yet.",
    incident_guidance_simulation_error: "Could not verify an upgrade of **{}** to {}: {}",
    incident_status_not_from_pypi: "not hosted on PyPI — release status not checked",
    incident_guidance_release_lookup_failed: "Could not check whether **{}** {} is released: {}. Check PyPI manually before upgrading.",
    incident_guidance_not_from_pypi: "**{}** is not installed from PyPI; check its source for a release containing the fix ({}).",
    warn_incident_release_lookup_failed: "⚠️  Could not check the release status of {} {}: {}",

    // Workspace incident report strings (#969)
    incident_member_heading: "#### Member: {}",
    incident_label_member_verdict: "Verdict",
    incident_packages_not_in_member: "None of the affected packages ({}) are reachable from this member.",
    incident_status_not_applicable_workspace: "Not applicable — no workspace member is affected.",
    incident_workspace_aggregate: "**{} of {} members affected**: {}",

    // Manual range spec strings (#963)
    incident_title_manual: "## Incident Report (manual range): `{}`",
    incident_manual_notice: "⚠️ This affected range was supplied by you. It is not taken from a vulnerability database and has not been verified.",
    incident_status_no_fixed_version_manual: "the supplied range names no fixed version",
};

static JA_MESSAGES: Messages = Messages {
    // Section headers
    section_sbom_title: "# ソフトウェア部品表 (SBOM)",
    section_component_inventory: "## コンポーネント一覧",
    section_direct_deps: "## 直接依存パッケージ",
    section_transitive_deps: "## 間接依存パッケージ",
    section_vuln_report: "## 脆弱性レポート",
    section_license_compliance: "## ライセンスコンプライアンスレポート",
    section_resolution_guide: "## 脆弱性解決ガイド",
    section_dependency_chains: "### 依存チェーン",

    // Table column headers
    col_package: "パッケージ",
    col_version: "バージョン",
    col_license: "ライセンス",
    col_description: "説明",
    col_current_version: "現在のバージョン",
    col_fixed_version: "修正済みバージョン",
    col_severity: "深刻度",
    col_vuln_id: "脆弱性ID",
    col_cvss: "CVSS",

    // Progress messages
    progress_generating_json: "📝 CycloneDX JSON形式で出力を生成中...",
    progress_generating_markdown: "📝 Markdown形式で出力を生成中...",
    progress_verifying_links: "🔗 PyPIリンクを検証中...",
    progress_fetching_license: "🔍 ライセンス情報を取得中...",
    progress_fetching_vulns: "🔍 脆弱性情報を取得中...",
    progress_diff_checking_base: "🔍 ベースロックファイルの脆弱性をチェック中...",
    progress_diff_checking_current: "🔍 現在のロックファイルの脆弱性をチェック中...",

    // Config loading messages (CLI layer)
    info_config_loaded_from: "📄 設定ファイルを読み込みました: {}",
    info_config_auto_discovered: "📄 プロジェクトディレクトリ内の設定ファイルを自動検出しました。",
    warn_unknown_config_field: "⚠️  警告: 不明な設定項目 '{}' は無視されます。",

    // Error reporting and --init messages (CLI layer)
    error_header: "❌ エラーが発生しました:",
    error_caused_by: "原因: {}",
    info_config_template_created: "{} を {} に作成しました",
    error_init_failed: "エラー: {}",
    error_no_workspace_members: "ワークスペースメンバーが見つかりません。これは uv ワークスペースですか？",
    error_incident_advisory_not_found: "アドバイザリ {} は OSV データベースに見つかりませんでした。ID を確認するか、https://osv.dev で検索してください",
    error_incident_invalid_target: "アドバイザリ ID またはバージョン範囲の指定が不正です: '{}'。{}",
    error_incident_target_hint: "GHSA-、PYSEC-、CVE-、OSV-、MAL- で始まるアドバイザリ ID か、\"foo<2.3.2\" や \"foo>=2.0,<2.3.2\" のようなパッケージの範囲（演算子は >=、<、<= のみ）を指定してください。< はシェルのリダイレクトになるため、範囲は引用符で囲んでください。",
    error_incident_spec_empty: "値が空です。",
    error_incident_spec_missing_name: "パッケージ名が指定されていません。",
    error_incident_spec_invalid_name: "'{}' はパッケージ名として不正です。",
    error_incident_spec_missing_specifier: "'{}' のバージョン範囲が指定されていません。",
    error_incident_spec_invalid_specifiers: "バージョン範囲 '{}' を解析できませんでした。",
    error_incident_spec_unsupported_operator: "'{}' はサポートされていない演算子を使っています。使える演算子は >=、<、<= のみです。",
    error_incident_spec_multiple_lower: "下限（>=）は 1 つだけ指定できます。",
    error_incident_spec_multiple_upper: "上限は 1 つだけ指定できます。修正バージョンには <、影響を受ける最後のバージョンには <= を使ってください。",
    error_incident_spec_empty_range: "範囲 '{}' に含まれるバージョンがありません。",

    // SBOM generation error messages (application layer, GenerateSbomUseCase)
    error_all_packages_excluded: "指定されたフィルターにより {} 個のパッケージがすべて除外されました。SBOM が空になります。除外パターンを見直してください。",
    error_pyproject_not_found: "プロジェクトディレクトリに pyproject.toml が見つかりません。",

    // Config error messages (CLI layer, rendered by src/cli/error_display.rs)
    error_config_already_exists: "{} は {} に既に存在します。別のディレクトリを指定するか、既存のファイルを削除してください。",
    error_config_template_write_failed: "設定テンプレートの書き込みに失敗しました: {}",
    error_config_read_failed: "設定ファイルの読み込みに失敗しました: {}\n\n💡 ヒント: ファイルが存在し、読み取り可能であることを確認してください。",
    error_config_parse_failed: "設定ファイルの解析に失敗しました: {}\n\n💡 ヒント: ファイルが有効な YAML 構文であることを確認してください。",
    error_config_empty_ignore_cve_id: "設定が不正です: ignore_cves[{}].id は空にできません。\n\n💡 ヒント: ignore_cves の各エントリには空でない 'id' フィールドが必要です（例: \"CVE-2024-1234\"）。",
    error_config_invalid_unknown_license_handling: "設定が不正です: license_policy.unknown は warn, deny, allow のいずれかである必要があります。指定値: \"{}\"",

    // Progress messages (use case layer)
    progress_loading_lockfile: "📖 uv.lockファイルを読み込み中: {}",
    progress_detected_packages: "✅ {}個のパッケージを検出",
    progress_parsing_deps: "📊 依存関係情報を解析中...",
    progress_direct_deps: "   - 直接依存: {}",
    progress_transitive_deps: "   - 間接依存: {}",
    warn_license_fetch_failed: "⚠️  警告: {}のライセンス情報の取得に失敗: {}",
    progress_license_complete: "✅ ライセンス情報取得完了: {}件成功 / {}件中、{}件失敗",
    progress_vuln_found: "✅ 脆弱性チェック完了: {}個のパッケージで{}件の脆弱性を検出",
    progress_vuln_none: "✅ 脆弱性チェック完了: 既知の脆弱性は検出されませんでした",

    // License compliance progress messages (use case layer)
    progress_license_violations_found: "⚠️  ライセンスコンプライアンス: {}件の違反が見つかりました",
    progress_license_no_violations: "✅ ライセンスコンプライアンス: 違反は見つかりませんでした",
    progress_license_unknown_packages: "⚠️  ライセンスコンプライアンス: ライセンス不明のパッケージが{}件あります",

    // Upgrade advisor progress messages (use case layer)
    // JA: only first {} (count) is used; second {} (unit word) is ignored
    progress_analyzing_upgrade_paths: "🔍 {}個の直接依存パッケージのアップグレード経路を解析中...",
    progress_upgrade_resolves: "  ✓ {}を{}にアップグレードすると{}が{}に解決されます ({})",
    progress_upgrade_unresolvable: "  ✗ {}経由で解決できません: {} ({})",
    progress_upgrade_simulation_failed: "  ❓ {}のシミュレーションに失敗しました: {}",

    // Singular/plural unit labels (no distinction in Japanese; unused by JA template)
    label_dependency_singular: "個の直接依存パッケージ",
    label_dependency_plural: "個の直接依存パッケージ",

    // Warning messages
    warn_check_license_no_effect: "⚠️  警告: JSON形式では --check-license は効果がありません。",
    warn_check_license_json_detail: "   ライセンスコンプライアンス情報はJSON出力には含まれません。",
    warn_check_license_json_hint: "   ライセンスコンプライアンスレポートを表示するには --format markdown を使用してください。",
    warn_verify_links_no_effect: "⚠️  警告: JSON形式では --verify-links は効果がありません。",
    warn_verify_links_json_detail: "   PyPIリンク検証はMarkdown出力にのみ適用されます。",
    warn_verify_links_json_hint: "   リンク検証を使用するには --format markdown を使用してください。",
    warn_abandoned_fetch_failed: "⚠️  警告: {}のメンテナンス情報の取得に失敗: {}",
    warn_vuln_detail_fetch_failed: "⚠️  警告: {}の詳細情報の取得に失敗: {}",
    warn_epss_fetch_failed: "警告: バッチ{}のEPSSデータ取得に失敗: {}",
    warn_kev_fetch_failed: "警告: KEVカタログの取得に失敗: {}",
    warn_ignored_cve_with_reason: "⚠ {} をパッケージ {} で無視しました (理由: {})",
    warn_ignored_cve_no_reason: "⚠ {} をパッケージ {} で無視しました (理由の指定なし)",
    warn_dependency_chain_truncated: "⚠️  警告: 最大再帰深度 ({}) に達しました（パッケージ: '{}'）。依存関係チェーンが切り詰められる可能性があります。",
    warn_exclude_pattern_unmatched: "⚠️  警告: 除外パターン '{}' はどの依存関係にも一致しませんでした。",
    warn_suggest_fix_requires_uv: "⚠ --suggest-fix には `uv` CLI が必要です。インストール: curl -LsSf https://astral.sh/uv/install.sh | sh",
    warn_suggest_fix_requires_pyproject: "⚠ --suggest-fix にはプロジェクトディレクトリに pyproject.toml が必要です。",
    progress_baseline_loaded: "📋 脆弱性ベースラインを読み込みました: {}",
    warn_baseline_not_found: "⚠ ベースラインファイルが見つかりません: {}。ベースラインフィルタリングなしで実行します。",
    progress_baseline_suppressed: "📋 脆弱性ベースラインにより {} 件の検出結果を抑制しました",
    progress_baseline_updated: "📋 脆弱性ベースラインを更新しました: {}（{}件）",
    footnote_baseline_suppressed: "_注: ベースラインにより {} 件の既知の検出結果が抑制されています。_",
    progress_fetching_abandoned: "🔍 パッケージのメンテナンス情報を取得中...",
    progress_abandoned_found: "✅ 廃止パッケージチェック完了: {}件廃止（直接: {}件、間接: {}件）、閾値: {}日",
    progress_abandoned_none: "✅ 廃止パッケージチェック完了: {}日以上更新のないパッケージはありません",
    progress_excluded_groups: "🚫 依存関係グループから{}個のパッケージを除外: {}",
    progress_packages_excluded: "🚫 フィルターにより{}個のパッケージを除外",
    progress_fetching_python_compat: "🔍 Pythonバージョン互換性を確認中...",
    progress_python_compat_found: "✅ Python互換性チェック完了: {}件のパッケージがPython {}と互換性がありません（直接: {}件、間接: {}件）",
    progress_python_compat_none: "✅ Python互換性チェック完了: すべてのパッケージがPython {}と互換性があります",

    // Section description paragraphs
    desc_sbom_report: "このプロジェクトに含まれるすべてのソフトウェアコンポーネントとライブラリの一覧です。",
    desc_direct_deps: "プロジェクト設定（例: pyproject.toml）に明示的に定義された主要パッケージです。",
    desc_transitive_deps: "主要パッケージによって導入される間接的な依存パッケージです。",
    desc_transitive_vuln_table: "以下の間接依存パッケージに既知の脆弱性があります。テーブルはどの直接依存パッケージが各脆弱性パッケージを導入しているかを示します。",

    // Empty-state labels
    label_no_direct_deps: "*直接依存パッケージなし*",
    label_no_transitive_deps: "*間接依存パッケージなし*",
    label_no_license_violations: "**ライセンス違反は見つかりませんでした。**",
    label_osv_attribution: "*脆弱性データは [OSV](https://osv.dev) より CC-BY 4.0 ライセンスの下で提供されています*",
    label_epss_kev_attribution: "*悪用可能性データ: [EPSS](https://www.first.org/epss)（FIRST.org 提供）; [KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)（CISA 提供）*",

    // Vulnerability count templates
    // JA uses 4 placeholders in order: vuln_count, vuln_unit, pkg_count, pkg_unit
    warn_no_vuln_above_threshold: "### ⚠️警告 閾値を超える脆弱性は見つかりませんでした。",
    warn_vuln_found: "### ⚠️警告 {}{}が{}{}で見つかりました。",
    info_vuln_found: "### ℹ️情報 {}{}が{}{}で見つかりました。",

    // Singular/plural unit labels (no distinction in Japanese)
    label_vulnerability_singular: "件の脆弱性",
    label_vulnerability_plural: "件の脆弱性",
    label_package_singular: "個のパッケージ",
    label_package_plural: "個のパッケージ",

    // License violation count summary (no plural distinction in Japanese)
    label_license_violation_singular: "件のライセンス違反が見つかりました。",
    label_license_violation_plural: "件のライセンス違反が見つかりました。",

    // License compliance section strings
    section_violations: "### 違反",
    section_warnings: "### 警告",
    col_reason: "理由",
    col_matched_pattern: "マッチしたパターン",
    // JA: only first {} (count) is used; second {} (unit word) is ignored
    warn_unknown_license_packages: "**{}個のライセンス不明パッケージがあります。**",

    // Resolution guide column headers
    col_vulnerable_package: "脆弱性のあるパッケージ",
    col_current: "現在",
    col_introduced_by: "導入元（直接依存）",
    col_recommended_action: "推奨アクション",

    // Resolution guide action strings
    action_upgrade: "⬆️ {}を{}にアップグレード（{}が{}に解決）",
    action_cannot_resolve: "⚠️ 解決不可: {}",
    action_could_not_analyze: "❓ 分析不可: {}",

    // Transitive dependency sub-header
    deps_for_header: "### {}の依存パッケージ",

    // Vulnerability summary line
    summary_vuln_found: "**{}{}が{}{}で見つかりました。**",

    // Workspace output messages
    output_complete: "✅ 出力完了: {}",
    workspace_mode_members_found: "ワークスペースモード: {} メンバーを検出",
    workspace_processing_member: "  処理中: {}",
    workspace_summary_header: "📦 ワークスペース SBOM サマリー",
    workspace_col_member: "メンバー",
    workspace_col_output_file: "出力ファイル",
    workspace_aggregate_header: "📊 ワークスペース集計サマリー",
    workspace_aggregate_total_cves: "対応が必要なCVE合計: {}",
    workspace_aggregate_license_violations: "ライセンスポリシー違反があるメンバー: {}",
    workspace_aggregate_abandoned: "メンテナンス停止パッケージがあるメンバー: {}",
    workspace_aggregate_non_pypi: "非PyPIパッケージがあるメンバー: {}",
    workspace_aggregate_python_incompatible: "Python非互換パッケージがあるメンバー: {}",
    workspace_aggregate_none: "なし",

    // Executive summary section
    section_summary: "## サマリー",
    col_item: "項目",
    col_count: "件数",
    col_status: "状態",
    label_direct_deps: "直接依存パッケージ",
    label_transitive_deps: "間接依存パッケージ",
    label_group_filter: "依存グループフィルター",
    label_vuln_critical: "脆弱性 (CRITICAL)",
    label_vuln_high: "脆弱性 (HIGH)",
    label_vuln_medium: "脆弱性 (MEDIUM)",
    label_vuln_low: "脆弱性 (LOW)",
    label_license_violations: "ライセンス違反",
    label_vuln_check_skipped: "_脆弱性チェックはスキップされました。_",
    overall_action_required: "**総合判定: 対応が必要です**",
    overall_attention_recommended: "**総合判定: 注意が必要です**",
    overall_no_issues: "**総合判定: 問題なし** ✅",

    // Abandoned packages section
    section_abandoned_packages: "## 廃止パッケージ",
    desc_abandoned_packages: "設定された非アクティブ閾値を超えて更新されていないパッケージです。メンテナンスが停止しているプロジェクトは未修正の脆弱性を含む可能性があり、長期的な保守リスクとなります。",
    label_abandoned_packages: "廃止パッケージ",
    label_abandoned_check_skipped: "_廃止パッケージチェックはスキップされました。_",
    label_no_abandoned_packages: "廃止パッケージは検出されませんでした。",
    col_last_release: "最終リリース",
    col_days_inactive: "非アクティブ日数",
    col_type: "種別",

    // Non-PyPI packages section
    section_non_pypi_packages: "## ⚠️ PyPI以外のパッケージソース",
    summary_non_pypi_packages: "{}個のパッケージが公式PyPIレジストリ以外から取得されています（直接依存 {}件、間接依存 {}件）。",
    note_non_pypi_packages: "> PyPI以外のソースから取得されたパッケージは、PyPIのセキュリティポリシーの対象外である可能性があります。本番環境へのデプロイ前に、各パッケージの取得元を確認してください。",
    col_source_type: "ソース種別",
    col_source: "取得元",

    // Python compatibility section
    section_python_compat_issues: "## ⚠️ Python {} 互換性の問題",
    section_python_compat_ok: "## ✅ Python {} 互換性",
    summary_python_compat_issues: "{}個のパッケージがターゲットPythonバージョンと非互換です（直接依存 {}件、間接依存 {}件）。",
    label_python_compat_all_clear: "すべてのパッケージがターゲットPythonバージョンと互換性があります。",
    col_requires_python: "Requires-Python",

    // Dependency explanation section
    section_explain: "## 依存関係の説明",
    summary_explain_paths: "**{}** は {} 個の経路で含まれています:",
    summary_explain_direct: "**{}** はこのプロジェクトの直接依存パッケージです。",
    summary_explain_also_transitive: "さらに {} 個の間接経路からも到達可能です:",
    summary_explain_not_found: "パッケージ **{}** はこのプロジェクトの依存関係に見つかりませんでした。",

    // Exploitability columns
    col_exploited_kev: "悪用確認済み (KEV)",
    col_epss: "EPSS",
    progress_fetching_exploitability: "🔍 悪用可能性データ (EPSS/KEV) を取得中...",

    // Dependency tree section
    section_dependency_tree: "## 依存関係ツリー",
    label_dependency_tree_truncated: "... (省略)",
    note_dependency_tree_truncated: "_深さ {} で省略されています。さらに深い階層を表示するには `--dependency-tree-depth <DEPTH>` を使用してください。_",
    label_dependency_tree_empty: "_直接依存パッケージが見つかりません。_",

    // Diff Markdown formatter strings
    diff_section_title: "## 依存関係差分レポート",
    diff_compared_line: "比較: `{}` と現在の `uv.lock`",
    diff_section_summary: "### サマリー",
    diff_col_metric: "指標",
    diff_col_count: "件数",
    diff_label_added: "追加",
    diff_label_removed: "削除",
    diff_label_updated: "更新",
    diff_label_unchanged: "変更なし",
    diff_section_changes: "### 変更一覧",
    diff_col_change: "変更種別",
    diff_col_old_version: "旧バージョン",
    diff_col_new_version: "新バージョン",
    diff_col_vulnerabilities: "脆弱性",
    diff_vuln_none: "なし",
    diff_section_cve_delta: "## CVE デルタ",
    diff_new_vulns_header: "### 🔴 新たな脆弱性 ({})",
    diff_resolved_vulns_header: "### ✅ 解消された脆弱性 ({})",
    diff_no_new_vulns: "新たな脆弱性はありません",
    diff_no_resolved_vulns: "解消された脆弱性はありません",

    // Incident report formatter strings (#967)
    incident_title: "## インシデントレポート: {}",
    incident_resolved_from: "（{} から解決）",
    incident_label_aliases: "別名",
    incident_label_severity: "深刻度",
    incident_label_summary: "概要",
    incident_label_overall: "総合判定",
    incident_section_impact: "### 1. 影響",
    incident_section_patch_status: "### 2. パッチ状況",
    incident_section_next_action: "### 3. 次のアクション",
    incident_verdict_not_affected: "影響なし",
    incident_verdict_fix_released: "影響あり — 修正版リリース済み",
    incident_verdict_fix_unreleased: "影響あり — 修正版未リリース",
    incident_verdict_no_fix: "影響あり — 修正版なし",
    incident_dependency_direct: "直接依存",
    incident_dependency_transitive: "間接依存",
    incident_paths_label: "依存経路:",
    incident_no_path: "プロジェクトの主依存からの経路なし（依存グループのパッケージの可能性）",
    incident_no_pypi_package: "このアドバイザリは PyPI パッケージに影響しません。",
    incident_packages_not_in_project: "影響対象パッケージ（{}）はこのプロジェクトに含まれていません。",
    incident_status_fixed_in: "{} で修正",
    incident_status_released: "リリース済み",
    incident_status_yanked: "取り下げ済み（yanked）",
    incident_status_not_found: "PyPI 未公開",
    incident_status_unknown: "リリース状況不明（取得失敗）",
    incident_status_no_fixed_version: "アドバイザリに修正バージョンの記載なし",
    incident_status_not_applicable: "該当なし — このプロジェクトは影響を受けません。",
    incident_action_verified: "試行解決で検証済み（uv.lock は変更されていません）:",
    incident_action_not_verified: "⚠️ 未検証（uv を利用できません）— 実行前に確認してください:",
    incident_guidance_resolution_blocked: "**{}** を {} へ更新できませんでした。制約を保持している可能性が高い直接依存: {}。`uv-sbom --suggest-fix` で互換性のある更新を確認してください。",
    incident_guidance_no_released_fix: "**{}** の修正版はまだリリースされていません。",
    incident_guidance_simulation_error: "**{}** の {} への更新を検証できませんでした: {}",
    incident_status_not_from_pypi: "PyPI 以外のソース — リリース状況は未確認",
    incident_guidance_release_lookup_failed: "**{}** {} のリリース状況を確認できませんでした: {}。更新前に PyPI を手動で確認してください。",
    incident_guidance_not_from_pypi: "**{}** は PyPI 以外からインストールされています。修正（{}）を含むリリースをソース側で確認してください。",
    warn_incident_release_lookup_failed: "⚠️  {} {} のリリース状況を確認できませんでした: {}",

    // Workspace incident report strings (#969)
    incident_member_heading: "#### メンバー: {}",
    incident_label_member_verdict: "判定",
    incident_packages_not_in_member: "影響対象パッケージ（{}）はこのメンバーから到達しません。",
    incident_status_not_applicable_workspace: "該当なし — 影響を受けるワークスペースメンバーはありません。",
    incident_workspace_aggregate: "**{} / {} メンバーが影響あり**: {}",

    // Manual range spec strings (#963)
    incident_title_manual: "## インシデントレポート（手動指定の範囲）: `{}`",
    incident_manual_notice: "⚠️ この影響範囲はユーザーが指定したものです。脆弱性データベースの記録ではなく、検証もされていません。",
    incident_status_no_fixed_version_manual: "指定された範囲に修正バージョンの記載なし",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locale_from_str_en() {
        assert_eq!(Locale::from_str("en"), Some(Locale::En));
    }

    #[test]
    fn test_locale_from_str_ja() {
        assert_eq!(Locale::from_str("ja"), Some(Locale::Ja));
    }

    #[test]
    fn test_locale_from_str_unknown() {
        assert_eq!(Locale::from_str("fr"), None);
        assert_eq!(Locale::from_str(""), None);
        assert_eq!(Locale::from_str("EN"), None);
    }

    #[test]
    fn test_locale_default_is_en() {
        assert_eq!(Locale::default(), Locale::En);
    }

    #[test]
    fn test_messages_for_locale_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            msgs.section_sbom_title,
            "# Software Bill of Materials (SBOM)"
        );
        assert_eq!(msgs.section_direct_deps, "## Direct Dependencies");
        assert_eq!(msgs.col_package, "Package");
        assert_eq!(
            msgs.progress_generating_json,
            "📝 Generating CycloneDX JSON format output..."
        );
    }

    #[test]
    fn test_messages_for_locale_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(msgs.section_sbom_title, "# ソフトウェア部品表 (SBOM)");
        assert_eq!(msgs.section_direct_deps, "## 直接依存パッケージ");
        assert_eq!(msgs.col_package, "パッケージ");
        assert_eq!(
            msgs.progress_generating_json,
            "📝 CycloneDX JSON形式で出力を生成中..."
        );
    }

    #[test]
    fn test_messages_use_case_progress_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            msgs.progress_loading_lockfile,
            "📖 Loading uv.lock file from: {}"
        );
        assert_eq!(msgs.progress_detected_packages, "✅ Detected {} package(s)");
        assert_eq!(
            msgs.progress_parsing_deps,
            "📊 Parsing dependency information..."
        );
        assert_eq!(msgs.progress_direct_deps, "   - Direct dependencies: {}");
        assert_eq!(
            msgs.progress_transitive_deps,
            "   - Transitive dependencies: {}"
        );
        assert_eq!(
            msgs.progress_vuln_none,
            "✅ Vulnerability check complete: No known vulnerabilities found"
        );
        assert_eq!(
            msgs.progress_license_violations_found,
            "⚠️  License compliance: {} violation(s) found"
        );
        assert_eq!(
            msgs.progress_license_no_violations,
            "✅ License compliance: No violations found"
        );
        assert_eq!(
            msgs.progress_license_unknown_packages,
            "⚠️  License compliance: {} package(s) with unknown license"
        );
    }

    #[test]
    fn test_messages_use_case_progress_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            msgs.progress_loading_lockfile,
            "📖 uv.lockファイルを読み込み中: {}"
        );
        assert_eq!(msgs.progress_detected_packages, "✅ {}個のパッケージを検出");
        assert_eq!(msgs.progress_parsing_deps, "📊 依存関係情報を解析中...");
        assert_eq!(msgs.progress_direct_deps, "   - 直接依存: {}");
        assert_eq!(msgs.progress_transitive_deps, "   - 間接依存: {}");
        assert_eq!(
            msgs.warn_license_fetch_failed,
            "⚠️  警告: {}のライセンス情報の取得に失敗: {}"
        );
        assert_eq!(
            msgs.progress_license_complete,
            "✅ ライセンス情報取得完了: {}件成功 / {}件中、{}件失敗"
        );
        assert_eq!(
            msgs.progress_vuln_found,
            "✅ 脆弱性チェック完了: {}個のパッケージで{}件の脆弱性を検出"
        );
        assert_eq!(
            msgs.progress_vuln_none,
            "✅ 脆弱性チェック完了: 既知の脆弱性は検出されませんでした"
        );
        assert_eq!(
            msgs.progress_license_violations_found,
            "⚠️  ライセンスコンプライアンス: {}件の違反が見つかりました"
        );
        assert_eq!(
            msgs.progress_license_no_violations,
            "✅ ライセンスコンプライアンス: 違反は見つかりませんでした"
        );
        assert_eq!(
            msgs.progress_license_unknown_packages,
            "⚠️  ライセンスコンプライアンス: ライセンス不明のパッケージが{}件あります"
        );
    }

    #[test]
    fn test_diff_progress_messages_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            msgs.progress_diff_checking_base,
            "🔍 Checking vulnerabilities in base lockfile..."
        );
        assert_eq!(
            msgs.progress_diff_checking_current,
            "🔍 Checking vulnerabilities in current lockfile..."
        );
    }

    #[test]
    fn test_diff_progress_messages_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            msgs.progress_diff_checking_base,
            "🔍 ベースロックファイルの脆弱性をチェック中..."
        );
        assert_eq!(
            msgs.progress_diff_checking_current,
            "🔍 現在のロックファイルの脆弱性をチェック中..."
        );
    }

    #[test]
    fn test_messages_config_loading_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            Messages::format(msgs.info_config_loaded_from, &["/tmp/uv-sbom.config.yml"]),
            "📄 Loaded config from: /tmp/uv-sbom.config.yml"
        );
        assert_eq!(
            msgs.info_config_auto_discovered,
            "📄 Auto-discovered config file in project directory."
        );
    }

    #[test]
    fn test_messages_config_loading_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            Messages::format(msgs.info_config_loaded_from, &["/tmp/uv-sbom.config.yml"]),
            "📄 設定ファイルを読み込みました: /tmp/uv-sbom.config.yml"
        );
        assert_eq!(
            msgs.info_config_auto_discovered,
            "📄 プロジェクトディレクトリ内の設定ファイルを自動検出しました。"
        );
    }

    #[test]
    fn test_messages_unknown_config_field_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            Messages::format(msgs.warn_unknown_config_field, &["typo_field"]),
            "⚠️  Warning: Unknown config field 'typo_field' will be ignored."
        );
    }

    #[test]
    fn test_messages_unknown_config_field_ja_format() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            Messages::format(msgs.warn_unknown_config_field, &["typo_field"]),
            "⚠️  警告: 不明な設定項目 'typo_field' は無視されます。"
        );
    }

    #[test]
    fn test_messages_startup_warning_details_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            msgs.warn_check_license_json_detail,
            "   License compliance data is not included in JSON output."
        );
        assert_eq!(
            msgs.warn_check_license_json_hint,
            "   Use --format markdown to see license compliance report."
        );
        assert_eq!(
            msgs.warn_verify_links_json_detail,
            "   PyPI link verification only applies to Markdown output."
        );
        assert_eq!(
            msgs.warn_verify_links_json_hint,
            "   Use --format markdown to use link verification."
        );
    }

    #[test]
    fn test_messages_startup_warning_details_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            msgs.warn_check_license_json_detail,
            "   ライセンスコンプライアンス情報はJSON出力には含まれません。"
        );
        assert_eq!(
            msgs.warn_check_license_json_hint,
            "   ライセンスコンプライアンスレポートを表示するには --format markdown を使用してください。"
        );
        assert_eq!(
            msgs.warn_verify_links_json_detail,
            "   PyPIリンク検証はMarkdown出力にのみ適用されます。"
        );
        assert_eq!(
            msgs.warn_verify_links_json_hint,
            "   リンク検証を使用するには --format markdown を使用してください。"
        );
    }

    #[test]
    fn test_messages_error_reporting_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(msgs.error_header, "❌ An error occurred:");
        assert_eq!(
            Messages::format(msgs.error_caused_by, &["network timeout"]),
            "Caused by: network timeout"
        );
        assert_eq!(
            Messages::format(
                msgs.info_config_template_created,
                &["uv-sbom.config.yml", "/tmp/project"]
            ),
            "Created uv-sbom.config.yml in /tmp/project"
        );
        assert_eq!(
            Messages::format(msgs.error_init_failed, &["permission denied"]),
            "Error: permission denied"
        );
        assert_eq!(
            msgs.error_no_workspace_members,
            "No workspace members found. Is this a uv workspace?"
        );
    }

    #[test]
    fn test_messages_error_reporting_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(msgs.error_header, "❌ エラーが発生しました:");
        assert_eq!(
            Messages::format(msgs.error_caused_by, &["network timeout"]),
            "原因: network timeout"
        );
        assert_eq!(
            Messages::format(
                msgs.info_config_template_created,
                &["uv-sbom.config.yml", "/tmp/project"]
            ),
            "uv-sbom.config.yml を /tmp/project に作成しました"
        );
        assert_eq!(
            Messages::format(msgs.error_init_failed, &["permission denied"]),
            "エラー: permission denied"
        );
        assert_eq!(
            msgs.error_no_workspace_members,
            "ワークスペースメンバーが見つかりません。これは uv ワークスペースですか？"
        );
    }

    #[test]
    fn test_error_all_packages_excluded_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            Messages::format(msgs.error_all_packages_excluded, &["3"]),
            "All 3 package(s) were excluded by the provided filters. The SBOM would be empty. Please adjust your exclusion patterns."
        );
    }

    #[test]
    fn test_error_all_packages_excluded_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            Messages::format(msgs.error_all_packages_excluded, &["3"]),
            "指定されたフィルターにより 3 個のパッケージがすべて除外されました。SBOM が空になります。除外パターンを見直してください。"
        );
    }

    #[test]
    fn test_error_pyproject_not_found_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            msgs.error_pyproject_not_found,
            "pyproject.toml not found in project directory"
        );
    }

    #[test]
    fn test_error_pyproject_not_found_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            msgs.error_pyproject_not_found,
            "プロジェクトディレクトリに pyproject.toml が見つかりません。"
        );
    }

    #[test]
    fn test_messages_config_errors_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            Messages::format(
                msgs.error_config_already_exists,
                &["uv-sbom.config.yml", "/tmp/project"]
            ),
            "uv-sbom.config.yml already exists in /tmp/project. Use a different directory or remove the existing file."
        );
        assert_eq!(
            Messages::format(msgs.error_config_template_write_failed, &["/tmp/x.yml"]),
            "Failed to write config template to: /tmp/x.yml"
        );
        assert_eq!(
            Messages::format(msgs.error_config_read_failed, &["/tmp/x.yml"]),
            "Failed to read config file: /tmp/x.yml\n\n💡 Hint: Check that the file exists and is readable."
        );
        assert_eq!(
            Messages::format(msgs.error_config_parse_failed, &["/tmp/x.yml"]),
            "Failed to parse config file: /tmp/x.yml\n\n💡 Hint: Ensure the file contains valid YAML syntax."
        );
        assert_eq!(
            Messages::format(msgs.error_config_empty_ignore_cve_id, &["2"]),
            "Invalid config: ignore_cves[2].id must not be empty.\n\n💡 Hint: Each ignore_cves entry must have a non-empty 'id' field (e.g., \"CVE-2024-1234\")."
        );
        assert_eq!(
            Messages::format(msgs.error_config_invalid_unknown_license_handling, &["maybe"]),
            "Invalid config: license_policy.unknown must be one of: warn, deny, allow. Got: \"maybe\""
        );
    }

    #[test]
    fn test_messages_config_errors_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            Messages::format(
                msgs.error_config_already_exists,
                &["uv-sbom.config.yml", "/tmp/project"]
            ),
            "uv-sbom.config.yml は /tmp/project に既に存在します。別のディレクトリを指定するか、既存のファイルを削除してください。"
        );
        assert_eq!(
            Messages::format(msgs.error_config_template_write_failed, &["/tmp/x.yml"]),
            "設定テンプレートの書き込みに失敗しました: /tmp/x.yml"
        );
        assert_eq!(
            Messages::format(msgs.error_config_read_failed, &["/tmp/x.yml"]),
            "設定ファイルの読み込みに失敗しました: /tmp/x.yml\n\n💡 ヒント: ファイルが存在し、読み取り可能であることを確認してください。"
        );
        assert_eq!(
            Messages::format(msgs.error_config_parse_failed, &["/tmp/x.yml"]),
            "設定ファイルの解析に失敗しました: /tmp/x.yml\n\n💡 ヒント: ファイルが有効な YAML 構文であることを確認してください。"
        );
        assert_eq!(
            Messages::format(msgs.error_config_empty_ignore_cve_id, &["2"]),
            "設定が不正です: ignore_cves[2].id は空にできません。\n\n💡 ヒント: ignore_cves の各エントリには空でない 'id' フィールドが必要です（例: \"CVE-2024-1234\"）。"
        );
        assert_eq!(
            Messages::format(msgs.error_config_invalid_unknown_license_handling, &["maybe"]),
            "設定が不正です: license_policy.unknown は warn, deny, allow のいずれかである必要があります。指定値: \"maybe\""
        );
    }

    #[test]
    fn test_messages_config_errors_placeholder_parity() {
        // EN and JA templates must have the same number of `{}` placeholders,
        // in the same semantic order, since Messages::format fills them
        // positionally.
        let pairs = [
            (
                EN_MESSAGES.error_config_already_exists,
                JA_MESSAGES.error_config_already_exists,
                2,
            ),
            (
                EN_MESSAGES.error_config_template_write_failed,
                JA_MESSAGES.error_config_template_write_failed,
                1,
            ),
            (
                EN_MESSAGES.error_config_read_failed,
                JA_MESSAGES.error_config_read_failed,
                1,
            ),
            (
                EN_MESSAGES.error_config_parse_failed,
                JA_MESSAGES.error_config_parse_failed,
                1,
            ),
            (
                EN_MESSAGES.error_config_empty_ignore_cve_id,
                JA_MESSAGES.error_config_empty_ignore_cve_id,
                1,
            ),
            (
                EN_MESSAGES.error_config_invalid_unknown_license_handling,
                JA_MESSAGES.error_config_invalid_unknown_license_handling,
                1,
            ),
        ];
        for (en, ja, expected_count) in pairs {
            let en_count = en.matches("{}").count();
            let ja_count = ja.matches("{}").count();
            assert_eq!(
                en_count, ja_count,
                "EN/JA placeholder count mismatch for {en:?}"
            );
            assert_eq!(
                en_count, expected_count,
                "unexpected placeholder count for {en:?}"
            );
        }
    }

    /// Expands to `[(field_name, en_value, ja_value); N]` for every listed `Messages` field.
    ///
    /// When adding a field to `Messages`, add its name here too. The exhaustive
    /// destructure (deliberately no `..`) makes an unlisted field a compile error.
    macro_rules! all_message_fields {
        ($($f:ident),+ $(,)?) => {{
            let Messages { $($f: _),+ } = &EN_MESSAGES;
            [$((stringify!($f), EN_MESSAGES.$f, JA_MESSAGES.$f)),+]
        }};
    }

    /// Fields whose JA template intentionally has fewer `{}` placeholders than EN,
    /// as `(field, en_count, ja_count)`. Each is marked in `JA_MESSAGES` with
    /// `// JA: only first {} (count) is used; second {} (unit word) is ignored`
    /// (Japanese has no singular/plural distinction). Counts are pinned exactly so a
    /// fixed or drifted entry fails instead of going stale.
    const PLACEHOLDER_MISMATCH_ALLOWLIST: &[(&str, usize, usize)] = &[
        ("progress_analyzing_upgrade_paths", 2, 1),
        ("warn_unknown_license_packages", 2, 1),
    ];

    #[test]
    fn test_all_messages_placeholder_parity() {
        // Messages::format fills `{}` positionally, so an EN/JA count mismatch
        // silently leaves a literal `{}` or drops an argument at runtime.
        // Only counts are checked; argument order is covered by per-field tests.
        let fields = all_message_fields!(
            section_sbom_title,
            section_component_inventory,
            section_direct_deps,
            section_transitive_deps,
            section_vuln_report,
            section_license_compliance,
            section_resolution_guide,
            section_dependency_chains,
            col_package,
            col_version,
            col_license,
            col_description,
            col_current_version,
            col_fixed_version,
            col_severity,
            col_vuln_id,
            col_cvss,
            progress_generating_json,
            progress_generating_markdown,
            progress_verifying_links,
            progress_fetching_license,
            progress_fetching_vulns,
            progress_diff_checking_base,
            progress_diff_checking_current,
            info_config_loaded_from,
            info_config_auto_discovered,
            warn_unknown_config_field,
            error_header,
            error_caused_by,
            info_config_template_created,
            error_init_failed,
            error_no_workspace_members,
            error_incident_advisory_not_found,
            error_incident_invalid_target,
            error_incident_target_hint,
            error_incident_spec_empty,
            error_incident_spec_missing_name,
            error_incident_spec_invalid_name,
            error_incident_spec_missing_specifier,
            error_incident_spec_invalid_specifiers,
            error_incident_spec_unsupported_operator,
            error_incident_spec_multiple_lower,
            error_incident_spec_multiple_upper,
            error_incident_spec_empty_range,
            error_all_packages_excluded,
            error_pyproject_not_found,
            error_config_already_exists,
            error_config_template_write_failed,
            error_config_read_failed,
            error_config_parse_failed,
            error_config_empty_ignore_cve_id,
            error_config_invalid_unknown_license_handling,
            progress_loading_lockfile,
            progress_detected_packages,
            progress_parsing_deps,
            progress_direct_deps,
            progress_transitive_deps,
            warn_license_fetch_failed,
            progress_license_complete,
            progress_vuln_found,
            progress_vuln_none,
            progress_license_violations_found,
            progress_license_no_violations,
            progress_license_unknown_packages,
            progress_analyzing_upgrade_paths,
            progress_upgrade_resolves,
            progress_upgrade_unresolvable,
            progress_upgrade_simulation_failed,
            label_dependency_singular,
            label_dependency_plural,
            warn_check_license_no_effect,
            warn_check_license_json_detail,
            warn_check_license_json_hint,
            warn_verify_links_no_effect,
            warn_verify_links_json_detail,
            warn_verify_links_json_hint,
            warn_abandoned_fetch_failed,
            warn_vuln_detail_fetch_failed,
            warn_epss_fetch_failed,
            warn_kev_fetch_failed,
            warn_ignored_cve_with_reason,
            warn_ignored_cve_no_reason,
            warn_dependency_chain_truncated,
            warn_exclude_pattern_unmatched,
            warn_suggest_fix_requires_uv,
            warn_suggest_fix_requires_pyproject,
            progress_baseline_loaded,
            warn_baseline_not_found,
            progress_baseline_suppressed,
            progress_baseline_updated,
            footnote_baseline_suppressed,
            progress_fetching_abandoned,
            progress_abandoned_found,
            progress_abandoned_none,
            progress_excluded_groups,
            progress_packages_excluded,
            progress_fetching_python_compat,
            progress_python_compat_found,
            progress_python_compat_none,
            desc_sbom_report,
            desc_direct_deps,
            desc_transitive_deps,
            desc_transitive_vuln_table,
            label_no_direct_deps,
            label_no_transitive_deps,
            label_no_license_violations,
            label_osv_attribution,
            label_epss_kev_attribution,
            warn_no_vuln_above_threshold,
            warn_vuln_found,
            info_vuln_found,
            label_vulnerability_singular,
            label_vulnerability_plural,
            label_package_singular,
            label_package_plural,
            label_license_violation_singular,
            label_license_violation_plural,
            section_violations,
            section_warnings,
            col_reason,
            col_matched_pattern,
            warn_unknown_license_packages,
            col_vulnerable_package,
            col_current,
            col_introduced_by,
            col_recommended_action,
            action_upgrade,
            action_cannot_resolve,
            action_could_not_analyze,
            deps_for_header,
            summary_vuln_found,
            output_complete,
            workspace_mode_members_found,
            workspace_processing_member,
            workspace_summary_header,
            workspace_col_member,
            workspace_col_output_file,
            workspace_aggregate_header,
            workspace_aggregate_total_cves,
            workspace_aggregate_license_violations,
            workspace_aggregate_abandoned,
            workspace_aggregate_non_pypi,
            workspace_aggregate_python_incompatible,
            workspace_aggregate_none,
            section_summary,
            col_item,
            col_count,
            col_status,
            label_direct_deps,
            label_transitive_deps,
            label_group_filter,
            label_vuln_critical,
            label_vuln_high,
            label_vuln_medium,
            label_vuln_low,
            label_license_violations,
            label_vuln_check_skipped,
            overall_action_required,
            overall_attention_recommended,
            overall_no_issues,
            section_abandoned_packages,
            desc_abandoned_packages,
            label_abandoned_packages,
            label_abandoned_check_skipped,
            label_no_abandoned_packages,
            col_last_release,
            col_days_inactive,
            col_type,
            section_non_pypi_packages,
            summary_non_pypi_packages,
            note_non_pypi_packages,
            col_source_type,
            col_source,
            section_python_compat_issues,
            section_python_compat_ok,
            summary_python_compat_issues,
            label_python_compat_all_clear,
            col_requires_python,
            section_explain,
            summary_explain_paths,
            summary_explain_direct,
            summary_explain_also_transitive,
            summary_explain_not_found,
            col_exploited_kev,
            col_epss,
            progress_fetching_exploitability,
            section_dependency_tree,
            label_dependency_tree_truncated,
            note_dependency_tree_truncated,
            label_dependency_tree_empty,
            diff_section_title,
            diff_compared_line,
            diff_section_summary,
            diff_col_metric,
            diff_col_count,
            diff_label_added,
            diff_label_removed,
            diff_label_updated,
            diff_label_unchanged,
            diff_section_changes,
            diff_col_change,
            diff_col_old_version,
            diff_col_new_version,
            diff_col_vulnerabilities,
            diff_vuln_none,
            diff_section_cve_delta,
            diff_new_vulns_header,
            diff_resolved_vulns_header,
            diff_no_new_vulns,
            diff_no_resolved_vulns,
            incident_title,
            incident_resolved_from,
            incident_label_aliases,
            incident_label_severity,
            incident_label_summary,
            incident_label_overall,
            incident_section_impact,
            incident_section_patch_status,
            incident_section_next_action,
            incident_verdict_not_affected,
            incident_verdict_fix_released,
            incident_verdict_fix_unreleased,
            incident_verdict_no_fix,
            incident_dependency_direct,
            incident_dependency_transitive,
            incident_paths_label,
            incident_no_path,
            incident_no_pypi_package,
            incident_packages_not_in_project,
            incident_status_fixed_in,
            incident_status_released,
            incident_status_yanked,
            incident_status_not_found,
            incident_status_unknown,
            incident_status_no_fixed_version,
            incident_status_not_applicable,
            incident_action_verified,
            incident_action_not_verified,
            incident_guidance_resolution_blocked,
            incident_guidance_no_released_fix,
            incident_guidance_simulation_error,
            incident_status_not_from_pypi,
            incident_guidance_release_lookup_failed,
            incident_guidance_not_from_pypi,
            warn_incident_release_lookup_failed,
            incident_member_heading,
            incident_label_member_verdict,
            incident_packages_not_in_member,
            incident_status_not_applicable_workspace,
            incident_workspace_aggregate,
            incident_title_manual,
            incident_manual_notice,
            incident_status_no_fixed_version_manual,
        );
        for (name, en, ja) in fields {
            let (en_count, ja_count) = (en.matches("{}").count(), ja.matches("{}").count());
            match PLACEHOLDER_MISMATCH_ALLOWLIST
                .iter()
                .find(|(allowed, _, _)| *allowed == name)
            {
                Some(&(_, expected_en, expected_ja)) => assert_eq!(
                    (en_count, ja_count),
                    (expected_en, expected_ja),
                    "allowlisted field `{name}` changed placeholder counts; update or remove its allowlist entry"
                ),
                None => assert_eq!(
                    en_count, ja_count,
                    "placeholder count mismatch in `{name}`: EN={en_count} JA={ja_count}\n EN: {en:?}\n JA: {ja:?}"
                ),
            }
        }
        for (allowed, _, _) in PLACEHOLDER_MISMATCH_ALLOWLIST {
            assert!(
                fields.iter().any(|(name, _, _)| name == allowed),
                "stale allowlist entry `{allowed}`: no such Messages field"
            );
        }
    }

    #[test]
    fn test_messages_format_no_placeholders() {
        assert_eq!(
            Messages::format("No placeholders here", &[]),
            "No placeholders here"
        );
    }

    #[test]
    fn test_messages_format_single_placeholder() {
        assert_eq!(
            Messages::format("Found {} packages", &["5"]),
            "Found 5 packages"
        );
    }

    #[test]
    fn test_messages_format_multiple_placeholders() {
        assert_eq!(
            Messages::format("{} succeeded out of {}, {} failed", &["8", "10", "2"]),
            "8 succeeded out of 10, 2 failed"
        );
    }

    #[test]
    fn test_messages_format_extra_args_ignored() {
        assert_eq!(
            Messages::format("Hello {}", &["world", "extra"]),
            "Hello world"
        );
    }

    #[test]
    fn test_messages_format_fewer_args_than_placeholders() {
        assert_eq!(Messages::format("{} of {} done", &["3"]), "3 of {} done");
    }

    #[test]
    fn test_section_dependency_chains_i18n() {
        assert_eq!(
            Messages::for_locale(Locale::En).section_dependency_chains,
            "### Dependency Chains"
        );
        assert_eq!(
            Messages::for_locale(Locale::Ja).section_dependency_chains,
            "### 依存チェーン"
        );
    }

    #[test]
    fn test_messages_markdown_new_fields_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            msgs.desc_sbom_report,
            "A comprehensive list of all software components and libraries included in this project."
        );
        assert_eq!(msgs.label_no_direct_deps, "*No direct dependencies*");
        assert_eq!(
            msgs.label_no_transitive_deps,
            "*No transitive dependencies*"
        );
        assert_eq!(
            msgs.warn_no_vuln_above_threshold,
            "### ⚠️Warning No vulnerabilities found above threshold."
        );
        assert_eq!(msgs.warn_vuln_found, "### ⚠️Warning Found {} {} in {} {}.");
        assert_eq!(msgs.info_vuln_found, "### ℹ️Info Found {} {} in {} {}.");
        assert_eq!(msgs.label_vulnerability_singular, "vulnerability");
        assert_eq!(msgs.label_vulnerability_plural, "vulnerabilities");
        assert_eq!(msgs.label_package_singular, "package");
        assert_eq!(msgs.label_package_plural, "packages");
        assert_eq!(
            msgs.label_no_license_violations,
            "**No license violations found.**"
        );
        assert_eq!(msgs.section_violations, "### Violations");
        assert_eq!(msgs.col_reason, "Reason");
        assert_eq!(msgs.col_matched_pattern, "Matched Pattern");
        assert_eq!(msgs.section_warnings, "### Warnings");
        assert_eq!(msgs.col_vulnerable_package, "Vulnerable Package");
        assert_eq!(msgs.col_current, "Current");
        assert_eq!(msgs.col_introduced_by, "Introduced By (Direct Dep)");
        assert_eq!(msgs.col_recommended_action, "Recommended Action");
        assert_eq!(
            msgs.action_upgrade,
            "⬆️ Upgrade {} → {} (resolves {} to {})"
        );
        assert_eq!(msgs.action_cannot_resolve, "⚠️ Cannot resolve: {}");
        assert_eq!(msgs.action_could_not_analyze, "❓ Could not analyze: {}");
    }

    #[test]
    fn test_messages_markdown_new_fields_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            msgs.desc_sbom_report,
            "このプロジェクトに含まれるすべてのソフトウェアコンポーネントとライブラリの一覧です。"
        );
        assert_eq!(msgs.label_no_direct_deps, "*直接依存パッケージなし*");
        assert_eq!(msgs.label_no_transitive_deps, "*間接依存パッケージなし*");
        assert_eq!(
            msgs.warn_no_vuln_above_threshold,
            "### ⚠️警告 閾値を超える脆弱性は見つかりませんでした。"
        );
        assert_eq!(msgs.label_vulnerability_singular, "件の脆弱性");
        assert_eq!(msgs.label_vulnerability_plural, "件の脆弱性");
        assert_eq!(msgs.label_package_singular, "個のパッケージ");
        assert_eq!(msgs.label_package_plural, "個のパッケージ");
        assert_eq!(
            msgs.label_no_license_violations,
            "**ライセンス違反は見つかりませんでした。**"
        );
        assert_eq!(msgs.section_violations, "### 違反");
        assert_eq!(msgs.col_reason, "理由");
        assert_eq!(msgs.col_matched_pattern, "マッチしたパターン");
        assert_eq!(msgs.section_warnings, "### 警告");
        assert_eq!(msgs.col_vulnerable_package, "脆弱性のあるパッケージ");
        assert_eq!(msgs.col_current, "現在");
        assert_eq!(msgs.col_introduced_by, "導入元（直接依存）");
        assert_eq!(msgs.col_recommended_action, "推奨アクション");
        assert_eq!(msgs.action_cannot_resolve, "⚠️ 解決不可: {}");
        assert_eq!(msgs.action_could_not_analyze, "❓ 分析不可: {}");
    }

    #[test]
    fn test_workspace_messages_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(msgs.output_complete, "✅ Output complete: {}");
        assert_eq!(
            msgs.workspace_mode_members_found,
            "Workspace mode: {} members found"
        );
        assert_eq!(msgs.workspace_processing_member, "  Processing: {}");
        assert_eq!(msgs.workspace_summary_header, "📦 Workspace SBOM Summary");
        assert_eq!(msgs.workspace_col_member, "Member");
        assert_eq!(msgs.workspace_col_output_file, "Output File");
        assert_eq!(
            msgs.workspace_aggregate_header,
            "📊 Workspace Aggregate Summary"
        );
        assert_eq!(
            msgs.workspace_aggregate_total_cves,
            "Total actionable CVEs: {}"
        );
        assert_eq!(
            msgs.workspace_aggregate_license_violations,
            "Members with license policy violations: {}"
        );
        assert_eq!(
            msgs.workspace_aggregate_abandoned,
            "Members with abandoned packages: {}"
        );
        assert_eq!(
            msgs.workspace_aggregate_non_pypi,
            "Members with non-PyPI packages: {}"
        );
        assert_eq!(
            msgs.workspace_aggregate_python_incompatible,
            "Members with Python-incompatible packages: {}"
        );
        assert_eq!(msgs.workspace_aggregate_none, "none");
    }

    #[test]
    fn test_workspace_messages_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(msgs.output_complete, "✅ 出力完了: {}");
        assert_eq!(
            msgs.workspace_mode_members_found,
            "ワークスペースモード: {} メンバーを検出"
        );
        assert_eq!(msgs.workspace_processing_member, "  処理中: {}");
        assert_eq!(
            msgs.workspace_summary_header,
            "📦 ワークスペース SBOM サマリー"
        );
        assert_eq!(msgs.workspace_col_member, "メンバー");
        assert_eq!(msgs.workspace_col_output_file, "出力ファイル");
        assert_eq!(
            msgs.workspace_aggregate_header,
            "📊 ワークスペース集計サマリー"
        );
        assert_eq!(
            msgs.workspace_aggregate_total_cves,
            "対応が必要なCVE合計: {}"
        );
        assert_eq!(
            msgs.workspace_aggregate_license_violations,
            "ライセンスポリシー違反があるメンバー: {}"
        );
        assert_eq!(
            msgs.workspace_aggregate_abandoned,
            "メンテナンス停止パッケージがあるメンバー: {}"
        );
        assert_eq!(
            msgs.workspace_aggregate_non_pypi,
            "非PyPIパッケージがあるメンバー: {}"
        );
        assert_eq!(
            msgs.workspace_aggregate_python_incompatible,
            "Python非互換パッケージがあるメンバー: {}"
        );
        assert_eq!(msgs.workspace_aggregate_none, "なし");
    }

    #[test]
    fn test_warn_vuln_found_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(
            msgs.warn_vuln_found,
            &[
                "2",
                msgs.label_vulnerability_plural,
                "1",
                msgs.label_package_singular,
            ],
        );
        assert_eq!(
            result,
            "### ⚠️Warning Found 2 vulnerabilities in 1 package."
        );
    }

    #[test]
    fn test_messages_upgrade_advisor_progress_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            msgs.progress_analyzing_upgrade_paths,
            "🔍 Analyzing upgrade paths for {} direct {}..."
        );
        assert_eq!(
            msgs.progress_upgrade_resolves,
            "  ✓ Upgrade {} → {} resolves {} to {} ({})"
        );
        assert_eq!(
            msgs.progress_upgrade_unresolvable,
            "  ✗ Cannot resolve via {}: {} ({})"
        );
        assert_eq!(
            msgs.progress_upgrade_simulation_failed,
            "  ❓ Simulation failed for {}: {}"
        );
        assert_eq!(msgs.label_dependency_singular, "dependency");
        assert_eq!(msgs.label_dependency_plural, "dependencies");
    }

    #[test]
    fn test_messages_upgrade_advisor_progress_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            msgs.progress_analyzing_upgrade_paths,
            "🔍 {}個の直接依存パッケージのアップグレード経路を解析中..."
        );
        assert_eq!(
            msgs.progress_upgrade_resolves,
            "  ✓ {}を{}にアップグレードすると{}が{}に解決されます ({})"
        );
        assert_eq!(
            msgs.progress_upgrade_unresolvable,
            "  ✗ {}経由で解決できません: {} ({})"
        );
        assert_eq!(
            msgs.progress_upgrade_simulation_failed,
            "  ❓ {}のシミュレーションに失敗しました: {}"
        );
    }

    #[test]
    fn test_progress_analyzing_upgrade_paths_en_singular() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(
            msgs.progress_analyzing_upgrade_paths,
            &["1", msgs.label_dependency_singular],
        );
        assert_eq!(
            result,
            "🔍 Analyzing upgrade paths for 1 direct dependency..."
        );
    }

    #[test]
    fn test_progress_analyzing_upgrade_paths_en_plural() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(
            msgs.progress_analyzing_upgrade_paths,
            &["3", msgs.label_dependency_plural],
        );
        assert_eq!(
            result,
            "🔍 Analyzing upgrade paths for 3 direct dependencies..."
        );
    }

    #[test]
    fn test_progress_analyzing_upgrade_paths_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        let result = Messages::format(
            msgs.progress_analyzing_upgrade_paths,
            &["3", msgs.label_dependency_plural],
        );
        assert_eq!(
            result,
            "🔍 3個の直接依存パッケージのアップグレード経路を解析中..."
        );
    }

    #[test]
    fn test_progress_upgrade_resolves_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(
            msgs.progress_upgrade_resolves,
            &["requests", "2.32.3", "urllib3", "2.2.1", "GHSA-xxxx"],
        );
        assert_eq!(
            result,
            "  ✓ Upgrade requests → 2.32.3 resolves urllib3 to 2.2.1 (GHSA-xxxx)"
        );
    }

    #[test]
    fn test_progress_upgrade_unresolvable_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(
            msgs.progress_upgrade_unresolvable,
            &["pkg-a", "no compatible version", "GHSA-yyyy"],
        );
        assert_eq!(
            result,
            "  ✗ Cannot resolve via pkg-a: no compatible version (GHSA-yyyy)"
        );
    }

    #[test]
    fn test_progress_upgrade_simulation_failed_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(
            msgs.progress_upgrade_simulation_failed,
            &["pkg-b", "uv lock failed"],
        );
        assert_eq!(result, "  ❓ Simulation failed for pkg-b: uv lock failed");
    }

    #[test]
    fn test_warn_vuln_found_ja_format() {
        let msgs = Messages::for_locale(Locale::Ja);
        let result = Messages::format(
            msgs.warn_vuln_found,
            &[
                "2",
                msgs.label_vulnerability_plural,
                "1",
                msgs.label_package_singular,
            ],
        );
        assert_eq!(
            result,
            "### ⚠️警告 2件の脆弱性が1個のパッケージで見つかりました。"
        );
    }

    #[test]
    fn test_warn_ignored_cve_with_reason_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(
            msgs.warn_ignored_cve_with_reason,
            &["CVE-2024-001", "requests", "False positive"],
        );
        assert_eq!(
            result,
            "⚠ Ignored CVE-2024-001 for package requests (reason: False positive)"
        );
    }

    #[test]
    fn test_warn_ignored_cve_no_reason_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(
            msgs.warn_ignored_cve_no_reason,
            &["CVE-2024-001", "requests"],
        );
        assert_eq!(
            result,
            "⚠ Ignored CVE-2024-001 for package requests (no reason provided)"
        );
    }

    #[test]
    fn test_warn_vuln_detail_fetch_failed_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(
            msgs.warn_vuln_detail_fetch_failed,
            &["CVE-2024-001", "request timed out"],
        );
        assert_eq!(
            result,
            "⚠️  Warning: Failed to fetch details for CVE-2024-001: request timed out"
        );
    }

    #[test]
    fn test_warn_vuln_detail_fetch_failed_ja_format() {
        let msgs = Messages::for_locale(Locale::Ja);
        let result = Messages::format(
            msgs.warn_vuln_detail_fetch_failed,
            &["CVE-2024-001", "リクエストがタイムアウトしました"],
        );
        assert_eq!(
            result,
            "⚠️  警告: CVE-2024-001の詳細情報の取得に失敗: リクエストがタイムアウトしました"
        );
    }

    #[test]
    fn test_warn_epss_fetch_failed_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(msgs.warn_epss_fetch_failed, &["3", "connection refused"]);
        assert_eq!(
            result,
            "Warning: EPSS fetch failed for batch 3: connection refused"
        );
    }

    #[test]
    fn test_warn_epss_fetch_failed_ja_format() {
        let msgs = Messages::for_locale(Locale::Ja);
        let result = Messages::format(msgs.warn_epss_fetch_failed, &["3", "接続が拒否されました"]);
        assert_eq!(
            result,
            "警告: バッチ3のEPSSデータ取得に失敗: 接続が拒否されました"
        );
    }

    #[test]
    fn test_warn_epss_fetch_failed_placeholder_parity() {
        let en_count = EN_MESSAGES.warn_epss_fetch_failed.matches("{}").count();
        let ja_count = JA_MESSAGES.warn_epss_fetch_failed.matches("{}").count();
        assert_eq!(en_count, ja_count);
        assert_eq!(en_count, 2);
    }

    #[test]
    fn test_warn_kev_fetch_failed_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(msgs.warn_kev_fetch_failed, &["connection refused"]);
        assert_eq!(
            result,
            "Warning: KEV catalog fetch failed: connection refused"
        );
    }

    #[test]
    fn test_warn_kev_fetch_failed_ja_format() {
        let msgs = Messages::for_locale(Locale::Ja);
        let result = Messages::format(msgs.warn_kev_fetch_failed, &["接続が拒否されました"]);
        assert_eq!(
            result,
            "警告: KEVカタログの取得に失敗: 接続が拒否されました"
        );
    }

    #[test]
    fn test_warn_kev_fetch_failed_placeholder_parity() {
        let en_count = EN_MESSAGES.warn_kev_fetch_failed.matches("{}").count();
        let ja_count = JA_MESSAGES.warn_kev_fetch_failed.matches("{}").count();
        assert_eq!(en_count, ja_count);
        assert_eq!(en_count, 1);
    }

    #[test]
    fn test_warn_ignored_cve_with_reason_ja_format() {
        let msgs = Messages::for_locale(Locale::Ja);
        let result = Messages::format(
            msgs.warn_ignored_cve_with_reason,
            &["CVE-2024-001", "requests", "誤検知"],
        );
        assert_eq!(
            result,
            "⚠ CVE-2024-001 をパッケージ requests で無視しました (理由: 誤検知)"
        );
    }

    #[test]
    fn test_warn_ignored_cve_no_reason_ja_format() {
        let msgs = Messages::for_locale(Locale::Ja);
        let result = Messages::format(
            msgs.warn_ignored_cve_no_reason,
            &["CVE-2024-001", "requests"],
        );
        assert_eq!(
            result,
            "⚠ CVE-2024-001 をパッケージ requests で無視しました (理由の指定なし)"
        );
    }

    #[test]
    fn test_warn_dependency_chain_truncated_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(
            msgs.warn_dependency_chain_truncated,
            &["100", "some-package"],
        );
        assert_eq!(
            result,
            "⚠️  Warning: Maximum recursion depth (100) reached for package 'some-package'. Dependency chain may be truncated."
        );
    }

    #[test]
    fn test_warn_dependency_chain_truncated_ja_format() {
        let msgs = Messages::for_locale(Locale::Ja);
        let result = Messages::format(
            msgs.warn_dependency_chain_truncated,
            &["100", "some-package"],
        );
        assert_eq!(
            result,
            "⚠️  警告: 最大再帰深度 (100) に達しました（パッケージ: 'some-package'）。依存関係チェーンが切り詰められる可能性があります。"
        );
    }

    #[test]
    fn test_warn_dependency_chain_truncated_placeholder_parity() {
        // EN and JA templates must have the same number of `{}` placeholders, in the
        // same semantic order, since Messages::format fills them positionally.
        let en_count = EN_MESSAGES
            .warn_dependency_chain_truncated
            .matches("{}")
            .count();
        let ja_count = JA_MESSAGES
            .warn_dependency_chain_truncated
            .matches("{}")
            .count();
        assert_eq!(en_count, ja_count);
        assert_eq!(en_count, 2);
    }

    #[test]
    fn test_warn_exclude_pattern_unmatched_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(msgs.warn_exclude_pattern_unmatched, &["foo-*"]);
        assert_eq!(
            result,
            "⚠️  Warning: Exclude pattern 'foo-*' did not match any dependencies."
        );
    }

    #[test]
    fn test_warn_exclude_pattern_unmatched_ja_format() {
        let msgs = Messages::for_locale(Locale::Ja);
        let result = Messages::format(msgs.warn_exclude_pattern_unmatched, &["foo-*"]);
        assert_eq!(
            result,
            "⚠️  警告: 除外パターン 'foo-*' はどの依存関係にも一致しませんでした。"
        );
    }

    #[test]
    fn test_warn_exclude_pattern_unmatched_placeholder_parity() {
        let en_count = EN_MESSAGES
            .warn_exclude_pattern_unmatched
            .matches("{}")
            .count();
        let ja_count = JA_MESSAGES
            .warn_exclude_pattern_unmatched
            .matches("{}")
            .count();
        assert_eq!(en_count, ja_count);
        assert_eq!(en_count, 1);
    }

    #[test]
    fn test_progress_packages_excluded_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(msgs.progress_packages_excluded, &["3"]);
        assert_eq!(result, "🚫 Excluded 3 package(s) based on filters");
    }

    #[test]
    fn test_progress_packages_excluded_ja_format() {
        let msgs = Messages::for_locale(Locale::Ja);
        let result = Messages::format(msgs.progress_packages_excluded, &["3"]);
        assert_eq!(result, "🚫 フィルターにより3個のパッケージを除外");
    }

    #[test]
    fn test_progress_packages_excluded_placeholder_parity() {
        let en_count = EN_MESSAGES.progress_packages_excluded.matches("{}").count();
        let ja_count = JA_MESSAGES.progress_packages_excluded.matches("{}").count();
        assert_eq!(en_count, ja_count);
        assert_eq!(en_count, 1);
    }

    #[test]
    fn test_warn_suggest_fix_requires_uv_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            msgs.warn_suggest_fix_requires_uv,
            "⚠ --suggest-fix requires `uv` CLI. Install it with: curl -LsSf https://astral.sh/uv/install.sh | sh"
        );
    }

    #[test]
    fn test_warn_suggest_fix_requires_uv_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            msgs.warn_suggest_fix_requires_uv,
            "⚠ --suggest-fix には `uv` CLI が必要です。インストール: curl -LsSf https://astral.sh/uv/install.sh | sh"
        );
    }

    #[test]
    fn test_warn_suggest_fix_requires_pyproject_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            msgs.warn_suggest_fix_requires_pyproject,
            "⚠ --suggest-fix requires pyproject.toml in the project directory."
        );
    }

    #[test]
    fn test_warn_suggest_fix_requires_pyproject_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            msgs.warn_suggest_fix_requires_pyproject,
            "⚠ --suggest-fix にはプロジェクトディレクトリに pyproject.toml が必要です。"
        );
    }

    #[test]
    fn test_messages_abandoned_section_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(msgs.section_abandoned_packages, "## Abandoned Packages");
        assert_eq!(msgs.label_abandoned_packages, "Abandoned packages");
        assert_eq!(
            msgs.label_abandoned_check_skipped,
            "_Abandoned package check skipped._"
        );
        assert_eq!(
            msgs.label_no_abandoned_packages,
            "No abandoned packages detected."
        );
        assert_eq!(msgs.col_last_release, "Last Release");
        assert_eq!(msgs.col_days_inactive, "Days Inactive");
        assert_eq!(msgs.col_type, "Type");
    }

    #[test]
    fn test_messages_abandoned_section_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(msgs.section_abandoned_packages, "## 廃止パッケージ");
        assert_eq!(msgs.label_abandoned_packages, "廃止パッケージ");
        assert_eq!(
            msgs.label_abandoned_check_skipped,
            "_廃止パッケージチェックはスキップされました。_"
        );
        assert_eq!(
            msgs.label_no_abandoned_packages,
            "廃止パッケージは検出されませんでした。"
        );
        assert_eq!(msgs.col_last_release, "最終リリース");
        assert_eq!(msgs.col_days_inactive, "非アクティブ日数");
        assert_eq!(msgs.col_type, "種別");
    }

    #[test]
    fn test_messages_non_pypi_section_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            msgs.section_non_pypi_packages,
            "## ⚠️ Non-PyPI Package Sources"
        );
        assert_eq!(
            Messages::format(msgs.summary_non_pypi_packages, &["3", "1", "2"]),
            "3 packages are sourced from outside the official PyPI registry (1 direct, 2 transitive)."
        );
        assert_eq!(
            msgs.note_non_pypi_packages,
            "> Packages from non-PyPI sources may not be subject to PyPI's security policies. Review each package's origin before production deployment."
        );
        assert_eq!(msgs.col_source_type, "Source Type");
        assert_eq!(msgs.col_source, "Source");
    }

    #[test]
    fn test_messages_non_pypi_section_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            msgs.section_non_pypi_packages,
            "## ⚠️ PyPI以外のパッケージソース"
        );
        assert_eq!(
            Messages::format(msgs.summary_non_pypi_packages, &["3", "1", "2"]),
            "3個のパッケージが公式PyPIレジストリ以外から取得されています（直接依存 1件、間接依存 2件）。"
        );
        assert_eq!(
            msgs.note_non_pypi_packages,
            "> PyPI以外のソースから取得されたパッケージは、PyPIのセキュリティポリシーの対象外である可能性があります。本番環境へのデプロイ前に、各パッケージの取得元を確認してください。"
        );
        assert_eq!(msgs.col_source_type, "ソース種別");
        assert_eq!(msgs.col_source, "取得元");
    }

    #[test]
    fn test_messages_python_compat_section_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            Messages::format(msgs.section_python_compat_issues, &["3.13"]),
            "## ⚠️ Python 3.13 Compatibility Issues"
        );
        assert_eq!(
            Messages::format(msgs.section_python_compat_ok, &["3.13"]),
            "## ✅ Python 3.13 Compatibility"
        );
        assert_eq!(
            Messages::format(msgs.summary_python_compat_issues, &["3", "1", "2"]),
            "3 package(s) incompatible with the target Python version (1 direct, 2 transitive)."
        );
        assert_eq!(
            msgs.label_python_compat_all_clear,
            "All packages are compatible with the target Python version."
        );
        assert_eq!(msgs.col_requires_python, "Requires-Python");
    }

    #[test]
    fn test_messages_explain_section_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(msgs.section_explain, "## Dependency Explanation");
        assert_eq!(
            Messages::format(msgs.summary_explain_paths, &["requests", "2"]),
            "**requests** is included via 2 path(s):"
        );
        assert_eq!(
            Messages::format(msgs.summary_explain_direct, &["requests"]),
            "**requests** is a direct dependency of this project."
        );
        assert_eq!(
            Messages::format(msgs.summary_explain_also_transitive, &["2"]),
            "It is also reachable through 2 transitive path(s):"
        );
        assert_eq!(
            Messages::format(msgs.summary_explain_not_found, &["nope"]),
            "Package **nope** was not found in this project's dependencies."
        );
    }

    #[test]
    fn test_messages_explain_section_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(msgs.section_explain, "## 依存関係の説明");
        assert_eq!(
            Messages::format(msgs.summary_explain_paths, &["requests", "2"]),
            "**requests** は 2 個の経路で含まれています:"
        );
        assert_eq!(
            Messages::format(msgs.summary_explain_direct, &["requests"]),
            "**requests** はこのプロジェクトの直接依存パッケージです。"
        );
        assert_eq!(
            Messages::format(msgs.summary_explain_also_transitive, &["2"]),
            "さらに 2 個の間接経路からも到達可能です:"
        );
        assert_eq!(
            Messages::format(msgs.summary_explain_not_found, &["nope"]),
            "パッケージ **nope** はこのプロジェクトの依存関係に見つかりませんでした。"
        );
    }

    #[test]
    fn test_messages_dependency_tree_section_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(msgs.section_dependency_tree, "## Dependency Tree");
        assert_eq!(msgs.label_dependency_tree_truncated, "... (truncated)");
        assert_eq!(
            Messages::format(msgs.note_dependency_tree_truncated, &["2"]),
            "_Tree truncated at depth 2. Use `--dependency-tree-depth <DEPTH>` to show more levels._"
        );
        assert_eq!(
            msgs.label_dependency_tree_empty,
            "_No direct dependencies found._"
        );
    }

    #[test]
    fn test_messages_dependency_tree_section_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(msgs.section_dependency_tree, "## 依存関係ツリー");
        assert_eq!(msgs.label_dependency_tree_truncated, "... (省略)");
        assert_eq!(
            Messages::format(msgs.note_dependency_tree_truncated, &["2"]),
            "_深さ 2 で省略されています。さらに深い階層を表示するには `--dependency-tree-depth <DEPTH>` を使用してください。_"
        );
        assert_eq!(
            msgs.label_dependency_tree_empty,
            "_直接依存パッケージが見つかりません。_"
        );
    }

    #[test]
    fn test_messages_python_compat_section_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            Messages::format(msgs.section_python_compat_issues, &["3.13"]),
            "## ⚠️ Python 3.13 互換性の問題"
        );
        assert_eq!(
            Messages::format(msgs.section_python_compat_ok, &["3.13"]),
            "## ✅ Python 3.13 互換性"
        );
        assert_eq!(
            Messages::format(msgs.summary_python_compat_issues, &["3", "1", "2"]),
            "3個のパッケージがターゲットPythonバージョンと非互換です（直接依存 1件、間接依存 2件）。"
        );
        assert_eq!(
            msgs.label_python_compat_all_clear,
            "すべてのパッケージがターゲットPythonバージョンと互換性があります。"
        );
        assert_eq!(msgs.col_requires_python, "Requires-Python");
    }

    #[test]
    fn test_messages_diff_fields_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(msgs.diff_section_title, "## Dependency Diff Report");
        assert_eq!(
            msgs.diff_compared_line,
            "Compared: `{}` vs current `uv.lock`"
        );
        assert_eq!(msgs.diff_section_summary, "### Summary");
        assert_eq!(msgs.diff_col_metric, "Metric");
        assert_eq!(msgs.diff_col_count, "Count");
        assert_eq!(msgs.diff_label_added, "Added");
        assert_eq!(msgs.diff_label_removed, "Removed");
        assert_eq!(msgs.diff_label_updated, "Updated");
        assert_eq!(msgs.diff_label_unchanged, "Unchanged");
        assert_eq!(msgs.diff_section_changes, "### Changes");
        assert_eq!(msgs.diff_col_change, "Change");
        assert_eq!(msgs.diff_col_old_version, "Old Version");
        assert_eq!(msgs.diff_col_new_version, "New Version");
        assert_eq!(msgs.diff_col_vulnerabilities, "Vulnerabilities");
        assert_eq!(msgs.diff_vuln_none, "None");
        assert_eq!(msgs.diff_section_cve_delta, "## CVE Delta");
        assert_eq!(
            msgs.diff_new_vulns_header,
            "### 🔴 New Vulnerabilities ({})"
        );
        assert_eq!(
            msgs.diff_resolved_vulns_header,
            "### ✅ Resolved Vulnerabilities ({})"
        );
        assert_eq!(msgs.diff_no_new_vulns, "No new vulnerabilities");
        assert_eq!(msgs.diff_no_resolved_vulns, "No resolved vulnerabilities");
    }

    #[test]
    fn test_messages_diff_fields_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(msgs.diff_section_title, "## 依存関係差分レポート");
        assert_eq!(msgs.diff_compared_line, "比較: `{}` と現在の `uv.lock`");
        assert_eq!(msgs.diff_section_summary, "### サマリー");
        assert_eq!(msgs.diff_col_metric, "指標");
        assert_eq!(msgs.diff_col_count, "件数");
        assert_eq!(msgs.diff_label_added, "追加");
        assert_eq!(msgs.diff_label_removed, "削除");
        assert_eq!(msgs.diff_label_updated, "更新");
        assert_eq!(msgs.diff_label_unchanged, "変更なし");
        assert_eq!(msgs.diff_section_changes, "### 変更一覧");
        assert_eq!(msgs.diff_col_change, "変更種別");
        assert_eq!(msgs.diff_col_old_version, "旧バージョン");
        assert_eq!(msgs.diff_col_new_version, "新バージョン");
        assert_eq!(msgs.diff_col_vulnerabilities, "脆弱性");
        assert_eq!(msgs.diff_vuln_none, "なし");
        assert_eq!(msgs.diff_section_cve_delta, "## CVE デルタ");
        assert_eq!(msgs.diff_new_vulns_header, "### 🔴 新たな脆弱性 ({})");
        assert_eq!(
            msgs.diff_resolved_vulns_header,
            "### ✅ 解消された脆弱性 ({})"
        );
        assert_eq!(msgs.diff_no_new_vulns, "新たな脆弱性はありません");
        assert_eq!(msgs.diff_no_resolved_vulns, "解消された脆弱性はありません");
    }
}
