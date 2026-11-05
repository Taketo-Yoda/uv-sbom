//! English (`Locale::En`) message catalog.

use super::Messages;

pub(super) static EN_MESSAGES: Messages = Messages {
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
    warn_format_default_changing: "⚠️  Warning: No output format specified; using JSON. The default output format will change to Markdown in v{}.\n   To keep JSON output, pass --format json. To switch to Markdown now, pass --format markdown.\n   Alternatively, set `format` in your config file (e.g. uv-sbom.config.yml) to silence this warning.",
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

    // Malicious-package (OSV `MAL-`) block in the vulnerability report
    warn_malicious_found: "### 🚨Alert Malicious packages detected.",
    action_remove_malicious: "Remove these packages and rotate any credentials they may have accessed.",

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
    warn_workspace_root_groups_uncovered: "⚠️  Warning: Workspace root dependency group(s) not covered by any member SBOM: {}",
    warn_workspace_root_groups_uncovered_hint: "   Packages reachable only through these groups are not in any SBOM. Add them to --exclude-groups to silence this warning.",

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
    label_vuln_malicious: "Malicious packages",
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
    incident_guidance_direct_pin_blocks_upgrade: "Upgrading **{}** to {} could not be resolved. It is a direct dependency, so its version requirement in `pyproject.toml` likely does not allow {}. Relax the requirement to allow `>={}`, then run `uv lock --upgrade-package {}` and `uv sync`.",
    incident_guidance_no_released_fix: "No released fix is available for **{}** yet.",
    incident_guidance_simulation_error: "Could not verify an upgrade of **{}** to {}: {}",
    incident_status_not_from_pypi: "not hosted on PyPI — release status not checked",
    incident_guidance_release_lookup_failed: "Could not check whether **{}** {} is released: {}. Check PyPI manually before upgrading.",
    incident_guidance_not_from_pypi: "**{}** is not installed from PyPI; check its source for a release containing the fix ({}).",
    warn_incident_release_lookup_failed: "⚠️  Could not check the release status of {} {}: {}",
    progress_incident_fetching_advisory: "🔍 Fetching advisory {}...",
    progress_incident_following_alias: "🔍 Following alias {}...",
    progress_incident_checking_release: "🔍 Checking release status of {} {}...",
    progress_incident_verifying_upgrade: "🔍 Verifying upgrade to {} {} (dry run)...",

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Locale;

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
    fn test_messages_unknown_config_field_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            Messages::format(msgs.warn_unknown_config_field, &["typo_field"]),
            "⚠️  Warning: Unknown config field 'typo_field' will be ignored."
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
    fn test_messages_format_default_changing_en() {
        let msgs = Messages::for_locale(Locale::En);
        let text = Messages::format(msgs.warn_format_default_changing, &["5.0.0"]);
        assert!(text.starts_with("⚠️  Warning:"));
        assert!(text.contains("v5.0.0"));
        assert!(text.contains("--format json"));
        assert!(text.contains("--format markdown"));
        assert!(text.contains("`format`"));
        assert!(!text.contains("{}"));
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
    fn test_error_all_packages_excluded_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            Messages::format(msgs.error_all_packages_excluded, &["3"]),
            "All 3 package(s) were excluded by the provided filters. The SBOM would be empty. Please adjust your exclusion patterns."
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
        assert_eq!(
            msgs.warn_malicious_found,
            "### 🚨Alert Malicious packages detected."
        );
        assert_eq!(
            msgs.action_remove_malicious,
            "Remove these packages and rotate any credentials they may have accessed."
        );
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
        assert_eq!(
            msgs.warn_workspace_root_groups_uncovered,
            "⚠️  Warning: Workspace root dependency group(s) not covered by any member SBOM: {}"
        );
        assert_eq!(
            msgs.warn_workspace_root_groups_uncovered_hint,
            "   Packages reachable only through these groups are not in any SBOM. Add them to --exclude-groups to silence this warning."
        );
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
    fn test_warn_epss_fetch_failed_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(msgs.warn_epss_fetch_failed, &["3", "connection refused"]);
        assert_eq!(
            result,
            "Warning: EPSS fetch failed for batch 3: connection refused"
        );
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
    fn test_warn_exclude_pattern_unmatched_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(msgs.warn_exclude_pattern_unmatched, &["foo-*"]);
        assert_eq!(
            result,
            "⚠️  Warning: Exclude pattern 'foo-*' did not match any dependencies."
        );
    }

    #[test]
    fn test_progress_packages_excluded_en_format() {
        let msgs = Messages::for_locale(Locale::En);
        let result = Messages::format(msgs.progress_packages_excluded, &["3"]);
        assert_eq!(result, "🚫 Excluded 3 package(s) based on filters");
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
    fn test_warn_suggest_fix_requires_pyproject_en() {
        let msgs = Messages::for_locale(Locale::En);
        assert_eq!(
            msgs.warn_suggest_fix_requires_pyproject,
            "⚠ --suggest-fix requires pyproject.toml in the project directory."
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
}
