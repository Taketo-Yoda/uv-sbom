//! Internationalization (i18n) module for multilingual output support.
//!
//! Provides a zero-dependency locale system using static message tables
//! for English and Japanese. No external i18n crates are used.
//!
//! Layout: `mod.rs` holds `Locale`, `Messages`, `Messages::for_locale`,
//! `Messages::format`, and the cross-locale tests; `en.rs` holds `EN_MESSAGES`
//! and `ja.rs` holds `JA_MESSAGES`, each with its single-locale tests.

mod en;
mod ja;

use en::EN_MESSAGES;
use ja::JA_MESSAGES;

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
    pub error_config_invalid_format: &'static str,
    pub error_config_invalid_severity_threshold: &'static str,

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
    pub warn_format_default_changing: &'static str,
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

    // Malicious-package (OSV `MAL-`) block in the vulnerability report
    pub warn_malicious_found: &'static str,
    pub action_remove_malicious: &'static str,

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
    pub warn_workspace_root_groups_uncovered: &'static str,
    pub warn_workspace_root_groups_uncovered_hint: &'static str,

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
    pub label_vuln_malicious: &'static str,
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
    pub incident_guidance_direct_pin_blocks_upgrade: &'static str,
    pub incident_guidance_no_released_fix: &'static str,
    pub incident_guidance_simulation_error: &'static str,
    pub incident_status_not_from_pypi: &'static str,
    pub incident_guidance_release_lookup_failed: &'static str,
    pub incident_guidance_not_from_pypi: &'static str,
    pub warn_incident_release_lookup_failed: &'static str,
    // Incident progress lines (#982)
    pub progress_incident_fetching_advisory: &'static str,
    pub progress_incident_following_alias: &'static str,
    pub progress_incident_checking_release: &'static str,
    pub progress_incident_verifying_upgrade: &'static str,
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
            (
                EN_MESSAGES.error_config_invalid_format,
                JA_MESSAGES.error_config_invalid_format,
                1,
            ),
            (
                EN_MESSAGES.error_config_invalid_severity_threshold,
                JA_MESSAGES.error_config_invalid_severity_threshold,
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
            error_config_invalid_format,
            error_config_invalid_severity_threshold,
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
            warn_format_default_changing,
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
            warn_malicious_found,
            action_remove_malicious,
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
            warn_workspace_root_groups_uncovered,
            warn_workspace_root_groups_uncovered_hint,
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
            label_vuln_malicious,
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
            incident_guidance_direct_pin_blocks_upgrade,
            incident_guidance_no_released_fix,
            incident_guidance_simulation_error,
            incident_status_not_from_pypi,
            incident_guidance_release_lookup_failed,
            incident_guidance_not_from_pypi,
            warn_incident_release_lookup_failed,
            progress_incident_fetching_advisory,
            progress_incident_following_alias,
            progress_incident_checking_release,
            progress_incident_verifying_upgrade,
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
    fn test_warn_epss_fetch_failed_placeholder_parity() {
        let en_count = EN_MESSAGES.warn_epss_fetch_failed.matches("{}").count();
        let ja_count = JA_MESSAGES.warn_epss_fetch_failed.matches("{}").count();
        assert_eq!(en_count, ja_count);
        assert_eq!(en_count, 2);
    }

    #[test]
    fn test_warn_kev_fetch_failed_placeholder_parity() {
        let en_count = EN_MESSAGES.warn_kev_fetch_failed.matches("{}").count();
        let ja_count = JA_MESSAGES.warn_kev_fetch_failed.matches("{}").count();
        assert_eq!(en_count, ja_count);
        assert_eq!(en_count, 1);
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
    fn test_progress_packages_excluded_placeholder_parity() {
        let en_count = EN_MESSAGES.progress_packages_excluded.matches("{}").count();
        let ja_count = JA_MESSAGES.progress_packages_excluded.matches("{}").count();
        assert_eq!(en_count, ja_count);
        assert_eq!(en_count, 1);
    }
}
