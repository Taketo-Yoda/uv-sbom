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
#[allow(dead_code)] // Some status fields reserved for future formatter sections
pub struct Messages {
    // Section headers
    pub section_sbom_title: &'static str,
    pub section_component_inventory: &'static str,
    pub section_direct_deps: &'static str,
    pub section_transitive_deps: &'static str,
    pub section_vuln_report: &'static str,
    pub section_license_compliance: &'static str,
    pub section_resolution_guide: &'static str,

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

    // Status labels
    pub status_compliant: &'static str,
    pub status_violation: &'static str,
    pub status_no_vulns: &'static str,
    pub status_direct_dep: &'static str,
    pub status_introduced_by: &'static str,

    // Progress messages (formatter/main layer)
    pub progress_generating_json: &'static str,
    pub progress_generating_markdown: &'static str,
    pub progress_verifying_links: &'static str,
    pub progress_fetching_license: &'static str,
    pub progress_fetching_vulns: &'static str,

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

    // Warning messages
    pub warn_check_cve_no_effect: &'static str,
    pub warn_check_license_no_effect: &'static str,
    pub warn_verify_links_no_effect: &'static str,

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

    // Executive summary section
    pub section_summary: &'static str,
    pub col_item: &'static str,
    pub col_count: &'static str,
    pub col_status: &'static str,
    pub label_direct_deps: &'static str,
    pub label_transitive_deps: &'static str,
    pub label_vuln_critical: &'static str,
    pub label_vuln_high: &'static str,
    pub label_vuln_medium: &'static str,
    pub label_vuln_low: &'static str,
    pub label_license_violations: &'static str,
    pub label_vuln_check_skipped: &'static str,
    pub overall_action_required: &'static str,
    pub overall_attention_recommended: &'static str,
    pub overall_no_issues: &'static str,
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

    // Status labels
    status_compliant: "Compliant",
    status_violation: "Violation",
    status_no_vulns: "No vulnerabilities found",
    status_direct_dep: "Direct dependency",
    status_introduced_by: "Introduced by",

    // Progress messages
    progress_generating_json: "📝 Generating CycloneDX JSON format output...",
    progress_generating_markdown: "📝 Generating Markdown format output...",
    progress_verifying_links: "🔗 Verifying PyPI links...",
    progress_fetching_license: "🔍 Fetching license information...",
    progress_fetching_vulns: "🔍 Fetching vulnerability information...",

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

    // Warning messages
    warn_check_cve_no_effect: "⚠️  Warning: --check-cve has no effect with JSON format.",
    warn_check_license_no_effect: "⚠️  Warning: --check-license has no effect with JSON format.",
    warn_verify_links_no_effect: "⚠️  Warning: --verify-links has no effect with JSON format.",

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

    // Executive summary section
    section_summary: "## Summary",
    col_item: "Item",
    col_count: "Count",
    col_status: "Status",
    label_direct_deps: "Direct dependencies",
    label_transitive_deps: "Transitive dependencies",
    label_vuln_critical: "Vulnerabilities (CRITICAL)",
    label_vuln_high: "Vulnerabilities (HIGH)",
    label_vuln_medium: "Vulnerabilities (MEDIUM)",
    label_vuln_low: "Vulnerabilities (LOW)",
    label_license_violations: "License violations",
    label_vuln_check_skipped: "_Vulnerability check skipped._",
    overall_action_required: "**Overall: Action required**",
    overall_attention_recommended: "**Overall: Attention recommended**",
    overall_no_issues: "**Overall: No issues found** ✅",
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

    // Status labels
    status_compliant: "準拠",
    status_violation: "違反",
    status_no_vulns: "脆弱性は検出されませんでした",
    status_direct_dep: "直接依存",
    status_introduced_by: "導入元",

    // Progress messages
    progress_generating_json: "📝 CycloneDX JSON形式で出力を生成中...",
    progress_generating_markdown: "📝 Markdown形式で出力を生成中...",
    progress_verifying_links: "🔗 PyPIリンクを検証中...",
    progress_fetching_license: "🔍 ライセンス情報を取得中...",
    progress_fetching_vulns: "🔍 脆弱性情報を取得中...",

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
    progress_license_no_violations: "✅ ライセンスコンプライアンス: 違反なし",
    progress_license_unknown_packages: "⚠️  ライセンスコンプライアンス: ライセンス不明のパッケージが{}件あります",

    // Warning messages
    warn_check_cve_no_effect: "⚠️  警告: JSON形式では --check-cve は効果がありません。",
    warn_check_license_no_effect: "⚠️  警告: JSON形式では --check-license は効果がありません。",
    warn_verify_links_no_effect: "⚠️  警告: JSON形式では --verify-links は効果がありません。",

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

    // Executive summary section
    section_summary: "## サマリー",
    col_item: "項目",
    col_count: "件数",
    col_status: "状態",
    label_direct_deps: "直接依存パッケージ",
    label_transitive_deps: "間接依存パッケージ",
    label_vuln_critical: "脆弱性 (CRITICAL)",
    label_vuln_high: "脆弱性 (HIGH)",
    label_vuln_medium: "脆弱性 (MEDIUM)",
    label_vuln_low: "脆弱性 (LOW)",
    label_license_violations: "ライセンス違反",
    label_vuln_check_skipped: "_脆弱性チェックはスキップされました。_",
    overall_action_required: "**総合判定: 対応が必要です**",
    overall_attention_recommended: "**総合判定: 注意が必要です**",
    overall_no_issues: "**総合判定: 問題なし** ✅",
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
        assert_eq!(msgs.status_compliant, "Compliant");
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
        assert_eq!(msgs.status_compliant, "準拠");
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
            "✅ ライセンスコンプライアンス: 違反なし"
        );
        assert_eq!(
            msgs.progress_license_unknown_packages,
            "⚠️  ライセンスコンプライアンス: ライセンス不明のパッケージが{}件あります"
        );
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
}
