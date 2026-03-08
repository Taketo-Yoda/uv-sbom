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
pub struct Messages {
    // Section headers
    pub section_sbom_report: &'static str,
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

    // Progress messages
    pub progress_generating_json: &'static str,
    pub progress_generating_markdown: &'static str,
    pub progress_verifying_links: &'static str,
    pub progress_fetching_license: &'static str,
    pub progress_fetching_vulns: &'static str,

    // Warning messages
    pub warn_check_cve_no_effect: &'static str,
    pub warn_check_license_no_effect: &'static str,
    pub warn_verify_links_no_effect: &'static str,
}

impl Messages {
    /// Return the static message table for the given locale.
    pub fn for_locale(locale: Locale) -> &'static Self {
        match locale {
            Locale::En => &EN_MESSAGES,
            Locale::Ja => &JA_MESSAGES,
        }
    }
}

static EN_MESSAGES: Messages = Messages {
    // Section headers
    section_sbom_report: "## SBOM Report",
    section_direct_deps: "### Direct Dependencies",
    section_transitive_deps: "### Transitive Dependencies",
    section_vuln_report: "## Vulnerability Report",
    section_license_compliance: "## License Compliance",
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

    // Warning messages
    warn_check_cve_no_effect: "⚠️  Warning: --check-cve has no effect with JSON format.",
    warn_check_license_no_effect: "⚠️  Warning: --check-license has no effect with JSON format.",
    warn_verify_links_no_effect: "⚠️  Warning: --verify-links has no effect with JSON format.",
};

static JA_MESSAGES: Messages = Messages {
    // Section headers
    section_sbom_report: "## SBOMレポート",
    section_direct_deps: "### 直接依存パッケージ",
    section_transitive_deps: "### 間接依存パッケージ",
    section_vuln_report: "## 脆弱性レポート",
    section_license_compliance: "## ライセンスコンプライアンス",
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

    // Warning messages
    warn_check_cve_no_effect: "⚠️  警告: JSON形式では --check-cve は効果がありません。",
    warn_check_license_no_effect: "⚠️  警告: JSON形式では --check-license は効果がありません。",
    warn_verify_links_no_effect: "⚠️  警告: JSON形式では --verify-links は効果がありません。",
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
        assert_eq!(msgs.section_sbom_report, "## SBOM Report");
        assert_eq!(msgs.section_direct_deps, "### Direct Dependencies");
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
        assert_eq!(msgs.section_sbom_report, "## SBOMレポート");
        assert_eq!(msgs.section_direct_deps, "### 直接依存パッケージ");
        assert_eq!(msgs.col_package, "パッケージ");
        assert_eq!(msgs.status_compliant, "準拠");
        assert_eq!(
            msgs.progress_generating_json,
            "📝 CycloneDX JSON形式で出力を生成中..."
        );
    }
}
