//! Locale-aware rendering of error text for the CLI.
//!
//! This is the only place that turns a typed error into user-facing localized
//! text (see `.claude/CLAUDE.md` → "Error Message Localization Policy", decided
//! in #832). Errors whose payloads are permanently English (`SbomError`,
//! domain/adapter `bail!` sites) fall through to their own `Display` impl
//! unchanged.

use crate::application::use_cases::IncidentError;
use crate::cli::incident::IncidentTargetError;
use crate::i18n::Messages;
use crate::sbom_generation::domain::incident_target::ManualSpecError;
use uv_sbom::config::ConfigError;

/// Renders a single [`ConfigError`] in `msgs`'s locale.
pub fn render_config_error(err: &ConfigError, msgs: &Messages) -> String {
    match err {
        ConfigError::TemplateAlreadyExists { filename, dir } => Messages::format(
            msgs.error_config_already_exists,
            &[filename, &dir.display().to_string()],
        ),
        ConfigError::TemplateWriteFailed { path, .. } => Messages::format(
            msgs.error_config_template_write_failed,
            &[&path.display().to_string()],
        ),
        ConfigError::ReadFailed { path, .. } => Messages::format(
            msgs.error_config_read_failed,
            &[&path.display().to_string()],
        ),
        ConfigError::ParseFailed { path, .. } => Messages::format(
            msgs.error_config_parse_failed,
            &[&path.display().to_string()],
        ),
        ConfigError::EmptyIgnoreCveId { index } => {
            Messages::format(msgs.error_config_empty_ignore_cve_id, &[&index.to_string()])
        }
        ConfigError::InvalidUnknownLicenseHandling { value } => {
            Messages::format(msgs.error_config_invalid_unknown_license_handling, &[value])
        }
    }
}

/// Renders a single [`IncidentError`] in `msgs`'s locale.
///
/// `IncidentError` is imported from the binary's own `mod application;` copy,
/// because that is the copy `run_incident` builds the use case from; a
/// `uv_sbom::` import would be a distinct type and never downcast.
pub fn render_incident_error(err: &IncidentError, msgs: &Messages) -> String {
    match err {
        IncidentError::AdvisoryNotFound { advisory_id } => {
            Messages::format(msgs.error_incident_advisory_not_found, &[advisory_id])
        }
    }
}

/// Renders a rejected `--incident` value (#963) in `msgs`'s locale: the
/// value and the reason on one line, then a hint naming both accepted forms.
pub fn render_incident_target_error(err: &IncidentTargetError, msgs: &Messages) -> String {
    let reason = match &err.reason {
        ManualSpecError::Empty => msgs.error_incident_spec_empty.to_string(),
        ManualSpecError::MissingPackageName => msgs.error_incident_spec_missing_name.to_string(),
        ManualSpecError::InvalidPackageName { name } => {
            Messages::format(msgs.error_incident_spec_invalid_name, &[name])
        }
        ManualSpecError::MissingSpecifier { package } => {
            Messages::format(msgs.error_incident_spec_missing_specifier, &[package])
        }
        ManualSpecError::InvalidSpecifiers { specifiers } => {
            Messages::format(msgs.error_incident_spec_invalid_specifiers, &[specifiers])
        }
        ManualSpecError::UnsupportedOperator { specifier } => {
            Messages::format(msgs.error_incident_spec_unsupported_operator, &[specifier])
        }
        ManualSpecError::MultipleLowerBounds => msgs.error_incident_spec_multiple_lower.to_string(),
        ManualSpecError::MultipleUpperBounds => msgs.error_incident_spec_multiple_upper.to_string(),
        ManualSpecError::EmptyRange { specifiers } => {
            Messages::format(msgs.error_incident_spec_empty_range, &[specifiers])
        }
    };
    format!(
        "{}\n{}",
        Messages::format(msgs.error_incident_invalid_target, &[&err.input, &reason]),
        msgs.error_incident_target_hint
    )
}

/// Renders an `anyhow::Error` and its full `source()` chain to a single string,
/// localized via `msgs`.
///
/// The top-level error is localized when it downcasts to a known typed error
/// ([`ConfigError`], [`IncidentError`], or [`IncidentTargetError`]); everything else — including every error in
/// the `source()` chain, which is typically a third-party `std::io::Error` or
/// `serde_yaml_ng::Error` — falls back to its own (English) `Display`, per the
/// permanent-English-payload policy documented in `.claude/CLAUDE.md`.
///
/// Reproduces the exact byte layout of the `print_error_chain` helper this
/// replaced: a leading blank line, the header, a blank line, the rendered
/// error, then one blank-line-prefixed "caused by" line per source, and a
/// trailing blank line.
pub fn render_error_chain(e: &anyhow::Error, msgs: &Messages) -> String {
    let head = if let Some(config_err) = e.downcast_ref::<ConfigError>() {
        render_config_error(config_err, msgs)
    } else if let Some(incident_err) = e.downcast_ref::<IncidentError>() {
        render_incident_error(incident_err, msgs)
    } else if let Some(target_err) = e.downcast_ref::<IncidentTargetError>() {
        render_incident_target_error(target_err, msgs)
    } else {
        e.to_string()
    };

    let mut out = format!("\n{}\n\n{}\n", msgs.error_header, head);

    let mut source = e.source();
    while let Some(err) = source {
        let cause = err.to_string();
        out.push_str(&format!(
            "\n{}\n",
            Messages::format(msgs.error_caused_by, &[&cause])
        ));
        source = err.source();
    }

    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Locale;
    use std::path::PathBuf;

    fn all_config_errors() -> Vec<ConfigError> {
        vec![
            ConfigError::TemplateAlreadyExists {
                filename: "uv-sbom.config.yml",
                dir: PathBuf::from("/tmp/project"),
            },
            ConfigError::TemplateWriteFailed {
                path: PathBuf::from("/tmp/project/uv-sbom.config.yml"),
                source: std::io::Error::other("permission denied"),
            },
            ConfigError::ReadFailed {
                path: PathBuf::from("/tmp/missing.yml"),
                source: std::io::Error::other("not found"),
            },
            ConfigError::ParseFailed {
                path: PathBuf::from("/tmp/bad.yml"),
                source: serde_yaml_ng::from_str::<serde_yaml_ng::Value>("[[[").unwrap_err(),
            },
            ConfigError::EmptyIgnoreCveId { index: 2 },
            ConfigError::InvalidUnknownLicenseHandling {
                value: "maybe".to_string(),
            },
        ]
    }

    /// Drift guard: the `#[error(...)]` template on `ConfigError` (the library's
    /// `Display` contract) must stay byte-for-byte in sync with `EN_MESSAGES`.
    /// If a future edit changes one without the other, this test fails instead
    /// of silently leaving `--lang en`/default output as a stale duplicate.
    #[test]
    fn test_render_config_error_matches_display_in_en() {
        let msgs = Messages::for_locale(Locale::En);
        for err in all_config_errors() {
            assert_eq!(
                render_config_error(&err, msgs),
                err.to_string(),
                "EN rendering must match ConfigError's own Display for {err:?}"
            );
        }
    }

    #[test]
    fn test_render_config_error_ja() {
        let msgs = Messages::for_locale(Locale::Ja);

        assert_eq!(
            render_config_error(
                &ConfigError::TemplateAlreadyExists {
                    filename: "uv-sbom.config.yml",
                    dir: PathBuf::from("/tmp/project"),
                },
                msgs
            ),
            "uv-sbom.config.yml は /tmp/project に既に存在します。別のディレクトリを指定するか、既存のファイルを削除してください。"
        );
        assert_eq!(
            render_config_error(
                &ConfigError::TemplateWriteFailed {
                    path: PathBuf::from("/tmp/x.yml"),
                    source: std::io::Error::other("denied"),
                },
                msgs
            ),
            "設定テンプレートの書き込みに失敗しました: /tmp/x.yml"
        );
        assert_eq!(
            render_config_error(
                &ConfigError::ReadFailed {
                    path: PathBuf::from("/tmp/x.yml"),
                    source: std::io::Error::other("denied"),
                },
                msgs
            ),
            "設定ファイルの読み込みに失敗しました: /tmp/x.yml\n\n💡 ヒント: ファイルが存在し、読み取り可能であることを確認してください。"
        );
        assert_eq!(
            render_config_error(
                &ConfigError::ParseFailed {
                    path: PathBuf::from("/tmp/x.yml"),
                    source: serde_yaml_ng::from_str::<serde_yaml_ng::Value>("[[[").unwrap_err(),
                },
                msgs
            ),
            "設定ファイルの解析に失敗しました: /tmp/x.yml\n\n💡 ヒント: ファイルが有効な YAML 構文であることを確認してください。"
        );
        assert_eq!(
            render_config_error(&ConfigError::EmptyIgnoreCveId { index: 2 }, msgs),
            "設定が不正です: ignore_cves[2].id は空にできません。\n\n💡 ヒント: ignore_cves の各エントリには空でない 'id' フィールドが必要です（例: \"CVE-2024-1234\"）。"
        );
        assert_eq!(
            render_config_error(
                &ConfigError::InvalidUnknownLicenseHandling {
                    value: "maybe".to_string(),
                },
                msgs
            ),
            "設定が不正です: license_policy.unknown は warn, deny, allow のいずれかである必要があります。指定値: \"maybe\""
        );
    }

    #[test]
    fn test_render_error_chain_layout_en_non_config_error() {
        let msgs = Messages::for_locale(Locale::En);
        let inner = anyhow::anyhow!("root cause").context("outer context");

        let rendered = render_error_chain(&inner, msgs);

        assert_eq!(
            rendered,
            "\n❌ An error occurred:\n\nouter context\n\nCaused by: root cause\n\n"
        );
    }

    #[test]
    fn test_render_error_chain_localizes_top_level_config_error() {
        let msgs = Messages::for_locale(Locale::Ja);
        let err: anyhow::Error = ConfigError::EmptyIgnoreCveId { index: 0 }.into();

        let rendered = render_error_chain(&err, msgs);

        assert_eq!(
            rendered,
            "\n❌ エラーが発生しました:\n\n設定が不正です: ignore_cves[0].id は空にできません。\n\n💡 ヒント: ignore_cves の各エントリには空でない 'id' フィールドが必要です（例: \"CVE-2024-1234\"）。\n\n"
        );
    }

    #[test]
    fn test_render_error_chain_localizes_incident_error() {
        let err = anyhow::Error::from(IncidentError::AdvisoryNotFound {
            advisory_id: "GHSA-xxxx-xxxx-xxxx".to_string(),
        });

        let en = render_error_chain(&err, Messages::for_locale(Locale::En));
        assert!(en.contains("Advisory GHSA-xxxx-xxxx-xxxx was not found in the OSV database."));

        let ja = render_error_chain(&err, Messages::for_locale(Locale::Ja));
        assert!(ja.contains(
            "アドバイザリ GHSA-xxxx-xxxx-xxxx は OSV データベースに見つかりませんでした。"
        ));
        assert!(ja.starts_with("\n❌ エラーが発生しました:"));
    }

    fn target_error(input: &str, reason: ManualSpecError) -> IncidentTargetError {
        IncidentTargetError {
            input: input.to_string(),
            reason,
        }
    }

    fn all_spec_errors() -> Vec<ManualSpecError> {
        vec![
            ManualSpecError::Empty,
            ManualSpecError::MissingPackageName,
            ManualSpecError::InvalidPackageName {
                name: "foo-".to_string(),
            },
            ManualSpecError::MissingSpecifier {
                package: "requests".to_string(),
            },
            ManualSpecError::InvalidSpecifiers {
                specifiers: "<abc".to_string(),
            },
            ManualSpecError::UnsupportedOperator {
                specifier: "==2.25.0".to_string(),
            },
            ManualSpecError::MultipleLowerBounds,
            ManualSpecError::MultipleUpperBounds,
            ManualSpecError::EmptyRange {
                specifiers: ">=2.3,<2.0".to_string(),
            },
        ]
    }

    #[test]
    fn test_render_incident_target_error_en_starts_with_display_head() {
        // Drift guard: the localized EN head line stays in step with the
        // library `Display` head.
        let err = target_error(
            "requests==2.25.0",
            ManualSpecError::UnsupportedOperator {
                specifier: "==2.25.0".to_string(),
            },
        );
        let out = render_incident_target_error(&err, Messages::for_locale(Locale::En));

        let head = "Invalid advisory ID or version-range spec: 'requests==2.25.0'.";
        assert!(err.to_string().starts_with(head));
        assert!(out.starts_with(head), "{out}");
        assert!(out
            .contains("'==2.25.0' uses an unsupported operator; only >=, <, and <= are allowed."));
        assert!(out.contains("Quote the range in the shell"));
    }

    #[test]
    fn test_render_incident_target_error_every_reason_both_locales() {
        for reason in all_spec_errors() {
            let err = target_error("x", reason.clone());
            let en = render_incident_target_error(&err, Messages::for_locale(Locale::En));
            let ja = render_incident_target_error(&err, Messages::for_locale(Locale::Ja));
            assert!(!en.contains("{}") && !ja.contains("{}"), "{reason:?}");
            assert!(en.starts_with("Invalid advisory ID or version-range spec: 'x'."));
            assert!(ja.starts_with("アドバイザリ ID またはバージョン範囲の指定が不正です: 'x'。"));
            assert_eq!(en.lines().count(), 2, "{en}");
            assert_eq!(ja.lines().count(), 2, "{ja}");
        }
    }

    #[test]
    fn test_render_error_chain_localizes_incident_target_error() {
        let err = anyhow::Error::from(target_error(
            "requests",
            ManualSpecError::MissingSpecifier {
                package: "requests".to_string(),
            },
        ));

        let ja = render_error_chain(&err, Messages::for_locale(Locale::Ja));
        assert!(ja.contains("'requests' のバージョン範囲が指定されていません。"));
        assert!(ja.contains("範囲は引用符で囲んでください。"));
    }
}
