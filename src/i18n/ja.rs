//! Japanese (`Locale::Ja`) message catalog.

use super::Messages;

pub(super) static JA_MESSAGES: Messages = Messages {
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
    error_config_invalid_format: "設定が不正です: format は json, markdown のいずれかである必要があります。指定値: \"{}\"",
    error_config_invalid_severity_threshold: "設定が不正です: severity_threshold は low, medium, high, critical のいずれかである必要があります。指定値: \"{}\"",

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
    warn_format_default_changing: "⚠️  警告: 出力形式が指定されていないため、JSON形式で出力します。v{} でデフォルトの出力形式は Markdown に変更されます。\n   JSON出力を維持するには --format json を、Markdown に今すぐ切り替えるには --format markdown を指定してください。\n   設定ファイル（例: uv-sbom.config.yml）で `format` を指定しても、この警告は表示されなくなります。",
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

    // Malicious-package (OSV `MAL-`) block in the vulnerability report
    warn_malicious_found: "### 🚨危険 悪意のあるパッケージが検出されました。",
    action_remove_malicious:
        "このパッケージを削除し、アクセスされた可能性のある認証情報をすべてローテーションしてください。",

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
    warn_workspace_root_groups_uncovered: "⚠️  警告: どのメンバーの SBOM にも含まれないワークスペースルートの依存グループ: {}",
    warn_workspace_root_groups_uncovered_hint: "   これらのグループからのみ到達するパッケージは、どの SBOM にも含まれません。この警告を抑止するには、これらのグループを --exclude-groups に追加してください。",

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
    label_vuln_malicious: "悪意のあるパッケージ",
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
    incident_guidance_direct_pin_blocks_upgrade: "**{}** を {} へ更新できませんでした。プロジェクトの直接依存のため、`pyproject.toml` のバージョン指定が {} を許容していない可能性があります。`>={}` を許容するよう指定を緩めてから、`uv lock --upgrade-package {}` と `uv sync` を実行してください。",
    incident_guidance_no_released_fix: "**{}** の修正版はまだリリースされていません。",
    incident_guidance_simulation_error: "**{}** の {} への更新を検証できませんでした: {}",
    incident_status_not_from_pypi: "PyPI 以外のソース — リリース状況は未確認",
    incident_guidance_release_lookup_failed: "**{}** {} のリリース状況を確認できませんでした: {}。更新前に PyPI を手動で確認してください。",
    incident_guidance_not_from_pypi: "**{}** は PyPI 以外からインストールされています。修正（{}）を含むリリースをソース側で確認してください。",
    warn_incident_release_lookup_failed: "⚠️  {} {} のリリース状況を確認できませんでした: {}",
    progress_incident_fetching_advisory: "🔍 アドバイザリ {} を取得中...",
    progress_incident_following_alias: "🔍 エイリアス {} を参照中...",
    progress_incident_checking_release: "🔍 {} {} のリリース状況を確認中...",
    progress_incident_verifying_upgrade: "🔍 {} {} へのアップグレードを検証中（ドライラン）...",

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
    use crate::i18n::Locale;

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
    fn test_messages_unknown_config_field_ja_format() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            Messages::format(msgs.warn_unknown_config_field, &["typo_field"]),
            "⚠️  警告: 不明な設定項目 'typo_field' は無視されます。"
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
    fn test_messages_format_default_changing_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        let text = Messages::format(msgs.warn_format_default_changing, &["5.0.0"]);
        assert!(text.starts_with("⚠️  警告:"));
        assert!(text.contains("v5.0.0 でデフォルトの出力形式は Markdown に変更されます"));
        assert!(text.contains("--format json"));
        assert!(text.contains("--format markdown"));
        assert!(text.contains("`format`"));
        assert!(!text.contains("{}"));
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
    fn test_error_all_packages_excluded_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            Messages::format(msgs.error_all_packages_excluded, &["3"]),
            "指定されたフィルターにより 3 個のパッケージがすべて除外されました。SBOM が空になります。除外パターンを見直してください。"
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
        assert_eq!(
            Messages::format(msgs.error_config_invalid_format, &["xml"]),
            "設定が不正です: format は json, markdown のいずれかである必要があります。指定値: \"xml\""
        );
        assert_eq!(
            Messages::format(msgs.error_config_invalid_severity_threshold, &["HIHG"]),
            "設定が不正です: severity_threshold は low, medium, high, critical のいずれかである必要があります。指定値: \"HIHG\""
        );
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
        assert_eq!(
            msgs.warn_malicious_found,
            "### 🚨危険 悪意のあるパッケージが検出されました。"
        );
        assert_eq!(
            msgs.action_remove_malicious,
            "このパッケージを削除し、アクセスされた可能性のある認証情報をすべてローテーションしてください。"
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
        assert_eq!(
            msgs.warn_workspace_root_groups_uncovered,
            "⚠️  警告: どのメンバーの SBOM にも含まれないワークスペースルートの依存グループ: {}"
        );
        assert_eq!(
            msgs.warn_workspace_root_groups_uncovered_hint,
            "   これらのグループからのみ到達するパッケージは、どの SBOM にも含まれません。この警告を抑止するには、これらのグループを --exclude-groups に追加してください。"
        );
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
    fn test_progress_incident_checking_release_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        let result = Messages::format(
            msgs.progress_incident_checking_release,
            &["urllib3", "2.0.6"],
        );
        assert_eq!(result, "🔍 urllib3 2.0.6 のリリース状況を確認中...");
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
    fn test_warn_epss_fetch_failed_ja_format() {
        let msgs = Messages::for_locale(Locale::Ja);
        let result = Messages::format(msgs.warn_epss_fetch_failed, &["3", "接続が拒否されました"]);
        assert_eq!(
            result,
            "警告: バッチ3のEPSSデータ取得に失敗: 接続が拒否されました"
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
    fn test_warn_exclude_pattern_unmatched_ja_format() {
        let msgs = Messages::for_locale(Locale::Ja);
        let result = Messages::format(msgs.warn_exclude_pattern_unmatched, &["foo-*"]);
        assert_eq!(
            result,
            "⚠️  警告: 除外パターン 'foo-*' はどの依存関係にも一致しませんでした。"
        );
    }

    #[test]
    fn test_progress_packages_excluded_ja_format() {
        let msgs = Messages::for_locale(Locale::Ja);
        let result = Messages::format(msgs.progress_packages_excluded, &["3"]);
        assert_eq!(result, "🚫 フィルターにより3個のパッケージを除外");
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
    fn test_warn_suggest_fix_requires_pyproject_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        assert_eq!(
            msgs.warn_suggest_fix_requires_pyproject,
            "⚠ --suggest-fix にはプロジェクトディレクトリに pyproject.toml が必要です。"
        );
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
