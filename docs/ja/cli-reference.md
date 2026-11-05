# CLI リファレンス

[メインページに戻る](../../README-JP.md)

uv-sbom の完全なコマンドラインオプションと出力形式の例です。

## 目次

- [コマンドラインオプション](#コマンドラインオプション)
- [出力例](#出力例)

---

## コマンドラインオプション

```
Options:
  -f, --format <FORMAT>              出力形式: json または markdown [デフォルト: json、--incident モードでは markdown]
  -p, --path <PATH>                  プロジェクトディレクトリのパス [デフォルト: カレントディレクトリ]
  -o, --output <OUTPUT>              出力ファイルパス（未指定の場合は stdout に出力）
  -e, --exclude <PATTERN>            パターンに一致するパッケージを除外（ワイルドカード * 対応）
  -c, --config <PATH>               設定ファイルのパス（未指定の場合は uv-sbom.config.yml を自動検出）
  -i, --ignore-cve <CVE_ID>         無視する CVE ID（複数指定可能）
      --lang <LANG>                  人間が読む形式の出力言語: en または ja [デフォルト: en]
      --init                         uv-sbom.config.yml テンプレートファイルを生成
      --dry-run                      ネットワーク通信や出力生成なしで設定を検証
      --verify-links                 ハイパーリンク生成前に PyPI リンクの存在を検証（Markdown 形式のみ）
      --no-check-cve                 CVE 脆弱性チェックを無効化（デフォルトで有効）
      --severity-threshold <LEVEL>   脆弱性チェックの重大度しきい値（low/medium/high/critical）
                                     --no-check-cve とは併用不可
      --cvss-threshold <SCORE>       脆弱性チェックの CVSS しきい値（0.0-10.0）
                                     --no-check-cve とは併用不可
      --suggest-fix                  推移的脆弱性を解決するための直接依存関係アップグレードバージョンを提案
                                     uv CLI のインストールとプロジェクトディレクトリに pyproject.toml が必要
      --workspace                    ワークスペースメンバーごとに 1 つの SBOM を生成
                                     --output とは併用不可
      --diff <REF_OR_PATH>           現在の uv.lock をベースと比較（git ref、タグ、コミット SHA、または uv.lock ファイルのパス）
      --check-license                ポリシーに対するライセンスコンプライアンスをチェック
      --check-abandoned              放置/メンテナンスされていないパッケージをチェック（しきい値日数以内にアップストリームリリースなし）
      --abandoned-threshold-days <DAYS>  放置パッケージ検出の非アクティブしきい値（日数）（デフォルト: 730）
      --check-non-pypi               非 PyPI オリジン（git、ダイレクト URL、プライベートレジストリ）からのパッケージをチェック
      --check-exploitability         CVE 結果を EPSS スコアと CISA KEV ステータスで強化
                                     --no-check-cve とは併用不可
      --license-allow <LIST>         許可するライセンスパターンのカンマ区切りリスト（設定を上書き）
      --license-deny <LIST>          拒否するライセンスパターンのカンマ区切りリスト（設定を上書き）
      --exclude-groups <GROUPS>      指定した依存グループ経由でのみ到達可能なパッケージを除外（カンマ区切り）
                                     例: --exclude-groups dev,test,lint。--production-only とは併用不可
      --production-only              デフォルト以外のすべての依存グループを除外（本番のみモード）
                                     --exclude-groups とは併用不可
      --target-python <VERSION>      互換性チェックのターゲット Python バージョン（PEP 440 形式、例: 3.8）
      --baseline <PATH>              以前に受け入れた検出結果を抑制するための脆弱性ベースラインファイルのパス
                                     --no-check-cve とは併用不可
      --update-baseline              SBOM 生成後、すべての現在の脆弱性検出結果でベースラインファイルを更新
                                     --baseline が必要
      --explain <PACKAGE_NAME>       指定パッケージへの依存パスをトレース（Markdown 形式のみ）
                                     --workspace とは併用不可
      --show-dependency-tree        依存関係グラフを ASCII ツリーとしてレンダリング（Markdown 形式のみ）
      --dependency-tree-depth <DEPTH>  依存関係ツリー可視化の最大深度（デフォルト: 3）
                                     --show-dependency-tree が必要
      --incident <ID_OR_RANGE>       1 つのアドバイザリ（GHSA-/PYSEC-/CVE-/OSV-/MAL- ID）がプロジェクトに影響するかチェック、
                                     修正がリリース済みか、実行するコマンドは何か（デフォルト Markdown）
                                     OSV に未登録のアドバイザリには "foo>=2.0,<2.3.2" のようなクォートされた範囲を渡す
                                     （演算子 >=, <, <= のみ）
                                     --workspace と併用で、1 つの統合レポートですべてのメンバーをレポート
                                     --diff やチェックフラグとは併用不可（インシデント対応を参照）
  -h, --help                         ヘルプを表示
  -V, --version                      バージョンを表示
```

## 出力例

### Markdown 形式

> **注意**: Markdown 形式のサンプルは [ja-complete v0.1.0](https://github.com/Taketo-Yoda/ja-complete/tree/v0.1.0) の SBOM 形式に基づいています。

```markdown
## Summary

| Item | Count | Status |
|------|-------|--------|
| Direct dependencies | 2 | ✅ |
| Transitive dependencies | 3 | ✅ |
| ...vulnerability rows... | | |
| License violations | 0 | ✅ |

**Overall: No issues found** ✅

# Software Bill of Materials (SBOM)

## Component Inventory

A comprehensive list of all software components and libraries included in this project.

| Package | Version | License | Description |
|---------|---------|---------|-------------|
| janome | 0.5.0 | AL2 | Japanese morphological analysis engine. |
| pydantic | 2.12.5 | MIT | Data validation using Python type hints |
| ...additional packages... |

## Direct Dependencies

Primary packages explicitly defined in the project configuration(e.g., pyproject.toml).

| Package | Version | License | Description |
|---------|---------|---------|-------------|
| janome | 0.5.0 | AL2 | Japanese morphological analysis engine. |
| pydantic | 2.12.5 | MIT | Data validation using Python type hints |

## Transitive Dependencies

Secondary dependencies introduced by the primary packages.

### Dependencies for pydantic

| Package | Version | License | Description |
|---------|---------|---------|-------------|
| annotated-types | 0.7.0 | MIT License | Reusable constraint types to use with typing.Annotated |
| pydantic-core | 2.41.5 | MIT | Core functionality for Pydantic validation and serialization |
```

### CycloneDX JSON 形式

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "serialNumber": "urn:uuid:...",
  "metadata": {
    "timestamp": "2024-01-01T00:00:00Z",
    "tools": [
      {
        "name": "uv-sbom",
        "version": "0.1.0"
      }
    ]
  },
  "components": [
    {
      "type": "library",
      "name": "requests",
      "version": "2.31.0",
      "description": "HTTP library for Python",
      "licenses": [
        {
          "license": {
            "name": "Apache 2.0"
          }
        }
      ],
      "purl": "pkg:pypi/requests@2.31.0"
    }
  ]
}
```
