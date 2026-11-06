# 設定

[メインページに戻る](../../README-JP.md)

uv-sbom は YAML 設定ファイル（`uv-sbom.config.yml`）をサポートしており、デフォルトオプション、パッケージ除外パターン、CVE 無視リスト、ライセンスポリシーを設定できます。CLI 引数は常に設定ファイルの値を上書きします。

## 目次

- [設定ファイル](#設定ファイル)
- [設定ファイルスキーマリファレンス](#設定ファイルスキーマリファレンス)
- [優先順位とマージルール](#優先順位とマージルール)
- [パッケージの除外](#パッケージの除外)
- [依存グループによるパッケージの除外](#依存グループによるパッケージの除外)
- [特定の CVE の無視](#特定の-cve-の無視)
- [ドライランによる設定の検証](#ドライランによる設定の検証)

---

## 設定ファイル

設定ファイル（`uv-sbom.config.yml`）を使用して、毎回コマンドラインで渡す代わりにデフォルトオプションを設定できます。

### 設定テンプレートの生成

`--init` オプションを使用して、すべての利用可能なフィールドがコメント付きの例として含まれるテンプレート設定ファイルを生成します：

```bash
# カレントディレクトリにテンプレートを生成
uv-sbom --init

# 特定のディレクトリにテンプレートを生成
uv-sbom --init --path ./my-project
```

これにより、すべてのオプションに関するインラインドキュメント付きの `uv-sbom.config.yml` ファイルが作成されます。ファイルが既に存在する場合、誤って上書きしないようにエラーで終了します。

**自動検出**: プロジェクトディレクトリ（`uv.lock` がある場所）に `uv-sbom.config.yml` ファイルを配置します。ツールは自動的に検出してロードします。

**明示的なパス**: `--config` / `-c` を使用して、カスタムの場所にある設定ファイルを指定します。

```bash
# 自動検出される設定ファイル（プロジェクトディレクトリに配置）
uv-sbom

# 明示的な設定ファイルパス
uv-sbom --config ./custom-config.yml
```

**設定ファイルの例**（`uv-sbom.config.yml`）：

```yaml
# 出力形式：json または markdown
format: markdown

# SBOM から除外するパッケージ（ワイルドカード対応）
exclude_packages:
  - "pytest"
  - "mypy"
  - "*-dev"

# CVE 脆弱性チェックを有効化
check_cve: true

# 脆弱性チェックの重大度しきい値（low/medium/high/critical）
severity_threshold: high

# 脆弱性チェックの CVSS しきい値（0.0-10.0）
# cvss_threshold: 7.0

# 無視する CVE（オプションで理由付き）
ignore_cves:
  - id: CVE-2024-1234
    reason: "False positive for our use case"
  - id: CVE-2024-5678
    reason: "Mitigated by network configuration"

# ライセンスコンプライアンスポリシー
license_policy:
  allow: ["MIT", "Apache-2.0", "BSD-*", "ISC", "PSF-2.0"]
  deny: ["GPL-3.0-only", "GPL-3.0-or-later", "AGPL-*"]
  unknown: "warn"  # "warn" | "deny" | "allow"

# CVE 結果を EPSS スコアと CISA KEV ステータスで強化
# check_exploitability: false

# 以前に受け入れた CVE 検出結果を抑制するための脆弱性ベースラインファイルのパス
# baseline_file: .uv-sbom-baseline.json
```

## 設定ファイルスキーマリファレンス

| フィールド | 型 | 必須 | 説明 |
|-------|------|----------|-------------|
| `format` | string | いいえ | 出力形式（`json` / `markdown`） |
| `exclude_packages` | string[] | いいえ | パッケージ除外パターン（ワイルドカード対応） |
| `check_cve` | bool | いいえ | CVE チェック動作を上書き。未設定時のデフォルトは true |
| `severity_threshold` | string | いいえ | 重大度しきい値（`low` / `medium` / `high` / `critical`） |
| `cvss_threshold` | number | いいえ | CVSS しきい値（0.0 - 10.0） |
| `ignore_cves` | object[] | いいえ | 無視する CVE のリスト |
| `ignore_cves[].id` | string | はい | CVE ID（例：`CVE-2024-1234`） |
| `ignore_cves[].reason` | string | いいえ | 無視する理由 |
| `license_policy` | object | いいえ | ライセンスコンプライアンスポリシー設定 |
| `license_policy.allow` | string[] | いいえ | 許可するライセンスパターン（ワイルドカード対応） |
| `license_policy.deny` | string[] | いいえ | 拒否するライセンスパターン（ワイルドカード対応） |
| `license_policy.unknown` | string | いいえ | 不明なライセンスの処理（`warn` / `deny` / `allow`） |
| `check_abandoned` | bool | いいえ | 放置パッケージ検出を有効化（オプトイン、デフォルト：false） |
| `abandoned_threshold_days` | integer | いいえ | 放置パッケージ検出の非アクティブしきい値（日数）（デフォルト：730） |
| `check_non_pypi` | bool | いいえ | 非 PyPI ソース検出を有効化（オプトイン、デフォルト：false） |
| `exclude_groups` | string[] | いいえ | 排他的に到達可能なパッケージを SBOM から除外する依存グループ |
| `check_exploitability` | bool | いいえ | CVE 結果を EPSS スコアと CISA KEV ステータスで強化（オプトイン、デフォルト：false） |
| `target_python` | string | いいえ | 互換性チェックのターゲット Python バージョン（PEP 440 形式、例：`"3.8"`）。未設定でチェック無効 |
| `baseline_file` | string | いいえ | 以前に受け入れた検出結果を抑制するための脆弱性ベースライン JSON ファイルのパス |

## 優先順位とマージルール

- **CLI 引数が設定ファイルの値を上書きします**（スカラーフィールド：`format`、`severity_threshold`、`cvss_threshold`）。明示的な `--format json` は設定の `format: markdown` も上書きします
- **`check_cve`** は未設定時のデフォルトが true。設定で false にして無効化。CLI フラグ `--no-check-cve` でオプトアウト
- **`exclude_packages`** は CLI と設定ファイルの両方から**マージ**され、重複排除されます
- **`ignore_cves`** は CLI（`--ignore-cve`）と設定ファイルの両方から**マージ**され、ID で重複排除されます（重複時は CLI エントリが優先）
- **`check_license`** は CLI フラグまたは設定ファイルで設定されている場合に有効化されます（論理 OR、`check_cve` と同様）
- **`--license-allow`** と **`--license-deny`** の CLI オプションは設定ファイルの `license_policy.allow` / `license_policy.deny` を**完全に上書き**します（マージではない）
- **`check_abandoned`** はオプトイン（デフォルト：false）。CLI フラグ `--check-abandoned` または設定ファイル `check_abandoned: true` で有効化。`abandoned_threshold_days` の値は CLI > 設定ファイル > デフォルト（730）の解決順序に従います
- **`check_non_pypi`** はオプトイン（デフォルト：false）。CLI フラグ `--check-non-pypi` または設定ファイル `check_non_pypi: true` で有効化
- **`check_exploitability`** はオプトイン（デフォルト：false）。CLI フラグ `--check-exploitability` または設定ファイル `check_exploitability: true` で有効化。CVE チェックが必要（`--no-check-cve` と競合）
- **`exclude_groups`**: CLI `--exclude-groups` は設定ファイルの値を**完全に上書き**します（マージではない）。`--production-only` は実行時にロックファイルからすべてのグループ名を解決し、CLI と設定の両方より優先されます
- **`target_python`** はオプトイン（デフォルト：未設定、チェックなし）。CLI フラグ `--target-python 3.8` または設定ファイル `target_python: "3.8"` で有効化。CLI 値が設定ファイルより優先

## パッケージの除外

`--exclude` または `-e` オプションを使用して、SBOM から特定のパッケージを除外できます：

```bash
# 単一のパッケージを除外
uv-sbom -e "pytest"

# 複数のパッケージを除外
uv-sbom -e "pytest" -e "mypy" -e "black"

# ワイルドカードでパターンを除外
uv-sbom -e "debug-*"        # "debug-" で始まるすべてのパッケージを除外
uv-sbom -e "*-dev"          # "-dev" で終わるすべてのパッケージを除外
uv-sbom -e "*-test-*"       # "-test-" を含むすべてのパッケージを除外

# 他のオプションと組み合わせ
uv-sbom --format json --output sbom.json -e "pytest" -e "*-dev"
```

**パターン構文:**
- ワイルドカードとして `*` を使用（0 文字以上にマッチ）
- パターンは大文字小文字を区別します
- 1 回の実行で最大 64 パターン

**情報漏洩の防止:**
`--exclude` オプションを使用して、特定の内部または独自ライブラリをスキップします。これにより、メタデータ取得時に外部レジストリ（PyPI など）にそれらの名前が送信されるのを防ぎ、内部プロジェクト構造のプライバシーが保護されます。

## 依存グループによるパッケージの除外

`--exclude-groups` を使用して、指定した[依存グループ](https://docs.astral.sh/uv/concepts/dependencies/#dependency-groups)（例：`dev`、`test`、`lint`）を通じて**排他的に到達可能な**パッケージを除外します。本番依存関係と共有されるパッケージは常に保持されます。グループ名は大文字小文字と区切り文字を区別せずにマッチングされます（[PEP 735](https://peps.python.org/pep-0735/)）。`--exclude-groups Lint` や `--exclude-groups type_check` はそれぞれ `lint` と `type-check` グループを除外します。設定ファイルの `exclude_groups` も同様です。

```bash
# "dev" グループ経由でのみ到達可能なパッケージを除外
uv-sbom --exclude-groups dev --format markdown

# 複数のグループを除外（カンマ区切り）
uv-sbom --exclude-groups dev,test,lint --format markdown

# 本番のみモード：デフォルト以外のすべての依存グループを自動的に除外
uv-sbom --production-only --format markdown
```

`--production-only` は `uv.lock` ファイルの `[manifest.dependency-groups]` セクションを実行時に読み取り、見つかったすべてのグループに `--exclude-groups` を設定します。すべてのグループを明示的にリストするのと同等ですが、より簡潔で、グループの追加や削除に自動的に対応します。

> **注意:** `--exclude-groups` と `--production-only` は相互排他です。

設定ファイルでも設定できます：

```yaml
# これらの依存グループ経由でのみ到達可能なパッケージを除外
exclude_groups:
  - dev
  - test
  - lint
```

## 特定の CVE の無視

コマンドラインから `--ignore-cve` / `-i` を使用して特定の CVE を無視できます：

```bash
# CLI から特定の CVE を無視
uv-sbom --ignore-cve CVE-2024-1234 --ignore-cve CVE-2024-5678

# 短縮形
uv-sbom -i CVE-2024-1234 -i CVE-2024-5678

# 設定ファイルと CLI の無視を組み合わせ（両方のソースがマージされます）
uv-sbom --config ./config.yml -i CVE-2024-9999
```

## ドライランによる設定の検証

`--dry-run` オプションを使用して、ツールが外部レジストリと通信する前に設定を検証します：

```bash
# 除外パターンが正しく動作するか確認
uv-sbom --dry-run -e "internal-*" -e "proprietary-pkg"

# すべてのオプションで設定をテスト
uv-sbom --dry-run --path /path/to/project --format json -e "*-dev"
```

**--dry-run を使用する理由:**
- **除外パターンの検証**: `--exclude` パターンがスキップしたいパッケージに正しくマッチするか確認
- **情報漏洩の防止**: ツールが PyPI レジストリと通信する前に、機密の内部パッケージが除外されていることを確認
- **高速な検証**: すべての入力検証がネットワークオーバーヘッドなしで実行
- **早期エラー検出**: 設定の問題（uv.lock の欠落、無効なパターンなど）を即座にキャッチ

**ドライランモードの動作:**
- ✅ `uv.lock` ファイルの読み取りとパース
- ✅ すべてのコマンドライン引数の検証
- ✅ 除外パターンのチェックとマッチしないパターンの警告
- ✅ 問題がなければ成功メッセージを出力
- ❌ PyPI からのライセンス取得をスキップ（ネットワーク通信なし）
- ❌ SBOM 出力生成をスキップ
