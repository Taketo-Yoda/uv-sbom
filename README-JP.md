# uv-sbom

[![GitHub release](https://img.shields.io/github/release/Taketo-Yoda/uv-sbom.svg)](https://github.com/Taketo-Yoda/uv-sbom/releases) [![PyPI - Version](https://img.shields.io/pypi/v/uv-sbom-bin?logo=python&logoColor=white&label=PyPI)](https://pypi.org/project/uv-sbom-bin/) [![Crates.io Version](https://img.shields.io/crates/v/uv-sbom?logo=rust&logoColor=white)](https://crates.io/crates/uv-sbom)
[![shield_license]][license_file] [![CI](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/ci.yml/badge.svg)](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/ci.yml)
[![Dependabot Updates](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/dependabot/dependabot-updates) [![CodeQL](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/github-code-scanning/codeql)

[English](README.md) | [日本語](README-JP.md)

----

[uv](https://github.com/astral-sh/uv)で管理されているPythonプロジェクトのSBOM（Software Bill of Materials）を生成します。

## 機能

- 📦 `uv.lock`ファイルを解析して依存関係情報を抽出
- 🔍 PyPIからライセンス情報を自動取得（リトライロジック付き）
- 🛡️ OSV APIを使用した既知の脆弱性チェック（Markdownフォーマットのみ）
- 📋 許可/拒否リストとワイルドカード対応のライセンスコンプライアンスポリシーチェック
- 🔎 **脆弱性解決ガイド** - 脆弱な推移的パッケージを導入している直接依存関係を特定
- 📊 複数のフォーマットに対応:
  - **CycloneDX 1.6** JSON形式（標準SBOM形式）
  - **Markdown**形式（直接依存と推移的依存を明確に分離）
- 🚀 高速でスタンドアロン - Rustで実装
- 💾 標準出力またはファイルへ出力
- 🛡️ 堅牢なエラーハンドリングと親切なエラーメッセージ・提案
- 📈 ライセンス情報取得時の進捗表示

## スコープとCycloneDXとの主な違い

### SBOMのスコープ

このツールは**uv.lock**ファイルの内容に基づいてSBOMを生成します。これには以下が含まれます:
- 直接的なランタイム依存関係
- 推移的なランタイム依存関係
- 開発依存関係（uv.lockにロックされている場合）

**含まれないもの:**
- ビルドシステム依存関係（例: hatchling, setuptools）
- 公開ツール（例: twine, build）
- 仮想環境にのみ存在し、uv.lockにロックされていない依存関係

### CycloneDX公式ツールとの比較

CycloneDX公式ツール (v7.2.1時点) は、まだ uv を直接サポートしていません。PythonプロジェクトのSBOMを生成する場合:

| 側面 | uv-sbom（このツール） | CycloneDX公式ツール |
|--------|---------------------|--------------------------|
| **データソース** | `uv.lock`ファイル | `.venv`仮想環境 |
| **スコープ** | 本番ランタイム依存のみ | ビルド/開発ツールを含むサプライチェーン全体 |
| **パッケージ数** | 通常少なめ（例: 16パッケージ） | 通常多め（例: 38+パッケージ） |
| **ユースケース** | 本番環境のセキュリティスキャン | 包括的なサプライチェーン監査 |
| **精度** | ロックされた依存関係を反映 | インストールされたパッケージを反映 |

### どちらのツールを使うべきか?

- **本番環境のセキュリティスキャン**: `uv-sbom`を使用して本番環境にデプロイされる依存関係に焦点を当てる
- **包括的なサプライチェーン監査**: CycloneDX公式ツールを使用してすべての開発・ビルド時依存関係を含める
- **規制コンプライアンス**: 特定の要件を確認 - 一部の規制では包括的なアプローチが必要な場合があります

`uv-sbom`の焦点を絞ったアプローチは、最終的なアプリケーションに含まれないビルド時依存関係を除外することで、セキュリティ脆弱性スキャンにおけるノイズを削減します。

## インストール

### Cargo（Rustユーザー向け推奨）

![Crates.io Total Downloads](https://img.shields.io/crates/d/uv-sbom)

[crates.io](https://crates.io/crates/uv-sbom)からインストール:

```bash
cargo install uv-sbom
```

### uv tool（Pythonユーザー向け）

![PyPI - Downloads](https://img.shields.io/pypi/dm/uv-sbom-bin?logo=PyPI&logoColor=white)

Pythonラッパーパッケージをインストール:

```bash
uv tool install uv-sbom-bin
```

またはpip経由:

```bash
pip install uv-sbom-bin
```

インストール後は `uv-sbom` コマンドで実行:

```bash
uv-sbom --version
```

**注意**: パッケージ名は `uv-sbom-bin` ですが、インストールされるコマンド名は `uv-sbom` です。

### プリビルドバイナリ

![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/Taketo-Yoda/uv-sbom/total?logo=GitHub)

[GitHub Releases](https://github.com/Taketo-Yoda/uv-sbom/releases)からプリビルドバイナリをダウンロード:

**macOS (Apple Silicon)**:
```bash
curl -LO https://github.com/Taketo-Yoda/uv-sbom/releases/latest/download/uv-sbom-aarch64-apple-darwin.tar.gz
tar xzf uv-sbom-aarch64-apple-darwin.tar.gz
sudo mv uv-sbom /usr/local/bin/
```

**macOS (Intel)**:
```bash
curl -LO https://github.com/Taketo-Yoda/uv-sbom/releases/latest/download/uv-sbom-x86_64-apple-darwin.tar.gz
tar xzf uv-sbom-x86_64-apple-darwin.tar.gz
sudo mv uv-sbom /usr/local/bin/
```

**Linux (x86_64)**:
```bash
curl -LO https://github.com/Taketo-Yoda/uv-sbom/releases/latest/download/uv-sbom-x86_64-unknown-linux-gnu.tar.gz
tar xzf uv-sbom-x86_64-unknown-linux-gnu.tar.gz
sudo mv uv-sbom /usr/local/bin/
```

**Windows**:
[リリースページ](https://github.com/Taketo-Yoda/uv-sbom/releases)から`uv-sbom-x86_64-pc-windows-msvc.zip`をダウンロードし、任意の場所に展開してください。

### ソースから

```bash
# リポジトリをクローン
git clone https://github.com/Taketo-Yoda/uv-sbom.git
cd uv-sbom

# ビルドとインストール
cargo build --release
cargo install --path .
```

### インストールの確認

```bash
uv-sbom --version
```

## 使用方法

### 基本的な使用方法

カレントディレクトリのCycloneDX JSON SBOMを生成:

```bash
uv-sbom
```

### 出力フォーマット

直接依存と推移的依存を含むMarkdownテーブルを生成:

```bash
uv-sbom --format markdown
```

CycloneDX JSONを生成（デフォルト）:

```bash
uv-sbom --format json
```

### 出力言語

`--lang` オプションを使用して、人間が読みやすいフォーマット（Markdown）の出力言語を切り替えます。デフォルトは英語（`en`）です。

```bash
# 日本語でMarkdown SBOMレポートを生成
uv-sbom --format markdown --lang ja

# 英語でMarkdown SBOMレポートを生成（デフォルト）
uv-sbom --format markdown --lang en
```

**対応値:** `en`（英語、デフォルト）、`ja`（日本語）

**注意:** `--lang` オプションは、Markdown出力のセクションヘッダー、テーブルの列名、ステータスラベルに影響します。パッケージ名・CVE ID・SPDXライセンス識別子は、`--lang` の設定によらず常に元の形式で出力されます。

### プロジェクトパスの指定

別のディレクトリのプロジェクトを解析:

```bash
uv-sbom --path /path/to/project
```

### ファイルへの保存

標準出力の代わりにファイルへ出力:

```bash
uv-sbom --format json --output sbom.json
uv-sbom --format markdown --output SBOM.md
```

### オプションの組み合わせ

```bash
uv-sbom --path /path/to/project --format markdown --output SBOM.md
```

### パッケージの除外

`--exclude`または`-e`オプションを使用して、特定のパッケージをSBOMから除外できます：

```bash
# 単一のパッケージを除外
uv-sbom -e "pytest"

# 複数のパッケージを除外
uv-sbom -e "pytest" -e "mypy" -e "black"

# ワイルドカードパターンを使用して除外
uv-sbom -e "debug-*"        # "debug-"で始まるすべてのパッケージを除外
uv-sbom -e "*-dev"          # "-dev"で終わるすべてのパッケージを除外
uv-sbom -e "*-test-*"       # "-test-"を含むすべてのパッケージを除外

# 他のオプションと組み合わせて使用
uv-sbom --format json --output sbom.json -e "pytest" -e "*-dev"
```

**パターン構文:**
- `*`をワイルドカードとして使用し、0文字以上の文字列にマッチさせます
- パターンは大文字小文字を区別します
- 1回の実行につき最大64個のパターンを指定できます

**情報の外部送信を防止する:**
独自の社内ライブラリなど、PyPI等の外部レジストリに名前を送信したくないパッケージがある場合は、`--exclude` オプションを使用してください。これにより、メタデータ取得時の通信から特定のライブラリ名を除外し、秘匿性を保つことができます。

### 設定ファイル

設定ファイル（`uv-sbom.config.yml`）を使用して、毎回コマンドラインでオプションを渡す代わりにデフォルトオプションを設定できます。

#### 設定テンプレートの生成

`--init`オプションを使用して、すべての設定項目をコメント付きで含むテンプレートファイルを生成できます：

```bash
# カレントディレクトリにテンプレートを生成
uv-sbom --init

# 指定したディレクトリにテンプレートを生成
uv-sbom --init --path ./my-project
```

これにより、すべてのオプションのインラインドキュメントを含む`uv-sbom.config.yml`ファイルが作成されます。ファイルが既に存在する場合、誤って上書きしないようにエラーで終了します。

**自動検出**: プロジェクトディレクトリ（`uv.lock`がある場所）に`uv-sbom.config.yml`ファイルを配置します。ツールが自動的に検出して読み込みます。

**明示的なパス指定**: `--config` / `-c`で任意の場所の設定ファイルを指定できます。

```bash
# 自動検出される設定ファイル（プロジェクトディレクトリに配置）
uv-sbom

# 明示的な設定ファイルパス
uv-sbom --config ./custom-config.yml
```

**設定ファイルの例**（`uv-sbom.config.yml`）:

```yaml
# 出力形式: json または markdown
format: markdown

# SBOMから除外するパッケージ（ワイルドカード対応）
exclude_packages:
  - "pytest"
  - "mypy"
  - "*-dev"

# CVE脆弱性チェックを無効化（デフォルトは有効）
# check_cve: false

# 脆弱性チェックの深刻度しきい値（low/medium/high/critical）
severity_threshold: high

# 脆弱性チェックのCVSSしきい値（0.0-10.0）
# cvss_threshold: 7.0

# 無視するCVE（オプションで理由を記載可能）
ignore_cves:
  - id: CVE-2024-1234
    reason: "このユースケースでは誤検出"
  - id: CVE-2024-5678
    reason: "ネットワーク設定で緩和済み"

# ライセンスコンプライアンスポリシー
license_policy:
  allow: ["MIT", "Apache-2.0", "BSD-*", "ISC", "PSF-2.0"]
  deny: ["GPL-3.0-only", "GPL-3.0-or-later", "AGPL-*"]
  unknown: "warn"  # "warn" | "deny" | "allow"
```

#### 設定ファイルスキーマリファレンス

| フィールド | 型 | 必須 | 説明 |
|-------|------|----------|-------------|
| `format` | string | No | 出力形式（`json` / `markdown`） |
| `exclude_packages` | string[] | No | パッケージ除外パターン（ワイルドカード対応） |
| `check_cve` | bool | No | CVEチェックを無効化（デフォルト: `true`。`false`に設定すると`--no-check-cve`と同等） |
| `severity_threshold` | string | No | 深刻度しきい値（`low` / `medium` / `high` / `critical`） |
| `cvss_threshold` | number | No | CVSSしきい値（0.0 - 10.0） |
| `ignore_cves` | object[] | No | 無視するCVEのリスト |
| `ignore_cves[].id` | string | Yes | CVE ID（例: `CVE-2024-1234`） |
| `ignore_cves[].reason` | string | No | 無視する理由 |
| `license_policy` | object | No | ライセンスコンプライアンスポリシー設定 |
| `license_policy.allow` | string[] | No | 許可するライセンスパターン（ワイルドカード対応） |
| `license_policy.deny` | string[] | No | 拒否するライセンスパターン（ワイルドカード対応） |
| `license_policy.unknown` | string | No | 不明ライセンスの処理（`warn` / `deny` / `allow`） |

#### 優先度とマージルール

- **CLIの引数が設定ファイルの値を上書き**します（スカラーフィールド: `format`, `severity_threshold`, `cvss_threshold`）
- **`check_cve`** はデフォルトで有効。`--no-check-cve`フラグまたは設定ファイルで`check_cve: false`を指定した場合に無効化（論理AND）
- **`exclude_packages`** はCLIと設定ファイルの両方から**マージ**され、重複が除去されます
- **`ignore_cves`** はCLI（`--ignore-cve`）と設定ファイルの両方から**マージ**され、IDで重複が除去されます（重複時はCLIの指定が優先）
- **`check_license`** はCLIフラグまたは設定ファイルのいずれかで設定されていれば有効化（論理OR、`check_cve`と同様）
- **`--license-allow`** と **`--license-deny`** CLIオプションは設定ファイルの `license_policy.allow` / `license_policy.deny` を**完全に上書き**します（マージされません）

### 特定のCVEを無視する

コマンドラインから`--ignore-cve` / `-i`を使用して特定のCVEを無視できます：

```bash
# CLIから特定のCVEを無視
uv-sbom --ignore-cve CVE-2024-1234 --ignore-cve CVE-2024-5678

# 短縮形
uv-sbom -i CVE-2024-1234 -i CVE-2024-5678

# 設定ファイルとCLIの無視設定を組み合わせ（両方がマージされます）
uv-sbom --config ./config.yml -i CVE-2024-9999
```

### 脆弱性のチェック

CVE脆弱性チェックはデフォルトで**有効**になっています。[OSV (Open Source Vulnerability) データベース](https://osv.dev)を使用してパッケージの既知のセキュリティ脆弱性を自動的にチェックします。

```bash
# Markdown出力で脆弱性をチェック（デフォルトで有効）
uv-sbom --format markdown

# 脆弱性レポートをファイルに保存
uv-sbom --format markdown --output SBOM.md

# 除外パターンと組み合わせて使用
uv-sbom --format markdown -e "pytest" -e "*-dev"
```

#### CVEチェックを無効にする

CVEチェックを無効にするには `--no-check-cve` フラグを使用します：

```bash
# CVEチェックなしでSBOMを生成
uv-sbom --format markdown --no-check-cve

# CVEチェックなしでCycloneDX JSONを生成
uv-sbom --no-check-cve
```

> **注:** `--check-cve`フラグは非推奨です。CVEチェックはデフォルトで有効になったため、このフラグは不要です。後方互換性のために引き続き動作しますが、将来のリリースで削除される予定です。使用するとstderrに非推奨警告が表示されます。

### ライセンスコンプライアンスチェック

`--check-license`オプションを使用して、設定可能なライセンスポリシーに対してパッケージをチェックできます：

```bash
# ライセンスコンプライアンスチェックを有効化（設定ファイルのポリシーを使用）
uv-sbom --check-license --format markdown

# インラインポリシーを指定（設定ファイルを上書き）
uv-sbom --check-license --license-allow "MIT,Apache-2.0,BSD-*" --license-deny "GPL-3.0,AGPL-*"

# 脆弱性チェックと組み合わせ
uv-sbom --check-license --severity-threshold high
```

**動作の仕組み:**
- **拒否リストが許可リストより優先**: ライセンスが両方のリストにマッチする場合、拒否されます
- **ワイルドカードパターン**: `BSD-*`、`AGPL-*`等のパターンマッチングに対応（大文字小文字を区別しない）
- **不明ライセンスの処理**: どちらのリストにもないライセンスの処理方法を設定:
  - `warn`（デフォルト）: 警告として報告するが失敗しない
  - `deny`: 不明ライセンスをポリシー違反として扱う
  - `allow`: 不明ライセンスを黙って許可
- **終了コード**: ポリシー違反が検出された場合、終了コード1を返す

### 脆弱性しきい値オプション

しきい値オプションを使用して、どの脆弱性が終了コード1をトリガーするかを制御できます：

```bash
# すべての脆弱性をチェック（見つかった場合は終了コード1）
uv-sbom --format markdown

# High または Critical の深刻度のみをチェック
uv-sbom --format markdown --severity-threshold high

# Critical の深刻度のみをチェック
uv-sbom --format markdown --severity-threshold critical

# CVSS >= 7.0 のみをチェック
uv-sbom --format markdown --cvss-threshold 7.0

# CVSS >= 9.0（Critical）のみをチェック
uv-sbom --format markdown --cvss-threshold 9.0
```

**しきい値オプション:**
- `--severity-threshold <LEVEL>`: 深刻度レベルでフィルタ（low, medium, high, critical）
- `--cvss-threshold <SCORE>`: CVSSスコアでフィルタ（0.0-10.0）

**注意事項:**
- しきい値オプションは一度に1つのみ使用可能
- `--no-check-cve`との同時使用は不可（CVEチェックが無効の場合、しきい値は意味がないため）
- しきい値以下の脆弱性はレポートに表示されますが、終了コード1はトリガーしません
- `--cvss-threshold`使用時、CVSSスコアのない脆弱性（N/A）はしきい値評価から除外されます

### PyPIリンク検証

`--verify-links`オプションを使用して、ハイパーリンクを生成する前にパッケージがPyPIに存在するかを検証できます。PyPIに存在しないパッケージはプレーンテキストとして表示されます：

```bash
# 検証済みPyPIリンク付きのMarkdownを生成
uv-sbom --format markdown --verify-links

# 他のオプションと組み合わせて使用
uv-sbom --format markdown --verify-links --output SBOM.md
```

**動作:**
- `--verify-links`なし: すべてのパッケージ名にPyPIハイパーリンクを付与（デフォルト、高速）
- `--verify-links`あり: 検証済みのパッケージのみハイパーリンクを付与。未検証のパッケージはプレーンテキスト
- ネットワークエラー時はプレーンテキストにフォールバック（クラッシュなし）
- リクエストは並列実行（最大10同時接続）でパフォーマンスを確保

### CI統合

CI/CDパイプライン統合には脆弱性しきい値を使用します：

```yaml
# GitHub Actionsの例
- name: Generate SBOM
  run: uv-sbom --format markdown --output sbom.md

- name: Security Check (High and Critical only)
  run: uv-sbom --format markdown --severity-threshold high

- name: Security Check (CVSS >= 7.0)
  run: uv-sbom --format markdown --cvss-threshold 7.0
```

```yaml
# GitHub Actions - ライセンスコンプライアンスチェック
- name: License Compliance Check
  run: uv-sbom --check-license --format markdown

- name: Combined Security and License Check
  run: uv-sbom --check-license --severity-threshold high
```

```yaml
# GitLab CIの例
security_scan:
  script:
    - uv-sbom --format markdown --severity-threshold high
  allow_failure: false
```

**重要な注意事項:**
- 脆弱性チェックは**Markdownフォーマットでのみ利用可能**です
- OSV APIへのクエリにはインターネット接続が必要です
- `--dry-run`モードでは利用できません（ネットワーク操作をスキップします）
- 内部パッケージがOSV APIに送信されないようにするには`--exclude`を使用してください

**出力例:**

脆弱性が見つかった場合、Markdown出力に次のようなセクションが追加されます：

```markdown
## Vulnerability Report

**⚠️ Security Issues Detected**

The following packages have known security vulnerabilities:

| Package | Current Version | Fixed Version | CVSS | Severity | CVE ID |
|---------|----------------|---------------|------|----------|--------|
| urllib3 | 2.0.0 | 2.0.7 | 9.8 | 🔴 CRITICAL | CVE-2023-45803 |
| requests | 2.28.0 | 2.31.0 | 7.5 | 🟠 HIGH | CVE-2023-32681 |

---

*Vulnerability data provided by [OSV](https://osv.dev) under CC-BY 4.0*
```

> **注:** 脆弱性レポート内の脆弱性ID（CVE, GHSA, PYSEC, RUSTSECなど）は、`--verify-links`の設定に関係なく常にハイパーリンクとして表示されます。これらのIDはOSVデータベースから取得され、権威ある脆弱性データベース（NVD、GitHub Advisories、OSV.dev）にリンクするため、リンク検証は不要です。

### 脆弱性解決ガイド

CVEチェック（デフォルトで有効）が推移的依存関係で脆弱性を検出すると、uv-sbomは自動的に**脆弱性解決ガイド**を生成します。このセクションは、各脆弱な推移的パッケージがどの直接依存関係から導入されているかを示し、アップグレードすべきパッケージを正確に把握できます。

#### Markdown出力例

```markdown
## Vulnerability Resolution Guide

The following transitive dependencies have known vulnerabilities. The table shows which direct dependency introduces each vulnerable package.

| Vulnerable Package | Current | Fixed Version | Severity | Introduced By (Direct Dep) | Vulnerability ID |
|--------------------|---------|---------------|----------|---------------------------|-----------------|
| urllib3 | 1.26.15 | >= 2.0.7 | 🟠 HIGH | requests (2.31.0) | [CVE-2024-XXXXX](https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX) |
| certifi | 2023.7.22 | >= 2024.2.2 | 🟠 HIGH | requests (2.31.0), httpx (0.25.0) | [CVE-2024-YYYYY](https://nvd.nist.gov/vuln/detail/CVE-2024-YYYYY) |
```

#### CycloneDX JSON出力

CycloneDX形式では、導入元の依存関係が`properties`エントリとして含まれます:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-XXXXX",
      "properties": [
        {
          "name": "uv-sbom:introduced-by",
          "value": "requests@2.31.0"
        }
      ]
    }
  ]
}
```

> **注:** 解決ガイドは**推移的**依存関係の脆弱性についてのみ表示されます。直接依存関係の脆弱性は標準の脆弱性テーブルに表示されます（ユーザーが直接アップグレードできるため）。

### アップグレードアドバイザー（`--suggest-fix`）

`--suggest-fix`を使用すると、各推移的脆弱性を解決するためにどの直接依存関係をどのバージョンにアップグレードすべきかを自動的に提案します（CVEチェックはデフォルトで有効です）。

**必要な条件**:
- CVEチェックが有効（デフォルト。`--no-check-cve`を指定しないこと）
- `uv` CLIのインストール
- プロジェクトディレクトリ内に`pyproject.toml`が存在すること

**使用例**:
```bash
uv-sbom generate --suggest-fix
```

**出力**: 脆弱性解決ガイドに「Recommended Action（推奨アクション）」列が追加されます:
- `⬆️ Upgrade requests → 2.32.3 (resolves urllib3 to 2.2.1)` — アップグレードで脆弱性が解決される場合
- `⚠️ Cannot resolve: latest httpx still pins idna < 3.7` — アップグレードでは解決できない場合
- `❓ Could not analyze: <error>` — シミュレーションに失敗した場合

**付属サンプルで試す**:

```bash
# Upgradable と Unresolvable の両方のケースを示す推移的CVEを含むサンプルプロジェクト
uv-sbom -p examples/suggest-fix-project --suggest-fix -f markdown
```

詳しい手順は [`examples/suggest-fix-project/README-JP.md`](examples/suggest-fix-project/README-JP.md) を参照してください。

**ライセンスコンプライアンスチェックの出力例:**

```markdown
## License Compliance Check

Policy: 3 allowed patterns, 1 denied pattern | Unknown: warn

### Violations (2 found)

| Package | Version | License | Reason |
|---------|---------|---------|--------|
| some-gpl-lib | 1.0.0 | GPL-3.0 | Denied by policy |
| mystery-pkg | 2.1.0 | Unknown | Not in allow list |
```

脆弱性が見つからなかった場合:

```markdown
## Vulnerability Report

**✅ No Known Vulnerabilities**

No security vulnerabilities were found in the scanned packages.

---

*Vulnerability data provided by [OSV](https://osv.dev) under CC-BY 4.0*
```

### uv ワークスペースサポート

[uv ワークスペース](https://docs.astral.sh/uv/concepts/projects/workspaces/)を使うと、共通の `uv.lock` ファイルを持つ複数の Python パッケージをひとつのリポジトリで管理できます。`uv-sbom --workspace` は各メンバーパッケージごとに個別の SBOM を生成し、そのメンバーから到達可能な依存関係のみを反映します。

**こんなときに使う:**
- リポジトリに複数の Python パッケージ（例: `api/`、`worker/`）が含まれている
- セキュリティスキャンやコンプライアンス対応のためにメンバーごとの SBOM が必要

**使用例:**

```bash
# ワークスペースの各メンバーに対して SBOM を生成（デフォルト: CycloneDX JSON）
uv-sbom --workspace --path /path/to/workspace
```

**実行結果の例:**

```
Workspace mode: 2 members found

  Processing: api
  ...
  Processing: worker
  ...

📦 Workspace SBOM Summary
────────────────────────────────────────────────────────────
Member               Output File
────────────────────────────────────────────────────────────
api                  /path/to/workspace/packages/api/sbom.json
worker               /path/to/workspace/packages/worker/sbom.json
────────────────────────────────────────────────────────────
```

各メンバーは、そのメンバーから到達可能なパッケージのみを含む独自の `sbom.json` を取得します。推移的依存関係は含まれますが、他のメンバーに属するパッケージは除外されます。

**他のオプションとの組み合わせ:**

```bash
# 全メンバーを Markdown 形式で出力
uv-sbom --workspace --path examples/workspace --format markdown

# CVE チェックを追加
uv-sbom --workspace --path examples/workspace --check-cve
```

> **注意:** `--workspace` と `--output` は同時に使用できません。ワークスペースモードでは、各メンバーの SBOM は自動的にメンバー自身のディレクトリ内の `sbom.json`（Markdown の場合は `sbom.md`）に書き込まれます。

2 つのメンバーパッケージ（`api` と `worker`）を含む実行可能なデモは [`examples/workspace/`](examples/workspace/) を参照してください。

### dry-runモードで設定を検証する

`--dry-run`オプションを使用して、ツールが外部レジストリと通信する前に設定を検証できます：

```bash
# 除外パターンが正しく動作するか確認
uv-sbom --dry-run -e "internal-*" -e "proprietary-pkg"

# すべてのオプションを含めた設定をテスト
uv-sbom --dry-run --path /path/to/project --format json -e "*-dev"
```

**--dry-runを使用する理由:**
- **除外パターンの検証**: `--exclude`パターンが意図したパッケージを正しく除外しているか確認できます
- **情報漏洩の防止**: ツールがPyPIレジストリと通信する**前に**、機密性の高い内部パッケージが除外されていることを確認できます
- **高速な検証**: ネットワーク通信なしで入力検証が行われます
- **早期エラー検出**: 設定の問題（uv.lockの欠損、無効なパターンなど）を即座に検出できます

**dry-runモードでの動作:**
- ✅ `uv.lock`ファイルを読み込んで解析
- ✅ すべてのコマンドライン引数を検証
- ✅ 除外パターンをチェックし、マッチしないパターンを警告
- ✅ 問題がなければ成功メッセージを出力
- ❌ PyPIからのライセンス取得をスキップ（ネットワーク通信なし）
- ❌ SBOM出力生成をスキップ

## セキュリティ

### 除外パターンの入力検証

`-e`/`--exclude`オプションは、悪意のある入力から保護するために以下のセキュリティ対策を実装しています：

#### 文字制限

パターンには以下の文字のみが許可されています：
- **英数字**: a-z, A-Z, 0-9, Unicode文字/数字
- **ハイフン** (`-`)、**アンダースコア** (`_`)、**ドット** (`.`): パッケージ名で一般的
- **角括弧** (`[`, `]`): パッケージのエクストラ用（例: `requests[security]`）
- **アスタリスク** (`*`): ワイルドカードマッチング用

制御文字、シェルメタキャラクタ、パス区切り文字は以下を防ぐためにブロックされています：
- ターミナルエスケープシーケンスインジェクション
- ログインジェクション攻撃
- コマンドインジェクション（多層防御）

#### パターンの制限

- **最大パターン数**: 1回の実行につき最大64個のパターンを指定可能
- **最大長**: パターンあたり255文字
- **最小内容**: パターンには少なくとも1つの非ワイルドカード文字が必要

これらの制限は、以下によるサービス拒否攻撃を防ぎます：
- 過剰なメモリ消費
- 複雑なパターンマッチングによるCPU枯渇

#### 例

**有効なパターン**:
```bash
uv-sbom -e 'pytest'           # 完全一致
uv-sbom -e 'test-*'           # プレフィックスワイルドカード
uv-sbom -e '*-dev'            # サフィックスワイルドカード
uv-sbom -e 'package[extra]'   # エクストラ付きパッケージ
```

**無効なパターン**（エラーで拒否）:
```bash
uv-sbom -e ''                 # 空のパターン
uv-sbom -e '***'              # ワイルドカードのみ
uv-sbom -e 'pkg;rm -rf /'     # シェルメタキャラクタを含む
uv-sbom -e "$(cat /etc/passwd)" # シェルコマンド置換がブロックされる
```

脅威モデルや攻撃ベクトルを含む詳細なセキュリティ情報については、[SECURITY.md](SECURITY.md)を参照してください。

## コマンドラインオプション

```
Options:
  -f, --format <FORMAT>              出力形式: json または markdown [デフォルト: json]
  -p, --path <PATH>                  プロジェクトディレクトリへのパス [デフォルト: カレントディレクトリ]
  -o, --output <OUTPUT>              出力ファイルパス（指定しない場合は標準出力）
  -e, --exclude <PATTERN>            パッケージ除外パターン（ワイルドカード対応: *）
  -c, --config <PATH>               設定ファイルのパス（指定しない場合はuv-sbom.config.ymlを自動検出）
  -i, --ignore-cve <CVE_ID>         無視するCVE ID（複数回指定可能）
      --lang <LANG>                  人間が読みやすいフォーマットの出力言語: en または ja [デフォルト: en]
      --init                         uv-sbom.config.ymlテンプレートファイルを生成
      --dry-run                      ネットワーク通信や出力生成を行わずに設定を検証
      --verify-links                 ハイパーリンク生成前にPyPIリンクの存在を検証（Markdownフォーマットのみ）
      --no-check-cve                 OSV APIによる既知の脆弱性チェックを無効化（デフォルトは有効）
      --check-cve                    [非推奨] CVEチェックはデフォルトで有効になりました。このフラグは不要です。
                                     後方互換性のために動作しますが、将来のリリースで削除される予定です。
      --severity-threshold <LEVEL>   脆弱性チェックの深刻度しきい値（low/medium/high/critical）
                                     --no-check-cveとの同時使用は不可
      --cvss-threshold <SCORE>       脆弱性チェックのCVSSしきい値（0.0-10.0）
                                     --no-check-cveとの同時使用は不可
      --suggest-fix                  推移的脆弱性を解決するための直接依存関係アップグレードバージョンを提案
                                     --no-check-cveとの同時使用は不可、uvのインストール、プロジェクトディレクトリのpyproject.tomlが必要
      --workspace                    ワークスペースの各メンバーに対して SBOM を生成
                                     --outputとの同時使用は不可
      --check-license                ライセンスコンプライアンスをポリシーに対してチェック
      --license-allow <LIST>         許可するライセンスパターンのカンマ区切りリスト（設定ファイルを上書き）
      --license-deny <LIST>          拒否するライセンスパターンのカンマ区切りリスト（設定ファイルを上書き）
  -h, --help                         ヘルプを表示
  -V, --version                      バージョンを表示
```

## 終了コード

uv-sbomは以下の終了コードを返します：

| 終了コード | 説明 | 例 |
|-----------|-------------|----------|
| 0 | 成功 | SBOMの生成成功、しきい値を超える脆弱性なし、`--help`や`--version`の表示 |
| 1 | 脆弱性またはライセンス違反検出 | しきい値を超える脆弱性検出、ライセンスポリシー違反検出 |
| 2 | 無効なコマンドライン引数 | 不明なオプション、無効な引数の型 |
| 3 | アプリケーションエラー | uv.lockファイルの欠損、無効なプロジェクトパス、無効な除外パターン、ネットワークエラー、ファイル書き込みエラー |

### 脆弱性・ライセンスチェック時の終了コード

CVEチェック（デフォルトで有効）または`--check-license`使用時、終了コードの動作はしきい値設定によって変わります：

| シナリオ | 終了コード |
|----------|-----------|
| 脆弱性が見つからない | 0 |
| 脆弱性が見つかった（しきい値指定なし） | 1 |
| 脆弱性が見つかった、すべてがしきい値以下 | 0 |
| 脆弱性が見つかった、一部がしきい値を超過 | 1 |
| ライセンスポリシー違反が検出された | 1 |
| 併用時: いずれかのチェックが失敗 | 1 |
| 併用時: 両方のチェックが成功 | 0 |

**例：**
```bash
# Low/Mediumの脆弱性があってもHigh/Criticalがなければ終了コード0を返す
uv-sbom --format markdown --severity-threshold high

# CVSS >= 7.0の脆弱性がなければ終了コード0を返す
uv-sbom --format markdown --cvss-threshold 7.0
```

### よくあるエラーシナリオ

**終了コード 3 - アプリケーションエラー:**
```bash
# uv.lockファイルが見つからない
$ uv-sbom --path /path/without/uv-lock
❌ An error occurred:
uv.lock file not found: /path/without/uv-lock/uv.lock
# 終了コード: 3

# 無効な除外パターン（空）
$ uv-sbom -e ""
❌ An error occurred:
Exclusion pattern cannot be empty
# 終了コード: 3

# 無効な除外パターン（無効な文字）
$ uv-sbom -e "pkg;name"
❌ An error occurred:
Exclusion pattern contains invalid character ';' in pattern 'pkg;name'
# 終了コード: 3

# 存在しないプロジェクトパス
$ uv-sbom --path /nonexistent
❌ An error occurred:
Invalid project path: /nonexistent
# 終了コード: 3
```

**終了コード 2 - CLI引数エラー:**
```bash
# 不明なオプション
$ uv-sbom --unknown-option
error: unexpected argument '--unknown-option' found
# 終了コード: 2

# 無効なフォーマット値
$ uv-sbom --format invalid
error: invalid value 'invalid' for '--format <FORMAT>'
# 終了コード: 2
```

### スクリプトでの使用例

```bash
#!/bin/bash

uv-sbom --format json --output sbom.json

case $? in
  0)
    echo "SBOMの生成に成功しました"
    ;;
  1)
    echo "しきい値を超える脆弱性が検出されました"
    exit 1
    ;;
  2)
    echo "無効なコマンドライン引数です"
    exit 2
    ;;
  3)
    echo "アプリケーションエラーが発生しました"
    exit 3
    ;;
esac
```

## 出力例

### Markdown形式

> **注**: Markdown形式のサンプルは[ja-complete v0.1.0](https://github.com/Taketo-Yoda/ja-complete/tree/v0.1.0)のSBOM形式に基づいています。

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

### CycloneDX JSON形式

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

## 要件

- `uv`で管理されており、`uv.lock`ファイルを持つPythonプロジェクト
- PyPIからライセンス情報を取得するためのインターネット接続

## ネットワーク要件

### アクセスする外部ドメイン

`uv-sbom`は、SBOM生成時に以下の外部サービスにHTTPリクエストを送信します：

#### すべての操作で必須:

1. **PyPI (Python Package Index)**
   - ドメイン: `https://pypi.org`
   - 目的: Pythonパッケージのライセンス情報を取得
   - タイミング: すべてのSBOM生成時（`--dry-run`を除く）
   - レート制限: 公式制限なし、ツールはリトライロジックを実装
   - エンドポイント: `/pypi/{package_name}/json`

#### オプション（`--verify-links`使用時）または必須（CVEチェック有効時）:

2. **PyPIリンク検証**
   - ドメイン: `https://pypi.org`
   - 目的: HTTP HEADリクエストでPyPI上のパッケージ存在を検証
   - タイミング: `--verify-links`フラグ使用時のみ
   - レート制限: 最大10同時リクエスト
   - エンドポイント: `/project/{package_name}/`

3. **OSV (Open Source Vulnerability Database)**
   - ドメイン: `https://api.osv.dev`
   - 目的: セキュリティスキャンのための脆弱性情報を取得
   - タイミング: CVEチェック有効時（デフォルト）。`--no-check-cve`で無効化可能
   - レート制限: ツールは10リクエスト/秒の制限を実装
   - エンドポイント:
     - `/v1/querybatch` - 脆弱性IDのバッチクエリ
     - `/v1/vulns/{vuln_id}` - 詳細な脆弱性情報

### ファイアウォール設定

企業のファイアウォールやプロキシの内側にいる場合は、以下のドメインを許可リストに追加してください：

```
# 必須
pypi.org

# CVEチェック用（デフォルトで必須）
api.osv.dev    # --no-check-cveで無効化可能

# オプション（--verify-links使用時）
pypi.org       # --verify-linksでも使用
```

### プロキシ設定

ツールは標準のHTTP/HTTPSプロキシ環境変数を尊重します：

```bash
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1

uv-sbom --format json
```

### オフラインモード

ネットワークリクエストなしで設定を検証するには、`--dry-run`を使用します：

```bash
uv-sbom --dry-run
```

このモードでは：
- `uv.lock`ファイルを検証
- コマンドライン引数を検証
- 除外パターンをチェック
- ライセンス取得をスキップ（PyPIアクセスなし）
- 脆弱性チェックをスキップ（OSVアクセスなし）
- SBOM出力生成をスキップ

## エラーハンドリング

uv-sbomは親切な提案を含む詳細なエラーメッセージを提供します:

- **uv.lockファイルが見つからない**: 修正方法の提案を含む明確なメッセージ
- **無効なプロジェクトパス**: 処理前にディレクトリの存在を検証
- **ライセンス取得の失敗**: 失敗したリクエストを再試行（最大3回）し、処理を継続
- **ファイル書き込みエラー**: ディレクトリの存在と権限を確認
- **進捗追跡**: ライセンス情報取得中のリアルタイム進捗表示

エラーメッセージの例:
```
❌ An error occurred:

uv.lock file not found: /path/to/project/uv.lock

💡 Hint: uv.lock file does not exist in project directory "/path/to/project".
   Please run in the root directory of a uv project, or specify the correct path with the --path option.
```

## トラブルシューティング

### uv.lockファイルが見つからない
`uv.lock`ファイルが含まれるディレクトリでコマンドを実行していることを確認するか、`--path`オプションで正しいプロジェクトディレクトリを指定してください。

### ライセンス情報取得の失敗
一部のパッケージはPyPIからライセンス情報を取得できない場合があります。ツールは以下を行います:
1. 最大3回まで自動的に再試行
2. 他のパッケージの処理を継続
3. 失敗したパッケージの警告を表示
4. 取得に失敗した場合でも、ライセンス情報なしでパッケージを出力に含める

### ネットワークの問題
プロキシやファイアウォールの内側にいる場合は、`https://pypi.org`にアクセスできることを確認してください。ツールはAPIリクエストに10秒のタイムアウトを使用します。

## 開発者向け

### アーキテクチャ

uv-sbomは保守性とテスタビリティのために**ヘキサゴナルアーキテクチャ**（ポート＆アダプター）+ **ドメイン駆動設計（DDD）**で実装されています。

レイヤー、ポート、アダプター、アーキテクチャ決定記録（ADR）の詳細は[ARCHITECTURE-JP.md](ARCHITECTURE-JP.md)を参照してください。

### テストカバレッジ

テストスイートはユニット、統合、エンドツーエンドの各シナリオをカバーしています。

テストの実行方法やコントリビュート方法については[DEVELOPMENT.md](DEVELOPMENT.md)を参照してください。

### 開発環境のセットアップ

リポジトリをクローンした後、gitフックを有効化してください：

```bash
make setup
```

これにより `.githooks/` の `pre-commit`（自動フォーマット）と `pre-push`（フォーマット確認・clippy・テスト）フックが有効になり、すべてのコントリビュータに対してコード品質チェックが自動的に実行されます。

### リファレンス

- [DEVELOPMENT.md](DEVELOPMENT.md) — 開発ガイド
- [ARCHITECTURE-JP.md](ARCHITECTURE-JP.md) — ヘキサゴナルアーキテクチャ + DDD実装の詳細
- [CHANGELOG.md](CHANGELOG.md) — 変更履歴
- [.claude/project-context.md](.claude/project-context.md) — Claude Code用の完全なプロジェクトコンテキスト
- [.claude/instructions.md](.claude/instructions.md) — Claude Code用のコーディングガイドラインと指示

## 帰属表示

### 脆弱性データ

CVEチェックが有効な場合（デフォルト）、このツールは[OSV (Open Source Vulnerability)](https://osv.dev)から脆弱性データを取得します。これは[Creative Commons Attribution 4.0 International License (CC-BY 4.0)](https://creativecommons.org/licenses/by/4.0/)の下で提供されています。

**必要な帰属表示:**
- OSVが提供する脆弱性データ
- 利用可能: https://osv.dev
- ライセンス: CC-BY 4.0

OSVデータベースは、オープンソースソフトウェアの包括的で正確かつアクセスしやすい脆弱性情報を提供するためのオープンな共同プロジェクトです。

## ライセンス

MITライセンス - 詳細は[LICENSE](LICENSE)ファイルを参照してください。

[shield_license]: https://img.shields.io/badge/license-MIT-blue.svg
[license_file]: LICENSE
