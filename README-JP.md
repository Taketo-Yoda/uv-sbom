# uv-sbom

[![GitHub release](https://img.shields.io/github/release/Taketo-Yoda/uv-sbom.svg)](https://github.com/Taketo-Yoda/uv-sbom/releases) [![GitHub Downloads](https://img.shields.io/github/downloads/Taketo-Yoda/uv-sbom/total?logo=github&logoColor=white)](https://github.com/Taketo-Yoda/uv-sbom/releases) [![PyPI - Version](https://img.shields.io/pypi/v/uv-sbom-bin?logo=python&logoColor=white&label=PyPI)](https://pypi.org/project/uv-sbom-bin/) [![PyPI - Downloads](https://img.shields.io/pypi/dm/uv-sbom-bin?logo=pypi&logoColor=white)](https://pypi.org/project/uv-sbom-bin/) [![Crates.io Version](https://img.shields.io/crates/v/uv-sbom?logo=rust&logoColor=white)](https://crates.io/crates/uv-sbom) [![Crates.io Downloads](https://img.shields.io/crates/d/uv-sbom?logo=rust&logoColor=white)](https://crates.io/crates/uv-sbom)
[![shield_license]][license_file] [![CI](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/ci.yml/badge.svg)](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/ci.yml)
[![Dependabot Updates](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/dependabot/dependabot-updates) [![CodeQL](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/github-code-scanning/codeql)

[English](README.md) | [日本語](README-JP.md)

----

**[uv](https://github.com/astral-sh/uv) で管理された Python プロジェクト向けの SBOM 生成ツール。読みやすい出力と、すぐ対応に使えるサプライチェーン分析を提供します。**

uv-sbom は `uv.lock` を読み取り、本番ランタイムの依存関係に絞った SBOM を Markdown または CycloneDX 1.6 JSON で生成します。脆弱性スキャン、ライセンス検査、インシデント対応など、サプライチェーンの各種チェックもコマンド1つで実行できます。

## 機能概要

```bash
uv-sbom -p examples/suggest-fix-project --suggest-fix -f markdown
```

1回の実行で、コンポーネント一覧、脆弱性レポート（修正ガイダンス付き）、アップグレード推奨をまとめて出力します。

```markdown
## サマリー

| 項目 | 件数 | ステータス |
|------|------|-----------|
| 直接依存 | 2 | ✅ |
| 間接依存 | 9 | ✅ |
| 脆弱性（閾値以上） | 32 | ❌ |

## 脆弱性レポート

| パッケージ | 現バージョン | 修正バージョン | CVSS | 深刻度 | 脆弱性 ID |
|-----------|-------------|--------------|------|--------|----------|
| urllib3 | 2.0.4 | 2.6.3 | 7.5 | 🟠 HIGH | GHSA-38jv-5279-wg99 |
| h11 | 0.14.0 | 0.16.0 | 9.1 | 🔴 CRITICAL | GHSA-vqfr-h8mv-ghfj |
| ...

## 脆弱性解決ガイド

| 脆弱パッケージ | 現バージョン | 修正バージョン | 深刻度 | 導入元（直接依存） | 推奨アクション |
|---------------|------------|--------------|--------|-----------------|--------------|
| urllib3 | 2.0.4 | 2.0.6 | 🟡 MEDIUM | requests (2.31.0) | ⬆️ requests → 2.32.3 へアップグレード |
| h11 | 0.14.0 | 0.16.0 | 🔴 CRITICAL | httpx (0.24.1) | ⬆️ httpx → 0.28.1 へアップグレード |
```

## uv-sbom の特長

- **uv.lock ネイティブ**：`uv.lock` を直接読み取り、本番ランタイムの依存関係のみを対象とします。仮想環境やビルド時の依存は不要です。
- **Markdown 中心の実用的な出力**：PR に貼り付けたりレポートに使える表形式で出力します。脆弱性ごとに、どの直接依存が原因か、依存チェーン全体を表示します。
- **サプライチェーンチェックを網羅**：CVE スキャン、ライセンス検査、放置パッケージ検出、取り下げバージョン検出、非 PyPI ソース検出、Python バージョン互換性、悪用可能性の優先順位付け（EPSS + CISA KEV）、インシデント対応、依存差分を1コマンドで実行できます。

## クイックスタート

### インストール

```bash
# Cargo（Rust ユーザー）
cargo install uv-sbom

# uv tool（Python ユーザー）
uv tool install uv-sbom-bin

# pip
pip install uv-sbom-bin
```

ビルド済みバイナリは [GitHub Releases](https://github.com/Taketo-Yoda/uv-sbom/releases) ページで macOS (Apple Silicon, Intel)、Linux (x86_64)、Windows 向けに提供しています。

### 基本コマンド

```bash
# 脆弱性スキャン付き Markdown SBOM を生成（CVE チェックはデフォルトで有効）
uv-sbom --format markdown --output SBOM.md

# CycloneDX JSON SBOM を生成（現在のデフォルト、v5.0.0 で Markdown に変更予定）
uv-sbom --format json --output sbom.json

# 特定のアドバイザリを確認：影響は？パッチは出た？何を実行？
uv-sbom --incident GHSA-v845-jxx5-vc9f
```

> **注意 (v5.0.0):** 現在のリリースではデフォルトの出力形式は JSON ですが、v5.0.0 で Markdown に変更されます。`--format` も設定ファイルの `format` キーも指定されていない場合、uv-sbom は stderr に非推奨警告を出力します（stdout は変更なし）。JSON 出力を維持するには `--format json` を指定するか、設定ファイルで `format: json` を設定してください。[設定 →](docs/ja/configuration.md)

### 出力言語

```bash
# 日本語 Markdown 出力
uv-sbom --format markdown --lang ja
```

対応言語は `en`（デフォルト）と `ja` です。`--lang` オプションはセクション見出し、表の列名、ステータスラベルに影響します。パッケージ名、CVE ID、SPDX 識別子は常に元の形式のままです。

## 機能ハイライト

### SBOM 生成

`uv.lock` から Markdown または CycloneDX 1.6 JSON 形式の SBOM（Software Bill of Materials）を生成します。Markdown 出力では直接依存と間接依存を明確に分離し、全パッケージのライセンス、説明、SHA-256 データを含みます。[出力例 →](docs/ja/cli-reference.md#出力例)

### セキュリティスキャン

[OSV データベース](https://osv.dev) 経由の CVE 脆弱性チェックが**デフォルトで有効**です。深刻度や CVSS スコアによるフィルタリング、脆弱性ベースラインによる既知の検出結果の抑制、どの直接依存をアップグレードすべきかの解決ガイドを提供します。[セキュリティチェック →](docs/ja/security-checks.md)

### インシデント対応 (`--incident`)

新しいアドバイザリが公開されたとき、コマンド1つでプロジェクトへの影響有無、修正版が PyPI に公開済みか、試行解決で検証済みの `uv lock --upgrade-package` コマンドを確認できます。解決できない場合はガイダンスを提示します。終了コードを利用すればパッチ待ちの自動化も容易です。[インシデント対応 →](docs/ja/incident-response.md)

### サプライチェーンチェック

- **ライセンスコンプライアンス** (`--check-license`)：ワイルドカード対応の許可/拒否リスト。[詳細 →](docs/ja/security-checks.md#ライセンスコンプライアンスチェック)
- **放置パッケージ検出** (`--check-abandoned`)：設定可能な期間内に PyPI リリースがないパッケージを検出。[詳細 →](docs/ja/security-checks.md#放置パッケージ検出)
- **取り下げバージョン検出** (`--check-yanked`)：PyPI で取り下げられたロック済みバージョンを報告。[詳細 →](docs/ja/security-checks.md#取り下げバージョン検出)
- **非 PyPI ソース検出** (`--check-non-pypi`)：git、URL、プライベートレジストリからのソースを識別。[詳細 →](docs/ja/security-checks.md#非-pypi-ソース検出)
- **Python バージョン互換性** (`--target-python`)：ターゲット Python バージョンに対する `Requires-Python` 制約を検査。[詳細 →](docs/ja/security-checks.md#python-バージョン互換性チェック)
- **悪用可能性の優先順位付け** (`--check-exploitability`)：EPSS スコアと CISA KEV ステータスで CVE を補強。[詳細 →](docs/ja/security-checks.md#悪用可能性の優先順位付け---check-exploitability)

### 依存関係インサイト

- **Explain** (`--explain <PACKAGE>`)：直接依存からの全パスをトレース。[詳細 →](docs/ja/dependency-insight.md#依存関係の説明---explain)
- **ツリー** (`--show-dependency-tree`)：依存グラフの ASCII ツリー表示。[詳細 →](docs/ja/dependency-insight.md#依存関係ツリーの可視化---show-dependency-tree)
- **差分** (`--diff <REF>`)：ロックファイルのバージョン比較（CVE デルタ付き）。[詳細 →](docs/ja/dependency-insight.md#依存関係の差分---diff)
- **アップグレードアドバイザー** (`--suggest-fix`)：アップグレードをシミュレーションし、解決できない間接依存の脆弱性に `constraint-dependencies` による回避策を提案。[詳細 →](docs/ja/dependency-insight.md#アップグレードアドバイザー---suggest-fix)

### ワークスペースサポート

`--workspace` でワークスペースメンバーごとの SBOM を生成し、全メンバーの集計サマリーを表示します。[ワークスペース →](docs/ja/workspace.md)

### CI 統合

構造化された終了コード、深刻度/CVSS しきい値、GitHub Actions と GitLab CI のすぐに使えるサンプルを提供します。[CI 統合 →](docs/ja/ci-integration.md)

### 設定

`uv-sbom.config.yml` ファイルで全オプションのデフォルト値を設定できます。`--init` でテンプレートを生成できます。CLI 引数は常に設定ファイルより優先されます。[設定 →](docs/ja/configuration.md)

## スコープと CycloneDX との主な違い

### SBOM スコープ

本ツールは **uv.lock** ファイルの内容に基づいて SBOM を生成します。以下の依存関係を含みます。

- 直接ランタイム依存
- 間接ランタイム依存
- 開発依存（uv.lock にロックされている場合）

**含まれないもの**

- ビルドシステム依存（例：hatchling、setuptools）
- 公開ツール（例：twine、build）
- uv.lock にロックされていない仮想環境内のみの依存

### CycloneDX 公式ツールとの比較

公式 cyclonedx-python ライブラリは `.venv` から読み取り、`uv.lock` をサポートしていません。uv 自体は `uv export --format cyclonedx1.5` で CycloneDX SBOM をエクスポートできます。

| 観点 | uv-sbom（本ツール） | CycloneDX 公式ツール |
|------|---------------------|---------------------|
| **データソース** | `uv.lock` ファイル | `.venv` 仮想環境 |
| **スコープ** | 本番ランタイム依存のみ | ビルド/開発ツール含む全サプライチェーン |
| **パッケージ数** | 少ない（例：16 パッケージ） | 多い（例：38+ パッケージ） |
| **ユースケース** | 本番セキュリティスキャン | 包括的サプライチェーン監査 |
| **精度** | ロックされた依存を反映 | インストール済みパッケージを反映 |

### 用途別のツール選択

- **本番セキュリティスキャン**：`uv-sbom` で本番にデプロイされる依存のみに注目。Markdown レポート、CVE チェック、アップグレードパスを提供します。
- **uv.lock からの CycloneDX SBOM**：`uv export --format cyclonedx1.5` でロックファイルから直接 CycloneDX 形式の SBOM を生成できます。
- **包括的サプライチェーン監査**：CycloneDX 公式ツールでインストール済み環境から開発・ビルド時依存をすべて含めます。
- **規制コンプライアンス**：要件を確認してください。場合によっては包括的なアプローチが必要です。

uv-sbom は本番アプリケーションに同梱されないビルド時依存を除外することで、セキュリティスキャンのノイズを低減します。

## ドキュメント

| ドキュメント | 説明 |
|-------------|------|
| [セキュリティチェック](docs/ja/security-checks.md) | CVE スキャン、しきい値、ベースライン、ライセンス、放置、取り下げ、非 PyPI、Python 互換性、悪用可能性 |
| [インシデント対応](docs/ja/incident-response.md) | `--incident` モード：アドバイザリ検索、ワークスペース、手動範囲、終了コード、パッチ待ち |
| [依存関係インサイト](docs/ja/dependency-insight.md) | `--explain`、`--show-dependency-tree`、`--diff`、解決ガイド、アップグレードアドバイザー |
| [設定](docs/ja/configuration.md) | 設定ファイル、スキーマリファレンス、マージルール、除外パターン、依存グループ |
| [CI 統合](docs/ja/ci-integration.md) | GitHub Actions、GitLab CI、終了コード、スクリプティング、エラーハンドリング |
| [ワークスペース](docs/ja/workspace.md) | `--workspace` モード、集計サマリー、ルート依存グループ |
| [ネットワーク](docs/ja/network.md) | 外部ドメイン、ファイアウォール、プロキシ、オフラインモード |
| [CLI リファレンス](docs/ja/cli-reference.md) | コマンドラインオプション一覧、出力形式の例 |

## 要件

- `uv` で管理された Python プロジェクト（`uv.lock` ファイルが必要）
- PyPI からのライセンス情報取得にインターネット接続が必要

## 開発者向け

### アーキテクチャ

uv-sbom は**ヘキサゴナルアーキテクチャ**（ポートとアダプター）と**ドメイン駆動設計（DDD）** を採用しています。保守性とテスト容易性を重視した設計です。

詳細は [ARCHITECTURE.md](ARCHITECTURE.md) を参照してください。

### 開発環境セットアップ

リポジトリをクローンした後、git フックを有効化します。

```bash
make setup
```

`.githooks/` の `pre-commit`（自動フォーマット）と `pre-push`（fmt チェック、clippy、テスト）フックが有効になり、コード品質チェックが自動実行されます。

### リファレンス

- [DEVELOPMENT.md](DEVELOPMENT.md)：開発ガイド
- [ARCHITECTURE.md](ARCHITECTURE.md)：ヘキサゴナルアーキテクチャ + DDD 実装詳細
- [CHANGELOG.md](CHANGELOG.md)：変更履歴
- [.claude/project-context.md](.claude/project-context.md)：Claude Code 向けプロジェクトコンテキスト
- [.claude/instructions.md](.claude/instructions.md)：Claude Code 向けコーディングガイドライン

## 帰属表示

### 脆弱性データ

本ツールはデフォルトで [OSV (Open Source Vulnerability)](https://osv.dev) から脆弱性データを取得します。このデータは [Creative Commons Attribution 4.0 International License (CC-BY 4.0)](https://creativecommons.org/licenses/by/4.0/) の下で提供されています。脆弱性チェックを無効にするには `--no-check-cve` を使用してください。

**必須帰属表示**

- 脆弱性データは OSV より提供
- URL: https://osv.dev
- ライセンス: CC-BY 4.0

### 悪用可能性データ

`--check-exploitability` 使用時、本ツールは以下のソースからデータを取得します。

- **EPSS (Exploit Prediction Scoring System)** by [FIRST.org](https://www.first.org/epss/)：CVE の悪用可能性を確率でスコアリング。詳細は https://www.first.org/epss を参照。
- **CISA KEV (Known Exploited Vulnerabilities)** catalog by [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)：活発な悪用が確認された CVE の公式リスト（パブリックドメイン、CC0）。

## ライセンス

MIT License - 詳細は [LICENSE](LICENSE) ファイルを参照してください。

[shield_license]: https://img.shields.io/badge/license-MIT-blue.svg
[license_file]: LICENSE
