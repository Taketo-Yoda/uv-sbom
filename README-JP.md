# uv-sbom

[![GitHub release](https://img.shields.io/github/release/Taketo-Yoda/uv-sbom.svg)](https://github.com/Taketo-Yoda/uv-sbom/releases) [![PyPI - Version](https://img.shields.io/pypi/v/uv-sbom-bin?logo=python&logoColor=white&label=PyPI)](https://pypi.org/project/uv-sbom-bin/) [![Crates.io Version](https://img.shields.io/crates/v/uv-sbom?logo=rust&logoColor=white)](https://crates.io/crates/uv-sbom)
[![shield_license]][license_file] [![CI](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/ci.yml/badge.svg)](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/ci.yml)

[English](README.md) | [日本語](README-JP.md)

----

[uv](https://github.com/astral-sh/uv)で管理されているPythonプロジェクトのSBOM（Software Bill of Materials）を生成します。

## 機能

- 📦 `uv.lock`ファイルを解析して依存関係情報を抽出
- 🔍 PyPIからライセンス情報を自動取得（リトライロジック付き）
- 📊 複数のフォーマットに対応:
  - **CycloneDX 1.6** JSON形式（標準SBOM形式）
  - **Markdown**形式（直接依存と推移的依存を明確に分離）
- 🚀 高速でスタンドアロン - Rustで実装
- 💾 標準出力またはファイルへ出力
- 🛡️ 堅牢なエラーハンドリングと親切なエラーメッセージ・提案
- 📈 ライセンス情報取得時の進捗表示
- 🏗️ **ヘキサゴナルアーキテクチャ**（ポート＆アダプター）+ **ドメイン駆動設計**による保守性とテスタビリティ
- ✅ 包括的なテストカバレッジ（ユニット、統合、E2E）

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

2026年1月1日時点で、CycloneDX公式ツールはまだuvを直接サポートしていません。Pythonプロジェクトの SBOMを生成する場合:

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

[crates.io](https://crates.io/crates/uv-sbom)からインストール:

```bash
cargo install uv-sbom
```

### uv tool（Pythonユーザー向け）

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

## コマンドラインオプション

```
Options:
  -f, --format <FORMAT>    出力形式: json または markdown [デフォルト: json]
  -p, --path <PATH>        プロジェクトディレクトリへのパス [デフォルト: カレントディレクトリ]
  -o, --output <OUTPUT>    出力ファイルパス（指定しない場合は標準出力）
  -e, --exclude <PATTERN>  パッケージ除外パターン（ワイルドカード対応: *）
  -h, --help               ヘルプを表示
  -V, --version            バージョンを表示
```

## 終了コード

uv-sbomは以下の終了コードを返します：

| 終了コード | 説明 | 例 |
|-----------|-------------|----------|
| 0 | 成功 | SBOMの生成成功、`--help`や`--version`の表示 |
| 1 | アプリケーションエラー | uv.lockファイルの欠損、無効なプロジェクトパス、無効な除外パターン、ネットワークエラー、ファイル書き込みエラー |
| 2 | 無効なコマンドライン引数 | 不明なオプション、無効な引数の型 |

### よくあるエラーシナリオ

**終了コード 1 - アプリケーションエラー:**
```bash
# uv.lockファイルが見つからない
$ uv-sbom --path /path/without/uv-lock
❌ An error occurred:
uv.lock file not found: /path/without/uv-lock/uv.lock
# 終了コード: 1

# 無効な除外パターン（空）
$ uv-sbom -e ""
❌ An error occurred:
Exclusion pattern cannot be empty
# 終了コード: 1

# 無効な除外パターン（無効な文字）
$ uv-sbom -e "pkg;name"
❌ An error occurred:
Exclusion pattern contains invalid character ';' in pattern 'pkg;name'
# 終了コード: 1

# 存在しないプロジェクトパス
$ uv-sbom --path /nonexistent
❌ An error occurred:
Invalid project path: /nonexistent
# 終了コード: 1
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
    echo "アプリケーションエラーが発生しました"
    exit 1
    ;;
  2)
    echo "無効なコマンドライン引数です"
    exit 2
    ;;
esac
```

## 出力例

### Markdown形式

> **注**: Markdown形式のサンプルは[ja-complete v0.1.0](https://github.com/Taketo-Yoda/ja-complete/tree/v0.1.0)のSBOM形式に基づいています。

```markdown
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

#### オプション（`--check-cve`使用時のみ）:

2. **OSV (Open Source Vulnerability Database)**
   - ドメイン: `https://api.osv.dev`
   - 目的: セキュリティスキャンのための脆弱性情報を取得
   - タイミング: `--check-cve`フラグ使用時のみ
   - レート制限: ツールは10リクエスト/秒の制限を実装
   - エンドポイント:
     - `/v1/querybatch` - 脆弱性IDのバッチクエリ
     - `/v1/vulns/{vuln_id}` - 詳細な脆弱性情報

### ファイアウォール設定

企業のファイアウォールやプロキシの内側にいる場合は、以下のドメインを許可リストに追加してください：

```
# 必須
pypi.org

# オプション（--check-cveのみ）
api.osv.dev
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

## ドキュメント

### ユーザー向け
- [README-JP.md](README-JP.md) - ユーザードキュメント
- [LICENSE](LICENSE) - MITライセンス

### 開発者向け
- [DEVELOPMENT.md](DEVELOPMENT.md) - 開発ガイド
- [ARCHITECTURE-JP.md](ARCHITECTURE-JP.md) - **ヘキサゴナルアーキテクチャ + DDD実装**（レイヤー、ポート、アダプター、テスト戦略、ADR）
- [CHANGELOG.md](CHANGELOG.md) - 変更履歴

### Claude Codeユーザー向け
- [.claude/project-context.md](.claude/project-context.md) - Claude Code用の完全なプロジェクトコンテキスト
- [.claude/instructions.md](.claude/instructions.md) - Claude Code用のコーディングガイドラインと指示

これらのファイルは、Claude Codeを使用したAI支援開発のための包括的なコンテキストを提供します。

## ライセンス

MITライセンス - 詳細は[LICENSE](LICENSE)ファイルを参照してください。

[shield_license]: https://img.shields.io/badge/license-MIT-blue.svg
[license_file]: LICENSE
