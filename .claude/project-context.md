# uv-sbom プロジェクトコンテキスト

このファイルは、Claude Codeや他の開発者がプロジェクトの完全なコンテキストを理解するためのものです。

## プロジェクト概要

**uv-sbom** は、Pythonのパッケージマネージャー[uv](https://github.com/astral-sh/uv)で管理されているプロジェクトから、SBOM (Software Bill of Materials) を生成するRust製のCLIツールです。

### 主要な目的
- uvプロジェクトの依存関係を可視化
- セキュリティ監査やコンプライアンスのためのSBOM生成
- ライセンス情報の自動収集と報告
- 直接依存と推移的依存の分析

### バージョン情報
- 現在のバージョン: 0.1.0
- Rust Edition: 2021
- CycloneDX仕様: 1.6
- アーキテクチャ: ヘキサゴナルアーキテクチャ + DDD

## 技術スタック

### 主要な依存関係
```toml
# CLI & 設定
clap = "4.5"                 # CLI引数パース (derive機能使用)

# シリアライゼーション
serde = "1.0"                # シリアライゼーション (derive機能使用)
serde_json = "1.0"           # JSON処理
toml = "0.8"                 # TOML (uv.lock) パース

# エラーハンドリング
anyhow = "1.0"               # エラーハンドリング

# HTTP クライアント
reqwest = "0.12"             # HTTP クライアント (blocking機能使用)

# ユーティリティ
chrono = "0.4"               # 日時処理
uuid = "1.10"                # UUID生成 (v4機能使用)

# テスト
tempfile = "3.8"             # テンポラリファイル作成
```

## アーキテクチャ: ヘキサゴナルアーキテクチャ + DDD

### アーキテクチャの原則

このプロジェクトは**ヘキサゴナルアーキテクチャ（ポート&アダプターパターン）**と**ドメイン駆動設計（DDD）**を採用しています。

**主な利点**:
1. **テスタビリティ**: ドメインロジックがI/Oから分離されており、モックで簡単にテスト可能
2. **保守性**: 関心の分離が明確で、コードの位置が分かりやすい
3. **柔軟性**: インフラストラクチャの実装を容易に差し替え可能
4. **叫ぶアーキテクチャ**: ディレクトリ構造がシステムの目的を表現

### レイヤー構成

プロジェクトは以下の4つの主要レイヤーで構成されています：

1. **ドメイン層** (`sbom_generation/`)
   - 純粋なビジネスロジック、インフラストラクチャ依存なし
   - バリューオブジェクト、集約、ドメインサービス、ポリシー

2. **アプリケーション層** (`application/`)
   - ユースケースのオーケストレーション
   - DTO（Data Transfer Objects）、ファクトリー

3. **ポート層** (`ports/`)
   - インターフェース定義（トレイト）
   - インバウンド/アウトバウンドポート

4. **アダプター層** (`adapters/`)
   - インフラストラクチャの具体実装
   - ファイルシステム、ネットワーク、フォーマッター、コンソール

5. **共有カーネル** (`shared/`)
   - エラー型、セキュリティ検証など

**詳細なディレクトリ構造**: [ARCHITECTURE-JP.md](../ARCHITECTURE-JP.md) を参照

## 最近の変更履歴（2025-01-02）

### コードレビュー指摘事項対応

**High優先度**:
- ✅ Clippy警告解消（型エイリアス追加）
  - `DependencyMap = HashMap<String, Vec<String>>`
  - `LockfileParseResult = (Vec<Package>, DependencyMap)`
  - `PyPiMetadata = (Option<String>, Option<String>, Vec<String>, Option<String>)`

**Medium優先度**:
- ✅ 不要なclone()削減
  - `DependencyGraph::new()`から未使用パラメータ削除
  - `DependencyAnalyzer::analyze()`のシグネチャ簡素化
- ✅ #[allow(dead_code)]整理
  - `LicenseFetchError`と`OutputGenerationError`にドキュメント追加
  - ライブラリAPI用として保持する理由を明記
- ✅ セキュリティ検証コード共通化
  - `shared/security.rs`モジュール新規作成
  - file_reader.rsとfile_writer.rsのリファクタリング

**テスト結果**:
- 全テスト合格
- 警告なし

## リソース

### ドキュメント
- `README.md`: ユーザー向け使用方法
- `.claude/instructions.md`: Claude Code向け指示

### 外部リファレンス
- [CycloneDX 1.6仕様](https://cyclonedx.org/docs/1.6/)
- [PyPI JSON API](https://warehouse.pypa.io/api-reference/json.html)
- [uv](https://github.com/astral-sh/uv)

---

最終更新: 2025-01-02
