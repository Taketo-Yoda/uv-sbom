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

### ディレクトリ構成

```
src/
├── main.rs                          # エントリーポイント（DI配線のみ）
├── lib.rs                           # ライブラリルート
│
├── sbom_generation/                 # ドメイン層（純粋なビジネスロジック）
│   ├── domain/                      # ドメインモデル
│   │   ├── package.rs               # Packageバリューオブジェクト
│   │   ├── dependency_graph.rs      # DependencyGraph集約
│   │   ├── license_info.rs          # LicenseInfoバリューオブジェクト
│   │   └── sbom_metadata.rs         # SBOMメタデータ
│   ├── services/                    # ドメインサービス
│   │   ├── dependency_analyzer.rs   # 推移的依存関係分析（純粋関数）
│   │   └── sbom_generator.rs        # SBOMメタデータ生成
│   └── policies/                    # ビジネスポリシー
│       └── license_priority.rs      # ライセンス選択優先順位ルール
│
├── application/                     # アプリケーション層（ユースケース）
│   ├── use_cases/
│   │   └── generate_sbom.rs         # GenerateSbomUseCase<LR,PCR,LREPO,PR>
│   └── dto/
│       ├── sbom_request.rs          # リクエストDTO
│       └── sbom_response.rs         # レスポンスDTO
│
├── ports/                           # ポート（インターフェース定義）
│   ├── inbound/
│   │   └── sbom_generation_port.rs  # インバウンドポート
│   └── outbound/                    # アウトバウンドポート
│       ├── lockfile_reader.rs       # LockfileReaderトレイト
│       ├── project_config_reader.rs # ProjectConfigReaderトレイト
│       ├── license_repository.rs    # LicenseRepositoryトレイト
│       ├── formatter.rs             # SbomFormatterトレイト
│       ├── output_presenter.rs      # OutputPresenterトレイト
│       └── progress_reporter.rs     # ProgressReporterトレイト
│
├── adapters/                        # アダプター層（インフラストラクチャ実装）
│   ├── inbound/
│   │   └── cli_adapter.rs           # CLI引数解析＋オーケストレーション
│   └── outbound/
│       ├── filesystem/              # ファイルシステムアダプター
│       │   ├── file_reader.rs       # FileSystemReader（セキュリティチェック付き）
│       │   └── file_writer.rs       # FileSystemWriter, StdoutPresenter
│       ├── network/                 # ネットワークアダプター
│       │   └── pypi_client.rs       # PyPiLicenseRepository
│       ├── formatters/              # フォーマッターアダプター
│       │   ├── cyclonedx_formatter.rs  # CycloneDxFormatter
│       │   └── markdown_formatter.rs   # MarkdownFormatter
│       └── console/                 # コンソールアダプター
│           ├── stdout_presenter.rs  # StdoutPresenter
│           └── stderr_progress_reporter.rs  # StderrProgressReporter
│
└── shared/                          # 共有カーネル
    ├── error.rs                     # ドメインエラー（SbomError）
    ├── result.rs                    # 型エイリアス（Result<T>）
    └── security.rs                  # セキュリティ検証関数（NEW）
```

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
