# Claude Codeへの指示

このファイルは、Claude Codeがこのプロジェクトを扱う際の具体的な指示を含みます。

## プロジェクトの性質

このプロジェクトは**Rust製のCLIツール**で、**ヘキサゴナルアーキテクチャ + DDD**を採用しています:

- 言語: Rust (Edition 2021)
- ビルドシステム: Cargo
- アーキテクチャ: ヘキサゴナル（ポート&アダプター）
- エラーハンドリング: anyhowベース、カスタムエラー型使用
- 依存性注入: Generic-based（静的ディスパッチ）

## アーキテクチャの理解

### レイヤーの責務

1. **ドメイン層** (`sbom_generation/`)
   - 純粋なビジネスロジック
   - I/O操作は一切禁止
   - `std::fs`, `reqwest`などの使用禁止
   - すべて純粋関数として実装

2. **アプリケーション層** (`application/`)
   - ユースケースのオーケストレーション
   - ポートを通じてインフラと通信
   - ビジネスフローの制御

3. **ポート層** (`ports/`)
   - インターフェース定義のみ
   - トレイトとして実装
   - 実装は含まない

4. **アダプター層** (`adapters/`)
   - インフラストラクチャの具体実装
   - ポートを実装
   - I/O操作を実行

5. **共有層** (`shared/`)
   - エラー型
   - 型エイリアス
   - セキュリティ検証関数

### 依存関係のルール

**CRITICAL**: 依存関係の方向を厳守すること

```
Adapters → Application → Domain
    ↓           ↓
  Ports   ←   Ports
```

- ドメイン層は他のレイヤーに依存しない
- アプリケーション層はドメイン層とポート層のみに依存
- アダプター層はポート層を実装

## コード変更時の注意事項

### 1. レイヤー違反の禁止

```rust
// ❌ 悪い例: ドメイン層でI/O操作
// domain/package.rs内
use std::fs;  // NG!!

// ✅ 良い例: ポート経由
// application/use_cases/generate_sbom.rs内
fn execute(&self, request: SbomRequest) -> Result<SbomResponse> {
    // ポート経由でI/O操作
    let content = self.lockfile_reader.read_lockfile(&path)?;
}
```

### 2. エラーハンドリング

ユーザーフレンドリーなメッセージを提供:

```rust
// ❌ 悪い例
return Err(anyhow::anyhow!("Failed"));

// ✅ 良い例
return Err(SbomError::LockfileParseError {
    path: lockfile_path.clone(),
    details: e.to_string(),
}.into());
```

### 3. セキュリティ検証

ファイル操作時は必ず`shared/security.rs`の関数を使用:

```rust
// ✅ 良い例
use crate::shared::security::{validate_regular_file, validate_file_size};

validate_regular_file(path, "uv.lock")?;
validate_file_size(file_size, path, MAX_FILE_SIZE)?;
```

### 4. 型エイリアスの使用

複雑な型には型エイリアスを使用（Clippy警告回避）:

```rust
// ✅ 良い例
pub type PyPiMetadata = (Option<String>, Option<String>, Vec<String>, Option<String>);

fn fetch_license_info(&self, name: &str, version: &str) -> Result<PyPiMetadata>;
```

### 5. テストの追加

すべての新機能にテストを追加:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_feature() {
        // ドメイン層: 純粋関数のテスト
        // アプリケーション層: モックを使用
        // アダプター層: tempfileなどで実環境テスト
    }
}
```

## モジュール別のガイドライン

### sbom_generation/domain/

**責務**: ビジネスロジックの中核
**禁止事項**:
- I/O操作（ファイル、ネットワーク、データベース）
- 外部クレートへの依存（`std`のみ許可）
- 副作用のある操作

**許可事項**:
- バリューオブジェクトの定義
- ドメインサービス（純粋関数）
- ビジネスポリシー

### sbom_generation/services/

**責務**: ドメインサービス
**特徴**:
- すべて純粋関数
- I/O依存なし
- テストが容易

**例**:
```rust
pub struct DependencyAnalyzer;

impl DependencyAnalyzer {
    pub fn analyze(
        project_name: &PackageName,
        dependency_map: &HashMap<String, Vec<String>>,
    ) -> Result<DependencyGraph> {
        // 純粋なアルゴリズム
    }
}
```

### application/use_cases/

**責務**: ワークフローのオーケストレーション
**パターン**: Generic-based DI

```rust
pub struct GenerateSbomUseCase<LR, PCR, LREPO, PR> {
    lockfile_reader: LR,
    project_config_reader: PCR,
    license_repository: LREPO,
    progress_reporter: PR,
}

impl<LR, PCR, LREPO, PR> GenerateSbomUseCase<LR, PCR, LREPO, PR>
where
    LR: LockfileReader,
    PCR: ProjectConfigReader,
    LREPO: LicenseRepository,
    PR: ProgressReporter,
{
    pub fn execute(&self, request: SbomRequest) -> Result<SbomResponse> {
        // オーケストレーション
    }
}
```

### ports/outbound/

**責務**: インターフェース定義
**パターン**: トレイト定義

```rust
pub trait LockfileReader {
    fn read_lockfile(&self, project_path: &Path) -> Result<String>;
}
```

### adapters/outbound/

**責務**: ポートの具体実装
**必須**: セキュリティチェック

**ファイルシステムアダプター**:
```rust
impl LockfileReader for FileSystemReader {
    fn read_lockfile(&self, project_path: &Path) -> Result<String> {
        // セキュリティ検証
        validate_regular_file(&lockfile_path, "uv.lock")?;
        
        // 実装
        self.safe_read_file(&lockfile_path, "uv.lock")
    }
}
```

### shared/

**責務**: 共通機能
**内容**:
- `error.rs`: エラー型定義
- `result.rs`: 型エイリアス
- `security.rs`: セキュリティ検証関数

## セキュリティガイドライン

### ファイル操作のセキュリティ

**必須チェック** (`shared/security.rs`使用):
1. シンボリックリンク検証 - `validate_not_symlink()`
2. 通常ファイル検証 - `validate_regular_file()`
3. ファイルサイズ制限 - `validate_file_size()`

**対策する脅威**:
- 任意ファイル読み取り（シンボリックリンク経由）
- DoS攻撃（巨大ファイル）
- TOCTOU攻撃（二重チェック）
- パストラバーサル

### ネットワーク操作のセキュリティ

**必須実装**:
1. タイムアウト設定
2. リトライ制限
3. レート制限（DoS防止）
4. HTTPS通信

**例** (PyPiLicenseRepository):
```rust
const MAX_RETRIES: u32 = 3;
const TIMEOUT_SECONDS: u64 = 10;
const RATE_LIMIT_MS: u64 = 100;  // 10 req/sec
```

## コーディングスタイル

### 命名規則
- 関数名: `snake_case`
- 型名: `PascalCase`
- 定数: `UPPER_SNAKE_CASE`
- トレイト: `PascalCase`（動詞推奨）

### コメント
- 公開API: `///` ドキュメントコメント必須
- 複雑なロジック: `//` 説明コメント
- セキュリティ関連: `// Security:` プレフィックス

### エラーハンドリング
- `?`演算子を積極的に使用
- `unwrap()`や`expect()`は避ける（テスト以外）
- エラーコンテキストを追加

## テスト戦略

### ドメイン層のテスト
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_logic() {
        // 純粋関数なのでモック不要
        let result = DependencyAnalyzer::analyze(...);
        assert_eq!(result, expected);
    }
}
```

### アプリケーション層のテスト
```rust
#[test]
fn test_use_case() {
    // モックを使用
    let mock_reader = MockLockfileReader { ... };
    let use_case = GenerateSbomUseCase::new(mock_reader, ...);
    
    let result = use_case.execute(request);
    assert!(result.is_ok());
}
```

### アダプター層のテスト
```rust
#[test]
fn test_file_reader() {
    // tempfileで実環境テスト
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("uv.lock");
    fs::write(&file_path, "content").unwrap();
    
    let reader = FileSystemReader::new();
    let result = reader.read_lockfile(temp_dir.path());
    assert!(result.is_ok());
}
```

## パフォーマンス考慮

### ボトルネック
1. PyPI API呼び出し（レート制限あり）
2. ネットワークレイテンシ

### 最適化時の注意
- ベンチマーク計測を必ず行う
- プロファイリング結果に基づく
- 早すぎる最適化を避ける

## ドキュメント更新

新機能追加時に更新すべきファイル:
1. `README.md` - ユーザー向け使用方法
2. `.claude/project-context.md` - アーキテクチャ情報
3. コード内ドキュメントコメント
4. テストケース

## 依存関係の追加

新しい依存関係を追加する場合:

1. **必要性を検討**: 既存で解決できないか確認
2. **最小限の機能**: `features`で必要な機能のみ
3. **適切なレイヤー**: 
   - ドメイン層: `std`のみ
   - アプリケーション層: anyhow, 基本的なユーティリティ
   - アダプター層: I/Oライブラリ許可
4. **ドキュメント更新**: `.claude/project-context.md`を更新

## よくある質問

### Q: 重複コードや複雑な条件分岐を見つけた場合、どうすべきか
A: GoFデザインパターンの適用を検討してください:
1. **重複コードが複数箇所にある場合**:
   - Template Methodパターン: 共通アルゴリズムを抽出
   - Strategyパターン: アルゴリズムの切り替えが必要な場合（例: Issue #9のFormatter選択）
2. **複雑な条件分岐（match/if-else）がある場合**:
   - Strategyパターン: 振る舞いの切り替え
   - Factoryパターン: オブジェクト生成の切り替え
   - Polymorphism: トレイトによる動的ディスパッチ
3. **実装前にGitHub Issueを起票して設計を相談すること**

### Q: 新しいフォーマットを追加したい
A:
1. `ports/outbound/formatter.rs`の`SbomFormatter`トレイトを確認
2. `adapters/outbound/formatters/`に新しいフォーマッターを実装
3. `application/dto/output_format.rs`の`OutputFormat`enumに新しいフォーマット種別を追加
4. `application/factories/formatter_factory.rs`の`FormatterFactory::create()`メソッドを更新
5. `FormatterFactory::progress_message()`を更新（必要に応じて）
6. テスト追加（OutputFormatのFromStrテストとFormatterFactoryのテスト）

### Q: 新しいライセンスソースを追加したい
A:
1. `LicenseRepository`トレイトを実装
2. `adapters/outbound/`に新しいアダプター作成
3. `main.rs`でDI配線
4. テスト追加

### Q: ドメイン層で外部APIを呼びたい
A: **NG!** ポートを定義してアダプターで実装すること

### Q: テストでファイルI/Oが必要
A: `tempfile`クレートを使用してテンポラリファイル作成

### Q: ファイル操作のセキュリティチェックを忘れた場合
A: **必ず修正してください**:
1. `shared/security.rs`の検証関数を使用
2. シンボリックリンク、ファイルサイズ、通常ファイルのチェック
3. テストでセキュリティ違反のケースも確認

## Git/ブランチ戦略

このプロジェクトではGit Flowベースのブランチ戦略を採用しています（詳細は `DEVELOPMENT.md` 参照）。

### 作業前のブランチ確認

**CRITICAL**: コーディング開始前に必ず現在のブランチを確認してください：

```bash
git status
git branch --show-current
```

### ブランチルール

1. **`develop`ブランチで直接作業しない**
   - 必ずfeatureブランチを作成してから作業

2. **`main`ブランチでは絶対に作業しない**
   - mainは本番リリース用

3. **適切なブランチ命名規則**:
   - Feature: `feature/<issue-number>-<short-description>`
   - Bugfix: `bugfix/<issue-number>-<short-description>`
   - Hotfix: `hotfix/<issue-number>-<short-description>`

### 作業開始時のチェックリスト

```bash
# 1. 現在のブランチを確認
git branch --show-current

# 2. developブランチまたはmainブランチの場合、featureブランチを作成
git checkout develop
git pull origin develop
git checkout -b feature/<issue-number>-<description>

# 3. 作業開始
```

### コミット前の確認

すべての変更をコミットする前に：

1. **正しいブランチにいることを確認**
   ```bash
   git branch --show-current
   # feature/*, bugfix/*, または hotfix/* であることを確認
   ```

2. **変更内容を確認**
   ```bash
   git status
   git diff
   ```

3. **品質チェックを実行**（後述）

## Claude Codeでの作業フロー

### 作業開始時

1. **ブランチ確認（必須）**: `git status` で現在のブランチを確認
   - `develop`または`main`の場合 → featureブランチを作成
   - featureブランチの場合 → そのまま作業継続
2. **コンテキスト確認**: `.claude/project-context.md`を読む
3. **アーキテクチャ確認**: レイヤーの責務を理解

### コーディング中

4. **変更箇所の特定**: 適切なレイヤーに変更を加える
5. **デザインパターンの検討**: 実装前にGoFデザインパターンの適用を検討
   - 重複コードや複雑な条件分岐がある場合、適切なパターン（Strategy, Factory, Template Method等）を検討
   - 既存のアーキテクチャパターン（ヘキサゴナル、DDD）との整合性を確認
6. **セキュリティレビュー**: 実装中に以下を確認
   - ファイル操作: `shared/security.rs`の検証関数を使用
   - ネットワーク操作: タイムアウト・リトライ・レート制限の実装
   - 入力検証: ユーザー入力や外部データの適切なバリデーション
   - エラーメッセージ: 機密情報（パス、内部構造等）を含まない
7. **テストの追加**: 新機能には必ずテストを追加
8. **ビルド確認**: `cargo build`
9. **テスト実行**: `cargo test`
10. **品質確認（必須）**:
    - **フォーマットチェック**: `cargo fmt --all -- --check` （エラーが出たら `cargo fmt --all` で修正）
    - **Clippyチェック**: `cargo clippy --all-targets --all-features -- -D warnings` （警告ゼロ必須）

### 作業完了時

11. **ドキュメント更新**: 必要に応じて
12. **ブランチ確認**: コミット前に再度ブランチを確認
13. **コミット**: 適切なコミットメッセージで変更をコミット

**重要**:
- ステップ1のブランチ確認は**作業開始時に必ず実行**すること
- ステップ5のデザインパターン検討は**実装前に必ず実施**すること
- ステップ6のセキュリティレビューは**実装中に継続的に実施**すること
- ステップ10の品質確認は**コーディング完了時に必ず実行**すること
- これらのチェックがパスしない限り、コードは完成していないと見なされます

## 注意事項

### 破壊的変更の禁止
- 公開APIの変更は慎重に
- 既存のCLIオプションを削除・変更しない
- 下位互換性を保つ

### コード品質

**コーディング完了時の必須チェック**:
1. **デザインパターン検証**:
   - 重複コードや複雑な条件分岐にGoFパターンを適用したか確認
   - Strategy, Factory, Template Method, Builder等の適用可能性を検討
   - 既存のアーキテクチャ（ヘキサゴナル、DDD）との整合性を確認
2. **セキュリティ検証**:
   - ファイル操作: `shared/security.rs`の検証関数使用確認
   - ネットワーク操作: タイムアウト、リトライ、レート制限の実装確認
   - 入力検証: ユーザー入力や外部データのバリデーション確認
   - エラーメッセージ: 機密情報の漏洩がないか確認
   - OWASP Top 10の脆弱性（パストラバーサル、インジェクション等）を考慮
3. **フォーマット**: `cargo fmt --all -- --check` がパスすること
4. **Clippy**: `cargo clippy --all-targets --all-features -- -D warnings` で警告ゼロ
5. **テスト**: `cargo test` が全テストパス
6. **テストカバレッジ**: 新機能には必ずテストを追加
7. **ドキュメント**: 公開APIには必ずドキュメントコメント

これらのチェックが全てパスしない限り、コードは完成していません。

### セキュリティ
- ファイル操作: 必ず`shared/security.rs`使用
- ネットワーク操作: タイムアウト・リトライ設定
- エラーメッセージ: 機密情報を含めない

---

最終更新: 2025-01-04

## 変更履歴

- 2025-01-04: Git/ブランチ戦略セクション追加
- 2025-01-04: デザインパターン検討・セキュリティレビューをワークフローに追加
