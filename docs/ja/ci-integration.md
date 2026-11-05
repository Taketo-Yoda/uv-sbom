# CI 連携

[メインページに戻る](../../README-JP.md)

uv-sbom は、構造化された終了コード、しきい値ベースの脆弱性ゲーティング、GitHub Actions と GitLab CI のすぐに使えるワークフロー例により、CI/CD パイプラインに統合できます。

## 目次

- [CI ワークフロー例](#ci-ワークフロー例)
- [終了コード](#終了コード)
- [脆弱性・ライセンスチェック時の終了コード](#脆弱性ライセンスチェック時の終了コード)
- [よくあるエラーシナリオ](#よくあるエラーシナリオ)
- [スクリプトでの使用](#スクリプトでの使用)
- [エラーハンドリング](#エラーハンドリング)
- [トラブルシューティング](#トラブルシューティング)

---

## CI ワークフロー例

CI/CD パイプライン統合のために脆弱性しきい値を使用します：

```yaml
# GitHub Actions の例
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
# GitHub Actions - 放置パッケージチェック
- name: Abandoned Package Detection
  run: uv-sbom --check-abandoned --format markdown
```

```yaml
# GitLab CI の例
security_scan:
  script:
    - uv-sbom --format markdown --severity-threshold high
  allow_failure: false
```

**重要な注意事項:**
- 脆弱性チェックは **Markdown 形式でのみ利用可能**です
- OSV API へのクエリにはインターネット接続が必要です
- `--dry-run` モードでは利用できません（ネットワーク操作をスキップ）
- 内部パッケージが OSV API に送信されるのを防ぐには `--exclude` を使用してください

**出力例:**

脆弱性が見つかった場合、Markdown 出力に以下のようなセクションが追加されます：

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

> **注意:** 脆弱性レポートの脆弱性 ID（CVE、GHSA、PYSEC、RUSTSEC など）は `--verify-links` に関係なく常にハイパーリンクとしてレンダリングされます。これらの ID は OSV データベースから取得され、権威ある脆弱性データベース（NVD、GitHub Advisories、OSV.dev）にリンクしているため、リンク検証は不要です。

脆弱性が見つからない場合：

```markdown
## Vulnerability Report

**✅ No Known Vulnerabilities**

No security vulnerabilities were found in the scanned packages.

---

*Vulnerability data provided by [OSV](https://osv.dev) under CC-BY 4.0*
```

## 終了コード

uv-sbom は以下の終了コードを返します：

| 終了コード | 説明 | 例 |
|-----------|-------------|----------|
| 0 | 成功 | SBOM が正常に生成、しきい値を超える脆弱性なし、`--help` または `--version` の表示 |
| 1 | 脆弱性またはライセンス違反を検出 | しきい値を超える脆弱性を検出、ライセンスポリシー違反を検出 |
| 2 | 無効なコマンドライン引数 | 不明なオプション、無効な引数型、不正な `--incident` アドバイザリ ID または範囲 |
| 3 | アプリケーションエラー | uv.lock ファイルの欠落、無効なプロジェクトパス、無効な除外パターン、ネットワークエラー、ファイル書き込みエラー、不明な `--incident` アドバイザリ ID |
| 4 | 影響あり、修正未リリース（`--incident` のみ） | プロジェクトがアドバイザリの影響を受けるが、修正が PyPI でまだリリースされていないか修正が存在しない |

## 脆弱性・ライセンスチェック時の終了コード

CVE またはライセンスチェック使用時、しきい値設定に基づいて終了コードの動作が変わります：

| シナリオ | 終了コード |
|----------|-----------|
| 脆弱性なし | 0 |
| 脆弱性あり（しきい値指定なし） | 1 |
| 脆弱性あり、すべてしきい値未満 | 0 |
| 脆弱性あり、一部がしきい値以上 | 1 |
| ライセンスポリシー違反を検出 | 1 |
| 組み合わせ：いずれかのチェックが失敗 | 1 |
| 組み合わせ：両方のチェックが合格 | 0 |

**例:**
```bash
# High/Critical の脆弱性がなければ 0 を返す（Low/Medium があっても）
uv-sbom --format markdown --severity-threshold high

# CVSS >= 7.0 の脆弱性がなければ 0 を返す
uv-sbom --format markdown --cvss-threshold 7.0
```

## よくあるエラーシナリオ

**終了コード 3 - アプリケーションエラー:**
```bash
# uv.lock ファイルの欠落
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

**終了コード 2 - CLI 引数エラー:**
```bash
# 不明なオプション
$ uv-sbom --unknown-option
error: unexpected argument '--unknown-option' found
# 終了コード: 2

# 無効な format 値
$ uv-sbom --format invalid
error: invalid value 'invalid' for '--format <FORMAT>'
# 終了コード: 2
```

## スクリプトでの使用

```bash
#!/bin/bash

uv-sbom --format json --output sbom.json

case $? in
  0)
    echo "SBOM generated successfully"
    ;;
  1)
    echo "Vulnerabilities detected above threshold"
    exit 1
    ;;
  2)
    echo "Invalid command-line arguments"
    exit 2
    ;;
  3)
    echo "Application error occurred"
    exit 3
    ;;
esac
```

## エラーハンドリング

uv-sbom は有用な提案を含む詳細なエラーメッセージを提供します：

- **uv.lock ファイルの欠落**: 修正方法に関する明確なメッセージと提案
- **無効なプロジェクトパス**: 処理前にディレクトリの存在を検証
- **ライセンス取得の失敗**: 失敗したリクエストを最大 3 回リトライし、処理を継続
- **ファイル書き込みエラー**: ディレクトリの存在と権限をチェック
- **進捗追跡**: ライセンス情報取得中にリアルタイムの進捗を表示

エラーメッセージの例：
```
❌ An error occurred:

uv.lock file not found: /path/to/project/uv.lock

💡 Hint: uv.lock file does not exist in project directory "/path/to/project".
   Please run in the root directory of a uv project, or specify the correct path with the --path option.
```

## トラブルシューティング

### uv.lock ファイルが見つからない
`uv.lock` ファイルを含むディレクトリでコマンドを実行しているか確認するか、`--path` オプションで正しいプロジェクトディレクトリを指定してください。

### ライセンス情報の取得に失敗する
一部のパッケージでは PyPI からのライセンス情報取得に失敗する場合があります。ツールは：
1. 自動的に最大 3 回リトライ
2. 他のパッケージの処理を継続
3. 失敗したパッケージについて警告を表示
4. ライセンス情報なしでパッケージを出力に含める

### ネットワークの問題
プロキシやファイアウォールの背後にいる場合、`https://pypi.org` にアクセスできることを確認してください。ツールは API リクエストに 10 秒のタイムアウトを使用します。ファイアウォールとプロキシの設定については [ネットワーク要件](network.md) を参照してください。
