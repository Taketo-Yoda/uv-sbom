# non-pypi-sources-project

Git・プライベートレジストリ・直接URLソースと標準PyPIパッケージを含む実際の`uv.lock`を使用して、
`uv-sbom` の `--check-non-pypi` 機能を実演するサンプルプロジェクトです。

## 目的

`--check-non-pypi` は各パッケージのソースを `uv.lock` から直接分類します。これまで、
非PyPIソースを含むサンプルプロジェクトが1つも存在しなかったため、`sample-project` に対して
このフラグを実行しても、常に空の「PyPI以外のパッケージソース」セクションしか得られませんでした。

このプロジェクトの `uv.lock` は、様々なソース種別を組み合わせて手作業で作成されており、
このフラグを実行すると常に実際の非空の出力が得られます。

## このサンプルに含まれる非PyPIソース

| パッケージ | バージョン | ソース種別 | 直接/間接 | レポートに表示？ |
|-----------|-----------|-----------|----------|----------------|
| acme-analytics-sdk | 1.4.0 | Private Registry | 直接 | ✅ 表示される |
| telemetry-agent | 0.9.2 | Git | 間接 | ✅ 表示される |
| edge-config | 2.1.0 | Direct URL | 間接 | ✅ 表示される |
| vendored-parser | 0.5.0 | Local Path | 直接 | ❌ 表示されない（仕様により除外） |
| requests | 2.32.3 | PyPI | 直接 | ❌ 表示されない（対照用の標準レジストリ） |

## 前提条件

- `uv-sbom` をソースからビルド済み（`cargo build --release`）またはインストール済み
- `--check-non-pypi` 自体はネットワークアクセス不要です — `uv.lock` から直接ソース分類を
  読み取ります。（このサンプルの架空パッケージについてはライセンス情報の取得で404警告が
  表示されますが、これは想定内であり非PyPIレポートには影響しません）

## 使用方法

### Step 1: 非PyPIソース検出

```bash
# リポジトリルートから実行
uv-sbom -p examples/non-pypi-sources-project --check-non-pypi --no-check-cve -f markdown --lang ja
```

**実際にレンダリングされる出力:**

```markdown
## ⚠️ PyPI以外のパッケージソース

3個のパッケージが公式PyPIレジストリ以外から取得されています（直接依存 1件、間接依存 2件）。

| パッケージ | バージョン | ソース種別 | 取得元 |
|-------|-------|-------|-----|
| acme-analytics-sdk | 1.4.0 | Private Registry | https://pypi.acme-corp.example/simple |
| edge-config | 2.1.0 | Direct URL | https://downloads.acme-corp.example/edge-config-2.1.0-py3-none-any.whl |
| telemetry-agent | 0.9.2 | Git | https://github.com/acme-corp/telemetry-agent?rev=9f2c1ab |

> PyPI以外のソースから取得されたパッケージは、PyPIのセキュリティポリシーの対象外である可能性があります。本番環境へのデプロイ前に、各パッケージの取得元を確認してください。
```

`vendored-parser`（Local Path）と `requests`（標準PyPI）は正しく表示**されません**。

### Step 2: 他のチェックと組み合わせ

```bash
uv-sbom -p examples/non-pypi-sources-project --check-non-pypi --check-cve -f markdown
```

`requests==2.32.3` は実在の、現在インストール可能なPyPIリリースであり、実際に現時点で
既知の脆弱性を含む場合があります — 新しいアドバイザリが公開されるたびに出力が変化するため、
Step 1では非PyPIソース検出のみに焦点を当てるために `--no-check-cve` を使用しています。

## なぜpathソースと標準PyPIパッケージはフラグされないのか

`--check-non-pypi` は **Private Registry**、**Git**、**Direct URL** のソースのみを検出対象と
します。ローカルファイルシステムパス（`path = "..."`）とワークスペースメンバーは意図的に
除外されます — これらは通常のuvワークスペース構成で想定される形態であり、サプライチェーン上の
外部リスクとはみなされません。標準PyPIレジストリ（`https://pypi.org/simple`）は定義上
「非PyPI」ではありません。

`vendored-parser` の `path = "vendor/vendored-parser"` の参照先はディスク上に存在する必要は
ありません — `--check-non-pypi` は `uv.lock` からテキストとしてソース分類を読み取るだけで、
パスを解決することはありません。

## なぜ `sample-project` を使わないのか？

`examples/sample-project/uv.lock` には標準PyPIレジストリのソース（とワークスペースルートの
エントリ1件）しか含まれていません。これに対して `--check-non-pypi` を実行しても常に0件と
なるため、この機能を実演できません。

このプロジェクトの `uv.lock` は、フラグされる全ソース種別（`Private Registry`、`Git`、
`Direct URL`）と、除外される2種類（`Local Path`、標準`PyPI`）を対照として示すために、
特別に構築されています。

## 他のサンプルとの比較

| | `examples/non-pypi-sources-project` | `examples/sample-project` | `examples/abandoned-packages-project` | `examples/suggest-fix-project` |
|---|---|---|---|---|
| 主な機能 | `--check-non-pypi`（特化） | CVE＋ライセンス＋放棄チェック | `--check-abandoned`（特化） | `--suggest-fix` アップグレードアドバイザー |
| 非PyPIデモ | ✅ あり（3件フラグ、対照用に2件除外） | ❌ なし（全パッケージがPyPI） | ❌ 対象外 | ❌ 対象外 |
| 脆弱なパッケージ | `requests`（実在の現行CVE） | 直接依存関係 | なし | 間接依存関係 |
| 設定ファイル | ❌ なし | ✅ あり（`config/`） | ❌ なし | ❌ なし |
