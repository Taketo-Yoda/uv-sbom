# abandoned-packages-project

PyPI上の**最新リリースが2年以上前**のPythonパッケージを使用して、`uv-sbom` の `--check-abandoned` 機能を実演するサンプルプロジェクトです。

## 目的

`--check-abandoned` は、ロックされたバージョンの日付ではなく、**パッケージの最新リリース日**をPyPIに問い合わせます。ほとんどのデモプロジェクトは、活発にメンテナンスされているパッケージの古いバージョンをピン留めしています。しかしそれらは最新リリースが最近であるため、放棄されたパッケージとして**フラグが立ちません**。

このプロジェクトは、PyPIレベルで本当にメンテナンスされていないパッケージを使用しています。各パッケージの最新バージョンでさえ何年も前のものです。そのため、`--check-abandoned` を実行すると、閾値に関わらず常に空でない「放棄されたパッケージ」セクションが表示されます。

> ⚠️ これらのパッケージを本番環境で使用しないでください。

## このサンプルに含まれる放棄されたパッケージ

| パッケージ | ロックバージョン | 最新PyPIリリース | 非活動日数（目安） | 備考 |
|-----------|--------------|----------------|-----------------|------|
| docopt  | 0.6.2         | 2014-06-16     | 4400日以上        | `docopt-ng` に引き継がれた |
| nose    | 1.3.7         | 2015-06-02     | 3990日以上        | 公式に非推奨。pytestを使用 |
| pep8    | 1.7.1         | 2017-10-24     | 3100日以上        | `pycodestyle` に改名 |
| Paver   | 1.3.4         | 2017-12-31     | 3050日以上        | アクティブなメンテナなし |

`six`（Paverのtransitive dependency）は活発にメンテナンスされており、放棄されたパッケージセクションには**表示されません**。

## 前提条件

- `uv-sbom` をソースからビルド済み（`cargo build --release`）またはインストール済み
- ネットワークアクセス（パッケージごとに1回PyPI APIを呼び出します）

## 使用方法

### Step 1: 放棄されたパッケージのチェック（デフォルト閾値: 730日）

```bash
# リポジトリルートから実行
uv-sbom -p examples/abandoned-packages-project --check-abandoned -f markdown
```

**期待される放棄されたパッケージセクション:**

```markdown
## Abandoned Packages

Packages whose most recent upstream release exceeds the configured inactivity threshold.
Inactive projects may carry unpatched vulnerabilities and pose long-term maintenance risk.

| Package | Version | Last Release | Days Inactive | Type                |
|---------|---------|--------------|---------------|---------------------|
| docopt  | 0.6.2   | 2014-06-16   | 4346          | Direct dependencies |
| nose    | 1.3.7   | 2015-06-02   | 3995          | Direct dependencies |
| pep8    | 1.7.1   | 2017-10-24   | 3120          | Direct dependencies |
| paver   | 1.3.4   | 2017-12-31   | 3052          | Direct dependencies |
```

### Step 2: カスタム非活動閾値

```bash
uv-sbom -p examples/abandoned-packages-project --check-abandoned \
  --abandoned-threshold-days 365 -f markdown
```

4つのパッケージすべてが引き続き表示されます（最終リリースは3000日以上前）。

### Step 3: CVEチェックとの組み合わせ

```bash
uv-sbom -p examples/abandoned-packages-project --check-abandoned -f markdown
```

## なぜ `sample-project` を使わないのか？

`examples/sample-project/` は活発にメンテナンスされているパッケージの古いバージョン（chardet 3.0.4、idna 2.10 など）をピン留めしています。これらのパッケージは最新リリースが最近であるため、`--check-abandoned` を `sample-project` に対して実行すると、放棄されたパッケージは0件になります。

このプロジェクトは**最新**リリースが古いパッケージを使用しているため、放棄チェックで常にフラグが立ちます。

## 他のサンプルとの比較

| | `examples/abandoned-packages-project` | `examples/sample-project` | `examples/suggest-fix-project` | `examples/workspace` |
|---|---|---|---|---|
| 主な機能 | `--check-abandoned`（特化） | CVE＋ライセンス＋放棄チェック | `--suggest-fix` アップグレードアドバイザー | `--workspace` モード |
| 放棄デモ | ✅ あり（4パッケージ、常にフラグ） | 一部（PyPIの状態に依存） | ❌ 対象外 | ❌ 対象外 |
| 脆弱なパッケージ | なし | 直接依存関係 | 間接依存関係 | N/A |
| 設定ファイル | ❌ なし | ✅ あり（`config/`） | ❌ なし | ❌ なし |
