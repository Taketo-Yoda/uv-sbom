# uv ワークスペースサポート

[メインページに戻る](../../README-JP.md)

[uv ワークスペース](https://docs.astral.sh/uv/concepts/projects/workspaces/)では、単一のリポジトリで共有の `uv.lock` ファイルを持つ複数の Python パッケージを管理できます。`uv-sbom --workspace` は各メンバーパッケージに対して個別の SBOM を生成し、そのメンバーから到達可能な依存関係のみを反映します。

## 目次

- [使用するタイミング](#使用するタイミング)
- [使用方法](#使用方法)
- [集計サマリー](#集計サマリー)
- [ワークスペースルート依存グループ](#ワークスペースルート依存グループ)
- [他のオプションとの併用](#他のオプションとの併用)

---

## 使用するタイミング

- リポジトリに複数の Python パッケージが含まれている場合（例：`api/`、`worker/`）
- 独立したセキュリティスキャンやコンプライアンスレポートのためにメンバーごとの SBOM が必要な場合

## 使用方法

```bash
# ワークスペースメンバーごとに 1 つの SBOM を生成（CycloneDX JSON、デフォルト）
uv-sbom --workspace --path /path/to/workspace
```

**期待される出力:**

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

📊 Workspace Aggregate Summary
────────────────────────────────────────────────────────────
Total actionable CVEs: 28
────────────────────────────────────────────────────────────

⚠️  Warning: Workspace root dependency group(s) not covered by any member SBOM: lint
   Packages reachable only through these groups are not in any SBOM. Add them to --exclude-groups to silence this warning.
```

各メンバーは、そのメンバーから到達可能なパッケージのみを含む独自の `sbom.json` を取得します。推移的依存関係は含まれますが、他のメンバーに属するパッケージは除外されます。

## 集計サマリー

メンバーごとのテーブルの後に、`--workspace` はモノレポ全体の健全性を各メンバーの SBOM ファイルを開かずに把握できる集計サマリーも出力します — CVE の合計数、ライセンスポリシー違反があるメンバー、放置 / 非 PyPI / Python 非互換パッケージがフラグされたメンバーが表示されます。実行で実際に有効化されたチェック（例：`--check-license`）の行のみ表示されます。実行されなかったチェックの行は、空の行であっても表示されません。

## ワークスペースルート依存グループ

仮想ワークスペースルート（`[project]` のないルート `pyproject.toml`）は独自の `[dependency-groups]`（例：リポジトリ全体のツール用の `lint` グループ）を宣言できます。どのメンバー SBOM もこれらのグループをたどらないため、`--workspace` は上記の出力の最後の行のように、除外されていない各ルートグループ名を stderr に警告として出力します（`examples/workspace` はルートで `lint = ["ruff"]` を宣言しています）。メンバーが自身の依存関係を通じて到達するパッケージは、引き続きそのメンバーの SBOM に表示されます。警告を消すには、ルートグループを `--exclude-groups` に追加するか、`--production-only` を使用してください。stdout とメンバーの SBOM ファイルは変更されません。`[project]` を持つルートはそれ自体がメンバーであり、そのグループは自身の SBOM でカバーされます。

## 他のオプションとの併用

```bash
# すべてのメンバーで Markdown 出力
uv-sbom --workspace --path examples/workspace --format markdown

# ライセンスコンプライアンスチェック付き
uv-sbom --workspace --path examples/workspace --check-license
```

```
📊 Workspace Aggregate Summary
────────────────────────────────────────────────────────────
Total actionable CVEs: 28
Members with license policy violations: none
────────────────────────────────────────────────────────────

⚠️  Warning: Workspace root dependency group(s) not covered by any member SBOM: lint
   Packages reachable only through these groups are not in any SBOM. Add them to --exclude-groups to silence this warning.
```

> **注意:** `--workspace` と `--output` は相互排他です。ワークスペースモードでは、各メンバーの SBOM は自動的にメンバー自身のディレクトリ内の `sbom.json`（Markdown の場合は `sbom.md`）に書き込まれます。

実行可能なデモ（2 つのメンバーパッケージ `api` と `worker`）は [`examples/workspace/`](../../examples/workspace/) を参照してください。
