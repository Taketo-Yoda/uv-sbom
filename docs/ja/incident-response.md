# インシデント対応 (`--incident`)

[メインページに戻る](../../README-JP.md)

新しいアドバイザリが発表された際、`--incident` は 1 つのコマンドでプロジェクトに対する 3 つの質問に回答します：**影響を受けるか、パッチは公開されているか、何を実行すればよいか？** 推奨されるアップグレードコマンドは `uv.lock` に対するドライラン解決で検証されます（ロックファイルは変更されません）。アップグレードが解決できない場合は、代わりにガイダンスが表示されます。

## 目次

- [クイックスタート](#クイックスタート)
- [アドバイザリの手動監視をやめる](#アドバイザリの手動監視をやめる)
- [受け入れ可能な ID](#受け入れ可能な-id)
- [出力構造](#出力構造)
- [ワークスペース (`--workspace`)](#ワークスペース---workspace)
- [手動範囲（アドバイザリが OSV に未登録の場合）](#手動範囲アドバイザリが-osv-に未登録の場合)
- [終了コード](#終了コード)
- [スコープオプションと相互排他](#スコープオプションと相互排他)

---

## クイックスタート

```bash
uv-sbom --incident GHSA-v845-jxx5-vc9f
```

[`examples/suggest-fix-project`](../../examples/suggest-fix-project) に対する実際の出力（終了コード `1`）：

````markdown
## Incident Report: GHSA-v845-jxx5-vc9f

- **Aliases**: CVE-2023-43804, PYSEC-2023-192
- **Severity**: MEDIUM
- **Summary**: `Cookie` HTTP header isn't stripped on cross-origin redirects
- **Overall verdict**: Affected — fix released

### 1. Impact

- **urllib3** 2.0.4 — Affected — fix released (transitive dependency)
  - Dependency path(s):
    - `requests → urllib3`

### 2. Patch status

- **urllib3**: fixed in 2.0.6 — released

### 3. Next action

**urllib3** — Verified by a dry-run resolution (your uv.lock was not modified):
```sh
uv lock --upgrade-package urllib3==2.0.6
uv sync
```
````

終了コードが、あなた（またはスクリプト）に次のアクションを伝えます：

| 終了コード | 判定 | 次のアクション |
|-----------|---------|-----------------|
| `0` | 影響なし | 何もしない |
| `1` | 影響あり、修正リリース済み | **Next action** のコマンドを実行 |
| `4` | 影響あり、修正未リリース | 修正を待って、後で再チェック（下記で自動化） |

## アドバイザリの手動監視をやめる

`--incident` は、プロジェクトが影響を受けているが脆弱性を修正するバージョンがまだリリースされていない場合、終了コード `4` で終了します。スクリプトやスケジューラに待機を任せましょう。例えば、[`wait-for-patch.sh`](../../examples/incident-response/wait-for-patch.sh) をプロジェクトルートにコピーし、実行可能にして、1 時間ごとにチェックさせます：

```bash
POLL_INTERVAL=3600 ./wait-for-patch.sh GHSA-v845-jxx5-vc9f
```

[`examples/incident-response/`](../../examples/incident-response/) には、このスクリプトを含む 2 つのすぐに使えるオプションが同梱されています：

- [`wait-for-patch.sh`](../../examples/incident-response/wait-for-patch.sh): 修正がリリースされるまでチェックを繰り返し、レポートを表示し、オプションで `ON_FIX_COMMAND`（通知、アップグレード PR など）を実行します。
- [`incident-watch.yml`](../../examples/incident-response/incident-watch.yml): スケジュールされた GitHub Actions ワークフロー。待機中は「still waiting」で成功し、修正がリリースされるとジョブサマリーにレポートを表示して失敗します。

uv-sbom は何も監視しません。cron ジョブや CI スケジュールが再実行し、毎回回答します。`uv.lock` を変更することはありません。なお、OSV が新しく発表されたアドバイザリをインデックスするまでに時間がかかる場合があります。それまでは、影響を受ける範囲を自分で指定してください（[#963](https://github.com/Taketo-Yoda/uv-sbom/issues/963)）。

## 受け入れ可能な ID

`GHSA-`、`PYSEC-`、`CVE-`、`OSV-`、`MAL-` で始まる ID が使用できます。プレフィックスは大文字小文字を区別しません。それ以外の値は手動範囲として読み取られ（下記参照）、いずれにも該当しない値は終了コード `2` で拒否されます。要求したレコードに PyPI パッケージがリストされていない場合（`CVE-` ID では一般的）、uv-sbom は `GHSA-` 次に `PYSEC-` エイリアスをたどり、レポートがどの ID から解決されたかを記録します。

```bash
# GHSA、PYSEC、CVE、OSV、MAL ID を検索
uv-sbom --incident GHSA-v845-jxx5-vc9f

# CVE ID は自動的に GHSA/PYSEC レコードに解決されます
uv-sbom --incident CVE-2023-43804 -p path/to/project

# 自動化用に JSON、またはレポートをファイルに保存
uv-sbom --incident GHSA-v845-jxx5-vc9f --format json
uv-sbom --incident GHSA-v845-jxx5-vc9f --output incident.md
```

## 出力構造

レポートは **デフォルトで Markdown** です（JSON がデフォルトの SBOM 生成とは異なります）。3 つのセクションで構成されます：

1. **Impact** — アドバイザリが名前を挙げた各パッケージ、そのロックされたバージョン、判定、直接依存か推移的依存か（依存パス付き）。
2. **Patch status** — 修正バージョンと PyPI でリリースされているかどうか。
3. **Next action** — コピー＆ペーストできる `uv lock --upgrade-package <name>==<fixed>` + `uv sync` コマンド。事前にドライラン解決で検証され、`uv.lock` は変更されません。アップグレードが解決できない場合、または修正がリリースされていない場合は、代わりにガイダンスが表示されます。ブロックしているパッケージ自体が直接依存の場合、修正バージョンを許可するよう `pyproject.toml` のバージョン要件を緩和するガイダンスが表示されます。

`examples/suggest-fix-project` に対する出力例（終了コード `1`）：

````markdown
## Incident Report: GHSA-v845-jxx5-vc9f

- **Aliases**: CVE-2023-43804, PYSEC-2023-192
- **Severity**: MEDIUM
- **Summary**: `Cookie` HTTP header isn't stripped on cross-origin redirects
- **Overall verdict**: Affected — fix released

### 1. Impact

- **urllib3** 2.0.4 — Affected — fix released (transitive dependency)
  - Dependency path(s):
    - `requests → urllib3`

### 2. Patch status

- **urllib3**: fixed in 2.0.6 — released

### 3. Next action

**urllib3** — Verified by a dry-run resolution (your uv.lock was not modified):
```sh
uv lock --upgrade-package urllib3==2.0.6
uv sync
```
````

## ワークスペース (`--workspace`)

uv ワークスペースルートで `--incident <ID> --workspace` を使用すると、すべてのメンバーを 1 回の実行でチェックし、**1 つの統合レポート**を出力します：アドバイザリの見出し、各メンバーの判定と依存パスを含むメンバーごとの `1. Impact` サブセクション、共有の `2. Patch status` と `3. Next action` セクション（ワークスペースは 1 つの `uv.lock` を共有するため、アップグレードコマンドはすべてのメンバーで同じ）、そして最後に「N of M members affected」行が表示されます。アドバイザリとその PyPI リリースステータスは実行ごとに 1 回取得され、メンバーごとではありません。ドライラン解決はワークスペースルートに対して実行されます。終了コードは最もアクション可能なメンバーの判定です（下記と同じテーブルを使用）。メンバーごとの `sbom.*` ファイルは書き込まれず、レポートは常に stdout に出力されます（`--workspace` は `--output` と併用できません）。

```bash
uv-sbom --incident GHSA-82w8-qh3p-5jfq --workspace -p examples/workspace
```

`examples/workspace` に対する出力。`api` メンバーのみが（`fastapi` 経由で）`starlette` に到達します（終了コード `1`）：

````markdown
## Incident Report: GHSA-82w8-qh3p-5jfq

- **Aliases**: CVE-2026-54283, PYSEC-2026-249
- **Severity**: HIGH
- **Summary**: Starlette: request.form() limits silently ignored for application/x-www-form-urlencoded enable DoS
- **Overall verdict**: Affected — fix released

### 1. Impact

#### Member: api

- **Verdict**: Affected — fix released
- **starlette** 1.0.0 — Affected — fix released (transitive dependency)
  - Dependency path(s):
    - `fastapi → starlette`

#### Member: worker

- **Verdict**: Not affected

None of the affected packages (starlette) are reachable from this member.

### 2. Patch status

- **starlette**: fixed in 1.3.1 — released

### 3. Next action

**starlette** — Verified by a dry-run resolution (your uv.lock was not modified):
```sh
uv lock --upgrade-package starlette==1.3.1
uv sync
```

**1 of 2 members affected**: api
````

**インシデントモードでのワークスペースルート依存グループ:** `--workspace` と同様（[uv ワークスペースサポート](workspace.md) を参照）、`--incident --workspace` は除外されていない各仮想ルートの `[dependency-groups]` グループ名を stderr に警告として出力します。これは、どのメンバースコープもこれらのグループをたどらず、これらを通じてのみ到達可能なパッケージはアドバイザリに対してチェックされないためです。警告は進捗行の後、レポートの前に出力され、実行が成功した場合のみ表示されます。stdout のレポート（Markdown または JSON）と終了コードは変更されないため、`--format json | jq` は引き続き機能します。`--exclude-groups`（または `--production-only`）にルートグループを追加すると警告が消えます。上記コマンドの stderr の末尾：

```
⚠️  Warning: Workspace root dependency group(s) not covered by any member SBOM: lint
   Packages reachable only through these groups are not in any SBOM. Add them to --exclude-groups to silence this warning.
```

## 手動範囲（アドバイザリが OSV に未登録の場合）

公開後の最初の数時間は、アドバイザリがまだ OSV に登録されていない場合があり、ID では何も検索できません。セキュリティアナウンスメントは通常、影響を受ける範囲をプレーンテキストで記載します（「2.0.6 より前のバージョンが影響を受けます」）。ID の代わりにその範囲を渡すことができます：パッケージ名の直後に 1 つ以上のカンマ区切りの指定子を続けます。

```bash
uv-sbom --incident "foo<2.3.2"          # 2.3.2 未満が影響あり、2.3.2 が修正
uv-sbom --incident "foo>=2.0,<2.3.2"    # 2.0 から 2.3.2 未満が影響あり
uv-sbom --incident "foo<=2.3.1"         # 2.3.1 以下が影響あり、修正は不明
```

| 指定子 | 意味 |
|-----------|---------|
| `>=X` | 最初の影響を受けるバージョン（オプション。なしの場合、上限未満のすべてのバージョンが影響あり） |
| `<X` | 修正バージョン。パッチステータスと検証済みアップグレードコマンドはアドバイザリ ID と同様に機能 |
| `<=X` | 最後の影響を受けるバージョン。修正は不明のため、判定は「no fix available」（終了コード `4`） |

- **引数をクォートしてください。** シェルでは `<` は入力リダイレクションです：`uv-sbom --incident foo<2.3.2` は `2.3.2` というファイルを読もうとします。
- `>=`、`<`、`<=` のみ受け入れられ、下限と上限はそれぞれ最大 1 つです（`<` と `<=` の同時指定は不可）。他の演算子（`==`、`!=`、`~=`、`>`、`===`）、ベアパッケージ名、バージョンを含まない範囲（例：`"foo>=2.3,<2.0"`）は終了コード `2` で拒否され、推測されません。
- `>=` のみの場合も、判定は「no fix available」（終了コード `4`）です。
- 1 回の実行につき 1 つの範囲です。複数のリリースラインでの修正には、範囲ごとにコマンドを 1 回実行してください。
- OSV リクエストは行われません。レポートヘッダーには範囲が表示され、ユーザーが提供したものであり脆弱性データベースに対して検証されていない旨が記載されます。JSON 出力では `source` は `"manual"`（アドバイザリ ID の場合は `"osv"`）で、`advisory_id` に範囲が格納されます。
- `--workspace`、`--format json`、`--lang ja` と併用でき、アドバイザリ ID と同じ終了コードが使用されます。

`examples/suggest-fix-project` に対する出力例（終了コード `1`）：

````markdown
## Incident Report (manual range): `urllib3<2.0.6`

⚠️ This affected range was supplied by you. It is not taken from a vulnerability database and has not been verified.

- **Overall verdict**: Affected — fix released

### 1. Impact

- **urllib3** 2.0.4 — Affected — fix released (transitive dependency)
  - Dependency path(s):
    - `requests → urllib3`

### 2. Patch status

- **urllib3**: fixed in 2.0.6 — released

### 3. Next action

**urllib3** — Verified by a dry-run resolution (your uv.lock was not modified):
```sh
uv lock --upgrade-package urllib3==2.0.6
uv sync
```
````

## 終了コード

| 判定 | 終了コード |
|---------|-----------|
| 影響なし（PyPI パッケージを含まないアドバイザリを含む） | 0 |
| 影響あり、修正リリース済み | 1 |
| 影響あり、修正未リリースまたは修正なし | 4 |
| 不明なアドバイザリ ID、ネットワークエラー、その他のアプリケーションエラー | 3 |
| 不正なアドバイザリ ID または範囲、またはフラグの競合 | 2 |

## スコープオプションと相互排他

**使用可能なスコープオプション:** `--path`、`--exclude`、`--exclude-groups`、`--production-only`、`--output`（`--workspace` とは不可）、`--format`、`--lang`、`--config`。設定ファイルの `exclude_packages` と `exclude_groups` も適用されます。

**無視される設定キー:** 設定ファイルの `format` はインシデントモードでは使用されません。`--format` のみが出力を変更します。ただし、設定ファイルの `format` 値が不正な場合は、モード分岐の前に設定検証が実行されるため、引き続き拒否されます（終了コード `3`）。脆弱性、ライセンス、メンテナンス、互換性チェックキー（`check_cve`、`severity_threshold`、`cvss_threshold`、`ignore_cves`、`check_license`、`license_policy`、`check_abandoned`、`check_non_pypi`、`check_exploitability`、`target_python`、`suggest_fix`、`baseline_file`）も無視されます。

**相互排他:** `--incident` は `--diff`、`--init`、`--dry-run`、`--explain`、`--show-dependency-tree`、`--no-check-cve`、`--baseline`、`--update-baseline`、`--suggest-fix`、`--check-license`、`--check-abandoned`、`--check-non-pypi`、`--check-exploitability`、`--target-python`、`--severity-threshold`、`--cvss-threshold`、`--ignore-cve`、`--verify-links` と併用できません。`--workspace` とは併用可能です（上記参照）。

**設定ファイルキー:** なし。`--incident` は意図的に CLI 専用です：単一のアドバイザリ（または範囲）に関する 1 回限りのクエリであり、永続的なポリシー設定ではありません。
