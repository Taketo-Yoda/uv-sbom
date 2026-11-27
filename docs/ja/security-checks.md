# セキュリティチェック

[メインページに戻る](../../README-JP.md)

uv-sbom は SBOM 生成と同時にセキュリティおよびサプライチェーンの各種チェックを実行できます。ここでは各チェックの設定と出力形式を説明します。

## 目次

- [脆弱性チェック](#脆弱性チェック)
- [CVE チェックの無効化](#cve-チェックの無効化)
- [脆弱性しきい値オプション](#脆弱性しきい値オプション)
- [悪意のあるパッケージ](#悪意のあるパッケージ)
- [脆弱性ベースライン](#脆弱性ベースライン)
- [ライセンスコンプライアンスチェック](#ライセンスコンプライアンスチェック)
- [放置パッケージ検出](#放置パッケージ検出)
- [取り下げバージョン検出](#取り下げバージョン検出)
- [非 PyPI ソース検出](#非-pypi-ソース検出)
- [Python バージョン互換性チェック](#python-バージョン互換性チェック)
- [悪用可能性の優先順位付け (`--check-exploitability`)](#悪用可能性の優先順位付け---check-exploitability)
- [PyPI リンク検証](#pypi-リンク検証)
- [除外パターンの入力バリデーション](#除外パターンの入力バリデーション)

---

## 脆弱性チェック

CVE 脆弱性チェックは [OSV (Open Source Vulnerability) データベース](https://osv.dev) を使用して**デフォルトで有効**です。特別なフラグは不要です。

```bash
# Markdown 出力で脆弱性をチェック（CVE チェックは自動実行）
uv-sbom --format markdown

# 脆弱性レポートをファイルに保存
uv-sbom --format markdown --output SBOM.md

# 除外パターンと組み合わせ
uv-sbom --format markdown -e "pytest" -e "*-dev"

# CVE チェックを無効化
uv-sbom --format markdown --no-check-cve
```

## CVE チェックの無効化

CVE 脆弱性チェックはデフォルトで有効です。無効にするには `--no-check-cve` フラグを使用します。

```bash
# CVE チェックなしで SBOM を生成
uv-sbom --format markdown --no-check-cve

# 設定ファイルで無効化
# check_cve: false  (uv-sbom.config.yml 内)
```

> **注意:** `--no-check-cve` は `--severity-threshold`、`--cvss-threshold`、`--suggest-fix` と併用できません。

## 脆弱性しきい値オプション

しきい値を指定すると、条件を満たす脆弱性が見つかった場合にのみ終了コード 1 が返されます。

```bash
# すべての脆弱性をチェック（見つかった場合は終了コード 1）
uv-sbom --format markdown

# High または Critical のみチェック
uv-sbom --format markdown --severity-threshold high

# Critical のみチェック
uv-sbom --format markdown --severity-threshold critical

# CVSS >= 7.0 のみチェック
uv-sbom --format markdown --cvss-threshold 7.0

# CVSS >= 9.0（Critical）のみチェック
uv-sbom --format markdown --cvss-threshold 9.0
```

**しきい値オプション**
- `--severity-threshold <LEVEL>`：重大度レベルでフィルタリング（low, medium, high, critical）
- `--cvss-threshold <SCORE>`：CVSS スコアでフィルタリング（0.0–10.0）

**注意事項**
- しきい値オプションは同時に1つしか使用できません
- `--no-check-cve` とは併用できません
- しきい値未満の脆弱性はレポートに表示されますが、終了コード 1 にはなりません
- `--cvss-threshold` 使用時、CVSS スコアのない脆弱性（N/A）はしきい値評価から除外されます

## 悪意のあるパッケージ

OSV の悪意のあるパッケージアドバイザリ（ID が `MAL-` で始まるもの。プライマリ ID またはエイリアスのいずれか）は、`--severity-threshold` や `--cvss-threshold` の設定に関係なく、常に終了コード 1 で実行を失敗させます。マルウェアには CVSS スコアがないため、しきい値フィルタリングではすべて通過してしまうからです。

これらのアドバイザリは[脆弱性ベースライン](#脆弱性ベースライン)に書き込まれず、既存のベースラインエントリがあっても抑制されません。意図的に受け入れるには `--ignore-cve` または `ignore_cves` で正確なプライマリ ID を指定してください。

Markdown レポートでは、脆弱性セクションの先頭に専用ブロックとして表示されます。各アドバイザリのサマリーとパッケージ削除の指示が記載され、通常の脆弱性テーブルには重複表示されません。

## 脆弱性ベースライン

`--baseline` を使用すると、以前に受け入れた脆弱性の検出結果を抑制できます。ベースラインファイルは `(package, version, vulnerability_id)` のタプルを記録します。完全一致のみが抑制対象です。パッケージバージョンを更新すると、以前ベースラインに登録された検出結果も新規として扱われます。

```bash
# 初回実行：現在の検出結果からベースラインファイルを生成
uv-sbom --baseline .uv-sbom-baseline.json --update-baseline

# 以降の実行：既知の検出結果を抑制、新しいものは終了コード 1 をトリガー
uv-sbom --baseline .uv-sbom-baseline.json
```

ベースラインファイルは `version` キーと `entries` 配列を持つ JSON ドキュメントです。

```json
{
  "version": 1,
  "entries": [
    {
      "package": "requests",
      "version": "2.25.0",
      "id": "GHSA-9wx4-h78v-vm56"
    }
  ]
}
```

**`--update-baseline`** は、現在の（フィルタリングされていない）すべての検出結果でベースラインファイルを書き換えます。既知の CVE をまとめて受け入れる際に使用してください。`--baseline` が必要です。悪意のあるパッケージアドバイザリ（`MAL-`）は記録も抑制もされません。[悪意のあるパッケージ](#悪意のあるパッケージ)を参照してください。

検出結果が抑制された場合、Markdown の脆弱性セクションに脚注が含まれます。

> _Note: 3 previously-baselined finding(s) suppressed._

**設定ファイルでの指定**

`--baseline` を毎回渡す代わりに、`uv-sbom.config.yml` で `baseline_file` を設定できます。

```yaml
baseline_file: .uv-sbom-baseline.json
```

**相互排他**

`--baseline` は `--no-check-cve` と併用できません。ベースラインの照合には脆弱性チェックが必要です。

**CI ワークフロー**

```bash
# 受け入れ済みの検出結果を抑制しつつ、新しい脆弱性をチェック
uv-sbom --baseline .uv-sbom-baseline.json --severity-threshold high -f markdown -o report.md

# レビュー後、現在のすべての検出結果をベースラインに受け入れ
uv-sbom --baseline .uv-sbom-baseline.json --update-baseline
```

## ライセンスコンプライアンスチェック

`--check-license` オプションで、設定可能なライセンスポリシーに対してパッケージを検査します。

```bash
# ライセンスコンプライアンスチェックを有効化（設定ファイルのポリシーを使用）
uv-sbom --check-license --format markdown

# インラインポリシーを使用（設定ファイルを上書き）
uv-sbom --check-license --license-allow "MIT,Apache-2.0,BSD-*" --license-deny "GPL-3.0,AGPL-*"

# 脆弱性チェックと組み合わせ
uv-sbom --check-license --severity-threshold high
```

**仕組み**
- **拒否が許可より優先**：ライセンスが両方のリストに一致する場合、拒否されます
- **ワイルドカードパターン**：`BSD-*`、`AGPL-*` などのパターンマッチングが可能（大文字小文字を区別しません）
- **不明なライセンスの処理**：どちらのリストにもないライセンスの扱いを設定できます
  - `warn`（デフォルト）：警告として報告するが失敗しない
  - `deny`：不明なライセンスを違反として扱う
  - `allow`：不明なライセンスを許可する
- **終了コード**：ポリシー違反が検出された場合、終了コード 1 を返します

**出力例**

```markdown
## License Compliance Check

Policy: 3 allowed patterns, 1 denied pattern | Unknown: warn

### Violations (2 found)

| Package | Version | License | Reason |
|---------|---------|---------|--------|
| some-gpl-lib | 1.0.0 | GPL-3.0 | Denied by policy |
| mystery-pkg | 2.1.0 | Unknown | Not in allow list |
```

## 放置パッケージ検出

`--check-abandoned` オプションで、PyPI で一定期間内に新しいリリースがないパッケージを検出します。CVE がまだ報告されていなくても、メンテナンスされていない依存関係は長期的なリスクとなる可能性があります。

```bash
# 放置パッケージ検出を有効化（デフォルトしきい値：730日 / 約2年）
uv-sbom --check-abandoned --format markdown

# しきい値をカスタム指定（例：365日 / 1年）
uv-sbom --check-abandoned --abandoned-threshold-days 365

# 脆弱性チェックとライセンスチェックと組み合わせ
uv-sbom --check-abandoned --check-license --severity-threshold high
```

**仕組み**
- 各パッケージの PyPI パッケージレベルエンドポイント（`https://pypi.org/pypi/{name}/json`）に問い合わせます
- 最新リリース日を「今日からしきい値を引いた日付」と比較します
- しきい値を超えたパッケージは Markdown 出力の **Abandoned Packages** セクションに表示されます
- パッケージの PyPI メタデータが取得できない場合、そのパッケージをスキップして実行を継続します
- ネットワークアクセスが必要です。パッケージごとに1回の API 呼び出しが追加されます

**出力**
- **サマリーテーブル行**：カウント > 0 の場合 `| Abandoned packages | N | ⚠️ |`、カウント == 0 の場合 `✅`
- **Abandoned Packages セクション**：Package、Version、Last Release 日、Days Inactive、Type（Direct / Transitive）のテーブル
- `--check-abandoned` を指定しない場合、セクションは省略され、サマリー行は `_Abandoned package check skipped._` と表示されます

**設定ファイルでの指定**

```yaml
check_abandoned: true
abandoned_threshold_days: 365  # オプション、デフォルト：730
```

**CI 連携の例**

```yaml
# GitHub Actions - 放置パッケージチェック
- name: Abandoned Package Detection
  run: uv-sbom --check-abandoned --abandoned-threshold-days 730 --format markdown
```

> **注意:** 放置パッケージデータは現在 Markdown のみです。CycloneDX JSON 出力には影響しません。

出力が保証されるデモを実行するには以下を実行してください。

```bash
uv-sbom -p examples/abandoned-packages-project --check-abandoned -f markdown
```

詳細なウォークスルーは [`examples/abandoned-packages-project/README.md`](../../examples/abandoned-packages-project/README.md) を参照してください。

## 取り下げバージョン検出

`--check-yanked` オプションを使用して、ロックされたバージョンが **PyPI で取り下げ（yanked）** されているパッケージを特定します。取り下げは通常、重大なバグ、セキュリティ上の問題、または誤った公開を示しています。ロックファイルに取り下げ済みバージョンを保持しているということは、メンテナーが明示的に撤回したリリースを使用していることを意味します。

```bash
# 取り下げバージョン検出を有効化
uv-sbom --check-yanked --format markdown

# 脆弱性チェックとライセンスチェックと組み合わせ
uv-sbom --check-yanked --check-license --severity-threshold high
```

**仕組み:**
- 各ロック済みパッケージの PyPI バージョンエンドポイント（`https://pypi.org/pypi/{name}/{version}/json`）にクエリします
- バージョンのメタデータが取り下げを示しているか（`info.yanked`）を確認します
- 取り下げ済みパッケージは Markdown 出力の **Yanked Packages** セクションに、メンテナーが提供した理由（ある場合）とともに表示されます
- パッケージの PyPI メタデータが取得できない場合、実行を中断せずにスキップします
- ネットワークアクセスが必要です。パッケージごとに 1 回の API 呼び出しが追加されます

**出力:**
- **サマリーテーブル行**: カウント > 0 の場合 `| Yanked packages | N | ⚠️ |`、カウント == 0 の場合 `✅`
- **Yanked Packages セクション**: Package、Version、Type（Direct / Transitive）、Reason、Status のテーブル
- `--check-yanked` が渡されない場合、セクションは完全に省略され、サマリー行は `_Yanked package check skipped._` を表示します

**設定ファイルでの指定:**
```yaml
check_yanked: true
```

**CI 連携の例:**
```yaml
# GitHub Actions - 取り下げバージョンチェック
- name: Yanked Version Detection
  run: uv-sbom --check-yanked --format markdown
```

> **注意:** 取り下げバージョンデータは現在 Markdown のみです。CycloneDX JSON 出力には影響しません。

出力が保証されるデモを実行するには：

```bash
uv-sbom -p examples/yanked-versions-project --check-yanked --no-check-cve -f markdown
```

**出力例（取り下げ済みパッケージセクション）：**

```markdown
## 取り下げ済みパッケージ

ロックされたバージョンがPyPIから取り下げられたパッケージです。取り下げは通常、重大なバグ、セキュリティ上の問題、または誤った公開を示しています。取り下げられていないバージョンに更新してください。

| パッケージ | バージョン | 種別 | 理由 | 状態 |
|-------|-------|----|----|----|
| requests | 2.32.0 | 直接依存パッケージ | Yanked due to conflicts with CVE-2024-35195 mitigation | ⚠️ |
```

取り下げ済みパッケージが検出されたため、終了コードは **1** になります。

詳細なウォークスルーは [`examples/yanked-versions-project/README.md`](../../examples/yanked-versions-project/README.md) を参照してください。

## 非 PyPI ソース検出

`--check-non-pypi` オプションで、公式 PyPI レジストリ以外のソース（Git リポジトリ、ダイレクト URL、プライベートレジストリ）からインストールされたパッケージを検出します。uv.lock はすべてのパッケージのソースタイプを明示的に記録しているため、uv プロジェクト固有のサプライチェーンリスクを特定するのに役立ちます。

```bash
# 非 PyPI ソース検出を有効化
uv-sbom --check-non-pypi --format markdown
```

**仕組み**
- `uv.lock` からソース分類を直接読み取ります（ネットワークアクセス不要、PyPI API 呼び出しなし）
- **プライベートレジストリ**、**Git** リポジトリ、**ダイレクト URL** からのパッケージを検出します
- ローカルファイルシステムパス（`path = "..."`）とワークスペースメンバーは検出対象外です。これらは uv ワークスペースレイアウトで想定されるものであり、外部サプライチェーンリスクとはみなされません

**出力**
- **Non-PyPI Package Sources セクション**：合計数（direct vs. transitive）とパッケージテーブル（Package、Version、Source Type、Source）が Markdown 出力に表示されます
- `--check-non-pypi` を指定しない場合、またはマッチするパッケージがない場合、セクションは省略されます

**出力例**

```markdown
## ⚠️ Non-PyPI Package Sources

3 packages are sourced from outside the official PyPI registry (1 direct, 2 transitive).

| Package | Version | Source Type | Source |
|---------|---------|-------------|--------|
| acme-analytics-sdk | 1.4.0 | Private Registry | https://pypi.acme-corp.example/simple |
| edge-config | 2.1.0 | Direct URL | https://downloads.acme-corp.example/edge-config-2.1.0-py3-none-any.whl |
| telemetry-agent | 0.9.2 | Git | https://github.com/acme-corp/telemetry-agent?rev=9f2c1ab |

> Packages from non-PyPI sources may not be subject to PyPI's security policies. Review each package's origin before production deployment.
```

**設定ファイルでの指定**

```yaml
check_non_pypi: true
```

> **注意:** 非 PyPI ソース検出にネットワークアクセスは不要です。すべてのデータは `uv.lock` から直接読み取られます。

出力が保証されるデモを実行するには以下を実行してください。

```bash
uv-sbom -p examples/non-pypi-sources-project --check-non-pypi --no-check-cve -f markdown
```

詳細なウォークスルーは [`examples/non-pypi-sources-project/README.md`](../../examples/non-pypi-sources-project/README.md) を参照してください。

## Python バージョン互換性チェック

`--target-python` オプションで、依存関係が PyPI メタデータで宣言した `Requires-Python` 制約がターゲット Python バージョンと互換性があるか検査します。Python バージョンのアップグレード（またはダウングレード）で壊れる依存関係を事前に検出できます。

```bash
# Python 3.8 との互換性をチェック
uv-sbom --target-python 3.8 --format markdown

# 他のチェックと組み合わせ
uv-sbom --target-python 3.8 --check-license --severity-threshold high
```

**仕組み**
- ロックされた各パッケージバージョンについて、PyPI バージョンレベルエンドポイント（`https://pypi.org/pypi/{name}/{version}/json`）に問い合わせます
- パッケージが宣言した `Requires-Python` 制約（PEP 440）をターゲットバージョンと比較します
- 制約が宣言されていないパッケージや、パースできない制約を持つパッケージは互換ありとして扱われます
- パッケージの PyPI メタデータが取得できない場合、そのパッケージをスキップして実行を継続します
- ネットワークアクセスが必要です。パッケージごとに1回の API 呼び出しが追加されます

**出力**
- **Python Compatibility Issues セクション**：非互換パッケージが見つかった場合、合計数（direct vs. transitive）とパッケージテーブル（Package、Version、Requires-Python、Type）が Markdown 出力に表示されます
- **Python Compatibility セクション（問題なし）**：すべてのパッケージがターゲットバージョンと互換性がある場合に表示されます
- `--target-python` を指定しない場合、互換性セクションは表示されません

**出力例**

```markdown
## ⚠️ Python 3.8 Compatibility Issues

11 package(s) incompatible with the target Python version (0 direct, 11 transitive).

| Package | Version | Requires-Python | Type |
|---------|---------|-----------------|------|
| coverage | 7.14.3 | >=3.10 | Transitive dependencies |
| iniconfig | 2.3.0 | >=3.10 | Transitive dependencies |
| librt | 0.11.0 | >=3.9 | Transitive dependencies |
| markupsafe | 3.0.3 | >=3.9 | Transitive dependencies |
| mypy | 2.1.0 | >=3.10 | Transitive dependencies |
| pathspec | 1.1.1 | >=3.9 | Transitive dependencies |
| pluggy | 1.6.0 | >=3.9 | Transitive dependencies |
| pygments | 2.20.0 | >=3.9 | Transitive dependencies |
| pytest | 9.1.1 | >=3.10 | Transitive dependencies |
| pytest-cov | 7.1.0 | >=3.9 | Transitive dependencies |
| typing-extensions | 4.15.0 | >=3.9 | Transitive dependencies |
```

[`examples/sample-project`](../../examples/sample-project) に対して実行した結果です。

```bash
uv-sbom -p examples/sample-project --target-python 3.8 --no-check-cve -f markdown
```

**設定ファイルでの指定**

```yaml
target_python: "3.8"
```

## 悪用可能性の優先順位付け (`--check-exploitability`)

`--check-exploitability` オプションで、CVE の検出結果を実際の悪用データで補強します。データソースは以下の2つです。

- **EPSS** (Exploit Prediction Scoring System)（[FIRST.org](https://www.first.org/epss/) 提供）：今後 30日以内に CVE が悪用される可能性を示すパーセンタイルランキング
- **CISA KEV** (Known Exploited Vulnerabilities) カタログ（[CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) 提供）：活発な悪用が確認された CVE の公式リスト

```bash
# 脆弱性結果を EPSS と KEV データで補強
uv-sbom --check-exploitability --format markdown

# 他のチェックと組み合わせ
uv-sbom --check-exploitability --severity-threshold high --check-license
```

**仕組み**
- FIRST.org EPSS API（`https://api.first.org/data/v1/epss`）から EPSS スコアとパーセンタイルを取得します
- CISA KEV JSON フィードをダウンロードして、各 CVE に活発な悪用が確認されているかチェックします
- 結果は脆弱性テーブルと解決ガイドに2つの追加列として表示されます
- いずれの CVE にも悪用可能性データがない場合、列は省略されます

**出力**
- **Exploited (KEV) 列**：CISA KEV カタログにある CVE は "Yes"、それ以外は "No"
- **EPSS 列**：EPSS パーセンタイルを序数文字列で表示（例："97th percentile"）
- これらの列は少なくとも1つの CVE に悪用可能性データがある場合のみ表示されます

**出力例**

[`examples/suggest-fix-project`](../../examples/suggest-fix-project) に対して実行した結果です。

```bash
uv-sbom -p examples/suggest-fix-project --check-exploitability -f markdown
```

```markdown
## Vulnerability Report

| Package | Current Version | Fixed Version | CVSS | Severity | Vulnerability ID | Exploited (KEV) | EPSS |
|---------|-----------------|---------------|------|----------|------------------|-----------------|------|
| urllib3 | 2.0.4 | 2.6.3 | 7.5 | 🟠 HIGH | GHSA-38jv-5279-wg99 | No | 87th percentile |
| certifi | 2023.7.22 | 2024.7.4 | N/A | 🟢 LOW | GHSA-248v-346w-9cwc | No | 63rd percentile |
| h11 | 0.14.0 | 0.16.0 | 9.1 | 🔴 CRITICAL | GHSA-vqfr-h8mv-ghfj | No | 46th percentile |
| urllib3 | 2.0.4 | 2.0.7 | 4.2 | 🟡 MEDIUM | GHSA-g4mx-q9vg-27p4 | No | 43rd percentile |
| anyio | 4.0.0 | 4.14.2 | N/A | 🔴 CRITICAL | GHSA-82r6-8w77-94w6 | No | 19th percentile |
```

_（全 32件の脆弱性から EPSS パーセンタイルでソートした抜粋。EPSS の値はライブデータのため変動します。）_

**設定ファイルでの指定**

```yaml
check_exploitability: true
```

> **注意:** `--check-exploitability` は CVE チェックが有効である必要があり、`--no-check-cve` と併用できません。SBOM 生成ごとに2つのネットワークリクエスト（FIRST.org EPSS API と CISA KEV カタログフィード）が追加されます。

## PyPI リンク検証

`--verify-links` オプションで、ハイパーリンクを生成する前にパッケージが PyPI に存在するか検証します。PyPI に存在しないパッケージはプレーンテキストとしてレンダリングされます。

```bash
# 検証済み PyPI リンク付きで Markdown を生成
uv-sbom --format markdown --verify-links

# 他のオプションと組み合わせ
uv-sbom --format markdown --verify-links --output SBOM.md
```

**動作**
- `--verify-links` なし：すべてのパッケージ名に PyPI ハイパーリンクが付きます（デフォルト、高速）
- `--verify-links` あり：検証済みパッケージのみハイパーリンクが付き、未検証パッケージはプレーンテキスト
- ネットワークエラー時はプレーンテキストにフォールバックします（クラッシュなし）
- リクエストはパフォーマンスのため並列実行されます（最大 10 同時接続）

## 除外パターンの入力バリデーション

`-e`/`--exclude` オプションは、悪意のある入力から保護するために以下のセキュリティ対策を実装しています。

### 文字制限

パターンに使用できる文字は以下のとおりです。

- **英数字**：a-z, A-Z, 0-9, Unicode 文字/数字
- **ハイフン** (`-`)、**アンダースコア** (`_`)、**ドット** (`.`)：パッケージ名で一般的
- **角括弧** (`[`, `]`)：パッケージエクストラ用（例：`requests[security]`）
- **アスタリスク** (`*`)：ワイルドカードマッチング用

制御文字、シェルメタ文字、パス区切り文字はブロックされ、以下を防止します。

- ターミナルエスケープシーケンスインジェクション
- ログインジェクション攻撃
- コマンドインジェクション（多層防御）

### パターン制限

- **最大パターン数**：1回の実行で 64 パターン
- **最大長**：パターンあたり 255 文字
- **最小内容**：パターンには少なくとも1つの非ワイルドカード文字が必要

これらの制限は以下によるサービス拒否攻撃を防止します。

- 過剰なメモリ消費
- 複雑なパターンマッチングによる CPU 枯渇

### 使用例

**有効なパターン**

```bash
uv-sbom -e 'pytest'           # 完全一致
uv-sbom -e 'test-*'           # プレフィックスワイルドカード
uv-sbom -e '*-dev'            # サフィックスワイルドカード
uv-sbom -e 'package[extra]'   # パッケージエクストラ付き
```

**無効なパターン**（エラーで拒否）

```bash
uv-sbom -e ''                 # 空のパターン
uv-sbom -e '***'              # ワイルドカードのみ
uv-sbom -e 'pkg;rm -rf /'     # シェルメタ文字を含む
uv-sbom -e "$(cat /etc/passwd)" # シェルコマンド置換がブロック
```

セキュリティに関するより詳細な情報（脅威モデルや攻撃ベクトルなど）は [SECURITY.md](../../SECURITY.md) を参照してください。
