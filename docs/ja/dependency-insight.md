# 依存関係の分析

[メインページに戻る](../../README-JP.md)

uv-sbom は依存関係グラフを理解するためのいくつかの機能を提供します：パッケージが含まれている理由のトレース、ツリー構造の可視化、ロックファイルバージョン間の変更比較、脆弱な推移的パッケージを導入した直接依存関係の特定、脆弱性を解決するためのアップグレード提案です。

## 目次

- [依存関係の説明 (`--explain`)](#依存関係の説明---explain)
- [依存関係ツリーの可視化 (`--show-dependency-tree`)](#依存関係ツリーの可視化---show-dependency-tree)
- [依存関係の差分 (`--diff`)](#依存関係の差分---diff)
- [脆弱性解決ガイド](#脆弱性解決ガイド)
- [アップグレードアドバイザー (`--suggest-fix`)](#アップグレードアドバイザー---suggest-fix)
  - [制約依存関係によるワークアラウンド](#制約依存関係によるワークアラウンド)

---

## 依存関係の説明 (`--explain`)

`--explain <PACKAGE_NAME>` オプションを使用して、パッケージが依存関係ツリーに含まれた経緯をトレースします。直接依存関係からターゲットパッケージまでのすべてのパスを表示することで、「なぜこのパッケージがここにあるのか？」に回答します。

```bash
# idna が含まれている理由をトレース
uv-sbom --explain idna --format markdown

# 他のオプションと組み合わせ
uv-sbom --explain idna --no-check-cve --format markdown
```

**仕組み:**
- Markdown レポート用に既に構築された依存関係グラフを再利用します — ネットワークアクセス不要、追加のトラバーサルなし
- パッケージが `[project.dependencies]` に含まれている場合は**直接依存関係**として報告し、そうでなければすべての推移的パスをリストします（パッケージは両方になることもあります）
- パスは左から右に読み、直接依存関係からターゲットまで、Dependency Chains サブセクションと同じバッククォートと矢印の記法を使用します
- 不明または無効なパッケージ名は「not found」として報告されます。SBOM 生成が中断されることはありません
- グラフは `[project.dependencies]` からのみ構築されます。`[dependency-groups]`（dev、test、lint など）を通じてのみ到達可能なパッケージは、コンポーネントインベントリやライセンステーブルに表示されていても「not found」として報告されます

**出力:**
- **Dependency Explanation セクション**: Markdown 出力の単一の `## Dependency Explanation` セクション。推移的パス、直接依存関係、not found の 3 つの状態のいずれかでレンダリングされます
- `--explain` が渡されない場合、セクションは完全に省略されます

**出力例（複数のパスで到達可能な推移的パッケージ）:**
```markdown
## Dependency Explanation

**idna** is included via 3 path(s):

- `httpx` → `idna`
- `requests` → `idna`
- `httpx` → `httpcore` → `anyio` → `idna`
```

[`examples/suggest-fix-project`](../../examples/suggest-fix-project) に対して実行した結果です：

```bash
uv-sbom -p examples/suggest-fix-project --explain idna --no-check-cve -f markdown
```

**出力例（直接依存関係）:**
```markdown
## Dependency Explanation

**requests** is a direct dependency of this project.
```

```bash
uv-sbom -p examples/suggest-fix-project --explain requests --no-check-cve -f markdown
```

**出力例（パッケージが見つからない場合）:**
```markdown
## Dependency Explanation

Package **definitely-not-a-real-package** was not found in this project's dependencies.
```

```bash
uv-sbom -p examples/suggest-fix-project --explain definitely-not-a-real-package --no-check-cve -f markdown
```

> **注意:** これらの例では `examples/sample-project`（この README の他の箇所で使用）ではなく `examples/suggest-fix-project` を使用しています。これは、ダイヤモンド依存関係を実際に含む同梱サンプルだからです — `idna` は `httpx` と `requests` の両方に必要とされています。

**設定ファイルでの指定:**

なし。`--explain` は意図的に CLI 専用です：単一のパッケージに関する 1 回限りの診断クエリであり、`check_non_pypi` や `target_python` のような永続的なポリシー設定ではありません。`uv-sbom.config.yml` キーはなく、Config File Schema Reference テーブルにも表示されません。

**フラグの相互作用:**
- **`--workspace` は拒否されます。** 引数パース時にハードエラーになります：
  ```
  error: the argument '--explain <PACKAGE_NAME>' cannot be used with '--workspace'
  ```
- **`--format json` は何も出力しません。** CycloneDX JSON 出力には explain データが含まれることはなく、`--check-license` や `--verify-links` とは異なり、この組み合わせに対する「no effect」警告は表示されません。`json` がデフォルト形式のため、`--explain` を使用する際は常に `--format markdown`（または `-f markdown`）を指定してください。

## 依存関係ツリーの可視化 (`--show-dependency-tree`)

`--show-dependency-tree` を使用して、プロジェクトの依存関係グラフを Markdown 出力の ASCII ツリーとしてレンダリングします。`--dependency-tree-depth <DEPTH>`（デフォルト：3）を使用して、各直接依存関係の下に何レベルまで展開するかを制御します。

```bash
# 完全な依存関係ツリーを表示
uv-sbom --show-dependency-tree --format markdown

# ツリーを各ルートの下 2 レベルに制限
uv-sbom --show-dependency-tree --dependency-tree-depth 2 --format markdown
```

**仕組み:**
- Markdown レポート用に既に構築された依存関係グラフを再利用します — ネットワークアクセス不要、追加のトラバーサルなし
- 直接依存関係ごとに 1 つのルート、Direct Dependencies リストと同じ順序。子はロックファイル自体の依存関係順序に従います
- ダイヤモンド依存関係（複数のパスから到達可能なパッケージ）は各親の下に 1 回表示され、重複排除されません — ツリーはフラット化されたパッケージリストではなく、グラフの形状を反映します
- `--dependency-tree-depth` は各ルートの*下*のレベルをカウントします：`0` はルートのみ、`1` はルートとその直接の子、以降同様
- 深度制限に達したために展開されなかった子を持つブランチでは、代わりに `... (truncated)` マーカーが表示され、適用された深度を示す注記が続きます

**出力:**
- **Dependency Tree セクション**: Markdown 出力の単一の `## Dependency Tree` セクション。パッケージ名とバージョンのみを含みます — ライセンス、説明、ハッシュデータは Component Inventory に既に表示されているため、ここでは繰り返されません
- `--show-dependency-tree` が渡されない場合、セクションは完全に省略されます

**出力例（完全なツリー、切り捨てなし）:**

[`examples/suggest-fix-project`](../../examples/suggest-fix-project) に対して実行した結果です：

```bash
uv-sbom -p examples/suggest-fix-project --show-dependency-tree --no-check-cve -f markdown
```

````markdown
## Dependency Tree

```text
├── httpx (0.24.1)
│   ├── certifi (2023.7.22)
│   ├── httpcore (0.17.3)
│   │   ├── anyio (4.0.0)
│   │   │   ├── idna (3.4)
│   │   │   └── sniffio (1.3.0)
│   │   ├── certifi (2023.7.22)
│   │   ├── h11 (0.14.0)
│   │   └── sniffio (1.3.0)
│   ├── idna (3.4)
│   └── sniffio (1.3.0)
└── requests (2.31.0)
    ├── certifi (2023.7.22)
    ├── charset-normalizer (3.2.0)
    ├── idna (3.4)
    └── urllib3 (2.0.4)
```
````

**出力例（深度 2 で切り捨て）:**

```bash
uv-sbom -p examples/suggest-fix-project --show-dependency-tree --dependency-tree-depth 2 --no-check-cve -f markdown
```

````markdown
## Dependency Tree

```text
├── httpx (0.24.1)
│   ├── certifi (2023.7.22)
│   ├── httpcore (0.17.3)
│   │   ├── anyio (4.0.0)
│   │   │   └── ... (truncated)
│   │   ├── certifi (2023.7.22)
│   │   ├── h11 (0.14.0)
│   │   └── sniffio (1.3.0)
│   ├── idna (3.4)
│   └── sniffio (1.3.0)
└── requests (2.31.0)
    ├── certifi (2023.7.22)
    ├── charset-normalizer (3.2.0)
    ├── idna (3.4)
    └── urllib3 (2.0.4)
```

_Tree truncated at depth 2. Use `--dependency-tree-depth <DEPTH>` to show more levels._
````

> **注意:** これらの例では `examples/sample-project`（この README の他の箇所で使用）ではなく `examples/suggest-fix-project` を使用しています。これは、深度を下げた際に切り捨てを実際にデモンストレーションできるほど深いチェーン（`httpx` → `httpcore` → `anyio` → `idna`/`sniffio`）を持つ同梱サンプルだからです。

**設定ファイルでの指定:**

なし。`--show-dependency-tree` は意図的に CLI 専用です：1 回限りの可視化リクエストであり、`check_non_pypi` や `target_python` のような永続的なポリシー設定ではありません。`uv-sbom.config.yml` キーはなく、Config File Schema Reference テーブルにも表示されません。

**フラグの相互作用:**
- **`--format json` は何も出力しません。** CycloneDX JSON 出力には依存関係ツリーが含まれることはなく、この組み合わせに対する「no effect」警告は表示されません。`json` がデフォルト形式のため、`--show-dependency-tree` を使用する際は常に `--format markdown`（または `-f markdown`）を指定してください。

## 依存関係の差分 (`--diff`)

`--diff` オプションを使用して、現在の `uv.lock` を以前のバージョンと比較します。マージ前にブランチ、タグ、任意のロックファイルスナップショット間で何が変更されたかを確認するのに便利です。

```bash
# Git ブランチまたはタグと比較
uv-sbom --diff main
uv-sbom --diff v1.2.0
uv-sbom --diff abc1234    # 短縮コミット SHA

# ファイルパスと比較（CWD からの絶対パスまたは相対パス）
uv-sbom --diff /path/to/old/uv.lock

# Markdown レポートとして出力
uv-sbom --diff main --format markdown --output diff.md

# JSON として出力
uv-sbom --diff main --format json
```

**自動検出:** 引数がディスク上の既存ファイルに解決される場合はファイルパスとして扱われ、それ以外は Git ref として扱われます。相対パスはプロセスの作業ディレクトリ（`--path` ではなく）に対して解決されます。

**Git ref のバリデーション:** Git ref には `[a-zA-Z0-9._/-]` の文字のみ使用できます。`-` で始まる ref も拒否されます。これによりコマンドインジェクションを防止します。

**相互排他:** `--diff` は `--workspace` または `--init` と併用できません。

### CVE デルタ

デフォルトでは、`--diff` はベースと現在の両方のロックファイルに対して脆弱性チェックも実行し、レポートに **CVE Delta** セクションを追加して、導入または解決された脆弱性を表示します：

- **新しい脆弱性** — 現在のロックのパッケージに影響するが、ベースには存在しなかった CVE。
- **解決された脆弱性** — ベースのロックのパッケージに影響していたが、もう該当しない CVE。

```bash
# CVE デルタ付きの差分（デフォルト — CVE チェックはオン）
uv-sbom --diff main

# 差分モードで CVE チェックを無効化
uv-sbom --diff main --no-check-cve
```

JSON 出力にはトップレベルの `cve_delta` キーが含まれ、`new` と `resolved` の配列があります。`--no-check-cve` が渡された場合、キーは完全に省略されます。

**重大度と CVSS のフィルタリング:** `--severity-threshold` と `--cvss-threshold` は CVE デルタに適用されます。しきい値以上のエントリのみがテーブルに表示されます。設定されたしきい値を超える新しい CVE が導入された場合、プロセスは終了コード `1` で終了します。

```bash
# HIGH 以上の CVE デルタエントリのみ表示
uv-sbom --diff main --severity-threshold high

# CVSS >= 7.0 の CVE デルタエントリのみ表示
uv-sbom --diff main --cvss-threshold 7.0
```

**CI での例:**
```bash
# この PR で導入された新しい依存関係に HIGH 以上の既知の CVE がある場合、ビルドを失敗させる
uv-sbom --diff origin/main --format markdown --output diff.md --severity-threshold high
```

## 脆弱性解決ガイド

推移的依存関係で脆弱性が検出された場合、uv-sbom は自動的に**脆弱性解決ガイド**を生成します。このセクションでは、どの直接依存関係が各脆弱な推移的パッケージを導入したかを表示し、何をアップグレードすべきかを正確に把握できます。

### Markdown 出力例

```markdown
## Vulnerability Resolution Guide

The following transitive dependencies have known vulnerabilities. The table shows which direct dependency introduces each vulnerable package.

| Vulnerable Package | Current | Fixed Version | Severity | Introduced By (Direct Dep) | Vulnerability ID |
|--------------------|---------|---------------|----------|---------------------------|-----------------|
| urllib3 | 1.26.15 | >= 2.0.7 | 🟠 HIGH | requests (2.31.0) | [CVE-2024-XXXXX](https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX) |
| h11 | 0.14.0 | >= 0.14.4 | 🟠 HIGH | httpx (0.24.0) | [CVE-2024-ZZZZZ](https://nvd.nist.gov/vuln/detail/CVE-2024-ZZZZZ) |

### Dependency Chains

**`h11 0.14.0`** — CVE-2024-ZZZZZ (HIGH)
- `httpcore` → `httpx` → **`h11 0.14.0`** ⚠️
```

> **注意:** `### Dependency Chains` サブセクションは、少なくとも 1 つの脆弱なパッケージがマルチホップチェーン（チェーン長 > 2）を経由して到達可能な場合にのみレンダリングされます。すべての脆弱なパッケージが第 1 レベルの依存関係によって直接導入されている場合、完全に省略されます。

### CycloneDX JSON 出力

CycloneDX 形式では、導入元の依存関係は `properties` エントリとして含まれます：

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-XXXXX",
      "properties": [
        {
          "name": "uv-sbom:introduced-by",
          "value": "requests@2.31.0"
        }
      ]
    }
  ]
}
```

> **注意:** 解決ガイドは**推移的**依存関係の脆弱性に対してのみ表示されます。直接依存関係の脆弱性は標準の脆弱性テーブルに表示されます（ユーザーが直接アップグレードできるため）。

## アップグレードアドバイザー (`--suggest-fix`)

`--suggest-fix` を使用して、各推移的脆弱性を解決するためにどの直接依存関係バージョンにアップグレードすべきかを自動提案します。

**必要条件**:
- `uv` CLI がインストール済み
- プロジェクトディレクトリに `pyproject.toml` があること

**例**:
```bash
uv-sbom generate --suggest-fix
```

**出力**: 脆弱性解決ガイドに「Recommended Action」列が追加されます：
- `⬆️ Upgrade requests → 2.32.3 (resolves urllib3 to 2.2.1)` — アップグレードで脆弱性が修正される場合
- `⚠️ Cannot resolve: latest httpx still pins idna < 3.7` — アップグレードでは解決できない場合（次の「[制約依存関係によるワークアラウンド](#制約依存関係によるワークアラウンド)」で追加のサジェスションが表示されます）
- `❓ Could not analyze: <error>` — シミュレーションが失敗した場合

**同梱サンプルで試す:**

```bash
# この例には、アップグレード可能と解決不可能の両方の結果を示す推移的 CVE があります
uv-sbom -p examples/suggest-fix-project --suggest-fix -f markdown
```

詳細なウォークスルーは [`examples/suggest-fix-project/README.md`](../../examples/suggest-fix-project/README.md) を参照してください。

### 制約依存関係によるワークアラウンド

直接依存関係のアップグレードだけでは推移的脆弱性を解決できない場合、`--suggest-fix` はさらに一歩進んで、[`[tool.uv].constraint-dependencies`](https://docs.astral.sh/uv/concepts/dependencies/#constraint-dependencies) エントリの追加を提案し、推移的パッケージを安全なバージョンに強制します。

**仕組み:**

1. 各「解決不可」の結果に対して、uv-sbom は `"<パッケージ名>>=<修正バージョン>"` という制約を構築します。
2. `--override` を使用してその制約を適用した `uv lock` をシミュレーションし、解決が成功するかを確認します。
3. 結果は脆弱性解決ガイドの「Recommended Action」列に追記されます。

**3 種類の結果:**

| 結果 | 表示 | 意味 |
|------|------|------|
| 検証済み | `💡 回避策: [tool.uv].constraint-dependenciesに"pkg>=X.Y" を追加（✅ 検証済み: Z.Wに解決）` | 制約が有効 — `pyproject.toml` に追加すれば安全なバージョンに強制される |
| 解決不可 | `💡 制約"pkg>=X.Y" を試行 — 解決不可: <理由>` | 制約を試みたが脆弱性は修正されない（例: 他の制約によりバージョンが選択されない） |
| シミュレーション失敗 | `⚠️ 制約"pkg>=X.Y" を検証できません: <エラー>` | シミュレーションを実行できなかった（例: 修正バージョン文字列が有効な PEP 440 バージョンではない） |

**出力例:**

[`examples/suggest-fix-project`](../../examples/suggest-fix-project) に対して実行した結果です：

```bash
uv-sbom -p examples/suggest-fix-project --suggest-fix -f markdown
```

```markdown
## Vulnerability Resolution Guide

| Vulnerable Package | Current | Fixed Version | Severity | Introduced By (Direct Dep) | Recommended Action | Vulnerability ID |
|--------------------|---------|---------------|----------|----------------------------|--------------------|------------------|
| h11 | 0.14.0 | 0.16.0 | 🔴 CRITICAL | httpx (0.24.1) | ⬆️ Upgrade httpx → 0.28.1 (resolves h11 to 0.16.0) | GHSA-vqfr-h8mv-ghfj |
| urllib3 | 2.0.4 | 2.6.0 | 🟠 HIGH | requests (2.31.0) | ⚠️ Cannot resolve: upgrading requests still resolves urllib3 to 2.0.4 which does not satisfy >= 2.6.0 💡 Workaround: add `"urllib3>=2.6.0"` to `[tool.uv].constraint-dependencies` (✅ verified: resolves to 2.8.0) | GHSA-2xpw-w6gg-jr37 |
| idna | 3.4 | 3.7 | 🟡 MEDIUM | httpx (0.24.1), requests (2.31.0) | ⚠️ Cannot resolve: upgrading httpx still resolves idna to 3.4 which does not satisfy >= 3.7 💡 Workaround: add `"idna>=3.7"` to `[tool.uv].constraint-dependencies` (✅ verified: resolves to 3.20) | GHSA-jjg7-2v4v-x38h |
```

_（抜粋 — 脆弱性の件数や解決されるバージョンは新しい CVE の公開に伴い変動する場合があります。）_

**ワークアラウンドの適用方法:**

検証済みの制約サジェスションが表示された場合、`pyproject.toml` に追加します：

```toml
[tool.uv]
constraint-dependencies = [
    "urllib3>=2.6.0",
    "idna>=3.7",
]
```

その後、再ロックと同期を実行します：

```bash
uv lock
uv sync
```

> **注意:** `constraint-dependencies` は、どのパッケージを選択するかを変更せずに下限を適用するだけです — バージョンリゾルバーに制約を与えるのみです。パッケージを直接依存関係として追加するのとは異なります。詳細は [uv のドキュメント](https://docs.astral.sh/uv/concepts/dependencies/#constraint-dependencies)を参照してください。

> **ワークスペースの制限:** 制約シミュレーションはルートの `pyproject.toml` のみを一時環境にコピーします。メンバー固有の `pyproject.toml` ファイルを持つワークスペースでは、シミュレーションがメンバー固有の制約を反映しない場合があります。
