# suggest-fix-project

`uv-sbom` の `--suggest-fix` フラグを示すためのサンプルプロジェクトです。

## 目的

このプロジェクトには**意図的に古い直接依存関係**が含まれており、ロックされたバージョンが**脆弱な推移的パッケージ**を引き起こします。以下の挙動を示すよう設計されています：

- 直接依存関係（`httpx`）のアップグレードで推移的脆弱性が**解消できる**
  → `--suggest-fix` の出力に **Upgradable（アップグレード可能）** 推奨が表示される
- 別の直接依存関係（`requests`）のアップグレードでは推移的脆弱性が**解消できない**
  → 出力に **Unresolvable（解消不可）** の警告が表示される

どちらも、内部で `uv lock --upgrade-package` を実行した実際の結果です。

> ⚠️ **これらのパッケージバージョンを本番環境で使用しないでください。** デモ目的で意図的に脆弱なバージョンを使用しています。

## 依存関係の構成

| 直接依存関係 | ロックバージョン | 推移的依存関係 | 推移的バージョン | CVE |
|-------------|----------------|--------------|----------------|-----|
| `httpx` | 0.24.1 | `h11`（`httpcore` 経由） | 0.14.0 | [GHSA-vqfr-h8mv-ghfj](https://github.com/advisories/GHSA-vqfr-h8mv-ghfj) CRITICAL |
| `requests` | 2.31.0 | `urllib3` | 2.0.4 | 複数の HIGH/MEDIUM CVE |

### `httpx` のアップグレードで `h11` が修正される理由（Upgradable）

```
httpx 0.24.1  →  httpcore <0.18.0  →  h11 0.14.x   (CRITICAL CVE)
httpx 0.28.1  →  httpcore ==1.*    →  h11 >=0.16.0  (修正済み)
```

`uv lock --upgrade-package httpx` を実行すると、httpx が 0.28.1 にアップグレードされ、`httpcore==1.*` が要求されます。`httpcore 1.0.9+` はさらに `h11>=0.16` を要求するため、uv は h11 を 0.16.0（修正済みバージョン）に解決します。

### `requests` のアップグレードで `urllib3` が修正されない理由（Unresolvable）

```
requests 2.31.0  →  urllib3 >=1.21.1,<1.27  (ロック済み: 2.0.4*)
requests 2.32.5  →  urllib3 >=1.21.1,<3     (2.0.4 のままでも許容される)
```

`uv lock --upgrade-package requests` を実行すると requests は 2.32.5 にアップグレードされますが、urllib3 の制約が緩い（`<3`）ため、uv は urllib3 を 2.0.4 のまま維持します。urllib3 2.x の CVE を解決するには urllib3 を直接アップグレードする必要があり、`requests` のアップグレードだけでは対応できません。

> *注: ロックは urllib3 2.0.4 に解決されました。これは、ロックファイル作成時点（2023-09-01 カットオフ）で最新バージョンだったためです。

## 前提条件

- `uv-sbom` がソースからビルド済み（`cargo build --release`）またはインストール済み
- `uv` CLI が PATH に存在すること（`--suggest-fix` に必要）

## 使用方法

### ステップ 1: 基本的な CVE チェック（アップグレード提案なし）

```bash
# リポジトリルートから実行
uv-sbom -p examples/suggest-fix-project -f markdown
```

**表示される内容:**
- `h11`、`urllib3`、`requests` の CVE を一覧表示する Vulnerability Report テーブル
- どの直接依存関係が各推移的 CVE を引き起こしているかを示す Vulnerability Resolution Guide
- **「Recommended Action」列は表示されない**（--suggest-fix 未使用）

### ステップ 2: アップグレードアドバイザー（`--suggest-fix`）の使用

```bash
uv-sbom -p examples/suggest-fix-project --suggest-fix -f markdown
```

**Resolution Guide に表示される内容:**

| Vulnerable Package | Introduced By | Recommended Action |
|--------------------|--------------|-------------------|
| `h11` 0.14.0 | `httpx` (0.24.1) | ⬆️ Upgrade httpx → 0.28.1 (resolves h11 to 0.16.0) |
| `urllib3` 2.0.4 | `requests` (2.31.0) | ⚠️ Cannot resolve: upgrading requests still resolves urllib3 to 2.0.4 |

### ステップ 3: CycloneDX 形式でアップグレード情報を出力

```bash
uv-sbom -p examples/suggest-fix-project --suggest-fix -f cyclonedx
```

**表示される内容:**
- 追加の `properties` を含む脆弱性エントリ:
  - `uv-sbom:recommended-action`: 人間が読める推奨アクション
  - `uv-sbom:resolved-version`: シミュレートされたアップグレード後の推移的依存関係バージョン

### ステップ 4: 深刻度でフィルタリング

```bash
# HIGH および CRITICAL の脆弱性のみ表示
uv-sbom -p examples/suggest-fix-project --suggest-fix \
  --severity-threshold high -f markdown
```

### ステップ 5: 依存関係ツリーの可視化（`--show-dependency-tree`）

このプロジェクトの `httpx` → `httpcore` → `anyio` → `idna`/`sniffio` という依存チェーンは3階層の深さがあり、
同梱サンプルの中で縮小した深さでの省略表示（truncation）を実際に再現できる唯一のプロジェクトです。
以下2コマンドの実際の出力全体は、[メインREADME](../../README-JP.md)の「依存関係ツリーの可視化」の節を参照してください。

```bash
# ツリー全体（デフォルトの深さ3 — 省略なし）
uv-sbom -p examples/suggest-fix-project --show-dependency-tree --no-check-cve -f markdown --lang ja

# 深さ2で省略 — anyio の子ノードが省略される
uv-sbom -p examples/suggest-fix-project --show-dependency-tree --dependency-tree-depth 2 --no-check-cve -f markdown --lang ja
```

**表示される内容:**
- 直接依存パッケージ（`httpx`、`requests`）ごとに1つのルートを持つ `## 依存関係ツリー` セクション
- 深さ2の場合、`anyio` の子ノードが `... (省略)` マーカーに置き換えられ、適用された深さを明記した注記が続く

## 出力例

```markdown
## Vulnerability Resolution Guide

| Vulnerable Package | Current | Fixed Version | Severity | Introduced By (Direct Dep) | Recommended Action | Vulnerability ID |
|--------------------|---------|--------------|---------|----------------------------|-------------------|-----------------|
| h11 | 0.14.0 | 0.16.0 | 🔴 CRITICAL | httpx (0.24.1) | ⬆️ Upgrade httpx → 0.28.1 (resolves h11 to 0.16.0) | GHSA-vqfr-h8mv-ghfj |
| urllib3 | 2.0.4 | 2.6.0 | 🟠 HIGH | requests (2.31.0) | ⚠️ Cannot resolve: upgrading requests still resolves urllib3 to 2.0.4 which does not satisfy >= 2.6.0 | GHSA-2xpw-w6gg-jr37 |
```

## 他のサンプルとの比較

| | `examples/sample-project` | `examples/suggest-fix-project` | `examples/abandoned-packages-project` |
|---|---|---|---|
| 脆弱なパッケージ | すべて**直接**依存関係 | すべて**推移的**依存関係 | なし（放棄チェックに特化） |
| Resolution Guide | 非表示（推移的 CVE なし） | Recommended Action 付きで表示 | 非表示 |
| `--suggest-fix` の出力 | アップグレード提案なし | Upgradable + Unresolvable のケース | 対象外 |
| `--check-abandoned` デモ | 一部 | ❌ 対象外 | ✅ あり（4パッケージ、常にフラグ） |

基本的な CVE チェックや `--check-license` 機能を試す場合は `sample-project` を使用してください。
`--suggest-fix` アップグレードアドバイザー機能を試す場合はこのプロジェクトを使用してください。
`--check-abandoned` 機能を確実な出力で試す場合は `abandoned-packages-project` を使用してください。
