# ネットワーク要件

[メインページに戻る](../../README-JP.md)

uv-sbom は SBOM 生成中にいくつかの外部サービスに HTTP リクエストを行います。このページでは、アクセスするドメイン、ファイアウォールとプロキシの設定、オフラインモードについて説明します。

## 目次

- [アクセスする外部ドメイン](#アクセスする外部ドメイン)
- [ファイアウォール設定](#ファイアウォール設定)
- [プロキシ設定](#プロキシ設定)
- [オフラインモード](#オフラインモード)

---

## アクセスする外部ドメイン

### すべての操作で必要:

1. **PyPI (Python Package Index)**
   - ドメイン: `https://pypi.org`
   - 目的: Python パッケージのライセンス情報の取得
   - タイミング: すべての SBOM 生成時（`--dry-run` 使用時を除く）
   - レート制限: 公式の制限なし。ツールはリトライロジックを実装
   - エンドポイント: `/pypi/{package_name}/json`

### オプション（`--no-check-cve` で CVE を無効化、または `--verify-links` 使用時）:

2. **PyPI リンク検証**
   - ドメイン: `https://pypi.org`
   - 目的: HTTP HEAD リクエストで PyPI 上のパッケージ存在を検証
   - タイミング: `--verify-links` フラグ使用時のみ
   - レート制限: 最大 10 同時リクエスト
   - エンドポイント: `/project/{package_name}/`

3. **OSV (Open Source Vulnerability Database)**
   - ドメイン: `https://api.osv.dev`
   - 目的: セキュリティスキャン用の脆弱性情報の取得
   - タイミング: デフォルト（`--no-check-cve` 使用時を除く）
   - レート制限: ツールは 10 リクエスト/秒の制限を実装
   - エンドポイント:
     - `/v1/querybatch` - 脆弱性 ID のバッチクエリ
     - `/v1/vulns/{vuln_id}` - 詳細な脆弱性情報

4. **FIRST.org EPSS API**
   - ドメイン: `https://api.first.org`
   - 目的: CVE の EPSS（Exploit Prediction Scoring System）スコアとパーセンタイルの取得
   - タイミング: `--check-exploitability` フラグ使用時のみ
   - エンドポイント: `/data/v1/epss?cve=CVE-A,CVE-B,...`（バッチ処理）

5. **CISA KEV (Known Exploited Vulnerabilities) カタログ**
   - ドメイン: `https://www.cisa.gov`
   - 目的: CVE に確認済みの活発な悪用があるかチェック
   - タイミング: `--check-exploitability` フラグ使用時のみ
   - エンドポイント: `/sites/default/files/feeds/known_exploited_vulnerabilities.json`

## ファイアウォール設定

企業のファイアウォールやプロキシの背後にいる場合、以下のドメインを許可リストに追加してください：

```
# 必須
pypi.org

# オプション（--verify-links のみ。OSV は --no-check-cve でなければデフォルトでアクセス）
pypi.org       # --verify-links でも使用
api.osv.dev    # --no-check-cve でのみ無効

# オプション（--check-exploitability のみ）
api.first.org  # EPSS スコア
www.cisa.gov   # CISA KEV カタログ
```

## プロキシ設定

ツールは標準の HTTP/HTTPS プロキシ環境変数を尊重します：

```bash
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1

uv-sbom --format json
```

## オフラインモード

ネットワークリクエストを行わずに設定を検証するには、`--dry-run` を使用します：

```bash
uv-sbom --dry-run
```

このモードでは：
- `uv.lock` ファイルを検証
- コマンドライン引数を検証
- 除外パターンをチェック
- ライセンス取得をスキップ（PyPI アクセスなし）
- 脆弱性チェックをスキップ（OSV アクセスなし）
- SBOM 出力生成をスキップ
