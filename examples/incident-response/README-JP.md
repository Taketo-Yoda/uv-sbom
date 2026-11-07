# incident-response

[`uv-sbom --incident`](../../README-JP.md#インシデント対応--incident) をそのまま使える自動化サンプルです。
**アドバイザリを手作業で確認し続けるのをやめて、やるべきことができたときだけ、スケジューラーや CI から知らせを受け取れます。**

`uv-sbom` は何も監視しません。実行されるたびに、その時点での「影響を受けているか、パッチは出ているか、何を
実行すればよいか」に答えるだけです。待つのは**あなたの**スケジューラー（下のループスクリプト、
cron、CI の定期実行）の役目で、答えが変わるまでチェックを繰り返し実行します。

| ファイル | こんなときに |
|---------|-------------|
| [`wait-for-patch.sh`](wait-for-patch.sh) | ターミナルや cron、任意の CI でチェックを続け、修正版が出たら止めたい |
| [`incident-watch.yml`](incident-watch.yml) | GitHub Actions で定期実行し、修正版が出たらジョブを失敗させ、GitHub の失敗通知で気づきたい |

どちらも `--incident` の終了コードで動きを決めます:

| 終了コード | 意味 | 動作 |
|-----------|------|------|
| `0` | 影響なし | 終了します。対応は不要です |
| `1` | 影響あり・修正版リリース済み | 終了し、次のアクション（試行解決で検証済みの `uv lock --upgrade-package` コマンド、またはガイダンス）を含むレポートを表示します |
| `4` | 影響あり・修正版は未リリース | 待機し、あとでもう一度チェックします |
| `2` / `3` | 引数が不正 / エラー | スクリプトは `2` なら即終了し、`3` なら `MAX_ERRORS` 回まで再試行します。ワークフローは失敗します |

> **新しいアドバイザリが見つからない？** 公開されたばかりのアドバイザリは、OSV に登録されるまで
> 時間がかかることがあります。それまでは `"urllib3<2.0.6"` のように影響範囲を自分で指定して
> ください（引用符で囲みます）。[#963](https://github.com/Taketo-Yoda/uv-sbom/issues/963) とメインの README も参照してください。
>
> 手動で範囲を指定した場合、答えが変わるのは範囲を変えたときだけです。`<=` を含む範囲や `>=` だけの範囲は
> 常に終了コード `4` になるので、OSV に登録されたらアドバイザリ ID に切り替えてください。

## 前提条件

- `uv-sbom` がインストール済みであること（`uv tool install uv-sbom-bin` または `pip install uv-sbom-bin`）
- `uv` が `PATH` 上にあること。`--incident` はアップグレードコマンドを試行解決で検証するときに
  `uv` を使います。`uv` がないと、検証済みコマンドの代わりにガイダンスが表示されます。

## 方法 A: `wait-for-patch.sh`

1. [`wait-for-patch.sh`](wait-for-patch.sh) をプロジェクトにコピーし、実行権限を付けます
   （`chmod +x wait-for-patch.sh`）。
2. アドバイザリとプロジェクトのパス（省略時は `.`）を指定して実行します:

   ```bash
   ./wait-for-patch.sh GHSA-xxxx-xxxx-xxxx
   ```

3. 必要なら `ON_FIX_COMMAND` を設定します。修正版がリリースされたときに、チャットへの通知や
   アップグレード PR を作るスクリプトなどを実行できます。

| 変数 | デフォルト | 意味 |
|------|-----------|------|
| `POLL_INTERVAL` | `600` | 修正版が未リリースの間、チェックする間隔（秒） |
| `MAX_ERRORS` | `3` | 連続エラー（終了コード `3`）がこの回数に達したらあきらめます |
| `UV_SBOM` | `uv-sbom` | 実行する `uv-sbom` コマンド |
| `ON_FIX_COMMAND` | （未設定） | 修正版がリリースされたときに実行するコマンド |

**`ON_FIX_COMMAND` の実行方法:** `bash -c "$ON_FIX_COMMAND" wait-for-patch <advisory> <report-path>`
として実行されます。コマンドの中では `$1` がアドバイザリ、`$2` が Markdown レポートのパスです。
どちらも引数として渡され、コマンド文字列に埋め込まれることはないので、細工されたアドバイザリ値で
コードを注入されることはありません。`$1` や `$2` があなたのシェルではなくフック側で展開されるよう、
シングルクォートで囲んでください。コマンド自体は信頼された設定としてそのまま実行されるので、ふだん
実行するシェルコマンドと同じ注意を払ってください。

このスクリプトは `uv lock` を実行せず、`uv.lock` を変更することもありません。アップグレードするか
どうかはあなた（または `ON_FIX_COMMAND`）が決めます。

**実際の実行例:** このリポジトリの `examples/sample-project`（`requests` 2.25.0 に完全固定）に
対して実行しました。修正版はすでにリリース済みなので、1回目のチェックで止まります:

```bash
ON_FIX_COMMAND='echo "ON_FIX_COMMAND ran for $1 ($(grep -c . "$2") report lines)"' \
  examples/incident-response/wait-for-patch.sh GHSA-j8r2-6x86-q33q examples/sample-project
```

````text
## Incident Report: GHSA-j8r2-6x86-q33q

- **Aliases**: CVE-2023-32681, PYSEC-2023-74
- **Severity**: MEDIUM
- **Summary**: Unintended leak of Proxy-Authorization header in requests
- **Overall verdict**: Affected — fix released

### 1. Impact

- **requests** 2.25.0 — Affected — fix released (direct dependency)

### 2. Patch status

- **requests**: fixed in 2.31.0 — released

### 3. Next action

Upgrading **requests** to 2.31.0 could not be resolved. It is a direct dependency, so its version requirement in `pyproject.toml` likely does not allow 2.31.0. Relax the requirement to allow `>=2.31.0`, then run `uv lock --upgrade-package requests` and `uv sync`.

A fix for GHSA-j8r2-6x86-q33q is released. See the Next action above.
ON_FIX_COMMAND ran for GHSA-j8r2-6x86-q33q (11 report lines)
````

（スクリプトは終了コード `0` で終わります。`uv-sbom` の進捗表示は stderr に出るため、ここでは省略しています。
スクリプト自身のメッセージは英語です。`--lang` を指定していないため、レポートも英語で出力されます。）`requests` は `==2.25.0` に固定されているので、次のアクションは
固定を緩めるよう促すガイダンスになります。アップグレードが解決できる場合は、代わりにそのまま
コピーして使える `uv lock --upgrade-package <name>==<fixed>` コマンドが表示されます。
詳しくは[メインの README](../../README-JP.md#インシデント対応--incident) を参照してください。

このスクリプトは長時間動き続けるループです。cron で使う場合はループを使わず、
`uv-sbom --incident <ID> -p <path>` そのものを定期実行し、終了コード（上の表）に応じて処理してください。

## 方法 B: `incident-watch.yml`（GitHub Actions）

1. [`incident-watch.yml`](incident-watch.yml) を、あなたのリポジトリの
   `.github/workflows/incident-watch.yml` にコピーします。
2. リポジトリ変数 `INCIDENT_ADVISORY` にアドバイザリ ID を設定します（Settings → Secrets and
   variables → Actions → Variables）。`uv.lock` がリポジトリのルートにない場合は、
   `INCIDENT_PROJECT_PATH` も設定します。`advisory` と `project_path` を入力して手動で実行する
   （**Run workflow**）こともできます。
3. スケジュールを決めます。デフォルトの `cron: '17 * * * *'` は1時間ごとにチェックします。
4. 新しい `uv-sbom` を使いたくなったら、固定している `uv-sbom-bin==` のバージョンを上げます。

結果は実行ごとに**ジョブサマリー**に載ります:

- 終了コード `0`: 「Not affected」としてジョブは成功します。
- 終了コード `4`: 「Still waiting」とレポートを載せて、ジョブは成功します。
- 終了コード `1`: 「Fix released」とレポート（次のアクションを含む）を載せて、**ジョブは失敗します**。
  GitHub のいつものワークフロー失敗通知が、対応を始める合図です。

アップグレードが済んだら、またはジョブが「Not affected」と報告したら、ワークフローを無効にするか `INCIDENT_ADVISORY` を空にしてください。

**セキュリティ:** ワークフローの権限は `permissions: contents: read` だけです。アドバイザリは環境変数
（`env:`）経由でのみスクリプトに渡され、`run:` の中で `${{ }}` として展開されることはありません。
そのため、細工した入力でシェルコードを注入されることはありません。
