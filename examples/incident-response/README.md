# incident-response

Copy-paste automation for [`uv-sbom --incident`](../../README.md#incident-response---incident):
**stop checking an advisory by hand: let your scheduler re-run it and tell you when there is something to do.**

`uv-sbom` does not monitor anything. It answers once each time it runs: *am I affected,
is the patch out, what do I run?* The waiting is done by **your** scheduler: the loop
script below, a cron job, or a scheduled CI workflow. They re-run the check until the
answer changes.

| File | Use it when |
|------|-------------|
| [`wait-for-patch.sh`](wait-for-patch.sh) | You want a terminal, cron, or any CI to keep checking and stop once the fix is out |
| [`incident-watch.yml`](incident-watch.yml) | You want a scheduled GitHub Actions job that fails (and so notifies you) once the fix is out |

Both act on the `--incident` exit code:

| Exit code | Meaning | What happens |
|-----------|---------|--------------|
| `0` | Not affected | Stop. Nothing to do |
| `1` | Affected, fix released | Stop and show the report with the next action (a dry-run-verified `uv lock --upgrade-package` command, or guidance) |
| `4` | Affected, no released fix yet | Keep waiting and check again later |
| `2` / `3` | Invalid arguments / error | The script stops on `2` and retries `3` up to `MAX_ERRORS` times. The workflow fails |

> **New advisory not found?** OSV can take some time to index an advisory after it is
> announced. Until then, pass the affected range yourself, e.g. `"urllib3<2.0.6"` (quoted).
> See [#963](https://github.com/Taketo-Yoda/uv-sbom/issues/963) and the main README.
>
> With a manual range, the answer changes only when you change the range. A range with
> `<=`, or with only `>=`, always exits `4`, so switch to the advisory ID once OSV has indexed it.

## Prerequisites

- `uv-sbom` installed (`uv tool install uv-sbom-bin` or `pip install uv-sbom-bin`)
- `uv` on `PATH`. `--incident` uses it for the dry-run that verifies the upgrade command.
  Without it you get guidance instead of a verified command.

## Option A: `wait-for-patch.sh`

1. Copy [`wait-for-patch.sh`](wait-for-patch.sh) into your project and make it executable
   (`chmod +x wait-for-patch.sh`).
2. Run it with the advisory and the project path (default `.`):

   ```bash
   ./wait-for-patch.sh GHSA-xxxx-xxxx-xxxx
   ```

3. Optionally, set `ON_FIX_COMMAND` to run something once the fix is released, such as
   a chat notification or a script that opens an upgrade PR.

| Variable | Default | Meaning |
|----------|---------|---------|
| `POLL_INTERVAL` | `600` | Seconds between checks while the fix is not released |
| `MAX_ERRORS` | `3` | Consecutive errors (exit `3`) before the script gives up |
| `UV_SBOM` | `uv-sbom` | The `uv-sbom` command to run |
| `ON_FIX_COMMAND` | (unset) | Command run once a fix is released |

**How `ON_FIX_COMMAND` runs:** `bash -c "$ON_FIX_COMMAND" wait-for-patch <advisory> <report-path>`.
Inside the command, `$1` is the advisory and `$2` is the path to the Markdown report.
They are passed as arguments and never pasted into the command string, so a strange
advisory value cannot inject code. Use single quotes so that `$1` and `$2` are expanded
by the hook, not by your shell. The command itself is trusted configuration, so treat it
like any other shell command you run.

The script never runs `uv lock` and never modifies `uv.lock`. Upgrading is your
decision, or your `ON_FIX_COMMAND`'s.

**Real run** against this repository's `examples/sample-project` (`requests` 2.25.0,
pinned exactly). The fix is already released, so the script stops on the first check:

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

(The script exits `0`. Progress lines from `uv-sbom` go to stderr and are omitted here.)
Because `requests` is pinned to `==2.25.0`, the next action is guidance to relax the pin.
When the upgrade resolves, you get a copy-paste `uv lock --upgrade-package <name>==<fixed>`
command instead. See the [main README](../../README.md#incident-response---incident).

The script is a long-running loop. For cron, skip the loop: schedule
`uv-sbom --incident <ID> -p <path>` itself and act on its exit code (the table above).

## Option B: `incident-watch.yml` (GitHub Actions)

1. Copy [`incident-watch.yml`](incident-watch.yml) to `.github/workflows/incident-watch.yml`
   in your repository.
2. Set the repository variable `INCIDENT_ADVISORY` to the advisory ID (Settings →
   Secrets and variables → Actions → Variables). If `uv.lock` is not at the repository
   root, also set `INCIDENT_PROJECT_PATH`. You can also run the workflow by hand
   (**Run workflow**) with the `advisory` and `project_path` inputs.
3. Choose a schedule. The default `cron: '17 * * * *'` checks hourly.
4. Bump the pinned `uv-sbom-bin==` version when you want a newer `uv-sbom`.

Each run puts the result in the **job summary**:

- exit `0`: the job succeeds with "Not affected".
- exit `4`: the job succeeds with "Still waiting", plus the report.
- exit `1`: **the job fails** with "Fix released", plus the report and its next action.
  GitHub's usual workflow-failure notification is your signal to act.

Once you have upgraded, or the job reports "Not affected", disable the workflow or clear `INCIDENT_ADVISORY`.

**Security:** the workflow has `permissions: contents: read`. The advisory reaches the
script only through an environment variable (`env:`), never through `${{ }}` inside
`run:`, so a crafted input cannot inject shell code.
