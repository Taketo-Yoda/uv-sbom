#!/usr/bin/env bash
# wait-for-patch.sh - re-run `uv-sbom --incident` until the advisory has a released fix.
#
# uv-sbom answers once per run; this loop is what does the waiting. It stops as soon
# as there is something to do (exit 1: fix released) or nothing to do (exit 0: not
# affected), and keeps polling while the fix is not released yet (exit 4).
#
# Usage:
#   wait-for-patch.sh <ADVISORY_ID_OR_RANGE> [PROJECT_PATH]
#
# Environment variables:
#   POLL_INTERVAL   Seconds between runs while waiting (default: 600)
#   MAX_ERRORS      Consecutive uv-sbom errors (exit 3) before giving up (default: 3)
#   UV_SBOM         uv-sbom executable to run (default: uv-sbom). A single path or
#                   command name, not a command line with arguments.
#   ON_FIX_COMMAND  Optional command run once the fix is released. It runs via
#                   `bash -c` with the advisory as $1 and the Markdown report path
#                   as $2; neither is interpolated into the command string.
#                   Treat it as trusted configuration, like any shell command.
#
# Exit codes:
#   0  Not affected, or fix released (and ON_FIX_COMMAND, if set, succeeded)
#   2  Invalid usage or arguments (uv-sbom exit 2 is not retried)
#   3  UV_SBOM cannot be run (not found or not executable; not retried)
#   3  ...or uv-sbom failed MAX_ERRORS times in a row
#   *  ON_FIX_COMMAND's own non-zero exit code
#
# This script never runs `uv lock` or modifies uv.lock. Put any automation (a
# notification, an upgrade PR) in ON_FIX_COMMAND.

set -euo pipefail

usage() {
  echo "Usage: $0 <ADVISORY_ID_OR_RANGE> [PROJECT_PATH]" >&2
  exit 2
}

[[ $# -ge 1 && $# -le 2 && -n "$1" ]] || usage

advisory="$1"
project="${2:-.}"
poll_interval="${POLL_INTERVAL:-600}"
max_errors="${MAX_ERRORS:-3}"
uv_sbom="${UV_SBOM:-uv-sbom}"

for value in "$poll_interval" "$max_errors"; do
  if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "POLL_INTERVAL and MAX_ERRORS must be positive integers (got '$value')" >&2
    exit 2
  fi
done

report="$(mktemp)"
trap 'rm -f "$report"' EXIT

errors=0
while true; do
  rc=0
  "$uv_sbom" --incident "$advisory" --format markdown -p "$project" >"$report" || rc=$?

  case "$rc" in
    0)
      echo "Not affected by $advisory. Nothing to do."
      exit 0
      ;;
    1)
      cat "$report"
      echo
      echo "A fix for $advisory is released. See the Next action above."
      if [[ -n "${ON_FIX_COMMAND:-}" ]]; then
        bash -c "$ON_FIX_COMMAND" wait-for-patch "$advisory" "$report"
      fi
      exit 0
      ;;
    4)
      errors=0
      echo "$(date '+%Y-%m-%d %H:%M:%S') Affected by $advisory, but no fix is released yet. Retrying in ${poll_interval}s."
      ;;
    2)
      echo "uv-sbom rejected the arguments (exit 2). Not retrying." >&2
      exit 2
      ;;
    126 | 127)
      echo "Cannot run '$uv_sbom' (exit $rc). Install uv-sbom or set UV_SBOM." >&2
      exit 3
      ;;
    *)
      errors=$((errors + 1))
      echo "$(date '+%Y-%m-%d %H:%M:%S') uv-sbom failed (exit $rc), error $errors of $max_errors." >&2
      if ((errors >= max_errors)); then
        echo "Giving up after $errors consecutive errors." >&2
        exit 3
      fi
      ;;
  esac

  sleep "$poll_interval"
done
