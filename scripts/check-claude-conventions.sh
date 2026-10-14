#!/usr/bin/env bash
#
# Lint .claude/ against the canonical convention files in .claude/conventions/.
#
# Each check is one check_* function; main runs every check and aggregates the
# failures, so one failing check never hides another.
#
# Usage: scripts/check-claude-conventions.sh [REPO_ROOT]
#   REPO_ROOT defaults to the repository containing this script. Passing a
#   different root lets you lint a scratch copy (e.g. to confirm a deliberately
#   broken derived block is caught).
#
# Exit status:
#   0  no violations
#   1  one or more convention violations
#   2  setup or internal error (e.g. the canonical block could not be found)
#
# Portability: must run on bash 3.2 (macOS) and GNU/Linux. Do not use mapfile,
# associative arrays, grep -P, sed -i, find -printf, or readlink -f.

set -u

ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
if ! cd "$ROOT"; then
  echo "error: cannot cd to repository root: $ROOT" >&2
  exit 2
fi

# Strings mirrored from .claude/conventions/ci-checks.md (the owner). If the
# owner renames its heading, marker path, or write-mode form, update these.
CI_CHECKS=".claude/conventions/ci-checks.md"
CANONICAL_HEADING="## Canonical Command Block"
DERIVED_MARKER="<!-- derived: $CI_CHECKS -->"
WRITE_MODE_FMT="cargo fmt --all" # ci-checks.md: the only sanctioned deviation

FAILURES=0

WORK_DIR="$(mktemp -d)" || { echo "error: mktemp failed" >&2; exit 2; }
trap 'rm -rf "$WORK_DIR"' EXIT

# report FILE LINE MESSAGE -- print one violation and count it. On GitHub
# Actions, also emit an ::error workflow command so it annotates the PR diff.
report() {
  local file=$1 line=$2 msg=$3
  printf '%s:%s: error: %s\n' "$file" "$line" "$msg" >&2
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    # Workflow-command escaping: '%' first, then CR/LF; property values
    # (file=) additionally escape ':' and ','.
    msg=${msg//%/%25}
    msg=${msg//$'\r'/%0D}
    msg=${msg//$'\n'/%0A}
    file=${file//%/%25}
    file=${file//:/%3A}
    file=${file//,/%2C}
    printf '::error file=%s,line=%s::%s\n' "$file" "$line" "$msg"
  fi
  FAILURES=$((FAILURES + 1))
}

# report_findings FILE FINDINGS -- report every "LINE<TAB>MESSAGE" record that
# a scanner wrote to FINDINGS for FILE. Scanners must escape tabs in MESSAGE.
report_findings() {
  local file=$1 findings=$2 line msg
  while IFS="$(printf '\t')" read -r line msg; do
    report "$file" "$line" "$msg"
  done <"$findings"
}

# list_claude_markdown OUT -- write every .claude/**/*.md path to OUT, sorted.
list_claude_markdown() {
  find .claude -type f -name '*.md' | LC_ALL=C sort >"$1"
}

# extract_canonical OUT -- write the non-empty command lines of the
# $CANONICAL_HEADING ```bash fence in ci-checks.md to OUT.
# Exits 2 if the section, the fence, or its contents are missing, so a renamed
# heading makes the lint fail loudly instead of silently passing.
extract_canonical() {
  local out=$1
  if [ ! -f "$CI_CHECKS" ]; then
    echo "error: canonical file not found: $CI_CHECKS" >&2
    exit 2
  fi
  if ! awk -v heading="$CANONICAL_HEADING" '
    $0 == heading { in_section = 1; next }
    in_section && !in_block && /^## / { exit }
    in_section && !in_block && $0 == "```bash" { in_block = 1; next }
    in_block && $0 == "```" { closed = 1; exit }
    in_block && $0 != "" { print }
    END { if (!closed) exit 3 }
  ' "$CI_CHECKS" >"$out" || [ ! -s "$out" ]; then
    echo "error: could not extract the \`\`\`bash block under '$CANONICAL_HEADING' in $CI_CHECKS" >&2
    exit 2
  fi
}

# scan_derived_blocks CANONICAL FILE -- print one "LINE<TAB>MESSAGE" record per
# derived-block violation in FILE. A derived block is the ```bash fence on the
# line directly after $DERIVED_MARKER; each non-empty line in it must be a line
# of CANONICAL or $WRITE_MODE_FMT.
scan_derived_blocks() {
  awk -v marker="$DERIVED_MARKER" -v owner="$CI_CHECKS" \
    -v owner_name="${CI_CHECKS##*/}" -v write_mode="$WRITE_MODE_FMT" -v q="'" '
    NR == FNR { canon[$0] = 1; next }

    state == "fence" {
      if ($0 == "```bash") { state = "block"; has_cmd = 0; next }
      print marker_line "\tderived marker not followed by a ```bash fence"
      state = ""
    }

    state == "block" {
      if ($0 == "```") {
        if (!has_cmd) print marker_line "\tempty derived block"
        state = ""
        next
      }
      if ($0 != "") {
        has_cmd = 1
        if (!($0 in canon) && $0 != write_mode) {
          # Make invisible drift (tabs, CR) visible and keep the record one field.
          shown = $0
          gsub(/\t/, "\\t", shown)
          gsub(/\r/, "\\r", shown)
          print FNR "\tderived CI line not in canonical block (" owner "): " q shown q
        }
      }
      next
    }

    $0 == marker { state = "fence"; marker_line = FNR; next }

    # Near-miss markers (extra/missing spaces, indentation, CRLF) would
    # otherwise silently exempt the block below them from this check.
    /^[ \t]*<!--[ \t]*derived[ \t]*:/ && index($0, owner_name) > 0 {
      print FNR "\tmalformed derived marker (expected exactly: " marker ")"
    }

    END {
      if (state == "block") print marker_line "\tunterminated ```bash fence after derived marker"
      else if (state == "fence") print marker_line "\tderived marker not followed by a ```bash fence"
    }
  ' "$1" "$2"
}

# check_derived_ci_blocks -- enforce ci-checks.md -> "Derived Copies" on every
# .claude/**/*.md file.
check_derived_ci_blocks() {
  local canonical="$WORK_DIR/canonical"
  local files="$WORK_DIR/files"
  local findings="$WORK_DIR/findings"
  local file

  extract_canonical "$canonical"
  list_claude_markdown "$files"

  while IFS= read -r file <&3; do
    scan_derived_blocks "$canonical" "$file" >"$findings"
    report_findings "$file" "$findings"
  done 3<"$files"
}

main() {
  check_derived_ci_blocks

  if [ "$FAILURES" -gt 0 ]; then
    echo "check-claude-conventions: $FAILURES violation(s) found" >&2
    exit 1
  fi
  echo "check-claude-conventions: OK"
}

main
