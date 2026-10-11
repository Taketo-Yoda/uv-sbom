---
name: release
description: Standardized release workflow with version updates and CHANGELOG management
---

# /release - Release Preparation Skill

Automates the pre-release preparation workflow, ensuring consistent version updates across all files and proper CHANGELOG management.

## Language Requirement

**IMPORTANT**: All outputs (commits, PRs, branch names) MUST be written in **English**.

## Scope Boundaries

### What this skill DOES:
- Update version numbers in all required files
- Update CHANGELOG.md format
- Run pre-flight checks (fmt, clippy, test)
- Create release branch and PR to `develop`

### Merge Flow

```
release/vX.Y.Z → develop → main
```

- **Step 8** creates a PR: `release/vX.Y.Z` → `develop`
- After merge, the user opens a second PR: `develop` → `main` (with tag creation)

### What this skill does NOT do (manual steps):
- **Tag creation** - User must manually create and push the tag after PR merge
- **PR merge** - User must manually review and merge the PR
- **Post-release verification** - User must verify the release was successful

This separation ensures human oversight for the irreversible release action (tag push triggers CI/CD).

## Pre-flight Checks (MANDATORY)

Before proceeding with version updates, ALL of the following checks MUST pass. The
commands below are a derived copy of `.claude/conventions/ci-checks.md`; this skill
intentionally uses the write-mode `cargo fmt --all` (format, then verify) instead of
`--check`.

### 1. Format Code

<!-- derived: .claude/conventions/ci-checks.md -->
```bash
cargo fmt --all
```

### 2. Clippy Check

<!-- derived: .claude/conventions/ci-checks.md -->
```bash
cargo clippy --all-targets --all-features -- -D warnings
```

**CRITICAL**: Zero warnings required. Fix all issues before proceeding.

### 3. Test Suite

<!-- derived: .claude/conventions/ci-checks.md -->
```bash
cargo test --all
```

All tests must pass.

## Steps

### Step 0: Validate Current Branch (MANDATORY)

```bash
git branch --show-current
```

**CRITICAL**: Must be on `develop` or a feature branch. Cannot release from `main`.

| Current Branch | Action |
|----------------|--------|
| `main` | ❌ **STOP** - Cannot release from main |
| `develop` | ✅ Proceed |
| `feature/*` | ✅ Proceed |
| `bugfix/*` | ✅ Proceed |

If on `main`:
```
⚠️ ERROR: Cannot start release from 'main' branch.
Please checkout 'develop' or a feature branch first.
```

### Step 1: Get Target Version from User

Ask the user for the target version number (e.g., "1.1.0").

**Version Format Validation**:
- Must be valid semver: `X.Y.Z` where X, Y, Z are non-negative integers
- Examples: `1.0.0`, `1.1.0`, `2.0.0-beta.1`
- Invalid: `v1.0.0` (no 'v' prefix), `1.0` (missing patch)

### Step 2: Run Pre-flight Checks

Execute ALL pre-flight checks:

<!-- derived: .claude/conventions/ci-checks.md -->
```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

If any check fails:
1. Fix the issues
2. Re-run all checks
3. Only proceed when ALL pass

### Step 3: Update Version Files

Update version in exactly these 3 files:

| File | Pattern | Example |
|------|---------|---------|
| `Cargo.toml` | `version = "X.Y.Z"` | `version = "1.1.0"` |
| `python-wrapper/pyproject.toml` | `version = "X.Y.Z"` | `version = "1.1.0"` |
| `python-wrapper/uv_sbom_bin/install.py` | `UV_SBOM_VERSION = "X.Y.Z"` | `UV_SBOM_VERSION = "1.1.0"` |

### Step 3.5: Regenerate Cargo.lock

After updating version files, run `cargo check` to regenerate `Cargo.lock` with the new version:

```bash
cargo check
```

This ensures `Cargo.lock` reflects the updated version before committing.

### Step 3.6: Clean [Unreleased] Section Before Promoting (MANDATORY)

Review the `[Unreleased]` section and remove any entries that do not reflect
user-observable changes. This step must be completed **before** promoting to a
versioned entry in Step 4.

#### Merged-PR Audit (run first)

List every PR merged into `develop` since the last tag whose diff touches `src/`, and
check that `[Unreleased]` accounts for it. A PR is accounted for when any of its
candidate numbers appears among the entry references described in
`.claude/conventions/changelog.md` → "Reference Numbers". A PR's candidates are:

- the PR number
- the Issues it closes, or the Issue number in its branch name if it closes none
- each such Issue's parent epic: a `Part of #N` line in its body, or a GitHub
  sub-issue parent

```bash
git fetch origin --tags
LAST_TAG=$(git describe --tags --abbrev=0 origin/main)
RANGE="$LAST_TAG..origin/develop"
REFS=$(awk '/^## \[Unreleased\]/{f=1;next} /^## \[/{f=0} f' CHANGELOG.md \
  | grep -oE '#[0-9]+' | tr -d '#' | sort -u)
git log --first-parent --no-merges --format='DIRECT %h %s' "$RANGE" -- src/
echo '| PR | Title | Branch | Candidates |'; echo '|----|-------|--------|------------|'
git log --first-parent --merges --format='%H %s' "$RANGE" | while read -r sha subject; do
  pr=$(printf '%s\n' "$subject" | sed -nE 's/^Merge pull request #([0-9]+) .*/\1/p')
  [ -n "$pr" ] || continue
  git diff --quiet "$sha^1" "$sha" -- src/ && continue
  info=$(gh pr view "$pr" --json title,headRefName,closingIssuesReferences \
    --jq '[.title, .headRefName, ([.closingIssuesReferences[].number] | join(" "))] | @tsv' </dev/null)
  title=$(printf '%s' "$info" | cut -f1 | sed 's/|/\\|/g'); branch=$(printf '%s' "$info" | cut -f2)
  issues=$(printf '%s' "$info" | cut -f3)
  [ -n "$issues" ] || issues=$(printf '%s\n' "$branch" | sed -nE 's#^[^/]+/([0-9]+)-.*#\1#p')
  cands="$pr $issues"
  for i in $issues; do
    cands="$cands $(gh issue view "$i" --json body \
      --jq '(.body // "") | capture("Part of #(?<n>[0-9]+)").n? // empty' </dev/null 2>/dev/null)"
    cands="$cands $(gh issue view "$i" --json parent --jq '.parent.number // empty' </dev/null 2>/dev/null)"
  done
  hit=no
  for c in $cands; do printf '%s\n' "$REFS" | grep -qx "$c" && { hit=yes; break; }; done
  [ "$hit" = yes ] || printf '| #%s | %s | `%s` | %s |\n' "$pr" "$title" "$branch" "$(echo $cands)"
done
```

Notes on the commands:

- **Range.** The range walks `origin/develop` with `--first-parent`. Never audit up to
  a tag: tags sit on `main` merge commits, so `--first-parent` from a tag sees only the
  `develop` → `main` merge.
- **Direct commits.** `DIRECT` lines are commits that reached `develop` without a merge
  commit (squash merges or direct pushes). The `--merges` loop cannot see them.
- **PR bodies.** PR bodies are deliberately not scanned for `#N`. They cite sibling PRs
  and epics, which would mark a PR as accounted for when it is not.

If the table has rows or any `DIRECT` line printed, **STOP**. Show the table, and for
each row ask the user to either supply an entry or confirm the PR as internal-only.
Continue only when every row is resolved.

#### Sections to REMOVE

> The REMOVE and KEEP tables below are a summary of `.claude/conventions/changelog.md` →
> "What Needs an Entry", mapped to section headings. That section is authoritative and
> wins on conflict.

| Section heading | Reason |
|----------------|--------|
| `### Refactored` / `### Internal` | No behavior change |
| `### Testing` | No behavior change |
| `### Dependencies` (non-security bumps) | No behavior change for users |
| `### CI` / `### Chore` | No behavior change |

#### Sections to KEEP

| Section heading | Reason |
|----------------|--------|
| `### Added` | New user-facing features |
| `### Changed` | Behavior changes |
| `### Deprecated` | User must know |
| `### Removed` | Breaking removal |
| `### Fixed` | Bug fixes users care about |
| `### Security` | Always required |
| `### Breaking Changes` | Critical for users |
| `### Performance` | Observable improvement |

#### Edge case: [Unreleased] becomes empty after cleaning

⚠️ **WARNING: STOP — DO NOT PROCEED SILENTLY.**

If after removing internal entries the `[Unreleased]` section is empty, this
typically means one of two things:
- (a) Every entry in `[Unreleased]` was legitimately internal (refactor, CI, tests) — safe to release with no user-facing changelog.
- (b) Feature PRs landed without anyone updating `CHANGELOG.md` — this is the v2.2.0 incident (Issue #491).

**You must ask the user explicitly before continuing:**

> ⚠️ The `[Unreleased]` section is empty after removing internal entries.
> Promoting this will produce a release with no user-facing changelog.
>
> Did you intentionally make no user-facing changes in this release?
> Re-check the Merged-PR Audit table above if unsure.
>
> Type **yes** to proceed with an empty release entry, or **no** to pause and add missing entries first.

- If the user answers **yes**: continue to Step 4. The resulting file will look like:

  ```markdown
  ## [Unreleased]

  ## [X.Y.Z] - YYYY-MM-DD
  ```

- If the user answers **no**: **STOP HERE.** Do not proceed to Step 4.
  Instruct the user to add missing entries under the appropriate sections
  (`### Added`, `### Fixed`, `### Security`, `### Changed`) and then re-run `/release`.

### Step 4: Update CHANGELOG.md

**Before**:
```markdown
## [Unreleased]

### Added
- New feature
```

**After**:
```markdown
## [Unreleased]

## [X.Y.Z] - YYYY-MM-DD

### Added
- New feature
```

- Replace `## [Unreleased]` section header with version and date
- Add new empty `## [Unreleased]` section above the new version
- Date format: `YYYY-MM-DD` (e.g., `2025-02-06`)

### Step 5: Verify Version Consistency

```bash
# Check all versions match
grep 'version = "' Cargo.toml | head -1
grep 'version = "' python-wrapper/pyproject.toml
grep 'UV_SBOM_VERSION = "' python-wrapper/uv_sbom_bin/install.py
```

All three must show the same version. If not, stop and fix.

### Step 6: Create Release Branch

```bash
git checkout -b release/vX.Y.Z
```

Branch naming: `release/v{version}` (e.g., `release/v1.1.0`)

### Step 7: Commit Changes

Stage and commit all version changes using `/commit` skill conventions:

```bash
git add Cargo.toml Cargo.lock python-wrapper/pyproject.toml python-wrapper/uv_sbom_bin/install.py CHANGELOG.md
```

Commit message format:
```
chore(release): prepare v{version}

- Update version to {version} in all files
- Update CHANGELOG with release date

Co-Authored-By: Claude <noreply@anthropic.com>
```

### Step 8: Create Pull Request

Create PR to `develop` (NOT `main`):

```bash
gh pr create --base develop --title "chore(release): prepare v{version}" --body "$(cat <<'EOF'
## Summary
- Prepare release v{version}
- Update version numbers in all required files
- Update CHANGELOG with release date

## Version Files Updated
- `Cargo.toml`: version = "{version}"
- `python-wrapper/pyproject.toml`: version = "{version}"
- `python-wrapper/uv_sbom_bin/install.py`: UV_SBOM_VERSION = "{version}"

## CHANGELOG
- Converted [Unreleased] to [{version}] - {date}
- Added empty [Unreleased] section

## Test Plan
- [x] `cargo fmt --all -- --check` passes
- [x] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [x] `cargo test --all` passes
- [x] All version strings are consistent

## Post-Merge Manual Steps
After merging this PR into `develop`:
1. Open a PR: `develop` → `main`
2. Merge the PR to main
3. Create tag: `git tag v{version}`
4. Push tag: `git push origin v{version}`
5. Verify CI release workflow completes successfully

---
Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

**IMPORTANT**: PR base branch is `develop`, NOT `main`. The `develop` → `main` PR is a separate manual step after this PR is merged.

### Step 9: Output Manual Next Steps

After PR creation, display the following instructions:

```
✅ Release PR created successfully!

📋 Manual steps after PR is merged:

1. Wait for CI to pass and get approval
2. Merge the PR into `develop`

3. Open a second PR: develop → main
   gh pr create --base main --head develop \
     --title "chore(release): v{version}" \
     --body "Merge release v{version} from develop into main."

4. Merge the develop → main PR

5. Create and push the tag:
   git checkout main
   git pull origin main
   git tag v{version}
   git push origin v{version}

6. Verify the release:
   - Check GitHub Actions release workflow
   - Verify GitHub Release was created
   - Check crates.io publication
   - Check PyPI publication
```

## Error Handling

### Invalid Version Format

If version doesn't match semver:
```
⚠️ ERROR: Invalid version format: '{input}'
Version must be in semver format: X.Y.Z (e.g., 1.1.0)
```

### Pre-flight Check Failures

If any pre-flight check fails:
1. Display the error
2. Fix the issues
3. Re-run ALL checks
4. Only proceed when all pass

### Version Mismatch After Update

If versions don't match after update:
```
⚠️ ERROR: Version mismatch detected!

Cargo.toml: {version1}
pyproject.toml: {version2}
install.py: {version3}

Please fix manually and retry.
```

### CHANGELOG Already Has Version

If CHANGELOG already contains the target version:
```
⚠️ WARNING: CHANGELOG.md already contains [{version}]
This version may have already been released.
Do you want to continue anyway? (y/N)
```

## Example Usage

User: "/release 1.1.0" or "リリース 1.1.0"

Claude executes /release skill:
1. Validates current branch (develop) ✓
2. Validates version format (1.1.0) ✓
3. Runs pre-flight checks (fmt, clippy, test) ✓
4. Updates Cargo.toml version
5. Updates pyproject.toml version
6. Updates install.py UV_SBOM_VERSION
7. Runs `cargo check` to regenerate Cargo.lock ✓
8. Removes non-user-facing sections from [Unreleased] (Testing, Dependencies, CI, etc.) ✓
9. Updates CHANGELOG.md (promotes cleaned [Unreleased] to [1.1.0])
10. Verifies all versions match ✓
11. Creates branch `release/v1.1.0`
12. Commits: "chore(release): prepare v1.1.0" (includes Cargo.lock)
13. Creates PR to `develop` (NOT main)
14. Outputs manual next steps (including develop → main PR)

Final output:
```
✅ Release preparation complete!
PR: https://github.com/Taketo-Yoda/uv-sbom/pull/XXX

📋 After PR merge, run:
   git tag v1.1.0
   git push origin v1.1.0
```
