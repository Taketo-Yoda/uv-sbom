---
name: dependabot
description: Handle Dependabot security vulnerability alerts with standardized workflow
---

# /dependabot - Security Alert Handling Skill

Handle Dependabot security vulnerability alerts with a standardized workflow, from alert analysis to PR submission.

## Language Requirement

**IMPORTANT**: All outputs (commits, PRs) MUST be written in **English**.

## Critical Restrictions

### Alert Number Usage - PROHIBITED

**Dependabot alert numbers MUST NOT appear in any of the following:**

- Branch names
- Commit messages
- PR titles
- PR bodies

**Reason**: Alert numbers are repository-specific and not readable by third parties. Use standard identifiers instead.

### Standard Identifiers - REQUIRED

Use these identifiers in order of priority:

| Priority | Identifier | Format | Example |
|----------|------------|--------|---------|
| 1 (Primary) | CVE ID | `CVE-YYYY-NNNNN` | `CVE-2026-25541` |
| 2 (Fallback) | GHSA ID | `GHSA-xxxx-xxxx-xxxx` | `GHSA-434x-w66g-qw3r` |

Use GHSA only when CVE is not available.

## Workflow Overview

```
Alert Analysis → Branch Creation → Fix Application → Commit → PR Creation
```

## Steps

### Step 1: Fetch Alert Details (MANDATORY)

```bash
gh api repos/{owner}/{repo}/dependabot/alerts/{alert_number}
```

Extract the following information:

| Field | JSON Path | Description |
|-------|-----------|-------------|
| CVE ID | `.security_advisory.cve_id` | Primary identifier |
| GHSA ID | `.security_advisory.ghsa_id` | Fallback identifier |
| Package | `.security_vulnerability.package.name` | Affected package |
| Severity | `.security_vulnerability.severity` | low/medium/high/critical |
| Vulnerable Range | `.security_vulnerability.vulnerable_version_range` | Affected versions |
| Fixed Version | `.security_vulnerability.first_patched_version.identifier` | Target version |
| Summary | `.security_advisory.summary` | Vulnerability description |

### Step 2: Analyze Vulnerability

Determine the fix approach:

| Scenario | Approach |
|----------|----------|
| Dependency update resolves | Run `cargo update -p <package>` |
| Code changes required | Implement necessary fixes |
| Breaking changes in fix | Evaluate and document migration |

**Decision Criteria**:
- Check if the fixed version is compatible with current code
- Review advisory references for migration guides
- Analyze if the vulnerability affects this project's usage

### Step 3: Create Branch (MANDATORY)

**Branch Naming Format**:

```
bugfix/CVE-YYYY-NNNNN
```

Or if CVE is not available:

```
bugfix/GHSA-xxxx-xxxx-xxxx
```

**Commands**:

```bash
# Verify current branch
git branch --show-current

# Create branch from develop
git fetch origin
git checkout -b bugfix/<CVE-or-GHSA-ID> origin/develop
```

**CRITICAL**: Never include the Dependabot alert number in the branch name.

### Step 4: Apply Fix

#### Option A: Dependency Update

```bash
# Update specific package
cargo update -p <package-name>

# Verify the update
cargo tree -p <package-name>
```

#### Option B: Code Changes

If code modifications are required:
1. Follow the advisory's recommended fixes
2. Update affected code paths
3. Ensure backward compatibility where possible

### Step 5: Run Tests

```bash
cargo test
```

**Note**: No additional security-specific tests required. Standard test suite is sufficient.

### Step 6: Commit Changes

Invoke `/commit` skill with:

- Commit type: `fix` (for security fixes)
- Scope: `deps` (for dependency updates) or affected module
- Reference CVE/GHSA in commit message (NOT alert number)

**Commit Message Format**:

```
fix(deps): update <package> to fix <CVE-ID>

<brief description of the vulnerability>

Advisory: <GHSA-ID>
```

### Step 7: Create Pull Request

Invoke `/pr` skill with the following PR body template:

```markdown
## Security Fix

- **Advisory**: GHSA-xxxx-xxxx-xxxx
- **CVE**: CVE-xxxx-xxxxx (if available)
- **Package**: <package-name>
- **Severity**: <low|medium|high|critical>
- **Fixed Version**: <version>
- **Summary**: <vulnerability summary>

## Changes

<description of changes made>

## Test Plan

- [ ] `cargo test` passes
- [ ] Vulnerability is resolved (Dependabot will auto-close alert)
```

**CRITICAL**:
- Use `security` label for the PR
- Never include the Dependabot alert number in title or body

### Step 8: Alert Closure

**No manual action required.**

GitHub Dependabot automatically closes alerts when:
- The vulnerable dependency is updated to a patched version
- The PR is merged and the fix is deployed

Do not manually dismiss or close alerts.

## Error Handling

### Alert Not Found

If `gh api` returns 404:
1. Verify the alert number is correct
2. Check repository permissions
3. Report error to user

### Package Update Fails

If `cargo update -p <package>` fails:
1. Check for version constraints in `Cargo.toml`
2. Review dependency tree for conflicts
3. Consider updating constraints if safe

### Breaking Changes

If the fixed version introduces breaking changes:
1. Document the breaking changes
2. Implement necessary code migrations
3. Update tests accordingly
4. Note breaking changes in PR description

### CVE Not Available

If only GHSA ID is available:
1. Use GHSA ID for branch name
2. Note in PR that CVE is pending or not assigned
3. Proceed with the fix

## Example Usage

User: "dependabot alert 36を対応して"

Claude executes /dependabot skill:

1. Fetches alert #36 details via `gh api`
2. Extracts: CVE-2026-25541, GHSA-434x-w66g-qw3r, package: bytes, severity: medium
3. Creates branch `bugfix/CVE-2026-25541`
4. Runs `cargo update -p bytes`
5. Verifies update with `cargo tree -p bytes`
6. Runs `cargo test`
7. Invokes `/commit` skill with security fix message
8. Invokes `/pr` skill with security fix template
9. Reports: "Created PR #XX for CVE-2026-25541 (bytes vulnerability)"

## Reference URLs

- Dependabot Alert: `https://github.com/{owner}/{repo}/security/dependabot/{number}`
- GHSA Advisory: `https://github.com/advisories/{GHSA-ID}`
- CVE Details: `https://nvd.nist.gov/vuln/detail/{CVE-ID}`
