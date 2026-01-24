# Security Policy

## User Input Handling

### Exclude Patterns (`-e`/`--exclude` option)

#### Threat Model

**Input source**: Command-line arguments provided by users
**Risk level**: Low to Medium
- Users typically run the tool in their own environment
- Patterns are never executed as code or used in file operations
- Primary risks: DoS, log injection, terminal escape sequence injection

#### Mitigations Implemented

1. **Input Validation**
   - Character whitelist (alphanumeric + safe punctuation)
   - Length limits (255 chars per pattern, 64 patterns max)
   - Empty/wildcard-only pattern rejection

2. **Safe Usage**
   - Patterns used only for string comparison
   - No shell command execution
   - No file system operations
   - No database queries

3. **DoS Prevention**
   - Pattern count limit (64)
   - Pattern length limit (255)
   - Efficient O(n) algorithm for common cases
   - Tested worst-case: 64 patterns × 1000 packages in ~12ms

#### Attack Vectors Considered

| Attack Type | Mitigation |
|------------|-----------|
| Command Injection | Patterns never passed to shell |
| Path Traversal | Patterns not used in file operations |
| DoS (Memory) | 64 pattern limit, 255 char limit |
| DoS (CPU) | Efficient algorithm, tested complexity |
| Log Injection | Control characters blocked |
| Terminal Escape | ESC and control chars blocked |
| Unicode Spoofing | Direction-override chars blocked |

#### Design Decisions

**Character Whitelist Rationale**:
- Alphanumeric characters (Unicode-aware) for international package names
- Hyphens, underscores, dots: Standard in Python package naming conventions
- Square brackets: Required for package extras (e.g., `requests[security]`)
- Asterisks: Wildcard matching functionality

**Limits Rationale**:
- 64 pattern limit: Balances flexibility with DoS prevention
- 255 character limit: Matches typical maximum package name length in Python ecosystem
- Combined limits ensure worst-case processing time remains acceptable (<20ms)

## Automated Security Scanning

### Dependency Scanning (Dependabot)

- **Frequency**: Weekly scans
- **Scope**: All dependencies in `Cargo.toml` / `Cargo.lock`
- **Response Policy**: All alerts are reviewed and addressed as a matter of principle

### Static Code Analysis (CodeQL)

- **Trigger**: All pull requests
- **Scope**: Full codebase analysis
- **Response Policy**: All findings are reviewed and addressed before merging

### Alert Response Policy

All Dependabot and CodeQL alerts are reviewed. Critical and High severity issues are prioritized. Alerts are addressed in accordance with our Security Update Policy below.

## Reporting Security Vulnerabilities

If you discover a security vulnerability, please report it by creating a [GitHub Security Advisory](https://github.com/Taketo-Yoda/uv-sbom/security/advisories/new).

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and aim to publish a fix within 7 days for critical vulnerabilities.

## Security Update Policy

- **Critical vulnerabilities**: Patched within 7 days
- **High-severity vulnerabilities**: Patched within 14 days
- **Medium/Low-severity vulnerabilities**: Patched in next regular release

Security patches will be released as patch versions (e.g., 1.2.3 → 1.2.4) and backported to the latest stable minor version if applicable.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Latest  | ✅ Yes             |
| < Latest| ❌ No (upgrade recommended) |

We recommend always using the latest version to ensure you have all security patches.
