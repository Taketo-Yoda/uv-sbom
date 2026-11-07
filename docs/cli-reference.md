# CLI Reference

[Back to README](../README.md)

Complete command-line options and output format examples for uv-sbom.

## Table of Contents

- [Command-Line Options](#command-line-options)
- [Output Examples](#output-examples)

---

## Command-Line Options

```
Options:
  -f, --format <FORMAT>              Output format: json or markdown [default: json; markdown in --incident mode]
  -p, --path <PATH>                  Path to the project directory [default: current directory]
  -o, --output <OUTPUT>              Output file path (if not specified, outputs to stdout)
  -e, --exclude <PATTERN>            Exclude packages matching patterns (supports wildcards: *)
  -c, --config <PATH>               Path to config file (auto-discovers uv-sbom.config.yml if not specified)
  -i, --ignore-cve <CVE_ID>         CVE IDs to ignore (can be specified multiple times)
      --lang <LANG>                  Output language for human-readable formats: en or ja [default: en]
      --init                         Generate a uv-sbom.config.yml template file
      --dry-run                      Validate configuration without network communication or output generation
      --verify-links                 Verify PyPI links exist before generating hyperlinks (Markdown format only)
      --no-check-cve                 Disable CVE vulnerability checking (enabled by default)
      --severity-threshold <LEVEL>   Severity threshold for vulnerability check (low/medium/high/critical)
                                     Cannot be used with --no-check-cve
      --cvss-threshold <SCORE>       CVSS threshold for vulnerability check (0.0-10.0)
                                     Cannot be used with --no-check-cve
      --suggest-fix                  Suggest direct dependency upgrade versions to resolve transitive vulnerabilities
                                     Requires uv CLI installed and pyproject.toml in project directory
      --workspace                    Generate one SBOM per workspace member
                                     Cannot be used with --output
      --diff <REF_OR_PATH>           Compare current uv.lock against a base (git ref, tag, commit SHA, or path to a uv.lock file)
      --check-license                Check license compliance against policy
      --check-abandoned              Check for abandoned/unmaintained packages (no upstream release within threshold days)
      --abandoned-threshold-days <DAYS>  Inactivity threshold in days for abandoned-package detection (default: 730)
      --check-non-pypi               Check for packages sourced from non-PyPI origins (git, direct URL, private registries)
      --check-exploitability         Enrich CVE results with EPSS scores and CISA KEV status
                                     Cannot be used with --no-check-cve
      --license-allow <LIST>         Comma-separated list of allowed license patterns (overrides config)
      --license-deny <LIST>          Comma-separated list of denied license patterns (overrides config)
      --exclude-groups <GROUPS>      Exclude packages reachable only through the specified dependency groups (comma-separated)
                                     Example: --exclude-groups dev,test,lint. Cannot be used with --production-only
      --production-only              Exclude all non-default dependency groups (production-only mode)
                                     Cannot be used with --exclude-groups
      --target-python <VERSION>      Target Python version for compatibility checking (PEP 440 format, e.g. 3.8)
      --baseline <PATH>              Path to a vulnerability baseline file for suppressing previously-accepted findings
                                     Cannot be used with --no-check-cve
      --update-baseline              Update the baseline file with all current vulnerability findings after SBOM generation
                                     Requires --baseline
      --explain <PACKAGE_NAME>       Trace the dependency path(s) to the given package (Markdown format only)
                                     Cannot be used with --workspace
      --show-dependency-tree        Render the dependency graph as an ASCII tree (Markdown format only)
      --dependency-tree-depth <DEPTH>  Maximum depth for the dependency tree visualization (default: 3)
                                     Requires --show-dependency-tree
      --incident <ID_OR_RANGE>       Check whether one advisory (GHSA-/PYSEC-/CVE-/OSV-/MAL- ID) affects the project,
                                     whether the fix is released, and which command to run (Markdown by default)
                                     For an advisory not yet in OSV, pass a quoted range such as "foo>=2.0,<2.3.2"
                                     (operators >=, <, <= only)
                                     With --workspace, reports every member in one combined report
                                     Cannot be used with --diff or the check flags (see Incident Response)
  -h, --help                         Print help
  -V, --version                      Print version
```

## Output Examples

### Markdown Format

> **Note**: The Markdown format sample is based on the SBOM format from [ja-complete v0.1.0](https://github.com/Taketo-Yoda/ja-complete/tree/v0.1.0).

```markdown
## Summary

| Item | Count | Status |
|------|-------|--------|
| Direct dependencies | 2 | ✅ |
| Transitive dependencies | 3 | ✅ |
| ...vulnerability rows... | | |
| License violations | 0 | ✅ |

**Overall: No issues found** ✅

# Software Bill of Materials (SBOM)

## Component Inventory

A comprehensive list of all software components and libraries included in this project.

| Package | Version | License | Description |
|---------|---------|---------|-------------|
| janome | 0.5.0 | AL2 | Japanese morphological analysis engine. |
| pydantic | 2.12.5 | MIT | Data validation using Python type hints |
| ...additional packages... |

## Direct Dependencies

Primary packages explicitly defined in the project configuration(e.g., pyproject.toml).

| Package | Version | License | Description |
|---------|---------|---------|-------------|
| janome | 0.5.0 | AL2 | Japanese morphological analysis engine. |
| pydantic | 2.12.5 | MIT | Data validation using Python type hints |

## Transitive Dependencies

Secondary dependencies introduced by the primary packages.

### Dependencies for pydantic

| Package | Version | License | Description |
|---------|---------|---------|-------------|
| annotated-types | 0.7.0 | MIT License | Reusable constraint types to use with typing.Annotated |
| pydantic-core | 2.41.5 | MIT | Core functionality for Pydantic validation and serialization |
```

### CycloneDX JSON Format

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "serialNumber": "urn:uuid:...",
  "metadata": {
    "timestamp": "2024-01-01T00:00:00Z",
    "tools": [
      {
        "name": "uv-sbom",
        "version": "0.1.0"
      }
    ]
  },
  "components": [
    {
      "type": "library",
      "name": "requests",
      "version": "2.31.0",
      "description": "HTTP library for Python",
      "licenses": [
        {
          "license": {
            "name": "Apache 2.0"
          }
        }
      ],
      "purl": "pkg:pypi/requests@2.31.0"
    }
  ]
}
```
