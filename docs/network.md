# Network Requirements

[Back to README](../README.md)

uv-sbom makes HTTP requests to several external services during SBOM generation. This page covers the domains accessed, firewall and proxy configuration, and offline mode.

## Table of Contents

- [External Domains Accessed](#external-domains-accessed)
- [Firewall Configuration](#firewall-configuration)
- [Proxy Configuration](#proxy-configuration)
- [Offline Mode](#offline-mode)

---

## External Domains Accessed

### Required for all operations:

1. **PyPI (Python Package Index)**
   - Domain: `https://pypi.org`
   - Purpose: Fetch license information for Python packages
   - When: Every SBOM generation (unless using `--dry-run`)
   - Rate limit: No official limit, but tool implements retry logic
   - Endpoint: `/pypi/{package_name}/json`

### Optional (only when using `--no-check-cve` disables CVE, or `--verify-links`):

2. **PyPI Link Verification**
   - Domain: `https://pypi.org`
   - Purpose: Verify package existence on PyPI via HTTP HEAD requests
   - When: Only when `--verify-links` flag is used
   - Rate limit: Max 10 concurrent requests
   - Endpoint: `/project/{package_name}/`

3. **OSV (Open Source Vulnerability Database)**
   - Domain: `https://api.osv.dev`
   - Purpose: Fetch vulnerability information for security scanning
   - When: By default (unless `--no-check-cve` is used)
   - Rate limit: Tool implements 10 requests/second limit
   - Endpoints:
     - `/v1/querybatch` - Batch query for vulnerability IDs
     - `/v1/vulns/{vuln_id}` - Detailed vulnerability information

4. **FIRST.org EPSS API**
   - Domain: `https://api.first.org`
   - Purpose: Fetch EPSS (Exploit Prediction Scoring System) scores and percentiles for CVEs
   - When: Only when `--check-exploitability` flag is used
   - Endpoint: `/data/v1/epss?cve=CVE-A,CVE-B,...` (batched)

5. **CISA KEV (Known Exploited Vulnerabilities) Catalog**
   - Domain: `https://www.cisa.gov`
   - Purpose: Check whether CVEs have confirmed active exploitation
   - When: Only when `--check-exploitability` flag is used
   - Endpoint: `/sites/default/files/feeds/known_exploited_vulnerabilities.json`

## Firewall Configuration

If you are behind a corporate firewall or proxy, ensure the following domains are on the allowlist:

```
# Required
pypi.org

# Optional (for --verify-links only; OSV is accessed by default unless --no-check-cve)
pypi.org       # Also used for --verify-links
api.osv.dev    # Disabled only with --no-check-cve

# Optional (for --check-exploitability only)
api.first.org  # EPSS scores
www.cisa.gov   # CISA KEV catalog
```

## Proxy Configuration

The tool respects standard HTTP/HTTPS proxy environment variables:

```bash
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1

uv-sbom --format json
```

## Offline Mode

To validate configuration without making network requests, use `--dry-run`:

```bash
uv-sbom --dry-run
```

This mode:
- Validates `uv.lock` file
- Validates command-line arguments
- Checks exclude patterns
- Skips license fetching (no PyPI access)
- Skips vulnerability checking (no OSV access)
- Skips SBOM output generation
