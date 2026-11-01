# uv-sbom Project Context

Orientation for Claude Code and contributors: what uv-sbom is and why it is built this
way. For facts that have an owner elsewhere, this file links to the owner instead of
copying it.

## Project Overview

**uv-sbom** is a Rust-based CLI tool that generates SBOM (Software Bill of Materials) from projects managed by the Python package manager [uv](https://github.com/astral-sh/uv).

### Key Objectives
- Visualize uv project dependencies
- Generate SBOMs for security audits and compliance
- Automatically collect and report license information
- Analyze direct and transitive dependencies
- Check for known vulnerabilities and license policy violations, and respond to a single advisory (`--incident`), with exit codes suited to CI

Full feature list: [README.md → Features](../README.md#features).

### Version Information
- Rust Edition: 2021
- CycloneDX Specification: 1.6
- Architecture: Hexagonal Architecture + DDD

The release version lives in `Cargo.toml`. To change it, run `/release`, which bumps
the version files listed in `.claude/skills/release/SKILL.md` → "Step 3: Update
Version Files".

## Technology Stack

Rust CLI. Crates and their versions: see `[dependencies]` / `[dev-dependencies]` in
[Cargo.toml](../Cargo.toml), the only source; this file lists no crate versions. Which
layer may depend on what: [instructions.md → Adding Dependencies](instructions.md#adding-dependencies).

## Architecture: Hexagonal Architecture + DDD

### Architecture Principles

This project adopts **Hexagonal Architecture (Ports & Adapters pattern)** and **Domain-Driven Design (DDD)**.

**Key Benefits**:
1. **Testability**: Domain logic is isolated from I/O, easily testable with mocks
2. **Maintainability**: Clear separation of concerns, easy to locate code
3. **Flexibility**: Infrastructure implementations can be easily swapped
4. **Screaming Architecture**: Directory structure expresses the system's purpose

### Layer Structure

- Module/layer structure, key types, and invariants:
  [CLAUDE.md → Architecture Overview](CLAUDE.md#architecture-overview) (authoritative)
- Quick summary: [instructions.md → Layer Rules](instructions.md#layer-rules)
- Longer narrative: [ARCHITECTURE.md](../ARCHITECTURE.md) /
  [ARCHITECTURE-JP.md](../ARCHITECTURE-JP.md) (may lag behind CLAUDE.md, which wins on
  conflict)

### Exit Codes

See [README.md → Exit Codes](../README.md#exit-codes), backed by `ExitCode` in
`src/shared/error.rs`.

## Resources

### Documentation
- `README.md`: User guide
- `.claude/CLAUDE.md`: Architecture, skill routing, Issue-First rule
- `.claude/instructions.md`: Quick reference for Claude Code
- `.claude/conventions/README.md`: Which file owns which cross-file convention
- `.claude/skills/`: Workflow skills; the routing table is
  [CLAUDE.md → Skill Invocation Rules](CLAUDE.md#skill-invocation-rules)
- `.claude/agents/`: Role-based agents; see
  [CLAUDE.md → Agent Invocation Rules](CLAUDE.md#agent-invocation-rules)
- `.claude/product-vision.md`: Product vision and competitive positioning
- `.claude/feature-triage.md`: Triage checklist for feature proposals
- `.claude/output-design.md`: Output structure rules, anti-patterns, and formatting standards

### External References
- [CycloneDX 1.6 Specification](https://cyclonedx.org/docs/1.6/)
- [PyPI JSON API](https://docs.pypi.org/api/json/)
- [uv](https://github.com/astral-sh/uv)
