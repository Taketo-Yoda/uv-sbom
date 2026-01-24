# Project Instructions

## Skill Invocation Rules

When the user requests any of the following operations, ALWAYS invoke the corresponding skill defined in `.claude/skills/` directory. Never execute these operations directly without following the skill procedures.

| User Request | Skill to Invoke | Key Requirements |
|--------------|-----------------|------------------|
| Commit changes | /commit | Run `cargo fmt`, `cargo clippy`, English message |
| Create PR | /pr | Run pre-flight checks, English title/body |
| Push to remote | /pre-push | Run all validations before push |
| Create Issue | /issue | English title/body, proper template |
| Implement Issue | /implement | Full workflow from branch to PR |

### Why This Rule Exists

Skills contain mandatory pre-flight checks and language requirements that prevent:
- CI failures from formatting issues (`cargo fmt --all -- --check`)
- Clippy warnings causing CI failures (`-D warnings` flag)
- Language inconsistencies in GitHub artifacts (all must be in English)
- Missing code quality validations
- Direct commits to protected branches (`main`, `develop`)

### Recent Incidents

- **PR #121**: Created in Japanese, `cargo fmt --all -- --check` failed in CI
- **Issue #59**: `cargo clippy` was run without `-D warnings`, causing CI failure after push

### Enforcement

When a user requests any operation listed above (even in Japanese), Claude MUST:

1. Recognize the operation type
2. Invoke the corresponding skill
3. Follow ALL steps defined in the skill, including pre-flight checks
4. Ensure all outputs (commits, PRs, Issues) are in English
