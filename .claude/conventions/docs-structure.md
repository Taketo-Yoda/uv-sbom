# Documentation Structure (canonical)

Single source of truth for where user-facing documentation lives, how new
content is routed after the README restructuring in #1064, and how English and
Japanese documentation is written (#1160). Japanese translation directory
(`docs/ja/`) added in #1088.

## Structure

README.md and README-JP.md are **landing pages** (~250 lines). They contain
badges, a hero section, a quick-start block, and 2–3 line feature summaries
with links to the appropriate `docs/` file. Detailed documentation — examples,
tables, option lists, configuration schemas — lives exclusively in `docs/`.

Each English `docs/` file has a corresponding Japanese translation in `docs/ja/`:

```
docs/
├── security-checks.md
├── incident-response.md
├── dependency-insight.md
├── configuration.md
├── ci-integration.md
├── workspace.md
├── network.md
├── cli-reference.md
└── ja/
    ├── security-checks.md
    ├── incident-response.md
    ├── dependency-insight.md
    ├── configuration.md
    ├── ci-integration.md
    ├── workspace.md
    ├── network.md
    └── cli-reference.md
```

## Routing Table

When adding or updating user-facing documentation for a CLI flag, config key,
or feature, route the **detailed content** to the correct `docs/` file:

| Content type | Target file |
|---|---|
| Security features (CVE, license, abandoned, non-PyPI, Python compat, exploitability, link verification, input validation) | `docs/security-checks.md` |
| Incident response (`--incident`) | `docs/incident-response.md` |
| Dependency insight (`--explain`, `--show-dependency-tree`, `--diff`, resolution guide, upgrade advisor) | `docs/dependency-insight.md` |
| Configuration file keys, schema reference, merge/priority rules, exclude patterns, dependency groups | `docs/configuration.md` |
| CI integration, exit codes, GitHub Actions / GitLab CI examples, scripting | `docs/ci-integration.md` |
| Workspace mode (`--workspace`) | `docs/workspace.md` |
| Network requirements, firewall, proxy, offline mode | `docs/network.md` |
| CLI options listing, output format examples | `docs/cli-reference.md` |

## Japanese Translation Routing

Each English source file maps to its Japanese counterpart:

| English source | Japanese translation |
|----------------|---------------------|
| `docs/security-checks.md` | `docs/ja/security-checks.md` |
| `docs/incident-response.md` | `docs/ja/incident-response.md` |
| `docs/dependency-insight.md` | `docs/ja/dependency-insight.md` |
| `docs/configuration.md` | `docs/ja/configuration.md` |
| `docs/ci-integration.md` | `docs/ja/ci-integration.md` |
| `docs/workspace.md` | `docs/ja/workspace.md` |
| `docs/network.md` | `docs/ja/network.md` |
| `docs/cli-reference.md` | `docs/ja/cli-reference.md` |

## README Landing Page Rules

- **README.md**: Add at most a 1-line summary + `docs/` link in the Feature
  Highlights section, only if the feature is significant enough. Never add a
  full subsection, config table, or multi-line example.
- **README-JP.md**: Mirror only the landing-page summary line (translated to
  Japanese). Link to `docs/ja/` files (Japanese); anchor fragments use Japanese
  heading text; no `（英語）` labels.
- **python-wrapper/README.md**: Update only when changes affect installation,
  basic usage examples, or version/badge updates.

## Update Checklist

Trigger this checklist when **any** of the following is true:
- A `docs/*.md` file is being changed
- README.md or README-JP.md content is being changed
- A new CLI flag or config key was added
- A new user-facing feature was implemented

When triggered, check:

| File | Action Required | Notes |
|---|---|---|
| `docs/<target>.md` | Add detailed content per routing table | Primary documentation home |
| `docs/ja/<target>.md` | Update with Japanese translation of new/changed content | Japanese translation |
| `docs/cli-reference.md` | Update CLI options listing if a flag was added/changed | Always |
| README.md | Add/update 1-line summary + link (if significant) | Landing page only |
| README-JP.md | Translate the README.md summary line; link to `docs/ja/` | Landing page only |
| python-wrapper/README.md | Reflect if applicable | PyPI-focused, keep concise |

When a new `docs/<file>.md` is created:

- [ ] A corresponding `docs/ja/<file>.md` is created
- [ ] A row is added to the Japanese Translation Routing table above
- [ ] Both README.md and README-JP.md documentation tables are updated

## Japanese Writing Style

Applies to `README-JP.md` and `docs/ja/*.md`. The `src/i18n/` message catalog
is not covered by this section.

### Approach

- Write each page as a native Japanese technical document, not a
  sentence-by-sentence translation. Carry over the meaning of each section;
  reorder, merge, or split sentences when that reads more naturally. Headings,
  code blocks, examples, and tables still mirror the English source mapped in
  "Japanese Translation Routing".

### Punctuation and Spacing

- Use 「、」 and 「。」 in Japanese sentences.
- No em dash (—) in Japanese text, including list items. Break the sentence,
  use parentheses, or, for a name + description list item, separate with 「：」
  (`` **ライセンスコンプライアンス** (`--check-license`)：ワイルドカード対応の許可/拒否リスト。 ``).
- No colon (「：」 or `:`) at the end of a line that introduces a list, table,
  or code block. End the sentence with 「。」 instead (「次のように設定します。」).
  Bold labels drop the colon (「**出力例**」, not 「**出力例:**」). A colon inside a
  line (「デフォルト：730」, the list-item separator above) is not affected.
- Put a half-width space between Japanese and Latin words, numbers, or inline
  code (「CVE スキャン」「`uv.lock` を読み取る」). Exception: no space between a
  digit and a Japanese counter or unit (「1つ」「3件」「2回」「730日」). Latin
  units keep the space (「10 MB」).

### Wording

- Avoid katakana calques when a plain Japanese term exists (「実用的」, not
  「アクション可能」). Established loanwords (ライセンス, ワークスペース) are fine;
  "Terminology" decides contested cases.
- Keep parallel lists grammatically parallel: every item ends in the same form.
- Do not address the reader as 「あなた」; omit the subject. Do not personify
  tools (「uv-sbom が教えてくれます」 → 「uv-sbom は〜を表示します」).
- Do not add marketing closers (「すべて1つのツールで」); see
  "English Writing Style".
- Keep CLI flags, config keys, package names, file names, CVE/GHSA IDs, and
  SPDX license IDs untranslated. Example output stays in the language the tool
  emits.

### Terminology

Use the Japanese term in this table. For a term not listed, use the form
dominant in `docs/ja/` unless it is a katakana calque, and add a row in the
same change.

| English term | Japanese term | Avoid | Note |
|---|---|---|---|
| abandoned package | 放置パッケージ | 放棄パッケージ | Matches the `docs/ja/security-checks.md` heading and anchor |
| prioritization | 優先順位付け | 優先度付け | Matches the `docs/ja/security-checks.md` heading and anchor |
| direct dependency | 直接依存 | — | 「直接依存関係」 is also correct; same form as CLI output |
| transitive dependency | 間接依存 | 推移的依存、推移的依存関係 | Same form as CLI output; as a modifier, 間接依存パッケージ, 間接依存の脆弱性 |
| dependency (general) | 依存関係 | 依存性 | |
| vulnerability | 脆弱性 | バルネラビリティ | |
| advisory | アドバイザリ | アドバイザリー | |
| fixed version | 修正バージョン | 修正版 | |
| workspace | ワークスペース | — | Feature name for `--workspace` |
| lockfile | ロックファイル | ロック ファイル | The file name stays `uv.lock` |
| threshold | しきい値 | 閾値 | 「閾」 is not a jōyō kanji |
| actionable | 実用的、すぐ対応できる | アクション可能 | Calque example |

### Mechanical Check

The mechanical check is the yomiyasu lint
(https://github.com/nanaism/yomiyasu): `scripts/yomiyasu_lint.py` with the
project word list in `.yomiyasu-words/`, run on `README-JP.md` and `docs/ja/` by
`.github/workflows/docs-lint.yml` (#1161). It is warn-only until #1165 switches
it to `--fail-on warn`, so until then these rules are also checked in review.
Add a term to `.yomiyasu-words/allow.txt` only when "Terminology" (or an
established project name) allows it. When the lint and this section disagree,
this section wins.

## English Writing Style

Applies to `README.md` and `docs/*.md`.

- Use em dashes sparingly. The list-item pattern
  `` **Name** (`--flag`) — description `` is allowed. In running prose, prefer a
  period, comma, colon, or parentheses; do not use an em dash as a general
  clause joiner.
- No filler sentences that stack adjectives without stating a fact
  ("Fast, reliable, and comprehensive."). Each sentence states what the tool
  does or how to use it.
- No marketing closers such as "all in one" or "everything you need in one
  tool" at the end of a list or section. End on the last concrete fact.

## Consumers

- `/implement` Step 4.3 — CLI Flag Documentation Gate (sub-checks A and B)
- `/pr` Step 4.6 — CLI Flag Documentation Backstop (sub-checks A and B)
- `CLAUDE.md` → "README Update Checklist" (links here)
- `.claude/agents/i18n.md` → Surface 2 — reviews `README-JP.md` and `docs/ja/*.md` against "Japanese Writing Style"
- `.claude/agents/devrel.md` → Responsibilities — reviews `README.md` and `docs/*.md` against "English Writing Style"
