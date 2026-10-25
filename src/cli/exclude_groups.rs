//! Resolution of the dependency groups to exclude (`--exclude-groups`,
//! `--production-only`).
//!
//! Kept out of `config_resolver` because `--production-only` needs lockfile
//! I/O, and out of `main.rs` so it can be unit tested (#995).

use crate::ports::outbound::{LockfileReader, WorkspaceMember};
use crate::shared::Result;
use std::collections::BTreeSet;
use std::path::Path;

/// Resolves the groups to exclude.
///
/// Without `production_only`, returns `configured` (the merged
/// `--exclude-groups` / config value) unchanged. With it, returns every
/// dependency-group name, sorted and deduplicated:
///
/// - single project (`members` is `None`): the groups in `root`'s lockfile;
/// - workspace (`members` is `Some`): the union of every member's own groups,
///   read with `read_and_parse_group_roots_for_member`, so a group declared
///   only by a later member in a revision-3 lockfile is not missed (#995). A
///   name a member does not declare matches nothing for that member, so the
///   union is safe to apply to each of them.
///
/// # Errors
/// Returns an error if the group roots cannot be read from the lockfile.
pub fn resolve_exclude_groups<R: LockfileReader>(
    reader: &R,
    production_only: bool,
    configured: &[String],
    root: &Path,
    members: Option<&[WorkspaceMember]>,
) -> Result<Vec<String>> {
    if !production_only {
        return Ok(configured.to_vec());
    }

    let mut names: BTreeSet<String> = BTreeSet::new();
    match members {
        None => names.extend(reader.read_and_parse_group_roots(root)?.into_keys()),
        Some(members) => {
            for member in members {
                names.extend(
                    reader
                        .read_and_parse_group_roots_for_member(root, &member.name)?
                        .into_keys(),
                );
            }
        }
    }
    Ok(names.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::outbound::filesystem::FileSystemReader;
    use crate::ports::outbound::{GroupRoots, LockfileParseResult, PackageSourceMap};
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Group roots per member, plus a different map for the workspace-wide
    /// read, so a test can tell which read was used.
    struct GroupsReader {
        workspace_wide: GroupRoots,
        by_member: HashMap<String, GroupRoots>,
    }

    impl LockfileReader for GroupsReader {
        fn read_lockfile(&self, _path: &Path) -> Result<String> {
            unreachable!("not used by resolve_exclude_groups")
        }

        fn read_and_parse_lockfile(&self, _path: &Path) -> Result<LockfileParseResult> {
            unreachable!("not used by resolve_exclude_groups")
        }

        fn read_and_parse_lockfile_for_member(
            &self,
            _path: &Path,
            _member_name: &str,
        ) -> Result<LockfileParseResult> {
            unreachable!("not used by resolve_exclude_groups")
        }

        fn read_and_parse_group_roots(&self, _path: &Path) -> Result<GroupRoots> {
            Ok(self.workspace_wide.clone())
        }

        fn read_and_parse_group_roots_for_member(
            &self,
            _path: &Path,
            member_name: &str,
        ) -> Result<GroupRoots> {
            Ok(self.by_member.get(member_name).cloned().unwrap_or_default())
        }

        fn read_and_parse_package_sources(&self, _path: &Path) -> Result<PackageSourceMap> {
            unreachable!("not used by resolve_exclude_groups")
        }
    }

    fn groups(entries: &[(&str, &[&str])]) -> GroupRoots {
        entries
            .iter()
            .map(|(group, roots)| {
                (
                    group.to_string(),
                    roots.iter().map(|r| r.to_string()).collect(),
                )
            })
            .collect()
    }

    fn member(name: &str) -> WorkspaceMember {
        WorkspaceMember {
            name: name.to_string(),
            absolute_path: PathBuf::from("/ws/packages").join(name),
        }
    }

    /// Revision-3 shape: `a`, which sorts first, declares only `lint`; `b`
    /// declares `dev` and `lint`. The workspace-wide read sees only `a`'s groups.
    fn rev3_reader() -> GroupsReader {
        GroupsReader {
            workspace_wide: groups(&[("lint", &["black"])]),
            by_member: HashMap::from([
                ("a".to_string(), groups(&[("lint", &["black"])])),
                (
                    "b".to_string(),
                    groups(&[("dev", &["ruff"]), ("lint", &["flake8"])]),
                ),
            ]),
        }
    }

    #[test]
    fn test_resolve_exclude_groups_workspace_takes_union_of_member_groups() {
        let members = [member("a"), member("b")];

        let names =
            resolve_exclude_groups(&rev3_reader(), true, &[], Path::new("/ws"), Some(&members))
                .unwrap();

        assert_eq!(names, vec!["dev", "lint"]);
    }

    #[test]
    fn test_resolve_exclude_groups_workspace_without_member_groups_is_empty() {
        // The union never falls back to the workspace-wide read.
        let reader = GroupsReader {
            workspace_wide: groups(&[("dev", &["mypy"])]),
            by_member: HashMap::new(),
        };
        let members = [member("a"), member("b")];

        let names =
            resolve_exclude_groups(&reader, true, &[], Path::new("/ws"), Some(&members)).unwrap();

        assert!(names.is_empty());
    }

    #[test]
    fn test_resolve_exclude_groups_single_project_reads_workspace_wide_groups() {
        let names =
            resolve_exclude_groups(&rev3_reader(), true, &[], Path::new("/p"), None).unwrap();

        assert_eq!(names, vec!["lint"]);
    }

    #[test]
    fn test_resolve_exclude_groups_without_production_only_returns_configured() {
        let configured = vec!["test".to_string(), "docs".to_string()];
        let members = [member("a"), member("b")];

        for members in [None, Some(&members[..])] {
            let names = resolve_exclude_groups(
                &rev3_reader(),
                false,
                &configured,
                Path::new("/ws"),
                members,
            )
            .unwrap();
            assert_eq!(names, configured);
        }
    }

    #[test]
    fn test_resolve_exclude_groups_workspace_reads_real_rev3_lockfile() {
        let temp = TempDir::new().unwrap();
        fs::write(
            temp.path().join("uv.lock"),
            r#"
version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "a"
version = "0.1.0"
source = { editable = "packages/a" }

[package.dev-dependencies]
lint = [{ name = "black" }]

[[package]]
name = "b"
version = "0.1.0"
source = { editable = "packages/b" }

[package.dev-dependencies]
dev = [{ name = "ruff" }]
"#,
        )
        .unwrap();
        let members = [member("a"), member("b")];

        let names = resolve_exclude_groups(
            &FileSystemReader::new(),
            true,
            &[],
            temp.path(),
            Some(&members),
        )
        .unwrap();

        assert_eq!(names, vec!["dev", "lint"]);
    }

    #[test]
    fn test_resolve_exclude_groups_workspace_includes_manifest_and_member_groups() {
        // With `[manifest.dependency-groups]` present, a member's own groups
        // are still collected (#999).
        let temp = TempDir::new().unwrap();
        fs::write(
            temp.path().join("uv.lock"),
            r#"
version = 1
revision = 3
requires-python = ">=3.11"

[manifest]
members = ["a", "b"]

[manifest.dependency-groups]
docs = [{ name = "sphinx" }]

[[package]]
name = "a"
version = "0.1.0"
source = { editable = "packages/a" }

[[package]]
name = "b"
version = "0.1.0"
source = { editable = "packages/b" }

[package.dev-dependencies]
lint = [{ name = "black" }]
"#,
        )
        .unwrap();
        let members = [member("a"), member("b")];

        let names = resolve_exclude_groups(
            &FileSystemReader::new(),
            true,
            &[],
            temp.path(),
            Some(&members),
        )
        .unwrap();

        assert_eq!(names, vec!["docs", "lint"]);
    }
}
