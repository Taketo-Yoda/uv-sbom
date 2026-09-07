use super::toml_schema::PackageSource;
use crate::ports::outbound::PackageSourceKind;

impl PackageSource {
    pub(super) fn is_local(&self) -> bool {
        self.editable.is_some() || self.virtual_path.is_some()
    }

    /// Classify this source into a `PackageSourceKind`.
    ///
    /// Priority when multiple fields are set (uv.lock sets exactly one in practice):
    /// WorkspaceMember > Git > LocalPath > DirectUrl > Registry.
    /// A registry URL of `"https://pypi.org/simple"` (with or without trailing slash)
    /// maps to `PyPi`; all other registry URLs map to `PrivateRegistry`.
    ///
    /// If none of the known fields are set (e.g., a future uv.lock source type or
    /// a `source = {}` empty table), falls back to `PyPi` as a non-flagging default.
    /// Callers should treat this fallback as "unknown / assumed PyPI" until a richer
    /// classification can be confirmed.
    pub(super) fn to_kind(&self) -> PackageSourceKind {
        if self.is_local() {
            return PackageSourceKind::WorkspaceMember;
        }
        if let Some(git) = &self.git {
            return PackageSourceKind::Git(git.clone());
        }
        if let Some(path) = &self.path {
            return PackageSourceKind::LocalPath(path.clone());
        }
        if let Some(url) = &self.url {
            return PackageSourceKind::DirectUrl(url.clone());
        }
        if let Some(reg) = &self.registry {
            let normalized = reg.trim_end_matches('/');
            if normalized == "https://pypi.org/simple" {
                return PackageSourceKind::PyPi;
            }
            return PackageSourceKind::PrivateRegistry(reg.clone());
        }
        // No source field set — treat as PyPI (non-flagging default).
        PackageSourceKind::PyPi
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_kind_workspace_member_takes_priority_over_registry() {
        let source = PackageSource {
            editable: Some(".".to_string()),
            virtual_path: None,
            registry: Some("https://pypi.org/simple".to_string()),
            git: None,
            path: None,
            url: None,
        };
        assert_eq!(source.to_kind(), PackageSourceKind::WorkspaceMember);
    }
}
