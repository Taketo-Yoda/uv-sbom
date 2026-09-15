use crate::cli::Args;
use crate::shared::Result;
use uv_sbom::config::{self, ConfigFile};

/// Load a config file from an explicit path or via auto-discovery.
pub fn load_config(args: &Args, project_path: &std::path::Path) -> Result<Option<ConfigFile>> {
    if let Some(ref config_path) = args.config {
        let path = std::path::Path::new(config_path);
        let cfg = config::load_config_from_path(path)?;
        eprintln!("📄 Loaded config from: {}", path.display());
        Ok(Some(cfg))
    } else {
        let cfg = config::discover_config(project_path)?;
        if cfg.is_some() {
            eprintln!("📄 Auto-discovered config file in project directory.");
        }
        Ok(cfg)
    }
}
