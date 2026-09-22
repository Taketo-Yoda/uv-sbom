use crate::cli::Args;
use crate::i18n::{Locale, Messages};
use crate::shared::Result;
use uv_sbom::config::{self, ConfigFile};

/// Load a config file from an explicit path or via auto-discovery.
///
/// Status messages are emitted to stderr in the given `locale`.
///
/// # Errors
/// Returns an error if an explicitly specified config file cannot be read or parsed.
pub fn load_config(
    args: &Args,
    project_path: &std::path::Path,
    locale: Locale,
) -> Result<Option<ConfigFile>> {
    let msgs = Messages::for_locale(locale);
    if let Some(ref config_path) = args.config {
        let path = std::path::Path::new(config_path);
        let cfg = config::load_config_from_path(path)?;
        let path_str = path.display().to_string();
        eprintln!(
            "{}",
            Messages::format(msgs.info_config_loaded_from, &[&path_str])
        );
        Ok(Some(cfg))
    } else {
        let cfg = config::discover_config(project_path)?;
        if cfg.is_some() {
            eprintln!("{}", msgs.info_config_auto_discovered);
        }
        Ok(cfg)
    }
}
