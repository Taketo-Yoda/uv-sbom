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
        warn_unknown_fields(&cfg, msgs);
        Ok(Some(cfg))
    } else {
        let cfg = config::discover_config(project_path)?;
        if let Some(ref c) = cfg {
            eprintln!("{}", msgs.info_config_auto_discovered);
            warn_unknown_fields(c, msgs);
        }
        Ok(cfg)
    }
}

/// Warns about config keys that `uv-sbom` does not recognize.
///
/// Lives here rather than in `uv_sbom::config` because the warning is
/// locale-dependent and `config.rs` has no `Locale` (and must stay free of
/// any i18n dependency); `ConfigFile::unknown_fields` already carries the data.
fn warn_unknown_fields(cfg: &ConfigFile, msgs: &Messages) {
    for key in cfg.unknown_fields.keys() {
        eprintln!(
            "{}",
            Messages::format(msgs.warn_unknown_config_field, &[key])
        );
    }
}
