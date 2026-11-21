/// Outbound adapter factories for creating formatters and presenters.
///
/// These factories construct concrete adapter implementations (formatters,
/// presenters) and therefore belong in the adapters layer, not the application
/// layer. The application layer passes configuration; the factories select the
/// concrete adapter.
mod formatter_factory;
mod presenter_factory;

pub use formatter_factory::FormatterFactory;
pub use presenter_factory::{PresenterFactory, PresenterType};
