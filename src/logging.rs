//! Logging and tracing infrastructure for Glaurung.
//!
//! This module provides structured logging using the tracing crate,
//! with support for different output formats and filtering.

use std::sync::Once;
#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

static INIT: Once = Once::new();

/// Initialize the global tracing subscriber.
///
/// This should be called once at program startup.
/// Subsequent calls are ignored.
pub fn init_tracing() {
    INIT.call_once(|| {
        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        let fmt_layer = fmt::layer()
            .with_span_events(FmtSpan::CLOSE)
            .with_target(true)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_file(true)
            .with_line_number(true);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();

        info!("Glaurung tracing initialized");
    });
}

/// Initialize tracing with JSON output for structured logging.
pub fn init_tracing_json() {
    INIT.call_once(|| {
        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        let fmt_layer = fmt::layer()
            .json()
            .with_span_events(FmtSpan::CLOSE)
            .with_target(true)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_file(true)
            .with_line_number(true)
            .with_current_span(true);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();

        info!("Glaurung tracing initialized (JSON mode)");
    });
}

/// Log levels for Python integration
#[cfg(feature = "python-ext")]
#[pyo3::prelude::pyclass]
#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[cfg(feature = "python-ext")]
#[pyo3::prelude::pymethods]
impl LogLevel {
    fn __str__(&self) -> String {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
        .to_string()
    }
}

/// Initialize logging from Python
#[cfg(feature = "python-ext")]
#[pyo3::prelude::pyfunction]
pub fn init_logging(json: bool) -> pyo3::PyResult<()> {
    if json {
        init_tracing_json();
    } else {
        init_tracing();
    }
    Ok(())
}

/// Log a message from Python
#[cfg(feature = "python-ext")]
#[pyo3::prelude::pyfunction]
pub fn log_message(level: LogLevel, message: &str) -> pyo3::PyResult<()> {
    match level {
        LogLevel::Trace => trace!("{}", message),
        LogLevel::Debug => debug!("{}", message),
        LogLevel::Info => info!("{}", message),
        LogLevel::Warn => warn!("{}", message),
        LogLevel::Error => error!("{}", message),
    }
    Ok(())
}

/// Macro for creating spans with automatic error logging
#[macro_export]
macro_rules! span_trace {
    ($name:expr) => {
        tracing::info_span!($name)
    };
    ($name:expr, $($field:tt)*) => {
        tracing::info_span!($name, $($field)*)
    };
}

/// Macro for logging and returning errors
#[macro_export]
macro_rules! log_error {
    ($err:expr) => {{
        let e = $err;
        tracing::error!(error = %e, "Operation failed");
        e
    }};
    ($err:expr, $msg:expr) => {{
        let e = $err;
        tracing::error!(error = %e, message = $msg, "Operation failed");
        e
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_tracing_once() {
        // Should be callable multiple times without panic
        init_tracing();
        init_tracing();
    }

    #[test]
    fn test_log_levels() {
        init_tracing();
        trace!("This is a trace message");
        debug!("This is a debug message");
        info!("This is an info message");
        warn!("This is a warning message");
        error!("This is an error message");
    }

    #[test]
    fn test_structured_logging() {
        init_tracing();
        let binary_name = "test.exe";
        let size = 1024;
        info!(
            binary = %binary_name,
            size_bytes = size,
            "Analyzing binary"
        );
    }

    #[test]
    fn test_span_creation() {
        init_tracing();
        let span = span_trace!("test_operation", id = 123, name = "test");
        let _guard = span.enter();
        info!("Inside span");
    }
}
