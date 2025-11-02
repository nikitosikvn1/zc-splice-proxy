//! Telemetry configuration and initialization for structured logging.
//!
//! This module provides utilities for setting up the `tracing` subscriber
//! infrastructure used throughout the proxy server. It configures log filtering,
//! formatting, and output destination for observability and debugging.
//!
//! # Overview
//!
//! The telemetry system is built on top of the `tracing` crate, which provides
//! structured, contextual logging with minimal runtime overhead. This module
//! offers two main functions:
//!
//! - [`get_subscriber`]: Creates a configured tracing subscriber
//! - [`init_subscriber`]: Installs the subscriber as the global default
//!
//! # Usage
//!
//! Typically called once at application startup:
//!
//! ```rust,ignore
//! let subscriber = telemetry::get_subscriber("info", std::io::stdout);
//! telemetry::init_subscriber(subscriber);
//! ```
//!
//! # Environment Variables
//!
//! Log filtering can be controlled via the `RUST_LOG` environment variable,
//! which follows the `tracing_subscriber::EnvFilter` syntax. If not set,
//! the default filter level provided to [`get_subscriber`] is used.
//!
//! Examples:
//! - `RUST_LOG=debug` - Enable debug logs for all modules
//! - `RUST_LOG=proxy_core=trace,hickory_resolver=info` - Trace for proxy_core, info for hickory_resolver
use tracing::subscriber::{self, Subscriber};
use tracing_subscriber::{EnvFilter, Registry};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::fmt::{self, MakeWriter};

/// Creates a configured tracing subscriber for structured logging.
///
/// Constructs a layered subscriber with environment-based filtering and
/// formatted output. The subscriber can be customized via the `env_filter`
/// and `writer` parameters.
pub fn get_subscriber<F, W>(env_filter: F, writer: W) -> impl Subscriber + Send + Sync
where
    F: AsRef<str>,
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(env_filter));

    let fmt_layer = fmt::layer()
        .with_writer(writer)
        .with_target(false)
        .compact();

    Registry::default().with(env_filter).with(fmt_layer)
}

/// Initializes the given subscriber as the global default.
///
/// This function must be called once at application startup to install
/// the tracing subscriber. After initialization, all `tracing` macros
/// (e.g., `info!`, `debug!`, `error!`) throughout the application will
/// use this subscriber for logging.
pub fn init_subscriber<S>(subscriber: S)
where
    S: Subscriber + Send + Sync,
{
    subscriber::set_global_default(subscriber).expect("Failed to set subscriber");
}
