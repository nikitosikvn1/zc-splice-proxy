//! Application configuration structures and loading.
//!
//! This module defines the configuration schema for the proxy server and
//! provides functionality to load configuration from files and environment
//! variables. Configuration is organized into logical sections for different
//! components of the server.
//!
//! # Configuration Sources
//!
//! Configuration is loaded with the following precedence (highest to lowest):
//!
//! 1. **Environment variables** - Prefixed with `PROXY__` and use double
//!    underscores as separators (e.g., `PROXY__SERVER__LISTEN_ADDRESS`)
//! 2. **TOML configuration file** - Optional file specified at startup
//! 3. **Default values** - Sensible defaults for all settings
//!
//! # Structure
//!
//! The configuration is organized into two main sections:
//!
//! - [`ServerConfig`]: Core server settings (address, timeouts, limits)
//! - [`Socks5Config`]: SOCKS5 protocol-specific settings
//!
//! These are combined in the root [`Config`] structure.
//!
//! # Usage
//!
//! ```rust,ignore
//! use noxen_proxy::config::Config;
//!
//! // Load from file with environment variable overrides
//! let config = Config::new("config.toml")?;
//!
//! println!("Listening on: {}", config.server.listen_address);
//! println!("Max connections: {}", config.server.max_connections);
//! ```
//!
//! # TOML File Format
//!
//! ```toml
//! [server]
//! listen_address = "0.0.0.0:1080"
//! shutdown_timeout = "60s"
//! backlog_size = 1024
//! max_connections = 0  # 0 means unlimited
//!
//! [socks5]
//! allow_no_auth = false
//! connect_timeout = "10s"
//! bind_timeout = "40s"
//! ```
//!
//! # Environment Variables
//!
//! Examples of environment variable overrides:
//!
//! ```bash
//! export PROXY__SERVER__LISTEN_ADDRESS="127.0.0.1:9050"
//! export PROXY__SERVER__MAX_CONNECTIONS=1000
//! export PROXY__SOCKS5__ALLOW_NO_AUTH=true
//! export PROXY__SOCKS5__CONNECT_TIMEOUT="30s"
//! ```
use std::path::Path;
use std::time::Duration;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};

use serde::Deserialize;
use config::{ConfigError, Environment, File, FileFormat};

/// Core server configuration settings.
///
/// Contains settings that control the server's network behavior, connection
/// limits, and shutdown behavior. All fields have sensible defaults and can
/// be overridden via configuration file or environment variables.
///
/// # Fields
///
/// - `listen_address`: Socket address to bind the server to
/// - `shutdown_timeout`: Maximum time to wait for graceful shutdown
/// - `backlog_size`: TCP listen backlog size (number of pending connections)
/// - `max_connections`: Maximum concurrent connections (0 = unlimited)
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub listen_address: SocketAddr,
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
    pub backlog_size: usize,
    pub max_connections: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 1080)),
            shutdown_timeout: Duration::from_secs(60),
            backlog_size: 1024,
            max_connections: 0, // Unlimited
        }
    }
}

/// SOCKS5 protocol configuration settings.
///
/// Contains settings specific to the SOCKS5 protocol handling, including
/// authentication requirements and command timeouts.
///
/// # Fields
///
/// - `allow_no_auth`: Whether to allow unauthenticated connections
/// - `connect_timeout`: Timeout for CONNECT command execution
/// - `bind_timeout`: Timeout for BIND command execution
///
/// # Security Note
///
/// Setting `allow_no_auth` to `true` allows clients to connect without
/// authentication. This should only be used in trusted environments.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Socks5Config {
    pub allow_no_auth: bool,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub bind_timeout: Duration,
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            allow_no_auth: false,
            connect_timeout: Duration::from_secs(10),
            bind_timeout: Duration::from_secs(40),
        }
    }
}

/// Root configuration structure combining all configuration sections.
///
/// This is the main entry point for application configuration. It aggregates
/// configuration for different components of the proxy server.
///
/// # Fields
///
/// - `server`: Core server settings ([`ServerConfig`])
/// - `socks5`: SOCKS5 protocol settings ([`Socks5Config`])
///
/// # Loading Configuration
///
/// Use the [`Config::new`] method to load configuration from a file path.
/// The file is optional; if it doesn't exist, only defaults and environment
/// variables are used.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub socks5: Socks5Config,
}

impl Config {
    /// Loads configuration from a file and environment variables.
    ///
    /// Attempts to load configuration from the specified TOML file, then
    /// applies overrides from environment variables prefixed with `PROXY__`.
    /// If the file does not exist, only environment variables and defaults
    /// are used.
    pub fn new(file: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let file_source = File::from(file.as_ref())
            .format(FileFormat::Toml)
            .required(false);

        let config = config::Config::builder()
            .add_source(file_source)
            .add_source(Environment::with_prefix("PROXY").separator("__"))
            .build()?;

        config.try_deserialize()
    }
}
