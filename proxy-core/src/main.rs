#![allow(unused)]
use std::{io, future};
use std::sync::Arc;
use std::net::SocketAddr;

use tokio::signal;
use tokio::net::TcpListener;

use proxy_core::{server, telemetry};
use proxy_core::config::Config;
use proxy_core::handler::socks5::context::Socks5Context;
use proxy_core::auth::auth_provider::StaticAuthProvider;
#[cfg(target_os = "linux")]
use proxy_core::relay::strategy::{SpliceRelay, StandardUdpRelay};
#[cfg(not(target_os = "linux"))]
use proxy_core::relay::strategy::{CopyRelay, StandardUdpRelay};

const DEFAULT_CONFIG_FILE: &str = "config.toml";

#[tokio::main]
async fn main() -> io::Result<()> {
    let subscriber = telemetry::get_subscriber("proxy_core=info", io::stdout);
    telemetry::init_subscriber(subscriber);
    tracing::info!("Starting SOCKS5 proxy server...");

    let config = Config::new(DEFAULT_CONFIG_FILE).expect("Failed to load config file");
    tracing::info!(?config, "Configuration loaded");

    let auth_provider = StaticAuthProvider::new("uname", "passwd");
    let auth_provider: Arc<StaticAuthProvider> = Arc::new(auth_provider);

    #[cfg(target_os = "linux")]
    let tcp_relay = {
        tracing::info!("Using splice-based relay strategy (Linux)");
        SpliceRelay
    };
    #[cfg(not(target_os = "linux"))]
    let tcp_relay = {
        tracing::info!("Using copy-based relay strategy");
        CopyRelay
    };
    let udp_relay = StandardUdpRelay;

    let socks5_ctx = Arc::new(Socks5Context {
        tcp_relay_strategy: tcp_relay,
        udp_relay_strategy: udp_relay,
        auth_provider,
        config: config.socks5,
    });

    let listener = TcpListener::bind(&config.server.listen_address).await?;
    let listen_addr: SocketAddr = listener.local_addr()?;

    tracing::info!(
        addr = %listen_addr,
        "Server listening, waiting for incoming connections"
    );
    server::run(listener, socks5_ctx, config.server, shutdown_signal()).await;
    tracing::info!("Server shutdown complete");

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Ctrl+C received, initiating shutdown");
        }
        _ = terminate => {
            tracing::info!("SIGTERM received, initiating shutdown");
        }
    }
}
