use std::io;
use std::sync::Arc;

use tokio::signal;
use tokio::net::TcpListener;

use noxen_proxy::{server, telemetry};
use noxen_proxy::config::Config;
use noxen_proxy::handler::socks5::context::Socks5Context;
use noxen_proxy::auth::auth_provider::StaticAuthProvider;
use noxen_proxy::relay::strategy::StandardUdpRelay;
#[cfg(target_os = "linux")]
use noxen_proxy::relay::strategy::SpliceRelay;
#[cfg(not(target_os = "linux"))]
use noxen_proxy::relay::strategy::CopyRelay;

const DEFAULT_CONFIG_FILE: &str = "config.toml";

#[tokio::main]
async fn main() -> io::Result<()> {
    let subscriber = telemetry::get_subscriber("proxy_core=info", io::stdout);
    telemetry::init_subscriber(subscriber);

    let config = Config::new(DEFAULT_CONFIG_FILE).expect("Failed to load config file");
    tracing::info!(?config, "Configuration loaded");

    // TODO: implement more reasonable auth provider
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

    tracing::info!(
        addr = %listener.local_addr()?,
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
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Ctrl+C received, initiating shutdown");
        }
        _ = terminate => {
            tracing::info!("SIGTERM received, initiating shutdown");
        }
    }
}
