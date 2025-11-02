pub mod shutdown;

use std::io;
use std::sync::Arc;
use std::future::Future;
use std::net::SocketAddr;

use tokio::time;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Semaphore, OwnedSemaphorePermit};

use crate::config::ServerConfig;
use crate::server::shutdown::Shutdown;
use crate::handler::socks5::context::Socks5Context;
use crate::handler::socks5::state::Socks5Handler;
use crate::relay::strategy::{TcpRelayStrategy, Traffic, UdpRelayStrategy};

struct Listener<TR, UR> {
    listener: TcpListener,
    socks5_ctx: Arc<Socks5Context<TR, UR>>,
    config: ServerConfig,
    limit_connections: Option<Arc<Semaphore>>,
    notify_shutdown: broadcast::Sender<()>,
    shutdown_complete_tx: mpsc::Sender<()>,
}

impl<TR, UR> Listener<TR, UR>
where
    TR: TcpRelayStrategy + Clone + Copy + 'static,
    UR: UdpRelayStrategy + Clone + Copy + 'static,
{
    async fn run(&mut self) -> io::Result<()> {
        loop {
            let permit: Option<OwnedSemaphorePermit> =
                if let Some(ref limiter) = self.limit_connections {
                    Some(limiter.clone().acquire_owned().await.unwrap())
                } else {
                    None
                };

            let (stream, _addr) = self.listener.accept().await?;
            let peer_addr: Option<SocketAddr> = stream.peer_addr().ok();
            tracing::debug!(?peer_addr, "Accepted new connection");

            let handler: Handler<TR, UR> = Handler {
                socks5_ctx: Arc::clone(&self.socks5_ctx),
                stream,
                shutdown: Shutdown::new(self.notify_shutdown.subscribe()),
                _shutdown_complete: self.shutdown_complete_tx.clone(),
            };

            tokio::spawn(async move {
                if let Err(e) = handler.run().await {
                    tracing::error!(
                        error = ?e,
                        ?peer_addr,
                        "Connection handler error"
                    );
                }
                drop(permit);
            });
        }
    }
}

struct Handler<TR, UR> {
    socks5_ctx: Arc<Socks5Context<TR, UR>>,
    stream: TcpStream,
    shutdown: Shutdown,
    _shutdown_complete: mpsc::Sender<()>,
}

impl<TR, UR> Handler<TR, UR>
where
    TR: TcpRelayStrategy + Clone + Copy,
    UR: UdpRelayStrategy + Clone + Copy,
{
    async fn run(self) -> io::Result<()> {
        let Handler {
            socks5_ctx,
            stream,
            mut shutdown,
            ..
        } = self;

        // Phase 1: Method negotiation
        let handler = Socks5Handler::new(stream, Arc::clone(&socks5_ctx));
        let handler = tokio::select! {
            result = handler.negotiate() => {
                match result {
                    Ok(handler) => handler,
                    Err(e) => {
                        tracing::debug!(error = ?e, "Negotiation failed");
                        return Err(e.into());
                    }
                }
            }
            _ = shutdown.recv() => {
                tracing::info!("Shutdown during negotiation");
                return Ok(());
            }
        };

        // Phase 2: Request processing
        let tunnel = tokio::select! {
            result = handler.handle() => {
                match result {
                    Ok(tunnel) => tunnel,
                    Err(e) => {
                        tracing::debug!(error = ?e, "Request handling failed");
                        return Err(e.into());
                    }
                }
            }
            _ = shutdown.recv() => {
                tracing::info!("Shutdown during request processing");
                return Ok(());
            }
        };

        // Phase 3: Data relay
        tracing::info!("Starting data relay");
        let traffic: Traffic = tunnel.run().await?;

        tracing::info!(
            tx_bytes = traffic.tx_bytes,
            rx_bytes = traffic.rx_bytes,
            "Data relay completed"
        );

        Ok(())
    }
}

pub async fn run<TR, UR>(
    listener: TcpListener,
    socks5_ctx: Arc<Socks5Context<TR, UR>>,
    config: ServerConfig,
    shutdown: impl Future,
) where
    TR: TcpRelayStrategy + Clone + Copy + 'static,
    UR: UdpRelayStrategy + Clone + Copy + 'static,
{
    let (notify_shutdown, _) = broadcast::channel(1);
    let (shutdown_complete_tx, mut shutdown_complete_rx) = mpsc::channel(1);

    let limit_connections: Option<Arc<Semaphore>> = if config.max_connections > 0 {
        Some(Arc::new(Semaphore::new(config.max_connections)))
    } else {
        None
    };

    let mut server: Listener<TR, UR> = Listener {
        listener,
        socks5_ctx,
        config,
        limit_connections,
        notify_shutdown,
        shutdown_complete_tx,
    };

    tokio::select! {
        res = server.run() => {
            if let Err(e) = res {
                tracing::error!(error = ?e, "Failed to accept connections");
            }
        }
        _ = shutdown => {
            tracing::info!("Shutdown signal received");
        }
    }

    let Listener {
        shutdown_complete_tx,
        notify_shutdown,
        config,
        ..
    } = server;

    drop(notify_shutdown);
    drop(shutdown_complete_tx);
    tracing::info!("Waiting for active connections to complete");

    let wait_for_shutdown = async { while shutdown_complete_rx.recv().await.is_some() {} };
    if time::timeout(config.shutdown_timeout, wait_for_shutdown)
        .await
        .is_err()
    {
        tracing::warn!("Shutdown timeout reached, forcing exit");
    } else {
        tracing::info!("All connections closed gracefully");
    }
}
