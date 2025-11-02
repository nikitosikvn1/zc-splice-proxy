//! SOCKS5 connection state machine implementation.
//!
//! This module implements a type-safe state machine for handling SOCKS5 protocol
//! connections. The state machine ensures that protocol phases are executed in the
//! correct order and prevents invalid state transitions at compile time.
//!
//! # State Machine Design
//!
//! The handler uses the typestate pattern to enforce correct protocol flow through
//! compile-time checks. Each state is represented by a zero-sized type, and state
//! transitions consume the handler, returning a new handler in the next state.
//!
//! ## State Transitions
//!
//! The SOCKS5 protocol proceeds through the following states:
//!
//! 1. **Method Selection** ([`MethodSelection`])
//!    - Initial state when a client connection is accepted
//!    - Negotiates authentication method with the client
//!    - Transitions to either [`Authentication`] or [`RequestProcessing`]
//!
//! 2. **Authentication** ([`Authentication`])
//!    - Only entered if username/password authentication is selected
//!    - Validates client credentials
//!    - Transitions to [`RequestProcessing`] on success
//!    - Connection is closed on failure
//!
//! 3. **Request Processing** ([`RequestProcessing`])
//!    - Receives and processes client command (CONNECT, BIND, UDP_ASSOCIATE)
//!    - Establishes connection to target server
//!    - Returns a configured [`Tunnel`] for data relay
//!
//! # Codec Transitions
//!
//! Each state uses a different codec for parsing protocol messages:
//!
//! - [`MethodSelection`] → [`GreetingCodec`]
//! - [`Authentication`] → [`AuthCodec`]
//! - [`RequestProcessing`] → [`RequestResponseCodec`]
//!
//! The framed stream's codec is swapped during state transitions to match
//! the expected message format for each protocol phase.
//!
//! # Error Handling
//!
//! Errors are handled according to SOCKS5 protocol requirements:
//!
//! - Protocol errors result in immediate connection closure
//! - Authentication failures send a failure response before closing
//! - Connection errors to target servers send appropriate reply codes
//! - All errors are logged with structured tracing for observability
//!
//! # RFC References
//!
//! - [RFC 1928: SOCKS Protocol Version 5](https://datatracker.ietf.org/doc/html/rfc1928)
//! - [RFC 1929: Username/Password Authentication for SOCKS V5](https://datatracker.ietf.org/doc/html/rfc1929)
use std::io;
use std::sync::Arc;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};

use tokio::time;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, Encoder, Decoder};
use futures::{StreamExt, SinkExt};
use tracing::{Span, field, instrument};

use crate::handler::socks5::error::Socks5Error;
use crate::handler::socks5::context::Socks5Context;
use crate::net::happy_eyeballs;
use crate::relay::tunnel::{Tunnel, TcpTunnel};
use crate::relay::strategy::{TcpRelayStrategy, UdpRelayStrategy};
use crate::proto::socks5::{
    ClientGreeting, ServerGreeting, AuthRequest, AuthResponse, ClientRequest, ServerResponse,
};
use crate::proto::socks5::types::{AuthMethod, AuthStatus, Command, Reply, Address};
use crate::proto::socks5::codecs::{GreetingCodec, AuthCodec, RequestResponseCodec};

/// Result type alias for SOCKS5 operations.
type Socks5Result<T> = std::result::Result<T, Socks5Error>;

/// Placeholder address (0.0.0.0:0) used in error responses.
///
/// According to RFC 1928, when a request fails, the bound address field
/// should be set to an unspecified address. This constant provides that value.
const UNSPECIFIED_ADDRESS: Address = Address::Ipv4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

/// Typestate marker for the method selection phase.
///
/// In this state, the handler is negotiating which authentication method
/// to use with the client. The client sends a list of supported methods,
/// and the server selects one (or rejects the connection).
///
/// Valid transitions: [`Authentication`], [`RequestProcessing`]
pub struct MethodSelection;

/// Typestate marker for the authentication phase.
///
/// In this state, the handler is performing username/password authentication.
/// The client provides credentials, which are validated against the configured
/// authentication provider.
///
/// Valid transitions: [`RequestProcessing`]
pub struct Authentication;

/// Typestate marker for the request processing phase.
///
/// In this state, the handler receives the client's command (CONNECT, BIND,
/// or UDP_ASSOCIATE) and processes it by establishing the appropriate connection
/// or responding with an error.
///
/// Terminal state: Returns a [`Tunnel`] for data relay.
pub struct RequestProcessing;

/// Type-safe SOCKS5 connection handler with state machine enforcement.
///
/// This handler manages a single SOCKS5 client connection through all protocol
/// phases. The generic parameters enforce correct protocol flow at compile time:
///
/// - `C`: The codec type for the current protocol phase
/// - `S`: The state type marker ([`MethodSelection`], [`Authentication`], or [`RequestProcessing`])
/// - `TR`: The TCP relay strategy implementation
/// - `UR`: The UDP relay strategy implementation
///
/// # Type Safety
///
/// The typestate pattern prevents invalid operations:
/// - You cannot call authentication methods in the wrong state
/// - You cannot skip required protocol phases
/// - State transitions consume the handler, preventing reuse
///
/// # Lifecycle
///
/// 1. Create with [`new`](Socks5Handler::new) in [`MethodSelection`] state
/// 2. Call [`negotiate`](Socks5Handler::negotiate) to select authentication method
/// 3. If auth required, internally transitions through [`Authentication`]
/// 4. Call [`handle`](Socks5Handler::handle) in [`RequestProcessing`] state
/// 5. Returns a [`Tunnel`] ready for data relay
pub struct Socks5Handler<C, S, TR, UR> {
    /// Framed stream wrapping the client TCP connection and protocol codec.
    framed: Framed<TcpStream, C>,
    /// Shared context containing configuration and strategies.
    ctx: Arc<Socks5Context<TR, UR>>,
    /// Zero-sized state marker for compile-time state tracking.
    _state: PhantomData<S>,
}

impl<C, S, TR, UR> Socks5Handler<C, S, TR, UR> {
    /// Transitions the handler to a new state with a different codec.
    ///
    /// This method is the core of the typestate pattern. It consumes the
    /// current handler and returns a new one in a different state, ensuring
    /// that the old state cannot be used after transition.
    ///
    /// The framed stream's codec is replaced to match the new protocol phase's
    /// message format requirements.
    fn into_state<NC, NS>(self, codec: NC) -> Socks5Handler<NC, NS, TR, UR> {
        Socks5Handler {
            framed: self.framed.map_codec(|_| codec),
            ctx: self.ctx,
            _state: PhantomData,
        }
    }

    /// Receives and decodes the next protocol message from the client.
    ///
    /// This method reads from the framed stream and decodes the message
    /// according to the current codec. It handles EOF by converting it
    /// to an `UnexpectedEof` error.
    async fn recv(&mut self) -> Socks5Result<C::Item>
    where
        C: Decoder,
        C::Error: Into<Socks5Error>,
    {
        // StreamExt::next() returns None when the stream ends (client disconnected).
        // In SOCKS5, this is always unexpected - the client should send complete
        // messages before disconnecting. Convert to UnexpectedEof for proper error handling.
        self.framed
            .next()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?
            .map_err(Into::into)
    }

    /// Encodes and sends a protocol message to the client.
    ///
    /// The message is encoded using the current codec and written to the
    /// underlying TCP stream. The stream is flushed to ensure the message
    /// is sent immediately.
    async fn send<M>(&mut self, message: M) -> Socks5Result<()>
    where
        C: Encoder<M>,
        C::Error: Into<Socks5Error>,
    {
        self.framed.send(message).await.map_err(Into::into)
    }

    /// Sends a final message and gracefully closes the connection.
    ///
    /// This method is used when the connection needs to be terminated after
    /// sending a rejection or error response. It attempts to send the message
    /// but does not propagate send errors, as the connection is being closed
    /// anyway. Errors are logged for diagnostics.
    ///
    /// The TCP stream is properly shut down to signal EOF to the client.
    async fn send_and_shutdown<M>(mut self, message: M)
    where
        C: Encoder<M>,
        C::Error: Into<Socks5Error> + Debug,
    {
        // Best-effort send: if it fails, we're closing anyway.
        // The important part is that we always attempt to shutdown cleanly.
        if let Err(e) = self.framed.send(message).await {
            tracing::warn!(error = ?e, "Failed to send final message before shutdown");
        }
        self.shutdown().await;
    }

    /// Gracefully shuts down the TCP connection.
    ///
    /// This performs a TCP half-close (shutdown write side) to signal to the
    /// client that no more data will be sent. This is important for proper
    /// connection cleanup and avoiding resource leaks.
    ///
    /// Errors during shutdown are logged but not propagated, as there's no
    /// meaningful recovery action at this point.
    async fn shutdown(self) {
        if let Err(e) = self.framed.into_inner().shutdown().await {
            tracing::error!(error = ?e, "Error shutting down SOCKS5 stream");
        }
    }

    /// Returns the client's socket address.
    ///
    /// This is used for logging and tracing to identify the client connection.
    /// Returns `None` if the peer address cannot be determined (rare edge case).
    fn downstream_addr(&self) -> Option<SocketAddr> {
        self.framed.get_ref().peer_addr().ok()
    }
}

impl<TR, UR> Socks5Handler<GreetingCodec, MethodSelection, TR, UR> {
    /// Creates a new SOCKS5 handler in the initial method selection state.
    ///
    /// This is the entry point for handling a new client connection. The handler
    /// is initialized with a [`GreetingCodec`] to parse the initial client greeting.
    pub fn new(stream: TcpStream, ctx: Arc<Socks5Context<TR, UR>>) -> Self {
        Self {
            framed: Framed::new(stream, GreetingCodec),
            ctx,
            _state: PhantomData,
        }
    }

    /// Negotiates authentication method with the client.
    ///
    /// This method implements the method selection phase of the SOCKS5 protocol.
    /// The client sends a list of authentication methods it supports, and the
    /// server selects one based on its configuration.
    ///
    /// # Selection Priority
    ///
    /// The server prefers methods in this order:
    /// 1. Username/Password authentication (if offered by client)
    /// 2. No authentication (if `allow_no_auth` is enabled and offered by client)
    /// 3. None (rejects connection if no acceptable method found)
    ///
    /// # State Transitions
    ///
    /// - If username/password is selected: transitions to [`Authentication`] state
    /// - If no authentication is selected: transitions to [`RequestProcessing`] state
    /// - If no method is acceptable: closes connection and returns error
    ///
    /// # RFC Reference
    ///
    /// See [RFC 1928 Section 3](https://datatracker.ietf.org/doc/html/rfc1928#section-3).
    #[instrument(skip_all, fields(downstream = ?self.downstream_addr()))]
    pub async fn negotiate(
        mut self,
    ) -> Socks5Result<Socks5Handler<RequestResponseCodec, RequestProcessing, TR, UR>> {
        tracing::debug!("Starting method selection");

        let client_greeting: ClientGreeting = self.recv().await?;
        let ClientGreeting { methods } = client_greeting;
        tracing::trace!(?methods, "Client proposed authentication methods");

        // Priority 1: Username/Password authentication
        // We prefer authenticated connections for security, even if no-auth is allowed.
        if methods.contains(&AuthMethod::UsernamePassword) {
            tracing::debug!("Selected username/password authentication");
            let message = ServerGreeting {
                method: AuthMethod::UsernamePassword,
            };
            self.send(message).await?;

            // Transition to Authentication state and perform auth subnegotiation
            return self.into_state(AuthCodec).authenticate().await;
        }

        // Priority 2: No authentication (only if explicitly allowed by config)
        // This is useful for trusted networks or development, but should be
        // disabled in production environments.
        if self.ctx.config.allow_no_auth && methods.contains(&AuthMethod::NoAuthenticationRequired)
        {
            tracing::debug!("Selected no authentication");
            let message = ServerGreeting {
                method: AuthMethod::NoAuthenticationRequired,
            };
            self.send(message).await?;

            // Skip authentication, go directly to request processing
            return Ok(self.into_state(RequestResponseCodec));
        }

        // No acceptable method: reject the connection
        // This happens when the client doesn't support any methods we're willing to accept.
        tracing::warn!(
            ?methods,
            allow_no_auth = self.ctx.config.allow_no_auth,
            "No mutually acceptable authentication method"
        );
        let message = ServerGreeting {
            method: AuthMethod::NoAcceptableMethods,
        };
        self.send_and_shutdown(message).await;

        Err(Socks5Error::NoAcceptableMethod)
    }
}

impl<TR, UR> Socks5Handler<AuthCodec, Authentication, TR, UR> {
    /// Authenticates the client using username and password.
    ///
    /// This method implements the username/password authentication subnegotiation
    /// defined in RFC 1929. The client provides credentials, which are validated
    /// against the configured authentication provider.
    ///
    /// # Authentication Process
    ///
    /// 1. Receive [`AuthRequest`] with username and password
    /// 2. Call the authentication provider to validate credentials
    /// 3. Send [`AuthResponse`] with success or failure status
    ///
    /// # State Transitions
    ///
    /// - Success: transitions to [`RequestProcessing`] state
    /// - Failure: closes connection and returns error
    ///
    /// # RFC Reference
    ///
    /// See [RFC 1929 Section 2](https://datatracker.ietf.org/doc/html/rfc1929#section-2).
    #[instrument(skip_all, fields(downstream = ?self.downstream_addr(), username))]
    async fn authenticate(
        mut self,
    ) -> Socks5Result<Socks5Handler<RequestResponseCodec, RequestProcessing, TR, UR>> {
        let auth_request: AuthRequest = self.recv().await?;
        let AuthRequest { username, password } = auth_request;

        // Record username after receiving it (not before) so it appears in logs.
        // This is done here rather than in the instrument macro because we don't
        // know the username until the request is parsed.
        Span::current().record("username", &username);

        match self
            .ctx
            .auth_provider
            .authenticate(&username, &password)
            .await
        {
            Ok(_) => {
                tracing::info!("Authentication succeeded");
                let message = AuthResponse {
                    status: AuthStatus::Success,
                };
                self.send(message).await?;

                // Auth successful: proceed to request processing
                Ok(self.into_state(RequestResponseCodec))
            }
            Err(e) => {
                tracing::warn!(error = ?e, "Authentication failed");
                let message = AuthResponse {
                    status: AuthStatus::Failure,
                };
                self.send_and_shutdown(message).await;

                Err(Socks5Error::AuthenticationFailed(e))
            }
        }
    }
}

impl<TR, UR> Socks5Handler<RequestResponseCodec, RequestProcessing, TR, UR>
where
    TR: TcpRelayStrategy + Clone + Copy,
    UR: UdpRelayStrategy + Clone + Copy,
{
    /// Processes the client's SOCKS5 command request.
    ///
    /// This method receives the client's request and dispatches it to the
    /// appropriate handler based on the requested command type.
    ///
    /// # Supported Commands
    ///
    /// - **CONNECT**: Establishes a TCP connection to a target server
    /// - **BIND**: Sets up a listening socket for incoming connections
    /// - **UDP_ASSOCIATE**: Currently not supported, returns error
    ///
    /// # Return Value
    ///
    /// On success, returns a [`Tunnel`] configured for data relay between
    /// the client and target. The tunnel can then be run to perform the
    /// actual data transfer.
    ///
    /// # RFC Reference
    ///
    /// See [RFC 1928 Section 4](https://datatracker.ietf.org/doc/html/rfc1928#section-4).
    #[instrument(skip_all, fields(downstream = ?self.downstream_addr()))]
    pub async fn handle(mut self) -> Socks5Result<Tunnel<TR, UR>> {
        let client_request: ClientRequest = self.recv().await?;
        let ClientRequest {
            command,
            dst_address,
        } = client_request;

        tracing::info!("Received client request");

        // Dispatch to appropriate command handler
        match command {
            Command::Connect => self.handle_connect(dst_address).await,
            Command::Bind => self.handle_bind().await,
            Command::UdpAssociate => self.handle_udp_associate().await,
        }
    }

    /// Handles the CONNECT command by establishing a connection to the target.
    ///
    /// This is the most commonly used SOCKS5 command. It creates a direct TCP
    /// connection to the requested target address and port, then returns a
    /// tunnel ready for bidirectional data relay.
    ///
    /// # Process Flow
    ///
    /// 1. Establish connection to target server (with timeout)
    /// 2. Send success response with bound address to client
    /// 3. Create and return TCP tunnel for data relay
    ///
    /// If connection fails, sends an appropriate error reply to the client
    /// before returning the error.
    ///
    /// # Target Resolution
    ///
    /// - IPv4/IPv6 addresses: Direct connection attempt
    /// - Domain names: Uses Happy Eyeballs algorithm for dual-stack connection
    ///
    /// # RFC Reference
    ///
    /// See [RFC 1928 Section 4](https://datatracker.ietf.org/doc/html/rfc1928#section-4).
    #[instrument(skip_all, name = "connect", fields(upstream))]
    async fn handle_connect(mut self, dst_address: Address) -> Socks5Result<Tunnel<TR, UR>> {
        // Establish connection to target
        let upstream: TcpStream = match self.connect_to_upstream(&dst_address).await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::warn!(error = ?e, "Failed to connect to upstream");
                return self.send_error_reply(e).await;
            }
        };
        Span::current().record("upstream", field::debug(&upstream.peer_addr().ok()));

        // Get the local address of the outgoing connection.
        // RFC 1928 requires sending back the bound address, though many clients ignore it.
        // If we can't get the address (shouldn't happen), fall back to 0.0.0.0:0.
        let bnd_address: Address = upstream
            .local_addr()
            .map(Address::from)
            .unwrap_or(UNSPECIFIED_ADDRESS);

        // Send success response with bound address
        let response = ServerResponse {
            reply: Reply::Succeeded,
            bnd_address,
        };
        if let Err(e) = self.send(response).await {
            tracing::error!(error = ?e, "Failed to send CONNECT success response");
            return Err(e);
        }

        tracing::info!("CONNECT completed, establishing tunnel");
        // Extract the raw TCP stream from the framed wrapper and create tunnel.
        // At this point, the SOCKS5 protocol is complete, and we're ready to
        // relay raw bytes between client and target.
        let downstream: TcpStream = self.framed.into_inner();
        let tunnel: TcpTunnel<TR> =
            TcpTunnel::new(self.ctx.tcp_relay_strategy, downstream, upstream);

        Ok(Tunnel::Tcp(tunnel))
    }

    /// Handles the BIND command by listening for an incoming connection.
    ///
    /// The BIND command is typically used for protocols like FTP that require
    /// the server to connect back to the client. This implementation:
    ///
    /// 1. Creates a TCP listener on an ephemeral port
    /// 2. Sends the bound address to the client (first reply)
    /// 3. Waits for an incoming connection (with timeout)
    /// 4. Sends the remote address of the incoming connection (second reply)
    /// 5. Returns a tunnel for data relay
    ///
    /// # Two-Reply Protocol
    ///
    /// BIND sends two server responses:
    /// - First: The address where the server is listening
    /// - Second: The address of the connected peer (after accept succeeds)
    ///
    /// # Timeout Behavior
    ///
    /// The accept operation is subject to `bind_timeout` from configuration.
    /// If no connection arrives within this period, the operation fails and
    /// an error reply is sent to the client.
    ///
    /// # RFC Reference
    ///
    /// See [RFC 1928 Section 4](https://datatracker.ietf.org/doc/html/rfc1928#section-4).
    #[instrument(skip_all, name = "bind", fields(upstream))]
    async fn handle_bind(mut self) -> Socks5Result<Tunnel<TR, UR>> {
        // Create listener on ephemeral port (OS assigns port number)
        let listener = match TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).await {
            Ok(listener) => listener,
            Err(e) => {
                tracing::error!(error = ?e, "Failed to create BIND listener");
                return self.send_error_reply(e).await;
            }
        };

        let bnd_address: SocketAddr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                tracing::error!(error = ?e, "Failed to get BIND listener address");
                return self.send_error_reply(e).await;
            }
        };

        tracing::debug!(?bnd_address, "BIND listener created");

        // First reply: Tell client where we're listening
        // The client (or target server) should connect to this address
        let response = ServerResponse {
            reply: Reply::Succeeded,
            bnd_address: bnd_address.into(),
        };
        if let Err(e) = self.send(response).await {
            tracing::error!(error = ?e, "Failed to send BIND first response");
            return Err(e);
        }

        // Wait for incoming connection with timeout
        // This prevents indefinite waiting if nothing connects
        let (upstream, remote_addr) =
            match time::timeout(self.ctx.config.bind_timeout, listener.accept()).await {
                Ok(Ok((stream, addr))) => {
                    tracing::info!(?addr, "BIND accepted incoming connection");
                    (stream, addr)
                }
                Ok(Err(e)) => {
                    tracing::error!(error = ?e, "BIND accept failed");
                    return self.send_error_reply(e).await;
                }
                Err(_) => {
                    tracing::warn!(
                        timeout = ?self.ctx.config.bind_timeout,
                        "BIND accept timed out"
                    );
                    return self.send_error_reply(Socks5Error::Timeout).await;
                }
            };

        // Close listener immediately after accepting one connection.
        // BIND only supports a single connection, not multiple.
        drop(listener);
        tracing::trace!(?bnd_address, "BIND listener closed, port released");
        Span::current().record("upstream", field::debug(&upstream.peer_addr().ok()));

        // Second reply: Tell client who connected
        // This lets the client verify that the correct peer connected
        let response = ServerResponse {
            reply: Reply::Succeeded,
            bnd_address: remote_addr.into(),
        };
        if let Err(e) = self.send(response).await {
            tracing::error!(error = ?e, "Failed to send BIND second response");
            return Err(e);
        }

        tracing::info!("BIND completed, establishing tunnel");
        let downstream: TcpStream = self.framed.into_inner();
        let tunnel: TcpTunnel<TR> =
            TcpTunnel::new(self.ctx.tcp_relay_strategy, downstream, upstream);

        Ok(Tunnel::Tcp(tunnel))
    }

    /// Handles the UDP_ASSOCIATE command.
    ///
    /// Currently, UDP association is not implemented in this proxy. When a client
    /// requests this command, the server responds with `CommandNotSupported` and
    /// closes the connection.
    ///
    /// # Future Implementation
    ///
    /// UDP_ASSOCIATE would require:
    /// - Creating a UDP socket for relaying packets
    /// - Maintaining the TCP control connection
    /// - Parsing and handling UDP datagram headers
    /// - Implementing packet routing between client and target
    ///
    /// # RFC Reference
    ///
    /// See [RFC 1928 Section 4](https://datatracker.ietf.org/doc/html/rfc1928#section-4).
    #[instrument(skip_all, name = "udp_associate")]
    async fn handle_udp_associate(self) -> Socks5Result<Tunnel<TR, UR>> {
        tracing::debug!("UDP_ASSOCIATE command not supported");

        let response = ServerResponse {
            reply: Reply::CommandNotSupported,
            bnd_address: UNSPECIFIED_ADDRESS,
        };
        self.send_and_shutdown(response).await;

        Err(Socks5Error::CommandNotSupported)
    }

    /// Establishes a connection to the target server.
    ///
    /// This method handles connection establishment with different address types
    /// and applies the configured connection timeout.
    ///
    /// # Address Handling
    ///
    /// - **IPv4**: Direct connection to specified address
    /// - **IPv6**: Direct connection to specified address
    /// - **Domain**: Uses Happy Eyeballs algorithm for optimal connection
    ///
    /// The Happy Eyeballs algorithm (RFC 8305) tries both IPv4 and IPv6 addresses
    /// in parallel for domain names, selecting whichever connects first. This
    /// provides better performance and reliability in dual-stack environments.
    ///
    /// # Timeout
    ///
    /// The entire connection attempt is bounded by `connect_timeout` from the
    /// configuration. This includes DNS resolution time for domain names.
    #[instrument(skip(self), level = "debug")]
    async fn connect_to_upstream(&self, target: &Address) -> Socks5Result<TcpStream> {
        let connect_future = async {
            tracing::debug!(?target, "Connecting to target");

            match target {
                // Direct IP addresses: simple connection attempt
                Address::Ipv4(addr) => TcpStream::connect(addr)
                    .await
                    .map_err(Socks5Error::TargetConnectionFailed),
                Address::Ipv6(addr) => TcpStream::connect(addr)
                    .await
                    .map_err(Socks5Error::TargetConnectionFailed),
                // Domain names: use Happy Eyeballs for dual-stack support
                Address::Domain(domain, port) => happy_eyeballs::connect(domain, *port)
                    .await
                    .map_err(Socks5Error::from),
            }
        };

        // Wrap the connection attempt in a timeout to prevent indefinite hanging.
        // This is critical for preventing resource exhaustion from slow/unresponsive targets.
        time::timeout(self.ctx.config.connect_timeout, connect_future)
            .await
            .inspect_err(|_| tracing::warn!("Connection to upstream timed out"))
            .map_err(|_| Socks5Error::Timeout)?
    }

    /// Sends an error reply to the client and terminates the connection.
    ///
    /// This helper method converts errors into appropriate SOCKS5 reply codes
    /// and sends them to the client before closing the connection. It ensures
    /// that the client receives proper error information rather than just a
    /// TCP connection reset.
    ///
    /// # Reply Code Mapping
    ///
    /// Errors are mapped to reply codes according to RFC 1928:
    /// - Connection refused → `ConnectionRefused`
    /// - Network unreachable → `NetworkUnreachable`
    /// - Host unreachable → `HostUnreachable`
    /// - DNS errors → `HostUnreachable`
    /// - Other errors → `GeneralFailure`
    ///
    /// # Behavior
    ///
    /// The connection is always closed after sending the error reply,
    /// regardless of whether the send operation succeeds.
    async fn send_error_reply(self, error: impl Into<Socks5Error>) -> Socks5Result<Tunnel<TR, UR>> {
        let error: Socks5Error = error.into();
        let reply: Reply = error.to_reply();

        let response = ServerResponse {
            reply,
            bnd_address: UNSPECIFIED_ADDRESS,
        };
        self.send_and_shutdown(response).await;

        Err(error)
    }
}
