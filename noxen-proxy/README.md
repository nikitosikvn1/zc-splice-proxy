# zc-splice-proxy

A high-performance, zero-copy SOCKS5 proxy server built with Rust.

## Overview

**zc-splice-proxy** is an asynchronous SOCKS5 proxy implementation focused on performance and efficiency. It leverages Linux's `splice()` system call for zero-copy data transfer between sockets, significantly reducing CPU overhead and improving throughput compared to traditional user-space proxies. On non-Linux platforms, it falls back to optimized async copy operations. The implementation follows a type-safe state machine design and supports modern dual-stack networking with Happy Eyeballs v2.

## Features

- **SOCKS5 Protocol Support** – Full implementation of SOCKS5 protocol ([RFC 1928])
  - `CONNECT` command for TCP connections
  - `BIND` command for incoming connections
- **Authentication** – Username/password authentication per [RFC 1929]
- **Zero-Copy Relay** – Linux `splice()` syscall for kernel-level data transfer
- **Happy Eyeballs v2** – Intelligent dual-stack connection per [RFC 8305]
- **Async I/O** – Built on Tokio runtime for high concurrency
- **Type-Safe State Machine** – Compile-time protocol flow enforcement
- **Flexible Configuration** – TOML files and environment variable overrides
- **Structured Logging** – Tracing-based observability with configurable levels
- **Graceful Shutdown** – Clean connection termination on SIGTERM/SIGINT

## TODO

The following features are planned for production readiness:

- [ ] **UDP ASSOCIATE Support** – Implement UDP relay for SOCKS5 ([RFC 1928])
- [ ] **Dynamic Authentication** – Load credentials from configuration file
- [ ] **Configuration Validation** – Startup-time config verification
- [ ] **Error Diagnostics** – Enhanced error messages and client feedback
- [ ] **Test Suite** – Unit and integration tests for protocol compliance
- [ ] **Benchmarks** – Performance measurement suite
- [ ] **Connection Limits** – Per-IP rate limiting and connection pooling
- [ ] **Metrics & Monitoring** – Prometheus/OpenTelemetry integration

## Building & Running

### Prerequisites

- Rust 1.90+ (edition 2024)
- Linux recommended for zero-copy support (works on other platforms with fallback)

### Build

```bash
# Debug build
cargo build

# Release build (recommended)
cargo build --release
```

Run

```bash
# Run with default configuration (reads config.toml if present)
cargo run --release

# Or run the binary directly
./target/release/proxy-core
```

### Configuration

#### Configuration File

Create a `config.toml` file in the working directory:

```toml
[server]
# Address to bind the proxy server
listen_address = "0.0.0.0:1080"
# Graceful shutdown timeout
shutdown_timeout = "60s"
# TCP listen backlog size
backlog_size = 1024
# Maximum concurrent connections (0 = unlimited)
max_connections = 0

[socks5]
# Allow connections without authentication
# WARNING: Only enable in trusted networks
allow_no_auth = true
# Timeout for CONNECT command execution
connect_timeout = "10s"
# Timeout for BIND command execution
bind_timeout = "40s"
```

#### Environment Variables

Configuration can be overridden using environment variables with the `PROXY__` prefix and double underscores as separators:

```bash
# Server configuration
export PROXY__SERVER__LISTEN_ADDRESS="127.0.0.1:9050"
export PROXY__SERVER__MAX_CONNECTIONS=0 # unlimited
export PROXY__SERVER__SHUTDOWN_TIMEOUT="30s"

# SOCKS5 configuration
export PROXY__SOCKS5__ALLOW_NO_AUTH=false
export PROXY__SOCKS5__CONNECT_TIMEOUT="15s"
export PROXY__SOCKS5__BIND_TIMEOUT="60s"

# Logging (uses RUST_LOG)
export RUST_LOG="proxy_core=debug,info"
```

#### Precedence

Configuration is loaded in the following order (highest to lowest priority):

1. Environment variables
2. Configuration file (`config.toml`)
3. Default values

## Usage

### Testing CONNECT Command

Use `curl` with SOCKS5 proxy support:

```bash
# Test HTTP connection through proxy
curl -si --socks5 127.0.0.1:1080 http://example.com

# With authentication (if allow_no_auth = false)
curl -si --socks5-hostname 127.0.0.1:1080 --proxy-user uname:passwd http://example.com

# Test HTTPS connection
curl -si --socks5-hostname 127.0.0.1:1080 https://example.com

# NOTE: `--socks5` resolves host locally, `--socks5-hostname` resolves via proxy
```

Redirecting traffic via proxy with `proxychains`

```bash
# Edit /etc/proxychains.conf or ~/.proxychains/proxychains.conf
# Add your proxy at the end of the file, for example:
# socks5  127.0.0.1 1080

# Then run any command through the proxy:
proxychains curl -si http://example.com

# Works with any TCP-based program:
proxychains nc -vz example.com 80
proxychains ssh user@example.com
```

### Testing BIND Command

The BIND command is typically used for FTP data connections or other protocols requiring inbound connections:

Simple python example for testing BIND:
```py
import socket
import struct

# Connect to SOCKS5 proxy
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 1080))

# Send greeting (no auth)
sock.sendall(b"\x05\x01\x00")
print("Greeting response:", sock.recv(2).hex())

# Send BIND request for 0.0.0.0:0
sock.sendall(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")

# First BIND response
response = sock.recv(10)
print("First BIND response:", response.hex())

_, reply, _, atyp = struct.unpack("BBBB", response[:4])
if reply != 0:
    print(f"Bind request failed with reply code {reply}")
    sock.close()
    exit()

addr = socket.inet_ntoa(response[4:8]) # only IPv4
port = struct.unpack("!H", response[8:10])[0]
print(f"Bound address: {addr}:{port}")
print("Waiting for incoming connection...")

# Second BIND response (connection accepted)
response2 = sock.recv(10)
print("Second BIND response:", response2.hex())

# Read and print everything from target
print("Incoming data from target:")
while True:
    data = sock.recv(4096)
    if not data:
        break
    print(data.decode("utf-8", errors="replace"))

sock.close()
```

## References

- [RFC 1928: SOCKS Protocol Version 5](https://datatracker.ietf.org/doc/html/rfc1928)
- [RFC 1929: Username/Password Authentication for SOCKS V5](https://datatracker.ietf.org/doc/html/rfc1929)
- [RFC 8305: Happy Eyeballs Version 2: Better Connectivity Using Concurrency](https://datatracker.ietf.org/doc/html/rfc8305)
- [RFC 6724: Default Address Selection for Internet Protocol Version 6 (IPv6)](https://datatracker.ietf.org/doc/html/rfc6724)
