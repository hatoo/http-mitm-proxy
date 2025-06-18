# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust HTTP MITM (Man-in-the-Middle) proxy library designed to be a backend for applications like Burp Proxy. It enables inspection of HTTP/HTTPS traffic by dynamically generating TLS certificates.

### Key Features
- HTTP/HTTPS traffic interception via on-the-fly certificate signing
- WebSocket support (raw traffic only)
- Server-Sent Events support
- Certificate caching with moka
- Support for both native-tls and rustls TLS backends

## Development Commands

### Building and Testing
```bash
# Build the project
cargo build

# Run tests
cargo test

# Build documentation
cargo doc --open

# Run clippy for linting
cargo clippy

# Format code
cargo fmt

# Build examples
cargo build --examples

# Run a specific example (proxy server)
cargo run --example proxy

# Run with specific features
cargo build --no-default-features --features rustls-client
```

### Testing with Different TLS Backends
The crate supports two TLS client backends:
- `native-tls-client` (default)
- `rustls-client`

Only one can be enabled at a time due to compile-time checks.

## Architecture

### Core Components

**MitmProxy** (`src/lib.rs`): The main proxy server struct that handles:
- HTTP CONNECT method tunneling for HTTPS
- Certificate generation and caching
- Service wrapping for request/response interception
- Both HTTP/1.1 and HTTP/2 support with ALPN negotiation

**DefaultClient** (`src/default_client.rs`): HTTP client implementation with:
- Automatic TLS connection handling
- HTTP version negotiation (HTTP/1.1 vs HTTP/2)
- WebSocket upgrade support
- Connection pooling preparation (TODO)

**TLS Certificate Generation** (`src/tls.rs`): 
- Dynamic certificate creation signed by a root CA
- Certificate serialization to DER format
- Integration with rcgen for certificate generation

### Request Flow

1. **HTTP Requests**: Passed directly to the user-provided service
2. **HTTPS Requests** (CONNECT method):
   - Proxy establishes TLS connection with dynamically generated certificate
   - Decrypts HTTPS traffic for inspection
   - Re-encrypts and forwards to destination
   - Falls back to TCP tunneling if no root certificate provided

### Certificate Management

The proxy can operate in two modes:
- **With Root Certificate**: Full HTTPS inspection by generating fake certificates
- **Without Root Certificate**: Simple TCP tunneling for HTTPS (no inspection)

Certificate caching is handled via moka::sync::Cache with hostname as the key.

## Development Notes

### Feature Flags
- `native-tls-client`: Uses native-tls for TLS connections (default)
- `rustls-client`: Uses rustls for TLS connections
- Cannot enable both simultaneously (compile error)

### Testing Setup
Tests use incremental port allocation starting from 3666 to avoid conflicts. The test suite includes:
- HTTP/HTTPS proxy functionality
- WebSocket proxying
- Server-Sent Events
- Certificate generation and validation

### Examples
The `examples/` directory contains practical usage patterns:
- `proxy.rs`: Basic HTTP/HTTPS proxy with certificate generation
- `https.rs`: HTTPS-specific proxy setup
- `websocket.rs`: WebSocket proxying demonstration
- `reqwest_proxy.rs`: Integration with reqwest HTTP client
- `dev_proxy.rs`: Development/debugging proxy setup