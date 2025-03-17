# QUIC Throttling Echo Server

This is an echo server implementation based on the QUIC protocol, supporting traffic throttling and certificate validation/non-validation modes. After accepting a client connection, the server proactively sends a welcome message and echoes back any messages sent by the client.

## Features

- High-performance communication based on QUIC protocol
- Support for certificate validation and non-validation modes
- Proactive welcome message from server
- Message echo functionality
- Configurable traffic throttling
- Comprehensive logging

## Main Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| quinn | 0.11 | QUIC protocol implementation |
| rustls | 0.23.5 | TLS encryption implementation with ring backend |
| tokio | 1.38 | Asynchronous runtime with full features |
| rcgen | 0.13 | Certificate generation |
| clap | 4.5 | Command-line argument parsing with derive and cargo features |
| tracing | 0.1.10 | Logging framework |
| anyhow | 1.0 | Error handling |
| tracing-subscriber | 0.3.0 | Logging subscriber implementation |

## Usage

By default, both server and client run in insecure mode (without certificate verification). You can enable certificate mode by specifying the certificate path.

### Server

#### Default Mode (Insecure)

```bash
cargo run --example server
```

This will start the server in insecure mode without using certificates.

#### Certificate Mode

```bash
cargo run --example server -- --cert server_cert.der
```

This will start the server with certificate validation. If the certificate file doesn't exist, it will be generated and saved to the specified path.

### Client

#### Default Mode (Insecure)

```bash
cargo run --example client
```

The client will connect to the server without certificate verification.

#### Certificate Mode

```bash
cargo run --example client -- --cert server_cert.der
```

The client will read the server certificate from the specified file and validate the connection.

### Custom Messages

```bash
cargo run --example client -- --message "Custom message" --repeat 3
```

This will send a custom message and repeat it 3 times.

## Workflow

1. Server starts and listens for connections
2. Client connects to the server
3. Server sends a "Hello Client" welcome message to the client
4. Client sends a message to the server
5. Server echoes the received message back to the client
6. Client verifies if the echo message is correct

## Project Structure

- `src/configure.rs`: Configuration module, handling certificates and connection setup
- `src/server.rs`: Core server implementation
- `examples/server.rs`: Server example
- `examples/client.rs`: Client example

## Notes

- Default mode is insecure (no certificate verification), which is suitable for development and testing environments
- Certificate mode should be used for production environments
- Default listening address is `127.0.0.1:5001`
- When using certificate mode, the certificate file will be generated if it doesn't exist 