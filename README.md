# QUIC Echo Server

A high-performance echo server implementation based on the QUIC protocol, built with Rust and the Quinn library. This server can receive client messages and echo them back, supporting various TLS certificate configuration options.

## Features

- High-performance communication based on QUIC protocol
- Multiple TLS certificate configuration methods (self-signed, PEM files, insecure mode)
- Automatic certificate generation and management
- Bidirectional communication between client and server
- Simple Echo service example
- Configurable receive window size and timeout parameters

## Building

```bash
cargo build --release
```

## Certificate Management

The server requires TLS certificates to work properly. This project provides multiple certificate configuration options:

### Generate Certificates with OpenSSL

You can generate self-signed certificates using the following command:

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout private.pem -out public.pem \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

This will generate two files:
- `public.pem`: Contains the public key and certificate
- `private.pem`: Contains the private key

### Using Generated Certificates

The program will automatically generate and save certificates, or use existing certificate files.

## Running the Server

The server has multiple startup modes that can be configured via command-line parameters:

### PEM Certificate Mode (Recommended)

Run the server using PEM format certificate and private key:

```bash
cargo run --example server -- --usepem --cert-pem public.pem --key-pem private.pem
```

### Default Self-Signed Certificate Mode

Use the built-in self-signed certificate:

```bash
cargo run --example server
```

### Save Certificate Mode

Generate a self-signed certificate and save it to a file:

```bash
cargo run --example server -- --cert certificate.der
```

### Insecure Mode

Disable certificate validation (for testing only):

```bash
cargo run --example server -- --insecure
```

### Client Authentication Mode

Require clients to present valid certificates:

```bash
cargo run --example server -- --require-client-cert
```

This can be combined with other certificate options:

```bash
cargo run --example server -- --usepem --cert-pem public.pem --key-pem private.pem --require-client-cert
```

## Server Parameters

The server supports the following command-line parameters:

- `<listen_address>`: Listen address, default is `127.0.0.1:5001`
- `--cert <PATH>`: Certificate save path
- `--usepem`: Use PEM format certificate
- `--cert-pem <PATH>`: PEM format certificate path
- `--key-pem <PATH>`: PEM format private key path
- `--insecure`: Insecure mode, disable certificate validation
- `--require-client-cert`: Require client to provide certificate for authentication

## Running the Client

The client also supports multiple validation modes:

### Validate Server with PEM Certificate

```bash
cargo run --example client -- --cert-pem public.pem
```

### Validate Server with DER Certificate

```bash
cargo run --example client -- --cert certificate.der
```

### Insecure Mode (No Server Certificate Validation)

```bash
cargo run --example client -- --insecure
```

### Client Authentication Mode

If the server requires client certificates, use these parameters to provide client certificate:

```bash
cargo run --example client -- --usepem --cert-pem public.pem --key-pem private.pem --client-auth
```

You can combine this with server validation:

```bash
# Validate server certificate and provide client certificate
cargo run --example client -- --usepem --cert-pem public.pem --key-pem private.pem --client-auth
```

## Client Parameters

The client supports the following command-line parameters:

- `--server-addr <IP>`: Server address, default is `127.0.0.1`
- `--server-port <PORT>`: Server port, default is `5001`
- `--message <TEXT>`: Message to send, default is `hello world`
- `--repeat <N>`: Number of times to repeat sending the message, default is `1`
- `--timeout <SECS>`: Operation timeout in seconds, default is `5`
- `--cert <PATH>`: DER format certificate path (for server validation)
- `--cert-pem <PATH>`: PEM format certificate path
- `--key-pem <PATH>`: PEM format private key path
- `--insecure`: Insecure mode, disable server certificate validation
- `--client-auth`: Enable client certificate authentication
- `--usepem`: Use PEM format certificate (use with --cert-pem and --key-pem)

## Communication Flow

1. Client connects to the server
2. Server sends "Hello Client" message to the client
3. Client sends messages to the server
4. Server echoes received messages back to the client

## Development

This project uses Quinn as the QUIC protocol implementation and rustls for TLS. Project structure:

- `src/configure.rs`: Certificate and configuration related functionality
- `src/server.rs`: Server core functionality
- `examples/server.rs`: Server example
- `examples/client.rs`: Client example

## License

MIT
