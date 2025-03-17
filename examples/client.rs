use {
    anyhow::{Result, Context},
    clap::Parser,
    quinn::Endpoint,
    std::net::{IpAddr, SocketAddr},
    std::time::Duration,
    std::fs,
    std::path::PathBuf,
    quinn_echo_server::configure::{configure_client, configure_client_insecure},
    tokio::io::AsyncWriteExt,
    tracing::{info, error},
    rustls::pki_types::CertificateDer,
};

#[derive(Parser)]
#[clap(name = "QUIC Echo Client")]
struct Cli {
    /// Server address
    #[clap(long, default_value = "127.0.0.1")]
    server_addr: IpAddr,

    /// Server port
    #[clap(long, default_value = "5001")]
    server_port: u16,

    /// Data to send (defaults to "hello world")
    #[clap(long, default_value = "hello world")]
    message: String,

    /// Number of times to repeat the message
    #[clap(long, default_value = "1")]
    repeat: usize,
    
    /// Path to the server certificate (if not specified, insecure mode is used)
    #[clap(long)]
    cert: Option<PathBuf>,
}

// Read data from stream
async fn read_stream(mut stream: quinn::RecvStream) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut buf = vec![0; 4096];
    
    while let Some(chunk) = stream.read_chunk(4096, false).await? {
        data.extend_from_slice(&chunk.bytes);
    }
    
    Ok(data)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .with_ansi(true)
        .init();

    // Parse command line arguments
    let args = Cli::parse();
    let server_addr = SocketAddr::new(args.server_addr, args.server_port);
    info!("Connecting to server: {}", server_addr);

    // Configure client
    let client_config = if let Some(cert_path) = &args.cert {
        // Certificate mode
        info!("Using certificate mode with path: {}", cert_path.display());
        
        // Read server certificate from file
        if !cert_path.exists() {
            return Err(anyhow::anyhow!("Certificate file not found: {}", cert_path.display()));
        }
        
        let cert_bytes = fs::read(cert_path)
            .with_context(|| format!("Failed to read certificate file: {}", cert_path.display()))?;
        info!("Certificate size: {} bytes", cert_bytes.len());
        let server_cert = CertificateDer::from(cert_bytes);
        configure_client(server_cert)
    } else {
        // Insecure mode (default)
        info!("Using insecure mode (no certificate verification)");
        configure_client_insecure()
    };
    
    // Create client endpoint
    let bind_addr = SocketAddr::new("0.0.0.0".parse()?, 0);
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    // Connect to server
    info!("Connecting to server...");
    let connection = match endpoint.connect(server_addr, "localhost") {
        Ok(connecting) => {
            match connecting.await {
                Ok(conn) => {
                    info!("Successfully connected to server!");
                    conn
                },
                Err(e) => {
                    error!("Failed to connect to server: {}", e);
                    return Err(e.into());
                }
            }
        },
        Err(e) => {
            error!("Failed to create connection: {}", e);
            return Err(e.into());
        }
    };

    // Wait for the "Hello Client" message from the server
    info!("Waiting for server welcome message...");
    if let Ok(stream) = connection.accept_uni().await {
        let data = read_stream(stream).await?;
        let message = String::from_utf8_lossy(&data);
        info!("Received server message: {}", message);
    }

    // Create data stream and send data
    for i in 0..args.repeat {
        info!("Opening unidirectional stream...");
        let mut send_stream = connection.open_uni().await?;
        info!("Sending message {}/{}: {}", i+1, args.repeat, args.message);
        
        send_stream.write_all(args.message.as_bytes()).await?;
        send_stream.finish()?;
        info!("Message sent");
        
        // Wait for echo message from server
        info!("Waiting for server echo...");
        if let Ok(stream) = connection.accept_uni().await {
            let data = read_stream(stream).await?;
            let echo_message = String::from_utf8_lossy(&data);
            info!("Received server echo: {}", echo_message);
            
            // Verify echo is correct
            if echo_message == args.message {
                info!("Echo verification successful!");
            } else {
                error!("Echo verification failed! Expected: {}, Actual: {}", args.message, echo_message);
            }
        } else {
            error!("No echo received from server");
        }
    }

    // Wait a bit to ensure data is sent and processed
    info!("Waiting for data processing...");
    tokio::time::sleep(Duration::from_millis(500)).await;
    info!("Message sending successful!");

    // Close connection and endpoint
    info!("Closing connection...");
    connection.close(0u32.into(), b"Done");
    endpoint.wait_idle().await;
    info!("Client exited");

    Ok(())
} 