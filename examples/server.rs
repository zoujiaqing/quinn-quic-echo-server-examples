use {
    anyhow::{Result, Context},
    clap::Parser,
    quinn::{Endpoint, Connection, RecvStream, SendStream},
    std::net::SocketAddr,
    std::fs::File,
    std::io::Write,
    std::path::PathBuf,
    tokio::{
        io::AsyncWriteExt,
        sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    },
    tokio_util::sync::CancellationToken,
    tracing::{info, error},
    std::sync::Arc,
    quinn_echo_server::{configure, server::EchoServer},
};

#[derive(Parser)]
#[clap(name = "QUIC Echo Server")]
struct Cli {
    /// Listen address
    #[clap(default_value = "127.0.0.1:5001")]
    listen_address: SocketAddr,
    
    /// Path to save/load the certificate (if not specified, insecure mode is used)
    #[clap(long)]
    cert: Option<PathBuf>,

    /// Use PEM certificate and key files
    #[clap(long)]
    usepem: bool,

    /// Path to PEM certificate file
    #[clap(long)]
    cert_pem: Option<String>,

    /// Path to PEM private key file
    #[clap(long)]
    key_pem: Option<String>,

    /// Use insecure mode (ignore certificate verification)
    #[clap(long)]
    insecure: bool,

    /// Whether to require client certificate
    #[clap(long, default_value = "false")]
    require_client_cert: bool,
}

// Custom server handler function that uses the core server's connection handler
// but adds data collection functionality via channels
async fn handle_connection(connection: Connection, sender: UnboundedSender<Vec<u8>>) -> Result<()> {
    // Wait for client to initiate bidirectional stream
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        info!("Accepted new bidirectional stream");
        let sender = sender.clone();
        
        tokio::spawn(async move {
            // Send welcome message
            let welcome_message = "Hello Client";
            if let Err(e) = send.write_all(welcome_message.as_bytes()).await {
                error!("Failed to write welcome message: {}", e);
                return;
            }
            info!("Sent welcome message: {}", welcome_message);
            
            // Read and collect all data from the client
            let mut data = Vec::new();
            while let Some(chunk) = recv.read_chunk(4096, false).await.unwrap_or(None) {
                data.extend_from_slice(&chunk.bytes);
            }
            
            if !data.is_empty() {
                // Echo back the data
                if let Err(e) = send.write_all(&data).await {
                    error!("Failed to write echo response: {}", e);
                    return;
                }
                
                if let Err(e) = send.finish() {
                    error!("Failed to finish stream: {}", e);
                    return;
                }
                
                // Send to consumer for additional processing
                let _ = sender.send(data.clone());
                
                // Print received message
                let text = String::from_utf8_lossy(&data);
                info!("Received message: {} ({} bytes)", text, data.len());
            }
        });
    }
    
    Ok(())
}

async fn consume_data(receiver: UnboundedReceiver<Vec<u8>>) -> Result<()> {
    let mut receiver = receiver;
    info!("Starting to receive data...");
    while let Some(data) = receiver.recv().await {
        let message = String::from_utf8_lossy(&data);
        info!("Consumer received message: {} ({} bytes)", message, data.len());
    }
    info!("Data reception ended");
    Ok(())
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
    info!("Listening address: {}", args.listen_address);

    // Configure server
    info!("Configuring server...");
    
    let server_endpoint = if args.insecure {
        // Insecure mode
        info!("Using insecure mode (no certificate verification)");
        let server_config = configure::configure_server_insecure(1500 * 100);
        Endpoint::server(server_config, args.listen_address)?
    } else if args.usepem && args.cert_pem.is_some() && args.key_pem.is_some() {
        // PEM certificate mode
        let cert_path = args.cert_pem.unwrap();
        let key_path = args.key_pem.unwrap();
        info!("Using PEM certificate mode");
        info!("Certificate file: {}", cert_path);
        info!("Private key file: {}", key_path);
        
        let server_config = if args.require_client_cert {
            info!("Requiring client certificate");
            configure::configure_server_require_client_cert_with_pem(&cert_path, &key_path)
                .context("Failed to configure server with PEM files and client cert verification")?
        } else {
            configure::configure_server_with_pem_files(cert_path, key_path, 1500 * 100)
                .context("Failed to configure server with PEM files")?
        };
        
        Endpoint::server(server_config, args.listen_address)?
    } else if let Some(cert_path) = &args.cert {
        // Default certificate mode
        info!("Using certificate mode with path: {}", cert_path.display());
        
        let (server_config, server_cert) = configure::configure_server(1500 * 100);
        
        // Save certificate to file if it doesn't exist
        if !cert_path.exists() {
            info!("Certificate file not found, generating and saving...");
            let cert_bytes = server_cert.as_ref();
            info!("Certificate size: {} bytes", cert_bytes.len());
            let mut file = File::create(cert_path)
                .with_context(|| format!("Failed to create certificate file: {}", cert_path.display()))?;
            file.write_all(cert_bytes)?;
            info!("Certificate saved to: {}", cert_path.display());
        } else {
            info!("Using existing certificate file: {}", cert_path.display());
        }
        
        Endpoint::server(server_config, args.listen_address)?
    } else {
        // Default built-in self-signed certificate
        info!("Using default self-signed certificate mode");
        let (server_config, _) = configure::configure_server(1500 * 100);
        Endpoint::server(server_config, args.listen_address)?
    };
    
    info!("Server endpoint created, listening on: {}", server_endpoint.local_addr()?);
    
    // Create data channel
    let (sender, receiver) = unbounded_channel();
    
    // Create Cancellation Token
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    
    // Set up Ctrl+C handler
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        info!("Ctrl+C received, shutting down...");
        cancel_clone.cancel();
    });
    
    // Start data consumer task
    tokio::spawn(consume_data(receiver));
    
    // Create an EchoServer with a custom handler
    let echo_server = EchoServer::new(server_endpoint);
    
    // Use our custom handler with data collection capability
    let handle_conn = move |conn: Connection| {
        let sender_clone = sender.clone();
        handle_connection(conn, sender_clone)
    };
    
    // Use EchoServer with our custom handler
    echo_server.run_server_with_handler(cancel, handle_conn).await?;
    
    info!("Server shut down");
    Ok(())
} 