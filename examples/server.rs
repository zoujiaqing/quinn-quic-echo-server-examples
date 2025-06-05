use {
    anyhow::{Result, Context},
    clap::Parser,
    quinn::Endpoint,
    std::net::SocketAddr,
    tokio_util::sync::CancellationToken,
    tracing::info,
    quinn_echo_server::{configure, server::EchoServer},
};

#[derive(Parser)]
#[clap(name = "QUIC Echo Server")]
struct Cli {
    /// Listen address
    #[clap(default_value = "127.0.0.1:5001")]
    listen_address: SocketAddr,

    /// Path to PEM certificate file
    #[clap(long)]
    cert_pem: Option<String>,

    /// Path to PEM private key file
    #[clap(long)]
    key_pem: Option<String>,

    /// Whether to require client certificate
    #[clap(long, default_value = "false")]
    require_client_cert: bool,
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
    info!("Starting QUIC Echo Server on: {}", args.listen_address);

    // Configure server based on certificate options
    let server_endpoint = if args.cert_pem.is_some() && args.key_pem.is_some() {
        // PEM certificate mode
        let cert_path = args.cert_pem.unwrap();
        let key_path = args.key_pem.unwrap();
        info!("Using PEM certificate mode: cert={}, key={}", cert_path, key_path);
        
        let server_config = if args.require_client_cert {
            info!("Requiring client certificate authentication");
            configure::configure_server_require_client_cert_with_pem(&cert_path, &key_path)
                .context("Failed to configure server with client cert verification")?
        } else {
            configure::configure_server_with_pem_files(cert_path, key_path, 1500 * 100)
                .context("Failed to configure server with PEM files")?
        };
        
        Endpoint::server(server_config, args.listen_address)?
    } else {
        // Default: insecure mode
        info!("Using insecure mode (perfect for testing)");
        let (server_config, _) = configure::configure_server(1500 * 100);
        Endpoint::server(server_config, args.listen_address)?
    };

    // Create cancellation token for graceful shutdown
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    
    // Set up Ctrl+C handler
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        info!("Ctrl+C received, shutting down...");
        cancel_clone.cancel();
    });

    // Create and run echo server
    let echo_server = EchoServer::new(server_endpoint);
    echo_server.run(cancel).await?;
    
    info!("Server shutdown complete");
    Ok(())
} 