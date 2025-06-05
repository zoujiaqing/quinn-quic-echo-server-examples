use {
    anyhow::Result,
    clap::Parser,
    quinn_echo_server::{configure, server::EchoClient},
    tracing::info,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Don't validate certificates (insecure mode)
    #[clap(long)]
    insecure: bool,
    
    /// Certificate file path
    #[clap(long)]
    cert_pem: Option<String>,
    
    /// Private key file path
    #[clap(long)]
    key_pem: Option<String>,
    
    /// Server address
    #[clap(long, default_value = "127.0.0.1:5001")]
    server: String,
    
    /// Enable client certificate authentication
    #[clap(long)]
    client_auth: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .with_ansi(true)
        .init();

    let args = Cli::parse();
    info!("QUIC Echo Client connecting to: {}", args.server);

    // Configure client based on arguments
    let client_config = if args.cert_pem.is_some() && args.client_auth && args.key_pem.is_some() {
        // Client authentication mode
        let cert_path = args.cert_pem.as_ref().unwrap();
        let key_path = args.key_pem.as_ref().unwrap();
        info!("Using client certificate authentication: cert={}, key={}", cert_path, key_path);
        
        if args.insecure {
            info!("Client auth with insecure server verification");
            configure::configure_client_with_client_auth_pem_insecure(cert_path, key_path)?
        } else {
            configure::configure_client_with_client_auth_pem(cert_path, key_path)?
        }
    } else if args.cert_pem.is_some() {
        // Server validation only
        let cert_path = args.cert_pem.as_ref().unwrap();
        info!("Using certificate to validate server: {}", cert_path);
        
        if args.insecure {
            info!("Insecure mode enabled (ignoring certificate)");
            configure::configure_client_insecure()
        } else {
            configure::configure_client_with_pem_cert(cert_path)?
        }
    } else {
        // Default: insecure mode
        info!("Using insecure mode (no certificate validation)");
        configure::configure_client_insecure()
    };

    // Fixed message for simplicity and automation
    let message = "Hello server!";

    // Create client and connect
    let server_addr: std::net::SocketAddr = args.server.parse()?;
    let client = EchoClient::new(client_config);
    
    // Step 1: Connect to server
    let connection = client.connect(server_addr).await?;
    
    // Step 2: Send message and receive echo
    let echo = EchoClient::echo_message(&connection, message).await?;
    info!("Echo received: {}", echo);

    info!("Client completed successfully");
    Ok(())
} 