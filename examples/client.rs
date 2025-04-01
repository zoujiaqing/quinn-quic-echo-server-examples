use {
    anyhow::{Result, Context, anyhow},
    clap::Parser,
    quinn::{Connection, Endpoint, RecvStream},
    std::net::{IpAddr, SocketAddr},
    std::time::Duration,
    quinn_echo_server::configure,
    tracing::{info, error, warn},
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Message content to send
    #[clap(short, long, default_value = "Hello, world!")]
    message: String,
    
    /// Number of times to repeat sending
    #[clap(short, long, default_value = "1")]
    repeat: usize,
    
    /// Timeout in milliseconds
    #[clap(short, long, default_value = "5000")]
    timeout: u64,
    
    /// Don't validate certificates (insecure mode)
    #[clap(long)]
    insecure: bool,

    /// Use PEM certificate
    #[clap(long)]
    usepem: bool,
    
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

// Function to read data from a stream
async fn read_stream(mut stream: RecvStream) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    
    while let Some(chunk) = stream.read_chunk(1024, false).await? {
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

    // Configure client
    let client_config = if args.usepem && args.cert_pem.is_some() && args.client_auth && args.key_pem.is_some() {
        // PEM mode with client authentication (highest priority)
        let cert_path = args.cert_pem.as_ref().unwrap();
        let key_path = args.key_pem.as_ref().unwrap();
        info!("Using PEM certificate for client authentication: cert={}, key={}", cert_path, key_path);
        
        if args.insecure {
            info!("Enabling insecure mode - skipping server certificate validation");
            configure::configure_client_with_client_auth_pem_insecure(cert_path, key_path)?
        } else {
            configure::configure_client_with_client_auth_pem(cert_path, key_path)?
        }
    } else if args.usepem && args.cert_pem.is_some() {
        // Using PEM certificate to validate server only
        let cert_path = args.cert_pem.as_ref().unwrap();
        info!("Using PEM certificate: {}", cert_path);
        
        if args.insecure {
            info!("Enabling insecure mode - skipping server certificate validation");
            configure::configure_client_insecure()
        } else {
            configure::configure_client_with_pem_cert(cert_path)
                .context("Failed to configure client with PEM certificate")?
        }
    } else if args.insecure {
        // Insecure mode (no certificate validation)
        info!("Using insecure mode (no certificate validation)");
        configure::configure_client_insecure()
    } else {
        // Default insecure mode
        info!("No certificate specified, using insecure mode");
        configure::configure_client_insecure()
    };
    
    // Create client endpoint
    let bind_addr = SocketAddr::new("0.0.0.0".parse::<IpAddr>()?, 0);
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    // Connect to server
    let server_addr = args.server.parse::<SocketAddr>()
        .context("Invalid server address")?;
    info!("Connecting to server: {}", server_addr);
    
    // Add connection timeout
    let conn_result = endpoint.connect(server_addr, "localhost")?;
    let connection = tokio::time::timeout(
        Duration::from_secs(10), // Increased to 10 seconds
        conn_result
    )
    .await
    .map_err(|_| anyhow!("Connection to server timed out"))?
    .map_err(|e| anyhow!("Failed to connect to server: {}", e))?;
    
    info!("Connection successful: {}", connection.remote_address());
    
    // Inform user that server communication is established, ready to send messages
    info!("Server connection established, preparing to send messages...");
    
    // Send messages
    for i in 0..args.repeat {
        let message = if args.repeat > 1 {
            format!("{} ({})", args.message, i + 1)
        } else {
            args.message.clone()
        };
        
        info!("Sending message: {}", message);
        
        // Create bidirectional stream
        let bi_stream = tokio::time::timeout(
            Duration::from_secs(5), // 5 second timeout
            connection.open_bi()
        ).await;
        
        match bi_stream {
            Ok(Ok((mut send, mut recv))) => {
                // First try to read server's welcome message (using peek method without consuming data)
                let mut peek_buf = [0u8; 1024];
                let greeting_result = tokio::time::timeout(
                    Duration::from_millis(1000), // 1 second timeout
                    recv.read(&mut peek_buf)
                ).await;
                
                match greeting_result {
                    Ok(Ok(Some(n))) if n > 0 => {
                        let greeting = &peek_buf[..n];
                        info!("Received server welcome message: {}", String::from_utf8_lossy(greeting));
                    },
                    _ => {
                        info!("No welcome message received, continuing to send");
                    }
                }
                
                // Send data
                if let Err(e) = send.write_all(message.as_bytes()).await {
                    error!("Failed to send data: {}", e);
                    continue;
                }
                
                // Close send direction
                if let Err(e) = send.finish() {
                    error!("Failed to finish stream: {}", e);
                    continue;
                }
                
                // Receive response
                let timeout_duration = Duration::from_millis(args.timeout);
                let result = tokio::time::timeout(
                    timeout_duration, 
                    read_stream(recv)
                ).await;
                
                match result {
                    Ok(Ok(data)) => {
                        let response = String::from_utf8_lossy(&data);
                        info!("Received response: {}", response);
                    },
                    Ok(Err(e)) => {
                        error!("Error reading response: {}", e);
                    },
                    Err(_) => {
                        error!("Receive response timed out ({}ms)", args.timeout);
                    }
                }
            },
            Ok(Err(e)) => {
                error!("Failed to open bidirectional stream: {}", e);
            },
            Err(_) => {
                error!("Opening bidirectional stream timed out");
            }
        }
        
        // If there are multiple messages, and this is not the last one, add a delay
        if i < args.repeat - 1 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    
    // Close connection
    info!("Closing connection...");
    connection.close(0u32.into(), b"client_close");
    endpoint.wait_idle().await;
    
    info!("Client exited");
    Ok(())
} 