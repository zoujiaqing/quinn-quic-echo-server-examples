use {
    anyhow::{Result, Context},
    clap::Parser,
    quinn::{Endpoint, Connection, RecvStream},
    std::net::SocketAddr,
    std::fs::File,
    std::io::Write,
    quinn_echo_server::configure::{configure_server, configure_server_insecure},
    tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    tokio_util::sync::CancellationToken,
    tracing::{info, error},
};

#[derive(Parser)]
#[clap(name = "QUIC Echo Server")]
struct Cli {
    /// Listen address
    #[clap(default_value = "127.0.0.1:5001")]
    listen_address: SocketAddr,
    
    /// Path to save the certificate
    #[clap(long, default_value = "cert.der")]
    cert_path: String,
    
    /// Skip using certificate (insecure)
    #[clap(long)]
    insecure: bool,
}

// Custom server handler function
async fn handle_connection(connection: Connection, sender: UnboundedSender<Vec<u8>>) -> Result<()> {
    // Proactively send "Hello Client" message to the client
    let mut send_stream = connection.open_uni().await?;
    let hello_message = b"Hello Client";
    send_stream.write_all(hello_message).await?;
    send_stream.finish()?;
    info!("Sent 'Hello Client' to client");
    
    // Receive client messages and echo them back
    while let Ok(stream) = connection.accept_uni().await {
        tokio::spawn(handle_stream(stream, sender.clone(), connection.clone()));
    }
    
    Ok(())
}

// Handle a single stream
async fn handle_stream(mut stream: RecvStream, sender: UnboundedSender<Vec<u8>>, connection: Connection) -> Result<()> {
    let mut message = Vec::new();
    
    // Read client message
    while let Some(chunk) = stream.read_chunk(4096, false).await? {
        message.extend_from_slice(&chunk.bytes);
    }
    
    if !message.is_empty() {
        // Send echo message back to client
        let mut send_stream = connection.open_uni().await?;
        send_stream.write_all(&message).await?;
        send_stream.finish()?;
        info!("Echoed {} bytes back to client", message.len());
        
        // Send to consumer
        let _ = sender.send(message.clone());
        
        // Print received message
        let text = String::from_utf8_lossy(&message);
        info!("Received message: {} ({} bytes)", text, message.len());
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
        info!("Using insecure mode - no certificate");
        let server_config = configure_server_insecure(1500 * 100);
        Endpoint::server(server_config, args.listen_address)?
    } else {
        let (server_config, server_cert) = configure_server(1500 * 100);
        
        // Save certificate to file
        info!("Saving certificate to file...");
        let cert_bytes = server_cert.as_ref();
        info!("Certificate size: {} bytes", cert_bytes.len());
        let mut file = File::create(&args.cert_path)
            .with_context(|| format!("Failed to create certificate file: {}", args.cert_path))?;
        file.write_all(cert_bytes)?;
        info!("Certificate saved to: {}", args.cert_path);
        
        Endpoint::server(server_config, args.listen_address)?
    };
    
    info!("Server endpoint created, listening on: {}", server_endpoint.local_addr()?);
    
    // Create channel
    let (sender, receiver) = unbounded_channel();
    
    // Create cancellation token
    let cancel = CancellationToken::new();
    
    // Start consumer
    let consumer_handle = tokio::spawn(consume_data(receiver));
    
    // Start server
    info!("Server starting...");
    
    // Accept connections
    while let Some(connecting) = server_endpoint.accept().await {
        info!("Accepting new connection...");
        match connecting.await {
            Ok(connection) => {
                info!("Client connected: {}", connection.remote_address());
                let sender_clone = sender.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(connection, sender_clone).await {
                        error!("Connection handling error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Connection error: {}", e);
            }
        }
    }
    
    // Wait for consumer to finish
    if let Err(e) = consumer_handle.await {
        error!("Consumer error: {}", e);
    }
    
    info!("Server shut down");
    Ok(())
} 