use {
    anyhow::Result,
    quinn::{Endpoint, Connection},
    std::net::SocketAddr,
    tokio::io::{AsyncReadExt, AsyncWriteExt},
    tokio_util::sync::CancellationToken,
    tracing::{info, error},
};

/// Simple Echo Server
pub struct EchoServer {
    endpoint: Endpoint,
}

impl EchoServer {
    /// Create a new EchoServer with the given endpoint
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// Run the echo server
    pub async fn run(&self, cancel_token: CancellationToken) -> Result<()> {
        info!("Echo server listening on: {}", self.endpoint.local_addr()?);
        
        tokio::select! {
            _ = async {
                while let Some(incoming) = self.endpoint.accept().await {
                    match incoming.await {
                        Ok(connection) => {
                            info!("New connection from: {}", connection.remote_address());
                            tokio::spawn(handle_connection(connection));
                        },
                        Err(e) => {
                            error!("Connection failed: {}", e);
                        }
                    }
                }
            } => {},
            _ = cancel_token.cancelled() => {
                info!("Server shutdown requested");
            }
        }
        
        info!("Echo server stopped");
        Ok(())
    }

    /// Get server local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }
}

/// Handle a single client connection
async fn handle_connection(connection: Connection) -> Result<()> {
    let remote_addr = connection.remote_address();
    info!("Handling connection from: {}", remote_addr);
    
    info!("Waiting for bidirectional streams from: {}", remote_addr);
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        info!("New stream from: {}", remote_addr);
        
        // Read and echo messages (no welcome message)
        let mut buffer = [0u8; 1024];
        while let Ok(Some(len)) = recv.read(&mut buffer).await {
            let message = &buffer[..len];
            
            // Log received message
            let text = String::from_utf8_lossy(message);
            info!("Received from {}: {} ({} bytes)", remote_addr, text, len);
            
            // Echo back immediately
            if let Err(e) = send.write_all(message).await {
                error!("Failed to echo to {}: {}", remote_addr, e);
                break;
            }
            if let Err(e) = send.flush().await {
                error!("Failed to flush echo to {}: {}", remote_addr, e);
                break;
            }
            info!("Echoed to {}: {} bytes", remote_addr, len);
        }
        
        info!("Stream ended for: {}", remote_addr);
    }
    
    info!("Connection closed: {}", remote_addr);
    Ok(())
}

/// Simple Echo Client
pub struct EchoClient {
    endpoint: Endpoint,
}

impl EchoClient {
    /// Create a new EchoClient with the given configuration
    pub fn new(config: quinn::ClientConfig) -> Self {
        let mut endpoint = Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0))).unwrap();
        endpoint.set_default_client_config(config);
        
        Self { endpoint }
    }

    /// Connect to server and return the connection
    pub async fn connect(&self, server_addr: SocketAddr) -> Result<Connection> {
        info!("Attempting to connect to: {}", server_addr);
        let connection = self.endpoint.connect(server_addr, "localhost")?.await?;
        info!("Connected to server: {}", server_addr);
        Ok(connection)
    }

    /// Send message and receive echo on an existing connection
    pub async fn echo_message(connection: &Connection, message: &str) -> Result<String> {
        info!("Opening bidirectional stream...");
        let (mut send, mut recv) = connection.open_bi().await?;
        info!("Bidirectional stream opened");
        
        // Send our message
        info!("Sending message: {}", message);
        send.write_all(message.as_bytes()).await?;
        info!("Message sent successfully");
        
        // Read echo back
        info!("Reading echo from server...");
        let mut buffer = [0u8; 1024];
        let len = recv.read(&mut buffer).await?
            .ok_or_else(|| anyhow::anyhow!("Failed to receive echo"))?;
        let echo = String::from_utf8_lossy(&buffer[..len]).to_string();
        info!("Received echo: {}", echo);
        
        Ok(echo)
    }
}
