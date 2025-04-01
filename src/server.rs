use {
    anyhow::{Context, Result},
    quinn::{Endpoint, Incoming, Connection, RecvStream, SendStream},
    std::{net::{SocketAddr, UdpSocket}, str::FromStr, sync::Arc, future::Future},
    tokio::{
        io::AsyncReadExt,
        sync::mpsc,
        time::{timeout, Duration},
    },
    tokio_util::sync::CancellationToken,
    tracing::{debug, error, info},
    rustls::{RootCertStore, pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer}},
};

// Server struct
pub struct Server {
    endpoint: Endpoint,
}

// Server implementation
impl Server {
    pub fn new(config: quinn::ServerConfig) -> Self {
        let socket = SocketAddr::from(([0, 0, 0, 0], 0));
        Self {
            endpoint: Endpoint::server(config, socket).unwrap(),
        }
    }

    pub async fn listen(&self, addr: &str) -> Result<()> {
        let addr = SocketAddr::from_str(addr)?;
        // Use standard library to rebind socket
        let udp_socket = UdpSocket::bind(addr)?;
        self.endpoint.rebind(udp_socket)?;
        info!("Server listening on: {}", addr);

        while let Some(conn) = self.endpoint.accept().await {
            let connection = conn.await?;
            info!("Accepted new connection from {}", connection.remote_address());
            
            // Check if client provided a certificate
            let remote_addr = connection.remote_address();
            let handshake_data = connection.handshake_data();
            
            if let Some(crypto_data) = handshake_data.and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok()) {
                // Connection established successfully, start a new task to handle it
                info!("Client connected: {}", remote_addr);
                tokio::spawn(handle_connection(connection));
            } else {
                info!("Unable to get connection handshake data, rejecting connection: {}", remote_addr);
                // Skip processing this connection
            }
        }

        info!("Server has closed");
        Ok(())
    }
}

// Handle client connections with optional welcome message
async fn handle_connection_with_welcome(connection: Connection, welcome_message: Option<String>) -> Result<()> {
    info!("Handling connection from {}", connection.remote_address());
    
    // Wait for client to initiate bidirectional stream
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        info!("Accepted new bidirectional stream");
        
        // Send welcome message immediately after bidirectional stream is established
        if let Some(message) = &welcome_message {
            send.write_all(message.as_bytes()).await?;
            info!("Sent welcome message: {}", message);
        }
        
        // Read messages from client
        let mut buffer = [0u8; 1024];
        while let Ok(Some(n)) = recv.read(&mut buffer).await {
            let message = &buffer[..n];
            info!("Received message: {}", String::from_utf8_lossy(message));
            
            // Echo the message back
            send.write_all(message).await?;
            info!("Echoed message: {}", String::from_utf8_lossy(message));
        }
    }
    
    info!("Connection closed: {}", connection.remote_address());
    Ok(())
}

// Default handle_connection function with standard welcome message
pub async fn handle_connection(connection: Connection) -> Result<()> {
    handle_connection_with_welcome(connection, Some("Hello Client".to_string())).await
}

// Echo server implementation - simpler interface
pub struct EchoServer {
    endpoint: Endpoint,
    welcome_message: Option<String>,
}

impl EchoServer {
    pub fn new(endpoint: Endpoint) -> Self {
        Self { 
            endpoint,
            welcome_message: Some("Hello Client".to_string()),
        }
    }
    
    /// Create a new EchoServer with a custom welcome message
    pub fn with_welcome_message(endpoint: Endpoint, message: Option<String>) -> Self {
        Self {
            endpoint,
            welcome_message: message,
        }
    }
    
    /// Get the current welcome message
    pub fn welcome_message(&self) -> Option<&String> {
        self.welcome_message.as_ref()
    }
    
    /// Set a new welcome message
    pub fn set_welcome_message(&mut self, message: Option<String>) {
        self.welcome_message = message;
    }
    
    pub async fn run_server(&self, cancel_token: CancellationToken) -> Result<()> {
        info!("Echo server started running, address: {}", self.endpoint.local_addr()?);
        
        let welcome_message = self.welcome_message.clone();
        
        tokio::select! {
            _ = async {
                while let Some(conn) = self.endpoint.accept().await {
                    match conn.await {
                        Ok(connection) => {
                            info!("New connection: {}", connection.remote_address());
                            let welcome = welcome_message.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection_with_welcome(connection, welcome).await {
                                    error!("Connection handling error: {}", e);
                                }
                            });
                        },
                        Err(e) => {
                            error!("Connection failed: {}", e);
                        }
                    }
                }
            } => {},
            _ = cancel_token.cancelled() => {
                info!("Received cancellation signal, server will shut down");
            }
        }
        
        info!("Echo server has stopped");
        Ok(())
    }
    
    // New method allowing custom connection handler function
    pub async fn run_server_with_handler<F, Fut>(&self, cancel_token: CancellationToken, handler: F) -> Result<()>
    where
        F: Fn(Connection) -> Fut + Send + Sync + 'static + Clone,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        info!("Echo server started running, address: {}", self.endpoint.local_addr()?);
        
        tokio::select! {
            _ = async {
                while let Some(conn) = self.endpoint.accept().await {
                    match conn.await {
                        Ok(connection) => {
                            info!("New connection: {}", connection.remote_address());
                            let handler = handler.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handler(connection).await {
                                    error!("Error handling connection: {}", e);
                                }
                            });
                        },
                        Err(e) => {
                            error!("Connection failed: {}", e);
                        }
                    }
                }
            } => {},
            _ = cancel_token.cancelled() => {
                info!("Received cancellation signal, server will shut down");
            }
        }
        
        info!("Echo server has stopped");
        Ok(())
    }
}

// Client module
pub struct Client {
    endpoint: Endpoint,
    config: quinn::ClientConfig,
}

impl Client {
    pub fn new(config: quinn::ClientConfig) -> Self {
        let socket = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut endpoint = Endpoint::client(socket).unwrap();
        endpoint.set_default_client_config(config.clone());
        
        Self {
            endpoint,
            config,
        }
    }

    pub async fn connect(&self, addr: &str) -> Result<Connection> {
        let addr = SocketAddr::from_str(addr)?;
        let connection = self.endpoint.connect(addr, "localhost")?.await?;
        info!("Connected to server: {}", connection.remote_address());
        Ok(connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_echo() {
        let (client, connection) = setup().await;
        
        // Send test message
        let test_message = b"Hello, World!";
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        
        send.write_all(test_message).await.unwrap();
        send.finish().unwrap();
        
        // Read echoed message
        let mut buffer = Vec::new();
        let mut read_buf = [0u8; 1024];
        
        while let Ok(Some(n)) = recv.read(&mut read_buf).await {
            buffer.extend_from_slice(&read_buf[..n]);
        }
        
        // Verify echoed message
        assert_eq!(buffer, test_message);
    }
    
    async fn setup() -> (Client, Connection) {
        // Create server configuration
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let priv_key = cert.key_pair.serialize_der();
        
        let server_config = quinn::ServerConfig::with_single_cert(
            vec![cert_der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(priv_key.clone()))
        )
        .unwrap();
        
        // Create server
        let server = Server::new(server_config);
        let server_addr = "127.0.0.1:0";
        tokio::spawn(async move {
            let _ = server.listen(server_addr).await;
        });
        
        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Create client configuration
        let mut roots = RootCertStore::empty();
        roots.add(cert_der.clone()).unwrap();
        
        let client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        
        let client_config = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap()));
        
        // Create client
        let client = Client::new(client_config);
        let connection = client.connect(server_addr).await.unwrap();
        
        (client, connection)
    }
}
