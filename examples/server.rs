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

    /// 是否要求客户端证书
    #[clap(long, default_value = "false")]
    require_client_cert: bool,
}

// Custom server handler function
async fn handle_connection(connection: Connection, sender: UnboundedSender<Vec<u8>>) -> Result<()> {
    // 不再主动发送单向流的欢迎消息
    // 改为在双向流中发送欢迎消息
    
    // Receive client messages and echo them back
    while let Ok(stream) = connection.accept_bi().await {
        let (mut send, mut recv) = stream;
        let sender = sender.clone();
        let connection = connection.clone();
        
        tokio::spawn(async move {
            // 立即发送欢迎消息
            let hello_message = b"Hello Client";
            if let Err(e) = send.write_all(hello_message).await {
                error!("Failed to write welcome message: {}", e);
                return;
            }
            info!("Sent 'Hello Client' to client in bi-directional stream");
            
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
                
                // Send to consumer
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
    
    // 创建数据通道
    let (sender, receiver) = unbounded_channel();
    
    // 创建 Cancellation Token
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    
    // 设置 Ctrl+C 处理
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        info!("Ctrl+C received, shutting down...");
        cancel_clone.cancel();
    });
    
    // 启动数据消费任务
    tokio::spawn(consume_data(receiver));
    
    // 使用自定义的连接处理器处理连接
    let handle_conn = |conn: Connection| {
        let sender_clone = sender.clone();
        handle_connection(conn, sender_clone)
    };
    
    // 使用 EchoServer
    let echo_server = EchoServer::new(server_endpoint);
    echo_server.run_server(cancel).await?;
    
    info!("Server shut down");
    Ok(())
} 