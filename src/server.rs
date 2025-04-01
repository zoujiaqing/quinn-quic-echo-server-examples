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

// 服务器结构体
pub struct Server {
    endpoint: Endpoint,
}

// 服务器实现
impl Server {
    pub fn new(config: quinn::ServerConfig) -> Self {
        let socket = SocketAddr::from(([0, 0, 0, 0], 0));
        Self {
            endpoint: Endpoint::server(config, socket).unwrap(),
        }
    }

    pub async fn listen(&self, addr: &str) -> Result<()> {
        let addr = SocketAddr::from_str(addr)?;
        // 使用标准库重新绑定socket
        let udp_socket = UdpSocket::bind(addr)?;
        self.endpoint.rebind(udp_socket)?;
        info!("服务器监听地址: {}", addr);

        while let Some(conn) = self.endpoint.accept().await {
            let connection = conn.await?;
            info!("接受来自 {} 的新连接", connection.remote_address());
            
            // 判断客户端是否提供了证书
            let remote_addr = connection.remote_address();
            let handshake_data = connection.handshake_data();
            
            if let Some(crypto_data) = handshake_data.and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok()) {
                // 成功建立连接，启动一个新的任务处理连接
                info!("客户端连接：{}", remote_addr);
                tokio::spawn(handle_connection(connection));
            } else {
                info!("无法获取连接握手数据，拒绝连接: {}", remote_addr);
                // 不处理此连接
            }
        }

        info!("服务器已关闭");
        Ok(())
    }
}

// 处理客户端连接
async fn handle_connection(connection: Connection) -> Result<()> {
    info!("处理来自 {} 的连接", connection.remote_address());
    
    // 等待客户端发起双向流
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        info!("接受到新的双向流");
        
        // 在双向流建立后立即发送欢迎消息
        send.write_all(b"Hello Client").await?;
        info!("发送欢迎消息: Hello Client");
        
        // 读取客户端消息
        let mut buffer = [0u8; 1024];
        while let Ok(Some(n)) = recv.read(&mut buffer).await {
            let message = &buffer[..n];
            info!("收到消息: {}", String::from_utf8_lossy(message));
            
            // 回显消息
            send.write_all(message).await?;
            info!("回显消息: {}", String::from_utf8_lossy(message));
        }
    }
    
    info!("连接已关闭: {}", connection.remote_address());
    Ok(())
}

// 回显服务器实现 - 更简单的接口
pub struct EchoServer {
    endpoint: Endpoint,
}

impl EchoServer {
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }
    
    pub async fn run_server(&self, cancel_token: CancellationToken) -> Result<()> {
        info!("Echo服务器开始运行，地址: {}", self.endpoint.local_addr()?);
        
        tokio::select! {
            _ = async {
                while let Some(conn) = self.endpoint.accept().await {
                    match conn.await {
                        Ok(connection) => {
                            info!("新连接: {}", connection.remote_address());
                            tokio::spawn(handle_connection(connection));
                        },
                        Err(e) => {
                            error!("连接失败: {}", e);
                        }
                    }
                }
            } => {},
            _ = cancel_token.cancelled() => {
                info!("收到取消信号，服务器即将关闭");
            }
        }
        
        info!("Echo服务器已停止");
        Ok(())
    }
    
    // 新增方法，允许使用自定义连接处理函数
    pub async fn run_server_with_handler<F, Fut>(&self, cancel_token: CancellationToken, handler: F) -> Result<()>
    where
        F: Fn(Connection) -> Fut + Send + Sync + 'static + Clone,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        info!("Echo服务器开始运行，地址: {}", self.endpoint.local_addr()?);
        
        tokio::select! {
            _ = async {
                while let Some(conn) = self.endpoint.accept().await {
                    match conn.await {
                        Ok(connection) => {
                            info!("新连接: {}", connection.remote_address());
                            let handler = handler.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handler(connection).await {
                                    error!("处理连接时出错: {}", e);
                                }
                            });
                        },
                        Err(e) => {
                            error!("连接失败: {}", e);
                        }
                    }
                }
            } => {},
            _ = cancel_token.cancelled() => {
                info!("收到取消信号，服务器即将关闭");
            }
        }
        
        info!("Echo服务器已停止");
        Ok(())
    }
}

// 客户端模块
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
        info!("连接到服务器: {}", connection.remote_address());
        Ok(connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_echo() {
        let (client, connection) = setup().await;
        
        // 发送测试消息
        let test_message = b"Hello, World!";
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        
        send.write_all(test_message).await.unwrap();
        send.finish().unwrap();
        
        // 读取回显消息
        let mut buffer = Vec::new();
        let mut read_buf = [0u8; 1024];
        
        while let Ok(Some(n)) = recv.read(&mut read_buf).await {
            buffer.extend_from_slice(&read_buf[..n]);
        }
        
        // 验证回显消息
        assert_eq!(buffer, test_message);
    }
    
    async fn setup() -> (Client, Connection) {
        // 创建服务器配置
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let priv_key = cert.key_pair.serialize_der();
        
        let server_config = quinn::ServerConfig::with_single_cert(
            vec![cert_der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(priv_key.clone()))
        )
        .unwrap();
        
        // 创建服务器
        let server = Server::new(server_config);
        let server_addr = "127.0.0.1:0";
        tokio::spawn(async move {
            let _ = server.listen(server_addr).await;
        });
        
        // 等待服务器启动
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // 创建客户端配置
        let mut roots = RootCertStore::empty();
        roots.add(cert_der.clone()).unwrap();
        
        let client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        
        let client_config = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap()));
        
        // 创建客户端
        let client = Client::new(client_config);
        let connection = client.connect(server_addr).await.unwrap();
        
        (client, connection)
    }
}
