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
    /// 发送消息内容
    #[clap(short, long, default_value = "Hello, world!")]
    message: String,
    
    /// 重复发送次数
    #[clap(short, long, default_value = "1")]
    repeat: usize,
    
    /// 超时时间（毫秒）
    #[clap(short, long, default_value = "5000")]
    timeout: u64,
    
    /// 不验证证书（不安全模式）
    #[clap(long)]
    insecure: bool,

    /// 使用 PEM 证书
    #[clap(long)]
    usepem: bool,
    
    /// 证书文件路径
    #[clap(long)]
    cert_pem: Option<String>,
    
    /// 私钥文件路径
    #[clap(long)]
    key_pem: Option<String>,
    
    /// 服务器地址
    #[clap(long, default_value = "127.0.0.1:5001")]
    server: String,
    
    /// 是否启用客户端证书认证
    #[clap(long)]
    client_auth: bool,
}

// 用于读取数据流
async fn read_stream(mut stream: RecvStream) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    
    while let Some(chunk) = stream.read_chunk(1024, false).await? {
        data.extend_from_slice(&chunk.bytes);
    }
    
    Ok(data)
}

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .with_ansi(true)
        .init();

    // 解析命令行参数
    let args = Cli::parse();

    // 配置客户端
    let client_config = if args.usepem && args.cert_pem.is_some() && args.client_auth && args.key_pem.is_some() {
        // 带客户端认证的 PEM 模式（优先级最高）
        let cert_path = args.cert_pem.as_ref().unwrap();
        let key_path = args.key_pem.as_ref().unwrap();
        info!("使用 PEM 证书进行客户端认证: 证书={}, 密钥={}", cert_path, key_path);
        
        if args.insecure {
            info!("启用不安全模式 - 跳过服务器证书验证");
            configure::configure_client_with_client_auth_pem_insecure(cert_path, key_path)?
        } else {
            configure::configure_client_with_client_auth_pem(cert_path, key_path)?
        }
    } else if args.usepem && args.cert_pem.is_some() {
        // 只用 PEM 证书验证服务器
        let cert_path = args.cert_pem.as_ref().unwrap();
        info!("使用 PEM 证书: {}", cert_path);
        
        if args.insecure {
            info!("启用不安全模式 - 跳过服务器证书验证");
            configure::configure_client_insecure()
        } else {
            configure::configure_client_with_pem_cert(cert_path)
                .context("配置带 PEM 证书的客户端失败")?
        }
    } else if args.insecure {
        // 不安全模式（不验证证书）
        info!("使用不安全模式（无证书验证）");
        configure::configure_client_insecure()
    } else {
        // 默认不安全模式
        info!("未指定证书，使用不安全模式");
        configure::configure_client_insecure()
    };
    
    // 创建客户端端点
    let bind_addr = SocketAddr::new("0.0.0.0".parse::<IpAddr>()?, 0);
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    // 连接到服务器
    let server_addr = args.server.parse::<SocketAddr>()
        .context("无效的服务器地址")?;
    info!("连接到服务器: {}", server_addr);
    
    // 增加连接超时
    let conn_result = endpoint.connect(server_addr, "localhost")?;
    let connection = tokio::time::timeout(
        Duration::from_secs(10), // 增加到10秒
        conn_result
    )
    .await
    .map_err(|_| anyhow!("连接服务器超时"))?
    .map_err(|e| anyhow!("连接服务器失败: {}", e))?;
    
    info!("连接成功: {}", connection.remote_address());
    
    // 提示用户服务器通信已建立，准备发送消息
    info!("服务器连接已建立，准备发送消息...");
    
    // 发送消息
    for i in 0..args.repeat {
        let message = if args.repeat > 1 {
            format!("{} ({})", args.message, i + 1)
        } else {
            args.message.clone()
        };
        
        info!("发送消息: {}", message);
        
        // 创建双向流
        let bi_stream = tokio::time::timeout(
            Duration::from_secs(5), // 5秒超时
            connection.open_bi()
        ).await;
        
        match bi_stream {
            Ok(Ok((mut send, mut recv))) => {
                // 首先尝试读取服务器的欢迎消息（使用peek方法不消费数据）
                let mut peek_buf = [0u8; 1024];
                let greeting_result = tokio::time::timeout(
                    Duration::from_millis(1000), // 1秒超时
                    recv.read(&mut peek_buf)
                ).await;
                
                match greeting_result {
                    Ok(Ok(Some(n))) if n > 0 => {
                        let greeting = &peek_buf[..n];
                        info!("收到服务器欢迎消息: {}", String::from_utf8_lossy(greeting));
                    },
                    _ => {
                        info!("未收到欢迎消息，继续发送");
                    }
                }
                
                // 发送数据
                if let Err(e) = send.write_all(message.as_bytes()).await {
                    error!("发送数据失败: {}", e);
                    continue;
                }
                
                // 关闭发送方向
                if let Err(e) = send.finish() {
                    error!("结束流失败: {}", e);
                    continue;
                }
                
                // 接收回应
                let timeout_duration = Duration::from_millis(args.timeout);
                let result = tokio::time::timeout(
                    timeout_duration, 
                    read_stream(recv)
                ).await;
                
                match result {
                    Ok(Ok(data)) => {
                        let response = String::from_utf8_lossy(&data);
                        info!("收到回应: {}", response);
                    },
                    Ok(Err(e)) => {
                        error!("读取回应时出错: {}", e);
                    },
                    Err(_) => {
                        error!("接收回应超时 ({}ms)", args.timeout);
                    }
                }
            },
            Ok(Err(e)) => {
                error!("打开双向流失败: {}", e);
            },
            Err(_) => {
                error!("打开双向流超时");
            }
        }
        
        // 如果有多条消息，且不是最后一条，则添加延迟
        if i < args.repeat - 1 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    
    // 关闭连接
    info!("关闭连接...");
    connection.close(0u32.into(), b"client_close");
    endpoint.wait_idle().await;
    
    info!("客户端退出");
    Ok(())
} 