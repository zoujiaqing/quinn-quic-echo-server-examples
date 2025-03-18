use {
    rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
        RootCertStore,
    },
    std::{convert::TryInto, fs, io, path::Path, sync::Arc, time::Duration},
};

/// Build client configuration, trusting the given node certificate
pub fn configure_client(node_cert: CertificateDer<'static>) -> quinn::ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(node_cert).unwrap();

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(20).try_into().unwrap()));

    let crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut client_config = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap()));
    client_config.transport_config(Arc::new(transport_config));
    client_config
}

/// Build client configuration without certificate verification
pub fn configure_client_insecure() -> quinn::ClientConfig {
    // Create client configuration without certificate verification
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let mut client_config = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap()));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(20).try_into().unwrap()));
    client_config.transport_config(Arc::new(transport_config));
    client_config
}

// Custom verifier that skips server certificate verification
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

// Use static variable to store certificate, ensuring the same certificate is generated each time
static mut CERT: Option<(Vec<u8>, Vec<u8>)> = None;

/// Build server configuration along with its certificate
pub fn configure_server(recv_window_size: u32) -> (quinn::ServerConfig, CertificateDer<'static>) {
    // Use static variable to store certificate, ensuring the same certificate is generated each time
    let (our_cert, our_priv_key) = unsafe {
        if CERT.is_none() {
            let (cert, key) = gen_cert();
            let cert_bytes = cert.as_ref().to_vec();
            let key_bytes = key.secret_pkcs8_der().to_vec();
            CERT = Some((cert_bytes, key_bytes));
            (cert, key)
        } else {
            let (cert_bytes, key_bytes) = CERT.as_ref().unwrap();
            (
                CertificateDer::from(cert_bytes.clone()),
                PrivatePkcs8KeyDer::from(key_bytes.clone())
            )
        }
    };
    
    let mut our_cfg =
        quinn::ServerConfig::with_single_cert(vec![our_cert.clone()], our_priv_key.into()).unwrap();

    let transport_config = Arc::get_mut(&mut our_cfg.transport).unwrap();
    transport_config.receive_window(recv_window_size.into());
    transport_config.max_idle_timeout(Some(Duration::from_secs(20).try_into().unwrap()));

    (our_cfg, our_cert)
}

/// Build server configuration without certificate verification
pub fn configure_server_insecure(recv_window_size: u32) -> quinn::ServerConfig {
    // Generate self-signed certificate, but don't require client verification
    let (cert, key) = gen_cert();
    let mut server_config = quinn::ServerConfig::with_single_cert(
        vec![cert.clone()], 
        key.into()
    ).unwrap();
    
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.receive_window(recv_window_size.into());
    transport_config.max_idle_timeout(Some(Duration::from_secs(20).try_into().unwrap()));
    
    server_config
}

fn gen_cert() -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    (
        cert.cert.into(),
        PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
    )
}

/// 使用PEM文件配置服务器
pub fn configure_server_with_pem_files(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    recv_window_size: u32,
) -> io::Result<quinn::ServerConfig> {
    // 读取私钥
    let key_data = fs::read(key_path)?;
    let key = rustls_pemfile::private_key(&mut &*key_data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("malformed private key: {}", e)))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private keys found"))?;

    // 读取证书链
    let cert_data = fs::read(cert_path)?;
    let certs = rustls_pemfile::certs(&mut &*cert_data)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid PEM-encoded certificate: {}", e)))?;
    
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no certificates found in PEM file",
        ));
    }

    // 创建服务器加密配置
    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("TLS configuration error: {}", e)))?;
    
    // 创建QUIC服务器配置
    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("QUIC configuration error: {}", e)))?;
    
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    
    // 配置传输参数
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.receive_window(recv_window_size.into());
    transport_config.max_idle_timeout(Some(Duration::from_secs(20).try_into().unwrap()));
    
    Ok(server_config)
}

/// 使用PEM证书文件配置客户端
pub fn configure_client_with_pem_cert(cert_path: impl AsRef<Path>) -> io::Result<quinn::ClientConfig> {
    // 读取证书链
    let cert_data = fs::read(cert_path)?;
    let certs = rustls_pemfile::certs(&mut &*cert_data)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid PEM-encoded certificate: {}", e)))?;
    
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no certificates found in PEM file",
        ));
    }
    
    // 配置信任存储
    let mut roots = RootCertStore::empty();
    for cert in &certs {
        roots.add(cert.clone()).map_err(|e| 
            io::Error::new(io::ErrorKind::InvalidData, format!("failed to add certificate: {}", e))
        )?;
    }
    
    // 创建客户端加密配置
    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    
    // 创建QUIC客户端配置
    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("QUIC configuration error: {}", e)))?;
    
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
    
    // 配置传输参数
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(20).try_into().unwrap()));
    client_config.transport_config(Arc::new(transport_config));
    
    Ok(client_config)
}

/// 生成自签名证书并保存为PEM文件
pub fn generate_pem_cert_files(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> io::Result<()> {
    // 生成自签名证书
    let subject_alt_names = vec!["localhost".to_string()];
    
    let rcgen::CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to generate certificate: {}", e)))?;
    
    // 保存PEM格式的证书
    fs::write(cert_path, cert.pem())?;
    
    // 保存PEM格式的私钥
    fs::write(key_path, key_pair.serialize_pem())?;
    
    Ok(())
}
