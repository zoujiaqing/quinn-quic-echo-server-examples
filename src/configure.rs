use {
    rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
        RootCertStore,
    },
    std::{convert::TryInto, sync::Arc, time::Duration},
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
