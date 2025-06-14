use {
    anyhow::Result,
    quinn::Endpoint,
    std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Once,
    },
    quinn_echo_server::{
        configure::{configure_client, configure_server},
        server::EchoServer,
    },
    tokio::{
        time::{sleep, Duration},
    },
    tokio_util::sync::CancellationToken,
    tracing::info,
    tracing_subscriber::EnvFilter,
};

async fn test_echo_performance() -> Result<f64, Box<dyn std::error::Error>> {
    const DATA: &[u8] = &[0; 128];

    let cancel = CancellationToken::new();

    // Configure the server
    let recv_window_size = DATA.len() as u32 * 16;
    let (mut server_config, server_cert) = configure_server(recv_window_size);
    server_config.incoming_buffer_size(1);
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())?;
    let listen_addr = server_endpoint.local_addr().unwrap();
    
    // Create EchoServer and run it
    let echo_server = EchoServer::new(server_endpoint);
    let server_handle = {
        let cancel = cancel.clone();
        tokio::spawn(async move { 
            echo_server.run(cancel).await 
        })
    };

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Configure the client
    let client_config = configure_client(server_cert);
    let bind = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0);
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(client_config);

    // Connect to the server
    let connection = endpoint
        .connect(listen_addr, "localhost")
        .expect("failed to create connecting")
        .await
        .expect("failed to connect");

    let cancel_timer = tokio::spawn(async move {
        sleep(Duration::from_secs(5)).await;
        cancel.cancel();
    });
    
    // Send test data using bidirectional streams (since EchoServer expects bi streams)
    let expected_num_txs = 10; // Reduce number for bi-directional streams
    let start_time = tokio::time::Instant::now();
    for _ in 0..expected_num_txs {
        // Open a bidirectional stream and send data
        let (mut send_stream, mut recv_stream) = connection.open_bi().await.unwrap();
        let data = DATA;
        send_stream.write_all(data).await.unwrap();
        send_stream.finish().unwrap();
        
        // Read the echo response
        let mut response = Vec::new();
        while let Some(chunk) = recv_stream.read_chunk(1024, false).await.unwrap() {
            response.extend_from_slice(&chunk.bytes);
        }
    }
    let elapsed_sending: f64 = start_time.elapsed().as_secs_f64();
    info!("Elapsed sending: {elapsed_sending}");

    let server_res = server_handle.await;
    assert!(server_res.is_ok(), "Error = {server_res:?}");

    let _ = cancel_timer.await;

    Ok(elapsed_sending)
}

static INIT: Once = Once::new();

#[allow(dead_code)]
fn init_tracing() {
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new("debug"))
            .init();
    });
}

#[tokio::test]
async fn test_echo_server() {
    init_tracing();
    let elapsed = test_echo_performance().await.unwrap();
    println!("Echo test completed. Send time: {elapsed}s");
}
