use {
    anyhow::Result,
    quinn::{Endpoint, Incoming, Connection},
    tokio::{
        io::AsyncReadExt,
        sync::mpsc::UnboundedSender,
    },
    tokio_util::sync::CancellationToken,
    tracing::{debug, error, info},
};

type Sender = UnboundedSender<Vec<u8>>;

async fn handle_stream<RecvType>(
    mut from: RecvType,
    sender: Sender,
    connection: Option<Connection>,
) -> Result<()>
where
    RecvType: AsyncReadExt + Unpin,
{
    const BUF_SIZE: usize = 4 * 1024;
    let mut data = vec![0u8; BUF_SIZE];
    let mut received_data = Vec::new();
    
    loop {
        let n_read = match from.read(&mut data).await {
            Ok(0) => {
                debug!("Stream finished.");
                break;
            },
            Ok(n) => {
                debug!("Read bytes: {n}");
                n
            },
            Err(e) => {
                error!("Error reading from stream: {}", e);
                return Err(e.into());
            }
        };
        
        received_data.extend_from_slice(&data[..n_read]);
    }
    
    if !received_data.is_empty() {
        // Send echo message back to client (if connection exists)
        if let Some(conn) = &connection {
            let mut send_stream = conn.open_uni().await?;
            send_stream.write_all(&received_data).await?;
            send_stream.finish()?;
            debug!("Echo sent back to client: {} bytes", received_data.len());
        }
        
        // Send to consumer
        let _ = sender.send(received_data)?;
    }
    
    Ok(())
}

async fn handle_connection(
    incoming: Incoming,
    sender: Sender,
    cancel: CancellationToken,
) -> Result<()> {
    let connection = incoming.await?;
    
    // Send "Hello Client" message to the client
    let mut send_stream = connection.open_uni().await?;
    let hello_message = b"Hello Client";
    send_stream.write_all(hello_message).await?;
    send_stream.finish()?;
    info!("Sent 'Hello Client' to the client");
    
    loop {
        if cancel.is_cancelled() {
            info!("stopping connection handling due to signal received.");
            break;
        }
        let stream = connection.accept_uni().await;
        let stream = match stream {
            Err(quinn::ConnectionError::ApplicationClosed(e)) => {
                info!("connection closed: {e:?}");
                break;
            }
            Err(e) => {
                return Err(e.into());
            }
            Ok(s) => s,
        };

        debug!("Got stream");
        handle_stream(stream, sender.clone(), Some(connection.clone())).await?;
    }
    Ok(())
}

pub async fn listen(
    endpoint: Endpoint,
    sender: Sender,
    cancel: CancellationToken,
) -> Result<()> {
    info!("listening on {}", endpoint.local_addr()?);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Shutting down.");
                break;
            },
            Some(incoming) = endpoint.accept() => {
                if sender.is_closed() {
                    error!("Sender is unexpectedly closed.");
                    break;
                }
                info!("accepting connection");
                tokio::spawn(handle_connection(incoming, sender.clone(), cancel.clone()));
            },
            else => {
                error!("Endpoint is unexpectedly closed.");
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::configure::{configure_client, configure_server},
        quinn::Endpoint,
        std::net::{Ipv4Addr, SocketAddr},
        tokio::{
            io::AsyncWriteExt,
            sync::mpsc,
            time::{timeout, Duration},
        },
    };

    #[tokio::test]
    async fn test_handle_stream() {
        let (mut send_stream, recv_stream) = tokio::io::duplex(64);
        let (unbounded_sender, mut unbounded_receiver) = mpsc::unbounded_channel();

        let data = b"hello world";
        send_stream.write_all(data).await.unwrap();
        send_stream.shutdown().await.unwrap();

        tokio::spawn(async move {
            handle_stream(recv_stream, unbounded_sender, None)
                .await
                .unwrap();
        });

        let received_data = unbounded_receiver.recv().await.unwrap();
        assert_eq!(received_data, data);
    }

    #[tokio::test]
    async fn test_listen() -> Result<()> {
        let (sender, mut receiver) = mpsc::unbounded_channel();

        let (server_config, server_cert) = configure_server(1500);
        let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())?;
        let listen_addr = server_endpoint.local_addr().unwrap();
        let cancel = CancellationToken::new();
        tokio::spawn(async move {
            listen(
                server_endpoint,
                sender,
                cancel,
            )
            .await
            .unwrap();
        });

        // Wait for the server to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Configure client
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

        // Wait for the "Hello Client" message from the server
        let mut hello_stream = connection.accept_uni().await.unwrap();
        let mut hello_message = Vec::new();
        
        while let Some(chunk) = hello_stream.read_chunk(1024, false).await.unwrap() {
            hello_message.extend_from_slice(&chunk.bytes);
        }
        
        assert_eq!(hello_message, b"Hello Client");

        // Open a unidirectional stream and send data
        let mut send_stream = connection.open_uni().await.unwrap();
        let data = b"hello world";
        send_stream.write_all(data).await.unwrap();
        send_stream.finish().unwrap();

        // Wait for the echo message from the server
        let mut echo_stream = connection.accept_uni().await.unwrap();
        let mut echo_message = Vec::new();
        
        while let Some(chunk) = echo_stream.read_chunk(1024, false).await.unwrap() {
            echo_message.extend_from_slice(&chunk.bytes);
        }
        
        assert_eq!(echo_message, data);

        // Ensure the server received the data
        let received_data = timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received_data, data);

        Ok(())
    }
}
