use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::{CONNECT_TIMEOUT_MILLIS, OUR_USER_AGENT};

pub struct RawDownloadConnection {
    tcp_stream: TcpStream,
    _tls_conn: ClientConnection, // Keep alive but don't use for reading
}

impl RawDownloadConnection {
    /// Establish connection, perform TLS handshake, send HTTP request
    /// After this, the connection is ready to read raw encrypted bytes from socket
    pub fn connect(url: &str, bytes_to_request: usize) -> std::io::Result<Self> {
        // Parse URL
        let url_parsed = url.strip_prefix("https://").ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "URL must be https")
        })?;

        let (host, path) = if let Some(pos) = url_parsed.find('/') {
            (&url_parsed[..pos], &url_parsed[pos..])
        } else {
            (url_parsed, "/")
        };

        // Connect TCP socket
        let mut tcp_stream = TcpStream::connect((host, 443))?;
        tcp_stream.set_read_timeout(Some(Duration::from_millis(CONNECT_TIMEOUT_MILLIS)))?;
        tcp_stream.set_write_timeout(Some(Duration::from_millis(CONNECT_TIMEOUT_MILLIS)))?;
        tcp_stream.set_nodelay(true)?;

        // Setup TLS config (matching agent.rs)
        let mut root_store = RootCertStore::empty();
        root_store.roots = webpki_roots::TLS_SERVER_ROOTS.to_vec();

        let provider = rustls::crypto::ring::default_provider();
        let chacha_only_provider = CryptoProvider {
            cipher_suites: vec![*provider
                .cipher_suites
                .iter()
                .find(|&&cs| cs.suite() == rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
                .expect("ChaCha20-Poly1305 cipher suite not found")],
            ..provider
        };

        let config = ClientConfig::builder_with_provider(Arc::new(chacha_only_provider))
            .with_safe_default_protocol_versions()
            .expect("Failed to configure protocol versions")
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Create TLS connection
        let server_name =
            rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid server name")
            })?;
        let mut tls_conn =
            ClientConnection::new(Arc::new(config), server_name).map_err(std::io::Error::other)?;

        // Perform TLS handshake
        loop {
            // Write TLS data to socket
            while tls_conn.wants_write() {
                tls_conn.write_tls(&mut tcp_stream)?;
            }

            // If handshake is done, break
            if !tls_conn.is_handshaking() {
                break;
            }

            // Read TLS data from socket
            if tls_conn.wants_read() {
                tls_conn.read_tls(&mut tcp_stream)?;
                tls_conn
                    .process_new_packets()
                    .map_err(std::io::Error::other)?;
            }
        }

        // Send HTTP request through TLS
        let http_request = format!(
            "GET {path}&bytes={bytes_to_request} HTTP/1.1\r\n\
             Host: {host}\r\n\
             User-Agent: {}\r\n\
             Connection: close\r\n\
             \r\n",
            OUR_USER_AGENT
        );

        tls_conn
            .writer()
            .write_all(http_request.as_bytes())
            .map_err(std::io::Error::other)?;

        // Flush TLS data to socket
        while tls_conn.wants_write() {
            tls_conn.write_tls(&mut tcp_stream)?;
        }

        // Now we're ready to read raw encrypted bytes directly from the socket
        // We don't parse headers - just read raw TCP data for bandwidth measurement
        Ok(Self {
            tcp_stream,
            _tls_conn: tls_conn,
        })
    }

    /// Read raw encrypted TLS record bytes directly from the TCP socket
    /// This completely bypasses TLS decryption for maximum performance
    pub fn read_encrypted_bytes(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Read directly from TCP socket, getting encrypted TLS records
        // This is the raw wire data including TLS record headers, encrypted payload, and MAC tags
        self.tcp_stream.read(buf)
    }
}
