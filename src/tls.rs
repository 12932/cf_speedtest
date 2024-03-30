use rustls::crypto::ring;
use rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256;
use rustls::pki_types::TrustAnchor;
use rustls::ClientConfig;
use rustls::RootCertStore;
use std::sync::Arc;
use ureq::TlsConnector;

use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Debug)]
pub struct RawIo {
    inner: TcpStream,
}

impl Read for RawIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let num_bytes = self.inner.read(buf)?;
        Ok(num_bytes)
    }
}

impl Write for RawIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl ureq::ReadWrite for RawIo {
    fn socket(&self) -> Option<&TcpStream> {
        Some(&self.inner)
    }
}

pub struct InterceptingTlsConnector {
    inner: Arc<ClientConfig>,
}

impl InterceptingTlsConnector {
    pub fn new() -> Self {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| TrustAnchor {
            subject: ta.subject.clone(),
            subject_public_key_info: ta.subject_public_key_info.clone(),
            name_constraints: None,
        }));

        let my_provider = rustls::crypto::CryptoProvider {
            cipher_suites: vec![TLS13_CHACHA20_POLY1305_SHA256],
            ..ring::default_provider()
        };

        let config = rustls::ClientConfig::builder_with_provider(my_provider.into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Self {
            inner: Arc::new(config),
        }
    }
}

impl std::io::Read for InterceptingIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let num_bytes = self.io.read(buf)?;
        Ok(num_bytes)
    }
}

impl std::io::Write for InterceptingIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.io.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }
}

impl ureq::ReadWrite for InterceptingIo {
    fn socket(&self) -> Option<&std::net::TcpStream> {
        None
    }
}

#[derive(Debug)]
pub struct InterceptingIo {
    io: Box<dyn ureq::ReadWrite>,
}

impl TlsConnector for InterceptingTlsConnector {
    fn connect(
        &self,
        dns_name: &str,
        io: Box<dyn ureq::ReadWrite>,
    ) -> std::result::Result<Box<dyn ureq::ReadWrite + 'static>, ureq::Error> {
        let raw_io = RawIo {
            inner: io.socket().unwrap().try_clone().unwrap(),
        };

        let tls_io = self
            .inner
            .connect(dns_name, Box::new(raw_io))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        Ok(Box::new(InterceptingIo { io: tls_io }))
    }
}
