use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use std::time::Duration;
use ureq::Agent;

// Import constants from main.rs
use crate::{CONNECT_TIMEOUT_MILLIS, OUR_USER_AGENT};

pub fn create_configured_agent() -> Agent {
    let mut root_store = RootCertStore::empty();
    root_store.roots = webpki_roots::TLS_SERVER_ROOTS.to_vec();

    // Create a custom crypto provider with only ChaCha20-Poly1305
    // because its fast in all cases, compared to AES where not all hardware has accel for it
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
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    ureq::builder()
        .tls_config(Arc::new(config))
        .timeout_connect(Duration::from_millis(CONNECT_TIMEOUT_MILLIS))
        .user_agent(OUR_USER_AGENT)
        .build()
}
