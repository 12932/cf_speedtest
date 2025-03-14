use rustls::crypto::CryptoProvider;
use rustls::RootCertStore;
use std::sync::Arc;
use std::time::Duration;
use ureq::Agent;

// Import constants from main.rs
use crate::{CONNECT_TIMEOUT_MILLIS, OUR_USER_AGENT};

pub fn create_configured_agent() -> Agent {
    let mut root_store = RootCertStore::empty();
    root_store.roots = webpki_roots::TLS_SERVER_ROOTS.to_vec();

    // Create a custom crypto provider with only ChaCha20-Poly1305
    let provider = rustls::crypto::ring::default_provider();
    let chacha_only_provider = CryptoProvider {
        cipher_suites: vec![*provider
            .cipher_suites
            .iter()
            .find(|&&cs| cs.suite() == rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
            .expect("ChaCha20-Poly1305 cipher suite not found")],
        ..provider
    };

    // Create a TlsConfig using the builder
    let tls_config = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        // Use the unversioned_rustls_crypto_provider method to pass your custom crypto provider
        .unversioned_rustls_crypto_provider(Arc::new(chacha_only_provider))
        .build();

    // Create the Agent with the TLS config
    let agent_config = Agent::config_builder()
        .tls_config(tls_config)
        .timeout_connect(Some(Duration::from_millis(CONNECT_TIMEOUT_MILLIS)))
        .user_agent(OUR_USER_AGENT)
        .build();

    agent_config.into()
}
