use rustls::crypto::CryptoProvider;
use rustls::RootCertStore;
use std::sync::Arc;
use std::time::Duration;
use ureq::Agent;

use crate::args::TlsCipher;
use crate::{CONNECT_TIMEOUT_MILLIS, OUR_USER_AGENT};

pub fn crypto_provider_for(cipher: TlsCipher) -> CryptoProvider {
    let provider = rustls::crypto::ring::default_provider();
    let target = match cipher {
        TlsCipher::Chacha20Poly1305 => rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        TlsCipher::Aes128Gcm => rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
    };
    CryptoProvider {
        cipher_suites: vec![*provider
            .cipher_suites
            .iter()
            .find(|&&cs| cs.suite() == target)
            .expect("requested TLS 1.3 cipher suite not available in ring provider")],
        ..provider
    }
}

pub fn create_configured_agent(cipher: TlsCipher) -> Agent {
    let mut root_store = RootCertStore::empty();
    root_store.roots = webpki_roots::TLS_SERVER_ROOTS.to_vec();

    let tls_config = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .unversioned_rustls_crypto_provider(Arc::new(crypto_provider_for(cipher)))
        .build();

    let agent_config = Agent::config_builder()
        .tls_config(tls_config)
        .timeout_connect(Some(Duration::from_millis(CONNECT_TIMEOUT_MILLIS)))
        .user_agent(OUR_USER_AGENT)
        .build();

    agent_config.into()
}
