//! The server's TLS configurations do not depend on the process's default rustls provider.
//!
//! This file is a test binary of its own, because the default provider is one per process:
//! the test installs a useless one, which every other test would trip over.

use std::sync::Arc;

use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use server::acme::AcmeChallenges;
use server::acme::CurrentCert;
use server::{self_signed_cert, tls_config, tls_config_with_resolver};

#[test]
fn tls_configurations_are_built_whatever_the_process_default_provider_is() {
    // A default provider without cipher suites: what `ServerConfig::builder()` would use.
    // rustls panics in that call when no default is installed and two providers are compiled
    // in, and that cannot be set up from a test, so a provider that cannot work stands in.
    let useless = CryptoProvider {
        cipher_suites: Vec::new(),
        ..rustls::crypto::aws_lc_rs::default_provider()
    };
    useless
        .install_default()
        .expect("nothing installed a provider before this test");
    assert!(
        std::panic::catch_unwind(ServerConfig::builder).is_err(),
        "the default builder depends on the process default, which is why it is not used"
    );

    let (certs, key) = self_signed_cert().expect("self-signed cert");
    let config = tls_config(certs, key).expect("built on the named provider");
    assert_eq!(
        config.alpn_protocols,
        [b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert_ne!(config.crypto_provider().cipher_suites.len(), 0);

    let resolver = Arc::new(CurrentCert::new());
    let config = tls_config_with_resolver(resolver);
    assert_ne!(config.crypto_provider().cipher_suites.len(), 0);

    // The acceptor for TLS-ALPN-01 validations builds its own configuration.
    drop(AcmeChallenges::new());
}
