use crate::config::store::get_tls;
use async_trait::async_trait;
use openssl::ssl::{NameType, SslRef};
use pingora::{listeners::TlsAccept, tls::ext};
use tracing::error;

/// Dynamically select and install a TLS certificate based on the SNI hostname.
#[derive(Default)]
pub struct DynamicCertificate;

#[async_trait]
impl TlsAccept for DynamicCertificate {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        // 1. Extract the hostname from SNI
        let server_name = match ssl.servername(NameType::HOST_NAME) {
            Some(name) => name,
            None => {
                error!("[TLS] Missing SNI hostname");
                return;
            }
        };

        // 2. Load the TLS map and lookup the certificate for this host
        let Some(tls_map) = get_tls() else {
            error!("[TLS] Configuration not found");
            return;
        };
        let Some(cert) = tls_map.get(server_name) else {
            error!("[TLS] No certificate for {}", server_name);
            return;
        };

        // 3. Install leaf certificate and private key
        if let Err(e) = ext::ssl_use_certificate(ssl, &cert.cert) {
            error!("[TLS] Failed to set certificate for {}: {}", server_name, e);
        }
        if let Err(e) = ext::ssl_use_private_key(ssl, &cert.key) {
            error!("[TLS] Failed to set private key for {}: {}", server_name, e);
        }

        // 4. Append any chain certificates
        for chain_cert in &cert.chain {
            if let Err(e) = ext::ssl_add_chain_cert(ssl, chain_cert) {
                error!("[TLS] Failed to add chain cert for {}: {}", server_name, e);
            }
        }
    }
}
