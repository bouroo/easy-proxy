use crate::{errors::Errors, utils};
use openssl::{pkey::PKey, x509::X509};
use std::collections::HashMap;
use std::fs;
use super::store::{AcmeStore, TlsGlobalConfig, TlsType};

/// Load or queue a TLS certificate for `host` based on `tls` config.
/// Returns `Ok(Some(cfg))` if ready, `Ok(None)` if queued for ACME, or `Err` on config errors.
pub fn load_cert(
    acme_store: &AcmeStore,
    tls: &Tls,
    host: &str,
    acme_requests: &mut HashMap<String, Vec<String>>,
) -> Result<Option<TlsGlobalConfig>, Errors> {
    // parse and validate TLS type
    let tls_type = TlsType::from_str(&tls.tls_type)
        .ok_or_else(|| Errors::ConfigError(format!("Invalid tls type: {}", tls.tls_type)))?;
    // validate the tls.name: alphanumeric or '-'
    if !tls.name.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(Errors::ConfigError(
            "Invalid tls name; must be alphanumeric or '-'".into(),
        ));
    }

    // helper to queue this host for a future ACME request
    let mut queue = |name: &str| {
        acme_requests.entry(name.to_string()).or_default().push(host.to_string());
    };

    match tls_type {
        TlsType::Custom => {
            // read and parse custom PEM cert, key, and optional chain
            let cert_pem = fs::read(
                tls.cert
                    .as_ref()
                    .ok_or_else(|| Errors::ConfigError("Custom tls requires a cert file".into()))?,
            )
            .map_err(|e| Errors::ConfigError(format!("Unable to read cert file: {}", e)))?;
            let key_pem = fs::read(
                tls.key
                    .as_ref()
                    .ok_or_else(|| Errors::ConfigError("Custom tls requires a key file".into()))?,
            )
            .map_err(|e| Errors::ConfigError(format!("Unable to read key file: {}", e)))?;
            let chain_pems = match &tls.chain {
                Some(paths) => paths
                    .iter()
                    .map(|p| {
                        fs::read(p)
                            .map_err(|e| Errors::ConfigError(format!("Unable to read chain file {}: {}", p, e)))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                None => Vec::new(),
            };
            let chain = chain_pems
                .into_iter()
                .map(|pem| X509::from_pem(&pem).map_err(|e| Errors::ConfigError(format!("Unable to parse chain: {}", e))))
                .collect::<Result<_, _>>()?;
            let cert = X509::from_pem(&cert_pem)
                .map_err(|e| Errors::ConfigError(format!("Unable to parse cert file: {}", e)))?;
            let key = PKey::private_key_from_pem(&key_pem)
                .map_err(|e| Errors::ConfigError(format!("Unable to parse key file: {}", e)))?;
            return Ok(Some(TlsGlobalConfig { cert, key, chain }));
        }
        TlsType::Acme => {
            // ensure ACME config exists
            tls.acme
                .as_ref()
                .ok_or_else(|| Errors::ConfigError("Acme tls requires an acme config".into()))?;
            // lookup or queue order ID
            let order_id = match acme_store.hostnames.get(host) {
                Some(id) => id,
                None => {
                    queue(&tls.name);
                    return Ok(None);
                }
            };
            // lookup or queue valid cert data
            let data = match acme_store.acme_certs.get(order_id) {
                Some(d) => d,
                None => {
                    queue(&tls.name);
                    return Ok(None);
                }
            };
            let cert = X509::from_pem(&data.cert)
                .map_err(|e| Errors::ConfigError(format!("Unable to parse cert file: {}", e)))?;
            let key = PKey::private_key_from_der(&data.key_der)
                .map_err(|e| Errors::ConfigError(format!("Unable to parse key file: {}", e)))?;
            let chain = data
                .chain
                .iter()
                .map(|pem| X509::from_pem(pem).map_err(|e| Errors::ConfigError(format!("Unable to parse chain file: {}", e))))
                .collect::<Result<_, _>>()?;
            // if cert expires within 5 days, queue renewal
            let expiry = utils::asn1_time_to_unix_time(cert.not_after())
                .map_err(|e| Errors::AcmeClientError(format!("Unable to parse cert expiry: {}", e)))?
                - 432_000;
            let now = chrono::Utc::now().timestamp() as i128;
            if expiry < now {
                tracing::info!("Renewing cert for {}", host);
                queue(&tls.name);
            }
            return Ok(Some(TlsGlobalConfig { cert, key, chain }));
        }
        _ => {}
    }

    Ok(None)
}
