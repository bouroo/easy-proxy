use crate::{acme::client::AcmeClient, acme::crypto::AcmeKeyPair, config::runtime, errors::Errors, utils};
use http::Extensions;
use openssl::{pkey::PKey, x509::X509};
use once_cell::sync::{Lazy, OnceCell};
use pingora::{
    lb::{LoadBalancer, discovery::Static, Backends},
    prelude::HttpPeer,
    protocols::l4::socket::SocketAddr,
    tls::pkey::PKey as _,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use super::{
    backend::load_backend, certs::load_cert, proxy::{
        Header, Path, ProxyConfig, ServiceReference, Tls, TlsRoute,
    }, store::{TlsGlobalConfig, BackendType},
};

/// Global proxy and TLS storage
static PROXY_STORE: OnceCell<ProxyStore> = OnceCell::new();
static TLS_CONFIG: OnceCell<HashMap<String, TlsGlobalConfig>> = OnceCell::new();

/// ACME globals
static ACME_REQUEST_QUEUE: Lazy<Mutex<HashMap<String, (Acme, Vec<String>)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static ACME_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
static ACME_RETRY_COUNT: Lazy<Mutex<HashMap<String, u8>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static ACME_AUTHZ: Lazy<Mutex<HashMap<String, String>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static ACME_PROVIDERS: Lazy<HashMap<AcmeProvider, String>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(AcmeProvider::LetsEncrypt, "https://acme-v02.api.letsencrypt.org/directory".into());
    m.insert(AcmeProvider::Buypass, "https://api.buypass.com/acme/directory".into());
    m
});

#[derive(Debug, Clone)]
pub struct TlsGlobalConfig {
    pub cert: X509,
    pub key: PKey<openssl::pkey::Private>,
    pub chain: Vec<X509>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AcmeStore {
    pub hostnames: HashMap<String, String>,
    pub account: HashMap<String, (String, AcmeAccount)>,
    pub acme_certs: HashMap<String, AcmeCertificate>,
    pub acme_expires: HashMap<String, (String, i128)>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AcmeCertificate {
    pub account_kid: String,
    pub key_der: Vec<u8>,
    pub cert: Vec<u8>,
    pub csr: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AcmeAccount {
    pub kid: String,
    pub key_pair: Vec<u8>,
}

#[derive(Clone)]
pub struct HttpService {
    pub name: String,
    pub backend_type: BackendType,
}

#[derive(Debug, Clone)]
pub struct Route {
    pub path: Path,
    pub service: ServiceReference,
    pub remove_headers: Option<Vec<String>>,
    pub add_headers: Option<Vec<Header>>,
    pub tls: Option<TlsRoute>,
}

#[derive(Debug, Clone)]
pub struct ProxyStore {
    pub header_selector: String,
    pub http_services: HashMap<String, HttpService>,
    pub host_routes: HashMap<String, matchit::Router<Route>>,
    pub header_routes: HashMap<String, matchit::Router<Route>>,
}

pub fn acme_store() -> Result<AcmeStore, Errors> {
    let path = runtime::config()
        .acme_store
        .clone()
        .unwrap_or_else(|| "/etc/easy-proxy/tls/acme.json".into());
    match fs::read(&path) {
        Ok(data) => serde_json::from_slice(&data)
            .map_err(|e| Errors::ConfigError(format!("Parse acme store: {}", e))),
        Err(_) => {
            let s = AcmeStore {
                hostnames: Default::default(),
                account: Default::default(),
                acme_certs: Default::default(),
                acme_expires: Default::default(),
            };
            s.save()?;
            Ok(s)
        }
    }
}

impl AcmeStore {
    pub fn save(&self) -> Result<(), Errors> {
        let path = runtime::config()
            .acme_store
            .clone()
            .unwrap_or_else(|| "/etc/easy-proxy/tls/acme.json".into());
        let json = serde_json::to_string(self)
            .map_err(|e| Errors::ConfigError(format!("Serialize acme store: {}", e)))?;
        fs::write(&path, json).map_err(|e| Errors::ConfigError(format!("Save acme store: {}", e)))
    }
}

pub async fn load(configs: Vec<ProxyConfig>) -> Result<(ProxyStore, HashMap<String, TlsGlobalConfig>), Errors> {
    let acme = acme_store()?;
    let mut store = ProxyStore {
        header_selector: String::new(),
        http_services: Default::default(),
        host_routes: Default::default(),
        header_routes: Default::default(),
    };
    let mut tls_confs = HashMap::new();
    let mut acme_reqs = Vec::new();

    // services
    for cfg in &configs {
        for svc in cfg.services.iter().flatten() {
            let be = load_backend(svc, &svc.endpoints).await?;
            store.http_services.insert(svc.name.clone(), HttpService { name: svc.name.clone(), backend_type: be });
        }
    }

    // tls configs
    let tls_list: Vec<Tls> = configs.iter().filter_map(|c| c.tls.clone()).flatten().collect();
    let mut acme_queue: HashMap<String, Vec<String>> = HashMap::new();
    for cfg in &configs {
        if store.header_selector.is_empty() {
            if let Some(hs) = &cfg.header_selector {
                store.header_selector = hs.clone();
            }
        }
        for r in cfg.routes.iter().flatten() {
            let mut router = matchit::Router::new();
            for p in r.paths.iter().flatten() {
                let rt = Route { path: p.clone(), service: p.service.clone(), remove_headers: r.remove_headers.clone(), add_headers: r.add_headers.clone(), tls: r.tls.clone() };
                router.insert(&p.path, rt.clone())
                    .map_err(|e| Errors::ConfigError(format!("Route insert: {}", e)))?;
                if p.path_type == "Prefix" {
                    let mp = if &p.path == "/" { "/{*p}" } else { &format!("{}/{{*p}}", p.path) };
                    router.insert(mp, rt).map_err(|e| Errors::ConfigError(format!("Route insert: {}", e)))?;
                }
            }
            if r.route.condition_type == "host" {
                for host in r.route.value.split('|') {
                    if let Some(tr) = &r.tls {
                        if let Some(t) = tls_list.iter().find(|t| t.name == tr.name) {
                            if let Some(conf) = load_cert(&acme, t, host.split(':').next().unwrap_or(host), &mut acme_queue)? {
                                tls_confs.insert(host.to_string(), conf);
                            }
                        }
                    }
                    store.host_routes.insert(host.to_string(), router.clone());
                }
            } else {
                store.header_routes.insert(r.route.value.clone(), router);
            }
        }
    }
    if store.header_selector.is_empty() {
        store.header_selector = "x-easy-proxy-svc".into();
    }
    // queue acme
    for (name, domains) in acme_queue {
        if let Some(t) = tls_list.iter().find(|t| t.name == name) {
            ACME_REQUEST_QUEUE.lock().unwrap().insert(name.clone(), (t.clone(), domains.clone()));
        }
    }

    PROXY_STORE.set(store.clone()).ok();
    TLS_CONFIG.set(tls_confs.clone()).ok();
    Ok((store, tls_confs))
}

pub fn get() -> Option<&'static ProxyStore> {
    PROXY_STORE.get()
}

pub fn get_tls() -> Option<&'static HashMap<String, TlsGlobalConfig>> {
    TLS_CONFIG.get()
}

pub async fn acme_request_queue() {
    if ACME_IN_PROGRESS.compare_and_swap(false, true, Ordering::SeqCst) { return; }
    let mut q = ACME_REQUEST_QUEUE.lock().unwrap();
    for (name, (acme, domains)) in q.clone() {
        match acme_request(&name, &acme, &domains).await {
            Ok(_) => tracing::info!("ACME cert generated: {}", name),
            Err(e) => {
                tracing::error!("ACME error {}: {:?}", name, e);
                let mut rc = ACME_RETRY_COUNT.lock().unwrap();
                let cnt = rc.entry(name.clone()).and_modify(|c| *c += 1).or_insert(1);
                if *cnt <= 2 {
                    let name2 = name.clone();
                    let acme2 = acme.clone();
                    let dom2 = domains.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_secs(60));
                        set_acme_request(name2, acme2, dom2);
                    });
                } else {
                    tracing::error!("Max retries for {}", name);
                }
            }
        }
        q.remove(&name);
    }
    ACME_IN_PROGRESS.store(false, Ordering::SeqCst);
}

pub fn set_acme_request(name: String, acme: Acme, domains: Vec<String>) {
    let mut q = ACME_REQUEST_QUEUE.lock().unwrap();
    q.entry(name).or_default().1.extend(domains);
}

pub fn remove_acme_request(name: &str) {
    ACME_REQUEST_QUEUE.lock().unwrap().remove(name);
}

pub fn acme_set_authz(domain: &str, authz: &str) {
    ACME_AUTHZ.lock().unwrap().insert(domain.to_string(), authz.to_string());
}

pub fn acme_get_authz(domain: &str) -> Option<String> {
    ACME_AUTHZ.lock().unwrap().get(domain).cloned()
}

pub async fn acme_request(tls_name: &str, acme: &Acme, domains: &[String]) -> Result<(), Errors> {
    let mut store = acme_store()?;
    let provider = acme.provider.clone().unwrap_or(AcmeProvider::LetsEncrypt);
    let url = ACME_PROVIDERS.get(&provider).ok_or_else(|| Errors::AcmeClientError("No provider".into()))?;
    let client = AcmeClient::new(url).await?;
    let email = &acme.email;
    let (kid, key_bytes) = match store.account.get(email).filter(|(p,_)| *p == provider.to_string()) {
        Some((_, acc)) => (acc.kid.clone(), acc.key_pair.clone()),
        None => {
            let kp = AcmeKeyPair::generate()?;
            let kid = client.create_account(&kp, &[email]).await?;
            store.account.insert(email.clone(), (provider.to_string(), AcmeAccount { kid: kid.clone(), key_pair: kp.pkcs8_bytes.clone() }));
            store.save()?;
            (kid, kp.pkcs8_bytes)
        }
    };
    let kp = AcmeKeyPair::from_pkcs8(&key_bytes)?;
    let doms: Vec<&str> = domains.iter().map(|d| d.as_str()).collect();
    let (order_url, order) = client.create_order(&kp, &kid, &doms).await?;
    let authz_url = order["authorizations"][0].as_str().ok_or(Errors::AcmeClientError("No authz".into()))?;
    let (_url, _tok, key_auth) = client.get_http_challenge(&kp, &kid, authz_url).await?;
    for d in &doms { acme_set_authz(d, &key_auth); }
    client.validate_challenge(&kp, &kid, _url).await?;
    let (csr, pk) = client.create_csr(&doms)?;
    let finalize = order["finalize"].as_str().ok_or(Errors::AcmeClientError("No finalize".into()))?;
    client.finalize_order(&kp, &kid, finalize, &csr).await?;
    let valid = client.wait_for_order_valid(&kp, &kid, &order_url).await?;
    let cert_url = valid["certificate"].as_str().ok_or(Errors::AcmeClientError("No cert URL".into()))?;
    let pem = client.download_certificate(&kp, &kid, cert_url).await?;
    let parts: Vec<&[u8]> = pem.split("-----BEGIN CERTIFICATE-----").filter(|s| !s.is_empty()).map(|s| format!("-----BEGIN CERTIFICATE-----{}", s).as_bytes()).collect();
    if parts.len() < 2 { return Err(Errors::AcmeClientError("Invalid PEM".into())); }
    let cert = X509::from_pem(parts[0]).map_err(|_| Errors::AcmeClientError("Parse cert".into()))?;
    let expiry = utils::asn1_time_to_unix_time(cert.not_after()).map_err(|e| Errors::AcmeClientError(format!("{}", e)))?;
    store.acme_expires.insert(order_url.split('/').last().unwrap().into(), (tls_name.into(), expiry));
    let chain = parts[1..].iter().map(|pem| X509::from_pem(pem).map_err(|_| Errors::AcmeClientError("Parse chain".into()))).collect::<Result<Vec<_>, _>>()?;
    store.acme_certs.insert(order_url.clone(), AcmeCertificate { account_kid: kid.clone(), key_der: pk.clone(), cert: cert.to_pem().unwrap(), csr: csr.clone(), chain: chain.iter().map(|c| c.to_pem().unwrap()).collect() });
    for d in &domains { store.hostnames.insert(d.clone(), order_url.clone()); }
    store.save()?;
    // update global TLS_CONFIG
    if let Some(mut cfgs) = TLS_CONFIG.get().cloned() {
        let key = PKey::private_key_from_der(&pk).map_err(|e| Errors::ConfigError(format!("{}", e)))?;
        let conf = TlsGlobalConfig { cert: cert.clone(), key, chain: chain.clone() };
        for d in domains { cfgs.insert(d.clone(), conf.clone()); }
        TLS_CONFIG.set(cfgs).ok();
    }
    Ok(())
}

pub async fn acme_renew() -> Result<(), Errors> {
    let store = acme_store()?;
    let now = chrono::Utc::now().timestamp() as i128;
    if store.acme_expires.values().any(|(_, exp)| exp - 432_000 < now) {
        if let Ok((ps, tls)) = load(super::proxy::read().await?).await {
            PROXY_STORE.set(ps).ok();
            TLS_CONFIG.set(tls).ok();
        }
    }
    Ok(())
}
