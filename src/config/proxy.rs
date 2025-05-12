use crate::{config::runtime, errors::Errors};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use super::store;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub header_selector: Option<String>,
    pub routes: Option<Vec<Route>>,
    pub services: Option<Vec<Service>>,
    pub tls: Option<Vec<Tls>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Tls {
    pub name: String,
    pub redirect: Option<bool>,
    #[serde(rename = "type")]
    pub tls_type: String,
    pub acme: Option<Acme>,
    pub key: Option<String>,
    pub cert: Option<String>,
    pub chain: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Acme {
    pub email: String,
    pub provider: Option<AcmeProvider>, // default: letsencrypt
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum AcmeProvider {
    #[serde(rename = "letsencrypt")]
    LetsEncrypt,
    #[serde(rename = "buypass")]
    Buypass,
}

impl std::fmt::Display for AcmeProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AcmeProvider::LetsEncrypt => write!(f, "letsencrypt"),
            AcmeProvider::Buypass => write!(f, "buypass"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub algorithm: String,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: String,
    pub port: u16,
    #[serde(default)]
    pub weight: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Route {
    pub route: RouteCondition,
    pub tls: Option<TlsRoute>,
    pub name: String,
    #[serde(default)]
    pub remove_headers: Option<Vec<String>>,
    #[serde(default)]
    pub add_headers: Option<Vec<Header>>,
    #[serde(default)]
    pub paths: Option<Vec<Path>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TlsRoute {
    pub name: String,
    #[serde(default)]
    pub redirect: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RouteCondition {
    #[serde(rename = "type")]
    pub condition_type: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Path {
    #[serde(rename = "pathType")]
    pub path_type: String,
    pub path: String,
    pub service: ServiceReference,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceReference {
    pub name: String,
    #[serde(default)]
    pub rewrite: Option<String>,
}

/// Recursively list all files under `dir` up to `max_depth`.
fn read_dir_recursive(dir: &Path, max_depth: usize) -> Result<Vec<PathBuf>, Errors> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| {
        Errors::ConfigError(format!("Failed to read directory {}: {}", dir.display(), e))
    })? {
        let entry = entry.map_err(|e| {
            Errors::ConfigError(format!("Failed to access entry in {}: {}", dir.display(), e))
        })?;
        let path = entry.path();
        if path.is_dir() && max_depth > 0 {
            files.extend(read_dir_recursive(&path, max_depth - 1)?);
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(files)
}

/// Load all proxy configs from files under `config_dir`.
pub async fn read() -> Result<Vec<ProxyConfig>, Errors> {
    let conf = runtime::config();
    let config_dir = Path::new(&conf.config_dir);
    let files = read_dir_recursive(config_dir, 6)?;
    let mut configs = Vec::with_capacity(files.len());
    for path in files {
        let file = File::open(&path).map_err(|e| {
            Errors::ConfigError(format!("Failed to open {}: {}", path.display(), e))
        })?;
        let cfg: ProxyConfig =
            serde_yaml::from_reader(BufReader::new(file)).map_err(|e| {
                Errors::ConfigError(format!("Failed to parse {}: {}", path.display(), e))
            })?;
        configs.push(cfg);
    }
    Ok(configs)
}

/// Read and store the merged proxy configuration.
pub async fn load() -> Result<(), Errors> {
    let configs = read().await?;
    let merged = store::load(configs).await?;
    store::set(merged);
    Ok(())
}