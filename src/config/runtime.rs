use crate::errors::Errors;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::File,
    io::BufReader,
    path::PathBuf,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuntimeConfig {
    pub proxy: Proxy,
    pub pingora: Pingora,
    pub config_dir: String,
    pub acme_store: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Proxy {
    pub http: String,
    pub https: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Pingora {
    pub daemon: Option<bool>,
    pub threads: Option<usize>,
    pub work_stealing: Option<bool>,           // default: true
    pub error_log: Option<String>,
    pub pid_file: Option<String>,              // default: "/tmp/pingora.pid"
    pub upgrade_sock: Option<String>,          // default: "/tmp/pingora_upgrade.sock"
    pub user: Option<String>,
    pub group: Option<String>,
    pub ca_file: Option<String>,
    pub upstream_keepalive_pool_size: Option<usize>,
    pub grace_period_seconds: Option<u64>,
    pub graceful_shutdown_timeout_seconds: Option<u64>,
}

// Global holder for RuntimeConfig
static GLOBAL_RUNTIME_CONFIG: OnceCell<RuntimeConfig> = OnceCell::new();

/// Determine the config file path from `$EASY_PROXY_CONF` or fall back to `/etc/easy-proxy/conf.yaml`.
fn config_path() -> PathBuf {
    env::var_os("EASY_PROXY_CONF")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/etc/easy-proxy/conf.yaml".into())
}

/// Load and store the global runtime configuration.
pub fn initialize() -> Result<(), Errors> {
    let path = config_path();
    let file = File::open(&path).map_err(|e| {
        Errors::ConfigError(format!("Unable to open {:?}: {}", path, e))
    })?;
    let reader = BufReader::new(file);
    let cfg: RuntimeConfig = serde_yaml::from_reader(reader).map_err(|e| {
        Errors::ConfigError(format!("Failed to parse {:?}: {}", path, e))
    })?;
    GLOBAL_RUNTIME_CONFIG
        .set(cfg)
        .map_err(|_| Errors::ConfigError("Config already initialized".into()))
}

/// Fetch the initialized global configuration (panics if uninitialized).
pub fn config() -> &'static RuntimeConfig {
    GLOBAL_RUNTIME_CONFIG
        .get()
        .expect("Configuration not initialized")
}
