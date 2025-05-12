use pingora::lb::Backend;
use std::collections::HashMap;

const BACKEND_ADDR: &str = "127.0.0.1:80";

/// Holds a load-balancer backend and template variables.
#[derive(Debug)]
pub struct Context {
    pub backend: Backend,
    pub variables: HashMap<String, String>,
}

impl Context {
    /// Initialize with the default backend address and an empty variable map.
    pub fn new() -> Self {
        let backend = Backend::new(BACKEND_ADDR)
            .unwrap_or_else(|e| panic!("Unable to create backend at {}: {}", BACKEND_ADDR, e));
        Self {
            backend,
            variables: HashMap::new(),
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}
