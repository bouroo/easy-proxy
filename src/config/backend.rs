use crate::{config::proxy::{Endpoint, Service}, errors::Errors};
use http::Extensions;
use pingora::{
    lb::{
        discovery::Static,
        selection::{
            algorithms::{Random, RoundRobin},
            consistent::KetamaHashing,
            weighted::Weighted,
        },
        Backend, Backends, LoadBalancer,
    },
    prelude::HttpPeer,
    protocols::l4::socket::SocketAddr,
};
use std::{collections::BTreeSet, sync::Arc};

pub async fn load_backend(
    svc: &Service,
    endpoints: &[Endpoint],
) -> Result<crate::config::proxy::BackendType, Errors> {
    // Build a set of raw Backends from endpoints
    let backends: BTreeSet<Backend> = endpoints
        .iter()
        .map(|e| {
            let ep = format!("{}:{}", e.ip, e.port);
            let addr: SocketAddr = ep
                .parse()
                .map_err(|e| Errors::ConfigError(format!("Invalid address {}: {}", ep, e)))?;
            let mut b = Backend {
                addr,
                weight: e.weight.unwrap_or(1) as usize,
                ext: Extensions::new(),
            };
            if b
                .ext
                .insert::<HttpPeer>(HttpPeer::new(ep.clone(), false, String::new()))
                .is_some()
            {
                return Err(Errors::ConfigError("HttpPeer insert failed".into()));
            }
            Ok(b)
        })
        .collect::<Result<_, _>>()?;

    // Initialize and update the selected load balancer
    let lb = match svc.algorithm.as_str() {
        "round_robin" => {
            let mut lb = LoadBalancer::<Weighted<RoundRobin>>::from_backends(Backends::new(Static::new(backends)));
            lb.update()
                .await
                .map_err(|e| Errors::PingoraError(e.to_string()))?;
            crate::config::proxy::BackendType::RoundRobin(Arc::new(lb))
        }
        "weighted" => {
            let mut lb = LoadBalancer::<Weighted<fnv::FnvHasher>>::from_backends(Backends::new(Static::new(backends)));
            lb.update()
                .await
                .map_err(|e| Errors::PingoraError(e.to_string()))?;
            crate::config::proxy::BackendType::Weighted(Arc::new(lb))
        }
        "consistent" => {
            let mut lb = LoadBalancer::<KetamaHashing>::from_backends(Backends::new(Static::new(backends)));
            lb.update()
                .await
                .map_err(|e| Errors::PingoraError(e.to_string()))?;
            crate::config::proxy::BackendType::Consistent(Arc::new(lb))
        }
        "random" => {
            let mut lb = LoadBalancer::<Weighted<Random>>::from_backends(Backends::new(Static::new(backends)));
            lb.update()
                .await
                .map_err(|e| Errors::PingoraError(e.to_string()))?;
            crate::config::proxy::BackendType::Random(Arc::new(lb))
        }
        other => {
            return Err(Errors::ConfigError(format!("Unknown algorithm: {}", other)));
        }
    };

    Ok(lb)
}
