#[cfg(not(debug_assertions))]
use mimalloc::MiMalloc;
#[cfg(not(debug_assertions))]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod acme;
mod commands;
mod config;
mod errors;
mod proxy;
mod utils;

use clap::Parser;
use commands::Commands;
use std::{process, thread};
use tokio::runtime::Builder;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Validate your configuration thoroughly.
    #[arg(short, long)]
    test: bool,

    /// Reload the configuration.
    #[arg(short, long)]
    reload: bool,
}

fn main() {
    // Initialize logging
    tracing_subscriber::fmt().init();

    // Parse CLI flags
    let args = Args::parse();
    if args.test {
        Commands::send_command("test");
        process::exit(0);
    }
    if args.reload {
        Commands::send_command("reload");
        process::exit(0);
    }

    // Initialize runtime configuration
    if let Err(e) = config::runtime::initialize() {
        tracing::error!("Failed to initialize config: {:?}", e);
        process::exit(1);
    }
    tracing::info!("Configuration initialized");

    // Load proxy configuration on a single-threaded Tokio runtime
    let rt = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime");
    rt.block_on(async {
        if let Err(e) = config::proxy::load().await {
            tracing::error!("Failed to load proxy config: {:?}", e);
            process::exit(1);
        }
        tracing::info!("Proxy configuration loaded");
    });

    // Spawn the commands listener
    thread::Builder::new()
        .name("cmd-listener".into())
        .spawn(|| Commands::run())
        .expect("Failed to spawn command listener");

    // Start proxy server (blocking)
    proxy::EasyProxy::new_proxy()
        .expect("Failed to create proxy server")
        .run_forever();
}
