//! GhostSim Network Engine executable.
//!
//! Initializes the networking core, configures operational logging,
//! validates basic startup configuration, and handles graceful shutdown.
//!
//! This entry point deliberately does not claim that peer discovery,
//! internet routing, or packet forwarding is operational. Those capabilities
//! require concrete transport and forwarding implementations.

use std::env;
use std::process::ExitCode;

use ghostsim_network_core::{
    ENGINE_NAME,
    MAX_CONTROL_MESSAGE_BYTES,
    MAX_ROUTE_HOPS,
    NETWORK_PROTOCOL_VERSION,
};

use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(message) = initialize_logging() {
        eprintln!("GhostSim startup error: {message}");
        return ExitCode::FAILURE;
    }

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error_message) => {
            error!("{error_message}");
            ExitCode::FAILURE
        }
    }
}

/// Initializes structured application logging.
fn initialize_logging() -> Result<(), String> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .try_init()
        .map_err(|error| error.to_string())
}

/// Initializes the executable and waits for a shutdown signal.
///
/// Network listeners are intentionally not started until concrete transport
/// implementations, authenticated peer handshakes, and forwarding policies
/// have been implemented.
async fn run() -> Result<(), String> {
    let arguments: Vec<String> = env::args().skip(1).collect();

    if arguments.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return Ok(());
    }

    if arguments.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!(
            "{} {}",
            ENGINE_NAME,
            env!("CARGO_PKG_VERSION")
        );

        return Ok(());
    }

    if arguments.iter().any(|arg| arg == "--check") {
        print_startup_report();
        return Ok(());
    }

    if !arguments.is_empty() {
        return Err(format!(
            "Unknown argument: {}. Run with --help for usage.",
            arguments[0]
        ));
    }

    print_startup_report();

    warn!(
        "Networking is not operational yet: concrete transports, \
         peer discovery, and forwarding are not implemented."
    );

    info!("Waiting for shutdown signal.");

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.map_err(|error| {
                format!("Failed to listen for shutdown signal: {error}")
            })?;

            info!("Shutdown signal received.");
        }
    }

    info!("GhostSim Network Engine stopped.");

    Ok(())
}

/// Displays the current core configuration without claiming that
/// actual network connectivity has been established.
fn print_startup_report() {
    println!();
    println!("==========================================");
    println!("         GHOSTSIM NETWORK CORE");
    println!("==========================================");
    println!("Engine:              {ENGINE_NAME}");
    println!("Version:             {}", env!("CARGO_PKG_VERSION"));
    println!("Protocol version:    {NETWORK_PROTOCOL_VERSION}");
    println!("Maximum route hops:  {MAX_ROUTE_HOPS}");
    println!(
        "Maximum control message: {MAX_CONTROL_MESSAGE_BYTES} bytes"
    );
    println!("Runtime:             Tokio");
    println!("Core initialization:  Available");
    println!("Peer discovery:       Not implemented");
    println!("Network transports:   Not implemented");
    println!("Internet forwarding:  Not implemented");
    println!("==========================================");
    println!();
}

/// Prints supported command-line arguments.
fn print_help() {
    println!("GhostSim Network Engine");
    println!();
    println!("Usage:");
    println!("  ghostsim-network [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --help, -h       Display this help message");
    println!("  --version, -V    Display engine version");
    println!("  --check          Display core initialization status and exit");
    println!();
    println!("Environment:");
    println!("  RUST_LOG         Configure logging verbosity");
    println!("                   Example: RUST_LOG=debug");
    println!();
}
