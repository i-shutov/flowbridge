//! User-mode development entry point. This binary does not intercept OS traffic.
use clap::{Parser, Subcommand};
use flowbridge_core::{Action, Config, Endpoint, Flow};
use flowbridge_net::connect_route_guarded;
use flowbridge_runtime::Engine;
use serde_json::json;
use std::{error::Error, net::IpAddr, path::Path, path::PathBuf, time::Duration};
use tokio::io::AsyncReadExt;
use tracing::info;

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "flowbridge",
    version,
    about = "Native proxy core — explicit SOCKS mode, policy tools, and diagnostics"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a profile without opening sockets or changing system settings.
    Validate {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Explain a hypothetical connection. Application is supplied evidence, not OS attestation.
    Explain {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long)]
        application: Option<String>,
        #[arg(long)]
        resolved_ip: Option<IpAddr>,
    },
    /// Run a loopback SOCKS5 TCP listener. Applications must explicitly use this listener.
    Serve {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        json_logs: bool,
    },
    /// Open and close one connection using the selected route (no application payload).
    Check {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
    },
    /// Explicit, non-authenticating, direct SSH identification-order A/B diagnostic.
    SshDiagnose {
        #[arg(long)]
        endpoint: std::net::SocketAddr,
        #[arg(long, default_value_t = 2000)]
        timeout_ms: u64,
        #[arg(long)]
        consent: String,
    },
    /// Report actual available features. Does not claim OS interception is active.
    Capabilities,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("flowbridge: {error}");
        std::process::exit(1);
    }
}

async fn run() -> AppResult<()> {
    match Cli::parse().command {
        Command::Validate { config } => {
            let profile = load_config(&config).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true, "version": profile.version, "rules": profile.rules.len(),
                    "proxies": profile.proxies.len(), "chains": profile.chains.len(),
                    "explicit_socks_compatible": explicit_compatible(&profile),
                }))?
            );
        }
        Command::Explain {
            config,
            host,
            port,
            application,
            resolved_ip,
        } => {
            let profile = load_config(&config).await?;
            let destination = Endpoint { host, port };
            destination.validate()?;
            let flow = Flow {
                application,
                destination,
                resolved_ip,
            };
            let decision = profile.evaluate(&flow);
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "flow": flow, "decision": decision,
                    "note": "Hypothetical policy evaluation; supplied application is not an authenticated process identity. No DNS queries performed."
                }))?
            );
        }
        Command::Serve { config, json_logs } => {
            if json_logs {
                tracing_subscriber::fmt()
                    .json()
                    .with_writer(std::io::stderr)
                    .with_env_filter("info")
                    .init();
            } else {
                tracing_subscriber::fmt()
                    .with_writer(std::io::stderr)
                    .with_env_filter("info")
                    .init();
            }
            let profile = load_config(&config).await?;
            require_explicit_compatible(&profile)?;
            serve(profile).await?;
        }
        Command::Check { config, host, port } => {
            let profile = load_config(&config).await?;
            require_explicit_compatible(&profile)?;
            let destination = Endpoint { host, port };
            destination.validate()?;
            let decision = profile.evaluate(&Flow {
                application: None,
                destination: destination.clone(),
                resolved_ip: None,
            });
            if matches!(decision.action, Action::Block) {
                return Err("connection blocked by policy".into());
            }
            let route = profile.route(&decision.action)?;
            let started = std::time::Instant::now();
            let stream = connect_route_guarded(
                &destination,
                &route,
                Duration::from_millis(profile.connect_timeout_ms),
                Duration::from_millis(profile.handshake_timeout_ms),
                profile.listen,
            )
            .await?;
            drop(stream);
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true, "elapsed_ms": started.elapsed().as_millis(), "decision": decision,
                    "proxy_hops": route.len(), "payload_sent": false
                }))?
            );
        }
        Command::SshDiagnose { endpoint, timeout_ms, consent } => {
            if consent != "DIRECT_SSH_DIAGNOSTIC" {
                return Err("ssh-diagnose requires --consent DIRECT_SSH_DIAGNOSTIC".into());
            }
            if !(100..=10000).contains(&timeout_ms) || endpoint.port() == 0 {
                return Err("SSH probe timeout must be 100..=10000 ms with a nonzero port".into());
            }
            let report = flowbridge_tunnel::handshake_diagnostic::compare_direct(
                endpoint, Duration::from_millis(timeout_ms)
            );
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Capabilities => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "version": env!("CARGO_PKG_VERSION"), "mode": "explicit_loopback_socks5",
                    "tcp": true, "upstream_protocols": ["socks5", "socks4a", "http_connect"],
                    "proxy_chains": true, "remote_target_dns_when_hostname_supplied": true,
                    "policy_explanation": true, "transparent_interception": false,
                    "authenticated_process_identity_in_socks_mode": false,
                    "udp": false, "quic": false, "tls_to_proxy": false,
                    "system_dns_interception": false, "system_kill_switch": false,
                    "native_ui": "engine_control_and_live_connections",
                    "hot_reload": true, "bounded_live_metrics": true,
                }))?
            );
        }
    }
    Ok(())
}

async fn load_config(path: &Path) -> AppResult<Config> {
    // Bound reads even if a file grows after metadata inspection.
    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err("configuration exceeds 1 MiB".into());
    }
    Ok(Config::from_json(std::str::from_utf8(&bytes)?)?)
}

fn explicit_compatible(profile: &Config) -> bool {
    !profile
        .rules
        .iter()
        .any(|r| r.enabled && !r.applications.is_empty())
}

fn require_explicit_compatible(profile: &Config) -> AppResult<()> {
    if !explicit_compatible(profile) {
        return Err("explicit SOCKS mode cannot authenticate the originating application; enabled application-specific rules require a native capture backend. Use `explain` to test such profiles, or remove those criteria before `serve`/`check`".into());
    }
    Ok(())
}

async fn serve(profile: Config) -> AppResult<()> {
    let engine = Engine::new(profile)?;
    let status = engine.start()?;
    info!(listen = %status.listen, transparent_interception = false, "SOCKS5 TCP listener ready; caller process identity unavailable");
    let mut last_event = 0;
    let mut poll = tokio::time::interval(Duration::from_millis(250));
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            result = &mut shutdown => { result?; break; }
            _ = poll.tick() => {
                let snapshot = engine.snapshot();
                for event in snapshot.events.iter().filter(|event| event.seq > last_event) {
                    info!(sequence = event.seq, level = %event.level, "{}", event.message);
                }
                if let Some(event) = snapshot.events.last() { last_event = event.seq; }
                if !snapshot.status.running { return Err("engine listener stopped unexpectedly".into()); }
            }
        }
    }
    let status = engine.stop()?;
    info!(
        accepted = status.accepted,
        completed = status.completed,
        failed = status.failed,
        uploaded = status.bytes_up,
        downloaded = status.bytes_down,
        "stopped; active connections cancelled"
    );
    Ok(())
}
