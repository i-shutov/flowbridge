//! Explicit user-owned SOCKS5 + managed OpenSSH entrypoint.
//! Deliberately no NDISRD, packet ownership, WFP filters or system kill switch.
use flowbridge_core::{Action, Config, Endpoint, ProxyKind};
use flowbridge_runtime::Engine;
use flowbridge_tunnel::{Config as SshConfig, Supervisor};
use serde::Deserialize;
use std::{error::Error, path::Path, time::Duration};
use tokio::io::AsyncReadExt;

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
const MAX_BYTES: u64 = 1024 * 1024;
const CONSENT: &str = "RUST_MANAGED_SSH_SOCKS_CANDIDATE";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedProfile {
    consent: String,
    engine: Config,
    ssh: SshConfig,
}

async fn load(path: &Path) -> AppResult<ManagedProfile> {
    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes).await?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("managed profile exceeds 1 MiB".into());
    }
    let profile: ManagedProfile = serde_json::from_slice(&bytes)?;
    validate(&profile)?;
    Ok(profile)
}

fn validate(profile: &ManagedProfile) -> AppResult<()> {
    if profile.consent != CONSENT {
        return Err("managed OpenSSH requires exact explicit consent".into());
    }
    profile.engine.validate()?;
    profile.ssh.validate()?;
    if ![
        profile.ssh.ssh_executable.as_deref(),
        profile.ssh.identity_file.as_deref(),
        profile.ssh.known_hosts_file.as_deref(),
    ]
    .iter()
    .all(|path| path.is_some_and(|p| Path::new(p).is_absolute()))
    {
        return Err(
            "SSH executable, private key and pinned known_hosts must be absolute paths".into(),
        );
    }
    let engine = &profile.engine;
    let ssh = &profile.ssh;
    if engine.proxies.len() != 1
        || !engine.rules.is_empty()
        || !engine.chains.is_empty()
        || !engine.remote_dns_via_ssh
        || engine.max_connections > 128
        || engine.listen.port() == ssh.local_port
        || !matches!(
            &engine.default_action,
            Action::Proxy { id } if id == &engine.proxies[0].id
        )
        || !matches!(&engine.proxies[0].kind, ProxyKind::Socks5)
        || engine.proxies[0].endpoint.host != "127.0.0.1"
        || engine.proxies[0].endpoint.port != ssh.local_port
        || engine.proxies[0].username.is_some()
        || engine.proxies[0].password_env.is_some()
    {
        return Err(
            "managed beta permits one pinned SSH SOCKS5 hop, default PROXY, no DIRECT, app rules, chains or local target DNS, and at most 128 connections".into(),
        );
    }
    Ok(())
}

async fn supervise(engine: &Engine, ssh: &Supervisor, endpoint: &Endpoint) -> AppResult<()> {
    let mut ready = false;
    let mut poll = tokio::time::interval(Duration::from_millis(50));
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result?;
                return Ok(());
            }
            _ = poll.tick() => {
                let status = ssh.snapshot().status;
                let observed = status.state == "ready" && status.pid.is_some();
                if observed != ready {
                    engine.set_upstream_gate(Some(endpoint.clone()), observed, 0)?;
                    ready = observed;
                    eprintln!(
                        "flowbridge: managed SSH SOCKS upstream {}",
                        if ready { "ready" } else { "unavailable; new connects denied" }
                    );
                }
                if !engine.snapshot().status.running {
                    return Err("SOCKS listener stopped unexpectedly".into());
                }
            }
        }
    }
}

/// The client must explicitly configure SOCKS5 at the engine's loopback port.
/// Applications not using that proxy remain outside FlowBridge's control.
pub async fn serve(path: &Path) -> AppResult<()> {
    let profile = load(path).await?;
    let endpoint = Endpoint {
        host: "127.0.0.1".into(),
        port: profile.ssh.local_port,
    };
    let engine = Engine::new(profile.engine)?;
    let ssh = Supervisor::new(profile.ssh)?;

    // Never expose the listener while the upstream is implicitly open.
    engine.set_upstream_gate(Some(endpoint.clone()), false, 0)?;
    engine.start()?;
    if let Err(error) = ssh.start() {
        let _ = engine.stop();
        return Err(Box::new(error));
    }
    eprintln!("flowbridge: explicit SOCKS5/SSH candidate started; no transparent interception");
    let outcome = supervise(&engine, &ssh, &endpoint).await;
    // Always attempt every cleanup; a failed operation cannot skip stopping SSH.
    let close = engine.set_upstream_gate(Some(endpoint), false, 0);
    let engine_stop = engine.stop();
    let ssh_stop = ssh.stop();
    outcome?;
    close?;
    engine_stop?;
    ssh_stop?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowbridge_core::Proxy;

    fn fixture() -> ManagedProfile {
        let ssh_executable = if cfg!(windows) {
            r"C:\Windows\System32\OpenSSH\ssh.exe"
        } else {
            "/usr/bin/ssh"
        };
        let private_key = if cfg!(windows) {
            r"C:\Users\Public\test_key"
        } else {
            "/tmp/test_key"
        };
        let known_hosts = if cfg!(windows) {
            r"C:\Users\Public\known_hosts"
        } else {
            "/tmp/known_hosts"
        };
        ManagedProfile {
            consent: CONSENT.into(),
            engine: Config {
                version: 1,
                listen: "127.0.0.1:1099".parse().unwrap(),
                proxies: vec![Proxy {
                    id: "managed".into(),
                    kind: ProxyKind::Socks5,
                    endpoint: Endpoint {
                        host: "127.0.0.1".into(),
                        port: 1080,
                    },
                    username: None,
                    password_env: None,
                }],
                chains: vec![],
                rules: vec![],
                default_action: Action::Proxy {
                    id: "managed".into(),
                },
                connect_timeout_ms: 3000,
                handshake_timeout_ms: 3000,
                idle_timeout_ms: 5000,
                max_connections: 16,
                remote_dns_via_ssh: true,
            },
            ssh: SshConfig {
                host: "example.com".into(),
                user: "example".into(),
                ssh_executable: Some(ssh_executable.into()),
                identity_file: Some(private_key.into()),
                known_hosts_file: Some(known_hosts.into()),
                ..SshConfig::default()
            },
        }
    }

    #[test]
    fn explicit_managed_profile_requires_one_pinned_proxy() {
        let mut profile = fixture();
        assert!(validate(&profile).is_ok());
        profile.engine.default_action = Action::Direct;
        assert!(validate(&profile).is_err());
        profile.engine.default_action = Action::Proxy {
            id: "managed".into(),
        };
        profile.engine.remote_dns_via_ssh = false;
        assert!(validate(&profile).is_err());
        profile.engine.remote_dns_via_ssh = true;
        profile.engine.proxies[0].endpoint.port = 1081;
        assert!(validate(&profile).is_err());
    }

    #[test]
    fn explicit_managed_profile_rejects_implicit_identity_and_credentials() {
        let mut profile = fixture();
        profile.ssh.identity_file = None;
        assert!(validate(&profile).is_err());
        profile.ssh.identity_file = fixture().ssh.identity_file;
        profile.engine.proxies[0].username = Some("implicit".into());
        assert!(validate(&profile).is_err());
        profile.engine.proxies[0].username = None;
        profile.consent = "AUTOMATIC".into();
        assert!(validate(&profile).is_err());
    }
}
