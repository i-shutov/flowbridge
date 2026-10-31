//! Explicit loopback-only integration probe for the real Rust SOCKS relay.
//! It does not attest packet ownership, open NDISRD, or claim DNS containment.

use crate::relay::RelayPool;
use flowbridge_core::Endpoint;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    pub upstream: SocketAddr,
    pub target: SocketAddr,
    pub consent: String,
}

fn validate(request: &ProbeRequest) -> Result<(), String> {
    if request.consent != "LOOPBACK_TCP_PROBE"
        || !request.upstream.ip().is_loopback()
        || !request.target.ip().is_loopback()
        || request.upstream.port() == 0
        || request.target.port() == 0
    {
        return Err("Probe requires explicit consent and two nonzero loopback endpoints".into());
    }
    Ok(())
}

pub fn run(request: ProbeRequest) -> Result<Value, String> {
    validate(&request)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), probe(request))
            .await
            .map_err(|_| "Overall relay probe deadline expired".to_owned())?
    })
}

async fn probe(request: ProbeRequest) -> Result<Value, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let ingress = listener.local_addr().map_err(|e| e.to_string())?;
    let deadline = Duration::from_secs(3);
    let pool = RelayPool::new(request.upstream, ingress, 1, deadline, deadline, deadline)
        .map_err(|e| format!("{e:?}"))?;
    let (supervisor, stop) = watch::channel(false);
    let target = Endpoint {
        host: request.target.ip().to_string(),
        port: request.target.port(),
    };
    let upstream = pool
        .connect(&target, stop)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let mut client = TcpStream::connect(ingress)
        .await
        .map_err(|e| e.to_string())?;
    let (accepted, _) = listener.accept().await.map_err(|e| e.to_string())?;

    let payload: Vec<u8> = (0u8..=255).cycle().take(4097).collect();
    let expected = payload.len() as u64;
    let transfer = async {
        client.write_all(&payload).await.map_err(|e| e.to_string())?;
        client.shutdown().await.map_err(|e| e.to_string())?;
        let mut returned = Vec::new();
        (&mut client)
            .take(expected + 1)
            .read_to_end(&mut returned)
            .await
            .map_err(|e| e.to_string())?;
        if returned != payload {
            return Err("Binary echo differs or includes excess bytes".to_owned());
        }
        Ok::<(), String>(())
    };
    let forwarding = async { upstream.forward(accepted).await.map_err(|e| format!("{e:?}")) };
    let (bytes, ()) = tokio::try_join!(forwarding, transfer)?;
    drop(supervisor);
    if bytes != (expected, expected) || pool.active() != 0 {
        return Err("Relay byte counts or admission cleanup differ".into());
    }
    Ok(json!({
        "ok": true,
        "roundtrip_passed": true,
        "sent": bytes.0,
        "received": bytes.1,
        "half_close_verified": true,
        "admission_final": pool.active(),
        "real_socks_connector": true,
        "ssh_requires_external_fixture_evidence": true,
        "ndisrd_opened": false,
        "native_process_proof": false,
        "dns_leak_free": false,
        "release_accepted": false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_and_unconsented_probe_inputs_are_rejected() {
        let mut request = ProbeRequest {
            upstream: "127.0.0.1:1080".parse().unwrap(),
            target: "127.0.0.1:443".parse().unwrap(),
            consent: "LOOPBACK_TCP_PROBE".into(),
        };
        assert!(validate(&request).is_ok());
        request.target = "192.0.2.7:443".parse().unwrap();
        assert!(validate(&request).is_err());
        request.target = "127.0.0.1:443".parse().unwrap();
        request.upstream = "127.0.0.1:0".parse().unwrap();
        assert!(validate(&request).is_err());
        request.upstream = "127.0.0.1:1080".parse().unwrap();
        request.consent.clear();
        assert!(validate(&request).is_err());
    }
}
