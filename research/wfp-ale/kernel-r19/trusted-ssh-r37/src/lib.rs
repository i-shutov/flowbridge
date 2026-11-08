//! R37 experimental direct, host-key-pinned SSH upstream for the FlowBridge broker.
//!
//! Unlike OpenSSH -D + SOCKS5 NOAUTH on a substitutable localhost port,
//! the caller supplies the ALREADY OWNED TCP socket to the actual SSH server.
//! Before establishing that socket, the Windows broker must set the original
//! WFP redirect records with SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS.
//! This module cannot itself attest that WFP records were set; native G2 NO-GO.
//! An authenticated SSH direct-tcpip channel replaces the insecure local SOCKS
//! listener while preserving the application's original destination.

use russh::{client, keys::{self, PublicKeyOrCertificate}};
use std::{io, net::{IpAddr, TcpStream}, sync::Arc, time::Duration};
use tokio::{io::{AsyncRead, AsyncWrite}, sync::watch};

fn reject(stage: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, stage)
}

#[derive(Clone)]
pub struct VerifiedHost {
    /// Exact raw OpenSSH public-key bytes, not an unverified string/fingerprint.
    pinned: Vec<u8>,
}

impl VerifiedHost {
    pub fn from_key(key: &keys::PublicKey) -> io::Result<Self> {
        let bytes = key.to_bytes().map_err(|_| reject("invalid_pinned_host_key"))?;
        if bytes.is_empty() || bytes.len() > 8192 { return Err(reject("invalid_pinned_host_key")); }
        Ok(Self { pinned: bytes })
    }

    fn accepts(&self, presented: &PublicKeyOrCertificate) -> bool {
        match presented {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                // Raw public-key comparison is exact. Host certificates need a
                // separate CA/principal/expiry validation and are NOT accepted.
                key.to_bytes().map(|bytes| bytes == self.pinned).unwrap_or(false)
            }
            PublicKeyOrCertificate::Certificate(_) => false,
        }
    }
}

impl client::Handler for VerifiedHost {
    type Error = russh::Error;
    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(self.accepts(key))
    }
}

#[derive(Clone)]
pub struct ChannelAuthority {
    pub host: VerifiedHost,
    pub username: String,
    pub user_key: Arc<keys::PrivateKey>,
}

impl ChannelAuthority {
    pub fn from_files(host_public: &std::path::Path, private_key: &std::path::Path, user: String) -> io::Result<Self> {
        if user.is_empty() || user.len() > 128 || user.chars().any(|c| c.is_control()) {
            return Err(reject("invalid_ssh_account"));
        }
        let public = keys::load_public_key(host_public).map_err(|_| reject("invalid_pinned_host_key"))?;
        let key = keys::load_secret_key(private_key, None).map_err(|_| reject("invalid_identity_key"))?;
        Ok(Self { host: VerifiedHost::from_key(&public)?, username: user, user_key: Arc::new(key) })
    }
}

/// Revocation is a terminal capability, not a one-time admission check.
/// A changed flag or lost sender wakes this future; there is no path to
/// convert a closed/failed kernel lease into an implicit permit.
async fn revoked(mut signal: watch::Receiver<bool>) {
    if *signal.borrow() { return; }
    loop {
        if signal.changed().await.is_err() { return; }
        if *signal.borrow_and_update() { return; }
    }
}

/// A source-level/user-mode fail-closed barrier. tokio select is biased toward
/// revocation and drops the in-progress bidirectional copy on a STOP message.
/// This is NOT a kernel/system-wide no-DIRECT guarantee: already queued bytes
/// and OS scheduling require separate physical observation.
pub async fn copy_with_revocation<A, B>(
    left: &mut A, right: &mut B, signal: watch::Receiver<bool>
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    if *signal.borrow() { return Err(reject("ssh_revoked_before_copy")); }
    let stop = revoked(signal.clone());
    tokio::pin!(stop);
    let copied = tokio::select! {
        biased;
        _ = &mut stop => return Err(reject("ssh_copy_revoked")),
        result = tokio::time::timeout(
            Duration::from_secs(60), tokio::io::copy_bidirectional(left, right)
        ) => result.map_err(|_| reject("ssh_relay_timeout"))?
            .map_err(|_| reject("ssh_relay_error"))?,
    };
    if *signal.borrow() { Err(reject("ssh_copy_revoked")) } else { Ok(copied) }
}

/// Both accepted application socket and actual SSH transport socket must be
/// passed by OWNERSHIP. No SSH socket creation or local SOCKS listener here.
/// No application bytes are released until host key, user authentication and
/// remote direct-tcpip channel-open ALL succeed.
pub async fn relay_over_pinned_ssh(
    accepted: TcpStream,
    actual_ssh_transport: TcpStream,
    destination: IpAddr,
    destination_port: u16,
    auth: ChannelAuthority,
    signal: watch::Receiver<bool>,
) -> io::Result<(u64, u64)> {
    if destination_port == 0 { return Err(reject("invalid_target_port")); }
    if *signal.borrow() { return Err(reject("ssh_revoked_before_connect")); }
    let stop = revoked(signal.clone());
    tokio::pin!(stop);
    accepted.set_nonblocking(true)?;
    actual_ssh_transport.set_nonblocking(true)?;
    let incoming = tokio::net::TcpStream::from_std(accepted)?;
    let ssh = tokio::net::TcpStream::from_std(actual_ssh_transport)?;
    let cfg = Arc::new(client::Config::default());
    let mut session = tokio::select! {
        biased;
        _ = &mut stop => return Err(reject("ssh_host_revoked")),
        result = tokio::time::timeout(
            Duration::from_secs(12), client::connect_stream(cfg, ssh, auth.host.clone())
        ) => result.map_err(|_| reject("ssh_host_timeout"))?
            .map_err(|_| reject("ssh_host_rejected"))?,
    };
    let key = keys::key::PrivateKeyWithHashAlg::new(auth.user_key, None);
    let outcome = tokio::select! {
        biased;
        _ = &mut stop => return Err(reject("ssh_auth_revoked")),
        result = tokio::time::timeout(
            Duration::from_secs(12), session.authenticate_publickey(auth.username, key)
        ) => result.map_err(|_| reject("ssh_auth_timeout"))?
            .map_err(|_| reject("ssh_auth_failed"))?,
    };
    if !outcome.success() { return Err(reject("ssh_auth_denied")); }
    let channel = tokio::select! {
        biased;
        _ = &mut stop => return Err(reject("ssh_channel_revoked")),
        result = tokio::time::timeout(Duration::from_secs(12),
            session.channel_open_direct_tcpip(
                destination.to_string(), u32::from(destination_port), "127.0.0.1", 0
            )
        ) => result.map_err(|_| reject("ssh_channel_timeout"))?
            .map_err(|_| reject("ssh_channel_denied"))?,
    };
    let mut io = channel.into_stream();
    let mut client_socket = incoming;
    copy_with_revocation(&mut client_socket, &mut io, signal).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_empty_ssh_user_without_key_read() {
        let result=ChannelAuthority::from_files(std::path::Path::new("missing-host"),
            std::path::Path::new("missing-key"),String::new());
        assert!(result.is_err());
    }
    #[test]
    fn deny_missing_host_key_and_untrusted_identity() {
        let result=ChannelAuthority::from_files(std::path::Path::new("missing-host"),
            std::path::Path::new("missing-key"),"user".into());
        assert!(result.is_err());
    }
    #[tokio::test]
    async fn stop_before_copy_fails_closed() {
        let (sender, signal) = watch::channel(false);
        sender.send_replace(true);
        let (mut a, _a_peer) = tokio::io::duplex(64);
        let (mut b, _b_peer) = tokio::io::duplex(64);
        assert!(copy_with_revocation(&mut a, &mut b, signal).await.is_err());
    }
    #[tokio::test]
    async fn revocation_interrupts_live_blocked_copy() {
        let (sender, signal) = watch::channel(false);
        let (mut a, _a_peer) = tokio::io::duplex(64);
        let (mut b, _b_peer) = tokio::io::duplex(64);
        let future = copy_with_revocation(&mut a, &mut b, signal);
        tokio::pin!(future);
        let first = tokio::time::timeout(Duration::from_millis(30), future.as_mut()).await;
        assert!(first.is_err(), "copy should remain pending while healthy");
        sender.send_replace(true);
        assert!(tokio::time::timeout(Duration::from_millis(200), future.as_mut())
            .await.expect("revocation must wake a running relay").is_err());
    }
    #[tokio::test]
    async fn lost_revocation_sender_is_terminal() {
        let (sender, signal) = watch::channel(false);
        drop(sender);
        let (mut a, _a_peer) = tokio::io::duplex(64);
        let (mut b, _b_peer) = tokio::io::duplex(64);
        assert!(tokio::time::timeout(Duration::from_millis(200),
            copy_with_revocation(&mut a, &mut b, signal)).await.unwrap().is_err());
    }

}
