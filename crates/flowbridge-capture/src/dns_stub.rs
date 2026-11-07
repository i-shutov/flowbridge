//! Explicit, bounded UDP DNS -> TCP DNS -> supervised local SOCKS laboratory.
//! Real loopback UDP and TCP sockets, but NOT NDISRD packet interception,
//! selected-app DNS attribution, a system resolver or leak-free enforcement.
use crate::relay::RelayPool;
use flowbridge_core::Endpoint;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{self, Instant};

const MAX_DNS_UDP: usize = 1232;
const MAX_QUERIES: u32 = 16;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub consent: String,
    pub bind: SocketAddr,
    pub upstream: SocketAddr,
    pub resolver: SocketAddr,
    pub duration_ms: u64,
    pub max_queries: u32,
}

impl Request {
    pub fn validate(&self) -> Result<(), String> {
        if self.consent != "DNS_UDP_OVER_SOCKS_LAB"
            || !self.bind.ip().is_loopback()
            || self.bind.port() < 1024
            || !self.upstream.ip().is_loopback()
            || self.upstream.port() == 0
            || self.bind == self.upstream
            || self.resolver.ip().is_unspecified()
            || self.resolver.ip().is_multicast()
            || self.resolver.port() == 0
            || (self.resolver.port() != 53 && !self.resolver.ip().is_loopback())
            || !(500..=15000).contains(&self.duration_ms)
            || !(1..=MAX_QUERIES).contains(&self.max_queries)
        {
            return Err(
                "Explicit bounded local DNS-over-SOCKS lab consent and endpoints required".into(),
            );
        }
        Ok(())
    }
}

/// Parse the complete uncompressed DNS question, plus at most one EDNS OPT.
/// Do not treat arbitrary UDP payloads as authorized proxy destinations.
fn question_end(message: &[u8]) -> Option<usize> {
    if message.len() < 17 {
        return None;
    }
    let mut pos = 12usize;
    let mut name_bytes = 0usize;
    loop {
        let size = usize::from(*message.get(pos)?);
        pos += 1;
        if size == 0 {
            break;
        }
        if size > 63 || pos + size > message.len() {
            return None;
        }
        pos += size;
        name_bytes += size + 1;
        if name_bytes > 253 {
            return None;
        }
    }
    if pos + 4 > message.len()
        || message[pos..pos + 2] == [0, 0]
        || message[pos + 2..pos + 4] == [0, 0]
    {
        return None;
    }
    Some(pos + 4)
}

fn valid_query(query: &[u8]) -> bool {
    if !(17..=MAX_DNS_UDP).contains(&query.len())
        || query[2] & 0x80 != 0
        || query[2] & 0x78 != 0
        || u16::from_be_bytes([query[4], query[5]]) != 1
        || query[6..10] != [0, 0, 0, 0]
        || query[10] != 0
        || query[11] > 1
    {
        return false;
    }
    let Some(pos) = question_end(query) else {
        return false;
    };
    if query[11] == 0 {
        return pos == query.len();
    }
    // Exactly one well-formed EDNS(0) OPT pseudo-RR, no compression.
    if pos + 11 > query.len() || query[pos] != 0 || query[pos + 1..pos + 3] != [0, 41] {
        return false;
    }
    let opt_len = u16::from_be_bytes([query[pos + 9], query[pos + 10]]) as usize;
    pos + 11 + opt_len == query.len()
}

fn valid_reply(query: &[u8], reply: &[u8]) -> bool {
    if !(12..=MAX_DNS_UDP).contains(&reply.len())
        || reply[..2] != query[..2]
        || reply[2] & 0x80 == 0
        || reply[2] & 0x78 != 0
        || reply[4..6] != [0, 1]
    {
        return false;
    }
    let (Some(query_end), Some(reply_end)) = (question_end(query), question_end(reply)) else {
        return false;
    };
    query_end == reply_end
        && query[12..query_end - 4].eq_ignore_ascii_case(&reply[12..reply_end - 4])
        && query[query_end - 4..query_end] == reply[reply_end - 4..reply_end]
}

/// This operation creates only explicitly consented loopback UDP ingress and
/// connects to the *configured* resolver solely through a local SOCKS5 server.
/// There is never a direct resolver socket, local DNS lookup or fallback.
async fn serve(request: Request) -> Result<Value, String> {
    let socket = UdpSocket::bind(request.bind)
        .await
        .map_err(|_| "Local UDP bind failed")?;
    let pool = RelayPool::new(
        request.upstream,
        request.bind,
        1,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(3),
    )
    .map_err(|_| "Local SOCKS relay configuration rejected")?;
    let destination = Endpoint {
        host: request.resolver.ip().to_string(),
        port: request.resolver.port(),
    };
    let (stop_tx, stop_rx) = watch::channel(false);
    let deadline = Instant::now() + Duration::from_millis(request.duration_ms);
    let mut received = 0u32;
    let mut rejected = 0u32;
    let mut accepted = 0u32;
    let mut replies = 0u32;
    let mut upstream_failures = 0u32;
    let mut response_rejections = 0u32;
    let mut buffer = [0u8; 4096];
    // A fixed readiness marker contains no identities, DNS questions or keys.
    eprintln!("FLOWBRIDGE_DNS_LAB_READY");
    while received < request.max_queries {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let result = time::timeout(remaining, socket.recv_from(&mut buffer)).await;
        let Ok(Ok((length, peer))) = result else {
            break;
        };
        received += 1;
        if !peer.ip().is_loopback() || !valid_query(&buffer[..length]) {
            rejected += 1;
            continue;
        }
        accepted += 1;
        // A slow SOCKS handshake or DNS-over-TCP peer must not extend the
        // single overall laboratory budget. Dropping this future cancels the
        // SOCKS admission permit instead of holding a live relay after expiry.
        let transaction_deadline = deadline.min(Instant::now() + Duration::from_secs(5));
        let result = time::timeout_at(transaction_deadline, async {
            let upstream = pool
                .connect(&destination, stop_rx.clone())
                .await
                .map_err(|_| ())?;
            upstream
                .dns_tcp_exchange(&buffer[..length])
                .await
                .map_err(|_| ())
        })
        .await;
        let reply = match result {
            Ok(Ok(reply)) => reply,
            _ => {
                upstream_failures += 1;
                continue;
            }
        };
        if !valid_reply(&buffer[..length], &reply) {
            response_rejections += 1;
            continue;
        }
        // Never deliver a late UDP answer after the bounded session expires.
        // Even a temporarily back-pressured local send observes the same cap.
        if Instant::now() >= deadline {
            break;
        }
        match time::timeout_at(deadline, socket.send_to(&reply, peer)).await {
            Ok(Ok(_)) => replies += 1,
            _ if Instant::now() >= deadline => break,
            _ => {}
        }
    }
    drop(stop_tx);
    Ok(json!({
        "kind": "explicit_local_udp_dns_via_supervised_socks_tcp_lab",
        "loop_completed": true,
        "bounded_duration_ms": request.duration_ms,
        "overall_deadline_exhausted": Instant::now() >= deadline,
        "queries_received": received,
        "queries_rejected_before_proxy": rejected,
        "queries_accepted": accepted,
        "replies_returned": replies,
        "upstream_failures_without_direct_retry": upstream_failures,
        "invalid_upstream_replies_dropped": response_rejections,
        "active_relay_slots_at_exit": pool.active(),
        "direct_resolver_connections": 0,
        "native_ndisrd_interception": false,
        "selected_app_dns_protected": false,
        "system_dns_modified": false,
        "dns_leak_free": false,
        "protected_mode": false,
        "win10_11_acceptance": false,
        "release_accepted": false
    }))
}

pub fn run(request: Request) -> Result<Value, String> {
    request.validate()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "Bounded DNS runtime unavailable".to_owned())?
        .block_on(serve(request))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn query() -> Vec<u8> {
        vec![
            0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 7, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]
    }
    #[test]
    fn strict_dns_query_and_reply_wire_contract() {
        let good = query();
        assert!(valid_query(&good));
        let mut reply = good.clone();
        reply[2] = 0x81;
        reply[3] = 0x80;
        assert!(valid_reply(&good, &reply));
        reply[0] ^= 1;
        assert!(!valid_reply(&good, &reply));
        let mut swapped_question = good.clone();
        swapped_question[2] = 0x81;
        swapped_question[13] = b'v';
        assert!(!valid_reply(&good, &swapped_question));
        let mut changed_type = good.clone();
        changed_type[2] = 0x81;
        changed_type[good.len() - 3] = 2;
        assert!(!valid_reply(&good, &changed_type));
        let mut short_answer = good[..12].to_vec();
        short_answer[2] = 0x81;
        assert!(!valid_reply(&good, &short_answer));
        let mut bad = good.clone();
        bad[4] = 2;
        assert!(!valid_query(&bad));
        let mut compressed = good.clone();
        compressed[12] = 0xc0;
        assert!(!valid_query(&compressed));
        let mut truncated = good.clone();
        truncated.pop();
        assert!(!valid_query(&truncated));
        let mut opt = good.clone();
        opt[11] = 1;
        opt.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        assert!(valid_query(&opt));
        opt.push(0);
        assert!(!valid_query(&opt));
    }
    #[test]
    fn no_consent_or_nonlocal_or_unbounded_service() {
        let mut request = Request {
            consent: "DNS_UDP_OVER_SOCKS_LAB".into(),
            bind: "127.0.0.1:15535".parse().unwrap(),
            upstream: "127.0.0.1:1080".parse().unwrap(),
            resolver: "1.1.1.1:53".parse().unwrap(),
            duration_ms: 5000,
            max_queries: 4,
        };
        assert!(request.validate().is_ok());
        request.consent.clear();
        assert!(request.validate().is_err());
        request.consent = "DNS_UDP_OVER_SOCKS_LAB".into();
        request.bind = "0.0.0.0:15535".parse().unwrap();
        assert!(request.validate().is_err());
        request.bind = "127.0.0.1:15535".parse().unwrap();
        request.resolver = "203.0.113.2:8080".parse().unwrap();
        assert!(request.validate().is_err());
        request.resolver = "1.1.1.1:53".parse().unwrap();
        request.max_queries = 100;
        assert!(request.validate().is_err());
    }
}
