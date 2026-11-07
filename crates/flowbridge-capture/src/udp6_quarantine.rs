//! Explicit IPv6-only signed-NDISRD UDP TEST-NET DROP experiment.
//! It owns the sending UDP socket and drops all outbound IPv6 datagrams from
//! that exact source to 2001:db8::53 (including extension/fragment variants).
//! No arbitrary packet-to-PID binding, system DNS change or persistent
//! fail-closed is established. Mode 0 restores ordinary DIRECT-capable traffic.
#[cfg(any(all(windows, target_pointer_width = "64"), test))]
use crate::ndis_session::LabDisposition;
#[cfg(any(all(windows, target_pointer_width = "64"), test))]
use crate::ndis_wire::{Direction, PacketView};
use serde::Deserialize;
#[cfg(all(windows, target_pointer_width = "64"))]
use serde_json::json;
use serde_json::Value;
use std::net::Ipv6Addr;

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
const TARGET: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0053);
#[cfg(all(windows, target_pointer_width = "64"))]
const QUERY: &[u8] = &[
    0x46, 0x42, 0x06, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'i', b'n', b'v', b'a', b'l', b'i', b'd', 0, 0,
    28, 0, 1,
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub consent: String,
    pub adapter_name: String,
    pub local_ipv6: Ipv6Addr,
    pub duration_ms: u64,
    pub max_queries: u32,
    /// A caller assertion, NOT proof. Orchestrator must independently arm
    /// a SYSTEM rescue task and verify VNC before changing adapter mode.
    pub rescue_attested: bool,
}

impl Request {
    pub fn validate(&self) -> Result<(), String> {
        let segments = self.local_ipv6.segments();
        let link_local = segments[0] & 0xffc0 == 0xfe80;
        if self.consent != "NATIVE_SELF_IPV6_UDP_TESTNET_DROP_LAB"
            || self.adapter_name.is_empty()
            || self.adapter_name.len() > 255
            || !self.adapter_name.bytes().all(|b| b.is_ascii_graphic())
            || self.local_ipv6.is_unspecified()
            || self.local_ipv6.is_loopback()
            || self.local_ipv6.is_multicast()
            || self.local_ipv6.to_ipv4_mapped().is_some()
            || link_local
            || !(2000..=8000).contains(&self.duration_ms)
            || !(2..=4).contains(&self.max_queries)
            || !self.rescue_attested
        {
            return Err(
                "Explicit bounded IPv6 TEST-NET drop lab and non-link-local source required".into(),
            );
        }
        Ok(())
    }
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
struct Quarantine {
    source: Ipv6Addr,
    dropped: u64,
    extensions_or_fragments: u64,
    selected_original_to_adapter: u64,
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
impl Quarantine {
    fn new(source: Ipv6Addr) -> Self {
        Self {
            source,
            dropped: 0,
            extensions_or_fragments: 0,
            selected_original_to_adapter: 0,
        }
    }

    /// The bound source address and fixed documentation destination identify
    /// only a short, owned-socket experiment, NOT an arbitrary application.
    /// With IPv6 extension headers, inferring UDP from the first next-header
    /// byte would miss fragments. Therefore *all* matching IPv6 datagrams
    /// are dropped, even if an upper-layer protocol is not recognizable.
    /// That deliberately overblocks other same-pair traffic during the lab.
    fn decide(&mut self, packet: &PacketView<'_>) -> LabDisposition {
        if packet.direction != Direction::ToAdapter {
            return LabDisposition::Original;
        }
        let frame = packet.frame;
        if frame.len() < 14 {
            return LabDisposition::Original;
        }
        let mut ether = u16::from_be_bytes([frame[12], frame[13]]);
        let mut offset = 14usize;
        for _ in 0..2 {
            if ether != 0x8100 && ether != 0x88a8 {
                break;
            }
            if frame.len() < offset + 4 {
                return LabDisposition::Original;
            }
            ether = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
            offset += 4;
        }
        if ether != 0x86dd || frame.len() < offset + 40 {
            return LabDisposition::Original;
        }
        let ip = &frame[offset..];
        if ip[0] >> 4 != 6 || ip[8..24] != self.source.octets() || ip[24..40] != TARGET.octets() {
            return LabDisposition::Original;
        }
        self.dropped += 1;
        if ip[6] != 17 {
            self.extensions_or_fragments += 1;
        }
        LabDisposition::Drop
    }
}

pub fn run(request: Request) -> Result<Value, String> {
    request.validate()?;
    #[cfg(all(windows, target_pointer_width = "64"))]
    {
        native(request)
    }
    #[cfg(not(all(windows, target_pointer_width = "64")))]
    {
        let _ = request;
        Err("Native IPv6 UDP quarantine requires signed NDISRD on Windows x64".into())
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn native(request: Request) -> Result<Value, String> {
    use crate::ndis_session::{LabMode, PacketSession};
    use crate::windows_ndis_device::Driver;
    use std::net::{SocketAddr, UdpSocket};
    use std::time::{Duration, Instant};

    let service = crate::windows_ndisrd_service::report();
    if service["service_registered"] != true
        || service["kernel_driver_type"] != true
        || service["service_state"] != "running"
    {
        return Err("Running native NDISRD driver not confirmed".into());
    }
    let mut device = Driver::open(true).map_err(|e| e.to_string())?;
    device.version().map_err(|e| e.to_string())?;
    let adapters = device.adapters().map_err(|e| e.to_string())?;
    if adapters.len() != 1 {
        return Err("IPv6 UDP drop lab requires one verified Ethernet adapter".into());
    }
    let adapter = &adapters[0];
    if adapter.name != request.adapter_name
        || adapter.medium != 0
        || adapter.mtu < 1280
        || usize::from(adapter.mtu) + 14 > crate::ndis_wire::MAX_FRAME_BYTES
    {
        return Err("IPv6 UDP drop lab adapter/MTU prerequisite failed".into());
    }
    // Establish the route *before* activating interception. No packet is
    // transmitted by connect(); send occurs only with a live driver session.
    let socket =
        UdpSocket::bind((request.local_ipv6, 0)).map_err(|_| "IPv6 canary source bind failed")?;
    socket
        .connect((TARGET, 53))
        .map_err(|_| "IPv6 documentation route unavailable")?;
    let local: SocketAddr = socket
        .local_addr()
        .map_err(|_| "IPv6 source endpoint unavailable")?;
    if local.ip() != request.local_ipv6 {
        return Err("IPv6 canary route changed source address".into());
    }
    crate::windows_udp_owner::require_self_owned_candidate(local)?;
    // No automatic fallback to IPv4 when IPv6 routing is unavailable.
    let mut session = PacketSession::start(&mut device, adapter.handle, LabMode::Passthrough)
        .map_err(|e| e.to_string())?;
    let mut quarantine = Quarantine::new(request.local_ipv6);
    let start = Instant::now();
    let duration = Duration::from_millis(request.duration_ms);
    let mut next_send = start;
    let mut sent = 0u32;
    let mut fault: Option<String> = None;
    while start.elapsed() < duration {
        if sent < request.max_queries && Instant::now() >= next_send {
            match socket.send(QUERY) {
                Ok(n) if n == QUERY.len() => {
                    sent += 1;
                    next_send = Instant::now() + Duration::from_millis(250);
                }
                _ => {
                    fault = Some("IPv6 UDP canary send failed".into());
                    break;
                }
            }
        }
        if let Err(error) = session.poll_lab_redirect(128, &mut |p| Ok(quarantine.decide(p))) {
            fault = Some(error.to_string());
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    // No subsequent canary transmission may outlive protected lab diversion.
    drop(socket);
    let stats = session.stats();
    let cleanup = session.close();
    let passed = fault.is_none()
        && cleanup.is_ok()
        && sent == request.max_queries
        && quarantine.dropped >= u64::from(sent)
        && stats.dropped >= quarantine.dropped
        && quarantine.selected_original_to_adapter == 0;
    Ok(json!({
        "kind": "bounded_real_ndisrd_self_owned_ipv6_udp_testnet_drop_lab",
        "passed": passed,
        "loop_completed": passed,
        "rollback_confirmed": cleanup.is_ok(),
        "rollback_error": cleanup.err().map(|e| e.to_string()),
        "pump_error": fault,
        "native_signed_driver_io_attempted": true,
        "adapter_mode_restored_to_ordinary_network": cleanup.is_ok(),
        "elapsed_ms": start.elapsed().as_millis(),
        "queries_sent_after_mode_activation": sent,
        "selected_ipv6_frames_dropped": quarantine.dropped,
        "ipv6_extension_or_fragment_headers_dropped": quarantine.extensions_or_fragments,
        "selected_original_frames_sent_to_adapter": quarantine.selected_original_to_adapter,
        "total_packets_seen": stats.observed,
        "total_other_frames_reinjected_unchanged": stats.injected,
        "udp_iphelper_local_bind_candidate_only": true,
        "native_packet_to_pid_proven": false,
        "arbitrary_selected_app_accepted": false,
        "dns_leak_free": false,
        "crash_persistent_fail_closed": false,
        "win10_11_acceptance": false,
        "release_accepted": false,
        "packet_payload_or_identity_saved": false,
        "external_rescue_self_attested_not_verified": request.rescue_attested
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(tags: u8, source: Ipv6Addr, target: Ipv6Addr, next: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; 14];
        bytes[12..14]
            .copy_from_slice(&(if tags == 0 { 0x86ddu16 } else { 0x8100u16 }).to_be_bytes());
        for index in 0..tags {
            bytes.extend_from_slice(&[0, index + 1, 0x81, 0]);
        }
        if tags != 0 {
            let n = bytes.len();
            bytes[n - 2..n].copy_from_slice(&0x86ddu16.to_be_bytes());
        }
        let mut ip = [0u8; 48];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&8u16.to_be_bytes());
        ip[6] = next;
        ip[7] = 64;
        ip[8..24].copy_from_slice(&source.octets());
        ip[24..40].copy_from_slice(&target.octets());
        bytes.extend_from_slice(&ip);
        bytes
    }

    fn drop_frame(q: &mut Quarantine, direction: Direction, bytes: &[u8]) -> bool {
        matches!(
            q.decide(&PacketView {
                direction,
                ndis_flags: 0,
                vlan_metadata: 0,
                filter_id: 0,
                frame: bytes,
            }),
            LabDisposition::Drop
        )
    }

    #[test]
    fn fixed_ipv6_canary_drops_unfragmented_fragmented_and_extension_headers() {
        let source: Ipv6Addr = "2001:db8:abcd::42".parse().unwrap();
        let mut q = Quarantine::new(source);
        for tags in 0..=2 {
            for next in [17, 44, 0, 60, 6] {
                let target = frame(tags, source, TARGET, next);
                assert!(drop_frame(&mut q, Direction::ToAdapter, &target));
                assert!(!drop_frame(&mut q, Direction::ToStack, &target));
                assert!(!drop_frame(
                    &mut q,
                    Direction::ToAdapter,
                    &frame(tags, source, "2001:db8::99".parse().unwrap(), next)
                ));
                assert!(!drop_frame(
                    &mut q,
                    Direction::ToAdapter,
                    &frame(tags, "2001:db8:abcd::43".parse().unwrap(), TARGET, next)
                ));
            }
        }
        assert_eq!(q.dropped, 15);
        assert_eq!(q.extensions_or_fragments, 12);
        assert_eq!(q.selected_original_to_adapter, 0);
    }

    #[test]
    fn ambiguous_or_truncated_ethernet_is_not_a_claim_of_packet_ownership() {
        let source: Ipv6Addr = "2001:db8:abcd::42".parse().unwrap();
        let mut q = Quarantine::new(source);
        assert!(!drop_frame(&mut q, Direction::ToAdapter, &[0; 13]));
        let mut ethernet = frame(0, source, TARGET, 17);
        ethernet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        assert!(!drop_frame(&mut q, Direction::ToAdapter, &ethernet));
        ethernet[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        ethernet[14] = 0x40;
        assert!(!drop_frame(&mut q, Direction::ToAdapter, &ethernet));
        ethernet[14] = 0x60;
        ethernet.truncate(14 + 39);
        assert!(!drop_frame(&mut q, Direction::ToAdapter, &ethernet));
    }

    #[test]
    fn consent_source_route_and_bounds_are_strict() {
        let mut r = Request {
            consent: "NATIVE_SELF_IPV6_UDP_TESTNET_DROP_LAB".into(),
            adapter_name: "native-adapter".into(),
            local_ipv6: "fd00::42".parse().unwrap(),
            duration_ms: 3000,
            max_queries: 3,
            rescue_attested: true,
        };
        assert!(r.validate().is_ok());
        r.rescue_attested = false;
        assert!(r.validate().is_err());
        r.rescue_attested = true;
        r.local_ipv6 = Ipv6Addr::LOCALHOST;
        assert!(r.validate().is_err());
        r.local_ipv6 = "fe80::1".parse().unwrap();
        assert!(r.validate().is_err());
        r.local_ipv6 = "::ffff:192.0.2.4".parse().unwrap();
        assert!(r.validate().is_err());
        r.local_ipv6 = "fd00::42".parse().unwrap();
        r.duration_ms = 10000;
        assert!(r.validate().is_err());
        r.duration_ms = 3000;
        r.max_queries = 5;
        assert!(r.validate().is_err());
        r.max_queries = 3;
        r.consent.clear();
        assert!(r.validate().is_err());
    }
}
