//! Bounded NDISRD UDP quarantine for a self-owned TEST-NET canary.
//! This is a native driver test of the DROP disposition, NOT selected-app
//! interception, Windows DNS configuration, remote UDP ownership, or protection
//! across process/OS crashes. Mode 0 restores ordinary DIRECT networking.

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
use crate::ndis_session::LabDisposition;
#[cfg(any(all(windows, target_pointer_width = "64"), test))]
use crate::ndis_wire::{Direction, PacketView};
use serde::Deserialize;
#[cfg(all(windows, target_pointer_width = "64"))]
use serde_json::json;
use serde_json::Value;
use std::net::Ipv4Addr;

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
const TARGET: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 53);
#[cfg(all(windows, target_pointer_width = "64"))]
const DNS_QUERY: &[u8] = &[
    0x46, 0x42, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'i', b'n', b'v', b'a', b'l', b'i', b'd', 0, 0,
    1, 0, 1,
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub consent: String,
    pub adapter_name: String,
    pub local_ipv4: Ipv4Addr,
    pub duration_ms: u64,
    pub max_queries: u32,
    /// Caller assertion only; separate orchestrator must verify VNC rescue.
    pub rescue_attested: bool,
}

impl Request {
    pub fn validate(&self) -> Result<(), String> {
        if self.consent != "NATIVE_SELF_UDP_TESTNET_DROP_LAB"
            || self.adapter_name.is_empty()
            || self.adapter_name.len() > 255
            || !self.adapter_name.bytes().all(|b| b.is_ascii_graphic())
            || self.local_ipv4.is_unspecified()
            || self.local_ipv4.is_loopback()
            || self.local_ipv4.is_multicast()
            || self.local_ipv4.is_broadcast()
            || !(2000..=8000).contains(&self.duration_ms)
            || !(2..=4).contains(&self.max_queries)
            || !self.rescue_attested
        {
            return Err("Explicit bounded self-owned IPv4 UDP drop lab required".into());
        }
        Ok(())
    }
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
#[derive(Debug)]
struct Quarantine {
    local: Ipv4Addr,
    dropped: u64,
    fragmented: u64,
    selected_original_to_adapter: u64,
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
impl Quarantine {
    fn new(local: Ipv4Addr) -> Self {
        Self {
            local,
            dropped: 0,
            fragmented: 0,
            selected_original_to_adapter: 0,
        }
    }

    /// This short lab owns its only sending socket. For the fixed TEST-NET
    /// destination it intentionally drops *every* local IPv4 UDP fragment,
    /// including unrelated traffic to that address, rather than trusting
    /// a source port in a fragment or corrupted UDP header. NDISRD has no PID.
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
        if ether != 0x0800 || frame.len() < offset + 20 {
            return LabDisposition::Original;
        }
        let ip = &frame[offset..];
        if ip[0] >> 4 != 4
            || ip[9] != 17
            || ip[12..16] != self.local.octets()
            || ip[16..20] != TARGET.octets()
        {
            return LabDisposition::Original;
        }
        // Do not trust UDP ports, checksums, IPv4 total length or fragment
        // contents for this deny. The complete targeted IPv4 UDP tuple space
        // is quarantined during this brief, explicitly consented experiment.
        self.dropped += 1;
        if u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0 {
            self.fragmented += 1;
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
        Err("Native UDP quarantine requires signed NDISRD on Windows x64".into())
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
        return Err("UDP drop lab requires a single verified Ethernet adapter".into());
    }
    let adapter = &adapters[0];
    if adapter.name != request.adapter_name
        || adapter.medium != 0
        || adapter.mtu < 576
        || usize::from(adapter.mtu) + 14 > crate::ndis_wire::MAX_FRAME_BYTES
    {
        return Err("UDP drop lab Ethernet adapter or MTU prerequisite failed".into());
    }

    // Connecting a UDP socket selects its route but sends no datagram.
    // Only this process creates/retains the sending socket; no arbitrary PID.
    let socket =
        UdpSocket::bind((request.local_ipv4, 0)).map_err(|_| "UDP canary source bind failed")?;
    socket
        .connect((TARGET, 53))
        .map_err(|_| "UDP canary TEST-NET route unavailable")?;
    let local: SocketAddr = socket
        .local_addr()
        .map_err(|_| "UDP canary local endpoint unavailable")?;
    if local.ip() != request.local_ipv4 {
        return Err("UDP canary route changed the selected source address".into());
    }
    crate::windows_udp_owner::require_self_owned_candidate(local)?;

    // The only canary data writes happen after the real NDISRD mode was
    // successfully activated, and the socket is destroyed before mode 0.
    // A separate VNC rescue/watchdog remains mandatory on a remote host.
    let mut session = PacketSession::start(&mut device, adapter.handle, LabMode::Passthrough)
        .map_err(|e| e.to_string())?;
    let mut quarantine = Quarantine::new(request.local_ipv4);
    let start = Instant::now();
    let duration = Duration::from_millis(request.duration_ms);
    let mut next_send = start;
    let mut sent = 0u32;
    let mut fault: Option<String> = None;
    while start.elapsed() < duration {
        if sent < request.max_queries && Instant::now() >= next_send {
            match socket.send(DNS_QUERY) {
                Ok(length) if length == DNS_QUERY.len() => {
                    sent += 1;
                    next_send = Instant::now() + Duration::from_millis(250);
                }
                _ => {
                    fault = Some("UDP self-canary send failed".into());
                    break;
                }
            }
        }
        if let Err(error) =
            session.poll_lab_redirect(128, &mut |packet| Ok(quarantine.decide(packet)))
        {
            fault = Some(error.to_string());
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    // Never let the canary re-send after restoring ordinary direct networking.
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
        "kind": "bounded_real_ndisrd_self_owned_udp_testnet_drop_lab",
        "passed": passed,
        "loop_completed": passed,
        "rollback_confirmed": cleanup.is_ok(),
        "rollback_error": cleanup.err().map(|e| e.to_string()),
        "pump_error": fault,
        "native_signed_driver_io_attempted": true,
        "adapter_mode_restored_to_ordinary_network": cleanup.is_ok(),
        "elapsed_ms": start.elapsed().as_millis(),
        "queries_sent_after_mode_activation": sent,
        "selected_udp_frames_dropped": quarantine.dropped,
        "ambiguous_ipv4_fragments_dropped": quarantine.fragmented,
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

    fn frame(vlan: u8, source: [u8; 4], target: [u8; 4], proto: u8, fragment: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 14];
        let initial_ethertype: u16 = if vlan == 0 { 0x0800 } else { 0x8100 };
        bytes[12..14].copy_from_slice(&initial_ethertype.to_be_bytes());
        for index in 0..vlan {
            bytes.extend_from_slice(&[0, index + 1, 0x81, 0]);
        }
        if vlan > 0 {
            let len = bytes.len();
            bytes[len - 2..len].copy_from_slice(&0x0800u16.to_be_bytes());
        }
        let mut ip = [0u8; 28];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&28u16.to_be_bytes());
        ip[6..8].copy_from_slice(&fragment.to_be_bytes());
        ip[9] = proto;
        ip[12..16].copy_from_slice(&source);
        ip[16..20].copy_from_slice(&target);
        ip[20..22].copy_from_slice(&53001u16.to_be_bytes());
        ip[22..24].copy_from_slice(&53u16.to_be_bytes());
        bytes.extend_from_slice(&ip);
        bytes
    }

    fn verdict(direction: Direction, frame: &[u8], quarantine: &mut Quarantine) -> bool {
        matches!(
            quarantine.decide(&PacketView {
                direction,
                ndis_flags: 0,
                vlan_metadata: 0,
                filter_id: 0,
                frame
            }),
            LabDisposition::Drop
        )
    }

    #[test]
    fn real_wire_shape_deny_and_unselected_passthrough() {
        let mut guard = Quarantine::new(Ipv4Addr::new(192, 0, 2, 10));
        for tags in 0..=2 {
            for fragment in [0, 0x2000, 0x0001] {
                let original = frame(tags, [192, 0, 2, 10], TARGET.octets(), 17, fragment);
                assert!(verdict(Direction::ToAdapter, &original, &mut guard));
                assert!(!verdict(Direction::ToStack, &original, &mut guard));
                let other = frame(tags, [192, 0, 2, 10], [203, 0, 113, 9], 17, fragment);
                assert!(!verdict(Direction::ToAdapter, &other, &mut guard));
                let other_proto = frame(tags, [192, 0, 2, 10], TARGET.octets(), 6, fragment);
                assert!(!verdict(Direction::ToAdapter, &other_proto, &mut guard));
            }
        }
        assert_eq!(guard.dropped, 9);
        assert_eq!(guard.fragmented, 6);
        assert_eq!(guard.selected_original_to_adapter, 0);
    }

    #[test]
    fn no_unconsented_or_remote_or_unbounded_quarantine() {
        let mut request = Request {
            consent: "NATIVE_SELF_UDP_TESTNET_DROP_LAB".into(),
            adapter_name: "device".into(),
            local_ipv4: "192.0.2.10".parse().unwrap(),
            duration_ms: 3000,
            max_queries: 3,
            rescue_attested: true,
        };
        assert!(request.validate().is_ok());
        request.rescue_attested = false;
        assert!(request.validate().is_err());
        request.rescue_attested = true;
        request.consent.clear();
        assert!(request.validate().is_err());
        request.consent = "NATIVE_SELF_UDP_TESTNET_DROP_LAB".into();
        request.local_ipv4 = Ipv4Addr::LOCALHOST;
        assert!(request.validate().is_err());
        request.local_ipv4 = "192.0.2.10".parse().unwrap();
        request.max_queries = 17;
        assert!(request.validate().is_err());
        request.max_queries = 3;
        request.duration_ms = 15000;
        assert!(request.validate().is_err());
        let deny = run(request);
        assert!(deny.is_err());
    }
}
