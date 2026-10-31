//! Bounded driver lifecycle shared by the real Windows transport and fault tests.
//! Observe copies packets. PassthroughLab diverts/reinjects ORIGINAL frames and
//! is explicitly NOT protected mode: restoring mode 0 permits normal networking.

use crate::ndis_wire::{decode_packet, Direction, LISTEN_BOTH, PACKET_BUFFER_BYTES, TUNNEL_BOTH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoFailure {
    pub operation: &'static str,
    pub code: u32,
}

impl std::fmt::Display for IoFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed ({})", self.operation, self.code)
    }
}
impl std::error::Error for IoFailure {}

pub trait PacketDevice {
    fn get_mode(&mut self, adapter: u64) -> Result<u32, IoFailure>;
    fn set_mode(&mut self, adapter: u64, mode: u32) -> Result<(), IoFailure>;
    fn queued(&mut self, adapter: u64) -> Result<u32, IoFailure>;
    fn read(&mut self, adapter: u64, packet: &mut [u8]) -> Result<(), IoFailure>;
    fn send(&mut self, adapter: u64, direction: Direction, packet: &[u8]) -> Result<(), IoFailure>;
    fn flush(&mut self, adapter: u64) -> Result<(), IoFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabMode {
    Observe,
    Passthrough,
}
impl LabMode {
    fn flags(self) -> u32 {
        match self { Self::Observe => LISTEN_BOTH, Self::Passthrough => TUNNEL_BOTH }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PumpStats {
    pub observed: u64,
    pub outgoing: u64,
    pub incoming: u64,
    pub injected: u64,
    pub bytes: u64,
    pub metadata_vlan: u64,
}

pub struct PacketSession<'a, D: PacketDevice> {
    device: &'a mut D,
    adapter: u64,
    mode: LabMode,
    armed: bool,
    faulted: bool,
    buffer: Vec<u8>,
    stats: PumpStats,
}

impl<'a, D: PacketDevice> PacketSession<'a, D> {
    pub fn start(device: &'a mut D, adapter: u64, mode: LabMode) -> Result<Self, IoFailure> {
        if adapter == 0 {
            return Err(IoFailure { operation: "invalid_adapter", code: 0 });
        }
        if device.get_mode(adapter)? != 0 {
            return Err(IoFailure { operation: "adapter_already_owned", code: 0 });
        }
        let mut session = Self {
            device, adapter, mode, armed: true, faulted: false,
            buffer: vec![0; PACKET_BUFFER_BYTES], stats: PumpStats::default(),
        };
        // Arm rollback BEFORE mutation: a failed IOCTL may have partial effects.
        if let Err(cause) = session.device.set_mode(adapter, mode.flags()) {
            return match session.close() { Ok(()) => Err(cause), Err(cleanup) => Err(cleanup) };
        }
        match session.device.get_mode(adapter) {
            Ok(actual) if actual == mode.flags() => Ok(session),
            result => {
                let cause = result.err().unwrap_or(IoFailure { operation: "mode_not_confirmed", code: 0 });
                match session.close() { Ok(()) => Err(cause), Err(cleanup) => Err(cleanup) }
            }
        }
    }

    pub fn stats(&self) -> PumpStats { self.stats }

    pub fn poll(&mut self, max_batch: usize) -> Result<usize, IoFailure> {
        if !self.armed || self.faulted || !(1..=256).contains(&max_batch) {
            return Err(IoFailure { operation: "session_not_runnable", code: 0 });
        }
        let result = self.pump(max_batch);
        if result.is_err() { self.faulted = true; }
        result
    }

    fn pump(&mut self, max_batch: usize) -> Result<usize, IoFailure> {
        if self.device.get_mode(self.adapter)? != self.mode.flags() {
            return Err(IoFailure { operation: "adapter_mode_changed", code: 0 });
        }
        let mut count = 0;
        while count < max_batch {
            let queued = self.device.queued(self.adapter)?;
            if queued == 0 { break; }
            if queued > 1_000_000 {
                return Err(IoFailure { operation: "invalid_queue_count", code: queued });
            }
            self.buffer.fill(0);
            // A read failure with a nonempty queue is NOT a normal empty read.
            self.device.read(self.adapter, &mut self.buffer)?;
            let packet = decode_packet(&self.buffer)
                .map_err(|_| IoFailure { operation: "invalid_packet_metadata", code: 0 })?;
            self.stats.observed += 1;
            self.stats.bytes += packet.frame.len() as u64;
            self.stats.metadata_vlan += u64::from(packet.vlan_metadata != 0);
            match packet.direction {
                Direction::ToAdapter => self.stats.outgoing += 1,
                Direction::ToStack => self.stats.incoming += 1,
            }
            if self.mode == LabMode::Passthrough {
                self.device.send(self.adapter, packet.direction, &self.buffer)?;
                self.stats.injected += 1;
            }
            count += 1;
        }
        Ok(count)
    }

    /// Explicit close is mandatory for reporting; Drop is only a last resort.
    /// Errors are not turned into successful rollback or protected-mode claims.
    pub fn close(&mut self) -> Result<(), IoFailure> {
        if !self.armed { return Ok(()); }
        self.faulted = true;
        self.device.set_mode(self.adapter, 0)?;
        if self.device.get_mode(self.adapter)? != 0 {
            return Err(IoFailure { operation: "restore_not_confirmed", code: 0 });
        }
        self.device.flush(self.adapter)?;
        self.armed = false;
        Ok(())
    }
}
impl<D: PacketDevice> Drop for PacketSession<'_, D> {
    fn drop(&mut self) { let _ = self.close(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct Device {
        mode: u32, queue: VecDeque<Vec<u8>>, sent: Vec<Vec<u8>>, calls: Vec<&'static str>,
        fail: Option<&'static str>,
    }
    impl Device {
        fn call(&mut self, name: &'static str) -> Result<(), IoFailure> {
            self.calls.push(name);
            if self.fail == Some(name) { Err(IoFailure { operation: name, code: 5 }) } else { Ok(()) }
        }
    }
    impl PacketDevice for Device {
        fn get_mode(&mut self, _: u64) -> Result<u32, IoFailure> { self.call("get")?; Ok(self.mode) }
        fn set_mode(&mut self, _: u64, mode: u32) -> Result<(), IoFailure> {
            self.mode = mode; self.call(if mode == 0 { "restore" } else { "set" })
        }
        fn queued(&mut self, _: u64) -> Result<u32, IoFailure> { self.call("queue")?; Ok(self.queue.len() as u32) }
        fn read(&mut self, _: u64, packet: &mut [u8]) -> Result<(), IoFailure> {
            self.call("read")?; packet.copy_from_slice(&self.queue.pop_front().unwrap()); Ok(())
        }
        fn send(&mut self, _: u64, _: Direction, packet: &[u8]) -> Result<(), IoFailure> {
            self.call("send")?; self.sent.push(packet.to_vec()); Ok(())
        }
        fn flush(&mut self, _: u64) -> Result<(), IoFailure> { self.call("flush")?; self.queue.clear(); Ok(()) }
    }
    fn frame() -> Vec<u8> {
        let mut b = vec![0; PACKET_BUFFER_BYTES]; b[16] = 1; b[20] = 60; b[52..112].fill(19); b
    }

    #[test]
    fn observation_never_reinjects_and_always_restores() {
        let mut d = Device::default(); d.queue.push_back(frame());
        {
            let mut s = PacketSession::start(&mut d, 7, LabMode::Observe).unwrap();
            assert_eq!(s.poll(4).unwrap(), 1); assert_eq!(s.stats().injected, 0); s.close().unwrap();
            assert!(s.poll(4).is_err());
        }
        assert_eq!(d.mode, 0); assert!(d.sent.is_empty()); assert!(d.calls.contains(&"flush"));
    }
    #[test]
    fn passthrough_preserves_complete_packet_and_is_bounded() {
        let mut d = Device::default(); let packet = frame();
        d.queue.push_back(packet.clone()); d.queue.push_back(packet.clone());
        {
            let mut s = PacketSession::start(&mut d, 7, LabMode::Passthrough).unwrap();
            assert_eq!(s.poll(1).unwrap(), 1); assert_eq!(s.stats().injected, 1);
        }
        assert_eq!(d.sent, [packet]); assert_eq!(d.mode, 0);
    }
    #[test]
    fn fault_paths_restore_without_retrying_failed_packet_or_masking_errors() {
        for failure in ["queue", "read", "send"] {
            let mut d = Device::default(); d.queue.push_back(frame());
            {
                let mut s = PacketSession::start(&mut d, 7, LabMode::Passthrough).unwrap();
                s.device.fail = Some(failure);
                assert_eq!(s.poll(4).unwrap_err().operation, failure);
                assert!(s.poll(4).is_err()); s.device.fail = None; s.close().unwrap();
            }
            assert_eq!(d.mode, 0); assert!(d.sent.is_empty());
        }
    }
    #[test]
    fn start_failure_rolls_back_even_after_partial_mutation() {
        let mut d = Device { fail: Some("set"), ..Device::default() };
        assert!(PacketSession::start(&mut d, 7, LabMode::Observe).is_err());
        assert_eq!(d.mode, 0); assert!(d.calls.contains(&"restore"));
    }
    #[test]
    fn prior_owner_is_not_overwritten() {
        let mut d = Device { mode: 3, ..Device::default() };
        assert!(PacketSession::start(&mut d, 7, LabMode::Observe).is_err());
        assert_eq!(d.mode, 3); assert_eq!(d.calls, ["get"]);
    }
    #[test]
    fn restoration_failure_is_visible_and_drop_retries() {
        let mut d = Device::default();
        {
            let mut s = PacketSession::start(&mut d, 7, LabMode::Observe).unwrap();
            s.device.fail = Some("restore"); assert!(s.close().is_err());
            s.device.fail = None;
        }
        assert_eq!(d.mode, 0); assert!(d.calls.iter().filter(|x| **x == "restore").count() >= 2);
    }
}
