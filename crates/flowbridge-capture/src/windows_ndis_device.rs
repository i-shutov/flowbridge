//! Native-x64 synchronous transport for the separately installed NDISRD device.
//! Uses public wire contracts, not ndisapi.dll or any vendor user-mode runtime.
//! No installation, filter-table changes, signing changes or protected claims.
#![cfg(all(windows, target_pointer_width = "64"))]

use crate::ndis_session::{IoFailure, PacketDevice};
use crate::ndis_wire::{self as wire, Adapter, Direction, PACKET_BUFFER_BYTES};
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::IO::DeviceIoControl;

pub(super) struct Driver { handle: HANDLE }
impl Driver {
    pub(super) fn open(exclusive: bool) -> Result<Self, IoFailure> {
        let path: Vec<u16> = r"\\.\NDISRD".encode_utf16().chain(Some(0)).collect();
        // SAFETY: Fixed device path, synchronous non-inheritable handle. Shared
        // mode is used only by diagnostics; lab sessions request exclusive use.
        let handle = unsafe { CreateFileW(path.as_ptr(), 0,
            if exclusive { 0 } else { FILE_SHARE_READ | FILE_SHARE_WRITE },
            std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut()) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(IoFailure { operation: "device_open_failed", code: unsafe { GetLastError() } });
        }
        Ok(Self { handle })
    }

    fn call(&mut self, index: u32, input: &[u8], output: &mut [u8], operation: &'static str) -> Result<usize, IoFailure> {
        let mut returned = 0;
        // SAFETY: Each caller supplies initialized fixed-length buffers. Native
        // nested packet pointers are pinned by the caller for this synchronous
        // call only; no kernel pointer/handle is ever deserialized from JSON.
        let ok = unsafe { DeviceIoControl(self.handle, wire::ioctl(index),
            input.as_ptr().cast::<c_void>(), input.len() as u32,
            if output.is_empty() { std::ptr::null_mut() } else { output.as_mut_ptr().cast::<c_void>() },
            output.len() as u32, &mut returned, std::ptr::null_mut()) };
        if ok == 0 { return Err(IoFailure { operation, code: unsafe { GetLastError() } }); }
        if returned as usize != output.len() {
            return Err(IoFailure { operation: "unexpected_ioctl_reply_size", code: returned });
        }
        Ok(returned as usize)
    }

    pub(super) fn version(&mut self) -> Result<u32, IoFailure> {
        let mut version = [0; 4];
        self.call(0, &u32::MAX.to_le_bytes(), &mut version, "version_query_failed")?;
        let version = u32::from_le_bytes(version);
        if ((version >> 12) & 15) != 3 || !(0x0601..=0x0602).contains(&(version >> 16)) {
            return Err(IoFailure { operation: "unsupported_driver_abi", code: version });
        }
        Ok(version)
    }

    pub(super) fn adapters(&mut self) -> Result<Vec<Adapter>, IoFailure> {
        let input = vec![0; wire::ADAPTER_LIST_BYTES];
        let mut output = vec![0; wire::ADAPTER_LIST_BYTES];
        self.call(1, &input, &mut output, "adapter_query_failed")?;
        wire::decode_adapters(&output).map_err(|_| IoFailure { operation: "invalid_adapter_inventory", code: 0 })
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        // SAFETY: Successfully opened, uniquely owned device handle.
        unsafe { CloseHandle(self.handle) };
    }
}

impl PacketDevice for Driver {
    fn get_mode(&mut self, adapter: u64) -> Result<u32, IoFailure> {
        let input = wire::mode_request(adapter, 0);
        let mut output = input;
        self.call(13, &input, &mut output, "get_adapter_mode")?;
        if output[..8] != input[..8] {
            return Err(IoFailure { operation: "adapter_identity_changed", code: 0 });
        }
        Ok(u32::from_le_bytes(output[8..12].try_into().expect("fixed mode buffer")))
    }
    fn set_mode(&mut self, adapter: u64, mode: u32) -> Result<(), IoFailure> {
        if !matches!(mode, 0 | wire::LISTEN_BOTH | wire::TUNNEL_BOTH) {
            return Err(IoFailure { operation: "unsupported_adapter_mode", code: mode });
        }
        self.call(5, &wire::mode_request(adapter, mode), &mut [], "set_adapter_mode")?;
        Ok(())
    }
    fn queued(&mut self, adapter: u64) -> Result<u32, IoFailure> {
        let mut count = [0; 4];
        // Native x64 contract uses sizeof(HANDLE)==8, not the old x86 web table.
        self.call(12, &adapter.to_le_bytes(), &mut count, "query_packet_queue")?;
        Ok(u32::from_le_bytes(count))
    }
    fn read(&mut self, adapter: u64, packet: &mut [u8]) -> Result<(), IoFailure> {
        if packet.len() != PACKET_BUFFER_BYTES {
            return Err(IoFailure { operation: "invalid_packet_capacity", code: 0 });
        }
        let input = wire::packet_request(adapter, packet.as_mut_ptr() as usize as u64);
        let mut output = input;
        self.call(4, &input, &mut output, "read_packet")?;
        if output != input {
            return Err(IoFailure { operation: "packet_pointer_changed", code: 0 });
        }
        wire::decode_packet(packet).map_err(|_| IoFailure { operation: "invalid_driver_packet", code: 0 })?;
        Ok(())
    }
    fn send(&mut self, adapter: u64, direction: Direction, packet: &[u8]) -> Result<(), IoFailure> {
        let decoded = wire::decode_packet(packet)
            .map_err(|_| IoFailure { operation: "invalid_injection_buffer", code: 0 })?;
        if decoded.direction != direction {
            return Err(IoFailure { operation: "injection_direction_mismatch", code: 0 });
        }
        // Copy before handing a pointer to the kernel, so no mutation can alias
        // the caller's immutable bytes, even if a driver updates metadata.
        let mut owned = packet.to_vec();
        let request = wire::packet_request(adapter, owned.as_mut_ptr() as usize as u64);
        let index = if direction == Direction::ToAdapter { 2 } else { 3 };
        self.call(index, &request, &mut [], "send_original_packet")?;
        Ok(())
    }
    fn flush(&mut self, adapter: u64) -> Result<(), IoFailure> {
        self.call(6, &adapter.to_le_bytes(), &mut [], "flush_packet_queue")?;
        Ok(())
    }
}
