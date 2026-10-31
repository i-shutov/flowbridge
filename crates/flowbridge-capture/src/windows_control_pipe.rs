//! A local-only Windows named-pipe transport for the non-privileged,
//! foreground explicit SOCKS controller. Never expose control over TCP/HTTP.
//! The owner, Administrators and SYSTEM alone may connect; remote clients
//! are explicitly rejected, and the first instance must be ours.
#![cfg(windows)]

use crate::control_plane::Controller;
use serde_json::{json, Value};
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

const PIPE_NAME: &str = r"\\.\pipe\FlowBridgeRustControlV1";
const MAX_FRAME: usize = 4096;
const REQUEST_DEADLINE: Duration = Duration::from_secs(3);
const POLL_INTERVAL: Duration = Duration::from_millis(250);

// Owner rights preserve a non-elevated same-user foreground UX. When launched
// elevated, the control pipe intentionally does NOT grant all local Users
// permission to change configuration or stop that process.
const CONTROL_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)";

fn secure_server(first: bool) -> Result<NamedPipeServer, String> {
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .max_instances(2);

    let wide: Vec<u16> = CONTROL_SDDL.encode_utf16().chain(Some(0)).collect();
    let mut descriptor: *mut c_void = ptr::null_mut();
    // SAFETY: The immutable SDDL input is NUL-terminated. The system creates
    // an owned, self-relative descriptor, freed below after CreateNamedPipe.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if ok == 0 || descriptor.is_null() {
        return Err(format!("secure pipe ACL could not be built: {}", unsafe {
            GetLastError()
        }));
    }
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: attrs and its descriptor remain live until the synchronous
    // CreateNamedPipeW returns; the handle is non-inheritable.
    let created = unsafe {
        options.create_with_security_attributes_raw(
            PIPE_NAME,
            (&mut attrs as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    };
    // SAFETY: ConvertStringSecurityDescriptor allocated this with LocalAlloc.
    unsafe { LocalFree(descriptor) };
    created.map_err(|e| format!("restricted pipe creation failed: {e}"))
}

async fn transaction(server: NamedPipeServer, ctl: &mut Controller) -> bool {
    let exchange = async {
        let (reader, mut writer) = tokio::io::split(server);
        let mut reader = BufReader::new(reader.take((MAX_FRAME + 1) as u64));
        let mut frame = Vec::new();
        reader.read_until(b'\n', &mut frame).await?;
        let (reply, shutdown) = if frame.last() == Some(&b'\n') && frame.len() <= MAX_FRAME {
            ctl.execute(&frame[..frame.len() - 1])
        } else {
            (
                json!({"ok":false,"error":"control frame length/terminator invalid","release_accepted":false}),
                false,
            )
        };
        let mut output = serde_json::to_vec(&reply).map_err(std::io::Error::other)?;
        if output.len() >= MAX_FRAME {
            return Err(std::io::Error::other("control response exceeds bound"));
        }
        output.push(b'\n');
        writer.write_all(&output).await?;
        writer.shutdown().await?;
        Ok::<bool, std::io::Error>(shutdown)
    };
    match tokio::time::timeout(REQUEST_DEADLINE, exchange).await {
        Ok(Ok(shutdown)) => shutdown,
        _ => false, // Hung/malformed clients cannot hold the only pipe forever.
    }
}

pub(super) async fn serve(mut controller: Controller) -> Result<Value, String> {
    let mut waiting = secure_server(true)?;
    loop {
        let connection = tokio::select! {
            result = waiting.connect() => result,
            _ = tokio::time::sleep(POLL_INTERVAL) => {
                if controller.status()["scm_service_running"] == true
                    && crate::windows_service::stop_requested()
                {
                    controller.stop_engine()?;
                    return Ok(json!({
                        "ok":true, "scm_stop_completed":true,
                        "driver_capture_active":false,
                        "protected_redirect_available":false, "release_accepted":false
                    }));
                }
                if !controller.status()["engine"]["running"].as_bool().unwrap_or(false) {
                    return Err("explicit SOCKS engine stopped unexpectedly; refusing stale control service".into());
                }
                continue;
            }
        };
        connection.map_err(|e| format!("restricted pipe accept failed: {e}"))?;
        // Keep an unused listener instance alive while serving an authenticated
        // client. This avoids name hijack between sequential connections.
        let standby = secure_server(false)?;
        let shutdown = transaction(waiting, &mut controller).await;
        if shutdown {
            drop(standby);
            return Ok(json!({
                "ok": true,
                "foreground_control_stopped": true,
                "driver_capture_active": false,
                "protected_redirect_available": false,
                "release_accepted": false
            }));
        }
        waiting = standby;
    }
}

pub(super) async fn client(action: &str) -> Result<Value, String> {
    let mut connection = ClientOptions::new()
        .open(PIPE_NAME)
        .map_err(|e| format!("local control pipe unavailable: {e}"))?;
    let request = format!("{{\"command\":\"{action}\"}}\n");
    let response = tokio::time::timeout(REQUEST_DEADLINE, async {
        connection
            .write_all(request.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut buffer = Vec::new();
        BufReader::new((&mut connection).take((MAX_FRAME + 1) as u64))
            .read_until(b'\n', &mut buffer)
            .await
            .map_err(|e| e.to_string())?;
        if buffer.last() != Some(&b'\n') || buffer.len() > MAX_FRAME {
            return Err::<Value, String>("invalid bounded control response".to_owned());
        }
        serde_json::from_slice::<Value>(&buffer[..buffer.len() - 1])
            .map_err(|_| "invalid control response JSON".into())
    })
    .await
    .map_err(|_| "local control deadline exceeded".to_owned())??;
    if response["ok"] != true {
        return Err(response["error"]
            .as_str()
            .unwrap_or("local control command rejected")
            .to_owned());
    }
    Ok(response)
}
