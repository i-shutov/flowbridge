//! Owned-string C ABI for native policy, engine control, and connected TCP streams.
use flowbridge_core::{Config, Flow};
use serde_json::{json, Value};
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};

mod diagnostics;
mod native_context;
mod native_dns;

const MAX_INPUT_BYTES: usize = 1024 * 1024;

unsafe fn input<'a>(pointer: *const c_char) -> Result<&'a str, String> {
    if pointer.is_null() {
        return Err("null input pointer".into());
    }
    // The caller guarantees a readable NUL-terminated string. This API is for
    // trusted in-process UI callers, not an IPC boundary or arbitrary pointers.
    let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes();
    if bytes.len() > MAX_INPUT_BYTES {
        return Err("input exceeds 1 MiB".into());
    }
    std::str::from_utf8(bytes).map_err(|_| "input is not UTF-8".into())
}

fn output(value: Value) -> *mut c_char {
    CString::new(value.to_string())
        .expect("JSON serialization escapes NUL bytes")
        .into_raw()
}

fn guarded(work: impl FnOnce() -> Result<Value, String>) -> *mut c_char {
    let result = match catch_unwind(AssertUnwindSafe(work)) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => json!({"ok": false, "error": error}),
        Err(_) => json!({"ok": false, "error": "internal FlowBridge panic"}),
    };
    output(result)
}

/// Produce a redacted, offline report from cached UI snapshots.
///
/// # Safety
/// `snapshot_json` must reference a live NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn fb_diagnostic_report_json(snapshot_json: *const c_char) -> *mut c_char {
    guarded(|| {
        let request: Value =
            serde_json::from_str(unsafe { input(snapshot_json) }?).map_err(|e| e.to_string())?;
        Ok(json!({"ok":true,"report":diagnostics::report(&request)}))
    })
}

/// Validate a profile. Returns an owned JSON string, released with `fb_string_free`.
///
/// # Safety
/// `config_json` must point to a live NUL-terminated UTF-8 string for this call.
#[no_mangle]
pub unsafe extern "C" fn fb_validate_json(config_json: *const c_char) -> *mut c_char {
    guarded(|| {
        let text = unsafe { input(config_json) }?;
        Config::from_json(text).map_err(|e| e.to_string())?;
        Ok(json!({"ok": true}))
    })
}

/// Evaluate a hypothetical or OS-attested flow; this function does not attest it.
///
/// # Safety
/// Both pointers must reference live NUL-terminated UTF-8 strings for this call.
#[no_mangle]
pub unsafe extern "C" fn fb_evaluate_json(
    config_json: *const c_char,
    flow_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let profile =
            Config::from_json(unsafe { input(config_json) }?).map_err(|e| e.to_string())?;
        let flow: Flow =
            serde_json::from_str(unsafe { input(flow_json) }?).map_err(|e| e.to_string())?;
        flow.destination.validate().map_err(|e| e.to_string())?;
        Ok(json!({"ok": true, "decision": profile.evaluate(&flow)}))
    })
}

/// Release exactly one pointer produced by a FlowBridge string-returning call.
///
/// # Safety
/// Pointer must be null or an unfreed pointer returned by this library. No aliases
/// may read the memory after this call. Double-free/foreign pointers are invalid.
#[no_mangle]
pub unsafe extern "C" fn fb_string_free(pointer: *mut c_char) {
    if !pointer.is_null() {
        drop(unsafe { CString::from_raw(pointer) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    unsafe fn consume(pointer: *mut c_char) -> Value {
        let value =
            serde_json::from_str(unsafe { CStr::from_ptr(pointer) }.to_str().unwrap()).unwrap();
        unsafe { fb_string_free(pointer) };
        value
    }
    #[test]
    fn null_and_malformed_inputs_return_owned_errors() {
        let result = unsafe { consume(fb_validate_json(std::ptr::null())) };
        assert_eq!(result["ok"], false);
        let malformed = CString::new("not json").unwrap();
        let result = unsafe { consume(fb_validate_json(malformed.as_ptr())) };
        assert_eq!(result["ok"], false);
        unsafe { fb_string_free(std::ptr::null_mut()) };
    }
    #[test]
    fn evaluate_matches_core_and_returns_owned_json() {
        let config = CString::new(include_str!("../../../examples/direct.json")).unwrap();
        let flow = CString::new(r#"{"application":null,"destination":{"host":"example.com","port":443},"resolved_ip":null}"#).unwrap();
        let result = unsafe { consume(fb_evaluate_json(config.as_ptr(), flow.as_ptr())) };
        assert_eq!(result["ok"], true);
        assert_eq!(result["decision"]["action"]["type"], "direct");
    }
}

use flowbridge_core::Action;
use flowbridge_runtime::Engine;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard, OnceLock,
    },
    time::Duration,
};

const MAX_ENGINES: usize = 64;
const MAX_STREAMS: usize = 4096;
const MAX_IO_BYTES: usize = 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_millis(200);
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static STREAM_COUNT: AtomicUsize = AtomicUsize::new(0);
fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
fn handle() -> Result<u64, String> {
    let mut id = NEXT_HANDLE.load(Ordering::Relaxed);
    loop {
        let next = id.checked_add(1).ok_or("handle space exhausted")?;
        match NEXT_HANDLE.compare_exchange_weak(id, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(id),
            Err(current) => id = current,
        }
    }
}
struct EngineSlot {
    engine: Engine,
    gate: Mutex<()>,
    destroyed: AtomicBool,
}
fn engines() -> &'static Mutex<HashMap<u64, Arc<EngineSlot>>> {
    static VALUE: OnceLock<Mutex<HashMap<u64, Arc<EngineSlot>>>> = OnceLock::new();
    VALUE.get_or_init(|| Mutex::new(HashMap::new()))
}
fn streams() -> &'static Mutex<HashMap<u64, Arc<NativeStream>>> {
    static VALUE: OnceLock<Mutex<HashMap<u64, Arc<NativeStream>>>> = OnceLock::new();
    VALUE.get_or_init(|| Mutex::new(HashMap::new()))
}
fn with_engine(
    id: u64,
    work: impl FnOnce(&Engine) -> Result<Value, String>,
) -> Result<Value, String> {
    let slot = locked(engines())
        .get(&id)
        .cloned()
        .ok_or("invalid engine handle")?;
    let _gate = locked(&slot.gate);
    if slot.destroyed.load(Ordering::Acquire) {
        return Err("engine destroyed".into());
    }
    work(&slot.engine)
}
/// Create a stopped explicit SOCKS5 engine. See `fb_validate_json` pointer rules.
/// # Safety
/// `config_json` must be a live NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn fb_engine_create_json(config_json: *const c_char) -> *mut c_char {
    guarded(|| {
        let engine =
            Engine::from_json(unsafe { input(config_json) }?).map_err(|e| e.to_string())?;
        let mut registry = locked(engines());
        if registry.len() >= MAX_ENGINES {
            return Err("engine capacity reached".into());
        }
        let id = handle()?;
        registry.insert(
            id,
            Arc::new(EngineSlot {
                engine,
                gate: Mutex::new(()),
                destroyed: AtomicBool::new(false),
            }),
        );
        Ok(json!({"ok":true,"engine_id":id}))
    })
}
#[no_mangle]
pub extern "C" fn fb_engine_start_json(id: u64) -> *mut c_char {
    guarded(|| {
        with_engine(id, |engine| {
            Ok(json!({"ok":true,"status":engine.start().map_err(|e|e.to_string())?}))
        })
    })
}
#[no_mangle]
pub extern "C" fn fb_engine_stop_json(id: u64) -> *mut c_char {
    guarded(|| {
        with_engine(id, |engine| {
            Ok(json!({"ok":true,"status":engine.stop().map_err(|e|e.to_string())?}))
        })
    })
}
/// # Safety
/// `config_json` must be a live NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn fb_engine_reload_json(id: u64, config_json: *const c_char) -> *mut c_char {
    guarded(|| {
        let text = unsafe { input(config_json) }?;
        with_engine(id, |engine| {
            Ok(json!({"ok":true,"status":engine.reload_json(text).map_err(|e|e.to_string())?}))
        })
    })
}
#[no_mangle]
pub extern "C" fn fb_engine_snapshot_json(id: u64) -> *mut c_char {
    guarded(|| {
        with_engine(id, |engine| {
            let snapshot = engine.snapshot();
            Ok(
                json!({"ok":true,"status":snapshot.status,"connections":snapshot.connections,"events":snapshot.events,"managed_upstream":snapshot.managed_upstream,"managed_pool":snapshot.managed_pool}),
            )
        })
    })
}
/// Stop/remove a handle. Safe for unknown/already removed IDs, including 0.
#[no_mangle]
pub extern "C" fn fb_engine_destroy(id: u64) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let slot = locked(engines()).remove(&id);
        if let Some(slot) = slot {
            let _gate = locked(&slot.gate);
            slot.destroyed.store(true, Ordering::Release);
            let _ = slot.engine.stop();
        }
    }));
}

// Reservation includes pending opens, so simultaneous callers cannot bypass the
// stream limit while DNS/handshakes run outside the registry lock.
struct StreamLease;
impl StreamLease {
    fn reserve() -> Result<Self, String> {
        let mut count = STREAM_COUNT.load(Ordering::Acquire);
        loop {
            if count >= MAX_STREAMS {
                return Err("stream capacity reached".into());
            }
            match STREAM_COUNT.compare_exchange_weak(
                count,
                count + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Self),
                Err(current) => count = current,
            }
        }
    }
}
impl Drop for StreamLease {
    fn drop(&mut self) {
        STREAM_COUNT.fetch_sub(1, Ordering::AcqRel);
    }
}
struct NativeStream {
    socket: TcpStream,
    closed: AtomicBool,
    reading: AtomicBool,
    writing: AtomicBool,
    _lease: StreamLease,
    native: Option<native_context::Lease>,
}
impl Drop for NativeStream {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}
struct Busy<'a>(&'a AtomicBool);
impl<'a> Busy<'a> {
    fn enter(flag: &'a AtomicBool) -> Result<Self, i64> {
        flag.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| -3i64)?;
        Ok(Self(flag))
    }
}
impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
/// Apply policy and connect a TCP route. Application identity is supplied by the
/// capture provider; it is never inferred or authenticated by this library.
/// This call may block for up to 30 seconds; call from a native worker queue.
/// # Safety
/// Both pointers must be live NUL-terminated UTF-8 strings for this call.
#[no_mangle]
pub unsafe extern "C" fn fb_stream_open_json(
    config_json: *const c_char,
    flow_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let config =
            Config::from_json(unsafe { input(config_json) }?).map_err(|e| e.to_string())?;
        let flow: Flow =
            serde_json::from_str(unsafe { input(flow_json) }?).map_err(|e| e.to_string())?;
        open_stream(config, flow, None)
    })
}

/// Open a native WFP flow with opaque redirect records installed before connect.
/// Fails before network I/O on non-Windows platforms, empty/oversized records,
/// or a failed WSAIoctl; it never retries without the records.
/// # Safety
/// String pointers must be live NUL-terminated UTF-8; records must point to
/// `length` readable bytes for this call. Records are copied before dispatch.
#[no_mangle]
pub unsafe extern "C" fn fb_stream_open_wfp_json(
    config_json: *const c_char,
    flow_json: *const c_char,
    records: *const u8,
    length: usize,
) -> *mut c_char {
    guarded(|| {
        if records.is_null() || length == 0 || length > 64 * 1024 {
            return Err("WFP redirect records must contain 1..65536 bytes".into());
        }
        #[cfg(not(windows))]
        {
            let _ = (config_json, flow_json, records, length);
            Err("WFP stream capture is available only on Windows".into())
        }
        #[cfg(windows)]
        {
            let records = unsafe { std::slice::from_raw_parts(records, length) }.to_vec();
            let config =
                Config::from_json(unsafe { input(config_json) }?).map_err(|e| e.to_string())?;
            let flow: Flow =
                serde_json::from_str(unsafe { input(flow_json) }?).map_err(|e| e.to_string())?;
            open_stream(config, flow, Some(records))
        }
    })
}

#[cfg(windows)]
fn set_wfp_records(socket: &tokio::net::TcpSocket, records: &[u8]) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        WSAGetLastError, WSAIoctl, SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS,
    };
    let mut returned = 0u32;
    // The slice remains alive throughout this synchronous IOCTL. A new socket
    // has been created but connect has not run, including address retries.
    let result = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS,
            records.as_ptr().cast(),
            records.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(unsafe {
            WSAGetLastError()
        }))
    }
}

#[cfg(not(windows))]
fn set_wfp_records(_socket: &tokio::net::TcpSocket, _records: &[u8]) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "WFP requires Windows",
    ))
}

fn open_stream(
    config: Config,
    flow: Flow,
    redirect_records: Option<Vec<u8>>,
) -> Result<Value, String> {
    open_stream_managed(config, flow, redirect_records, None)
}
fn open_stream_managed(
    config: Config,
    flow: Flow,
    redirect_records: Option<Vec<u8>>,
    native: Option<Arc<native_context::Session>>,
) -> Result<Value, String> {
    flow.destination.validate().map_err(|e| e.to_string())?;
    let decision = config.evaluate(&flow);
    if matches!(decision.action, Action::Block) {
        return Err("connection blocked by policy".into());
    }
    let route = config.route(&decision.action).map_err(|e| e.to_string())?;
    let lease = StreamLease::reserve()?;
    let session = native.clone();
    let (socket, admission) = std::thread::Builder::new().name("flowbridge-connect".into())
        .spawn(move || -> Result<(TcpStream, Option<native_context::Lease>), String> {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e|e.to_string())?;
            let result = runtime.block_on(async {
                let work = async {
                    let mut admission = if let Some(session) = &session { Some(session.admit(&route).await?) } else { None };
                    if let Some(session) = &session { session.recheck(&route)?; }
                    let stream = tokio::time::timeout(Duration::from_secs(30), async {
                        let connect = Duration::from_millis(config.connect_timeout_ms);
                        let handshake = Duration::from_millis(config.handshake_timeout_ms);
                        if let Some(records) = redirect_records.as_deref() {
                            let prepare = |socket: &tokio::net::TcpSocket| set_wfp_records(socket, records);
                            flowbridge_net::connect_route_prepared(&flow.destination, &route, connect, handshake, config.listen, &prepare).await
                        } else {
                            flowbridge_net::connect_route_guarded(&flow.destination, &route, connect, handshake, config.listen).await
                        }
                    }).await.map_err(|_|"connection deadline exceeded".to_string())?.map_err(|e|e.to_string())?;
                    if let Some(session) = &session { session.recheck(&route)?; }
                    if let Some(admission) = &mut admission { admission.connected(); }
                    Ok((stream.into_std().map_err(|e|e.to_string())?, admission))
                };
                if let Some(session) = &session {
                    tokio::select! { biased;
                        _ = session.cancelled() => Err("native capture stopped during connection".into()),
                        result = work => result,
                    }
                } else { work.await }
            });
            runtime.shutdown_timeout(Duration::from_millis(50)); result
        }).map_err(|e|e.to_string())?.join().map_err(|_|"connection worker panicked".to_string())??;
    configure_native_socket(&socket).map_err(|e| e.to_string())?;
    socket.set_nodelay(true).map_err(|e| e.to_string())?;
    let id = handle()?;
    let mut registry = locked(streams());
    if native
        .as_ref()
        .is_some_and(|s| s.stopped.load(Ordering::Acquire))
    {
        return Err("native capture stopped before stream registration".into());
    }
    registry.insert(
        id,
        Arc::new(NativeStream {
            socket,
            closed: AtomicBool::new(false),
            reading: AtomicBool::new(false),
            writing: AtomicBool::new(false),
            _lease: lease,
            native: admission,
        }),
    );
    Ok(json!({"ok":true,"stream_id":id,"decision":decision}))
}

// On Windows SO_RCVTIMEO/SO_SNDTIMEO can leave a connection indeterminate
// after a timeout (Microsoft SOL_SOCKET documentation). Poll a nonblocking
// socket instead, so a readiness timeout is safely retryable without any send
// or receive having started. Unix retains its documented socket-timeout path.
#[cfg(windows)]
fn configure_native_socket(socket: &TcpStream) -> std::io::Result<()> {
    socket.set_nonblocking(true)
}
#[cfg(not(windows))]
fn configure_native_socket(socket: &TcpStream) -> std::io::Result<()> {
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(IO_TIMEOUT))?;
    socket.set_write_timeout(Some(IO_TIMEOUT))
}

#[cfg(windows)]
fn wait_ready(socket: &TcpStream, reading: bool) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        WSAGetLastError, WSAPoll, POLLERR, POLLHUP, POLLNVAL, POLLRDNORM, POLLWRNORM, WSAPOLLFD,
    };
    let events = if reading { POLLRDNORM } else { POLLWRNORM };
    let mut descriptor = WSAPOLLFD {
        fd: socket.as_raw_socket() as usize,
        events,
        revents: 0,
    };
    // The operation retains NativeStream's Arc throughout this poll. Close
    // uses shutdown rather than closing/freeing the socket beneath WSAPoll.
    let result = unsafe { WSAPoll(&mut descriptor, 1, IO_TIMEOUT.as_millis() as i32) };
    if result < 0 {
        return Err(std::io::Error::from_raw_os_error(unsafe {
            WSAGetLastError()
        }));
    }
    if descriptor.revents & POLLNVAL != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid socket during readiness poll",
        ));
    }
    if result == 0 || descriptor.revents & (events | POLLERR | POLLHUP) == 0 {
        return Err(std::io::ErrorKind::WouldBlock.into());
    }
    // HUP/ERR must reach the actual nonblocking read/write so buffered bytes,
    // EOF and the socket's real error preserve their normal TCP semantics.
    Ok(())
}

fn io_result(result: std::io::Result<usize>) -> i64 {
    match result {
        Ok(n) => n as i64,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            -2
        }
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut && !cfg!(windows) => -2,
        Err(_) => -1,
    }
}

fn native_stream(id: u64) -> Result<Arc<NativeStream>, i64> {
    locked(streams()).get(&id).cloned().ok_or(-3)
}
/// Read at most 1 MiB; 0 is EOF, -1 I/O, -2 timeout/busy OS, -3 handle/argument.
/// Exactly one simultaneous reader is supported. Close interrupts blocked I/O.
/// # Safety
/// For nonzero capacity, buffer must reference writable memory of that size.
#[no_mangle]
pub unsafe extern "C" fn fb_stream_read(id: u64, buffer: *mut u8, capacity: usize) -> i64 {
    catch_unwind(AssertUnwindSafe(|| -> Result<i64, i64> {
        if capacity > MAX_IO_BYTES || (capacity > 0 && buffer.is_null()) {
            return Err(-3);
        }
        let stream = native_stream(id)?;
        let _busy = Busy::enter(&stream.reading)?;
        if stream.closed.load(Ordering::Acquire) {
            return Err(-3);
        }
        if capacity == 0 {
            return Ok(0);
        }
        #[cfg(windows)]
        if let Err(error) = wait_ready(&stream.socket, true) {
            return Ok(io_result(Err(error)));
        }
        let bytes = unsafe { std::slice::from_raw_parts_mut(buffer, capacity) };
        let result = (&stream.socket).read(bytes);
        if let (Some(native), Ok(count)) = (&stream.native, &result) {
            native.progress(false, *count);
        }
        Ok(io_result(result))
    }))
    .unwrap_or(Err(-1))
    .unwrap_or_else(|code| code)
}
/// Write at most 1 MiB. Partial writes are normal; caller retries the remainder.
/// Exactly one simultaneous writer is supported; read may run concurrently.
/// # Safety
/// For nonzero length, buffer must reference readable memory of that size.
#[no_mangle]
pub unsafe extern "C" fn fb_stream_write(id: u64, buffer: *const u8, length: usize) -> i64 {
    catch_unwind(AssertUnwindSafe(|| -> Result<i64, i64> {
        if length > MAX_IO_BYTES || (length > 0 && buffer.is_null()) {
            return Err(-3);
        }
        let stream = native_stream(id)?;
        let _busy = Busy::enter(&stream.writing)?;
        if stream.closed.load(Ordering::Acquire) {
            return Err(-3);
        }
        if length == 0 {
            return Ok(0);
        }
        #[cfg(windows)]
        if let Err(error) = wait_ready(&stream.socket, false) {
            return Ok(io_result(Err(error)));
        }
        let bytes = unsafe { std::slice::from_raw_parts(buffer, length) };
        let result = (&stream.socket).write(bytes);
        if let (Some(native), Ok(count)) = (&stream.native, &result) {
            native.progress(true, *count);
        }
        Ok(io_result(result))
    }))
    .unwrap_or(Err(-1))
    .unwrap_or_else(|code| code)
}
/// Half-close outbound data. Reads may continue through the final peer response.
#[no_mangle]
pub extern "C" fn fb_stream_shutdown_write(id: u64) -> i32 {
    catch_unwind(AssertUnwindSafe(|| -> Result<i32, i64> {
        let stream = native_stream(id)?;
        let _busy = Busy::enter(&stream.writing)?;
        if stream.closed.load(Ordering::Acquire) {
            return Err(-3);
        }
        Ok(match stream.socket.shutdown(Shutdown::Write) {
            Ok(()) => 0,
            Err(_) => -1,
        })
    }))
    .unwrap_or(Err(-1))
    .unwrap_or_else(|code| code as i32)
}
/// Remove and cancel a stream. Existing operations retain their Arc until they
/// return; shutdown wakes the OS read/write without freeing memory underneath it.
#[no_mangle]
pub extern "C" fn fb_stream_close(id: u64) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let stream = locked(streams()).remove(&id);
        if let Some(stream) = stream {
            stream.closed.store(true, Ordering::Release);
            let _ = stream.socket.shutdown(Shutdown::Both);
        }
    }));
}

#[cfg(test)]
mod network_tests {
    use super::*;
    use std::{net::TcpListener, thread, time::Instant};
    unsafe fn consume(pointer: *mut c_char) -> Value {
        let value =
            serde_json::from_str(unsafe { CStr::from_ptr(pointer) }.to_str().unwrap()).unwrap();
        unsafe { fb_string_free(pointer) };
        value
    }
    fn profile() -> CString {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut config = Config::from_json(include_str!("../../../examples/direct.json")).unwrap();
        config.listen = listener.local_addr().unwrap();
        CString::new(serde_json::to_string(&config).unwrap()).unwrap()
    }
    fn open(config: &CString, address: std::net::SocketAddr) -> u64 {
        let flow=CString::new(json!({"application":null,"destination":{"host":address.ip().to_string(),"port":address.port()},"resolved_ip":null}).to_string()).unwrap();
        let result = unsafe { consume(fb_stream_open_json(config.as_ptr(), flow.as_ptr())) };
        assert_eq!(result["ok"], true, "{result}");
        result["stream_id"].as_u64().unwrap()
    }
    fn wait(mut check: impl FnMut() -> bool) {
        let until = Instant::now() + Duration::from_secs(2);
        while !check() {
            assert!(Instant::now() < until);
            thread::yield_now();
        }
    }
    #[test]
    fn stream_policy_half_close_and_checked_buffers() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let responder = thread::spawn(move || {
            let (mut stream, _) = server.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).unwrap();
            assert_eq!(payload, b"payload");
            stream.write_all(b"final response").unwrap();
        });
        let config = profile();
        let id = open(&config, address);
        assert_eq!(unsafe { fb_stream_write(id, std::ptr::null(), 1) }, -3);
        assert_eq!(
            unsafe { fb_stream_read(id, std::ptr::null_mut(), MAX_IO_BYTES + 1) },
            -3
        );
        assert_eq!(unsafe { fb_stream_write(id, b"payload".as_ptr(), 7) }, 7);
        assert_eq!(fb_stream_shutdown_write(id), 0);
        let mut response = Vec::new();
        loop {
            let mut buffer = [0u8; 64];
            let n = unsafe { fb_stream_read(id, buffer.as_mut_ptr(), buffer.len()) };
            if n == -2 {
                continue;
            }
            assert!(n >= 0, "read error: {n}");
            if n == 0 {
                break;
            }
            response.extend_from_slice(&buffer[..n as usize]);
        }
        assert_eq!(response, b"final response");
        fb_stream_close(id);
        fb_stream_close(id);
        assert_eq!(unsafe { fb_stream_read(id, std::ptr::null_mut(), 0) }, -3);
        responder.join().unwrap();
        let mut blocked: Value = serde_json::from_str(config.to_str().unwrap()).unwrap();
        blocked["default_action"] = json!({"type":"block"});
        let blocked = CString::new(blocked.to_string()).unwrap();
        let flow=CString::new(json!({"application":null,"destination":{"host":"127.0.0.1","port":address.port()},"resolved_ip":null}).to_string()).unwrap();
        let result = unsafe { consume(fb_stream_open_json(blocked.as_ptr(), flow.as_ptr())) };
        assert_eq!(result["ok"], false);
    }
    #[test]
    fn stream_timeout_single_reader_and_close_wakeup_keep_memory_alive() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let (release, held) = std::sync::mpsc::channel();
        let responder = thread::spawn(move || {
            let (_stream, _) = server.accept().unwrap();
            held.recv_timeout(Duration::from_secs(3)).unwrap();
        });
        let id = open(&profile(), address);
        let mut buffer = [0u8; 1];
        let start = Instant::now();
        assert_eq!(unsafe { fb_stream_read(id, buffer.as_mut_ptr(), 1) }, -2);
        assert!(start.elapsed() < Duration::from_secs(1));
        let retained = native_stream(id).unwrap();
        let reader = thread::spawn(move || {
            let mut byte = [0];
            unsafe { fb_stream_read(id, byte.as_mut_ptr(), 1) }
        });
        wait(|| retained.reading.load(Ordering::Acquire));
        assert_eq!(unsafe { fb_stream_read(id, buffer.as_mut_ptr(), 1) }, -3);
        let start = Instant::now();
        fb_stream_close(id);
        let code = reader.join().unwrap();
        // Closing may race just after Busy::enter and before the reader's
        // closed check. In that valid order the documented handle/argument
        // error is -3 rather than EOF/I/O/timeout. All four outcomes must
        // promptly wake without retaining the handle or dangling memory.
        assert!(
            matches!(code, -3..=0),
            "unexpected close/read result: {code}"
        );
        assert!(start.elapsed() < Duration::from_millis(500));
        assert!(retained.closed.load(Ordering::Acquire));
        assert!(native_stream(id).is_err());
        drop(retained);
        release.send(()).unwrap();
        responder.join().unwrap();
    }
    #[test]
    fn engine_handles_lifecycle_reload_and_destroy_are_serialized() {
        let config = profile();
        let result = unsafe { consume(fb_engine_create_json(config.as_ptr())) };
        assert_eq!(result["ok"], true);
        let id = result["engine_id"].as_u64().unwrap();
        assert_eq!(
            unsafe { consume(fb_engine_start_json(id)) }["status"]["running"],
            true
        );
        assert_eq!(
            unsafe { consume(fb_engine_reload_json(id, config.as_ptr())) }["status"]["generation"],
            2
        );
        let invalid = CString::new("{}").unwrap();
        assert_eq!(
            unsafe { consume(fb_engine_reload_json(id, invalid.as_ptr())) }["ok"],
            false
        );
        assert_eq!(
            unsafe { consume(fb_engine_snapshot_json(id)) }["status"]["generation"],
            2
        );
        let mut workers = Vec::new();
        for _ in 0..4 {
            workers.push(thread::spawn(move || {
                for _ in 0..20 {
                    let result = unsafe { consume(fb_engine_snapshot_json(id)) };
                    assert!(result["ok"].is_boolean());
                }
            }));
        }
        fb_engine_destroy(id);
        for worker in workers {
            worker.join().unwrap();
        }
        fb_engine_destroy(id);
        assert_eq!(unsafe { consume(fb_engine_start_json(id)) }["ok"], false);
        assert_eq!(unsafe { consume(fb_engine_snapshot_json(id)) }["ok"], false);
    }
}

#[cfg(test)]
mod wfp_tests {
    use super::*;
    unsafe fn consume(pointer: *mut c_char) -> Value {
        let result =
            serde_json::from_str(unsafe { CStr::from_ptr(pointer) }.to_str().unwrap()).unwrap();
        unsafe { fb_string_free(pointer) };
        result
    }
    #[test]
    fn empty_null_and_oversized_wfp_records_are_rejected_before_reading_inputs() {
        let byte = 0u8;
        for (records, length) in [
            (std::ptr::null(), 0),
            (std::ptr::null(), 1),
            (&byte as *const u8, 0),
            (&byte as *const u8, 65537),
            (&byte as *const u8, usize::MAX),
        ] {
            // Null config/flow and a deliberately smaller record allocation are
            // safe here because invalid lengths must fail before dereferencing.
            let result = unsafe {
                consume(fb_stream_open_wfp_json(
                    std::ptr::null(),
                    std::ptr::null(),
                    records,
                    length,
                ))
            };
            assert_eq!(result["ok"], false);
            assert!(result["error"].as_str().unwrap().contains("1..65536"));
        }
    }
    #[test]
    fn unsupported_or_rejected_wfp_records_never_open_an_unprepared_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let config = CString::new(include_str!("../../../examples/direct.json")).unwrap();
        let flow=CString::new(json!({"application":null,"destination":{"host":"127.0.0.1","port":address.port()},"resolved_ip":null}).to_string()).unwrap();
        let records = [0u8; 16];
        let result = unsafe {
            consume(fb_stream_open_wfp_json(
                config.as_ptr(),
                flow.as_ptr(),
                records.as_ptr(),
                records.len(),
            ))
        };
        assert_eq!(result["ok"], false);
        #[cfg(not(windows))]
        assert!(result["error"]
            .as_str()
            .unwrap()
            .contains("only on Windows"));
        #[cfg(windows)]
        assert!(result["error"]
            .as_str()
            .unwrap()
            .contains("native pre-connect preparation"));
        assert!(matches!(listener.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
    }
}

#[cfg(all(test, windows))]
mod windows_readiness_tests {
    use super::*;
    use std::{net::TcpListener, thread, time::Instant};

    #[test]
    fn pending_readiness_is_bounded_and_retryable_without_socket_timeouts() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (release, ready) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            ready.recv_timeout(Duration::from_secs(3)).unwrap();
            peer.write_all(b"after readiness timeouts").unwrap();
        });
        let stream = TcpStream::connect(address).unwrap();
        configure_native_socket(&stream).unwrap();
        assert_eq!(stream.read_timeout().unwrap(), None);
        assert_eq!(stream.write_timeout().unwrap(), None);
        for _ in 0..2 {
            let started = Instant::now();
            let error = wait_ready(&stream, true).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
            assert_eq!(io_result(Err(error)), -2);
            assert!(started.elapsed() >= Duration::from_millis(100));
            assert!(started.elapsed() < Duration::from_secs(1));
        }
        release.send(()).unwrap();
        let mut bytes = Vec::new();
        loop {
            if let Err(error) = wait_ready(&stream, true) {
                assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
                continue;
            }
            let mut buffer = [0u8; 64];
            match (&stream).read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&buffer[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(error) => panic!("nonblocking read failed: {error}"),
            }
        }
        assert_eq!(bytes, b"after readiness timeouts");
        worker.join().unwrap();
    }

    #[test]
    fn actual_windows_socket_timeout_is_fatal() {
        assert_eq!(io_result(Err(std::io::ErrorKind::TimedOut.into())), -1);
        assert_eq!(io_result(Err(std::io::ErrorKind::WouldBlock.into())), -2);
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GateInput {
    endpoint: Option<flowbridge_core::Endpoint>,
    ready: bool,
    #[serde(default = "default_gate_grace")]
    grace_ms: u64,
    #[serde(default)]
    limits: flowbridge_runtime::admission::Limits,
}
fn default_gate_grace() -> u64 {
    30000
}
/// # Safety
/// `gate_json` must be a live NUL-terminated UTF-8 string for this call.
#[no_mangle]
pub unsafe extern "C" fn fb_engine_set_upstream_gate_json(
    id: u64,
    gate_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let gate: GateInput =
            serde_json::from_str(unsafe { input(gate_json) }?).map_err(|e| e.to_string())?;
        with_engine(id, |engine| {
            Ok(
                json!({"ok":true,"status":engine.set_upstream_gate_with_limits(gate.endpoint,gate.ready,gate.grace_ms,gate.limits).map_err(|e|e.to_string())?}),
            )
        })
    })
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolInput {
    primary: flowbridge_core::Endpoint,
    workers: Vec<flowbridge_runtime::pool::WorkerInput>,
    limits: flowbridge_runtime::admission::Limits,
    aggregate_max_flows: usize,
}
/// Explicit managed SSH pool. No process is launched by this call: the GUI
/// must start and independently monitor each real OpenSSH child first.
/// Every flow remains pinned to one selected worker for its full lifetime.
/// # Safety
/// `pool_json` must reference a live NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn fb_engine_set_upstream_pool_json(
    id: u64,
    pool_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let pool: PoolInput =
            serde_json::from_str(unsafe { input(pool_json) }?).map_err(|e| e.to_string())?;
        with_engine(id, |engine| {
            Ok(
                json!({"ok":true,"status":engine.set_upstream_pool_with_limits(
                pool.primary,pool.workers,pool.limits,pool.aggregate_max_flows)
                .map_err(|e|e.to_string())?}),
            )
        })
    })
}

/// An owned-pool refresh derives availability and listener port from actual
/// registered SSH supervisor handles rather than trusting a caller-provided
/// "ready":true flag. It never launches or restarts an SSH process. The
/// caller repeats this operation after supervisor status changes.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedPoolInput {
    ssh_ids: Vec<u64>,
    limits: flowbridge_runtime::admission::Limits,
    aggregate_max_flows: usize,
    // A caller can withdraw admissions, never assert a child's readiness.
    // Keep the same budgets while paused; switching to a default single-child
    // gate would conflict with a pool's different per-worker limits.
    #[serde(default = "default_owned_pool_enabled")]
    enabled: bool,
}

fn default_owned_pool_enabled() -> bool {
    true
}

/// # Safety
/// `pool_json` must reference live NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn fb_engine_sync_owned_ssh_pool_json(
    id: u64,
    pool_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let pool: OwnedPoolInput =
            serde_json::from_str(unsafe { input(pool_json) }?).map_err(|e| e.to_string())?;
        if !(1..=4).contains(&pool.ssh_ids.len()) {
            return Err("owned SSH pool requires 1..=4 supervisor handles".into());
        }
        let mut unique = std::collections::HashSet::new();
        let mut workers = Vec::with_capacity(pool.ssh_ids.len());
        for ssh_id in &pool.ssh_ids {
            if !unique.insert(*ssh_id) {
                return Err("duplicate SSH supervisor handle in owned pool".into());
            }
            let status = with_ssh(*ssh_id, |supervisor| {
                serde_json::to_value(supervisor.snapshot().status)
                    .map_err(|error| error.to_string())
            })?;
            let port = status["local_port"]
                .as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .ok_or("invalid owned SSH supervisor listener port")?;
            let ready = pool.enabled
                && status["state"] == "ready"
                && status["pid"].as_u64().is_some_and(|pid| pid > 0);
            workers.push(flowbridge_runtime::pool::WorkerInput {
                endpoint: flowbridge_core::Endpoint {
                    host: "127.0.0.1".into(),
                    port,
                },
                ready,
            });
        }
        let primary = workers[0].endpoint.clone();
        with_engine(id, |engine| {
            let status = engine
                .set_upstream_pool_with_limits(
                    primary,
                    workers,
                    pool.limits,
                    pool.aggregate_max_flows,
                )
                .map_err(|e| e.to_string())?;
            Ok(json!({"ok":true,"status":status}))
        })
    })
}

struct SshSlot {
    supervisor: flowbridge_tunnel::Supervisor,
    gate: Mutex<()>,
    destroyed: AtomicBool,
}
fn ssh_supervisors() -> &'static Mutex<HashMap<u64, Arc<SshSlot>>> {
    static VALUE: OnceLock<Mutex<HashMap<u64, Arc<SshSlot>>>> = OnceLock::new();
    VALUE.get_or_init(|| Mutex::new(HashMap::new()))
}
fn ssh_json(snapshot: flowbridge_tunnel::Snapshot) -> Value {
    json!({"ok":true,"status":snapshot.status,"events":snapshot.events,"stderr":snapshot.stderr})
}
fn with_ssh(
    id: u64,
    work: impl FnOnce(&flowbridge_tunnel::Supervisor) -> Result<Value, String>,
) -> Result<Value, String> {
    let slot = locked(ssh_supervisors())
        .get(&id)
        .cloned()
        .ok_or("invalid SSH handle")?;
    let _gate = locked(&slot.gate);
    if slot.destroyed.load(Ordering::Acquire) {
        return Err("SSH supervisor destroyed".into());
    }
    work(&slot.supervisor)
}
/// Create a stopped managed-OpenSSH supervisor. The JSON contains settings only,
/// never passwords, private-key contents, or host-key acceptance overrides.
/// # Safety
/// `config_json` must be a live NUL-terminated UTF-8 string for this call.
#[no_mangle]
pub unsafe extern "C" fn fb_ssh_create_json(config_json: *const c_char) -> *mut c_char {
    guarded(|| {
        let supervisor = flowbridge_tunnel::Supervisor::from_json(unsafe { input(config_json) }?)
            .map_err(|e| e.to_string())?;
        let mut registry = locked(ssh_supervisors());
        if registry.len() >= 16 {
            return Err("SSH supervisor capacity reached".into());
        }
        let id = handle()?;
        registry.insert(
            id,
            Arc::new(SshSlot {
                supervisor,
                gate: Mutex::new(()),
                destroyed: AtomicBool::new(false),
            }),
        );
        Ok(json!({"ok":true,"ssh_id":id}))
    })
}
#[no_mangle]
pub extern "C" fn fb_ssh_start_json(id: u64) -> *mut c_char {
    guarded(|| {
        with_ssh(id, |supervisor| {
            supervisor.start().map(ssh_json).map_err(|e| e.to_string())
        })
    })
}
#[no_mangle]
pub extern "C" fn fb_ssh_stop_json(id: u64) -> *mut c_char {
    guarded(|| {
        with_ssh(id, |supervisor| {
            supervisor.stop().map(ssh_json).map_err(|e| e.to_string())
        })
    })
}
/// Fixed read-only remote resolver discovery. Stop can cancel it concurrently.
#[no_mangle]
pub extern "C" fn fb_ssh_remote_dns_json(id: u64) -> *mut c_char {
    guarded(|| {
        let slot = locked(ssh_supervisors())
            .get(&id)
            .cloned()
            .ok_or("invalid SSH handle")?;
        if slot.destroyed.load(Ordering::Acquire) {
            return Err("SSH supervisor destroyed".into());
        }
        let servers = slot
            .supervisor
            .remote_dns_servers()
            .map_err(|e| e.to_string())?;
        Ok(
            json!({"ok":true,"servers":servers,"source":"remote_resolv_conf","local_fallback":false}),
        )
    })
}
#[no_mangle]
pub extern "C" fn fb_ssh_snapshot_json(id: u64) -> *mut c_char {
    guarded(|| with_ssh(id, |supervisor| Ok(ssh_json(supervisor.snapshot()))))
}
#[no_mangle]
pub extern "C" fn fb_ssh_destroy(id: u64) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let slot = locked(ssh_supervisors()).remove(&id);
        if let Some(slot) = slot {
            let _gate = locked(&slot.gate);
            slot.destroyed.store(true, Ordering::Release);
            let _ = slot.supervisor.stop();
        }
    }));
}

#[cfg(test)]
mod ssh_and_gate_tests {
    use super::*;
    unsafe fn consume(pointer: *mut c_char) -> Value {
        let result =
            serde_json::from_str(unsafe { CStr::from_ptr(pointer) }.to_str().unwrap()).unwrap();
        unsafe { fb_string_free(pointer) };
        result
    }
    // These two tests share the same bounded global SSH supervisor registry.
    // Rust runs unit tests in parallel; holding the 16-slot test at the same
    // time as the owned-pool test can manufacture an unrelated capacity FAIL.
    // Serialize only the test fixtures, never the production supervisor.
    fn serial_ssh_registry_tests() -> std::sync::MutexGuard<'static, ()> {
        static GUARD: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        GUARD
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    #[test]
    fn ssh_registry_is_bounded_checked_and_destroy_safe_without_starting_network() {
        let _serial = serial_ssh_registry_tests();
        let invalid =
            CString::new(r#"{"host":"server","user":"alice","password":"forbidden"}"#).unwrap();
        assert_eq!(
            unsafe { consume(fb_ssh_create_json(invalid.as_ptr())) }["ok"],
            false
        );
        let config = CString::new(r#"{"host":"server.example","user":"alice"}"#).unwrap();
        let mut handles = Vec::new();
        for _ in 0..16 {
            let created = unsafe { consume(fb_ssh_create_json(config.as_ptr())) };
            assert_eq!(created["ok"], true);
            let id = created["ssh_id"].as_u64().unwrap();
            let snapshot = unsafe { consume(fb_ssh_snapshot_json(id)) };
            assert_eq!(snapshot["status"]["state"], "stopped");
            assert_eq!(snapshot["status"]["local_port"], 1080);
            handles.push(id);
        }
        assert_eq!(
            unsafe { consume(fb_ssh_create_json(config.as_ptr())) }["ok"],
            false
        );
        let id = handles[0];
        let reader = std::thread::spawn(move || {
            for _ in 0..50 {
                let result = unsafe { consume(fb_ssh_snapshot_json(id)) };
                assert!(result["ok"].is_boolean());
            }
        });
        fb_ssh_destroy(id);
        reader.join().unwrap();
        assert_eq!(unsafe { consume(fb_ssh_start_json(id)) }["ok"], false);
        for id in handles {
            fb_ssh_destroy(id);
            fb_ssh_destroy(id);
        }
        assert_eq!(unsafe { consume(fb_ssh_stop_json(0)) }["ok"], false);
        assert_eq!(unsafe { consume(fb_ssh_snapshot_json(0)) }["ok"], false);
    }
    #[test]
    fn pool_ffi_rejects_unsafe_workers_without_changing_last_valid_generation() {
        let config = CString::new(include_str!("../../../examples/ssh-socks.json")).unwrap();
        let engine = unsafe { consume(fb_engine_create_json(config.as_ptr())) };
        let id = engine["engine_id"].as_u64().unwrap();
        let value = json!({
            "primary":{"host":"127.0.0.1","port":1080},
            "workers":[
                {"endpoint":{"host":"127.0.0.1","port":1080},"ready":true},
                {"endpoint":{"host":"127.0.0.1","port":1082},"ready":false}
            ],
            "limits":{"max_flows":2,"max_opening":1,"max_queued":2,"wait_timeout_ms":100},
            "aggregate_max_flows":4
        });
        let input = CString::new(value.to_string()).unwrap();
        assert_eq!(
            unsafe { consume(fb_engine_set_upstream_pool_json(id, input.as_ptr())) }["ok"],
            true
        );
        let snapshot = unsafe { consume(fb_engine_snapshot_json(id)) };
        assert_eq!(snapshot["managed_pool"]["ready_workers"], 1);
        assert_eq!(snapshot["managed_pool"]["workers"][1]["ready"], false);
        for bad in [
            json!({"invalid":true}),
            json!({"primary":{"host":"127.0.0.1","port":1080},
                "workers":[{"endpoint":{"host":"127.0.0.1","port":1080},"ready":true},
                           {"endpoint":{"host":"127.0.0.1","port":1080},"ready":true}],
                "limits":{"max_flows":2,"max_opening":1,"max_queued":2,"wait_timeout_ms":100},
                "aggregate_max_flows":4}),
            json!({"primary":{"host":"127.0.0.1","port":1080},
                "workers":[{"endpoint":{"host":"127.0.0.1","port":1080},"ready":true},
                           {"endpoint":{"host":"127.0.0.1","port":1082},"ready":true}],
                "limits":{"max_flows":2,"max_opening":1,"max_queued":2,"wait_timeout_ms":100},
                "aggregate_max_flows":3}),
        ] {
            let arg = CString::new(bad.to_string()).unwrap();
            assert_eq!(
                unsafe { consume(fb_engine_set_upstream_pool_json(id, arg.as_ptr())) }["ok"],
                false
            );
            let after = unsafe { consume(fb_engine_snapshot_json(id)) };
            assert_eq!(after["managed_pool"]["ready_workers"], 1);
        }
        fb_engine_destroy(id);
    }

    #[test]
    fn owned_pool_cannot_claim_stopped_ssh_is_ready_or_accept_stale_handles() {
        let _serial = serial_ssh_registry_tests();
        let profile = CString::new(include_str!("../../../examples/ssh-socks.json")).unwrap();
        let engine = unsafe { consume(fb_engine_create_json(profile.as_ptr())) };
        let id = engine["engine_id"].as_u64().unwrap();
        let first =
            CString::new(r#"{"host":"test.invalid","user":"qa","local_port":1080}"#).unwrap();
        let second =
            CString::new(r#"{"host":"test.invalid","user":"qa","local_port":1082}"#).unwrap();
        let a = unsafe { consume(fb_ssh_create_json(first.as_ptr())) }["ssh_id"]
            .as_u64()
            .unwrap();
        let b = unsafe { consume(fb_ssh_create_json(second.as_ptr())) }["ssh_id"]
            .as_u64()
            .unwrap();
        let payload = json!({
            "ssh_ids":[a,b],
            "limits":{"max_flows":2,"max_opening":1,"max_queued":2,"wait_timeout_ms":100},
            "aggregate_max_flows":4
        });
        let arg = CString::new(payload.to_string()).unwrap();
        assert_eq!(
            unsafe { consume(fb_engine_sync_owned_ssh_pool_json(id, arg.as_ptr())) }["ok"],
            true
        );
        let state = unsafe { consume(fb_engine_snapshot_json(id)) };
        assert_eq!(state["managed_pool"]["ready_workers"], 0);
        assert_eq!(state["managed_pool"]["workers"][0]["ready"], false);
        assert_eq!(
            state["managed_pool"]["workers"][1]["endpoint"]["port"],
            1082
        );
        for bad in [
            json!({"ssh_ids":[a,a],"limits":payload["limits"],"aggregate_max_flows":4}),
            json!({"ssh_ids":[a,0],"limits":payload["limits"],"aggregate_max_flows":4}),
            json!({"ssh_ids":[],"limits":payload["limits"],"aggregate_max_flows":4}),
            json!({"ssh_ids":[a,b],"limits":payload["limits"],"aggregate_max_flows":3}),
            json!({"ssh_ids":[a,b],"limits":payload["limits"],"aggregate_max_flows":4,"enabled":"yes"}),
            json!({"ssh_ids":[a,b],"limits":payload["limits"],"aggregate_max_flows":4,"ready":true}),
        ] {
            let value = CString::new(bad.to_string()).unwrap();
            assert_eq!(
                unsafe { consume(fb_engine_sync_owned_ssh_pool_json(id, value.as_ptr())) }["ok"],
                false
            );
            let unchanged = unsafe { consume(fb_engine_snapshot_json(id)) };
            assert_eq!(unchanged["managed_pool"]["ready_workers"], 0);
        }
        fb_ssh_destroy(b);
        assert_eq!(
            unsafe { consume(fb_engine_sync_owned_ssh_pool_json(id, arg.as_ptr())) }["ok"],
            false
        );
        fb_ssh_destroy(a);
        fb_engine_destroy(id);
    }

    #[test]
    fn gate_ffi_validates_strict_input_and_checked_engine_handles() {
        let config = CString::new(include_str!("../../../examples/direct.json")).unwrap();
        let engine = unsafe { consume(fb_engine_create_json(config.as_ptr())) };
        let id = engine["engine_id"].as_u64().unwrap();
        for value in [
            json!({"endpoint":{"host":"203.0.113.1","port":1080},"ready":false}),
            json!({"endpoint":null,"ready":true,"grace_ms":120001}),
            json!({"endpoint":null,"ready":true,"unexpected":true}),
        ] {
            let value = CString::new(value.to_string()).unwrap();
            assert_eq!(
                unsafe { consume(fb_engine_set_upstream_gate_json(id, value.as_ptr())) }["ok"],
                false
            );
        }
        // Use a test-only endpoint outside the other FFI pool fixtures
        // (which reserve 127.0.0.1:1080 and :1082). Pool admission budgets
        // are intentionally shared across engines in production; unrelated
        // parallel tests must not compete for the same endpoint.
        let value =
            CString::new(r#"{"endpoint":{"host":"127.0.0.1","port":11983},"ready":false}"#).unwrap();
        assert_eq!(
            unsafe { consume(fb_engine_set_upstream_gate_json(id, value.as_ptr())) }["ok"],
            true
        );
        fb_engine_destroy(id);
        assert_eq!(
            unsafe { consume(fb_engine_set_upstream_gate_json(id, value.as_ptr())) }["ok"],
            false
        );
    }
}
