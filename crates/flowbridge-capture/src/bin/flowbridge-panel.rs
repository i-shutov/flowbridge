//! Native Windows, same-user operator panel for the original Rust SSH/SOCKS candidate.
//! It controls ONLY the restricted local pipe. It cannot activate NDISRD,
//! authenticate arbitrary packet ownership, or claim protected fail-closed.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("FlowBridge Rust panel requires Windows; protected capture is unavailable");
    std::process::exit(1);
}

#[cfg(windows)]
mod panel {
    use flowbridge_capture::control_plane;
    use serde_json::Value;
    use std::path::PathBuf;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect,
        GetDlgItem, GetMessageW, GetWindowTextLengthW, GetWindowTextW, MessageBoxW, MoveWindow,
        PostMessageW, PostQuitMessage, RegisterClassW, SetWindowTextW, ShowWindow,
        TranslateMessage, CW_USEDEFAULT, ES_AUTOHSCROLL, ES_AUTOVSCROLL, ES_MULTILINE, ES_READONLY,
        IDYES, MB_ICONWARNING, MB_YESNO, MSG, SW_SHOW, WM_APP, WM_CLOSE, WM_COMMAND, WM_CREATE,
        WM_DESTROY, WM_SIZE, WNDCLASSW, WS_BORDER, WS_CHILD, WS_CLIPCHILDREN, WS_OVERLAPPEDWINDOW,
        WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
    };

    const WINDOW_CLASS: &str = "FlowBridgeRustPanelV1";
    const ID_PATH: i32 = 101;
    const ID_START: i32 = 102;
    const ID_REFRESH: i32 = 103;
    const ID_RELOAD: i32 = 104;
    const ID_STOP: i32 = 105;
    const ID_STATUS: i32 = 106;
    const STATUS_CHANGED: u32 = WM_APP + 1;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    static WINDOW: AtomicIsize = AtomicIsize::new(0);
    static BUSY: AtomicBool = AtomicBool::new(false);
    static RESPONSE: Mutex<Option<String>> = Mutex::new(None);

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    fn child(
        parent: HWND,
        kind: &str,
        label: &str,
        id: i32,
        style: u32,
        bounds: (i32, i32, i32, i32),
    ) -> HWND {
        let (x, y, w, h) = bounds;
        let kind = wide(kind);
        let label = wide(label);
        // SAFETY: The parent belongs to the current UI thread; Windows copies
        // both terminating UTF-16 strings during synchronous control creation.
        unsafe {
            CreateWindowExW(
                0,
                kind.as_ptr(),
                label.as_ptr(),
                WS_CHILD | WS_VISIBLE | style,
                x,
                y,
                w,
                h,
                parent,
                id as usize as _,
                GetModuleHandleW(null()),
                null(),
            )
        }
    }

    fn control(parent: HWND, id: i32) -> HWND {
        // SAFETY: Child IDs are fixed constants created by this UI thread.
        unsafe { GetDlgItem(parent, id) }
    }

    fn set_text(parent: HWND, id: i32, value: &str) {
        let wide = wide(value);
        // SAFETY: Windows copies the NUL-terminated UTF-16 string.
        unsafe { SetWindowTextW(control(parent, id), wide.as_ptr()) };
    }

    fn path_from_edit(parent: HWND) -> Result<PathBuf, &'static str> {
        let edit = control(parent, ID_PATH);
        // SAFETY: This is the user's own standard EDIT control.
        let length = unsafe { GetWindowTextLengthW(edit) };
        if !(1..=2048).contains(&length) {
            return Err("Choose an existing absolute JSON profile (max 2048 characters).");
        }
        let mut chars = vec![0u16; length as usize + 1];
        // SAFETY: Capacity includes the trailing NUL. GetWindowTextW bounds writes.
        let copied = unsafe { GetWindowTextW(edit, chars.as_mut_ptr(), chars.len() as i32) };
        if copied <= 0 || copied > length {
            return Err("Profile path is unavailable.");
        }
        let value = String::from_utf16(&chars[..copied as usize])
            .map_err(|_| "Profile path is not valid Unicode.")?;
        let path = PathBuf::from(value.trim());
        if !path.is_absolute()
            || !path.is_file()
            || !path.extension().is_some_and(|ext| {
                ext.to_str()
                    .is_some_and(|value| value.eq_ignore_ascii_case("json"))
            })
        {
            return Err("Profile must be an existing absolute .json file.");
        }
        Ok(path)
    }

    fn status_text(value: &Value) -> String {
        let engine = &value["engine"];
        let running = engine["running"] == true;
        let ssh = &value["managed_ssh"];
        let ssh_status = if ssh.is_null() {
            "not configured (explicit SOCKS only)".to_owned()
        } else {
            format!(
                "{} (gate ready: {})",
                ssh["state"].as_str().unwrap_or("unknown"),
                value["managed_ssh_gate_ready"] == true
            )
        };
        format!(
            "RUST SOCKS / SSH CANDIDATE\r\n\r\n\
             SOCKS engine: {}\r\n\
             Listener: {}\r\n\
             SSH: {}\r\n\
             Active flows: {}\r\n\
             Accepted: {}     Completed: {}     Failed: {}\r\n\
             Config generation: {}\r\n\r\n\
             NDISRD packet interception: NOT ACTIVE\r\n\
             Arbitrary application identity: NOT VERIFIED\r\n\
             Persistent protected fail-closed: NOT AVAILABLE\r\n\
             DNS/UDP/IPv6 leak-free: NOT PROVEN\r\n\
             Windows 10/11 native acceptance: NOT PERFORMED\r\n\
             Production release: NOT APPROVED",
            if running { "RUNNING" } else { "STOPPED" },
            engine["listen"].as_str().unwrap_or("unavailable"),
            ssh_status,
            engine["active"],
            engine["accepted"],
            engine["completed"],
            engine["failed"],
            engine["generation"],
        )
    }

    fn start_agent(path: PathBuf) -> Result<Value, &'static str> {
        use std::os::windows::process::CommandExt;
        if control_plane::command("status").is_ok() {
            return Err("An agent already owns the local control pipe. Use Refresh.");
        }
        let exe = std::env::current_exe().map_err(|_| "Panel executable is unavailable.")?;
        let agent = exe.with_file_name("flowbridge-agent.exe");
        if !agent.is_file() || agent.is_symlink() {
            return Err("Original Rust agent is missing or is a link.");
        }
        // Spawn the verified sibling name with separated arguments, never via
        // cmd.exe or elevated service. The agent strictly validates the profile.
        let mut child = std::process::Command::new(&agent)
            .arg("control-serve")
            .arg(&path)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|_| "Could not start the same-user Rust agent.")?;
        for _ in 0..50 {
            if let Ok(report) = control_plane::command("status") {
                return Ok(report);
            }
            if child
                .try_wait()
                .map_err(|_| "Agent startup status is unavailable.")?
                .is_some()
            {
                return Err("Agent exited: check the JSON profile and SSH prerequisites.");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // A partially started agent must not outlive a failed Start action.
        // On Windows the managed SSH supervisor owns its child job.
        let _ = child.kill();
        let _ = child.wait();
        Err("Agent did not open its restricted control pipe.")
    }

    fn launch(action: &'static str, path: Option<PathBuf>) {
        if BUSY.swap(true, Ordering::AcqRel) {
            return;
        }
        std::thread::spawn(move || {
            let result = match action {
                "start" => start_agent(path.expect("UI validated profile before dispatch")),
                "status" | "reload" | "stop" => control_plane::command(action)
                    .map_err(|_| "Local Rust agent unavailable or command rejected."),
                _ => Err("Unsupported operator action."),
            };
            let text = match result {
                Ok(status) if action == "stop" => format!(
                    "Stop requested; local proxy is no longer managed by this panel.\r\n\r\n{}",
                    status_text(&status)
                ),
                Ok(status) => status_text(&status),
                Err(error) => format!(
                    "OPERATION: {}\r\n{}\r\n\r\n\
                     No driver protection has been enabled by this panel.\r\n\
                     This candidate must NOT be treated as a system-wide kill switch.",
                    action, error
                ),
            };
            if let Ok(mut guard) = RESPONSE.lock() {
                *guard = Some(text);
            }
            // SAFETY: An old HWND may have been destroyed; PostMessageW then
            // fails harmlessly. The UI thread owns all actual control mutation.
            let hwnd = WINDOW.load(Ordering::Acquire) as HWND;
            if !hwnd.is_null() {
                unsafe { PostMessageW(hwnd, STATUS_CHANGED, 0, 0) };
            }
            BUSY.store(false, Ordering::Release);
        });
    }

    fn create_controls(window: HWND) {
        child(
            window,
            "STATIC",
            "FlowBridge  |  Windows Rust operator panel",
            0,
            0,
            (18, 13, 740, 26),
        );
        child(
            window,
            "STATIC",
            "Experimental SSH/SOCKS only. NO protected interception or DNS privacy guarantee.",
            0,
            0,
            (18, 43, 790, 24),
        );
        child(
            window,
            "STATIC",
            "Explicit JSON profile:",
            0,
            0,
            (18, 78, 155, 24),
        );
        let default_profile = std::env::var_os("LOCALAPPDATA")
            .map(|root| PathBuf::from(root).join("FlowBridge").join("profile.json"))
            .unwrap_or_default();
        child(
            window,
            "EDIT",
            &default_profile.to_string_lossy(),
            ID_PATH,
            WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL as u32,
            (177, 75, 610, 27),
        );
        child(
            window,
            "BUTTON",
            "Start",
            ID_START,
            WS_TABSTOP,
            (18, 116, 130, 32),
        );
        child(
            window,
            "BUTTON",
            "Refresh",
            ID_REFRESH,
            WS_TABSTOP,
            (157, 116, 130, 32),
        );
        child(
            window,
            "BUTTON",
            "Reload",
            ID_RELOAD,
            WS_TABSTOP,
            (296, 116, 130, 32),
        );
        child(
            window,
            "BUTTON",
            "Stop",
            ID_STOP,
            WS_TABSTOP,
            (435, 116, 130, 32),
        );
        child(
            window,
            "EDIT",
            "Checking the local agent...\r\nNo protected application routing is available.",
            ID_STATUS,
            WS_BORDER
                | WS_VSCROLL
                | ES_MULTILINE as u32
                | ES_READONLY as u32
                | ES_AUTOVSCROLL as u32,
            (18, 162, 769, 426),
        );
    }

    unsafe extern "system" fn window_proc(
        window: HWND,
        msg: u32,
        wp: WPARAM,
        lp: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_CREATE => {
                WINDOW.store(window as isize, Ordering::Release);
                create_controls(window);
                launch("status", None);
                0
            }
            WM_SIZE => {
                let mut bounds = unsafe { std::mem::zeroed() };
                // SAFETY: Window owns the client area and its status control.
                if unsafe { GetClientRect(window, &mut bounds) } != 0 {
                    let width = (bounds.right - bounds.left - 36).max(420);
                    let height = (bounds.bottom - bounds.top - 179).max(160);
                    unsafe {
                        MoveWindow(
                            control(window, ID_PATH),
                            177,
                            75,
                            (width - 159).max(220),
                            27,
                            1,
                        );
                        MoveWindow(control(window, ID_STATUS), 18, 162, width, height, 1);
                    }
                }
                0
            }
            WM_COMMAND if ((wp >> 16) as u16) == 0 => {
                match (wp as u16) as i32 {
                    ID_START => match path_from_edit(window) {
                        Ok(path) => launch("start", Some(path)),
                        Err(error) => set_text(window, ID_STATUS, error),
                    },
                    ID_REFRESH => launch("status", None),
                    ID_RELOAD => launch("reload", None),
                    ID_STOP => {
                        let explanation = wide(
                            "Stop the current same-user Rust SOCKS/SSH agent?\n\
                             This DOES NOT activate a firewall or protected mode.",
                        );
                        let title = wide("FlowBridge candidate - stop");
                        // SAFETY: Modal confirmation is attached to this panel only.
                        let approved = unsafe {
                            MessageBoxW(
                                window,
                                explanation.as_ptr(),
                                title.as_ptr(),
                                MB_YESNO | MB_ICONWARNING,
                            )
                        };
                        if approved == IDYES {
                            launch("stop", None);
                        }
                    }
                    _ => {}
                }
                0
            }
            STATUS_CHANGED => {
                if let Ok(mut guard) = RESPONSE.lock() {
                    if let Some(message) = guard.take() {
                        set_text(window, ID_STATUS, &message);
                    }
                }
                0
            }
            WM_CLOSE => {
                // Closing the panel does not silently kill the user's explicit
                // SOCKS agent. Stop is a separate confirmed control action.
                unsafe { DestroyWindow(window) };
                0
            }
            WM_DESTROY => {
                WINDOW.store(0, Ordering::Release);
                unsafe { PostQuitMessage(0) };
                0
            }
            _ => unsafe { DefWindowProcW(window, msg, wp, lp) },
        }
    }

    pub fn run() -> Result<(), &'static str> {
        let class = wide(WINDOW_CLASS);
        let title = wide("FlowBridge Rust Candidate - NOT PROTECTED");
        // SAFETY: Window class/instance/strings are valid for synchronous
        // registration and creation in the owning UI thread.
        let instance = unsafe { GetModuleHandleW(null()) };
        let settings = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: class.as_ptr(),
            // Win32 COLOR_WINDOW + 1, expressed as a system-color brush handle.
            hbrBackground: 6_usize as _,
            ..unsafe { std::mem::zeroed() }
        };
        if unsafe { RegisterClassW(&settings) } == 0 {
            return Err("Window class registration failed");
        }
        let window = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                title.as_ptr(),
                WS_OVERLAPPEDWINDOW | WS_VISIBLE | WS_CLIPCHILDREN,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                830,
                650,
                null_mut(),
                null_mut(),
                instance,
                null(),
            )
        };
        if window.is_null() {
            return Err("Window creation failed");
        }
        unsafe {
            ShowWindow(window, SW_SHOW);
        }
        let mut message: MSG = unsafe { std::mem::zeroed() };
        loop {
            let ready = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
            if ready <= 0 {
                break;
            }
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
fn main() {
    // The GUI never launches NDISRD, installs an SCM service or elevates.
    if let Err(_failure) = panel::run() {
        std::process::exit(1);
    }
}
