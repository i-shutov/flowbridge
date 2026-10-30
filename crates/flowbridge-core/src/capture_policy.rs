//! Original, independent routing gates for a future Rust NDISAPI capture worker.
//! No ProxiFyre code is used. OS process identity MUST be attested by a native
//! resolver, not supplied by a GUI profile. This module does not capture packets.
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Other,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Proxy,
    Direct,
    Block,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Selected,
    Unselected,
    NoProxy,
    UdpUnsupported,
    UnknownOwner,
    Carrier,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub route: Route,
    pub reason: Reason,
}
#[derive(Debug, Clone, Copy)]
pub enum Process<'a> {
    /// Path verified by OS process ownership evidence, not user input.
    Attested(&'a str),
    Unknown,
}
pub struct CapturePolicy {
    selected: BTreeSet<String>,
    strict_unknown: bool,
    strict_udp: bool,
}
fn normalize(path: &str) -> Result<String, &'static str> {
    let p = path.replace('/', "\\");
    let b = p.as_bytes();
    if b.len() < 8 || b.len() > 4096 || !b[0].is_ascii_alphabetic() || b[1] != b':' || b[2] != b'\\'
    {
        return Err("expected absolute Windows drive path");
    }
    if p.chars()
        .any(|c| c.is_control() || matches!(c, '*' | '?' | '"' | '<' | '>' | '|'))
    {
        return Err("unsupported path character");
    }
    let parts: Vec<&str> = p[3..].split('\\').collect();
    if parts.iter().any(|part| {
        part.is_empty()
            || *part == "."
            || *part == ".."
            || part.ends_with(' ')
            || part.ends_with('.')
            || part.contains(':')
    }) {
        return Err("ambiguous path component");
    }
    if !parts
        .last()
        .is_some_and(|p| p.len() > 4 && p.to_ascii_lowercase().ends_with(".exe"))
    {
        return Err("not an executable");
    }
    Ok(p.to_lowercase())
}
fn carrier(path: &str) -> bool {
    matches!(
        path.rsplit('\\').next().unwrap_or(""),
        "flowbridge.exe" | "flowbridgecapture.exe" | "ssh.exe" | "proxifyre.exe"
    )
}
impl CapturePolicy {
    pub fn new(
        paths: &[String],
        strict_unknown: bool,
        strict_udp: bool,
    ) -> Result<Self, &'static str> {
        if paths.is_empty() || paths.len() > 64 {
            return Err("select 1..64 EXEs");
        }
        let mut selected = BTreeSet::new();
        for path in paths {
            let p = normalize(path)?;
            if carrier(&p) {
                return Err("carrier process cannot be proxied");
            }
            if !selected.insert(p) {
                return Err("duplicate process");
            }
        }
        Ok(Self {
            selected,
            strict_unknown,
            strict_udp,
        })
    }
    /// Identity/transport-only decision: actual destination policy remains
    /// in Config::evaluate. Proxy is NOT proof of a connected upstream socket.
    pub fn route(&self, owner: Process<'_>, protocol: Protocol, ready: bool) -> Verdict {
        let path = match owner {
            Process::Unknown => {
                return Verdict {
                    route: if self.strict_unknown {
                        Route::Block
                    } else {
                        Route::Direct
                    },
                    reason: Reason::UnknownOwner,
                };
            }
            Process::Attested(raw) => match normalize(raw) {
                Ok(p) => p,
                Err(_) => {
                    return Verdict {
                        route: Route::Block,
                        reason: Reason::UnknownOwner,
                    }
                }
            },
        };
        if carrier(&path) {
            return Verdict {
                route: Route::Direct,
                reason: Reason::Carrier,
            };
        }
        if !self.selected.contains(&path) {
            return Verdict {
                route: Route::Direct,
                reason: Reason::Unselected,
            };
        }
        match protocol {
            Protocol::Tcp if ready => Verdict {
                route: Route::Proxy,
                reason: Reason::Selected,
            },
            Protocol::Tcp => Verdict {
                route: Route::Block,
                reason: Reason::NoProxy,
            },
            Protocol::Udp => Verdict {
                route: if self.strict_udp {
                    Route::Block
                } else {
                    Route::Direct
                },
                reason: Reason::UdpUnsupported,
            },
            Protocol::Other => Verdict {
                route: Route::Block,
                reason: Reason::UdpUnsupported,
            },
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn p(strict: bool) -> CapturePolicy {
        CapturePolicy::new(&[r"C:\Apps\Browser.exe".into()], strict, strict).unwrap()
    }
    #[test]
    fn selected_tcp_requires_real_readiness() {
        let app = Process::Attested(r"c:\apps\BROWSER.EXE");
        assert_eq!(p(true).route(app, Protocol::Tcp, true).route, Route::Proxy);
        assert_eq!(p(true).route(app, Protocol::Tcp, false).route, Route::Block);
    }
    #[test]
    fn only_selected_exact_path_is_routed() {
        for path in [r"C:\Different\Browser.exe", r"C:\Apps\BadBrowser.exe"] {
            assert_eq!(
                p(true)
                    .route(Process::Attested(path), Protocol::Tcp, true)
                    .route,
                Route::Direct
            );
        }
    }
    #[test]
    fn carriers_are_never_diverted() {
        for name in ["ssh.exe", "FlowBridge.exe", "ProxiFyre.exe"] {
            let path = format!(r"C:\Windows\System32\{name}");
            assert_eq!(
                p(true)
                    .route(Process::Attested(&path), Protocol::Tcp, true)
                    .reason,
                Reason::Carrier
            );
            assert!(CapturePolicy::new(&[path], true, true).is_err());
        }
    }
    #[test]
    fn unknown_owner_is_explicitly_blocked_in_strict_mode() {
        assert_eq!(
            p(true).route(Process::Unknown, Protocol::Tcp, true).route,
            Route::Block
        );
        assert_eq!(
            p(false).route(Process::Unknown, Protocol::Tcp, true).route,
            Route::Direct
        );
    }
    #[test]
    fn udp_not_mistaken_for_ssh_tcp() {
        let app = Process::Attested(r"C:\Apps\Browser.exe");
        assert_eq!(p(true).route(app, Protocol::Udp, true).route, Route::Block);
        assert_eq!(
            p(false).route(app, Protocol::Udp, true).route,
            Route::Direct
        );
        assert_eq!(
            p(false).route(app, Protocol::Other, true).route,
            Route::Block
        );
    }
    #[test]
    fn malformed_owner_identity_fails_closed() {
        for path in [
            "browser.exe",
            r"\\server\share\browser.exe",
            r"C:\Apps\..\browser.exe",
            r"C:\Apps\evil?.exe",
            "",
        ] {
            assert_eq!(
                p(false)
                    .route(Process::Attested(path), Protocol::Tcp, true)
                    .route,
                Route::Block
            );
        }
    }
    #[test]
    fn invalid_or_duplicate_exe_selection_is_rejected() {
        for path in [
            "browser.exe",
            r"C:\Apps\..\browser.exe",
            r"C:\Apps\browser?.exe",
        ] {
            assert!(CapturePolicy::new(&[path.into()], true, true).is_err());
        }
        assert!(CapturePolicy::new(
            &[r"C:\Apps\Browser.exe".into(), r"c:\apps\BROWSER.EXE".into()],
            true,
            true
        )
        .is_err());
    }
}
