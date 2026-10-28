from pathlib import Path

def edit(path, old, new):
    p=Path(path);s=p.read_text(encoding='utf-8')
    if s.count(old)!=1:raise RuntimeError(f'{path}: match count {s.count(old)}')
    p.write_text(s.replace(old,new),encoding='utf-8')

p='crates/flowbridge-ffi/src/lib.rs'
edit(p,'mod native_context;','mod native_context;\nmod native_dns;')
edit(p,'#[no_mangle]\npub extern "C" fn fb_ssh_snapshot_json',r'''/// Fixed read-only remote resolver discovery. Stop can cancel it concurrently.
#[no_mangle]
pub extern "C" fn fb_ssh_remote_dns_json(id: u64) -> *mut c_char {
    guarded(|| {
        let slot = locked(ssh_supervisors()).get(&id).cloned().ok_or("invalid SSH handle")?;
        if slot.destroyed.load(Ordering::Acquire) { return Err("SSH supervisor destroyed".into()); }
        let servers = slot.supervisor.remote_dns_servers().map_err(|e|e.to_string())?;
        Ok(json!({"ok":true,"servers":servers,"source":"remote_resolv_conf","local_fallback":false}))
    })
}
#[no_mangle]
pub extern "C" fn fb_ssh_snapshot_json''')
p='crates/flowbridge-ffi/src/native_context.rs'
edit(p,'    limits: Limits,','    limits: Limits,\n    dns: Option<super::native_dns::Options>,')
edit(p,'            limits: Limits::default(),','            limits: Limits::default(),\n            dns: None,')
edit(p,'    config: Mutex<Config>,','    config: Mutex<Config>,\n    dns_server: Mutex<Option<super::native_dns::Server>>,')
edit(p,'fn session(id: u64)', 'pub(super) fn session(id: u64)')
edit(p,'        let max_flows = config.max_connections.min(1024);',r'''        if let Some(dns) = &options.dns {
            dns.validate()?;
            let endpoint = options.managed_endpoint.as_ref().ok_or("Remote DNS requires a managed SSH endpoint")?;
            if !config.proxies.iter().any(|p| normalized(&p.endpoint) == normalized(endpoint)
                && matches!(p.kind, flowbridge_core::ProxyKind::Socks5)) {
                return Err("Remote DNS requires the managed SOCKS5 SSH route".into());
            }
        }
        let max_flows = config.max_connections.min(1024);''')
edit(p,'            config: Mutex::new(config),','            config: Mutex::new(config),\n            dns_server: Mutex::new(None),')
edit(p,'    pub fn config(&self) -> Result<Config, String> {',r'''    pub async fn dns_query(self: &Arc<Self>, query: Vec<u8>) -> Result<Vec<u8>, String> {
        super::native_dns::validate_query(&query)?;
        let dns = self.options.dns.clone().ok_or("Remote DNS is disabled in this native session")?;
        let config = self.config()?;
        let endpoint = self.options.managed_endpoint.as_ref().ok_or("Managed DNS route is unavailable")?;
        let proxy = config.proxies.iter().find(|p| normalized(&p.endpoint) == normalized(endpoint)
            && matches!(p.kind, flowbridge_core::ProxyKind::Socks5))
            .cloned().ok_or("Managed DNS route is absent")?;
        let work = async {
            let route = vec![proxy];
            let mut lease = self.admit(&route).await?;
            self.recheck(&route)?;
            let stream = connect_route_guarded(&dns.resolver,&route,
                Duration::from_millis(config.connect_timeout_ms),
                Duration::from_millis(config.handshake_timeout_ms),config.listen).await.map_err(|e| e.to_string())?;
            self.recheck(&route)?;
            lease.connected();
            let answer = super::native_dns::exchange(stream,&query).await?;
            lease.progress(true,query.len()+2);lease.progress(false,answer.len()+2);
            Ok::<_,String>(answer)
        };
        tokio::select! { biased;
            _ = self.cancelled() => Err("Native DNS stopped".into()),
            result = tokio::time::timeout(Duration::from_millis(dns.timeout_ms),work) =>
                result.map_err(|_| "Remote DNS deadline expired; local fallback disabled".to_string())?
        }
    }
    pub fn dns_exchange(self: &Arc<Self>, query: Vec<u8>) -> Result<Vec<u8>, String> {
        let session = self.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
            runtime.block_on(session.dns_query(query))
        }).join().map_err(|_| "Native DNS worker panicked".to_string())?
    }
    pub fn start_dns(self: &Arc<Self>, listen: std::net::SocketAddr) -> Result<Value,String> {
        if self.options.dns.is_none() || self.stopped.load(Ordering::Acquire) {
            return Err("Native DNS is disabled or the session stopped".into());
        }
        let mut slot = locked(&self.dns_server);
        if slot.is_some() { return Err("Native DNS listener is already running".into()); }
        let server=super::native_dns::Server::start(self.clone(),listen)?;
        let result=json!({"ok":true,"listen":server.listen.to_string(),"system_dns_modified":false});
        *slot=Some(server);
        Ok(result)
    }
    pub fn stop_dns(&self) { let server=locked(&self.dns_server).take(); drop(server); }
    pub fn config(&self) -> Result<Config, String> {''')
edit(p,'        session.cancel.send_replace(true);','        session.cancel.send_replace(true);\n        session.stop_dns();')
p='crates/flowbridge-tunnel/src/lib.rs'
edit(p,'    /// Arguments are passed directly to OpenSSH; no command shell is involved.',r'''    fn dns_discovery_arguments(&self) -> Vec<String> {
        let mut source = self.arguments().into_iter();
        let mut args = Vec::new();
        while let Some(arg) = source.next() {
            if arg == "-N" { continue; }
            if arg == "-D" { source.next(); continue; }
            args.push(arg);
        }
        args.push("printf 'FLOWBRIDGE_DNS_BEGIN\\n' >&2; cat /etc/resolv.conf >&2; printf '\\nFLOWBRIDGE_DNS_END\\n' >&2".into());
        args
    }
    /// Arguments are passed directly to OpenSSH; no command shell is involved.''')
edit(p,'    pub fn snapshot(&self) -> Snapshot {',r'''    /// Read the remote POSIX resolver configuration through authenticated SSH.
    /// This is a fixed read-only command, not a shell command supplied by the UI.
    pub fn remote_dns_servers(&self) -> Result<Vec<String>, TunnelError> {
        let snapshot = self.snapshot();
        if snapshot.status.state != "ready" { return Err(TunnelError("SSH must be ready before DNS discovery".into())); }
        let executable = snapshot.status.backend_path.ok_or_else(|| TunnelError("SSH executable is unknown".into()))?;
        let control = lock(&self.running).as_ref().map(|worker| worker.control.clone())
            .ok_or_else(|| TunnelError("SSH is stopped".into()))?;
        let mut command = Command::new(executable);
        command.args(self.config.dns_discovery_arguments());
        let mut child = ChildGuard::spawn(command)?;
        let mut pipe = child.child.stderr.take().ok_or_else(|| TunnelError("DNS discovery output unavailable".into()))?;
        prepare_stderr(&pipe)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut output = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            if control.cancelled() { return Err(TunnelError("DNS discovery cancelled".into())); }
            if Instant::now() >= deadline { return Err(TunnelError("Remote DNS discovery timed out".into())); }
            match read_stderr(&mut pipe,&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    output.extend_from_slice(&chunk[..n]);
                    if output.len()>32768 { return Err(TunnelError("Remote DNS configuration exceeds 32 KiB".into())); }
                }
                Err(e) if e.kind()==io::ErrorKind::WouldBlock => {
                    if matches!(child.child.try_wait(),Ok(Some(_))) { break; }
                    control.wait(Duration::from_millis(20));
                }
                Err(e) if e.kind()==io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind()==io::ErrorKind::BrokenPipe => break,
                Err(e) => return Err(e.into()),
            }
        }
        let result = parse_resolvers(&String::from_utf8_lossy(&output));
        child.terminate();
        result
    }
    pub fn snapshot(&self) -> Snapshot {''')
edit(p,'fn resolve_ssh() -> io::Result<std::path::PathBuf> {',r'''fn parse_resolvers(output: &str) -> Result<Vec<String>, TunnelError> {
    let data = output.split_once("FLOWBRIDGE_DNS_BEGIN\n")
        .and_then(|(_,tail)| tail.split_once("FLOWBRIDGE_DNS_END"))
        .map(|(data,_)|data).ok_or_else(|| TunnelError("Remote host did not return a POSIX resolver file; configure its DNS resolver IP explicitly".into()))?;
    let mut result = Vec::new();
    for line in data.lines() {
        let mut words = line.split_whitespace();
        if words.next()!=Some("nameserver") { continue; }
        let Some(ip) = words.next().and_then(|v|v.parse::<std::net::IpAddr>().ok()) else { continue; };
        if ip.is_unspecified() || ip.is_multicast() { continue; }
        let address = ip.to_string();
        if !result.contains(&address) { result.push(address); }
        if result.len()==3 { break; }
    }
    if result.is_empty() { return Err(TunnelError("No supported IP DNS resolvers in remote /etc/resolv.conf".into())); }
    Ok(result)
}
fn resolve_ssh() -> io::Result<std::path::PathBuf> {''')
edit(p,'    #[test]\n    fn strict_config_and_arguments_do_not_allow_shell_or_host_key_overrides()',r'''    #[test]
    fn remote_dns_discovery_is_fixed_bounded_and_keeps_strict_ssh_options() {
        let args=config().dns_discovery_arguments();
        assert!(!args.iter().any(|v|v=="-D" || v=="-N"));
        assert!(args.iter().any(|v|v=="StrictHostKeyChecking=yes"));
        assert!(args.last().unwrap().contains("cat /etc/resolv.conf"));
        let response="untrusted banner nameserver 192.0.2.2\nFLOWBRIDGE_DNS_BEGIN\nnameserver 127.0.0.53\nnameserver ::1\nnameserver 127.0.0.53\nFLOWBRIDGE_DNS_END\n";
        assert_eq!(parse_resolvers(response).unwrap(),vec!["127.0.0.53","::1"]);
        assert!(parse_resolvers("nameserver 127.0.0.53").is_err());
        assert!(parse_resolvers("FLOWBRIDGE_DNS_BEGIN\nnameserver 0.0.0.0\nFLOWBRIDGE_DNS_END").is_err());
    }
    #[test]
    fn strict_config_and_arguments_do_not_allow_shell_or_host_key_overrides()''')
p='native/include/flowbridge.h'
edit(p,'void fb_native_destroy(uint64_t session_id);','''/* DNS wire query/answer arrays, no system settings changes or local fallback. */
char *fb_native_dns_exchange_json(uint64_t session_id, const char *request_json);
char *fb_native_dns_start_json(uint64_t session_id, const char *options_json);
void fb_native_dns_stop(uint64_t session_id);
void fb_native_destroy(uint64_t session_id);''')
edit(p,'void fb_ssh_destroy(uint64_t ssh_id);','''/* Authenticated read of remote /etc/resolv.conf; never guesses a public DNS. */
char *fb_ssh_remote_dns_json(uint64_t ssh_id);
void fb_ssh_destroy(uint64_t ssh_id);''')
p='tests/ssh_real_integration.py'
needle="            passed('Native capture ABI: selected application -> real SSH -> target, without SOCKS ingress')"
edit(p,needle,needle+"\n            from native_dns_integration import actual_ssh as actual_dns\n            actual_dns(abi, profile, endpoint, supervisor)\n            passed('Native DNS: resolver discovery and UDP/TCP queries through actual SSH')")
print('Native DNS transport and remote resolver discovery applied')
