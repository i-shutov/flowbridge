from pathlib import Path

def edit(path,old,new):
    p=Path(path);s=p.read_text(encoding='utf-8')
    if s.count(old)!=1:raise RuntimeError(f'{path}: match count {s.count(old)}')
    p.write_text(s.replace(old,new),encoding='utf-8')

p='crates/flowbridge-tunnel/src/lib.rs'
edit(p,'if self.verbose_diagnostics { "DEBUG3" } else { "ERROR" }','if self.verbose_diagnostics { "DEBUG3" } else { "INFO" }')
edit(p,'''    if let Some(fatal) = fatal {
        s.fatal = Some(fatal.into());''','''    if lower.contains("timeout, server ") && lower.contains("not responding") {
        s.status.diagnostic_code = Some("ssh_server_unresponsive".into());
        s.status.last_error = Some("SSH server did not answer keepalive requests. Check the network, server load and keepalive budget; a local SOCKS greeting alone does not prove remote readiness.".into());
    }
    if let Some(fatal) = fatal {
        s.fatal = Some(fatal.into());''')
edit(p,'''        let error = s
            .fatal
            .clone()
            .or(error)''','''        let diagnosed = s.status.diagnostic_code.as_deref()
            .filter(|code| *code == "ssh_server_unresponsive")
            .and(s.status.last_error.clone());
        let error = s
            .fatal
            .clone()
            .or(diagnosed)
            .or(error)''')
edit(p,'''            s.event("info", "starting managed OpenSSH dynamic forwarding");''','''            s.event("info", "starting managed OpenSSH dynamic forwarding");
            if self.config.server_alive_interval_secs.saturating_mul(u64::from(self.config.server_alive_count_max)) < 10 {
                s.event("warn", "SSH keepalive budget is below 10 seconds; server login or load delays can cause premature disconnects");
            }''')
edit(p,'    #[test]\n    fn strict_config_and_arguments_do_not_allow_shell_or_host_key_overrides()', '''    #[test]
    fn keepalive_timeout_reason_is_actionable_and_info_logging_is_preserved() {
        let supervisor = Supervisor::new(config()).unwrap();
        stderr_line(&supervisor.state, b"Timeout, server synthetic.invalid not responding.");
        let snapshot = supervisor.snapshot();
        assert_eq!(snapshot.status.diagnostic_code.as_deref(), Some("ssh_server_unresponsive"));
        assert!(snapshot.status.last_error.as_deref().unwrap().contains("keepalive"));
        assert!(!snapshot.status.last_error.as_deref().unwrap().contains("synthetic.invalid"));
        assert!(config().arguments().iter().any(|arg| arg == "LogLevel=INFO"));
        assert_eq!(snapshot.status.resource_exhaustion_count, 0);
    }

    #[test]
    fn strict_config_and_arguments_do_not_allow_shell_or_host_key_overrides()''')
p='crates/flowbridge-ffi/src/diagnostics.rs'
s=Path(p).read_text(encoding='utf-8')
a='"ssh_health_unresponsive"'
assert s.count(a)==1
Path(p).write_text(s.replace(a,a+', "ssh_server_unresponsive"'),encoding='utf-8')
p='tests/ssh_real_integration.py'
edit(p,"'server_alive_interval_secs': 1,", "'server_alive_interval_secs': 15,")
edit(p,"'server_alive_count_max': 2,", "'server_alive_count_max': 3,")
edit(p,"            supervisor = abi.call('fb_ssh_create_json', settings)['ssh_id']",'''            report['keepalive'] = {'interval_seconds': settings['server_alive_interval_secs'],
                                   'count_max': settings['server_alive_count_max']}
            supervisor = abi.call('fb_ssh_create_json', settings)['ssh_id']''')
a="            capture_log = (args.output / 'capture.log').open('wb')"
s=Path(p).read_text(encoding='utf-8');start=s.index(a);end=s.index("            known = root / 'known hosts'",start)
block=s[start:end]
s=s[:start]+"            if os.environ.get('FLOWBRIDGE_TEST_CAPTURE') == '1':\n"+''.join('    '+line+'\n' for line in block.splitlines())+s[end:]
Path(p).write_text(s,encoding='utf-8')
p=Path('docs/SSH_RELIABILITY.md')
p.write_text(p.read_text()+'''\nQA found that the isolated test forced ServerAliveInterval=1 and ServerAliveCountMax=2. Packet capture showed a correct SOCKS request queued while the test sshd remained in PAM session setup, then the client exited 255 after roughly three seconds. OpenSSH logs its keepalive timeout at INFO, so the old ERROR setting hid the reason. Normal managed logging is now INFO (DEBUG3 is opt-in), the timeout receives an explicit diagnostic code preserved across child exit, and sub-ten-second keepalive budgets produce a warning. The real test now uses the product defaults 15/3; watchdog restart is still tested by killing the owned child, and no assertions are skipped. Optional packet capture is confined to disposable CI via FLOWBRIDGE_TEST_CAPTURE=1.\n''')
print('Keepalive reason retained; normal INFO logging and production-default 15/3 integration settings applied')
