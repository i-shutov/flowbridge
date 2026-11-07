"""Isolated OpenSSH transport QA; never loads a kernel driver.
sshd runs in its own private mount namespace with an ephemeral /run. The host
service, account, firewall, /run and configuration are never modified.
"""
from pathlib import Path
import json, os, pwd, re, signal, socket, subprocess, sys, tempfile, time

class FixtureError(RuntimeError): pass

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]

def cause(raw):
    text=raw.decode('utf-8','replace').lower()
    for needle, code in [('privilege separation directory','privsep_directory_missing'),
                         ('bad configuration','bad_sshd_config'),('account is locked','account_locked'),
                         ('bad ownership or modes','key_path_permissions'),('permission denied','permission_denied'),('address already in use','port_busy'),
                         ('host key verification failed','hostkey_rejected')]:
        if needle in text: return code
    return 'unclassified_stderr'

def command(args, stage, **kwargs):
    try: result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45,**kwargs)
    except FileNotFoundError: raise FixtureError(stage+'_executable_missing') from None
    except subprocess.TimeoutExpired: raise FixtureError(stage+'_timeout') from None
    if result.returncode: raise FixtureError(stage+'_'+cause(result.stderr))
    return result

def terminate(process, privileged=False):
    if process is None: return
    if process.poll() is None:
        def stop(sig):
            if privileged:
                subprocess.run(['sudo','-n','/bin/kill',f'-{sig}','--',f'-{process.pid}'],
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
            else:
                try: os.killpg(process.pid,getattr(signal,'SIG'+sig))
                except ProcessLookupError: pass
        stop('TERM')
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            stop('KILL');process.wait(timeout=5)

def run(test_binary):
    if os.name!='posix' or os.geteuid()==0: raise FixtureError('unprivileged_linux_required')
    if not Path('/usr/sbin/sshd').is_file(): raise FixtureError('sshd_executable_missing')
    with tempfile.TemporaryDirectory(prefix='fb-r23-ssh-') as directory:
        root=Path(directory);os.chmod(root,0o700);sshd_port=port();socks_port=port()
        if sshd_port==socks_port: raise FixtureError('fixture_port_collision')
        user=pwd.getpwuid(os.getuid()).pw_name
        key=root/'client';host=root/'host'
        command(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],'client_keygen')
        command(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(host)],'host_keygen')
        public=host.with_suffix('.pub').read_text().split();known=root/'known_hosts'
        known.write_text(f'[127.0.0.1]:{sshd_port} {public[0]} {public[1]}\n')
        config=root/'sshd_config'
        config.write_text(f'Port {sshd_port}\nListenAddress 127.0.0.1\nHostKey {host}\nPidFile {root / "sshd.pid"}\n'
            f'AuthorizedKeysFile {key.with_suffix(".pub")}\nAllowUsers {user}\n'
            'PubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n'
            'UsePAM yes\nStrictModes yes\nAllowTcpForwarding local\nPermitTunnel no\nLogLevel VERBOSE\n')
        ssh=None;server=None
        with (root/'private.log').open('wb') as log:
            try:
                script = ('set -eu; mount -t tmpfs -o mode=0755,size=1m tmpfs /run; '
                          'mkdir -m 0755 /run/sshd; readlink /proc/self/ns/mnt > "$2"; '
                          '/usr/sbin/sshd -t -f "$1"; exec /usr/sbin/sshd -D -e -f "$1"')
                server=subprocess.Popen(['sudo','-n','unshare','--mount','--fork','--kill-child=TERM',
                    '--propagation','private','/bin/sh','-c',script,'r23-sshd',str(config),str(root/'namespace')],
                    stdout=log,stderr=log,start_new_session=True)
                # Bounded readiness only, before any test. No failed test is retried.
                end=time.monotonic()+5
                while True:
                    if server.poll() is not None: raise FixtureError('sshd_start_'+cause((root/'private.log').read_bytes()))
                    try:
                        with socket.create_connection(('127.0.0.1',sshd_port),timeout=.2):break
                    except OSError:
                        if time.monotonic()>end:raise FixtureError('sshd_start_timeout')
                        time.sleep(.05)
                namespace=(root/'namespace').read_text().strip()
                if namespace==os.readlink('/proc/self/ns/mnt'):raise FixtureError('mount_namespace_not_isolated')
                ssh=subprocess.Popen(['ssh','-F','/dev/null','-N','-D',f'127.0.0.1:{socks_port}',
                    '-p',str(sshd_port),'-i',str(key),'-o','IdentitiesOnly=yes','-o','BatchMode=yes',
                    '-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={known}',
                    '-o','ExitOnForwardFailure=yes',f'{user}@127.0.0.1'],stdout=log,stderr=log,start_new_session=True)
                end=time.monotonic()+10
                while True:
                    if ssh.poll() is not None or server.poll() is not None:raise FixtureError('ssh_start_'+cause((root/'private.log').read_bytes()))
                    try:
                        with socket.create_connection(('127.0.0.1',socks_port),timeout=.2):break
                    except OSError:
                        if time.monotonic()>end:raise FixtureError('ssh_start_timeout')
                        time.sleep(.05)
                env=os.environ.copy();env['FB_SSH_SOCKS_PORT']=str(socks_port)
                result=command([str(test_binary),'--nocapture'],'rust_transport_tests',env=env)
                text=result.stdout.decode('utf-8','replace')
                if 'REAL_OPENSSH_TRANSPORT_ONLY_PASS' not in text:raise FixtureError('real_transport_marker_absent')
                count=re.search(r'test result: ok\. (\d+) passed; 0 failed',text)
                if not count:raise FixtureError('rust_test_summary_absent')
                result=dict(ok=True,source_sha=os.environ['GITHUB_SHA'],transport='actual_OpenSSH_dynamic_SOCKS',
                    rust_tests_passed=int(count[1]),ipv4_ipv6_exact_response=True,half_close=True,
                    private_mount_namespace_verified=True,host_ssh_service_changed=False,
                    fixture_context_used=False,kernel_redirect_executed=False,g2_pass=False,release_accepted=False)
            finally:
                terminate(ssh);terminate(server,privileged=True)
        if any(p is not None and p.poll() is None for p in (ssh,server)):raise FixtureError('fixture_process_cleanup_failed')
    if root.exists():raise FixtureError('fixture_file_cleanup_failed')
    result['fixture_processes_and_keys_removed']=True
    return result

def main():
    out=Path(sys.argv[2]);out.parent.mkdir(parents=True,exist_ok=True)
    try: result=run(Path(sys.argv[1]).resolve())
    except FixtureError as exc: result=dict(ok=False,error=str(exc),g2_pass=False,release_accepted=False)
    except Exception: result=dict(ok=False,error='fixture_unexpected_failure',g2_pass=False,release_accepted=False)
    out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result));return 0 if result['ok'] else 2
if __name__=='__main__':sys.exit(main())
