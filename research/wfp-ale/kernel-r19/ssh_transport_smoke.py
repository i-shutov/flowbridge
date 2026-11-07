"""Isolated OpenSSH transport QA only. No driver, BFE filters or remote host.
Ephemeral keys and config stay in a private temp dir; no service is changed.
The Rust test uses the SAME SOCKS handshake/relay functions as the broker.
"""
from pathlib import Path
import json, os, pwd, signal, socket, subprocess, sys, tempfile, time

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0));return s.getsockname()[1]

def command(args, **kwargs):
    result=subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, **kwargs)
    if result.returncode: raise RuntimeError('fixture_command_failed')
    return result

def main():
    out=Path(sys.argv[2]);test_binary=Path(sys.argv[1]).resolve()
    if os.name!='posix': raise RuntimeError('linux_fixture_only')
    ssh=None;server=None
    try:
        with tempfile.TemporaryDirectory(prefix='fb-r23-ssh-') as d:
            root=Path(d);os.chmod(root,0o700);server_port=port();socks_port=port()
            user=pwd.getpwuid(os.getuid()).pw_name
            key=root/'client';host=root/'host'
            command(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)])
            command(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(host)])
            known=root/'known_hosts';pub=host.with_suffix('.pub').read_text().split()
            known.write_text(f'[127.0.0.1]:{server_port} {pub[0]} {pub[1]}\n')
            config=root/'sshd_config'
            config.write_text(f'Port {server_port}\nListenAddress 127.0.0.1\nHostKey {host}\nPidFile {root / "server.pid"}\n'
                f'AuthorizedKeysFile {key.with_suffix(".pub")}\nAllowUsers {user}\n'
                'PubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n'
                'UsePAM yes\nStrictModes yes\nAllowTcpForwarding local\nPermitTunnel no\nLogLevel ERROR\n')
            # Existing sshd binary only. Never install/start/reconfigure a service.
            command(['sudo','-n','/usr/sbin/sshd','-t','-f',str(config)])
            log=(root/'private.log').open('wb')
            server=subprocess.Popen(['sudo','-n','/usr/sbin/sshd','-D','-e','-f',str(config)],
                                    stdout=log,stderr=log,start_new_session=True)
            time.sleep(.3)
            ssh=subprocess.Popen(['ssh','-F','/dev/null','-N','-D',f'127.0.0.1:{socks_port}',
                '-p',str(server_port),'-i',str(key),'-o','IdentitiesOnly=yes','-o','BatchMode=yes',
                '-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={known}',
                '-o','ExitOnForwardFailure=yes',f'{user}@127.0.0.1'],stdout=log,stderr=log)
            deadline=time.monotonic()+10
            while True:
                if ssh.poll() is not None or server.poll() is not None:raise RuntimeError('ssh_fixture_start_failed')
                try:
                    with socket.create_connection(('127.0.0.1',socks_port),timeout=.2):break
                except OSError:
                    if time.monotonic()>deadline:raise RuntimeError('ssh_fixture_start_timeout')
                    time.sleep(.1)
            env=os.environ.copy();env['FB_SSH_SOCKS_PORT']=str(socks_port)
            result=command([str(test_binary),'--nocapture'],env=env)
            text=result.stdout.decode('utf-8','replace')
            if 'REAL_OPENSSH_TRANSPORT_ONLY_PASS' not in text:raise RuntimeError('real_transport_marker_absent')
            out.parent.mkdir(parents=True,exist_ok=True)
            out.write_text(json.dumps(dict(ok=True,source_sha=os.environ['GITHUB_SHA'],
                transport='actual_OpenSSH_dynamic_SOCKS',ipv4_ipv6_exact_response=True,half_close=True,
                fixture_context_used=False,kernel_redirect_executed=False,g2_pass=False,release_accepted=False),indent=2))
            print('Real OpenSSH transport-only QA passed; no kernel acceptance.')
            # Delete keys only after both fixture processes have been stopped.
            ssh.terminate();ssh.wait(timeout=5);ssh=None
            command(['sudo','-n','kill','-TERM','--',f'-{server.pid}']);server.wait(timeout=5);server=None
            log.close()
    finally:
        if ssh is not None and ssh.poll() is None: ssh.terminate();ssh.wait(timeout=5)
        if server is not None and server.poll() is None:
            subprocess.run(['sudo','-n','kill','-TERM','--',f'-{server.pid}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5);server.wait(timeout=5)

if __name__=='__main__':
    try:main()
    except Exception:
        print('SSH transport fixture FAILED; no native or G2 acceptance.',file=sys.stderr);sys.exit(2)
