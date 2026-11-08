"""Isolated real OpenSSH server for authenticated native Rust R37 transport.

No kernel driver, WFP filter, service, signing, firewall or host /run changes.
All generated keys and logs are temporary under the private runner home.
"""
from __future__ import annotations
import json, os, pwd, select, signal, socket, subprocess, sys, tempfile, threading, time
from pathlib import Path

class Fail(RuntimeError): pass

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]

def run_checked(cmd, label):
    r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
    if r.returncode:
        raise Fail(label+'_failed')

def stop(proc, privileged=False):
    if proc is None or proc.poll() is not None:return
    try:
        if privileged:
            subprocess.run(['sudo','-n','/bin/kill','-TERM','--',f'-{proc.pid}'],
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
        else:os.killpg(proc.pid,signal.SIGTERM)
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if privileged:
            subprocess.run(['sudo','-n','/bin/kill','-KILL','--',f'-{proc.pid}'],
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
        else:os.killpg(proc.pid,signal.SIGKILL)
        proc.wait(timeout=5)

def target_server(family):
    host='127.0.0.1' if family==4 else '::1'
    server=socket.socket(socket.AF_INET if family==4 else socket.AF_INET6)
    server.settimeout(12);server.bind((host,0));server.listen(1)
    destination=server.getsockname()
    observed=[]
    def serve():
        try:
            with server:
                conn,_=server.accept()
                with conn:
                    conn.settimeout(12)
                    received=b''
                    while True:
                        n=conn.recv(4096)
                        if not n:break
                        received+=n
                    observed.append(received)
                    conn.sendall(b'hostkey-pinned-ssh-exact-response')
        except (OSError,TimeoutError):
            observed.append(None)
    task=threading.Thread(target=serve,daemon=True);task.start()
    return destination, observed, task

def case(binary, ssh_port, user, key, pinned, family, expected_good):
    dest,observed,task=target_server(family)
    listen=free_port()
    command=[str(binary),'--isolated-transport-lab','R37_NO_KERNEL',str(listen),
             '127.0.0.1',str(ssh_port),user,str(pinned),str(key),dest[0],str(dest[1])]
    process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,text=True)
    try:
        ready,_,_=select.select([process.stdout],[],[],10)
        if not ready or process.stdout.readline().strip()!='R37_TRANSPORT_READY':
            raise Fail('r37_ready_not_observed')
        with socket.create_connection(('127.0.0.1',listen),timeout=10) as client:
            client.settimeout(15)
            client.sendall(b'r37-native-forwarded-data');client.shutdown(socket.SHUT_WR)
            response=b''
            try:
                while True:
                    payload=client.recv(4096)
                    if not payload:break
                    response+=payload
            except socket.timeout:
                if expected_good:raise Fail('r37_response_timeout')
        try: out,err=process.communicate(timeout=20)
        except subprocess.TimeoutExpired:raise Fail('r37_process_timeout')
        if expected_good:
            if process.returncode or response!=b'hostkey-pinned-ssh-exact-response' or not ('"ok":true' in out):
                raise Fail('r37_authenticated_transport_failed')
        else:
            if process.returncode==0 or response:
                raise Fail('r37_wrong_host_key_was_not_rejected')
        # A negative host-key test should not ever deliver application bytes.
        if not expected_good:
            task.join(timeout=1)
            if observed and observed[0] is not None:raise Fail('r37_unverified_payload_leaked')
    finally:
        stop(process)
        task.join(timeout=0.5)
        if task.is_alive():
            # Negatives never open the remote socket; terminate the accept wait.
            # The daemon fixture thread owns only its temporary listener.
            pass
    return {'family':family,'positive':expected_good,'verified':True}

def main():
    result={'ok':False,'g2_pass':False,'kernel_redirect_executed':False,'wfp_records_forwarded':False}
    stage='start'
    try:
        if os.name!='posix' or os.geteuid()==0:raise Fail('linux_unprivileged_required')
        if not Path('/usr/sbin/sshd').is_file():raise Fail('sshd_unavailable')
        binary=Path(sys.argv[1]).resolve();out=Path(sys.argv[2]);out.parent.mkdir(parents=True,exist_ok=True)
        stage='create_fixture'
        with tempfile.TemporaryDirectory(prefix='.flowbridge-r37-',dir=Path.home()) as dirname:
            root=Path(dirname);os.chmod(root,0o700)
            ssh_port=free_port();user=pwd.getpwuid(os.getuid()).pw_name
            key=root/'client';host=root/'host';fake=root/'fake'
            stage='generate_keys'
            for f in (key,host,fake):run_checked(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(f)],'key_generation')
            stage='configure_sshd'
            cfg=root/'sshd_config'
            cfg.write_text(f'Port {ssh_port}\nListenAddress 127.0.0.1\nHostKey {host}\nPidFile {root / "sshd.pid"}\n'
                f'AuthorizedKeysFile {key.with_suffix(".pub")}\nAllowUsers {user}\n'
                'PubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n'
                'UsePAM yes\nStrictModes yes\nAllowTcpForwarding local\nPermitTunnel no\nLogLevel ERROR\n')
            server=None
            with (root/'private-sshd.log').open('wb') as log:
                try:
                    # Existing CI's private mount-namespace technique.
                    script=('set -eu; mount -t tmpfs -o mode=0755,size=1m tmpfs /run; '
                            'mkdir -m 0755 /run/sshd; exec /usr/sbin/sshd -D -e -f "$1"')
                    stage='launch_isolated_sshd'
                    server=subprocess.Popen(['sudo','-n','unshare','--mount','--fork','--kill-child=TERM',
                        '--propagation','private','/bin/sh','-c',script,'r37-sshd',str(cfg)],
                        stdout=log,stderr=log,start_new_session=True)
                    stage='probe_sshd'
                    start=time.monotonic()
                    while True:
                        if server.poll() is not None:raise Fail('isolated_sshd_start_failed')
                        try:
                            with socket.create_connection(('127.0.0.1',ssh_port),timeout=.2):break
                        except OSError:
                            if time.monotonic()-start>8:raise Fail('isolated_sshd_timeout')
                            time.sleep(.05)
                    stage='ipv4_good'
                    result4=case(binary,ssh_port,user,key,host.with_suffix('.pub'),4,True)
                    stage='ipv6_good'
                    result6=case(binary,ssh_port,user,key,host.with_suffix('.pub'),6,True)
                    stage='wrong_host_key'
                    resultbad=case(binary,ssh_port,user,key,fake.with_suffix('.pub'),4,False)
                    cases=[result4,result6,resultbad]
                    result.update(ok=True,source_sha=os.environ['GITHUB_SHA'],
                        transport='owned_socket_and_pinned_SSH_direct_tcpip',cases=cases,
                        actual_ssh_authenticated=True,negative_wrong_host_pin_rejected=True,
                        native_host_protection_mutated=False)
                finally:
                    stage='cleanup_sshd' if stage=='done' else stage
                    stop(server,privileged=True)
        result['fixture_keys_and_processes_removed']=True
    except Fail as e:
        result['error']=str(e);result['stage']=stage
    except Exception as e:
        result['error']='unexpected_r37_fixture_failure';result['stage']=stage
        result['exception_class']=type(e).__name__
    try:out.write_text(json.dumps(result,indent=2)+'\n')
    except Exception:return 2
    print(json.dumps(result))
    return 0 if result['ok'] else 2

if __name__=='__main__':raise SystemExit(main())
