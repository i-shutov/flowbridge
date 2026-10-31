#!/usr/bin/env python3
"""Original Rust experimental banner-first adapter, actual TCP and OpenSSH integration."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def receive_all(connection):
    body = bytearray()
    while True:
        data = connection.recv(16384)
        if not data:
            return bytes(body)
        body.extend(data)
        require(len(body) <= 10000, "Oversized fixture")


def binary_fixture(cli):
    payload = b"SSH-2.0-ClientFixture_1\r\n" + bytes(range(256)) * 15 + b"\x00\xff" + b"z" * 255
    preamble = b"Notice\r\nSSH-2.0-ServerFixture_1\r\n"
    response = preamble + b"\x00\xff" + bytes(range(255, -1, -1)) * 16
    observed = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    endpoint = "127.0.0.1:" + str(listener.getsockname()[1])

    def server():
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(.18)
            try:
                early = connection.recv(1)
            except socket.timeout:
                early = b""
            require(not early, "Client data preceded server identification")
            connection.settimeout(5)
            connection.sendall(preamble[:13])
            time.sleep(.02)
            connection.sendall(preamble[13:])
            observed.append(receive_all(connection))
            connection.sendall(response[len(preamble):])
            connection.shutdown(socket.SHUT_WR)

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    cmd = [str(cli), "ssh-banner-gate", "--endpoint", endpoint,
           "--timeout-ms", "2000", "--consent", "BANNER_FIRST_EXPERIMENTAL"]
    denied = subprocess.run(cmd[:-1] + ["DENY"], input=payload, capture_output=True, timeout=5)
    require(denied.returncode != 0 and not denied.stdout, "No-consent adapter accepted")
    got = subprocess.run(cmd, input=payload, capture_output=True, timeout=10)
    thread.join(timeout=5)
    listener.close()
    require(got.returncode == 0 and not thread.is_alive(), "Real adapter subprocess failed")
    require(observed == [payload], "Client binary bytes or FIN modified")
    require(got.stdout == response, "Server preamble/binary bytes modified")
    return {"passed": True, "binary_bytes_up": len(payload),
            "binary_bytes_down": len(response), "consent_denied": True}


def timeout_fixture(cli):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    received = []

    def server():
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(.7)
            try:
                received.append(connection.recv(1024))
            except socket.timeout:
                received.append(b"")

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    got = subprocess.run([str(cli), "ssh-banner-gate", "--endpoint",
                          "127.0.0.1:" + str(listener.getsockname()[1]),
                          "--timeout-ms", "250", "--consent", "BANNER_FIRST_EXPERIMENTAL"],
                         input=b"SSH-2.0-NoLeak\r\n", capture_output=True, timeout=5)
    thread.join(timeout=3)
    listener.close()
    require(got.returncode != 0 and not got.stdout and received == [b""],
            "Timeout leaked bytes or gave false success")
    return True


def interactive_kex_fixture(cli):
    """Server sends binary KEX and waits for the next CLIENT packet before FIN.

    A final-flush-only stdout pump deadlocks here. Use a bounded reader thread
    so a broken bridge cannot hang this CI test or falsely pass at EOF.
    """
    import queue
    client_ident = b"SSH-2.0-InteractiveClient\r\n"
    server_ident = b"SSH-2.0-InteractiveServer\r\n"
    server_kex = b"\x00\x00\x00\x0c\x08\x00\xff"
    client_kex = b"\x01\x02\x00\xff\x03"
    final_packet = b"\x07\x08\x00\x09"
    errors = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)

    def exact(connection, count):
        data = bytearray()
        while len(data) < count:
            chunk = connection.recv(count - len(data))
            if not chunk:
                raise RuntimeError("EOF before interactive KEX completion")
            data.extend(chunk)
        return bytes(data)

    def server():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(4)
                connection.sendall(server_ident)
                require(exact(connection, len(client_ident)) == client_ident,
                        "Client identification changed")
                connection.sendall(server_kex)
                require(exact(connection, len(client_kex)) == client_kex,
                        "Client KEX packet changed")
                connection.sendall(final_packet)
                connection.shutdown(socket.SHUT_WR)
        except Exception as error:
            errors.append(type(error).__name__)

    server_thread = threading.Thread(target=server, daemon=True)
    server_thread.start()
    process = subprocess.Popen([str(cli), "ssh-banner-gate",
                                "--endpoint", "127.0.0.1:" + str(listener.getsockname()[1]),
                                "--consent", "BANNER_FIRST_EXPERIMENTAL"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL)
    try:
        process.stdin.write(client_ident)
        process.stdin.flush()
        result = queue.Queue(maxsize=1)
        read_thread = threading.Thread(
            target=lambda: result.put(process.stdout.read(len(server_ident) + len(server_kex))),
            daemon=True)
        read_thread.start()
        require(result.get(timeout=3) == server_ident + server_kex,
                "KEX binary bytes were buffered without an immediate flush")
        process.stdin.write(client_kex)
        process.stdin.close()
        require(process.stdout.read() == final_packet, "Subsequent KEX packet changed")
        require(process.wait(timeout=4) == 0, "Interactive bridge exited abnormally")
        server_thread.join(timeout=4)
        require(not server_thread.is_alive() and not errors, "Interactive peer did not finish")
        return True
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        listener.close()


def real_authenticated_ssh(cli, ssh, identity, known, user, ssh_port, echo_port, socks_port):
    """Strict host-key, ephemeral public-key auth, real SOCKS/half-close via gate."""
    from ssh_real_integration import round_trip, until
    cli = Path(cli).resolve(strict=True)
    require(" " not in str(cli) and '"' not in str(cli),
            "QA ProxyCommand binary path must be shell-unambiguous")
    command_text = (f"{cli.as_posix()} ssh-banner-gate --endpoint 127.0.0.1:{ssh_port} "
                    "--timeout-ms 5000 --consent BANNER_FIRST_EXPERIMENTAL")
    command = [str(ssh), "-F", "none", "-N", "-T", "-n",
               "-D", f"127.0.0.1:{socks_port}", "-p", str(ssh_port),
               "-l", user, "-i", str(identity),
               "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", "PreferredAuthentications=publickey",
               "-o", "PasswordAuthentication=no",
               "-o", f'UserKnownHostsFile="{Path(known).as_posix()}"',
               "-o", "ExitOnForwardFailure=yes", "-o", "ConnectTimeout=5",
               "-o", f"ProxyCommand={command_text}", "127.0.0.1"]
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        def ready():
            require(child.poll() is None, "Gated real OpenSSH exited before authentication")
            with socket.socket() as test:
                test.settimeout(.25)
                return test.connect_ex(("127.0.0.1", socks_port)) == 0
        until(ready, seconds=15)
        round_trip(socks_port, echo_port)
        return {"real_openssh_authenticated": True, "binary_half_close": True,
                "strict_known_hosts": True,
                "cli_sha256": hashlib.sha256(cli.read_bytes()).hexdigest()}
    finally:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)


def real_supervised_banner_gate(abi, cli, settings, echo_port, socks_port):
    """Real Rust Supervisor -> OpenSSH -> original Rust gate -> real SOCKS."""
    from ssh_real_integration import round_trip, until
    cli = Path(cli).resolve(strict=True)
    require(all(c.isascii() and (c.isalnum() or c in '/\\._:-') for c in str(cli)),
            'Managed gate requires shell-inert local CLI')
    settings = dict(settings, local_port=socks_port,
                    banner_gate_executable=str(cli),
                    banner_gate_consent='BANNER_FIRST_EXPERIMENTAL',
                    banner_gate_timeout_ms=5000, startup_timeout_ms=15000,
                    max_restarts=0)
    ssh_id = abi.call('fb_ssh_create_json', settings)['ssh_id']
    try:
        abi.call('fb_ssh_start_json', ssh_id)
        def ready():
            state = abi.call('fb_ssh_snapshot_json', ssh_id)['status']
            require(state['state'] != 'failed', 'Supervised SSH gate failed before readiness')
            return state['state'] == 'ready' and state['pid']
        until(ready, seconds=20)
        round_trip(socks_port, echo_port)
        return {'managed_banner_first_socks_passed': True,
                'real_authenticated_openssh': True,
                'binary_half_close': True, 'manual_proxycommand_not_required': True,
                'cli_sha256': hashlib.sha256(cli.read_bytes()).hexdigest()}
    finally:
        abi.lib.fb_ssh_destroy(ssh_id)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cli = Path("target/debug/flowbridge" + (".exe" if os.name == "nt" else "")).resolve(strict=True)
    report = {"kind": "original_rust_ssh_banner_first", "passed": False,
              "protected_fail_closed": False, "native_packet_capture": False,
              "affected_route_workaround_proven": False, "dns_leak_free": False,
              "win10_11_acceptance": False, "source_sha": os.getenv("GITHUB_SHA")}
    try:
        report["binary"] = binary_fixture(cli)
        report["interactive_kex_no_line_buffer_deadlock"] = interactive_kex_fixture(cli)
        report["absent_banner_rejects_no_client_leak"] = timeout_fixture(cli)
        report["passed"] = True
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ssh_banner_gate": report}))


if __name__ == "__main__":
    main()
