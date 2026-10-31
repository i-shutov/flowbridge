#!/usr/bin/env python3
"""Operator-only real Windows OpenSSH capacity on an isolated loopback sshd VM.

Requires an already configured and authorized sshd on 127.0.0.1, enrolled
known_hosts and ephemeral test identity. Does not install sshd, change system
limits, disable host-key verification or contact production servers. Measures
Windows OS handle count separately from OpenSSH's internal file descriptor
table. Does not claim WFP or actual selected-application interception.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import threading
import time

from real_ssh_capacity import exact, require
from windows_ssh_probe_core import ResourceErrors, probe_capacity


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(180)
        try:
            while data := self.request.recv(8192):
                self.request.sendall(data)
        except OSError:
            pass


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 512


def windows_handle_count(pid):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.GetProcessHandleCount.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel.GetProcessHandleCount.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        count = ctypes.c_uint32()
        if not kernel.GetProcessHandleCount(handle, ctypes.byref(count)):
            return None
        return count.value
    finally:
        kernel.CloseHandle(handle)


def port_unused():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def read_reply(sock):
    prefix = exact(sock, 4)
    require(prefix[0] == 5, "Invalid SOCKS reply version")
    if prefix[3] == 1:
        exact(sock, 6)
    elif prefix[3] == 4:
        exact(sock, 18)
    elif prefix[3] == 3:
        exact(sock, exact(sock, 1)[0] + 2)
    else:
        raise AssertionError("Invalid SOCKS reply address type")
    return prefix[1]


def connect(port, echo_port):
    client = socket.create_connection(("127.0.0.1", port), timeout=4)
    try:
        client.settimeout(4)
        client.sendall(b"\x05\x01\x00")
        require(exact(client, 2) == b"\x05\x00", "Invalid SOCKS greeting")
        client.sendall(b"\x05\x01\x00\x03\x09localhost" + echo_port.to_bytes(2, "big"))
        code = read_reply(client)
        if code:
            client.close()
            return None
        return client
    except Exception:
        client.close()
        raise


def verify_echo(sock, nonce):
    sock.sendall(nonce)
    require(exact(sock, len(nonce)) == nonce, "Existing SSH stream changed under load")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh", type=Path, required=True, help="Exact approved local Windows ssh.exe")
    parser.add_argument("--identity", type=Path, required=True, help="Disposable, pre-enrolled test private key")
    parser.add_argument("--known-hosts", type=Path, required=True, help="Pinned loopback SSH host public key")
    parser.add_argument("--user", required=True, help="User account on isolated loopback sshd")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--held", type=int, default=128)
    parser.add_argument("--min-held", type=int, default=128,
                        help="Minimum real concurrent byte-verified channels required to pass")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == "win32" and os.environ.get("FLOWBRIDGE_SSH_VM") == "1",
            "Authorized Windows VM and explicit FLOWBRIDGE_SSH_VM=1 required")
    require(1 <= args.min_held <= args.held <= 512 and 1 <= args.ssh_port <= 65535,
            "Bounded capacity must be 1..512")
    require(args.user.isascii() and args.user.replace("_", "").replace("-", "").isalnum()
            and not args.user.startswith("-"), "Invalid SSH user identity")
    ssh = args.ssh.resolve(strict=True)
    identity = args.identity.resolve(strict=True)
    known_hosts = args.known_hosts.resolve(strict=True)
    require(ssh.suffix.lower() == ".exe" and ssh.name.lower() == "ssh.exe",
            "Exact Windows ssh.exe required")
    require(identity.is_file() and known_hosts.is_file() and known_hosts.stat().st_size > 0,
            "SSH test keys and enrolled host fingerprint are required")
    report = {"passed": False, "driver_loaded": False, "windows_openssh_tested": True,
              "source_commit": os.environ.get("GITHUB_SHA"),
              "actual_ssh_executable_sha256": hashlib.sha256(ssh.read_bytes()).hexdigest(),
              "ssh_version": None, "ssh_pid": None,
              "attempts": [], "windows_handle_samples": [],
              "actual_internal_fd_table_measured": False,
              "notes": ["OS HANDLE counts are not the internal Win32 OpenSSH FD table.",
                        "A hard OpenSSH socket ceiling is not inferred from an attempt count."],
              "external_network": False}
    ssh_process = None
    resource_errors = ResourceErrors()
    stderr_thread = None
    listener = None
    thread = None
    try:
        version = subprocess.run([str(ssh), "-V"], text=True,
                                 capture_output=True, timeout=10, check=True)
        require("OpenSSH" in version.stderr + version.stdout,
                "Selected executable is not a recognized OpenSSH client")
        report["ssh_version"] = (version.stderr + version.stdout).strip()[:180]
        listener = EchoServer(("127.0.0.1", 0), Echo)
        thread = threading.Thread(target=listener.serve_forever, daemon=True)
        thread.start()
        forward_port = port_unused()
        cmd = [str(ssh), "-F", "none", "-N", "-T", "-D", f"127.0.0.1:{forward_port}",
               "-p", str(args.ssh_port), "-i", str(identity),
               "-o", f"UserKnownHostsFile={known_hosts}",
               "-o", "StrictHostKeyChecking=yes",
               "-o", "BatchMode=yes",
               "-o", "IdentitiesOnly=yes",
               "-o", "ProxyCommand=none",
               "-o", "ProxyJump=none",
               "-o", "PasswordAuthentication=no",
               "-o", "KbdInteractiveAuthentication=no",
               "-o", "ExitOnForwardFailure=yes",
               "-o", "ControlMaster=no",
               "-o", "ServerAliveInterval=10",
               "-o", "ServerAliveCountMax=3",
               "-l", args.user, "127.0.0.1"]
        ssh_process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.PIPE,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
        def collect_stderr():
            # Bounded readline: no raw line, hostname, key path or user saved.
            while line := ssh_process.stderr.readline(8192):
                resource_errors.observe(line)
        stderr_thread = threading.Thread(target=collect_stderr, daemon=True)
        stderr_thread.start()
        report["ssh_pid"] = ssh_process.pid
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            require(ssh_process.poll() is None, "OpenSSH child exited before local readiness")
            try:
                with socket.create_connection(("127.0.0.1", forward_port), timeout=0.4):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("Real Windows OpenSSH SOCKS listener did not start")
        def sample(stage):
            count = windows_handle_count(ssh_process.pid)
            require(count is not None, "Actual Windows process handle measurement unavailable")
            report["windows_handle_samples"].append({"stage": stage, "os_handle_count": count})
            return count
        baseline = sample("baseline")
        probe_capacity(lambda: connect(forward_port, listener.server_address[1]),
                       verify_echo, lambda: ssh_process.poll() is None, sample, report,
                       held_limit=args.held, min_held=args.min_held)
        # OS handles and OpenSSH internal descriptor slots remain distinct.
        deadline = time.monotonic() + 15
        while True:
            count = windows_handle_count(ssh_process.pid)
            require(count is not None, "Cannot observe process handles after release")
            if count <= baseline + 32:
                break
            require(time.monotonic() < deadline, "OpenSSH HANDLE count failed to return near baseline")
            time.sleep(0.1)
        sample("after_recovery")
        report["resource_recovery_verified"] = True
        report["minimum_required_held"] = args.min_held
        report["selected_held_ceiling"] = args.held
        require(ssh_process.poll() is None, "OpenSSH exited after release")
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        if ssh_process:
            ssh_process.terminate()
            try:
                ssh_process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                ssh_process.kill()
                ssh_process.wait(timeout=8)
        if stderr_thread:
            stderr_thread.join(timeout=5)
        if ssh_process and ssh_process.stderr:
            ssh_process.stderr.close()
        report["resource_error_counts"] = resource_errors.snapshot()
        if listener:
            listener.shutdown()
            listener.server_close()
        if thread:
            thread.join(timeout=5)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    main()
