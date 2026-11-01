"""Cross-process real UDP DNS -> original Rust -> FlowBridge SOCKS -> authenticated OpenSSH.

Called ONLY within existing isolated real-OpenSSH integration harnesses. Unlike
the independent SOCKS stub test, the SOCKS endpoint here is the live FlowBridge
engine backed by the existing authenticated OpenSSH supervisor. No driver
interception, selected-app DNS routing, DNS leak-free or production DNS claim.
"""
import hashlib
import json
import queue
import socket
import subprocess
import threading
from pathlib import Path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        block = sock.recv(size - len(data))
        if not block:
            raise EOFError("DNS TCP closed unexpectedly")
        data.extend(block)
    return bytes(data)


def query(identifier):
    return (identifier.to_bytes(2, "big") +
            bytes.fromhex("01000001000000000000") +
            b"\x03www\x07example\x03com\x00\x00\x01\x00\x01")


def reserve_udp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def run(agent: Path, engine_port: int, gate, ssh_pid: int, output: Path) -> dict:
    agent = agent.resolve(strict=True)
    require(engine_port > 0 and ssh_pid > 0, "Unverified SSH supervisor")
    resolver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    resolver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    resolver.bind(("127.0.0.1", 0))
    resolver.listen(5)
    resolver.settimeout(0.4)
    resolver_port = resolver.getsockname()[1]
    stop = threading.Event()
    errors = queue.Queue()
    accepted_tcp = [0]

    def serve_tcp():
        try:
            while not stop.is_set():
                try:
                    conn, _ = resolver.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(6)
                    n = int.from_bytes(read_exact(conn, 2), "big")
                    request = read_exact(conn, n)
                    require(request[4:6] == b"\x00\x01" and n >= 17,
                            "Unexpected resolver DNS TCP request")
                    accepted_tcp[0] += 1
                    response = bytearray(request)
                    response[2] = 0x81
                    response[3] = 0x80
                    conn.sendall(n.to_bytes(2, "big") + response)
        except Exception as exc:
            errors.put(type(exc).__name__)

    thread = threading.Thread(target=serve_tcp, daemon=True)
    thread.start()
    udp_port = reserve_udp_port()
    for _ in range(12):
        if udp_port not in (engine_port, resolver_port):
            break
        udp_port = reserve_udp_port()
    require(udp_port not in (engine_port, resolver_port),
            "Could not reserve a distinct DNS lab UDP port")
    request = {
        "consent": "DNS_UDP_OVER_SOCKS_LAB",
        "bind": f"127.0.0.1:{udp_port}",
        "upstream": f"127.0.0.1:{engine_port}",
        "resolver": f"127.0.0.1:{resolver_port}",
        "max_queries": 4,
        "duration_ms": 14000,
    }
    gate(True)
    process = subprocess.Popen(
        [str(agent), "dns-udp-lab", json.dumps(request)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        ready = queue.Queue()
        threading.Thread(target=lambda: ready.put(process.stderr.readline()),
                         daemon=True).start()
        require(ready.get(timeout=8).strip() == "FLOWBRIDGE_DNS_LAB_READY",
                "Rust DNS agent did not open UDP listener")

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(("127.0.0.1", 0))
            udp.settimeout(2)
            def exchange(identifier, expected):
                udp.sendto(query(identifier), ("127.0.0.1", udp_port))
                try:
                    data, _ = udp.recvfrom(4096)
                except socket.timeout:
                    data = None
                if expected:
                    require(data is not None
                            and data[:2] == identifier.to_bytes(2, "big")
                            and data[2:4] == bytes.fromhex("8180"),
                            "Authenticated SSH DNS reply missing or corrupt")
                else:
                    require(data is None, "SOCKS-denied DNS unexpectedly returned UDP")
            exchange(0x1111, True)
            require(accepted_tcp[0] == 1, "SSH resolver did not receive first TCP query")
            gate(False)
            exchange(0x2222, False)
            require(accepted_tcp[0] == 1, "Closed SOCKS gate leaked DNS to resolver")
            invalid = bytearray(query(0x3333))
            invalid[4] = 2
            udp.sendto(invalid, ("127.0.0.1", udp_port))
            try:
                stray, _ = udp.recvfrom(4096)
            except socket.timeout:
                stray = None
            require(stray is None, "Malformed DNS obtained UDP answer")
            gate(True)
            exchange(0x4444, True)
        stdout, _stderr = process.communicate(timeout=20)
        require(process.returncode == 0, "Rust DNS agent returned nonzero exit")
        report = json.loads(stdout)
        require(report["loop_completed"] is True
                and report["queries_received"] == 4
                and report["queries_rejected_before_proxy"] == 1
                and report["queries_accepted"] == 3
                and report["replies_returned"] == 2
                and report["upstream_failures_without_direct_retry"] == 1
                and report["invalid_upstream_replies_dropped"] == 0
                and report["active_relay_slots_at_exit"] == 0
                and accepted_tcp[0] == 2
                and errors.empty(), "Real SSH DNS transport contract violated")
        for flag in ("native_ndisrd_interception", "selected_app_dns_protected",
                     "system_dns_modified", "dns_leak_free", "protected_mode",
                     "win10_11_acceptance", "release_accepted"):
            require(report[flag] is False, f"False release assertion: {flag}")
        evidence = {
            "kind": "original_rust_udp_dns_to_authenticated_openssh_real_tcp_resolver",
            "passed": True, "actual_udp_socket": True, "actual_tcp_resolver": True,
            "rust_dns_agent_sha256": hashlib.sha256(agent.read_bytes()).hexdigest(),
            "source_commit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], text=True).strip(),
            "managed_authenticated_openssh": True,
            "dns_queries_through_ssh": 2,
            "socks_closed_denied_without_tcp_resolver": True,
            "invalid_dns_denied_before_ssh": True,
            "recovery_without_direct": True,
            "driver_interception_claim": False,
            "selected_application_dns_leak_free": False,
            "release_accepted": False,
            "agent_report": report,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        return evidence
    finally:
        gate(True)
        stop.set()
        resolver.close()
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
        thread.join(timeout=3)
