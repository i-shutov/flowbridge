#!/usr/bin/env python3
"""Real Windows PowerShell child socket handshake without a network driver.

This exercises the EXACT immutable script embedded in the Rust source, with a
live loopback HTTP server. It cannot attest native NDISRD or a selected app.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import threading

REQUEST = b"HEAD / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n"
RESPONSE = b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def require(ok: bool, error: str) -> None:
    if not ok:
        raise AssertionError(error)


def executable() -> Path:
    root = os.environ.get("SystemRoot")
    require(bool(root), "Missing Windows system directory")
    path = Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    require(path.is_file(), "In-box Windows PowerShell unavailable")
    expr = "$ErrorActionPreference = 'Stop'; " + \
           "$s = Get-AuthenticodeSignature -LiteralPath '" + str(path).replace("'", "''") + "'; " + \
           "$ms = [bool]($s.SignerCertificate -and " + \
           "$s.SignerCertificate.Subject -match 'Microsoft'); " + \
           "@{status=[string]$s.Status;signer_present=[bool]$s.SignerCertificate;" + \
           "signer_microsoft=$ms} | ConvertTo-Json -Compress"
    encoded = base64.b64encode(expr.encode("utf-16-le")).decode("ascii")
    check = subprocess.run([str(path), "-NoLogo", "-NoProfile", "-NonInteractive",
                            "-EncodedCommand", encoded],
                           capture_output=True, text=True, timeout=15, check=False)
    try:
        signature = json.loads(check.stdout.strip())
    except (ValueError, TypeError):
        signature = {}
    require(check.returncode == 0 and signature.get("status") == "Valid" and
            signature.get("signer_present") is True and
            signature.get("signer_microsoft") is True,
            "Microsoft Authenticode requirement not met: " +
            f"status={signature.get('status', 'unavailable')}, " +
            f"signer_present={signature.get('signer_present', 'unavailable')}, " +
            f"signer_microsoft={signature.get('signer_microsoft', 'unavailable')}, " +
            f"exit_code={check.returncode}")
    return path


def embedded_script(path: Path) -> str:
    content = path.read_text(encoding="utf-8")
    match = re.search(r'const POWERSHELL_CLIENT_SCRIPT: &str = r#"\s*\n(.*?)\n"#;',
                      content, re.DOTALL)
    require(match is not None, "Rust embedded script missing")
    script = match.group(1)
    require("FLOWBRIDGE_LAB_TARGET_PORT" in script and
            "[Console]::ReadLine()" in script and
            "ConvertTo-Json -Compress" in script,
            "Embedded client handshake changed without test update")
    return script


def trial(exe: Path, script: str, allowed: bool) -> tuple[bool, int]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(1.0)
        target_port = server.getsockname()[1]
        env = dict(os.environ, FLOWBRIDGE_LAB_LOCAL_IPV4="127.0.0.1",
                   FLOWBRIDGE_LAB_TARGET_IPV4="127.0.0.1",
                   FLOWBRIDGE_LAB_TARGET_PORT=str(target_port))
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        process = subprocess.Popen([str(exe), "-NoLogo", "-NoProfile", "-NonInteractive",
                                    "-EncodedCommand", encoded], env=env, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, encoding="utf-8")
        try:
            # The port announcement must happen BEFORE the first connection.
            # Use one bounded reader thread to enforce a startup deadline.
            line: list[str] = []
            ready = threading.Thread(target=lambda: line.append(process.stdout.readline()), daemon=True)
            ready.start()
            ready.join(timeout=8)
            require(not ready.is_alive() and line and line[0].strip().isdigit(),
                    "PowerShell child did not announce a reserved TCP port")
            require(1 <= int(line[0].strip()) <= 65535, "Reserved port invalid")
            server.settimeout(0.35)
            try:
                connection, _ = server.accept()
            except socket.timeout:
                pass
            else:
                connection.close()
                raise AssertionError("TCP SYN escaped before GO handshake")
            if not allowed:
                process.stdin.write("reject\n")
                process.stdin.flush()
                process.stdin.close()
                process.wait(timeout=10)
                server.settimeout(0.35)
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    pass
                else:
                    connection.close()
                    raise AssertionError("Rejected child initiated a TCP flow")
                require(process.returncode != 0, "Rejected GO did not exit with failure")
                return True, 0
            received: list[bytes] = []
            errors: list[str] = []
            def serve() -> None:
                try:
                    server.settimeout(8)
                    with server.accept()[0] as connection:
                        connection.settimeout(8)
                        parts = []
                        while True:
                            chunk = connection.recv(4096)
                            if not chunk:
                                break
                            parts.append(chunk)
                            require(sum(map(len, parts)) <= 2048, "Unexpected oversized request")
                        received.append(b"".join(parts))
                        connection.sendall(RESPONSE)
                except Exception as exc:
                    errors.append(type(exc).__name__)
            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            process.stdin.write("go\n")
            process.stdin.flush()
            process.stdin.close()
            process.wait(timeout=12)
            worker.join(timeout=10)
            require(not worker.is_alive() and not errors, "HTTP stub failed")
            body = process.stdout.read()
            require(process.returncode == 0 and received == [REQUEST],
                    "PowerShell TCP half-close request mismatched")
            report = json.loads(body.strip())
            require(report.get("ok") is True and report.get("bytes") == len(RESPONSE),
                    "PowerShell response bytes/HTTP validation failed")
            return True, len(RESPONSE)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(os.name == "nt", "Windows-only system client test")
    result = {"passed": False, "kind": "hosted_signed_os_powershell_loopback_client",
              "native_driver_tested": False, "arbitrary_app_owner_binding_accepted": False,
              "protected_mode_available": False, "dns_leak_free": False,
              "win10_11_acceptance": False, "release_accepted": False,
              "source_sha": os.environ.get("PR_HEAD_SHA", ""),
              "process_identity_or_endpoints_saved": False}
    try:
        exe = executable()
        result["powershell_sha256"] = hashlib.sha256(exe.read_bytes()).hexdigest()
        script = embedded_script(args.source)
        denied, _ = trial(exe, script, False)
        granted, count = trial(exe, script, True)
        require(denied and granted, "Both live child phases required")
        result.update({"negative_go_no_tcp": True, "positive_half_close_http": True,
                       "verified_http_reply_bytes": count, "passed": True})
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
