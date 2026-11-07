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
import shutil
import socket
import subprocess
import threading

REQUEST = b"HEAD / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n"
RESPONSE = b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def require(ok: bool, error: str) -> None:
    if not ok:
        raise AssertionError(error)


def executable() -> Path:
    """Select only the fixed in-box PowerShell, then authenticate its publisher.

    Run the signature query with a separate available PowerShell host rather
    than asking the target binary to attest itself. The signed target must
    still pass the same strict Authenticode gate on every Windows machine.
    """
    root = os.environ.get("SystemRoot")
    require(bool(root), "Missing Windows system directory")
    path = Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    require(path.is_file(), "In-box Windows PowerShell unavailable")
    escaped = str(path).replace("'", "''")
    expr = (
        "$ErrorActionPreference='Stop'; "
        "try { "
        f"$sig=Get-AuthenticodeSignature -LiteralPath '{escaped}'; "
        "if ($null -eq $sig) { throw 'Missing Authenticode result' }; "
        "$present=($null -ne $sig.SignerCertificate); "
        "$subject=if ($present) { [string]$sig.SignerCertificate.Subject } else { '' }; "
        "$ms=($subject -match '(^|,\\s*)O=Microsoft Corporation(,|$)'); "
        "[pscustomobject]@{status=[string]$sig.Status;signer_present=[bool]$present;"
        "signer_microsoft=[bool]$ms} | ConvertTo-Json -Compress; "
        "} catch { [Console]::Error.WriteLine('signature_error_type=' + "
        "$_.Exception.GetType().Name); exit 9 }"
    )
    encoded = base64.b64encode(expr.encode("utf-16-le")).decode("ascii")
    # Hosted Actions uses pwsh, while stock Windows 10/11 can use the in-box
    # shell. A failed signature query NEVER falls back to a weaker checker.
    checker = shutil.which("pwsh") or str(path)
    check = subprocess.run(
        [checker, "-NoLogo", "-NoProfile", "-NonInteractive",
         "-EncodedCommand", encoded],
        capture_output=True, timeout=20, check=False
    )
    try:
        signature = json.loads(check.stdout.decode("utf-8-sig", errors="replace").strip())
    except (ValueError, TypeError):
        signature = {}
    require(
        check.returncode == 0
        and signature.get("status") == "Valid"
        and signature.get("signer_present") is True
        and signature.get("signer_microsoft") is True,
        "Microsoft Authenticode requirement not met: "
        + f"status={signature.get('status', 'unavailable')}, "
        + f"signer_present={signature.get('signer_present', 'unavailable')}, "
        + f"signer_microsoft={signature.get('signer_microsoft', 'unavailable')}, "
        + f"exit_code={check.returncode}, "
        + f"checker={'pwsh' if checker != str(path) else 'inbox'}"
    )
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



def read_startup_line(process: subprocess.Popen, timeout: float = 20.0) -> str:
    """Read one pre-GO line from the real signed child, with a hard deadline.

    A cold in-box PowerShell startup on a busy Windows runner may exceed the
    former eight-second timeout. No network authorization is sent while this
    waits. Never include stderr or the encoded script in failure diagnostics.
    """
    require(process.stdout is not None, "Signed PowerShell stdout unavailable")
    lines: list[str] = []
    read_errors: list[str] = []

    def read() -> None:
        try:
            lines.append(process.stdout.readline())
        except (OSError, UnicodeError) as exc:
            read_errors.append(type(exc).__name__)

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    reader.join(timeout=timeout)
    state = "running" if process.poll() is None else "exited"
    require(not reader.is_alive(),
            f"Signed PowerShell startup deadline exceeded (state={state})")
    require(not read_errors, "Signed PowerShell startup pipe failed")
    require(len(lines) == 1 and bool(lines[0].strip()),
            f"Signed PowerShell did not announce readiness (state={state})")
    require(process.poll() is None,
            "Signed PowerShell exited before any GO authorization")
    return lines[0].strip()

def trial(exe: Path, script: str, allowed: bool | None) -> tuple[bool, int]:
    """Run a signed OS child through idle/no-GO, rejected-GO or allowed-GO.

    None leaves stdin open until a bounded forced termination, proving that
    an independently launched process cannot initiate TCP without GO.
    """
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
            # Keep stdin open and the TCP listener armed throughout cold
            # startup: a slow signed PowerShell launch must not be mistaken
            # for a missing GO or a permitted direct connection.
            announced = read_startup_line(process)
            require(announced.isascii() and announced.isdecimal(),
                    "Signed PowerShell readiness was not a decimal TCP port")
            require(1 <= int(announced) <= 65535, "Reserved port invalid")
            server.settimeout(0.35)
            try:
                connection, _ = server.accept()
            except socket.timeout:
                pass
            else:
                connection.close()
                raise AssertionError("TCP SYN escaped before GO handshake")
            if allowed is None:
                # Kill while stdin remains open. Merely closing stdin could
                # mimic the explicit denied-GO case and obscure a leak.
                require(process.poll() is None,
                        "PowerShell child exited unexpectedly while awaiting GO")
                server.settimeout(0.7)
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    pass
                else:
                    connection.close()
                    raise AssertionError("Idle PowerShell child sent TCP before GO")
                process.kill()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    raise AssertionError("Idle PowerShell child survived forced termination") from None
                require(process.returncode != 0,
                        "Idle PowerShell child did not record forced termination")
                server.settimeout(0.35)
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    pass
                else:
                    connection.close()
                    raise AssertionError("Idle PowerShell child connected after termination")
                return True, 0
            if not allowed:
                process.stdin.write("reject\n")
                process.stdin.flush()
                process.stdin.close()
                try:
                    process.wait(timeout=18)
                except subprocess.TimeoutExpired:
                    raise AssertionError("Rejected-GO PowerShell child failed to terminate") from None
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
            server_done = threading.Event()

            def serve() -> None:
                try:
                    server.settimeout(18)
                    with server.accept()[0] as connection:
                        connection.settimeout(18)
                        parts = []
                        size = 0
                        while True:
                            chunk = connection.recv(4096)
                            if not chunk:
                                break
                            size += len(chunk)
                            require(size <= 2048, "Unexpected oversized request")
                            parts.append(chunk)
                        received.append(b"".join(parts))
                        connection.sendall(RESPONSE)
                except Exception as exc:
                    errors.append(type(exc).__name__)
                finally:
                    server_done.set()
            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            process.stdin.write("go\n")
            process.stdin.flush()
            process.stdin.close()
            # Wait for actual server-side HTTP completion BEFORE the child
            # process exit. A fixed 12-second Popen.wait() raced the Windows
            # PowerShell transport on a loaded hosted runner and leaked the
            # base64 EncodedCommand into TimeoutExpired diagnostics.
            require(server_done.wait(timeout=24),
                    "PowerShell GO HTTP exchange did not complete within its bounded deadline")
            worker.join(timeout=1)
            require(not worker.is_alive() and not errors, "HTTP stub failed after GO")
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                raise AssertionError(
                    "PowerShell completed HTTP but failed to exit within deadline") from None
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
        result["embedded_script_sha256"] = hashlib.sha256(
            script.encode("utf-16-le")).hexdigest()
        idle, _ = trial(exe, script, None)
        denied, _ = trial(exe, script, False)
        granted, count = trial(exe, script, True)
        require(idle and denied and granted, "All three live child phases required")
        result.update({"idle_child_killed_no_tcp": True,
                       "negative_go_no_tcp": True, "positive_half_close_http": True,
                       "verified_http_reply_bytes": count, "passed": True})
    except Exception as error:
        # Classification only: never persist a child command, stderr, PID or path.
        result["error_class"] = type(error).__name__
        raise
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
