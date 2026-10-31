#!/usr/bin/env python3
"""Unrelated signed in-box PowerShell TCP canary for real native lab testing.

Launched by a Python QA orchestrator, NOT by the FlowBridge Rust agent.
The source TCP socket is reserved before any GO and owned by PowerShell.
Only a local loopback control port is used. No PID/port is saved in reports.
This DOES NOT prove arbitrary packet-to-process ownership or protected mode.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import threading

from windows_powershell_lab_client import executable, REQUEST, RESPONSE, require

_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ip = [System.Net.IPAddress]::Parse($env:FLOWBRIDGE_LAB_LOCAL_IPV4)
$target = [System.Net.IPAddress]::Parse($env:FLOWBRIDGE_LAB_TARGET_IPV4)
$port = [int]$env:FLOWBRIDGE_LAB_TARGET_PORT
if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
    $target.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
    $port -lt 1 -or $port -gt 65535) { exit 2 }
$s = [System.Net.Sockets.Socket]::new([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$control = $null
try {
  $s.ReceiveTimeout = 7000
  $s.SendTimeout = 7000
  $s.Bind([System.Net.IPEndPoint]::new($ip, 0))
  $listener.Start(1)
  [Console]::Out.WriteLine((@{
      source_port=([System.Net.IPEndPoint]$s.LocalEndPoint).Port
      control_port=([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
  } | ConvertTo-Json -Compress))
  [Console]::Out.Flush()
  $control = $listener.AcceptTcpClient()
  $control.ReceiveTimeout = 7000
  $control.SendTimeout = 7000
  $reader = [System.IO.StreamReader]::new($control.GetStream())
  $writer = [System.IO.StreamWriter]::new($control.GetStream())
  $writer.AutoFlush = $true
  $ok = $false
  $received = [long]0
  if ($reader.ReadLine() -ceq 'go') {
    try {
      $s.Connect([System.Net.IPEndPoint]::new($target, $port))
      $crlf = [string][char]13 + [string][char]10
      $payload = 'HEAD / HTTP/1.0' + $crlf + 'Host: example.com' + $crlf + 'Connection: close' + $crlf + $crlf
      $bytes = [System.Text.Encoding]::ASCII.GetBytes($payload)
      $offset = 0
      while ($offset -lt $bytes.Length) {
        $n = $s.Send($bytes, $offset, $bytes.Length - $offset, [System.Net.Sockets.SocketFlags]::None)
        if ($n -le 0) { throw 'Socket send refused' }
        $offset += $n
      }
      $s.Shutdown([System.Net.Sockets.SocketShutdown]::Send)
      $buffer = New-Object byte[] 4096
      $reply = [System.IO.MemoryStream]::new()
      while ($true) {
        $n = $s.Receive($buffer)
        if ($n -eq 0) { break }
        if ($reply.Length + $n -gt 8192) { throw 'Reply exceeded bound' }
        $reply.Write($buffer, 0, $n)
      }
      $text = [System.Text.Encoding]::ASCII.GetString($reply.ToArray())
      $ok = $text.StartsWith('HTTP/1.') -and $text.Contains($crlf + $crlf)
      $received = [long]$reply.Length
    } catch {
      $ok = $false
      $received = [long]0
    }
  }
  $s.Dispose()
  $writer.WriteLine((@{ok=[bool]$ok;bytes=[long]$received} | ConvertTo-Json -Compress))
  $writer.Flush()
  # Keep the independently owned process alive until Rust acknowledges the
  # complete response, including when the upstream SOCKS gate denies it.
  if ($reader.ReadLine() -cne 'ack') { exit 4 }
} finally {
  $s.Dispose()
  if ($null -ne $control) { $control.Dispose() }
  $listener.Stop()
}
"""


class ExternalPowerShellCanary:
    """Live independently spawned OS process. The Rust agent only queries it."""
    def __init__(self, local_ipv4: str, target_ipv4: str, target_port: int = 80) -> None:
        self.local_ipv4, self.target_ipv4, self.target_port = local_ipv4, target_ipv4, target_port
        self.proc: subprocess.Popen | None = None
        self.source_port = 0
        self.control_port = 0

    def __enter__(self) -> "ExternalPowerShellCanary":
        signed = executable()  # Independent Authenticode Microsoft gate, no fallback.
        env = dict(os.environ, FLOWBRIDGE_LAB_LOCAL_IPV4=self.local_ipv4,
                   FLOWBRIDGE_LAB_TARGET_IPV4=self.target_ipv4,
                   FLOWBRIDGE_LAB_TARGET_PORT=str(self.target_port))
        encoded = base64.b64encode(_SCRIPT.encode("utf-16-le")).decode("ascii")
        self.proc = subprocess.Popen(
            [str(signed), "-NoLogo", "-NoProfile", "-NonInteractive",
             "-EncodedCommand", encoded],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
            creationflags=subprocess.CREATE_NO_WINDOW)
        line: list[str] = []
        reader = threading.Thread(target=lambda: line.append(self.proc.stdout.readline()), daemon=True)
        reader.start()
        reader.join(timeout=8)
        try:
            require(not reader.is_alive() and len(line) == 1,
                    "Independent PowerShell did not reserve a source socket")
            ready = json.loads(line[0])
            self.source_port = int(ready["source_port"])
            self.control_port = int(ready["control_port"])
            require(1024 <= self.source_port <= 65535 and
                    1024 <= self.control_port <= 65535 and
                    self.source_port != self.control_port,
                    "Independent client ports not distinct/ephemeral")
            require(self.proc.poll() is None, "Independent PowerShell already exited")
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def request(self) -> dict:
        require(self.proc is not None and self.proc.poll() is None, "External process exited")
        return {"pid": self.proc.pid, "source_port": self.source_port,
                "control_port": self.control_port}

    def await_exit(self, timeout: float = 5.0) -> None:
        require(self.proc is not None, "No external client")
        require(self.proc.wait(timeout=timeout) == 0, "Independent PowerShell failed")

    def __exit__(self, _kind, _error, _trace) -> None:
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait(timeout=8)
            if self.proc.stdout:
                self.proc.stdout.close()


def trial(allowed: bool) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(0.3)
        port = server.getsockname()[1]
        with ExternalPowerShellCanary("127.0.0.1", "127.0.0.1", port) as canary:
            try:
                connection, _ = server.accept()
            except socket.timeout:
                pass
            else:
                connection.close()
                raise AssertionError("Independent client transmitted before GO")
            received: list[bytes] = []
            errors: list[str] = []
            if allowed:
                def serve() -> None:
                    try:
                        server.settimeout(8)
                        with server.accept()[0] as conn:
                            conn.settimeout(8)
                            request = b""
                            while True:
                                chunk = conn.recv(2048)
                                if not chunk:
                                    break
                                request += chunk
                                require(len(request) <= 2048, "Canary payload exceeded limit")
                            received.append(request)
                            conn.sendall(RESPONSE)
                    except Exception as exc:
                        errors.append(type(exc).__name__)
                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
            with socket.create_connection(("127.0.0.1", canary.control_port), timeout=3) as ctl:
                ctl.sendall(b"go\n" if allowed else b"reject\n")
                ctl.settimeout(10)
                raw = b""
                while not raw.endswith(b"\n") and len(raw) <= 256:
                    block = ctl.recv(256)
                    if not block:
                        break
                    raw += block
                require(raw.endswith(b"\n") and len(raw) <= 256,
                        "External client reply missing or oversized")
                response = json.loads(raw)
                ctl.sendall(b"ack\n")
            canary.await_exit()
            if allowed:
                worker.join(timeout=10)
                require(not worker.is_alive() and not errors, "Loopback HTTP server did not complete")
                require(response == {"ok": True, "bytes": len(RESPONSE)}
                        and received == [REQUEST], "Independent HTTP half-close mismatch")
            else:
                require(response.get("ok") is False and response.get("bytes") == 0,
                        "Non-GO command failed to deny external client")
                server.settimeout(0.3)
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    pass
                else:
                    connection.close()
                    raise AssertionError("Rejected independent client transmitted")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    require(os.name == "nt", "Windows signed OS client required")
    result = {
        "passed": False, "kind": "unrelated_signed_os_powershell_loopback_control",
        "native_driver_tested": False, "general_packet_pid_proof": False,
        "protected_redirect_available": False, "dns_leak_free": False,
        "win10_11_acceptance": False, "release_accepted": False,
        "process_identity_or_endpoints_saved": False,
        "source_sha": os.environ.get("PR_HEAD_SHA", ""),
    }
    try:
        trial(False)
        trial(True)
        result.update({"negative_go_no_tcp": True, "positive_half_close_http": True,
                       "tested_unrelated_process": True, "passed": True})
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
