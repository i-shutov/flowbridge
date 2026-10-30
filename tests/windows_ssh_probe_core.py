"""Bounded, testable acceptance for the manual real-Windows SSH probe.

Socket and process observations are injected, never fabricated by this helper.
Requested tiers are NOT relabelled as actual attempted/successful connections.
"""
from __future__ import annotations

from collections import Counter
import threading
from typing import Callable, Any


class ResourceErrors:
    """Count allowlisted resource markers without keeping raw SSH stderr."""
    def __init__(self) -> None:
        self._counts: Counter[str] = Counter()
        self._lock = threading.Lock()

    def observe(self, line: bytes) -> None:
        text = line[:8192].lower()
        for name, patterns in {
            "too_many_open_files": (b"too many open files", b"emfile", b"enfile"),
            "no_buffer_space": (b"no buffer space", b"10055", b"wsaenobufs"),
            "allocation_failure": (b"cannot allocate memory", b"out of memory"),
        }.items():
            if any(value in text for value in patterns):
                with self._lock:
                    self._counts[name] += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)


def probe_capacity(connect: Callable[[], Any], echo: Callable[[Any, bytes], None],
                   child_alive: Callable[[], bool], sample: Callable[[str], None],
                   report: dict, *, held_limit: int, min_held: int,
                   tiers=(64, 128, 192, 256, 512), recovery_count: int = 16) -> None:
    """Require real baseline channels/bytes and post-release reconnects.

    A requested tier greater than held_limit is visibly capped. One failed
    attempt stops expansion within that tier, never an unbounded retry storm.
    Rejected opens may characterize saturation, but cannot count as success.
    """
    if not (1 <= min_held <= held_limit <= 512 and 1 <= recovery_count <= 64):
        raise ValueError("Require 1 <= min_held <= held_limit <= 512 and bounded recovery")
    held = []
    report.update(attempts=[], actual_connection_attempts=0, successful_connections=0,
                  peak_held=0, recovery_successes=0, capacity_baseline_verified=False,
                  resource_recovery_verified=False, capacity_enforced_by_flowbridge=False)
    try:
        for tier in tiers:
            if not isinstance(tier, int) or not 1 <= tier <= 512:
                raise ValueError("Invalid test tier")
            target = min(tier, held_limit)
            item = {"requested_tier": tier, "target_held": target,
                    "test_ceiling_applied": tier > held_limit,
                    "actual_new_attempts": 0, "accepted_new": 0, "failed_new": 0,
                    "held_at_start": len(held)}
            report["attempts"].append(item)
            while len(held) < target:
                if not child_alive():
                    raise RuntimeError("OpenSSH child exited during capacity probe")
                item["actual_new_attempts"] += 1
                report["actual_connection_attempts"] += 1
                try:
                    candidate = connect()
                except (OSError, EOFError, TimeoutError) as error:
                    item["failed_new"] += 1
                    item["failed_stage"] = "candidate_connect"
                    item["failed_error_type"] = type(error).__name__
                    break
                if candidate is None:
                    item["failed_new"] += 1
                    item["failed_stage"] = "socks_rejected"
                    break
                try:
                    echo(candidate, b"FlowBridge initial real Windows SSH\x00\xff")
                except (OSError, EOFError, TimeoutError) as error:
                    # At the OpenSSH backend's own descriptor ceiling, SOCKS
                    # may accept CONNECT and reset the *new* stream before its
                    # first byte. This is an unaccepted capacity probe, not
                    # corruption of the already-established held channels.
                    candidate.close()
                    item["failed_new"] += 1
                    item["failed_stage"] = "candidate_initial_echo"
                    item["failed_error_type"] = type(error).__name__
                    break
                except BaseException:
                    candidate.close()
                    raise
                held.append(candidate)
                item["accepted_new"] += 1
                report["successful_connections"] += 1
                report["peak_held"] = max(report["peak_held"], len(held))
            item["accepted_held"] = len(held)
            sample(f"tier_{tier}")
            for index, client in enumerate(held):
                echo(client, b"FlowBridge held integrity\x00\xff" + index.to_bytes(2, "big"))
            if not child_alive():
                raise RuntimeError("OpenSSH child exited under held load")
        if len(held) < min_held:
            raise RuntimeError(f"Only {len(held)} real channels verified; required {min_held}")
        report["capacity_baseline_verified"] = True
    finally:
        for client in held:
            client.close()
    sample("after_release")
    # A living process is not evidence that SOCKS/SSH forwarding recovered.
    for index in range(recovery_count):
        if not child_alive():
            raise RuntimeError("OpenSSH child exited before forwarding recovery")
        report["actual_connection_attempts"] += 1
        client = connect()
        if client is None:
            raise RuntimeError("SOCKS forwarding did not recover after load release")
        try:
            echo(client, b"FlowBridge recovered real SSH\x00\xff" + bytes([index]))
        finally:
            client.close()
        report["successful_connections"] += 1
        report["recovery_successes"] += 1
