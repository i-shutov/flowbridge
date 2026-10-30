"""Disposable loopback load-test dialer; never used by production routing.

On Windows a long series of connections to the SAME loopback listener can
raise WSAEADDRINUSE/10048 while the listener and SSH transport remain healthy.
Request a source port with an explicit bind and retry only this one Winsock
address-collision condition, with a small fixed retry budget. Never retry a
SOCKS rejection, TCP reset, timeout or an actual transport failure.
"""
import errno
import os
import socket
import threading
import time


class LoopbackDialer:
    def __init__(self, *, windows=None, socket_factory=socket.socket,
                 sleep=time.sleep, max_addrinuse_retries=6):
        if not 0 <= max_addrinuse_retries <= 8:
            raise ValueError("Retry budget must remain bounded")
        self.windows = os.name == "nt" if windows is None else bool(windows)
        self.socket_factory = socket_factory
        self.sleep = sleep
        self.max_addrinuse_retries = max_addrinuse_retries
        self.lock = threading.Lock()
        self.logical_connections = 0
        self.addrinuse_retries = 0
        self.addrinuse_exhaustions = 0

    def _record(self, field):
        with self.lock:
            setattr(self, field, getattr(self, field) + 1)

    def snapshot(self):
        with self.lock:
            return {
                "explicit_windows_loopback_bind": self.windows,
                "logical_connections": self.logical_connections,
                "addrinuse_retries": self.addrinuse_retries,
                "addrinuse_exhaustions": self.addrinuse_exhaustions,
                "max_retries_per_connection": self.max_addrinuse_retries,
            }

    def connect(self, port, *, timeout=8):
        if not 1 <= port <= 65535:
            raise ValueError("Invalid loopback destination port")
        if not self.windows:
            client = socket.create_connection(("127.0.0.1", port), timeout=timeout)
            self._record("logical_connections")
            return client
        for retry in range(self.max_addrinuse_retries + 1):
            client = self.socket_factory(socket.AF_INET, socket.SOCK_STREAM)
            try:
                client.settimeout(timeout)
                client.bind(("127.0.0.1", 0))
                client.connect(("127.0.0.1", port))
                self._record("logical_connections")
                return client
            except OSError as error:
                client.close()
                # Only Winsock address-in-use is a local loopback candidate.
                # A SOCKS/SSH/backend failure must remain an immediate failure.
                code = getattr(error, "winerror", None)
                if code != 10048 and error.errno not in (10048, errno.EADDRINUSE):
                    raise
                if retry == self.max_addrinuse_retries:
                    self._record("addrinuse_exhaustions")
                    raise
                self._record("addrinuse_retries")
                self.sleep(min(0.015 * (retry + 1), 0.1))
