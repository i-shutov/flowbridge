"""Read-only native Windows GUI-owner process creation FILETIME for VM QA.

This binds the elevated user-mode helper to one process incarnation. It is
NOT a WFP/NDISRD packet owner token and never permits native G2 acceptance.
No driver, WFP policy, service or operating-system setting is modified.
"""
from __future__ import annotations

import ctypes
import os
import sys

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
WAIT_TIMEOUT = 258


class FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


def creation_filetime(pid: int) -> int:
    if sys.platform != "win32" or not isinstance(pid, int) or pid <= 0:
        raise ValueError("A positive native Windows process PID is required")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.GetProcessId.argtypes = [ctypes.c_void_p]
    kernel.GetProcessId.restype = ctypes.c_uint32
    kernel.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(FileTime)] * 4
    kernel.GetProcessTimes.restype = ctypes.c_int
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.WaitForSingleObject.restype = ctypes.c_uint32
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int

    handle = kernel.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
    if not handle:
        raise OSError("GUI owner process handle unavailable")
    try:
        if kernel.GetProcessId(handle) != pid or kernel.WaitForSingleObject(handle, 0) != WAIT_TIMEOUT:
            raise RuntimeError("GUI owner PID changed or its process already exited")
        created = FileTime()
        exited, cpu_kernel, cpu_user = FileTime(), FileTime(), FileTime()
        if not kernel.GetProcessTimes(handle, ctypes.byref(created),
                                      ctypes.byref(exited),
                                      ctypes.byref(cpu_kernel),
                                      ctypes.byref(cpu_user)):
            raise OSError("Windows cannot read the GUI owner process creation time")
        epoch = (int(created.high) << 32) | int(created.low)
        if not epoch:
            raise RuntimeError("GUI owner process creation time is empty")
        return epoch
    finally:
        kernel.CloseHandle(handle)


if __name__ == "__main__":
    print(creation_filetime(os.getpid()))
