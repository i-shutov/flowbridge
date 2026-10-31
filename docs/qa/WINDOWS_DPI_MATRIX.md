# Windows true-DPI layout acceptance (1366×768 / 1920×1080)

2026-10-29. Prepared dedicated VM QA, **not** a claim that 100%, 125%,
150% and 200% have all been accepted.

## What is tested

The compact GUI is Win32 and currently chooses a 980×680 outer minimum.
An ordinary hosted runner checks only *its current display DPI*. An image
that merely exists is not visual or ergonomic acceptance.

To obtain real evidence, `tests/windows_dpi_matrix_vm.py` checks:

1. The operator-configured **actual primary monitor physical resolution** is
   1366×768 or 1920×1080, and the actual Windows work area can contain the
   compact minimum without off-screen cropping.
2. The compiled native C++ harness launches the GUI and reads
   **GetDpiForWindow** on the running native window, not a synthetic DPI
   multiplier. It must equal the operator-selected 96/120/144/192 DPI,
   corresponding to 100/125/150/200% scaling.
3. The existing real GUI smoke checks window and child bounds, non-overlap
   of SSH inputs and DNS checkbox, navigation to five pages, actual FFI
   networking, Start/Stop and clean GUI shutdown.
4. The QA records five distinct, complete BMP captures for Dashboard,
   managed SSH, external SOCKS, Applications and Advanced/Log. Each report
   has the real DPI, resolution, work area, pixel size and SHA-256 of all
   screenshots. Truncation and duplicate views fail the automated check.

These are **geometric** checks. Text readability, contrast, tab order,
screen reader accessibility, 125/150/200% effective hit-target sizes and
legibility must also be **manually reviewed**; a passing hash/rectangle check
is not sufficient to close [#6](https://github.com/i-shutov/flowbridge/issues/6).

## Operator sequence (isolated Windows VM only)

1. Create a snapshot and authorize a disposable Windows 10/11 GUI VM with
   an interactive desktop session and installed Visual Studio C++,
   Rust stable, CMake and Python 3.13. Register a dedicated runner with
   labels `self-hosted, windows, x64, flowbridge-dpi-vm`.
2. Set the monitor *physically* to 1366×768 and display scaling to **100%**;
   sign out/in if required by Windows. Do not simulate a different DPI via
   SendMessage or a screenshot rescale.
3. Run GitHub Actions → **Windows true DPI 100-200% visual QA —
   authorized VM only**; choose expected_dpi=96 and
   expected_resolution=1366x768.
4. Inspect the JSON and all five BMP images, record manual readability,
   keyboard and contrast findings. Repeat the operator display change and
   workflow at **120, 144 and 192 DPI** (125/150/200%). Optionally repeat
   1920×1080. Four separate **actual run IDs and screenshot sets** are
   required for four-DPI acceptance.
5. If the GUI gets clipped, a control is too small, text overlaps or some
   pages are unreachable, fail that gate; correct layout/scroll behavior
   before certifying. Preserve the failing evidence instead of claiming
   compliance.
6. Restore the isolated VM snapshot after the work. Do not run these
   commands on a production workstation or shared runner.

The scripts **never** change OS display scaling or resolution themselves.
The manual-only workflow requires `FLOWBRIDGE_DPI_VM=1`, and its last
`if: always()` step preserves available screenshot/report artifacts on
failure. Normal Windows CI still builds/smokes the UI at its current DPI
and only syntax-checks the dedicated VM runner script.

## Still not accepted

No exact-height/label-size verification at real 125–200% scaling yet;
the app is currently system-DPI-aware, not independently proven per-monitor
V2 DPI-aware across multiple monitors or mid-session monitor switching.
This workflow prepares genuinely reproducible evidence without making a
false all-DPI quality claim. Issue #6 remains open until that evidence
exists and functional/visual remediation is complete.
