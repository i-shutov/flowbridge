# FlowBridge v0.2 implementation contract

User now requests finishing the application and actual installers after providing archive password.
Goal: real native app controlling real Rust engine; complete native integration source paths and
produce a Windows installer in current Linux environment. Native OS testing/signing must be reported accurately.
No original executable or keygen may be executed or redistributed. Original archive is reference only.

## Ownership

- runtime_engine: crates/flowbridge-runtime/**, crates/flowbridge-ffi/**, native/include/flowbridge.h.
- managed_ssh: crates/flowbridge-tunnel/**, runtime upstream gate and SSH C ABI.
- windows_app: native/windows/** EXCEPT native/windows/wfp/**; packaging/windows/**; third_party/nlohmann/** if needed.
- macos_app: native/macos/**; packaging/macos/**.
- Root: workspace/Cargo.lock, net/core/CLI changes, Windows WFP/driver/service, docs, integration tests, artifacts.

Version: workspace 0.2.0. Keep Config schema1 compatible. No user config auto-migration or OS-wide proxy changes.
Rust toolchain exists: CARGO_HOME=/workspace/scratch/78d80ff877dc/toolchain/cargo
RUSTUP_HOME=/workspace/scratch/78d80ff877dc/toolchain/rustup
PATH=/workspace/scratch/78d80ff877dc/toolchain/cargo/bin:$PATH.

## Common runtime API

Preserve fb_validate_json/fb_evaluate_json/fb_string_free. All string results are UTF8 owned JSON,
freed by fb_string_free. Errors: {"ok":false,"error":"..."}. Handles are checked u64 registry IDs, not raw pointers.

```c
char *fb_engine_create_json(const char *config_json); // {ok:true,engine_id:N}
char *fb_engine_start_json(uint64_t engine_id); // {ok:true,status:{...}}
char *fb_engine_stop_json(uint64_t engine_id);
char *fb_engine_reload_json(uint64_t engine_id, const char *config_json);
char *fb_engine_snapshot_json(uint64_t engine_id);
void fb_engine_destroy(uint64_t engine_id); // stop + remove; unknown ID safe no-op

char *fb_stream_open_json(const char *config_json, const char *flow_json);
// -> {ok:true,stream_id:N,decision:{...}}; applies policy; block is error; connects route.
// Called off native UI/provider callback queue. Uses bounded connection/handshake deadlines.
int64_t fb_stream_read(uint64_t id, uint8_t *buffer, size_t capacity);
int64_t fb_stream_write(uint64_t id, const uint8_t *buffer, size_t length);
// >=0 bytes (read0 EOF); -1 I/O error; -2 temporary would-block/timeout; -3 invalid handle/argument.
// Each call has bounded waiting (~200ms). Windows uses nonblocking sockets + WSAPoll;
// a real Windows socket timeout is fatal, not a retryable readiness timeout.
// Single reader/single writer per stream.
int32_t fb_stream_shutdown_write(uint64_t id);
void fb_stream_close(uint64_t id); // shutdown both + remove; cancellation-safe; repeated close safe
```

Snapshot:
```json
{"ok":true,"status":{"running":false,"listen":"127.0.0.1:1081","mode":"explicit_socks5","generation":1,"active":0,"accepted":0,"completed":0,"failed":0,"bytes_up":0,"bytes_down":0,"transparent":false},"connections":[{"id":1,"host":"example.com","port":443,"rule":"default","action":"proxy:ssh","state":"active","bytes_up":0,"bytes_down":0,"error":null}],"events":[{"seq":1,"level":"info","message":"..."}]}
```

The engine owns Tokio runtime/listener/cancellation and bounded recent connections/events. Snapshot is cheap,
native UIs poll at about1Hz. Start acknowledges only after bind succeeds. stop cancels/drains boundedly and
releases port. Reload must validate before apply; allow live rule/proxy changes with fixed listen, max_connections;
reject changed listen/max while running, preserve old config on error. New flows get new revision; existing keep theirs.
Explicit SOCKS rejects enabled application criteria (origin process unknown). Use connect_route_guarded to avoid recursion.
Read/write FFI must cap buffers, validate handles, retain Arc while I/O active, support close waking blocked operations.
Native callers maintain exactly one read and write operation per stream at a time and retry -2 off callback queues.
Snapshots retain all active connections, the latest 512 finished connections and 256 events.

## User-directed SSH and AI / Web expansion

Implemented after the user requested managed SSH with a watchdog and native application templates:

- `flowbridge-tunnel` owns native OpenSSH, without a shell or visible terminal. Configurable ports,
  key/agent authentication, known_hosts, compression, keepalive, deadlines and reconnect backoff.
  Strict host-key checking, explicit Stop, bounded output and Windows kill-on-close Job Object.
- `fb_ssh_create_json/start_json/stop_json/snapshot_json/destroy` expose owned handles and JSON;
  final signatures and bounds are authoritative in `native/include/flowbridge.h`.
- `fb_engine_set_upstream_gate_json` holds new explicit SOCKS connects for the matching first proxy
  hop while SSH recovers; default UI grace 30s, API maximum 120s. Other routes remain independent.
- Existing TCP streams are not resumed or replayed after a lost SSH session. A persistent remote
  relay is designed in `SSH_AND_RECONNECT.md`, but is not included in this release.
- Native UI pages expose structured settings, local discovery and AI / Web / AI + Web presets from
  `resources/presets.json`. Discovery suggestions expose actual observed paths/metadata.
- Explicit SOCKS cannot identify the originating process. Application selections create native
  profiles and must not be presented as active per-application capture in the local-only package.
- OpenSSH must exist on the machine. Password auth, first-trust enrollment and OS secret stores
  are not implemented. Unix abrupt-parent-exit cleanup remains weaker than normal explicit Stop.

## Native product UI minimum

Default usable profile: listen127.0.0.1:1081 -> SSH SOCKS5 at127.0.0.1:1080. No auto-start on installation.
Real Start/Stop, state/error, reload/apply configuration, proxy host/port/protocol quick editor,
open/save profile, advanced JSON for complete rules/chains, current/recent connections and bounded log.
Save settings under user's application data folder, retain them on uninstall. Clear mode labels: local SOCKS
versus transparent capture. No fake active statuses; do not advertise system interception until backend exists and ready.

## Windows native/installer

Root installs MinGW64/CMake/NSIS and builds Rust Windows GNU DLL/staticlib and CLI. Support MinGW and MSVC.
DLL linking preferred for MinGW (flowbridge_ffi.dll + libflowbridge_ffi.dll.a). CMake variable
FLOWBRIDGE_FFI_LIBRARY supplies import/staticlib path. Don't rely on private WinRT packages.
NSIS build produces actual Windows x64 installer, per-user, Unicode, install/uninstall/start-menu, retain config.
Version0.2.0, product FlowBridge. Install GUI, Rust DLL, CLI, examples and concise help. No WFP driver installed
unless a separately built/validated/signed driver is supplied through an explicit future gate.

## macOS native/extension/installer

SwiftUI actual engine controller and views; local mode works without NE. Implement NE TCP flow adapter using
fb_stream_* in background tasks, source metadata and explicit Direct/Block/Proxy semantics. Implement manager
activation/configuration code only with honest unavailable/approval states and validated embedded extension.
Do not use global fake-IP DNS or claim DNS-leak prevention. Runtime native compile requires Xcode; root has Linux.
Provide genuine build/package scripts for .app/.pkg and proper XcodeGen targets, embedding/signing parameters.
No fabricated team IDs/profiles or instructions to disable OS security.

## Gates

Meaningful tests on engine lifecycle, occupied-port bind failure, reload rollback, connection metrics and FFI stream
half-close/cancel. Root cross-compiles Windows real PE outputs, builds NSIS, inspects dependencies and payload.
All agents communicate API deviations before editing. Avoid duplicate cargo builds; root coordinates cache/dependencies.
