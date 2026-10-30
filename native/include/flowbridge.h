#ifndef FLOWBRIDGE_H
#define FLOWBRIDGE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* In-process ABI: callers supply valid UTF-8 NUL-terminated strings and buffers.
 * Every returned JSON string is Rust-owned and must be freed exactly once with
 * fb_string_free. Errors are {"ok":false,"error":"..."}. Handles are checked,
 * process-local uint64 registry IDs, never pointers. Unknown destroy/close is safe.
 * All engine control and stream open calls belong on a worker queue. */
/* Offline, allowlist-redacted report from {engine:<snapshot>,ssh:<snapshot>}.
 * Contains no raw logs, profile, keys, paths or destination names. */
char *fb_diagnostic_report_json(const char *snapshot_json);
char *fb_validate_json(const char *config_json);
char *fb_evaluate_json(const char *config_json, const char *flow_json);
void fb_string_free(char *value);

/* Create validates explicit SOCKS compatibility; enabled application criteria
 * are rejected because this mode cannot authenticate the originating process.
 * start returns success only after the loopback listener is actually bound.
 * stop cancels active connections and releases the port. Reload is atomic and
 * rejects listen/max_connections changes while running. Snapshot contains status,
 * all active connections (bounded by max_connections), the last 512 completed
 * connections, and 256 events. No system interception is enabled. */
char *fb_engine_create_json(const char *config_json);
char *fb_engine_start_json(uint64_t engine_id);
char *fb_engine_stop_json(uint64_t engine_id);
char *fb_engine_reload_json(uint64_t engine_id, const char *config_json);
char *fb_engine_snapshot_json(uint64_t engine_id);
/* Gate only flows whose first proxy hop is the supplied loopback endpoint.
 * {endpoint:{host:"127.0.0.1",port:1080}|null,ready:true,grace_ms:30000}.
 * New matching flows may wait for readiness; existing TCP bytes are never replayed. */
char *fb_engine_set_upstream_gate_json(uint64_t engine_id, const char *gate_json);
/* Independent managed OpenSSH worker selection (1..=4 local listeners).
 * The first worker must match the existing configured SOCKS5 proxy.
 * Workers: [{endpoint:{host:"127.0.0.1",port:1080},ready:true}, ...].
 * Provide strict per-worker limits and aggregate_max_flows >= workers*max_flows.
 * Caller owns/monitors separate SSH processes; this does not launch SSH,
 * alter local DNS or migrate/replay established streams. */
char *fb_engine_set_upstream_pool_json(uint64_t engine_id, const char *pool_json);
/* Preferred desktop-GUI API: derive ports, PIDs and readiness from live,
 * registered OpenSSH supervisors instead of caller-supplied ready flags.
 * Input: {"ssh_ids":[id1,id2], "limits":{...}, "aggregate_max_flows":128,
 *         "enabled":true}. Optional enabled defaults true; false masks every
 * worker unready WITHOUT changing budgets or asserting process availability.
 * Duplicate/stale/missing handles are rejected atomically without changing
 * the active route. The GUI still owns process start/stop and error handling. */
char *fb_engine_sync_owned_ssh_pool_json(uint64_t engine_id, const char *pool_json);
void fb_engine_destroy(uint64_t engine_id);

/* Native capture session: caller attests application identity. Upstream readiness
 * expires without heartbeats (default 5 seconds); only new managed flows wait.
 * Options: managed_endpoint|null, ready=false, ready_lease_ms=5000,
 * pause_grace_ms=30000, limits={max_flows:128,max_opening:16,max_queued:64,wait_timeout_ms:10000}.
 * Does not install a driver, start SSH, or change any machine-wide DNS setting.
 * destroy cancels pending opens and shuts down all this session's streams. */
char *fb_native_create_json(const char *config_json, const char *options_json);
char *fb_native_set_gate_json(uint64_t session_id, const char *gate_json);
char *fb_native_reload_json(uint64_t session_id, const char *config_json);
char *fb_native_snapshot_json(uint64_t session_id);
char *fb_native_stream_open_json(uint64_t session_id, const char *flow_json);
char *fb_native_stream_open_wfp_json(uint64_t session_id, const char *flow_json,
                                   const uint8_t *records, size_t length);
/* DNS wire query/answer arrays, no system settings changes or local fallback. */
char *fb_native_dns_exchange_json(uint64_t session_id, const char *request_json);
char *fb_native_dns_start_json(uint64_t session_id, const char *options_json);
void fb_native_dns_stop(uint64_t session_id);
void fb_native_destroy(uint64_t session_id);

/* Stream open applies supplied flow policy and connects Direct/Proxy/Chain,
 * refusing Block. A native capture provider supplies application identity.
 * Connect + all proxy handshakes have a total 30-second deadline.
 * open => {ok:true,stream_id:N,decision:{...}}.
 * I/O: >=0 byte count (read 0 is EOF); -1 I/O error; -2 temporary timeout;
 * -3 invalid handle/argument or concurrent operation in the same direction.
 * Maximum buffer is 1 MiB. Each I/O call has a ~200ms readiness deadline on
 * Windows and a socket timeout on Unix.
 * Partial writes are normal. Exactly one reader and one writer may run at once.
 * A zero-length operation permits NULL, after validating the handle.
 * shutdown_write returns 0 success or a negative I/O status, preserving reads.
 * close cancels both directions and safely wakes outstanding operations. */
char *fb_stream_open_json(const char *config_json, const char *flow_json);
/* Windows WFP service only: opaque redirect records (1..65536 bytes) are copied
 * and attached BEFORE every outbound socket connect. Failure never falls back
 * to a socket without records. Other platforms return an owned JSON error. */
char *fb_stream_open_wfp_json(const char *config_json, const char *flow_json,
                              const uint8_t *records, size_t length);
int64_t fb_stream_read(uint64_t stream_id, uint8_t *buffer, size_t capacity);
int64_t fb_stream_write(uint64_t stream_id, const uint8_t *buffer, size_t length);
int32_t fb_stream_shutdown_write(uint64_t stream_id);
void fb_stream_close(uint64_t stream_id);
/* Managed OpenSSH -D: keys/agent, strict enrolled host keys, no terminal.
 * Required config: host,user. Defaults: port22, local_port1080,
 * identity_file/known_hosts_file null, compression false,
 * server_alive_interval_secs15, server_alive_count_max3, connect_timeout_secs10,
 * health_check_interval_ms1000, health_check_timeout_ms1000,
 * startup_timeout_ms15000, restart_initial_delay_ms1000,
 * restart_max_delay_ms30000, max_restarts0 (unlimited).
 * start launches supervision; poll state for actual ready. Explicit stop cancels
 * reconnects and reaps the child. No existing TCP session survives SSH restart.
 * Windows uses a kill-on-close process job. On Unix abrupt parent death can
 * leave the child alive; normal stop/destroy performs cleanup.
 * Returns {ok:true,status:{state,pid,local_port,restarts,attempt,last_error,...},
 * events:[{seq,level,message}],stderr:[...]}; create returns ssh_id.
 * At most 16 supervisors. All returned strings use fb_string_free. */
char *fb_ssh_create_json(const char *config_json);
char *fb_ssh_start_json(uint64_t ssh_id);
char *fb_ssh_stop_json(uint64_t ssh_id);
char *fb_ssh_snapshot_json(uint64_t ssh_id);
/* Authenticated read of remote /etc/resolv.conf; never guesses a public DNS. */
char *fb_ssh_remote_dns_json(uint64_t ssh_id);
void fb_ssh_destroy(uint64_t ssh_id);
#ifdef __cplusplus
}
#endif
#endif
