# SSH diagnostics and managed admission

Implementation checkpoint, not a production-release claim.

SSH status reports the resolved executable, a bounded ssh -V probe, resource-error count/time, diagnostic code and consecutive health failures. Resource exhaustion places the supervisor in degraded. Native UIs close the existing new-flow gate for every state except ready. Repeated errors are counted but rate-limited in logs. An overloaded live SSH child is not killed for failed health probes. Two successful checks after the quiet interval reopen the gate; user Stop still terminates the owned child. Existing streams cannot be migrated or resumed after actual SSH death.

health_failure_threshold (default 3, 1..20) and overload_quiet_ms (default 5000, 100..300000) are accepted in SSH JSON. A SOCKS greeting does not prove remote connectivity.

The explicit SOCKS runtime shares an admission budget across engines using the same managed loopback endpoint. Gate JSON accepts limits: max_flows (128), max_opening (16), max_queued (64), wait_timeout_ms (10000). Permits return on cancellation, timeout and disconnect. No DIRECT or local-DNS fallback. Conflicting active limits are rejected. Counts appear as managed_upstream in the engine snapshot. Defaults are conservative, not a measured universal capacity.

Remaining release gates: native WFP/NE path budget integration, selected Windows backend stress/soak tests, fair per-application admission, independent SSH pool, DNS capture for applications resolving before CONNECT, signing and small-screen/DPI acceptance. Unmanaged external clients of the SSH listener are outside this process-local budget. Issue #7 remains open.

Native UIs provide a redacted diagnostic JSON export. An allowlist in Rust excludes profiles, keys, usernames, full executable paths, destination hosts and arbitrary errors/logs. The report marks unmeasured OS descriptor counts and unverified transparent DNS explicitly. It uses cached status and performs no network probes.
