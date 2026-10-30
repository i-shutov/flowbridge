# Windows loopback 10k-churn scope and failed evidence

An unrestricted one-machine 3-hop churn in workflow 41011459160 failed after
4,988 completed channels (5,003 starts, 15 failures). The preceding 128-held
baseline, 1,152 managed overload refusals, byte integrity and release all passed.
The actual Windows 9.5p2 client HANDLE count was 164 before/after/release/failure
and 292 under 128 held streams; it was not leaking observed process handles.
At failure netstat recorded 16,684 TIME_WAIT entries. The SSH server reported
outbound connect failure; the echo remained reachable via Python autobind.
These observations suggest source-port reservation pressure in the shared
loopback test machine, but TIME_WAIT count alone is not definitive proof of
port exhaustion or proof of an internal descriptor leak. Keep failed evidence.

The long Windows recycling phase now explicitly limits NEW channel starts to
15 per second, with unchanged 128-flow capacity/overload tests. All 10,000
successful binary echoes, half-closes, same original PID and zero final permits
remain required. It is NOT a throughput benchmark or proof of surviving
unbounded connection creation. No OS dynamic-port range, TIME_WAIT registry,
firewall or production admission parameter is changed. The JSON records the
rate, exact starts/completions/failures, elapsed time and resource samples.
A negative outcome additionally probes explicit-bind vs autobind and records
numeric Windows errors without saving network destinations.

The original 251/252-active-channel issue is a DIFFERENT measurement from
many short closed TCP sockets in TIME_WAIT. A separate bare-client capacity
probe still attempts bounded 64/128/192/256/512 tiers. Do not close full Issue #7
without real user-platform/WFP, fairness/rate-policy and prolonged soak evidence.

Primary context: Microsoft TCP/IP port-exhaustion troubleshooting; distinguish
TIME_WAIT from process-owned handles and use actual bind failures/counters.
