# Small block: restrict Windows capture to explicitly selected executables

Base: main `96391d29aab2f42e5567a22e91845f340a4d8cf6`.

Problem: the capture service installed a TCP catch-all. Application selection in
Rust happened only after every application had already been redirected.

Change: `FlowBridgeCapture` now requires one or more `--capture-app ABSOLUTE_EXE`
arguments (maximum 64). Each application is resolved using the Windows full-path
application ID, and gets its own TCP AND application-ID filter on each redirect
layer. No wildcard/catch-all is installed. Driver ownership, explicit SSH/self
bypasses and transactional dynamic-filter lifetime are unchanged. An empty scope
or nonexisting/relative path fails before starting capture.

## Check this block, not the whole beta

`tests/windows_wfp_scope.py` uses a compiled native test client copied to two
separate directories with the SAME executable basename. It makes actual loopback
TCP/UDP connections using IPv4 and IPv6, with no proxy settings. The test installs
the production selector in a disposable BFE dynamic session using a BLOCK action
at ALE_AUTH_CONNECT, checks WSAEACCES only for the selected path/TCP, and verifies
normal stop, abrupt owner termination and repeated activation restore traffic.
It never loads a kernel driver or changes DNS, Secure Boot, or driver policy.

This proves real kernel application/protocol selection and dynamic filter cleanup.
It does NOT prove ALE_CONNECT_REDIRECT, delivery of redirect records, forwarding
through SSH, DNS capture, UI wiring or complete beta readiness. The unsigned
FlowBridge WFP driver remains excluded from automatic hosted-runner activation.

Example after driver installation has been separately approved and validated:

```powershell
FlowBridgeCapture.exe --console --profile C:\QA\profile.json `
  --capture-app C:\QA\client.exe --ssh-profile C:\QA\ssh.json
```

The UI must pass actual selected executable paths before claiming native activation;
this CLI change alone is not UI completion. Existing whole-machine invocation now
fails intentionally instead of implicitly redirecting unrelated applications.

## Execution

```powershell
cmake -S tests/wfp_scope -B build/wfp-scope -A x64
cmake --build build/wfp-scope --config Release
python tests/windows_wfp_scope.py --executable build/wfp-scope/Release/FlowBridgeWfpScopeQA.exe --output build/verification/wfp-scope/result.json
```

Use a disposable elevated Windows test session. The executable only accepts
loopback probe addresses; test filters target a freshly created temporary EXE.
