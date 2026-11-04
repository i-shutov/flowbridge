# Controlled HTTP origin: G1 rollout and evidence contract

## Интеграция существующего узла, 04.11.2026

Владелец разрешил использовать существующий сервер `153.80.246.207` только
на TCP `18080`. Архив не нужен: исходники берутся непосредственно из GitHub
с закреплением точного commit SHA. Wolfram, Docker, nginx/Caddy, порты 80/443
и действующие службы не изменяются. Подтверждённый исходящий IPv4 Windows VPS
пока не предоставлен: подготовка допускается, внешний listener не запускается.
Подготовка через Linux runner не является native NDISRD workflow.

Защищённая native-конфигурация и оба Rust-клиента разрешают только `80` и
`18080`; для этого стенда порт всегда явно `18080`. Исходный TCP destination,
SOCKS CONNECT, sshd PermitOpen и PowerShell используют один origin.port.
Независимый PowerShell-клиент больше не имеет default 80. Все 23 фазы,
57-байтный запрос, PID/epoch, TCP/ACK/FIN и запрет DIRECT fallback сохраняются.

Для LIVE обязательны проверенный исходящий IPv4 клиента, свободный порт,
новый nonce, отдельный private журнал и конечный срок работы. Если IPv4 или
порт недоступны, результат — STAGED без listener. Обычный HTTP и ранний
half-close в локальных тестах доказывают только fixture, не путь Windows→origin.
G1 остаётся OPEN: причинный эксперимент и 10/10 полных нативных испытаний
на одном проверенном source/binary set ещё не выполнены. Их dispatch требует
отдельной авторизации, новых SHA-проверок, VNC, SYSTEM rescue,
Defender/firewall и rollback.

Status: implementation locally checked; external deployment and native acceptance
NOT performed. This is a QA fixture, not a production routing backend. It does not
fix or prove the cause of the historical two empty upstream responses.

## What is different

The native harness no longer accepts an implicit/public HTTP oracle. It requires
an explicit owner-controlled literal IPv4 destination and verifies ordinary HTTP
and early-write-half-close exchange independently before native work. The original
57-byte request, original destination, all 23 native phases, signed-OS clients,
owner/epoch/TCP restrictions and negative criteria remain unchanged.

The literal `Host: example.com` in the fixed historical request is intentionally
retained for a byte-identical experiment. It is **not** resolved or contacted by
this fixture. Only the owner-configured IP is used. Replacing it with another
public website is not an acceptable fix.

## Provisioning boundaries

Run the origin on a separately authorized, reachable interface/host, not the
Windows test machine's own address or a loopback/TEST-NET alias. Otherwise traffic
may bypass the physical adapter and cannot prove NDISRD interception. No new paid
machine, third-party relay, firewall change or server reuse is authorized by this
implementation. Configure it only after ownership/access approval. The server
binds exactly one specified address, admits only the specified peer address,
accepts only the fixed request, limits concurrent handlers to four and lifetime to
one hour, and never forwards traffic or changes services/network policy.

Example commands are templates; replace placeholders with approved private values.
Do not put real endpoints or process identities into GitHub comments or artifacts.

```text
python tests/g1_controlled_origin.py serve --owner-authorized \
  --bind <ORIGIN_INTERFACE_IPV4> --port 18080 --allow-peer <VPS_EGRESS_IPV4> \
  --run-nonce <32_LOWERCASE_HEX_DIGITS> --seconds 900 \
  --output <NEW_PROTECTED_RECEIPT_FILE>
```

Create the nonce once per bounded workflow experiment with
`python -c "import secrets; print(secrets.token_hex(16))"`. It is a correlation
identifier, **not an authentication secret**. Use a new, exclusively created
receipt file; never append a new experiment to old evidence. Bind conflicts fail,
not replace an existing service. Port 80 may require local OS authorization; do
not disable firewall/Defender or silently elevate to make the fixture start.

## Protected local context

The existing private workflow must load the approved values without logging them.
Retain its adapter/local-IP/rescue/Defender fields and make `target_ipv4` equal to
`controlled_origin.ipv4`:

```json
{
  "adapter_name": "<VERIFIED_ADAPTER>",
  "local_ipv4": "<VERIFIED_VPS_IPV4>",
  "target_ipv4": "<APPROVED_ORIGIN_IPV4>",
  "recovery_armed": true,
  "defender_active": true,
  "controlled_origin": {
    "schema": "flowbridge_g1_controlled_origin_v1",
    "owner_authorized": true,
    "ipv4": "<APPROVED_ORIGIN_IPV4>",
    "port": 18080,
    "run_nonce": "<32_LOWERCASE_HEX_DIGITS>"
  }
}
```

These true values are attestations to actual completed preflight actions, never
instructions to bypass them. Placeholders are deliberately invalid. Missing consent,
unknown fields, hostname, local/loopback/TEST-NET destination, wrong port or target
mismatch fail closed before FFI/SSH/native execution. The private old workflow is
still pinned to historical source until a separate exact-byte repin is completed.
Do not dispatch that old ref as a test of this implementation.

Before any native run, a separate no-driver discriminator is available:

```text
python tests/g1_controlled_origin.py probe --context <PROTECTED_CONTEXT_JSON> \
  --source-sha <EXACT_40_HEX_SOURCE_SHA> --socks-port <EXISTING_LOOPBACK_SOCKS_PORT> \
  --output <NEW_PREFLIGHT_REPORT_JSON>
```

Omit the SOCKS option to check only direct origin availability. This command does
not start SSH. Each path gets one ordinary and one half-close request, no retries.
A rejected/broken SOCKS connection never falls back to direct. The explicitly
labeled direct observation is a separate unselected QA control, not selected-app
routing. Its result always states native_test_executed=false and release_accepted=false.

## Native integration and causal interpretation

The initial direct controls must match the exact nonce-bearing response. After
real managed SSH setup, separate SOCKS controls must match it too. After restart
there is **no new warm-up** before the original native phase. If a native phase
fails, the harness first retains that original result. Only when its own rollback
and external-client exit are confirmed does it execute the bounded direct/SOCKS
comparison. The phase and whole native job remain failed. Failed/unknown rollback
means no further controls.

| Observation | Meaning, with required qualification |
|---|---|
| CONNECT succeeds, response is zero | Classify upstream EOF, not HTTP success; does not locate the exact earlier closing process |
| Direct fails too | Origin/network availability remains a confounder; no causal Rust fix justified |
| Direct passes, SOCKS fails | Narrows that control's failure to the proxy/SSH path; not proof of the preceding native request's cause |
| Controls pass, native fails | Preserve native failure and compare independent origin receipts, half-close and reverse path; no retry-to-green |
| Wrong nonce/response | Fail the control, including otherwise syntactically valid HTTP |

Collect origin JSONL independently of the Windows agent. It records only run nonce,
fixed-request/response hashes and receipt/write outcomes: no IP, PID or packet
payload. A completed server send is **not** proof of client receipt. Correlate it
with the exact workflow/trial/phase and existing relay/client byte counts. The
existing native Rust report exposes length, not response digest; its new length
check alone is not per-phase nonce authentication. A separate reviewer must audit
server receipts; passing local controls alone never authorizes native G1 acceptance.

## Reproducible checks and release boundary

```text
python -m unittest discover -s tests -p test_g1_controlled_origin.py -v
python -m py_compile tests/g1_controlled_origin.py tests/windows_ndisrd_self_redirect.py
```

Eight local tests pass: real loopback ordinary/half-close origin and SOCKS forwarding,
empty-response after successful CONNECT, rejection/truncation with no fallback,
stale nonce, strict context rejection, pre-FFI rejection, scoped/bounded server and
exclusive journal. The SOCKS fault peer is synthetic; these are NOT real OpenSSH,
NDISRD, Windows 10/11 or leak-free evidence. Hosted workflows run the same check
without a driver. All existing CI tests remain mandatory.

The native tooling ZIP gains only `g1_controlled_origin.py`: twelve payload files
plus manifest, thirteen total. Private exact allowlist and all byte pins must be
updated only after independent new-artifact verification. No vendor driver, keys
or fixture listener is bundled into the five-file product candidate.

G1 still needs authorized manual execution with fresh safety gates and >=10/10
full 23-phase same-SHA native PASS after causal correction/review. G2-G6 remain open.
See [release plan](../../plans/windows-release-g0-g6.md).
