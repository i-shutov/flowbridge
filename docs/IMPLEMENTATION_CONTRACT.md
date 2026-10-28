# FlowBridge — implementation contract (v0.1)

Historical v0.1 contract. Current desktop/SSH scope, APIs and release status are documented in
`IMPLEMENTATION_V02.md`, `ARCHITECTURE.md` and `VERIFICATION.md`; this file preserves the original design decisions.

Working name: FlowBridge. Independent implementation, not a modification of Proxifier.
The initial deliverable is a tested Rust user-mode proxy core and native integration sources.
It must never claim that transparent OS interception is operational before native build/signing/VM tests.

## Ownership

- Core agent: `crates/flowbridge-core/**` only.
- Network agent: `crates/flowbridge-net/**` only.
- Platform agent: `native/**`, `docs/PLATFORMS.md` only.
- Root: workspace, CLI, FFI, examples, integration, other documentation, packaging.

## Core public API

All model types are public, derive Debug, Clone, Serialize, Deserialize; enums use snake_case.
All config structs reject unknown JSON fields. Configuration contains no plaintext passwords.

```rust
pub struct Endpoint { pub host: String, pub port: u16 }
pub enum ProxyKind { Socks5, Socks4a, HttpConnect }
pub struct Proxy { pub id: String, pub kind: ProxyKind, pub endpoint: Endpoint,
    pub username: Option<String>, pub password_env: Option<String> }
pub struct Chain { pub id: String, pub proxies: Vec<String> }
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action { Direct, Block, Proxy { id: String }, Chain { id: String } }
pub struct PortRange { pub start: u16, pub end: u16 }
pub struct Rule { pub id: String, pub enabled: bool, pub applications: Vec<String>,
    pub hosts: Vec<String>, pub networks: Vec<ipnet::IpNet>, pub ports: Vec<PortRange>, pub action: Action }
pub struct Config { pub version: u32, pub listen: std::net::SocketAddr,
    pub proxies: Vec<Proxy>, pub chains: Vec<Chain>, pub rules: Vec<Rule>, pub default_action: Action,
    pub connect_timeout_ms: u64, pub handshake_timeout_ms: u64, pub idle_timeout_ms: u64,
    pub max_connections: usize }
pub struct Flow { pub application: Option<String>, pub destination: Endpoint,
    pub resolved_ip: Option<std::net::IpAddr> }
pub struct Decision { pub rule_id: Option<String>, pub action: Action, pub reason: String }
impl Config {
    pub fn from_json(json: &str) -> Result<Self, ConfigError>;
    pub fn validate(&self) -> Result<(), ConfigError>;
    pub fn evaluate(&self, flow: &Flow) -> Decision;
    pub fn route(&self, action: &Action) -> Result<Vec<Proxy>, ConfigError>;
}
impl Endpoint { pub fn validate(&self) -> Result<(), ConfigError>; }
```

Match rules in order, first matching enabled rule wins; AND across criteria, OR within one criterion.
No hostname inference from IP/reverse DNS. No process identity inference in explicit SOCKS ingress.
Reject empty chains, invalid references, duplicates, malformed endpoints/ports, non-loopback listeners,
zero/unbounded timeouts and excessive resource limits. Empty criteria mean any. Proxy error never becomes direct.

## Network public API

```rust
pub async fn connect_route(target: &Endpoint, route: &[Proxy],
    connect_timeout: std::time::Duration, handshake_timeout: std::time::Duration)
    -> Result<tokio::net::TcpStream, NetError>;
pub async fn connect_route_guarded(target: &Endpoint, route: &[Proxy],
    connect_timeout: std::time::Duration, handshake_timeout: std::time::Duration,
    forbidden_listener: std::net::SocketAddr)
    -> Result<tokio::net::TcpStream, NetError>;
pub async fn accept_socks5(stream: &mut tokio::net::TcpStream,
    timeout: std::time::Duration) -> Result<Endpoint, NetError>;
pub async fn reply_socks5(stream: &mut tokio::net::TcpStream, code: u8)
    -> Result<(), NetError>;
pub async fn relay(a: &mut tokio::net::TcpStream, b: &mut tokio::net::TcpStream,
    idle_timeout: std::time::Duration) -> Result<(u64, u64), NetError>;
```

SOCKS5 CONNECT + optional RFC1929 auth; SOCKS4a; HTTP CONNECT + optional Basic auth.
Proxy chains negotiate next hop on the same tunnel. Resolve only first-hop endpoint locally.
Remote DNS for hostname targets via SOCKS5/SOCKS4a/CONNECT. Direct explicitly uses local resolver.
The guarded connector resolves the actual first TCP hop once, rejects loopback/mapped-loopback
results at the listener port, then connects to the same vetted address set. Later tunnel targets
remain remote. CLI serve/check use this guarded API; no pre-decision block on remote target strings.
Only TCP for v0.1. Reject SOCKS5 UDP ASSOCIATE/BIND with appropriate status, no silent fallback.
Bound all handshake input and header sizes, reject CRLF/control characters; preserve post-header bytes.
Relay must handle half-close correctly and reset idle timeout on activity in either direction.

## Dependencies and build

Rust edition 2021; workspace dependencies provided by root: serde (derive), serde_json, thiserror,
ipnet (serde), tokio (full), base64, clap (derive), tracing, tracing-subscriber.
Agents create their crate Cargo.toml with inherited version/edition and workspace dependencies. Crates remain unpublished (publish = false); distribution license is not selected.
Do not run uploaded executables or add original software binaries to the new source tree.
Do not write outside owned paths. Root will install a local Rust toolchain and run integration tests.
