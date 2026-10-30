//! Configuration and deterministic policy evaluation for FlowBridge.
//!
//! Rules use AND across criteria and OR within a criterion. An empty criterion
//! matches any value. Application and host patterns match the entire string,
//! ignoring ASCII case; `*` matches zero or more characters (including dots and
//! path separators) and `?` matches one Unicode scalar. Other characters are
//! literal. Application identity is supplied by the caller: this crate never
//! infers a process, basename, hostname, DNS answer, or reverse-DNS name.
//!
//! A trailing DNS root dot is ignored for host matching. Network criteria use a
//! literal destination IP first, otherwise the caller's optional resolved IP.
//! Hostname resolution is never performed by policy evaluation.
//! Exact IP host criteria compare address identity. IPv4-mapped IPv6 addresses
//! also match the corresponding IPv4 CIDR, while retaining IPv6 CIDR matches.

pub mod capture_policy;
pub mod ndis_ethernet;
pub mod tcp_packet;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_PROXIES: usize = 256;
const MAX_CHAINS: usize = 256;
const MAX_CHAIN_HOPS: usize = 16;
const MAX_RULES: usize = 4096;
const MAX_CRITERIA: usize = 256;
const MAX_APPLICATION_BYTES: usize = 1024;
const MAX_CONNECTIONS: usize = 65_536;
const MAX_NEGOTIATION_TIMEOUT_MS: u64 = 300_000;
const MAX_IDLE_TIMEOUT_MS: u64 = 86_400_000;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid JSON configuration: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(invalid("endpoint port must be nonzero"));
        }
        validate_host(&self.host, false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyKind {
    Socks5,
    Socks4a,
    HttpConnect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    pub id: String,
    pub kind: ProxyKind,
    pub endpoint: Endpoint,
    pub username: Option<String>,
    pub password_env: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    pub id: String,
    pub proxies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    deny_unknown_fields,
    from = "ActionWire"
)]
pub enum Action {
    Direct,
    Block,
    Proxy { id: String },
    Chain { id: String },
}

// Serde's internally tagged unit variants ignore extra fields, even with
// deny_unknown_fields. Empty struct variants in this deserialization adapter
// enforce the same strictness for Direct/Block as for Proxy/Chain.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ActionWire {
    Direct {},
    Block {},
    Proxy { id: String },
    Chain { id: String },
}

impl From<ActionWire> for Action {
    fn from(value: ActionWire) -> Self {
        match value {
            ActionWire::Direct {} => Self::Direct,
            ActionWire::Block {} => Self::Block,
            ActionWire::Proxy { id } => Self::Proxy { id },
            ActionWire::Chain { id } => Self::Chain { id },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub enabled: bool,
    pub applications: Vec<String>,
    pub hosts: Vec<String>,
    pub networks: Vec<IpNet>,
    pub ports: Vec<PortRange>,
    pub action: Action,
}

fn default_remote_dns_via_ssh() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub listen: SocketAddr,
    pub proxies: Vec<Proxy>,
    pub chains: Vec<Chain>,
    pub rules: Vec<Rule>,
    pub default_action: Action,
    pub connect_timeout_ms: u64,
    pub handshake_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub max_connections: usize,
    /// When false, reject hostname destinations without *any* local DNS
    /// fallback. Literal IPs continue to use normal policy/routing. Only
    /// explicit SOCKS input can preserve and forward original hostnames.
    #[serde(default = "default_remote_dns_via_ssh")]
    pub remote_dns_via_ssh: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flow {
    pub application: Option<String>,
    pub destination: Endpoint,
    pub resolved_ip: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub rule_id: Option<String>,
    pub action: Action,
    pub reason: String,
}

impl Config {
    /// Parse strict JSON and validate all entries, including disabled rules.
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        if json.len() > MAX_JSON_BYTES {
            return Err(invalid("JSON exceeds 1 MiB limit"));
        }
        let config: Self = serde_json::from_str(json)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(invalid("only configuration version 1 is supported"));
        }
        if !self.listen.ip().is_loopback() || self.listen.port() == 0 {
            return Err(invalid("listen must use a loopback IP and nonzero port"));
        }
        bounded_timeout(
            "connect_timeout_ms",
            self.connect_timeout_ms,
            MAX_NEGOTIATION_TIMEOUT_MS,
        )?;
        bounded_timeout(
            "handshake_timeout_ms",
            self.handshake_timeout_ms,
            MAX_NEGOTIATION_TIMEOUT_MS,
        )?;
        bounded_timeout("idle_timeout_ms", self.idle_timeout_ms, MAX_IDLE_TIMEOUT_MS)?;
        if !(1..=MAX_CONNECTIONS).contains(&self.max_connections) {
            return Err(invalid("max_connections must be between 1 and 65536"));
        }
        if self.proxies.len() > MAX_PROXIES
            || self.chains.len() > MAX_CHAINS
            || self.rules.len() > MAX_RULES
        {
            return Err(invalid(
                "configuration exceeds proxy, chain, or rule count limit",
            ));
        }

        let mut route_ids = HashSet::new();
        let mut proxy_ids = HashSet::new();
        for proxy in &self.proxies {
            validate_proxy(proxy)?;
            let is_loopback_host = proxy
                .endpoint
                .host
                .parse::<IpAddr>()
                .ok()
                .is_some_and(is_loopback)
                || proxy
                    .endpoint
                    .host
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case("localhost");
            if proxy.endpoint.port == self.listen.port() && is_loopback_host {
                return Err(invalid(format!(
                    "proxy {} points back to the local listener port",
                    proxy.id
                )));
            }
            if !route_ids.insert(proxy.id.as_str()) {
                return Err(invalid(format!("duplicate route id: {}", proxy.id)));
            }
            proxy_ids.insert(proxy.id.as_str());
        }
        let mut chain_ids = HashSet::new();
        for chain in &self.chains {
            validate_id(&chain.id)?;
            if !route_ids.insert(chain.id.as_str()) {
                return Err(invalid(format!("duplicate route id: {}", chain.id)));
            }
            chain_ids.insert(chain.id.as_str());
            if chain.proxies.is_empty() || chain.proxies.len() > MAX_CHAIN_HOPS {
                return Err(invalid(format!(
                    "chain {} must contain 1..=16 proxies",
                    chain.id
                )));
            }
            for id in &chain.proxies {
                if !proxy_ids.contains(id.as_str()) {
                    return Err(invalid(format!(
                        "chain {} references unknown proxy {}",
                        chain.id, id
                    )));
                }
            }
        }
        validate_action(&self.default_action, &proxy_ids, &chain_ids)?;
        let mut rule_ids = HashSet::new();
        for rule in &self.rules {
            validate_id(&rule.id)?;
            if !rule_ids.insert(rule.id.as_str()) {
                return Err(invalid(format!("duplicate rule id: {}", rule.id)));
            }
            if [
                rule.applications.len(),
                rule.hosts.len(),
                rule.networks.len(),
                rule.ports.len(),
            ]
            .iter()
            .any(|&count| count > MAX_CRITERIA)
            {
                return Err(invalid(format!(
                    "rule {} exceeds 256 entries per criterion",
                    rule.id
                )));
            }
            for application in &rule.applications {
                if !valid_application(application) {
                    return Err(invalid(format!("rule {} has an empty, oversized, or control-containing application pattern", rule.id)));
                }
            }
            for host in &rule.hosts {
                validate_host(host, true)?;
            }
            for ports in &rule.ports {
                if ports.start == 0 || ports.end < ports.start {
                    return Err(invalid(format!(
                        "rule {} has an invalid port range",
                        rule.id
                    )));
                }
            }
            validate_action(&rule.action, &proxy_ids, &chain_ids)?;
        }
        Ok(())
    }

    /// Evaluate without performing I/O. Invalid flow input fails closed.
    /// Callers must validate a Config before using it (from_json does this).
    pub fn evaluate(&self, flow: &Flow) -> Decision {
        if flow.destination.validate().is_err()
            || flow
                .application
                .as_ref()
                .is_some_and(|app| !valid_application(app))
        {
            return Decision {
                rule_id: None,
                action: Action::Block,
                reason: "invalid flow endpoint or application identity".into(),
            };
        }
        // The GUI's remote-SSH-DNS switch is a real policy gate. It cannot
        // force local DNS when disabled: that would leak. Reject names before
        // route expansion and before any socket or system resolver is touched.
        if !self.remote_dns_via_ssh && flow.destination.host.parse::<IpAddr>().is_err() {
            return Decision {
                rule_id: None,
                action: Action::Block,
                reason: "remote SSH DNS disabled; hostname rejected without local fallback".into(),
            };
        }
        for rule in &self.rules {
            if rule.enabled && rule.matches(flow) {
                return Decision {
                    rule_id: Some(rule.id.clone()),
                    action: rule.action.clone(),
                    reason: format!("matched rule {}", rule.id),
                };
            }
        }
        Decision {
            rule_id: None,
            action: self.default_action.clone(),
            reason: "no enabled rule matched; using default action".into(),
        }
    }

    /// Expand a route in the configured order. Only Direct returns an empty
    /// route. Block and invalid references are errors, never direct fallbacks.
    pub fn route(&self, action: &Action) -> Result<Vec<Proxy>, ConfigError> {
        let get_proxy = |id: &str| -> Result<Proxy, ConfigError> {
            let mut matches = self.proxies.iter().filter(|proxy| proxy.id == id);
            let proxy = matches
                .next()
                .ok_or_else(|| invalid(format!("unknown proxy: {id}")))?;
            if matches.next().is_some() {
                return Err(invalid(format!("duplicate proxy: {id}")));
            }
            validate_proxy(proxy)?;
            Ok(proxy.clone())
        };
        match action {
            Action::Direct => Ok(Vec::new()),
            Action::Block => Err(invalid("blocked action has no connection route")),
            Action::Proxy { id } => Ok(vec![get_proxy(id)?]),
            Action::Chain { id } => {
                let mut matches = self.chains.iter().filter(|chain| chain.id == *id);
                let chain = matches
                    .next()
                    .ok_or_else(|| invalid(format!("unknown chain: {id}")))?;
                if matches.next().is_some() {
                    return Err(invalid(format!("duplicate chain: {id}")));
                }
                if chain.proxies.is_empty() || chain.proxies.len() > MAX_CHAIN_HOPS {
                    return Err(invalid("chain must contain 1..=16 proxies"));
                }
                chain.proxies.iter().map(|id| get_proxy(id)).collect()
            }
        }
    }
}

impl Rule {
    fn matches(&self, flow: &Flow) -> bool {
        let application_matches = self.applications.is_empty()
            || flow.application.as_ref().is_some_and(|app| {
                self.applications
                    .iter()
                    .any(|pattern| wildcard_matches(pattern, app))
            });
        let host = flow.destination.host.trim_end_matches('.');
        let host_ip = flow.destination.host.parse::<IpAddr>().ok();
        let host_matches = self.hosts.is_empty()
            || self
                .hosts
                .iter()
                .any(|pattern| match (pattern.parse::<IpAddr>().ok(), host_ip) {
                    (Some(pattern_ip), Some(host_ip)) => {
                        canonical_ip(pattern_ip) == canonical_ip(host_ip)
                    }
                    _ => wildcard_matches(pattern.trim_end_matches('.'), host),
                });
        let ip = flow
            .destination
            .host
            .parse::<IpAddr>()
            .ok()
            .or(flow.resolved_ip);
        let network_matches = self.networks.is_empty()
            || ip.is_some_and(|ip| {
                self.networks
                    .iter()
                    .any(|network| network.contains(&ip) || network.contains(&canonical_ip(ip)))
            });
        let port_matches = self.ports.is_empty()
            || self
                .ports
                .iter()
                .any(|ports| (ports.start..=ports.end).contains(&flow.destination.port));
        application_matches && host_matches && network_matches && port_matches
    }
}

fn bounded_timeout(name: &str, value: u64, max: u64) -> Result<(), ConfigError> {
    if value == 0 || value > max {
        return Err(invalid(format!("{name} must be between 1 and {max}")));
    }
    Ok(())
}

fn validate_id(id: &str) -> Result<(), ConfigError> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
    {
        return Err(invalid(
            "ids must contain 1..=64 ASCII letters, digits, underscores, dots, or hyphens",
        ));
    }
    Ok(())
}

fn valid_application(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_APPLICATION_BYTES
        && !value.chars().any(char::is_control)
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

fn validate_proxy(proxy: &Proxy) -> Result<(), ConfigError> {
    validate_id(&proxy.id)?;
    proxy.endpoint.validate()?;
    if let Some(username) = &proxy.username {
        if username.is_empty() || username.len() > 255 || username.chars().any(char::is_control) {
            return Err(invalid(
                "proxy username must contain 1..=255 bytes and no controls",
            ));
        }
        if proxy.kind == ProxyKind::HttpConnect && username.contains(':') {
            return Err(invalid("HTTP Basic username cannot contain a colon"));
        }
    }
    if let Some(name) = &proxy.password_env {
        let mut bytes = name.bytes();
        if name.len() > 128
            || !bytes
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
            || !bytes.all(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            return Err(invalid("password_env must be a conventional ASCII environment variable name of at most 128 bytes"));
        }
    }
    match proxy.kind {
        ProxyKind::Socks4a if proxy.password_env.is_some() => {
            Err(invalid("SOCKS4a does not support passwords"))
        }
        ProxyKind::Socks4a => Ok(()),
        _ if proxy.username.is_some() != proxy.password_env.is_some() => Err(invalid(
            "proxy username and password_env must both be present or absent",
        )),
        _ => Ok(()),
    }
}

fn validate_action(
    action: &Action,
    proxies: &HashSet<&str>,
    chains: &HashSet<&str>,
) -> Result<(), ConfigError> {
    match action {
        Action::Proxy { id } if !proxies.contains(id.as_str()) => {
            Err(invalid(format!("unknown proxy action reference: {id}")))
        }
        Action::Chain { id } if !chains.contains(id.as_str()) => {
            Err(invalid(format!("unknown chain action reference: {id}")))
        }
        _ => Ok(()),
    }
}

fn validate_host(host: &str, pattern: bool) -> Result<(), ConfigError> {
    if host.is_empty()
        || host.len() > 254
        || !host.is_ascii()
        || host
            .bytes()
            .any(|c| c.is_ascii_control() || c.is_ascii_whitespace())
    {
        return Err(invalid(
            "host must be a bounded ASCII DNS name or bare IP without whitespace or controls",
        ));
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() || name.len() > 253 {
        return Err(invalid("DNS host length must be between 1 and 253 bytes"));
    }
    // Reject ambiguous malformed IPv4-looking strings instead of allowing a
    // platform resolver to interpret alternate numeric address formats.
    if !pattern
        && name.split('.').all(|label| {
            !label.is_empty()
                && (label.bytes().all(|c| c.is_ascii_digit())
                    || label
                        .strip_prefix("0x")
                        .or_else(|| label.strip_prefix("0X"))
                        .is_some_and(|hex| {
                            !hex.is_empty() && hex.bytes().all(|c| c.is_ascii_hexdigit())
                        }))
        })
    {
        return Err(invalid("invalid or ambiguous numeric IP address"));
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(|c| {
                c.is_ascii_alphanumeric() || c == b'-' || (pattern && (c == b'*' || c == b'?'))
            })
        {
            return Err(invalid(
                "invalid DNS host or host pattern (use ASCII DNS labels or bare IPv4/IPv6)",
            ));
        }
    }
    Ok(())
}

/// Greedy bounded glob matcher; unlike regex, no recursive/exponential search.
fn wildcard_matches(pattern: &str, value: &str) -> bool {
    if !pattern.contains(['*', '?']) {
        return pattern.eq_ignore_ascii_case(value);
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let (mut p, mut v) = (0, 0);
    let mut star = None;
    let mut retry = 0;
    while v < value.len() {
        if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if p < pattern.len()
            && (pattern[p] == '?' || pattern[p].eq_ignore_ascii_case(&value[v]))
        {
            p += 1;
            v += 1;
        } else if let Some(last_star) = star {
            p = last_star + 1;
            retry += 1;
            v = retry;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}
