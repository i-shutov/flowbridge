use flowbridge_core::{Action, Chain, Config, Endpoint, Flow, PortRange, Proxy, ProxyKind, Rule};

fn config() -> Config {
    Config {
        version: 1,
        listen: "127.0.0.1:1081".parse().unwrap(),
        proxies: vec![
            proxy("first", "127.0.0.1", 1080),
            proxy("second", "upstream.example", 8080),
        ],
        chains: vec![Chain {
            id: "both".into(),
            proxies: vec!["first".into(), "second".into()],
        }],
        rules: vec![],
        default_action: Action::Block,
        connect_timeout_ms: 10_000,
        handshake_timeout_ms: 10_000,
        idle_timeout_ms: 60_000,
        max_connections: 256,
    }
}

fn proxy(id: &str, host: &str, port: u16) -> Proxy {
    Proxy {
        id: id.into(),
        kind: ProxyKind::Socks5,
        endpoint: Endpoint {
            host: host.into(),
            port,
        },
        username: None,
        password_env: None,
    }
}

fn rule(id: &str, action: Action) -> Rule {
    Rule {
        id: id.into(),
        enabled: true,
        applications: vec![],
        hosts: vec![],
        networks: vec![],
        ports: vec![],
        action,
    }
}

fn flow(host: &str, port: u16) -> Flow {
    Flow {
        application: None,
        destination: Endpoint {
            host: host.into(),
            port,
        },
        resolved_ip: None,
    }
}

#[test]
fn strict_json_roundtrip_and_missing_fields() {
    let json = serde_json::to_string(&config()).unwrap();
    assert_eq!(Config::from_json(&json).unwrap(), config());
    let mut value = serde_json::to_value(config()).unwrap();
    value.as_object_mut().unwrap().remove("max_connections");
    assert!(Config::from_json(&value.to_string()).is_err());
    assert!(Config::from_json(&(json + " null")).is_err());
}

#[test]
fn rejects_unknown_json_fields_everywhere_including_actions() {
    for pointer in [
        "",
        "/proxies/0",
        "/proxies/0/endpoint",
        "/chains/0",
        "/default_action",
    ] {
        let mut value = serde_json::to_value(config()).unwrap();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("typo".into(), true.into());
        assert!(
            Config::from_json(&value.to_string()).is_err(),
            "accepted unknown at {pointer}"
        );
    }
    let mut cfg = config();
    cfg.rules
        .push(rule("r", Action::Proxy { id: "first".into() }));
    cfg.rules[0].ports.push(PortRange { start: 80, end: 80 });
    for pointer in ["/rules/0", "/rules/0/ports/0", "/rules/0/action"] {
        let mut value = serde_json::to_value(&cfg).unwrap();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("typo".into(), true.into());
        assert!(
            Config::from_json(&value.to_string()).is_err(),
            "accepted unknown at {pointer}"
        );
    }
}

#[test]
fn rejects_plaintext_password_and_duplicate_json_fields() {
    let mut value = serde_json::to_value(config()).unwrap();
    value["proxies"][0]["password"] = "do-not-store-this".into();
    assert!(Config::from_json(&value.to_string()).is_err());
    let json = serde_json::to_string(&config()).unwrap().replacen(
        "\"version\":1",
        "\"version\":1,\"version\":1",
        1,
    );
    assert!(Config::from_json(&json).is_err());
}

#[test]
fn action_deserializer_rejects_extra_fields_on_unit_variants() {
    for json in [
        r#"{"type":"direct","id":"first"}"#,
        r#"{"type":"block","id":null}"#,
        r#"{"type":"direct","type":"block"}"#,
        r#"{"type":"proxy"}"#,
        r#"{"type":"proxy","id":"first","extra":true}"#,
        r#"{"type":"fallback"}"#,
    ] {
        assert!(
            serde_json::from_str::<Action>(json).is_err(),
            "accepted {json}"
        );
    }
    for action in [
        Action::Direct,
        Action::Block,
        Action::Proxy { id: "first".into() },
        Action::Chain { id: "both".into() },
    ] {
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(serde_json::from_str::<Action>(&json).unwrap(), action);
    }
}

#[test]
fn loopback_only_and_nonzero_listener() {
    for address in ["127.0.0.1:1081", "127.7.8.9:1081", "[::1]:1081"] {
        let mut cfg = config();
        cfg.listen = address.parse().unwrap();
        assert!(cfg.validate().is_ok());
    }
    for address in [
        "0.0.0.0:1081",
        "[::]:1081",
        "192.168.1.1:1081",
        "127.0.0.1:0",
    ] {
        let mut cfg = config();
        cfg.listen = address.parse().unwrap();
        assert!(cfg.validate().is_err());
    }
}

#[test]
fn rejects_simple_proxy_recursion_including_mapped_ipv6() {
    for host in [
        "127.0.0.1",
        "127.9.8.7",
        "::1",
        "::ffff:127.0.0.1",
        "LOCALHOST.",
    ] {
        let mut cfg = config();
        cfg.proxies[0].endpoint = Endpoint {
            host: host.into(),
            port: cfg.listen.port(),
        };
        assert!(cfg.validate().is_err(), "accepted recursion to {host}");
    }
}

#[test]
fn rejects_malformed_endpoints_and_control_injection() {
    for host in [
        "",
        " example.org",
        "example.org ",
        "example.org\r\nX: y",
        "bad\0host",
        "http://example.org",
        "a..b",
        "-bad.org",
        "bad-.org",
        "a_b.org",
        "[::1]",
        "example.org:80",
        "127.1",
        "999.1.1.1",
        "2130706433",
        "0x7f000001",
        "0X7F.0.0.1",
        "0177.0.0.1",
        "☃.example",
        ".",
    ] {
        assert!(
            Endpoint {
                host: host.into(),
                port: 80
            }
            .validate()
            .is_err(),
            "accepted {host:?}"
        );
    }
    for host in [
        "localhost",
        "EXAMPLE.org.",
        "xn--n3h.example",
        "192.0.2.1",
        "2001:db8::1",
    ] {
        assert!(
            Endpoint {
                host: host.into(),
                port: 80
            }
            .validate()
            .is_ok(),
            "rejected {host}"
        );
    }
    assert!(Endpoint {
        host: "example.org".into(),
        port: 0
    }
    .validate()
    .is_err());
    assert!(Endpoint {
        host: format!("{}.org", "a".repeat(64)),
        port: 80
    }
    .validate()
    .is_err());
}

#[test]
fn explicit_unknown_application_never_matches_even_wildcard() {
    let mut cfg = config();
    let mut app_rule = rule("process", Action::Direct);
    app_rule.applications = vec!["*".into()];
    cfg.rules.push(app_rule);
    let mut known = flow("example.org", 443);
    assert_eq!(cfg.evaluate(&known).action, Action::Block);
    known.application = Some("browser.exe".into());
    assert_eq!(cfg.evaluate(&known).rule_id.as_deref(), Some("process"));
    known.application = Some("".into());
    assert_eq!(cfg.evaluate(&known).action, Action::Block);
}

#[test]
fn first_enabled_match_wins_with_default() {
    let mut cfg = config();
    let mut disabled = rule("disabled", Action::Block);
    disabled.enabled = false;
    cfg.rules = vec![
        disabled,
        rule("first-match", Action::Direct),
        rule("later", Action::Block),
    ];
    let decision = cfg.evaluate(&flow("example.org", 443));
    assert_eq!(decision.rule_id.as_deref(), Some("first-match"));
    assert_eq!(decision.action, Action::Direct);
    cfg.rules.clear();
    let decision = cfg.evaluate(&flow("example.org", 443));
    assert_eq!(decision.rule_id, None);
    assert_eq!(decision.action, Action::Block);
}

#[test]
fn criteria_are_anded_and_sets_are_ored() {
    let mut cfg = config();
    let mut r = rule("all", Action::Direct);
    r.applications = vec!["other".into(), "browser*".into()];
    r.hosts = vec!["other.example".into(), "*.example.org".into()];
    r.networks = vec![
        "10.0.0.0/8".parse().unwrap(),
        "192.0.2.0/24".parse().unwrap(),
    ];
    r.ports = vec![
        PortRange { start: 80, end: 80 },
        PortRange {
            start: 440,
            end: 443,
        },
    ];
    cfg.rules.push(r);
    cfg.validate().unwrap();
    let mut f = flow("API.Example.ORG.", 443);
    f.application = Some("Browser.EXE".into());
    f.resolved_ip = Some("192.0.2.55".parse().unwrap());
    assert_eq!(cfg.evaluate(&f).action, Action::Direct);
    let mut bad = f.clone();
    bad.application = Some("curl".into());
    assert_eq!(cfg.evaluate(&bad).action, Action::Block);
    let mut bad = f.clone();
    bad.destination.host = "example.net".into();
    assert_eq!(cfg.evaluate(&bad).action, Action::Block);
    let mut bad = f.clone();
    bad.resolved_ip = Some("203.0.113.1".parse().unwrap());
    assert_eq!(cfg.evaluate(&bad).action, Action::Block);
    let mut bad = f;
    bad.destination.port = 444;
    assert_eq!(cfg.evaluate(&bad).action, Action::Block);
}

#[test]
fn globs_have_whole_string_case_insensitive_and_literal_semantics() {
    let mut cfg = config();
    let mut r = rule("glob", Action::Direct);
    r.hosts = vec!["API?.EXAMPLE.ORG".into()];
    cfg.rules.push(r);
    for name in ["api1.example.org", "APIZ.example.org."] {
        assert_eq!(cfg.evaluate(&flow(name, 80)).action, Action::Direct);
    }
    for name in [
        "api.example.org",
        "xapi1.example.org",
        "api12.example.org",
        "api1.example.org.evil",
    ] {
        assert_eq!(cfg.evaluate(&flow(name, 80)).action, Action::Block);
    }
    cfg.rules[0].hosts = vec!["*.example.org".into()];
    assert_eq!(
        cfg.evaluate(&flow("a.b.example.org", 80)).action,
        Action::Direct
    );
    assert_eq!(cfg.evaluate(&flow("example.org", 80)).action, Action::Block);
    cfg.rules[0].hosts.clear();
    cfg.rules[0].applications = vec!["C:\\Tools\\App[1].EXE".into()];
    let mut f = flow("example.org", 80);
    f.application = Some("c:\\tools\\app[1].exe".into());
    assert_eq!(cfg.evaluate(&f).action, Action::Direct);
    f.application = Some("app[1].exe".into());
    assert_eq!(cfg.evaluate(&f).action, Action::Block);
    cfg.rules[0].applications = vec!["*a".into()];
    f.application = Some("*ba".into());
    assert_eq!(cfg.evaluate(&f).action, Action::Direct);
    cfg.rules[0].applications = vec!["app?.exe".into()];
    f.application = Some("appé.exe".into());
    assert_eq!(cfg.evaluate(&f).action, Action::Direct);
}

#[test]
fn ipv4_ipv6_cidr_boundaries_and_no_dns_inference() {
    let mut cfg = config();
    let mut r = rule("network", Action::Direct);
    r.networks = vec![
        "192.0.2.0/24".parse().unwrap(),
        "2001:db8::/32".parse().unwrap(),
    ];
    cfg.rules.push(r);
    for ip in ["192.0.2.0", "192.0.2.255", "2001:db8::", "2001:db8:ffff::1"] {
        assert_eq!(cfg.evaluate(&flow(ip, 80)).action, Action::Direct);
    }
    for ip in ["192.0.3.0", "2001:db9::1", "example.org"] {
        assert_eq!(cfg.evaluate(&flow(ip, 80)).action, Action::Block);
    }
    let mut f = flow("example.org", 80);
    f.resolved_ip = Some("192.0.2.1".parse().unwrap());
    assert_eq!(cfg.evaluate(&f).action, Action::Direct);
    // A supplied resolved IP cannot override a literal destination address.
    f.destination.host = "203.0.113.1".into();
    assert_eq!(cfg.evaluate(&f).action, Action::Block);
    cfg.rules[0].networks.clear();
    cfg.rules[0].hosts = vec!["example.org".into()];
    f.destination.host = "192.0.2.1".into();
    assert_eq!(cfg.evaluate(&f).action, Action::Block);
}

#[test]
fn mapped_ipv6_cannot_bypass_ipv4_policy_and_retains_ipv6_cidr_matches() {
    let mut cfg = config();
    cfg.default_action = Action::Direct;
    let mut r = rule("loopback-block", Action::Block);
    r.networks = vec!["127.0.0.0/8".parse().unwrap()];
    cfg.rules.push(r);
    for host in ["127.0.0.1", "::ffff:127.0.0.1", "0:0:0:0:0:ffff:7f00:1"] {
        assert_eq!(
            cfg.evaluate(&flow(host, 80)).rule_id.as_deref(),
            Some("loopback-block")
        );
    }
    let mut resolved = flow("example.org", 80);
    resolved.resolved_ip = Some("::ffff:127.0.0.1".parse().unwrap());
    assert_eq!(cfg.evaluate(&resolved).action, Action::Block);
    cfg.rules[0].networks = vec!["::ffff:127.0.0.0/104".parse().unwrap()];
    assert_eq!(
        cfg.evaluate(&flow("::ffff:127.0.0.1", 80)).action,
        Action::Block
    );
    assert_eq!(cfg.evaluate(&flow("127.0.0.1", 80)).action, Action::Direct);
}

#[test]
fn exact_ip_host_patterns_use_address_identity_and_globs_use_text() {
    let mut cfg = config();
    let mut r = rule("ip", Action::Direct);
    r.hosts = vec!["::1".into(), "127.0.0.1".into()];
    cfg.rules.push(r);
    for host in ["0:0:0:0:0:0:0:1", "::1", "::ffff:127.0.0.1"] {
        assert_eq!(cfg.evaluate(&flow(host, 80)).action, Action::Direct);
    }
    cfg.rules[0].hosts = vec!["127.*".into()];
    assert_eq!(cfg.evaluate(&flow("127.0.0.1", 80)).action, Action::Direct);
    assert_eq!(
        cfg.evaluate(&flow("::ffff:127.0.0.1", 80)).action,
        Action::Block
    );
}

#[test]
fn rejects_duplicate_ids_and_bad_refs_even_in_disabled_rules() {
    let mut cfg = config();
    cfg.proxies.push(cfg.proxies[0].clone());
    assert!(cfg.validate().is_err());
    let mut cfg = config();
    cfg.chains[0].id = "first".into();
    assert!(cfg.validate().is_err());
    let mut cfg = config();
    cfg.chains.push(cfg.chains[0].clone());
    assert!(cfg.validate().is_err());
    let mut cfg = config();
    cfg.chains[0].proxies = vec!["missing".into()];
    assert!(cfg.validate().is_err());
    let mut cfg = config();
    cfg.chains[0].proxies.clear();
    assert!(cfg.validate().is_err());
    let mut cfg = config();
    cfg.default_action = Action::Proxy {
        id: "missing".into(),
    };
    assert!(cfg.validate().is_err());
    let mut cfg = config();
    let mut r = rule(
        "r",
        Action::Chain {
            id: "missing".into(),
        },
    );
    r.enabled = false;
    cfg.rules.push(r);
    assert!(cfg.validate().is_err());
    let mut cfg = config();
    cfg.rules = vec![rule("same", Action::Block), rule("same", Action::Direct)];
    assert!(cfg.validate().is_err());
}

#[test]
fn route_expansion_preserves_order_and_never_falls_back() {
    let cfg = config();
    assert_eq!(cfg.route(&Action::Direct).unwrap(), vec![]);
    assert!(cfg.route(&Action::Block).is_err());
    assert_eq!(
        cfg.route(&Action::Proxy { id: "first".into() }).unwrap(),
        vec![cfg.proxies[0].clone()]
    );
    assert_eq!(
        cfg.route(&Action::Chain { id: "both".into() }).unwrap(),
        cfg.proxies
    );
    assert!(cfg
        .route(&Action::Proxy {
            id: "missing".into()
        })
        .is_err());
    assert!(cfg
        .route(&Action::Chain {
            id: "missing".into()
        })
        .is_err());
    let mut broken = config();
    broken.chains[0].proxies.push("missing".into());
    assert!(broken.route(&Action::Chain { id: "both".into() }).is_err());
    broken.chains[0].proxies.clear();
    assert!(broken.route(&Action::Chain { id: "both".into() }).is_err());
}

#[test]
fn rejects_invalid_ports_timeouts_versions_and_resource_limits() {
    let mut cfg = config();
    cfg.version = 2;
    assert!(cfg.validate().is_err());
    for value in [0, 300_001, u64::MAX] {
        let mut cfg = config();
        cfg.connect_timeout_ms = value;
        assert!(cfg.validate().is_err());
        let mut cfg = config();
        cfg.handshake_timeout_ms = value;
        assert!(cfg.validate().is_err());
    }
    for value in [0, 86_400_001, u64::MAX] {
        let mut cfg = config();
        cfg.idle_timeout_ms = value;
        assert!(cfg.validate().is_err());
    }
    for value in [0, 65_537, usize::MAX] {
        let mut cfg = config();
        cfg.max_connections = value;
        assert!(cfg.validate().is_err());
    }
    for ports in [
        PortRange { start: 0, end: 80 },
        PortRange {
            start: 443,
            end: 80,
        },
    ] {
        let mut cfg = config();
        let mut r = rule("r", Action::Direct);
        r.ports.push(ports);
        cfg.rules.push(r);
        assert!(cfg.validate().is_err());
    }
    let mut cfg = config();
    cfg.rules = vec![rule("r", Action::Direct)];
    cfg.rules[0].hosts = vec!["*".into(); 257];
    assert!(cfg.validate().is_err());
    let mut cfg = config();
    cfg.chains[0].proxies = vec!["first".into(); 17];
    assert!(cfg.validate().is_err());
    assert!(Config::from_json(&" ".repeat(1024 * 1024 + 1)).is_err());
}

#[test]
fn validates_auth_configuration_without_reading_secrets() {
    let mut cfg = config();
    cfg.proxies[0].username = Some("user".into());
    assert!(cfg.validate().is_err());
    cfg.proxies[0].password_env = Some("FLOWBRIDGE_TEST_PASSWORD".into());
    assert!(cfg.validate().is_ok());
    for name in ["", "1BAD", "BAD=NAME", "bad name", "BAD\nNAME"] {
        cfg.proxies[0].password_env = Some(name.into());
        assert!(cfg.validate().is_err());
    }
    cfg.proxies[0].password_env = None;
    cfg.proxies[0].kind = ProxyKind::Socks4a;
    assert!(cfg.validate().is_ok());
    cfg.proxies[0].username = Some("user\0injection".into());
    assert!(cfg.validate().is_err());
    cfg.proxies[0].kind = ProxyKind::HttpConnect;
    cfg.proxies[0].username = Some("user:bad".into());
    cfg.proxies[0].password_env = Some("PASSWORD".into());
    assert!(cfg.validate().is_err());
}

#[test]
fn invalid_flow_fails_closed_even_with_permissive_default() {
    let mut cfg = config();
    cfg.default_action = Action::Direct;
    assert_eq!(
        cfg.evaluate(&flow("evil\r\nHost: x", 80)).action,
        Action::Block
    );
    assert_eq!(cfg.evaluate(&flow("example.org", 0)).action, Action::Block);
    let mut f = flow("example.org", 80);
    f.application = Some("x\0.exe".into());
    assert_eq!(cfg.evaluate(&f).action, Action::Block);
}

#[test]
fn rejects_invalid_host_patterns_and_application_controls() {
    for pattern in ["", "example.org\n", "a..b", "[*.]", "http://*", "a_b"] {
        let mut cfg = config();
        let mut r = rule("r", Action::Direct);
        r.hosts.push(pattern.into());
        cfg.rules.push(r);
        assert!(cfg.validate().is_err());
    }
    for pattern in ["", "app\0", "app\n", &"x".repeat(1025)] {
        let mut cfg = config();
        let mut r = rule("r", Action::Direct);
        r.applications.push(pattern.into());
        cfg.rules.push(r);
        assert!(cfg.validate().is_err());
    }
}
