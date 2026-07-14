use std::net::IpAddr;

use hk_proton_core::{
    ConfigError, FIRST_HOP_SELECTOR, FirstHopProfile, ImportMetadata, LanPolicy, OUTLET_SELECTOR,
    OperatingMode, PROTON_SELECTOR, ProfileId, ProtonProfile, RuntimeOptions, RuntimeSelection,
    SecretValue, TailscalePolicy, generate_profile, parse_wireguard, validate_rendered_profile,
};
use serde_yaml_ng::Value;
use time::macros::datetime;

const FIRST_HOP_HK: &str = include_str!("fixtures/first-hop-hk.synthetic.conf");
const FIRST_HOP_JP: &str = include_str!("fixtures/first-hop-jp.synthetic.conf");
const PROTON_JP: &str = include_str!("fixtures/proton-jp.synthetic.conf");
const PROTON_SG: &str = include_str!("fixtures/proton-sg.synthetic.conf");

#[test]
fn parses_standard_wireguard_without_exposing_secrets_in_debug() {
    let parsed = parse_wireguard(FIRST_HOP_HK).expect("合成 fixture 应可解析");
    assert_eq!(
        parsed.config.interface.addresses[0].to_string(),
        "10.5.5.2/32"
    );
    assert_eq!(
        parsed.config.interface.dns_servers[0].to_string(),
        "10.5.5.1"
    );
    assert_eq!(parsed.config.peer.endpoint.server(), "203.0.113.10");
    assert_eq!(parsed.config.peer.endpoint.port, 51820);
    assert_eq!(parsed.config.peer.persistent_keepalive, Some(25));
    assert_eq!(parsed.source_sha256.len(), 64);

    let debug = format!("{parsed:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("AQEBAQEBAQ"));
    assert!(!debug.contains("AwMDAwMDAw"));
}

#[test]
fn rejects_wg_quick_commands_and_never_echoes_bad_secret() {
    let unsafe_config = FIRST_HOP_HK.replace(
        "DNS = 10.5.5.1",
        "DNS = 10.5.5.1\nPostUp = powershell.exe -Command ignored",
    );
    assert!(matches!(
        parse_wireguard(&unsafe_config),
        Err(ConfigError::UnsafeDirective { .. })
    ));

    let marker = "THIS_MUST_NOT_APPEAR_IN_AN_ERROR";
    let bad_key = FIRST_HOP_HK.replace("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", marker);
    let error = parse_wireguard(&bad_key).expect_err("无效密钥必须失败");
    assert!(!error.to_string().contains(marker));
    assert!(!format!("{error:?}").contains(marker));
}

#[test]
fn supports_bom_crlf_comments_and_split_default_routes() {
    let input = format!("\u{feff}{}", FIRST_HOP_JP.replace('\n', "\r\n"));
    let parsed = parse_wireguard(&input).expect("BOM/CRLF 应受支持");
    assert_eq!(parsed.config.peer.allowed_ips.len(), 2);
    assert!(parsed.config.peer.preshared_key.is_none());
}

#[test]
fn generates_multiple_nodes_and_a_deterministic_double_hop_path() {
    let fixture = fixture_set();
    let selection = RuntimeSelection {
        mode: OperatingMode::DoubleHop,
        first_hop: id("fh-jp"),
        proton: Some(id("proton-sg")),
    };
    let mut lan = LanPolicy::preset_172_23();
    lan.dns_servers = vec!["172.23.0.1".parse::<IpAddr>().unwrap()];
    lan.domain_suffixes.push("corp.example".to_owned());

    let generated = generate_profile(
        &fixture.first_hops,
        &fixture.protons,
        &selection,
        &lan,
        &TailscalePolicy::standard(),
        &runtime(),
    )
    .expect("双跳配置应生成成功");

    assert_eq!(generated.validation.proxy_count, 4);
    assert_eq!(
        generated.validation.active_path,
        vec![
            OUTLET_SELECTOR,
            PROTON_SELECTOR,
            "PN-proton-sg",
            FIRST_HOP_SELECTOR,
            "FH-fh-jp",
        ]
    );

    let yaml: Value = serde_yaml_ng::from_str(generated.as_str()).unwrap();
    let proxies = yaml["proxies"].as_sequence().unwrap();
    assert_eq!(proxies.len(), 4);
    for proxy in proxies {
        assert!(proxy.get("peers").and_then(Value::as_sequence).is_some());
        assert!(proxy.get("server").is_none(), "必须使用完整 peers 语法");
        assert!(proxy.get("public-key").is_none());
        if proxy["name"].as_str().unwrap().starts_with("PN-") {
            assert_eq!(proxy["dialer-proxy"], FIRST_HOP_SELECTOR);
            assert_eq!(proxy["mtu"].as_u64(), Some(1280));
        } else if proxy["name"].as_str() == Some("FH-fh-hk") {
            // 源配置显式给出的 MTU 必须保留。
            assert_eq!(proxy["mtu"].as_u64(), Some(1360));
        } else {
            assert_eq!(proxy["mtu"].as_u64(), Some(1408));
        }
    }

    assert_eq!(yaml["tun"]["mtu"].as_u64(), Some(1280));
    assert_eq!(yaml["dns"]["enhanced-mode"].as_str(), Some("redir-host"));
    assert_eq!(yaml["profile"]["store-fake-ip"].as_bool(), Some(false));

    assert_eq!(group_members(&yaml, FIRST_HOP_SELECTOR), vec!["FH-fh-jp"]);
    assert_eq!(group_members(&yaml, PROTON_SELECTOR), vec!["PN-proton-sg"]);
    assert_eq!(group_members(&yaml, OUTLET_SELECTOR), vec![PROTON_SELECTOR]);

    let excludes = yaml["tun"]["route-exclude-address"].as_sequence().unwrap();
    let excludes: Vec<_> = excludes.iter().filter_map(Value::as_str).collect();
    assert!(excludes.contains(&"172.23.0.0/16"));
    assert!(excludes.contains(&"100.64.0.0/10"));
    assert!(excludes.contains(&"fd7a:115c:a1e0::/48"));
    assert!(excludes.contains(&"203.0.113.11/32"));
    assert!(!excludes.contains(&"203.0.113.10/32"));
    assert!(!excludes.iter().any(|value| value.contains("198.51.100")));
    assert!(yaml["tun"]["inet6-address"].is_sequence());

    let nameservers = yaml["dns"]["nameserver"].as_sequence().unwrap();
    assert_eq!(nameservers.len(), 1, "双跳公网 DNS 只能来自当前出口节点");
    assert_eq!(
        nameservers[0].as_str(),
        Some("udp://10.3.0.1:53#HK-Proton-Outlet")
    );
    assert_eq!(
        find_proxy(&yaml, "FH-fh-jp").unwrap()["dns"][0].as_str(),
        Some("10.6.0.1"),
        "转发节点必须保留自己的 DNS"
    );
    assert_eq!(
        find_proxy(&yaml, "PN-proton-sg").unwrap()["dns"][0].as_str(),
        Some("10.3.0.1"),
        "出口节点必须保留自己的 DNS"
    );
    assert!(
        nameservers
            .iter()
            .all(|server| !server.as_str().unwrap_or_default().contains("10.6.0.1")),
        "双跳公网 DNS 不得混入转发节点 DNS"
    );
    assert!(
        !generated
            .as_str()
            .to_ascii_lowercase()
            .contains("system://")
    );
    assert!(!format!("{generated:?}").contains("AQEBAQEBAQ"));
}

#[test]
fn single_hop_uses_the_selected_first_hop_and_its_dns() {
    let fixture = fixture_set();
    let selection = RuntimeSelection {
        mode: OperatingMode::SingleHop,
        first_hop: id("fh-hk"),
        // 单跳时保留库存选择不会影响运行路径。
        proton: Some(id("proton-jp")),
    };
    let generated = generate_profile(
        &fixture.first_hops,
        &fixture.protons,
        &selection,
        &LanPolicy::default(),
        &TailscalePolicy::default(),
        &runtime(),
    )
    .expect("单跳配置应生成成功");
    let yaml: Value = serde_yaml_ng::from_str(generated.as_str()).unwrap();

    assert_eq!(group_members(&yaml, FIRST_HOP_SELECTOR), vec!["FH-fh-hk"]);
    assert!(find_group(&yaml, PROTON_SELECTOR).is_none());
    assert_eq!(
        group_members(&yaml, OUTLET_SELECTOR),
        vec![FIRST_HOP_SELECTOR]
    );
    assert_eq!(
        yaml["dns"]["nameserver"][0].as_str(),
        Some("udp://10.5.5.1:53#HK-Proton-Outlet")
    );
    assert_eq!(
        yaml["dns"]["nameserver"].as_sequence().unwrap().len(),
        1,
        "单跳公网 DNS 只能来自当前转发节点"
    );
    assert_eq!(
        generated.validation.active_path,
        vec![OUTLET_SELECTOR, FIRST_HOP_SELECTOR, "FH-fh-hk"]
    );
}

#[test]
fn updates_to_each_resource_class_do_not_rewrite_the_other_class() {
    let mut fixture = fixture_set();
    let selection = RuntimeSelection {
        mode: OperatingMode::DoubleHop,
        first_hop: id("fh-hk"),
        proton: Some(id("proton-jp")),
    };
    let base = render_value(&fixture, &selection);
    let base_proton = find_proxy(&base, "PN-proton-jp").unwrap().clone();

    fixture.first_hops[0].metadata.config_version += 1;
    fixture.first_hops[0].wireguard.interface.mtu = Some(1320);
    let after_first_hop = render_value(&fixture, &selection);
    assert_eq!(
        find_proxy(&after_first_hop, "PN-proton-jp").unwrap(),
        &base_proton,
        "更新第一跳不应改写 Proton 节点"
    );

    let stable_first_hop = find_proxy(&after_first_hop, "FH-fh-hk").unwrap().clone();
    fixture.protons[0].metadata.config_version += 1;
    fixture.protons[0].wireguard.interface.mtu = Some(1240);
    let after_proton = render_value(&fixture, &selection);
    assert_eq!(
        find_proxy(&after_proton, "FH-fh-hk").unwrap(),
        &stable_first_hop,
        "更新 Proton 不应改写第一跳节点"
    );
}

#[test]
fn rendered_validation_catches_missing_references_cycles_and_direct_leaks() {
    let fixture = fixture_set();
    let selection = RuntimeSelection {
        mode: OperatingMode::DoubleHop,
        first_hop: id("fh-hk"),
        proton: Some(id("proton-jp")),
    };
    let generated = generate_profile(
        &fixture.first_hops,
        &fixture.protons,
        &selection,
        &LanPolicy::default(),
        &TailscalePolicy::default(),
        &runtime(),
    )
    .unwrap();

    let missing = generated.as_str().replace(
        "dialer-proxy: FirstHopSelector",
        "dialer-proxy: MissingGroup",
    );
    assert!(matches!(
        validate_rendered_profile(&missing),
        Err(ConfigError::RuntimeValidation(_))
    ));

    let direct = generated
        .as_str()
        .replace("MATCH,HK-Proton-Outlet", "MATCH,DIRECT");
    assert!(matches!(
        validate_rendered_profile(&direct),
        Err(ConfigError::RuntimeValidation(_))
    ));

    let wrong_endpoint_exclusion = generated
        .as_str()
        .replace("203.0.113.10/32", "198.51.100.20/32");
    assert!(matches!(
        validate_rendered_profile(&wrong_endpoint_exclusion),
        Err(ConfigError::RuntimeValidation(_))
    ));

    let mut cyclic: Value = serde_yaml_ng::from_str(generated.as_str()).unwrap();
    let first_hop_group = find_group_mut(&mut cyclic, FIRST_HOP_SELECTOR).unwrap();
    first_hop_group["proxies"] = Value::Sequence(vec![Value::String(OUTLET_SELECTOR.to_owned())]);
    let cyclic = serde_yaml_ng::to_string(&cyclic).unwrap();
    assert!(matches!(
        validate_rendered_profile(&cyclic),
        Err(ConfigError::RuntimeValidation(_))
    ));
}

#[test]
fn rejects_overbroad_lan_and_tailscale_exit_node() {
    let fixture = fixture_set();
    let selection = RuntimeSelection {
        mode: OperatingMode::SingleHop,
        first_hop: id("fh-hk"),
        proton: None,
    };
    let overbroad = LanPolicy {
        enabled: true,
        cidrs: vec!["10.0.0.0/8".parse().unwrap()],
        ..LanPolicy::default()
    };
    assert!(matches!(
        generate_profile(
            &fixture.first_hops,
            &fixture.protons,
            &selection,
            &overbroad,
            &TailscalePolicy::default(),
            &runtime(),
        ),
        Err(ConfigError::RuntimeValidation(_))
    ));

    let exit_node = TailscalePolicy {
        enabled: true,
        exit_node_enabled: true,
    };
    assert!(matches!(
        generate_profile(
            &fixture.first_hops,
            &fixture.protons,
            &selection,
            &LanPolicy::default(),
            &exit_node,
            &runtime(),
        ),
        Err(ConfigError::TailscaleExitNodeConflict)
    ));
}

struct FixtureSet {
    first_hops: Vec<FirstHopProfile>,
    protons: Vec<ProtonProfile>,
}

fn fixture_set() -> FixtureSet {
    FixtureSet {
        first_hops: vec![
            first_hop("fh-hk", "香港 WireGuard", FIRST_HOP_HK),
            first_hop("fh-jp", "日本 WireGuard", FIRST_HOP_JP),
        ],
        protons: vec![
            proton("proton-jp", "Proton JP", PROTON_JP),
            proton("proton-sg", "Proton SG", PROTON_SG),
        ],
    }
}

fn first_hop(id_value: &str, name: &str, source: &str) -> FirstHopProfile {
    let parsed = parse_wireguard(source).unwrap();
    FirstHopProfile::new(
        id(id_value),
        name,
        parsed.config,
        metadata(parsed.source_sha256),
    )
    .unwrap()
}

fn proton(id_value: &str, name: &str, source: &str) -> ProtonProfile {
    let parsed = parse_wireguard(source).unwrap();
    ProtonProfile::new(
        id(id_value),
        name,
        parsed.config,
        metadata(parsed.source_sha256),
    )
    .unwrap()
}

fn metadata(hash: String) -> ImportMetadata {
    ImportMetadata::new(datetime!(2026-07-12 00:00 UTC), 1, hash)
}

fn id(value: &str) -> ProfileId {
    ProfileId::new(value).unwrap()
}

fn runtime() -> RuntimeOptions {
    RuntimeOptions::checked(
        true,
        17890,
        19090,
        SecretValue::new("synthetic-controller-secret"),
    )
    .unwrap()
}

fn render_value(fixture: &FixtureSet, selection: &RuntimeSelection) -> Value {
    let generated = generate_profile(
        &fixture.first_hops,
        &fixture.protons,
        selection,
        &LanPolicy::default(),
        &TailscalePolicy::default(),
        &runtime(),
    )
    .unwrap();
    serde_yaml_ng::from_str(generated.as_str()).unwrap()
}

fn find_group<'a>(yaml: &'a Value, name: &str) -> Option<&'a Value> {
    yaml["proxy-groups"]
        .as_sequence()?
        .iter()
        .find(|group| group["name"].as_str() == Some(name))
}

fn find_group_mut<'a>(yaml: &'a mut Value, name: &str) -> Option<&'a mut Value> {
    yaml["proxy-groups"]
        .as_sequence_mut()?
        .iter_mut()
        .find(|group| group["name"].as_str() == Some(name))
}

fn group_members<'a>(yaml: &'a Value, name: &str) -> Vec<&'a str> {
    find_group(yaml, name).unwrap()["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect()
}

fn find_proxy<'a>(yaml: &'a Value, name: &str) -> Option<&'a Value> {
    yaml["proxies"]
        .as_sequence()?
        .iter()
        .find(|proxy| proxy["name"].as_str() == Some(name))
}
