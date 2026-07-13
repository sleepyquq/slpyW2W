use std::{collections::BTreeMap, fmt, net::IpAddr};

use ipnet::IpNet;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    ConfigError, FirstHopProfile, LanPolicy, OperatingMode, ProtonProfile, Result, RuntimeOptions,
    RuntimeSelection, SecretValue, TailscalePolicy, ValidationReport, WireGuardConfig,
    validate_rendered_profile,
};

/// slpyW2W 独占的本机 DNS 监听端口，避开 Clash Verge 常用的 1053。
pub const HK_PROTON_DNS_PORT: u16 = 21_053;

pub const FIRST_HOP_SELECTOR: &str = "FirstHopSelector";
pub const PROTON_SELECTOR: &str = "ProtonNodes";
pub const OUTLET_SELECTOR: &str = "HK-Proton-Outlet";

pub struct GeneratedProfile {
    yaml: Zeroizing<String>,
    pub validation: ValidationReport,
}

impl GeneratedProfile {
    pub fn as_str(&self) -> &str {
        &self.yaml
    }

    pub fn into_zeroizing_string(self) -> Zeroizing<String> {
        self.yaml
    }
}

impl fmt::Debug for GeneratedProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedProfile")
            .field("yaml", &"[REDACTED RUNTIME YAML]")
            .field("validation", &self.validation)
            .finish()
    }
}

pub fn generate_profile(
    first_hops: &[FirstHopProfile],
    proton_nodes: &[ProtonProfile],
    selection: &RuntimeSelection,
    lan: &LanPolicy,
    tailscale: &TailscalePolicy,
    runtime: &RuntimeOptions,
) -> Result<GeneratedProfile> {
    if tailscale.exit_node_enabled {
        return Err(ConfigError::TailscaleExitNodeConflict);
    }

    let enabled_first_hops: Vec<_> = first_hops.iter().filter(|node| node.enabled).collect();
    if enabled_first_hops.is_empty() {
        return Err(ConfigError::NoEnabledFirstHop);
    }
    ensure_unique_ids(
        enabled_first_hops.iter().map(|node| node.id.as_str()),
        "第一跳",
    )?;

    let selected_first_hop = enabled_first_hops
        .iter()
        .copied()
        .find(|node| node.id == selection.first_hop)
        .ok_or(ConfigError::SelectedFirstHopUnavailable)?;

    let enabled_protons: Vec<_> = proton_nodes.iter().filter(|node| node.enabled).collect();
    ensure_unique_ids(
        enabled_protons.iter().map(|node| node.id.as_str()),
        "Proton",
    )?;

    let selected_proton = match selection.mode {
        OperatingMode::DoubleHop => {
            let unavailable = if enabled_protons.is_empty() {
                ConfigError::NoEnabledProton
            } else {
                ConfigError::SelectedProtonUnavailable
            };
            Some(
                selection
                    .proton
                    .as_ref()
                    .and_then(|id| enabled_protons.iter().copied().find(|node| &node.id == id))
                    .ok_or(unavailable)?,
            )
        }
        OperatingMode::SingleHop => None,
    };

    for node in &enabled_first_hops {
        validate_first_hop(node)?;
    }
    for node in &enabled_protons {
        validate_proton(node, selected_first_hop)?;
    }

    let mut proxies = Vec::with_capacity(enabled_first_hops.len() + enabled_protons.len());
    for node in &enabled_first_hops {
        proxies.push(wireguard_proxy(
            node.mihomo_name(),
            &node.wireguard,
            WireGuardRole::FirstHop,
            None,
        )?);
    }
    for node in &enabled_protons {
        proxies.push(wireguard_proxy(
            node.mihomo_name(),
            &node.wireguard,
            WireGuardRole::NestedProton,
            Some(FIRST_HOP_SELECTOR),
        )?);
    }

    // 活动组只包含当前选择，避免 Mihomo 的历史选择缓存造成短暂走错链路。
    let mut proxy_groups = vec![ProxyGroup {
        name: FIRST_HOP_SELECTOR,
        kind: "select",
        proxies: vec![selected_first_hop.mihomo_name()],
    }];
    if let Some(proton) = selected_proton {
        proxy_groups.push(ProxyGroup {
            name: PROTON_SELECTOR,
            kind: "select",
            proxies: vec![proton.mihomo_name()],
        });
    }
    proxy_groups.push(ProxyGroup {
        name: OUTLET_SELECTOR,
        kind: "select",
        proxies: vec![match selection.mode {
            OperatingMode::DoubleHop => PROTON_SELECTOR.to_owned(),
            OperatingMode::SingleHop => FIRST_HOP_SELECTOR.to_owned(),
        }],
    });

    let active_dns = match selected_proton {
        Some(node) => ipv4_dns(&node.wireguard)?,
        None => ipv4_dns(&selected_first_hop.wireguard)?,
    };

    let mut route_exclude_address = Vec::new();
    let mut rules = Vec::new();
    if lan.enabled {
        for cidr in &lan.cidrs {
            route_exclude_address.push(cidr.to_string());
            rules.push(direct_cidr_rule(*cidr));
        }
    }
    for cidr in tailscale.cidrs() {
        route_exclude_address.push(cidr.to_string());
        rules.push(direct_cidr_rule(cidr));
    }
    // 外层 WireGuard 握手必须从物理出口抵达第一跳；若也被 TUN 捕获会形成自环。
    // 只排除当前第一跳的精确主机地址，Proton 第二跳仍由 dialer-proxy 强制穿过第一跳。
    route_exclude_address.push(endpoint_host_cidr(
        selected_first_hop
            .wireguard
            .peer
            .endpoint
            .ip()
            .ok_or(ConfigError::InvalidField {
                field: "First-hop Endpoint",
            })?,
    ));
    route_exclude_address.sort();
    route_exclude_address.dedup();

    // 先允许明确的本地 IPv6，再拒绝其余 IPv6，避免物理网卡原生 IPv6 绕过。
    rules.push("IP-CIDR6,::/0,REJECT,no-resolve".to_owned());
    rules.push(format!("MATCH,{OUTLET_SELECTOR}"));

    let (nameserver_policy, direct_nameserver, _fake_ip_filter) = lan_dns_policy(lan)?;
    let config = MihomoConfig {
        mixed_port: runtime.mixed_port,
        allow_lan: false,
        bind_address: "127.0.0.1",
        mode: "rule",
        log_level: "warning",
        ipv6: true,
        external_controller: format!("127.0.0.1:{}", runtime.controller_port),
        secret: runtime.controller_secret.clone(),
        profile: ProfileOptions {
            store_selected: false,
            store_fake_ip: false,
        },
        tun: TunConfig {
            enable: runtime.tun_enabled,
            stack: "mixed",
            device: runtime.tun_device.clone(),
            // 应用流量进入内层 WireGuard 前先限制包长，避免双层封装后的 UDP 包超过外层 MTU。
            mtu: 1280,
            auto_route: true,
            auto_detect_interface: true,
            strict_route: true,
            dns_hijack: vec!["any:53", "tcp://any:53"],
            inet6_address: vec!["fdfe:dcba:9876::1/126"],
            route_address: vec!["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"],
            route_exclude_address,
        },
        dns: DnsConfig {
            enable: true,
            listen: format!("127.0.0.1:{HK_PROTON_DNS_PORT}"),
            ipv6: false,
            // Windows TUN 下 fake-ip 的域名映射路径会重置已接管连接；当前规则统一走
            // slpyW2W 的出口 selector，无需依赖 fake-ip 做域名分流，使用真实解析结果更稳妥。
            enhanced_mode: "redir-host",
            fake_ip_range: "198.18.0.1/16",
            use_hosts: true,
            use_system_hosts: true,
            respect_rules: false,
            nameserver: active_dns
                .iter()
                .map(|ip| dns_uri(*ip, OUTLET_SELECTOR))
                .collect(),
            nameserver_policy,
            direct_nameserver,
            direct_nameserver_follow_policy: true,
            fake_ip_filter: Vec::new(),
        },
        proxies,
        proxy_groups,
        rules,
    };

    let yaml =
        Zeroizing::new(serde_yaml_ng::to_string(&config).map_err(|_| ConfigError::YamlSerialize)?);
    let validation = validate_rendered_profile(&yaml)?;
    Ok(GeneratedProfile { yaml, validation })
}

fn ensure_unique_ids<'a>(ids: impl Iterator<Item = &'a str>, role: &str) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        if !seen.insert(id) {
            return Err(ConfigError::RuntimeValidation(format!(
                "{role}配置 ID 重复"
            )));
        }
    }
    Ok(())
}

fn validate_first_hop(node: &FirstHopProfile) -> Result<()> {
    if node.wireguard.peer.endpoint.is_domain() {
        return Err(ConfigError::FirstHopEndpointNeedsResolution);
    }
    validate_ipv4_wireguard(&node.wireguard)?;
    Ok(())
}

fn validate_proton(node: &ProtonProfile, selected_first_hop: &FirstHopProfile) -> Result<()> {
    if node.wireguard.peer.endpoint.is_domain() {
        return Err(ConfigError::ProtonEndpointNeedsResolution);
    }
    validate_ipv4_wireguard(&node.wireguard)?;

    let endpoint_ip = node
        .wireguard
        .peer
        .endpoint
        .ip()
        .ok_or(ConfigError::ProtonEndpointNeedsResolution)?;
    if !selected_first_hop
        .wireguard
        .peer
        .allowed_ips
        .iter()
        .any(|cidr| cidr.contains(&endpoint_ip))
    {
        return Err(ConfigError::RuntimeValidation(
            "所选第一跳的 AllowedIPs 不覆盖 Proton Endpoint".to_owned(),
        ));
    }
    Ok(())
}

fn validate_ipv4_wireguard(config: &WireGuardConfig) -> Result<()> {
    let ipv4_addresses = config
        .interface
        .addresses
        .iter()
        .filter(|net| net.addr().is_ipv4())
        .count();
    if ipv4_addresses != 1 {
        return Err(ConfigError::TooManyInterfaceAddresses);
    }
    let dns = ipv4_dns(config)?;
    for server in dns {
        if !config
            .peer
            .allowed_ips
            .iter()
            .any(|cidr| cidr.contains(&server))
        {
            return Err(ConfigError::RuntimeValidation(
                "WireGuard AllowedIPs 不覆盖导入的 DNS".to_owned(),
            ));
        }
    }
    if !covers_all_ipv4(&config.peer.allowed_ips) {
        return Err(ConfigError::RuntimeValidation(
            "WireGuard AllowedIPs 未覆盖全部 IPv4 公网流量".to_owned(),
        ));
    }
    Ok(())
}

fn covers_all_ipv4(networks: &[IpNet]) -> bool {
    let mut ranges: Vec<(u32, u32)> = networks
        .iter()
        .filter_map(|network| match network {
            IpNet::V4(network) => {
                Some((u32::from(network.network()), u32::from(network.broadcast())))
            }
            IpNet::V6(_) => None,
        })
        .collect();
    ranges.sort_unstable();
    let Some(&(first_start, first_end)) = ranges.first() else {
        return false;
    };
    if first_start != 0 {
        return false;
    }
    let mut covered_to = first_end;
    for &(start, end) in &ranges[1..] {
        if start > covered_to.saturating_add(1) {
            return false;
        }
        covered_to = covered_to.max(end);
    }
    covered_to == u32::MAX
}

fn wireguard_proxy(
    name: String,
    source: &WireGuardConfig,
    role: WireGuardRole,
    dialer_proxy: Option<&'static str>,
) -> Result<WireGuardProxy> {
    let ipv4 = source
        .interface
        .addresses
        .iter()
        .find_map(|network| match network {
            IpNet::V4(network) => Some(network.addr().to_string()),
            IpNet::V6(_) => None,
        })
        .ok_or(ConfigError::InvalidField {
            field: "IPv4 Address",
        })?;
    let endpoint_ip =
        source
            .peer
            .endpoint
            .ip()
            .filter(IpAddr::is_ipv4)
            .ok_or(ConfigError::InvalidField {
                field: "IPv4 Endpoint",
            })?;
    let allowed_ips: Vec<String> = source
        .peer
        .allowed_ips
        .iter()
        .filter_map(|network| match network {
            IpNet::V4(_) => Some(network.to_string()),
            IpNet::V6(_) => None,
        })
        .collect();

    Ok(WireGuardProxy {
        name,
        kind: "wireguard",
        ip: ipv4,
        private_key: source.interface.private_key.clone(),
        peers: vec![WireGuardPeerYaml {
            server: endpoint_ip.to_string(),
            port: source.peer.endpoint.port,
            public_key: source.peer.public_key.clone(),
            pre_shared_key: source.peer.preshared_key.clone(),
            allowed_ips,
        }],
        persistent_keepalive: source.peer.persistent_keepalive,
        udp: true,
        ip_version: "ipv4",
        // Mihomo 的 WireGuard 默认 MTU 为 1408。Proton 是内层隧道，需要为外层
        // WireGuard 的 UDP/IP 封装预留空间；源配置显式给值时仍以源配置为准。
        mtu: Some(source.interface.mtu.unwrap_or(match role {
            WireGuardRole::FirstHop => 1408,
            WireGuardRole::NestedProton => 1280,
        })),
        dialer_proxy,
        remote_dns_resolve: true,
        dns: ipv4_dns(source)?
            .into_iter()
            .map(|server| server.to_string())
            .collect(),
    })
}

#[derive(Clone, Copy)]
enum WireGuardRole {
    FirstHop,
    NestedProton,
}

fn ipv4_dns(config: &WireGuardConfig) -> Result<Vec<IpAddr>> {
    let servers: Vec<_> = config
        .interface
        .dns_servers
        .iter()
        .copied()
        .filter(IpAddr::is_ipv4)
        .collect();
    if servers.is_empty() {
        return Err(ConfigError::MissingEgressDns);
    }
    Ok(servers)
}

fn direct_cidr_rule(cidr: IpNet) -> String {
    let kind = if cidr.addr().is_ipv4() {
        "IP-CIDR"
    } else {
        "IP-CIDR6"
    };
    format!("{kind},{cidr},DIRECT,no-resolve")
}

fn endpoint_host_cidr(endpoint: IpAddr) -> String {
    match endpoint {
        IpAddr::V4(address) => format!("{address}/32"),
        IpAddr::V6(address) => format!("{address}/128"),
    }
}

fn dns_uri(server: IpAddr, proxy: &str) -> String {
    match server {
        IpAddr::V4(ip) => format!("udp://{ip}:53#{proxy}"),
        IpAddr::V6(ip) => format!("udp://[{ip}]:53#{proxy}"),
    }
}

type LanDnsPolicy = (BTreeMap<String, Vec<String>>, Vec<String>, Vec<String>);

fn lan_dns_policy(lan: &LanPolicy) -> Result<LanDnsPolicy> {
    let mut policy = BTreeMap::new();
    let mut filters = vec![
        "+.lan".to_owned(),
        "+.local".to_owned(),
        "+.home.arpa".to_owned(),
    ];
    if !lan.enabled || lan.dns_servers.is_empty() {
        return Ok((policy, Vec::new(), filters));
    }

    let direct_nameserver: Vec<_> = lan
        .dns_servers
        .iter()
        .copied()
        .map(|server| dns_uri(server, "DIRECT"))
        .collect();
    for suffix in &lan.domain_suffixes {
        let suffix = normalized_domain_suffix(suffix)?;
        let pattern = format!("+.{suffix}");
        policy.insert(pattern.clone(), direct_nameserver.clone());
        filters.push(pattern);
    }
    filters.sort();
    filters.dedup();
    Ok((policy, direct_nameserver, filters))
}

fn normalized_domain_suffix(value: &str) -> Result<String> {
    let value = value.trim().trim_start_matches('.').to_ascii_lowercase();
    let valid = !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        return Err(ConfigError::InvalidField {
            field: "LAN domain suffix",
        });
    }
    Ok(value)
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct MihomoConfig {
    mixed_port: u16,
    allow_lan: bool,
    bind_address: &'static str,
    mode: &'static str,
    log_level: &'static str,
    ipv6: bool,
    external_controller: String,
    secret: SecretValue,
    profile: ProfileOptions,
    tun: TunConfig,
    dns: DnsConfig,
    proxies: Vec<WireGuardProxy>,
    proxy_groups: Vec<ProxyGroup>,
    rules: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct ProfileOptions {
    store_selected: bool,
    store_fake_ip: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct TunConfig {
    enable: bool,
    stack: &'static str,
    device: String,
    mtu: u16,
    auto_route: bool,
    auto_detect_interface: bool,
    strict_route: bool,
    dns_hijack: Vec<&'static str>,
    inet6_address: Vec<&'static str>,
    route_address: Vec<&'static str>,
    route_exclude_address: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct DnsConfig {
    enable: bool,
    listen: String,
    ipv6: bool,
    enhanced_mode: &'static str,
    fake_ip_range: &'static str,
    use_hosts: bool,
    use_system_hosts: bool,
    respect_rules: bool,
    nameserver: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    nameserver_policy: BTreeMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    direct_nameserver: Vec<String>,
    direct_nameserver_follow_policy: bool,
    fake_ip_filter: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct WireGuardProxy {
    name: String,
    #[serde(rename = "type")]
    kind: &'static str,
    ip: String,
    private_key: SecretValue,
    peers: Vec<WireGuardPeerYaml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    persistent_keepalive: Option<u16>,
    udp: bool,
    ip_version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dialer_proxy: Option<&'static str>,
    remote_dns_resolve: bool,
    dns: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct WireGuardPeerYaml {
    server: String,
    port: u16,
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pre_shared_key: Option<SecretValue>,
    allowed_ips: Vec<String>,
}

#[derive(Serialize)]
struct ProxyGroup {
    name: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
    proxies: Vec<String>,
}
