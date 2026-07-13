use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use ipnet::IpNet;
use serde::{Deserialize, de::IgnoredAny};

use crate::{ConfigError, FIRST_HOP_SELECTOR, OUTLET_SELECTOR, PROTON_SELECTOR, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationReport {
    pub proxy_count: usize,
    pub group_count: usize,
    /// 从最终出口开始展开的内部路径，不含任何地址或密钥。
    pub active_path: Vec<String>,
}

/// 验证最终渲染的 YAML，而不是只验证生成器输入。
///
/// 这一步专门防止历史上出现过的“源模型正确、运行时 YAML 丢节点”问题。
pub fn validate_rendered_profile(yaml: &str) -> Result<ValidationReport> {
    let profile: RuntimeProjection =
        serde_yaml_ng::from_str(yaml).map_err(|_| ConfigError::YamlParse)?;

    validate_general(&profile)?;
    let graph = validate_references(&profile)?;
    validate_routes(&profile)?;
    validate_dns(&profile, &graph.names)?;
    let active_path = graph.active_path()?;

    Ok(ValidationReport {
        proxy_count: profile.proxies.len(),
        group_count: profile.proxy_groups.len(),
        active_path,
    })
}

fn validate_general(profile: &RuntimeProjection) -> Result<()> {
    if profile.allow_lan
        || profile.bind_address != "127.0.0.1"
        || !profile.external_controller.starts_with("127.0.0.1:")
    {
        return invalid("监听地址不是预期的本机隔离配置");
    }
    if !profile.ipv6 || profile.dns.ipv6 {
        return invalid("IPv6 接管或 DNS IPv6 策略不符合防泄漏约束");
    }
    if profile.profile.store_selected || profile.profile.store_fake_ip {
        return invalid("不得使用 Mihomo 缓存覆盖应用选择或 fake-ip 状态");
    }
    if profile.tun.mtu != 1280
        || !profile.tun.strict_route
        || !profile.tun.auto_route
        || !profile.tun.auto_detect_interface
        || !profile.tun.dns_hijack.iter().any(|item| item == "any:53")
        || !profile
            .tun
            .dns_hijack
            .iter()
            .any(|item| item == "tcp://any:53")
    {
        return invalid("TUN MTU、严格路由或 DNS 劫持不完整");
    }
    let route_addresses: BTreeSet<_> = profile
        .tun
        .route_address
        .iter()
        .map(String::as_str)
        .collect();
    for required in ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"] {
        if !route_addresses.contains(required) {
            return invalid("TUN 未完整接管 IPv4/IPv6 默认路由");
        }
    }
    if profile.dns.enhanced_mode != "redir-host"
        || !profile.dns.enable
        || profile.dns.nameserver.is_empty()
    {
        return invalid("DNS redir-host 或 nameserver 配置不完整");
    }
    if profile
        .dns
        .fallback
        .as_ref()
        .is_some_and(|fallback| !fallback.is_empty())
        || profile
            .dns
            .default_nameserver
            .as_ref()
            .is_some_and(|servers| !servers.is_empty())
    {
        return invalid("检测到未经导入配置授权的 DNS 兜底");
    }

    for proxy in &profile.proxies {
        if proxy.kind != "wireguard" || proxy.peers.len() != 1 {
            return invalid("运行时只允许完整单 Peer WireGuard 节点");
        }
        if proxy.top_level_pre_shared_key.is_some() {
            return invalid("pre-shared-key 必须位于 peers 内");
        }
        if proxy.ip_version.as_deref() != Some("ipv4") {
            return invalid("第一阶段 WireGuard 节点必须固定使用 IPv4 Endpoint");
        }
        if !proxy.remote_dns_resolve || proxy.dns.is_empty() {
            return invalid("WireGuard 节点缺少导入 DNS 或远端解析约束");
        }
        if proxy.mtu.is_none_or(|mtu| !(576..=9000).contains(&mtu)) {
            return invalid("WireGuard 节点缺少有效 MTU");
        }
        let peer = &proxy.peers[0];
        if peer.port == 0 || peer.allowed_ips.is_empty() || peer.server.parse::<IpAddr>().is_err() {
            return invalid("WireGuard Peer 字段不完整");
        }
    }
    Ok(())
}

struct Graph<'a> {
    names: BTreeSet<&'a str>,
    edges: BTreeMap<&'a str, Vec<&'a str>>,
}

impl Graph<'_> {
    fn active_path(&self) -> Result<Vec<String>> {
        let mut path = Vec::new();
        let mut current = OUTLET_SELECTOR;
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(current) {
                return invalid("活动出口路径存在循环");
            }
            path.push(current.to_owned());
            let Some(edges) = self.edges.get(current) else {
                break;
            };
            if edges.is_empty() {
                break;
            }
            // 生成器的活动组只有一个成员；代理的唯一边是 dialer-proxy。
            current = edges[0];
        }
        Ok(path)
    }
}

fn validate_references(profile: &RuntimeProjection) -> Result<Graph<'_>> {
    let mut names = BTreeSet::new();
    for proxy in &profile.proxies {
        if !names.insert(proxy.name.as_str()) {
            return invalid("代理或组名称重复");
        }
    }
    for group in &profile.proxy_groups {
        if !names.insert(group.name.as_str()) {
            return invalid("代理或组名称重复");
        }
        if group.kind != "select" || group.proxies.len() != 1 {
            return invalid("内部活动组必须是只含当前选择的 select 组");
        }
    }

    for required in [FIRST_HOP_SELECTOR, OUTLET_SELECTOR] {
        if !names.contains(required) {
            return invalid("缺少必需的内部代理组");
        }
    }

    let mut edges: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for proxy in &profile.proxies {
        let edge = proxy.dialer_proxy.as_deref().into_iter().collect();
        edges.insert(proxy.name.as_str(), edge);
        if proxy.name.starts_with("PN-")
            && proxy.dialer_proxy.as_deref() != Some(FIRST_HOP_SELECTOR)
        {
            return invalid("Proton 节点未固定绑定 FirstHopSelector");
        }
        if proxy.name.starts_with("FH-") && proxy.dialer_proxy.is_some() {
            return invalid("第一跳节点不得反向引用其他出口");
        }
    }
    for group in &profile.proxy_groups {
        edges.insert(
            group.name.as_str(),
            group.proxies.iter().map(String::as_str).collect(),
        );
    }

    for references in edges.values() {
        for reference in references {
            if !names.contains(reference) {
                return invalid("代理组或 dialer-proxy 存在悬空引用");
            }
        }
    }

    let outlet = profile
        .proxy_groups
        .iter()
        .find(|group| group.name == OUTLET_SELECTOR)
        .ok_or_else(|| ConfigError::RuntimeValidation("缺少最终出口组".to_owned()))?;
    let outlet_target = outlet.proxies[0].as_str();
    if outlet_target != FIRST_HOP_SELECTOR && outlet_target != PROTON_SELECTOR {
        return invalid("最终出口只能选择第一跳组或 Proton 组");
    }
    if outlet_target == PROTON_SELECTOR && !names.contains(PROTON_SELECTOR) {
        return invalid("双跳模式缺少 Proton 活动组");
    }

    detect_cycles(&edges)?;
    Ok(Graph { names, edges })
}

fn detect_cycles(edges: &BTreeMap<&str, Vec<&str>>) -> Result<()> {
    fn visit<'a>(
        node: &'a str,
        edges: &BTreeMap<&'a str, Vec<&'a str>>,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
    ) -> Result<()> {
        if visited.contains(node) {
            return Ok(());
        }
        if !visiting.insert(node) {
            return invalid("代理引用图存在循环");
        }
        if let Some(children) = edges.get(node) {
            for child in children {
                visit(child, edges, visiting, visited)?;
            }
        }
        visiting.remove(node);
        visited.insert(node);
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for node in edges.keys() {
        visit(node, edges, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn validate_routes(profile: &RuntimeProjection) -> Result<()> {
    if profile.rules.last().map(String::as_str) != Some("MATCH,HK-Proton-Outlet") {
        return invalid("最终 MATCH 规则未绑定 HK-Proton-Outlet");
    }

    let mut direct_cidrs = BTreeSet::new();
    for rule in &profile.rules {
        if rule == "MATCH,DIRECT" {
            return invalid("普通公网流量不得 DIRECT");
        }
        let fields: Vec<_> = rule.split(',').collect();
        if fields.len() >= 3 && matches!(fields[0], "IP-CIDR" | "IP-CIDR6") && fields[2] == "DIRECT"
        {
            let cidr = fields[1]
                .parse::<IpNet>()
                .map_err(|_| ConfigError::RuntimeValidation("DIRECT CIDR 无效".to_owned()))?;
            if !is_allowed_local_cidr(cidr) {
                return invalid("检测到过宽或非本地的 DIRECT CIDR");
            }
            direct_cidrs.insert(cidr.to_string());
        }
    }

    let excludes: BTreeSet<_> = profile.tun.route_exclude_address.iter().cloned().collect();
    let first_hop_name = profile
        .proxy_groups
        .iter()
        .find(|group| group.name == FIRST_HOP_SELECTOR)
        .and_then(|group| group.proxies.first())
        .ok_or_else(|| ConfigError::RuntimeValidation("缺少第一跳选择".to_owned()))?;
    let first_hop_endpoint = profile
        .proxies
        .iter()
        .find(|proxy| &proxy.name == first_hop_name)
        .and_then(|proxy| proxy.peers.first())
        .ok_or_else(|| ConfigError::RuntimeValidation("第一跳引用无效".to_owned()))?
        .server
        .parse::<IpAddr>()
        .map_err(|_| ConfigError::RuntimeValidation("第一跳 Endpoint 无效".to_owned()))?;
    let endpoint_exclusion = match first_hop_endpoint {
        IpAddr::V4(address) => format!("{address}/32"),
        IpAddr::V6(address) => format!("{address}/128"),
    };
    let mut expected_excludes = direct_cidrs;
    expected_excludes.insert(endpoint_exclusion);
    if excludes != expected_excludes {
        return invalid("route-exclude-address 只能包含本地网段和当前第一跳 Endpoint");
    }
    Ok(())
}

fn validate_dns(profile: &RuntimeProjection, names: &BTreeSet<&str>) -> Result<()> {
    for server in &profile.dns.nameserver {
        if contains_system_dns(server) || dns_reference(server) != Some(OUTLET_SELECTOR) {
            return invalid("公网 DNS 未明确绑定最终出口组");
        }
    }
    for server in &profile.dns.direct_nameserver {
        if contains_system_dns(server) || dns_reference(server) != Some("DIRECT") {
            return invalid("LAN DNS 必须明确绑定 DIRECT");
        }
    }
    for servers in profile.dns.nameserver_policy.values() {
        for server in servers {
            if contains_system_dns(server) || dns_reference(server) != Some("DIRECT") {
                return invalid("本地域名策略包含未授权 DNS 路径");
            }
        }
    }

    for server in profile
        .dns
        .nameserver
        .iter()
        .chain(profile.dns.direct_nameserver.iter())
        .chain(profile.dns.nameserver_policy.values().flatten())
    {
        if let Some(reference) = dns_reference(server) {
            if reference != "DIRECT" && reference != "RULES" && !names.contains(reference) {
                return invalid("DNS 引用了不存在的代理或组");
            }
        }
    }
    Ok(())
}

fn dns_reference(value: &str) -> Option<&str> {
    value
        .rsplit_once('#')
        .map(|(_, parameters)| parameters.split('&').next().unwrap_or(parameters))
}

fn contains_system_dns(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered == "system" || lowered.starts_with("system://") || lowered.starts_with("dhcp://")
}

fn is_allowed_local_cidr(cidr: IpNet) -> bool {
    match cidr {
        IpNet::V4(network) => {
            let address = network.network();
            let private = address.is_private() && network.broadcast().is_private();
            let tailscale = network == "100.64.0.0/10".parse().expect("固定 CIDR 有效");
            let sufficiently_narrow = network.prefix_len() >= 16;
            (private && sufficiently_narrow) || tailscale
        }
        IpNet::V6(network) => {
            let first = network.network().segments()[0];
            let unique_local = (first & 0xfe00) == 0xfc00 && network.prefix_len() >= 48;
            let tailscale = network == "fd7a:115c:a1e0::/48".parse().expect("固定 CIDR 有效");
            unique_local || tailscale
        }
    }
}

fn invalid<T>(message: &str) -> Result<T> {
    Err(ConfigError::RuntimeValidation(message.to_owned()))
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RuntimeProjection {
    allow_lan: bool,
    bind_address: String,
    ipv6: bool,
    external_controller: String,
    profile: ProfileProjection,
    tun: TunProjection,
    dns: DnsProjection,
    proxies: Vec<ProxyProjection>,
    proxy_groups: Vec<GroupProjection>,
    rules: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ProfileProjection {
    store_selected: bool,
    store_fake_ip: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct TunProjection {
    mtu: u16,
    auto_route: bool,
    auto_detect_interface: bool,
    strict_route: bool,
    dns_hijack: Vec<String>,
    route_address: Vec<String>,
    #[serde(default)]
    route_exclude_address: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct DnsProjection {
    enable: bool,
    ipv6: bool,
    enhanced_mode: String,
    nameserver: Vec<String>,
    #[serde(default)]
    nameserver_policy: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    direct_nameserver: Vec<String>,
    #[serde(default)]
    default_nameserver: Option<Vec<String>>,
    #[serde(default)]
    fallback: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ProxyProjection {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "private-key")]
    _private_key: IgnoredAny,
    peers: Vec<PeerProjection>,
    #[serde(default)]
    dialer_proxy: Option<String>,
    #[serde(default, rename = "pre-shared-key")]
    top_level_pre_shared_key: Option<IgnoredAny>,
    #[serde(default)]
    ip_version: Option<String>,
    #[serde(default)]
    mtu: Option<u16>,
    #[serde(default)]
    remote_dns_resolve: bool,
    #[serde(default)]
    dns: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct PeerProjection {
    server: String,
    port: u16,
    allowed_ips: Vec<String>,
}

#[derive(Deserialize)]
struct GroupProjection {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    proxies: Vec<String>,
}
