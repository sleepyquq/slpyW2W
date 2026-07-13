use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::{ManagerError, Result};

pub const PINNED_MIHOMO_VERSION: &str = "v1.19.28";
const MAX_API_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionSnapshot {
    pub meta: bool,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConfigSnapshot {
    pub tun_enabled: bool,
    pub allow_lan: bool,
    pub bind_address: String,
    pub mode: String,
    pub mixed_port: u16,
    pub ipv6: bool,
    pub tun_device: String,
    pub auto_route: bool,
    pub strict_route: bool,
    pub dns_hijack: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxySnapshot {
    pub kind: String,
    pub now: Option<String>,
    pub all: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ExpectedRuntime {
    pub tun_enabled: bool,
    pub mixed_port: u16,
    pub tun_device: String,
    pub required_proxies: BTreeSet<String>,
    pub selectors: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileReport {
    pub version: VersionSnapshot,
    pub config: RuntimeConfigSnapshot,
    pub proxy_count: usize,
    pub selectors: BTreeMap<String, String>,
}

/// 不包含节点、地址或密钥的 API 对账失败分类，可安全用于界面诊断。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiContractViolation {
    SnapshotTooLarge,
    InvalidVersionPayload,
    InvalidConfigPayload,
    InvalidProxiesPayload,
    VersionMismatch,
    TunDisabled,
    TunDeviceMismatch,
    UnexpectedTunState,
    AllowLanEnabled,
    BindAddressMismatch,
    ModeMismatch,
    MixedPortMismatch,
    Ipv6Disabled,
    AutoRouteDisabled,
    StrictRouteDisabled,
    DnsHijackMismatch,
    RequiredProxyMissing,
    SelectorMismatch,
}

/// 对已经取得的 Mihomo API JSON 进行纯函数对账。
///
/// 本模块不建立 socket，也不包含任何控制器读写客户端。未来只有经过 PID、generation
/// 和端口所有权验证的 `OwnedCoreSession` 才能负责取得这些响应。
pub fn reconcile_api_snapshot_json(
    version_json: &str,
    config_json: &str,
    proxies_json: &str,
    expected: &ExpectedRuntime,
) -> Result<ReconcileReport> {
    reconcile_api_snapshot_json_detailed(version_json, config_json, proxies_json, expected)
        .map_err(|_| ManagerError::ApiContract)
}

pub fn reconcile_api_snapshot_json_detailed(
    version_json: &str,
    config_json: &str,
    proxies_json: &str,
    expected: &ExpectedRuntime,
) -> std::result::Result<ReconcileReport, ApiContractViolation> {
    reconcile_api_snapshot_json_inner(version_json, config_json, proxies_json, expected, false)
}

/// 调用方已从操作系统确认本次新建的专属 TUN 与公网路由就绪时使用。
/// Mihomo 1.19.28 在 Windows 上可能为 `/configs.tun` 返回默认值。
pub fn reconcile_api_snapshot_json_with_observed_tun(
    version_json: &str,
    config_json: &str,
    proxies_json: &str,
    expected: &ExpectedRuntime,
) -> std::result::Result<ReconcileReport, ApiContractViolation> {
    reconcile_api_snapshot_json_inner(version_json, config_json, proxies_json, expected, true)
}

fn reconcile_api_snapshot_json_inner(
    version_json: &str,
    config_json: &str,
    proxies_json: &str,
    expected: &ExpectedRuntime,
    owned_tun_observed: bool,
) -> std::result::Result<ReconcileReport, ApiContractViolation> {
    if [version_json, config_json, proxies_json]
        .iter()
        .any(|payload| payload.len() > MAX_API_SNAPSHOT_BYTES)
    {
        return Err(ApiContractViolation::SnapshotTooLarge);
    }

    let version_response: VersionResponse = serde_json::from_str(version_json)
        .map_err(|_| ApiContractViolation::InvalidVersionPayload)?;
    let version = VersionSnapshot {
        meta: version_response.meta,
        version: version_response.version,
    };
    if !version.meta || version.version != PINNED_MIHOMO_VERSION {
        return Err(ApiContractViolation::VersionMismatch);
    }

    let config_response: ConfigResponse = serde_json::from_str(config_json)
        .map_err(|_| ApiContractViolation::InvalidConfigPayload)?;
    let tun = config_response
        .tun
        .ok_or(ApiContractViolation::InvalidConfigPayload)?;
    let config = RuntimeConfigSnapshot {
        tun_enabled: tun
            .enable
            .ok_or(ApiContractViolation::InvalidConfigPayload)?,
        allow_lan: config_response
            .allow_lan
            .ok_or(ApiContractViolation::InvalidConfigPayload)?,
        bind_address: config_response
            .bind_address
            .ok_or(ApiContractViolation::InvalidConfigPayload)?,
        mode: config_response
            .mode
            .ok_or(ApiContractViolation::InvalidConfigPayload)?,
        mixed_port: config_response
            .mixed_port
            .ok_or(ApiContractViolation::InvalidConfigPayload)?,
        ipv6: config_response
            .ipv6
            .ok_or(ApiContractViolation::InvalidConfigPayload)?,
        tun_device: tun.device.unwrap_or_default(),
        auto_route: tun.auto_route.unwrap_or(false),
        strict_route: tun.strict_route.unwrap_or(false),
        dns_hijack: tun.dns_hijack.unwrap_or_default(),
    };
    if !owned_tun_observed {
        if expected.tun_enabled && !config.tun_enabled {
            return Err(ApiContractViolation::TunDisabled);
        }
        if config.tun_device != expected.tun_device {
            return Err(ApiContractViolation::TunDeviceMismatch);
        }
        if config.tun_enabled != expected.tun_enabled {
            return Err(ApiContractViolation::UnexpectedTunState);
        }
    }
    if config.allow_lan {
        return Err(ApiContractViolation::AllowLanEnabled);
    }
    if config.bind_address != "127.0.0.1" {
        return Err(ApiContractViolation::BindAddressMismatch);
    }
    if config.mode != "rule" {
        return Err(ApiContractViolation::ModeMismatch);
    }
    if config.mixed_port != expected.mixed_port {
        return Err(ApiContractViolation::MixedPortMismatch);
    }
    if !config.ipv6 {
        return Err(ApiContractViolation::Ipv6Disabled);
    }
    if !owned_tun_observed {
        if !config.auto_route {
            return Err(ApiContractViolation::AutoRouteDisabled);
        }
        if !config.strict_route {
            return Err(ApiContractViolation::StrictRouteDisabled);
        }
        if !config.dns_hijack.iter().any(|item| item == "any:53")
            || !config.dns_hijack.iter().any(|item| item == "tcp://any:53")
        {
            return Err(ApiContractViolation::DnsHijackMismatch);
        }
    }

    let response: ProxiesResponse = serde_json::from_str(proxies_json)
        .map_err(|_| ApiContractViolation::InvalidProxiesPayload)?;
    let proxies: BTreeMap<_, _> = response
        .proxies
        .ok_or(ApiContractViolation::InvalidProxiesPayload)?
        .into_iter()
        .filter_map(|(name, proxy)| {
            proxy.map(|proxy| {
                (
                    name,
                    ProxySnapshot {
                        kind: proxy.kind.unwrap_or_default(),
                        now: proxy.now,
                        all: proxy.all.unwrap_or_default(),
                    },
                )
            })
        })
        .collect();
    if !expected
        .required_proxies
        .iter()
        .all(|name| proxies.contains_key(name))
    {
        return Err(ApiContractViolation::RequiredProxyMissing);
    }
    let mut selectors = BTreeMap::new();
    for (name, selected) in &expected.selectors {
        let proxy = proxies
            .get(name)
            .ok_or(ApiContractViolation::RequiredProxyMissing)?;
        if proxy.kind != "Selector"
            || proxy.now.as_deref() != Some(selected.as_str())
            || !proxy.all.iter().any(|item| item == selected)
        {
            return Err(ApiContractViolation::SelectorMismatch);
        }
        selectors.insert(name.clone(), selected.clone());
    }

    Ok(ReconcileReport {
        version,
        config,
        proxy_count: proxies.len(),
        selectors,
    })
}

#[derive(Deserialize)]
struct VersionResponse {
    meta: bool,
    version: String,
}

#[derive(Deserialize)]
struct ConfigResponse {
    #[serde(rename = "allow-lan")]
    allow_lan: Option<bool>,
    #[serde(rename = "bind-address")]
    bind_address: Option<String>,
    mode: Option<String>,
    #[serde(rename = "mixed-port")]
    mixed_port: Option<u16>,
    ipv6: Option<bool>,
    tun: Option<TunResponse>,
}

#[derive(Deserialize)]
struct TunResponse {
    enable: Option<bool>,
    device: Option<String>,
    #[serde(rename = "auto-route")]
    auto_route: Option<bool>,
    #[serde(rename = "strict-route")]
    strict_route: Option<bool>,
    #[serde(rename = "dns-hijack")]
    dns_hijack: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct ProxiesResponse {
    proxies: Option<BTreeMap<String, Option<ProxyResponse>>>,
}

#[derive(Deserialize)]
struct ProxyResponse {
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    now: Option<String>,
    #[serde(default)]
    all: Option<Vec<String>>,
}
