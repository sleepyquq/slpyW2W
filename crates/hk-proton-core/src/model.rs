use std::{fmt, net::IpAddr, str::FromStr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{ConfigError, Result, SecretValue};

/// Windows 中 slpyW2W 自有 TUN 的兼容名称，必须与其他 Mihomo 客户端区分。
pub const HK_PROTON_TUN_DEVICE: &str = "HK-Proton";

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileId(String);

impl ProfileId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
        if !valid {
            return Err(ConfigError::InvalidProfileId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointHost {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub host: EndpointHost,
    pub port: u16,
}

impl Endpoint {
    pub fn server(&self) -> String {
        match &self.host {
            EndpointHost::Ip(ip) => ip.to_string(),
            EndpointHost::Domain(domain) => domain.clone(),
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self.host {
            EndpointHost::Ip(ip) => Some(ip),
            EndpointHost::Domain(_) => None,
        }
    }

    pub fn is_domain(&self) -> bool {
        matches!(self.host, EndpointHost::Domain(_))
    }
}

impl FromStr for Endpoint {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.is_empty() {
            return Err(ConfigError::EmptyField { field: "Endpoint" });
        }

        let (host, port_text) = if let Some(rest) = value.strip_prefix('[') {
            let closing = rest
                .find(']')
                .ok_or(ConfigError::InvalidField { field: "Endpoint" })?;
            let host = &rest[..closing];
            let suffix = &rest[closing + 1..];
            let port = suffix
                .strip_prefix(':')
                .ok_or(ConfigError::InvalidField { field: "Endpoint" })?;
            (host, port)
        } else {
            value
                .rsplit_once(':')
                .ok_or(ConfigError::InvalidField { field: "Endpoint" })?
        };

        let port = port_text
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or(ConfigError::InvalidField { field: "Endpoint" })?;

        let host = if let Ok(ip) = host.parse::<IpAddr>() {
            EndpointHost::Ip(ip)
        } else {
            let normalized = host.trim_end_matches('.').to_ascii_lowercase();
            let valid_domain = !normalized.is_empty()
                && normalized.len() <= 253
                && normalized.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                });
            if !valid_domain {
                return Err(ConfigError::InvalidField { field: "Endpoint" });
            }
            EndpointHost::Domain(normalized)
        };

        Ok(Self { host, port })
    }
}

#[derive(Clone, Debug)]
pub struct WireGuardInterface {
    pub private_key: SecretValue,
    pub addresses: Vec<IpNet>,
    pub dns_servers: Vec<IpAddr>,
    pub mtu: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct WireGuardPeer {
    pub public_key: String,
    pub preshared_key: Option<SecretValue>,
    pub endpoint: Endpoint,
    pub allowed_ips: Vec<IpNet>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct WireGuardConfig {
    pub interface: WireGuardInterface,
    pub peer: WireGuardPeer,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImportMetadata {
    pub imported_at: OffsetDateTime,
    pub config_version: u64,
    /// 原始导入文件的 SHA-256，仅用于版本与备份一致性检查。
    pub source_sha256: String,
}

impl ImportMetadata {
    pub fn new(
        imported_at: OffsetDateTime,
        config_version: u64,
        source_sha256: impl Into<String>,
    ) -> Self {
        Self {
            imported_at,
            config_version,
            source_sha256: source_sha256.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeResult {
    pub checked_at: OffsetDateTime,
    pub latency_ms: Option<u32>,
    pub success: bool,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FirstHopProfile {
    pub id: ProfileId,
    pub display_name: String,
    pub enabled: bool,
    pub wireguard: WireGuardConfig,
    pub last_probe: Option<ProbeResult>,
    pub metadata: ImportMetadata,
}

impl FirstHopProfile {
    pub fn new(
        id: ProfileId,
        display_name: impl Into<String>,
        wireguard: WireGuardConfig,
        metadata: ImportMetadata,
    ) -> Result<Self> {
        Ok(Self {
            id,
            display_name: checked_display_name(display_name)?,
            enabled: true,
            wireguard,
            last_probe: None,
            metadata,
        })
    }

    pub fn mihomo_name(&self) -> String {
        format!("FH-{}", self.id)
    }
}

#[derive(Clone, Debug)]
pub struct ProtonProfile {
    pub id: ProfileId,
    pub display_name: String,
    pub enabled: bool,
    pub wireguard: WireGuardConfig,
    pub last_probe: Option<ProbeResult>,
    pub metadata: ImportMetadata,
}

impl ProtonProfile {
    pub fn new(
        id: ProfileId,
        display_name: impl Into<String>,
        wireguard: WireGuardConfig,
        metadata: ImportMetadata,
    ) -> Result<Self> {
        Ok(Self {
            id,
            display_name: checked_display_name(display_name)?,
            enabled: true,
            wireguard,
            last_probe: None,
            metadata,
        })
    }

    pub fn mihomo_name(&self) -> String {
        format!("PN-{}", self.id)
    }
}

fn checked_display_name(value: impl Into<String>) -> Result<String> {
    let value = value.into().trim().to_owned();
    if value.is_empty() || value.chars().count() > 80 || value.chars().any(char::is_control) {
        return Err(ConfigError::InvalidDisplayName);
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperatingMode {
    DoubleHop,
    SingleHop,
}

#[derive(Clone, Debug)]
pub struct RuntimeSelection {
    pub mode: OperatingMode,
    pub first_hop: ProfileId,
    pub proton: Option<ProfileId>,
}

#[derive(Clone, Debug, Default)]
pub struct LanPolicy {
    pub enabled: bool,
    pub cidrs: Vec<IpNet>,
    pub dns_servers: Vec<IpAddr>,
    /// 例如 `corp.example`。仅这些后缀可通过 LAN DNS 查询。
    pub domain_suffixes: Vec<String>,
}

impl LanPolicy {
    pub fn preset_172_23() -> Self {
        Self {
            enabled: true,
            cidrs: vec!["172.23.0.0/16".parse().expect("固定 CIDR 必须有效")],
            dns_servers: Vec::new(),
            domain_suffixes: vec!["lan".to_owned(), "local".to_owned()],
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TailscalePolicy {
    /// 仅在检测到 Tailscale 网卡后开启，避免无条件放行 CGNAT 地址段。
    pub enabled: bool,
    pub exit_node_enabled: bool,
}

impl TailscalePolicy {
    pub fn standard() -> Self {
        Self {
            enabled: true,
            exit_node_enabled: false,
        }
    }

    pub fn cidrs(&self) -> Vec<IpNet> {
        if !self.enabled {
            return Vec::new();
        }
        vec![
            "100.64.0.0/10".parse().expect("固定 CIDR 必须有效"),
            "fd7a:115c:a1e0::/48".parse().expect("固定 CIDR 必须有效"),
        ]
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeOptions {
    pub tun_enabled: bool,
    pub tun_device: String,
    pub mixed_port: u16,
    pub controller_port: u16,
    pub controller_secret: SecretValue,
}

impl RuntimeOptions {
    pub fn checked(
        tun_enabled: bool,
        mixed_port: u16,
        controller_port: u16,
        controller_secret: SecretValue,
    ) -> Result<Self> {
        let valid = mixed_port >= 1024
            && controller_port >= 1024
            && mixed_port != controller_port
            && !controller_secret.is_empty();
        if !valid {
            return Err(ConfigError::InvalidRuntimePorts);
        }
        Ok(Self {
            tun_enabled,
            tun_device: HK_PROTON_TUN_DEVICE.to_owned(),
            mixed_port,
            controller_port,
            controller_secret,
        })
    }
}
