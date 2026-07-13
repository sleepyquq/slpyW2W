use std::collections::BTreeSet;

use hk_proton_core::{
    EndpointHost, ImportMetadata, OperatingMode, ProfileId, SecretValue, WireGuardConfig,
    WireGuardInterface, WireGuardPeer,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{ManagerError, Result};

pub const STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileRole {
    FirstHop,
    Proton,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretPurpose {
    WireGuardPrivateKey,
    WireGuardPresharedKey,
    RuntimeProfile,
    ManifestHmac,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretRef {
    pub id: Uuid,
    pub purpose: SecretPurpose,
    pub envelope_version: u16,
}

impl SecretRef {
    pub fn random(purpose: SecretPurpose) -> Self {
        Self {
            id: Uuid::new_v4(),
            purpose,
            envelope_version: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PendingSecret {
    pub reference: SecretRef,
    pub value: SecretValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRecord {
    pub server: String,
    pub port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileVersionRecord {
    pub version_id: Uuid,
    pub imported_at: OffsetDateTime,
    pub config_version: u64,
    pub source_sha256: String,
    pub interface_addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub mtu: Option<u16>,
    pub private_key: SecretRef,
    pub endpoint: EndpointRecord,
    pub public_key: String,
    pub preshared_key: Option<SecretRef>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: Option<u16>,
}

impl ProfileVersionRecord {
    pub fn from_wireguard(
        config: WireGuardConfig,
        metadata: ImportMetadata,
    ) -> (Self, Vec<PendingSecret>) {
        let WireGuardConfig { interface, peer } = config;
        let WireGuardInterface {
            private_key,
            addresses,
            dns_servers,
            mtu,
        } = interface;
        let WireGuardPeer {
            public_key,
            preshared_key,
            endpoint,
            allowed_ips,
            persistent_keepalive,
        } = peer;

        let private_key_ref = SecretRef::random(SecretPurpose::WireGuardPrivateKey);
        let mut pending = vec![PendingSecret {
            reference: private_key_ref.clone(),
            value: private_key,
        }];
        let preshared_key_ref = preshared_key.map(|value| {
            let reference = SecretRef::random(SecretPurpose::WireGuardPresharedKey);
            pending.push(PendingSecret {
                reference: reference.clone(),
                value,
            });
            reference
        });

        (
            Self {
                version_id: Uuid::new_v4(),
                imported_at: metadata.imported_at,
                config_version: metadata.config_version,
                source_sha256: metadata.source_sha256,
                interface_addresses: addresses.into_iter().map(|item| item.to_string()).collect(),
                dns_servers: dns_servers
                    .into_iter()
                    .map(|item| item.to_string())
                    .collect(),
                mtu,
                private_key: private_key_ref,
                endpoint: EndpointRecord {
                    server: endpoint.server(),
                    port: endpoint.port,
                },
                public_key,
                preshared_key: preshared_key_ref,
                allowed_ips: allowed_ips
                    .into_iter()
                    .map(|item| item.to_string())
                    .collect(),
                persistent_keepalive,
            },
            pending,
        )
    }

    pub fn materialize(
        &self,
        private_key: SecretValue,
        preshared_key: Option<SecretValue>,
    ) -> Result<WireGuardConfig> {
        if self.private_key.purpose != SecretPurpose::WireGuardPrivateKey
            || self.private_key.envelope_version != 1
            || self.preshared_key.is_some() != preshared_key.is_some()
            || self.preshared_key.as_ref().is_some_and(|reference| {
                reference.purpose != SecretPurpose::WireGuardPresharedKey
                    || reference.envelope_version != 1
            })
        {
            return Err(ManagerError::SecretUnavailable);
        }
        let addresses = self
            .interface_addresses
            .iter()
            .map(|item| {
                item.parse()
                    .map_err(|_| ManagerError::InvalidState("Address 无效".to_owned()))
            })
            .collect::<Result<Vec<_>>>()?;
        let dns_servers = self
            .dns_servers
            .iter()
            .map(|item| {
                item.parse()
                    .map_err(|_| ManagerError::InvalidState("DNS 无效".to_owned()))
            })
            .collect::<Result<Vec<_>>>()?;
        let allowed_ips = self
            .allowed_ips
            .iter()
            .map(|item| {
                item.parse()
                    .map_err(|_| ManagerError::InvalidState("AllowedIPs 无效".to_owned()))
            })
            .collect::<Result<Vec<_>>>()?;
        let host = self
            .endpoint
            .server
            .parse()
            .map(EndpointHost::Ip)
            .unwrap_or_else(|_| EndpointHost::Domain(self.endpoint.server.clone()));

        Ok(WireGuardConfig {
            interface: WireGuardInterface {
                private_key,
                addresses,
                dns_servers,
                mtu: self.mtu,
            },
            peer: WireGuardPeer {
                public_key: self.public_key.clone(),
                preshared_key,
                endpoint: hk_proton_core::Endpoint {
                    host,
                    port: self.endpoint.port,
                },
                allowed_ips,
                persistent_keepalive: self.persistent_keepalive,
            },
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileResourceRecord {
    pub id: ProfileId,
    pub role: ProfileRole,
    pub display_name: String,
    pub enabled: bool,
    pub current_version_id: Uuid,
    pub versions: Vec<ProfileVersionRecord>,
}

impl ProfileResourceRecord {
    pub fn current_version(&self) -> Option<&ProfileVersionRecord> {
        self.versions
            .iter()
            .find(|version| version.version_id == self.current_version_id)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LanPolicyRecord {
    pub enabled: bool,
    pub cidrs: Vec<String>,
    pub dns_servers: Vec<String>,
    pub domain_suffixes: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TailscalePolicyRecord {
    pub enabled: bool,
    pub exit_node_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppState {
    pub schema_version: u32,
    pub revision: u64,
    pub mode: OperatingMode,
    pub selected_first_hop: ProfileId,
    pub selected_proton: Option<ProfileId>,
    pub first_hops: Vec<ProfileResourceRecord>,
    pub proton_nodes: Vec<ProfileResourceRecord>,
    pub lan: LanPolicyRecord,
    pub tailscale: TailscalePolicyRecord,
}

impl AppState {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != STATE_SCHEMA_VERSION {
            return invalid("不支持的 schema_version");
        }
        validate_resources(&self.first_hops, ProfileRole::FirstHop)?;
        validate_resources(&self.proton_nodes, ProfileRole::Proton)?;

        let selected_first_hop = self
            .first_hops
            .iter()
            .find(|resource| resource.id == self.selected_first_hop && resource.enabled);
        if selected_first_hop.is_none() {
            return invalid("当前第一跳不存在或已禁用");
        }
        if self.mode == OperatingMode::DoubleHop {
            let selected_proton = self.selected_proton.as_ref().and_then(|selected| {
                self.proton_nodes
                    .iter()
                    .find(|resource| &resource.id == selected && resource.enabled)
            });
            if selected_proton.is_none() {
                return invalid("双跳模式缺少有效 Proton 选择");
            }
        }
        if self.tailscale.exit_node_enabled {
            return invalid("普通模式不允许 Tailscale Exit Node");
        }
        Ok(())
    }
}

pub struct GenerationCandidate {
    pub(crate) state: AppState,
    pub(crate) runtime_yaml: SecretValue,
    pub(crate) pending_secrets: Vec<PendingSecret>,
    pub(crate) mihomo_version: String,
    pub(crate) created_at: OffsetDateTime,
}

impl GenerationCandidate {
    pub fn validated(
        state: AppState,
        runtime_yaml: SecretValue,
        pending_secrets: Vec<PendingSecret>,
        mihomo_version: impl Into<String>,
        created_at: OffsetDateTime,
    ) -> Result<Self> {
        state.validate()?;
        let mihomo_version = mihomo_version.into();
        if mihomo_version != "1.19.28" {
            return Err(ManagerError::InvalidState(
                "候选 generation 的 Mihomo 版本未锁定".to_owned(),
            ));
        }
        hk_proton_core::validate_rendered_profile(runtime_yaml.expose_secret())
            .map_err(|_| ManagerError::InvalidState("候选运行 YAML 未通过语义验证".to_owned()))?;
        Ok(Self {
            state,
            runtime_yaml,
            pending_secrets,
            mihomo_version,
            created_at,
        })
    }
}

impl std::fmt::Debug for GenerationCandidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GenerationCandidate")
            .field("state_revision", &self.state.revision)
            .field("runtime_yaml", &"[REDACTED]")
            .field("pending_secret_count", &self.pending_secrets.len())
            .field("mihomo_version", &self.mihomo_version)
            .field("created_at", &self.created_at)
            .finish()
    }
}

fn validate_resources(resources: &[ProfileResourceRecord], role: ProfileRole) -> Result<()> {
    let mut ids = BTreeSet::new();
    let mut version_ids = BTreeSet::new();
    for resource in resources {
        if resource.role != role || !ids.insert(resource.id.as_str()) {
            return invalid("资源角色或 ID 重复");
        }
        if ProfileId::new(resource.id.as_str()).is_err()
            || resource.display_name.trim().is_empty()
            || resource.display_name.chars().count() > 80
            || resource.display_name.chars().any(char::is_control)
            || resource.versions.is_empty()
        {
            return invalid("资源名称或版本列表为空");
        }
        if resource.current_version().is_none() {
            return invalid("current_version_id 不存在");
        }
        for version in &resource.versions {
            if !version_ids.insert(version.version_id) {
                return invalid("版本 ID 重复");
            }
            if version.source_sha256.len() != 64
                || !version
                    .source_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || version.interface_addresses.is_empty()
                || version.dns_servers.is_empty()
                || version.allowed_ips.is_empty()
                || version.endpoint.port == 0
                || version.private_key.purpose != SecretPurpose::WireGuardPrivateKey
                || version.private_key.envelope_version != 1
                || version.preshared_key.as_ref().is_some_and(|reference| {
                    reference.purpose != SecretPurpose::WireGuardPresharedKey
                        || reference.envelope_version != 1
                })
                || !valid_endpoint(&version.endpoint)
            {
                return invalid("WireGuard 版本字段不完整");
            }
        }
    }
    Ok(())
}

fn valid_endpoint(endpoint: &EndpointRecord) -> bool {
    let server = endpoint.server.trim();
    if server.is_empty() || server.chars().any(char::is_whitespace) {
        return false;
    }
    let value = match server.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(_)) => format!("[{server}]:{}", endpoint.port),
        _ => format!("{server}:{}", endpoint.port),
    };
    value.parse::<hk_proton_core::Endpoint>().is_ok()
}

fn invalid<T>(message: &str) -> Result<T> {
    Err(ManagerError::InvalidState(message.to_owned()))
}
