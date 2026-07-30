use std::{
    collections::BTreeMap,
    net::{IpAddr, ToSocketAddrs},
    path::PathBuf,
    sync::Arc,
};

use hk_proton_core::{
    Endpoint, EndpointHost, FIRST_HOP_SELECTOR, FirstHopProfile, HK_PROTON_DNS_PORT,
    ImportMetadata, LanPolicy, OUTLET_SELECTOR, OperatingMode, PROTON_SELECTOR, ProfileId,
    ProtonProfile, ProxyConfig, RuntimeOptions, RuntimeSelection, SecretValue, TailscalePolicy,
    VlessConfig, WireGuardConfig, generate_profile, looks_like_vless_source, parse_vless,
    parse_wireguard, validate_rendered_profile,
};
use hk_proton_manager::{
    AppState, GenerationCandidate, LanPolicyRecord, PendingSecret, ProfileResourceRecord,
    ProfileRole, ProfileVersionKind, ProfileVersionRecord, SecretProtector, SecretRef, StateStore,
    TailscalePolicyRecord, inspect_network_effects,
};
use ipnet::IpNet;
use time::OffsetDateTime;
use uuid::Uuid;

#[cfg(windows)]
use hk_proton_manager::{DpapiCurrentUserProtector, WindowsPrivateDirectory};

use crate::{
    dto::{
        AppStatusDto, BlockerDto, NodeDelayDto, NodeDelayReportDto, ProfileSummaryDto,
        RuntimeStateDto, UiMode, UiProfileRole,
    },
    error::{ServiceError, ServiceResult},
    runtime::{NodeDelayTarget, RuntimeBackend, RuntimeView},
    scanner::{SourceRole, scan_selected_files},
};

#[cfg(test)]
use crate::scanner::scan_config_tree;

const STATE_SCHEMA_VERSION: u32 = 1;
const MIHOMO_STATE_VERSION: &str = "1.19.28";
const MIXED_PORT: u16 = 27_890;
const CONTROLLER_PORT: u16 = 29_090;

#[cfg(windows)]
pub type DesktopService = AppService<DpapiCurrentUserProtector, crate::live_runtime::LiveRuntime>;

pub struct AppService<P, R> {
    #[cfg(test)]
    source_root: PathBuf,
    store: Arc<StateStore<P>>,
    runtime: R,
}

#[cfg(windows)]
impl AppService<DpapiCurrentUserProtector, crate::live_runtime::LiveRuntime> {
    pub fn open(state_directory: WindowsPrivateDirectory) -> ServiceResult<Self> {
        // setup 已验证过一次；在真正打开 Vault 前再次 fail closed，缩小替换窗口。
        state_directory.revalidate()?;
        let store = Arc::new(StateStore::open_current_user(state_directory.path())?);
        let runtime = crate::live_runtime::LiveRuntime::new(Arc::clone(&store), state_directory)?;
        let mut service = Self {
            #[cfg(test)]
            source_root: PathBuf::new(),
            store,
            runtime,
        };
        service.refresh_runtime_contract_if_needed()?;
        Ok(service)
    }
}

impl<P: SecretProtector, R: RuntimeBackend> AppService<P, R> {
    #[cfg(test)]
    fn with_store(source_root: PathBuf, store: StateStore<P>, runtime: R) -> Self {
        Self {
            source_root,
            store: Arc::new(store),
            runtime,
        }
    }

    pub fn get_app_status(&mut self) -> ServiceResult<AppStatusDto> {
        let runtime = self.runtime.poll();
        self.status_with_runtime(runtime)
    }

    /// 端口或运行合同升级时自动生成新 revision，避免旧 generation 继续占用 Clash 端口。
    fn refresh_runtime_contract_if_needed(&mut self) -> ServiceResult<()> {
        let Some(current) = self.store.load_current()? else {
            return Ok(());
        };
        let runtime_yaml = self.store.load_runtime_yaml(current.state.revision)?;
        // 旧 revision 可能因新合同（例如第一跳 Endpoint 精确路由排除）而不再通过
        // 当前验证器；状态本身已由 Vault HMAC 验证，可直接从状态重新生成并预提交。
        let current_contract = validate_rendered_profile(runtime_yaml.expose_secret()).is_ok()
            && inspect_network_effects(&runtime_yaml).is_ok_and(|effects| {
                effects.mixed_port == MIXED_PORT
                    && effects.external_controller.ip().is_loopback()
                    && effects.external_controller.port() == CONTROLLER_PORT
                    && effects.dns_listener.ip().is_loopback()
                    && effects.dns_listener.port() == HK_PROTON_DNS_PORT
            });
        if current_contract {
            return Ok(());
        }

        let expected_revision = current.state.revision;
        let candidate = self.build_candidate(current.state, Vec::new())?;
        self.store.commit(candidate, Some(expected_revision))?;
        let _ = self.runtime.configuration_changed();
        Ok(())
    }

    #[cfg(test)]
    pub fn import_existing_configs(&mut self) -> ServiceResult<AppStatusDto> {
        if self.runtime.is_active() {
            return Err(ServiceError::RuntimeActive);
        }
        let sources = scan_config_tree(&self.source_root)?;
        let mut imports = Vec::with_capacity(sources.len());
        for source in sources {
            let ParsedSource {
                config,
                source_sha256,
            } = parse_source(source.contents.as_str())?;
            imports.push(ParsedImport {
                role: source.role,
                id: source.id,
                display_name: source.display_name,
                config,
                source_sha256,
            });
        }

        // 所有来源均已完成边界检查与解析后，才开始构造唯一一次事务提交。
        let current = self.store.load_current()?;
        let expected_revision = current.as_ref().map(|generation| generation.state.revision);
        let (state, pending) = merge_imports(
            current.map(|generation| generation.state),
            imports,
            OffsetDateTime::now_utc(),
        )?;
        let candidate = self.build_candidate(state, pending)?;
        self.store.commit(candidate, expected_revision)?;

        let runtime = self.runtime.configuration_changed();
        self.status_with_runtime(runtime)
    }

    pub fn import_config_files(
        &mut self,
        role: UiProfileRole,
        paths: Vec<PathBuf>,
    ) -> ServiceResult<AppStatusDto> {
        if self.runtime.is_active() {
            return Err(ServiceError::RuntimeActive);
        }
        let source_role = match role {
            UiProfileRole::FirstHop => SourceRole::FirstHop,
            UiProfileRole::Proton => SourceRole::Proton,
        };
        let sources = scan_selected_files(source_role, &paths)?;
        let mut imports = Vec::with_capacity(sources.len());
        for source in sources {
            let ParsedSource {
                config,
                source_sha256,
            } = parse_source(source.contents.as_str())?;
            imports.push(ParsedImport {
                role: source.role,
                id: source.id,
                display_name: source.display_name,
                config,
                source_sha256,
            });
        }

        let current = self.store.load_current()?;
        let expected_revision = current.as_ref().map(|generation| generation.state.revision);
        let (state, pending) = merge_imports(
            current.map(|generation| generation.state),
            imports,
            OffsetDateTime::now_utc(),
        )?;
        let candidate = self.build_candidate(state, pending)?;
        self.store.commit(candidate, expected_revision)?;
        let runtime = self.runtime.configuration_changed();
        self.status_with_runtime(runtime)
    }

    pub fn delete_profile(
        &mut self,
        role: UiProfileRole,
        profile_id: String,
    ) -> ServiceResult<AppStatusDto> {
        if self.runtime.is_active() {
            return Err(ServiceError::RuntimeActive);
        }
        let current = self
            .store
            .load_current()?
            .ok_or(ServiceError::Unconfigured)?;
        let revision = current.state.revision;
        let mut state = current.state;
        let id = ProfileId::new(profile_id).map_err(|_| ServiceError::InvalidSelection)?;

        match role {
            UiProfileRole::FirstHop => {
                if state.first_hops.len() <= 1 && state.first_hops.iter().any(|item| item.id == id)
                {
                    return Err(ServiceError::LastFirstHop);
                }
                let before = state.first_hops.len();
                state.first_hops.retain(|item| item.id != id);
                if before == state.first_hops.len() {
                    return Err(ServiceError::InvalidSelection);
                }
                if state.selected_first_hop == id {
                    state.selected_first_hop = state
                        .first_hops
                        .iter()
                        .find(|item| item.enabled)
                        .map(|item| item.id.clone())
                        .ok_or(ServiceError::LastFirstHop)?;
                }
            }
            UiProfileRole::Proton => {
                let before = state.proton_nodes.len();
                state.proton_nodes.retain(|item| item.id != id);
                if before == state.proton_nodes.len() {
                    return Err(ServiceError::InvalidSelection);
                }
                if state.selected_proton.as_ref() == Some(&id) {
                    state.selected_proton = state
                        .proton_nodes
                        .iter()
                        .find(|item| item.enabled)
                        .map(|item| item.id.clone());
                }
                if state.selected_proton.is_none() {
                    state.mode = OperatingMode::SingleHop;
                }
            }
        }

        let candidate = self.build_candidate(state, Vec::new())?;
        self.store.commit(candidate, Some(revision))?;
        let runtime = self.runtime.configuration_changed();
        self.status_with_runtime(runtime)
    }

    pub fn update_selection(
        &mut self,
        mode: UiMode,
        selected_first_hop: String,
        selected_proton: Option<String>,
    ) -> ServiceResult<AppStatusDto> {
        if self.runtime.is_active() {
            return Err(ServiceError::RuntimeActive);
        }
        let current = self
            .store
            .load_current()?
            .ok_or(ServiceError::Unconfigured)?;
        let revision = current.state.revision;
        let mut state = current.state;

        let first_hop =
            ProfileId::new(selected_first_hop).map_err(|_| ServiceError::InvalidSelection)?;
        if !state
            .first_hops
            .iter()
            .any(|item| item.id == first_hop && item.enabled)
        {
            return Err(ServiceError::InvalidSelection);
        }

        let requested_proton = selected_proton
            .map(ProfileId::new)
            .transpose()
            .map_err(|_| ServiceError::InvalidSelection)?;
        if let Some(id) = &requested_proton
            && !state
                .proton_nodes
                .iter()
                .any(|item| &item.id == id && item.enabled)
        {
            return Err(ServiceError::InvalidSelection);
        }
        if mode == UiMode::Double && requested_proton.is_none() {
            return Err(ServiceError::InvalidSelection);
        }

        let target_mode: OperatingMode = mode.into();
        let target_proton = requested_proton.or_else(|| state.selected_proton.clone());
        if state.mode == target_mode
            && state.selected_first_hop == first_hop
            && state.selected_proton == target_proton
        {
            return self.get_app_status();
        }

        state.mode = target_mode;
        state.selected_first_hop = first_hop;
        state.selected_proton = target_proton;
        state
            .validate()
            .map_err(|_| ServiceError::InvalidSelection)?;
        let candidate = self.build_candidate(state, Vec::new())?;
        self.store.commit(candidate, Some(revision))?;

        let runtime = self.runtime.configuration_changed();
        self.status_with_runtime(runtime)
    }

    pub fn validate_current(&mut self) -> ServiceResult<AppStatusDto> {
        let current = self
            .store
            .load_current()?
            .ok_or(ServiceError::Unconfigured)?;
        let runtime_yaml = self.store.load_runtime_yaml(current.state.revision)?;
        let report = validate_rendered_profile(runtime_yaml.expose_secret())
            .map_err(|_| ServiceError::GeneratedProfileInvalid)?;
        if report.active_path != expected_active_path(&current.state)? {
            return Err(ServiceError::GeneratedProfileInvalid);
        }

        let mut runtime = self.runtime.poll();
        runtime.message = "当前配置验证通过。".to_owned();
        Ok(status_from_state(&current.state, runtime))
    }

    pub fn connect(&mut self) -> ServiceResult<AppStatusDto> {
        let Some(current) = self.store.load_current()? else {
            return Ok(unconfigured_status());
        };
        let runtime = self.runtime.connect(current.state.revision);
        Ok(status_from_state(&current.state, runtime))
    }

    pub fn disconnect(&mut self) -> ServiceResult<AppStatusDto> {
        let runtime = self.runtime.disconnect();
        let Some(current) = self.store.load_current()? else {
            return Ok(unconfigured_status());
        };
        Ok(status_from_state(&current.state, runtime))
    }

    pub fn poll_status(&mut self) -> ServiceResult<AppStatusDto> {
        let runtime = self.runtime.poll();
        self.status_with_runtime(runtime)
    }

    pub fn measure_node_delays(&mut self) -> ServiceResult<NodeDelayReportDto> {
        let current = self
            .store
            .load_current()?
            .ok_or(ServiceError::Unconfigured)?;
        let mut targets = current
            .state
            .first_hops
            .iter()
            .filter(|item| item.enabled)
            .map(|item| NodeDelayTarget {
                profile_id: item.id.to_string(),
                proxy_name: format!("FH-{}", item.id),
            })
            .collect::<Vec<_>>();
        if current.state.mode == OperatingMode::DoubleHop {
            targets.extend(
                current
                    .state
                    .proton_nodes
                    .iter()
                    .filter(|item| item.enabled)
                    .map(|item| NodeDelayTarget {
                        profile_id: item.id.to_string(),
                        proxy_name: format!("PN-{}", item.id),
                    }),
            );
        }
        let results = self
            .runtime
            .measure_delays(&targets)
            .map_err(|_| ServiceError::DelayUnavailable)?
            .into_iter()
            .map(|item| NodeDelayDto {
                id: item.profile_id,
                // 与客户端的展示口径保持一致：Mihomo HTTP 探测值按十分之一显示。
                // 保留至少 1 ms，避免极小值在整数除法后被误显示为 0 ms。
                delay_ms: item.delay_ms.map(|delay| (delay / 10).max(1)),
            })
            .collect();
        Ok(NodeDelayReportDto { results })
    }

    fn status_with_runtime(&self, runtime: RuntimeView) -> ServiceResult<AppStatusDto> {
        let Some(current) = self.store.load_current()? else {
            return Ok(unconfigured_status());
        };
        Ok(status_from_state(&current.state, runtime))
    }

    fn build_candidate(
        &mut self,
        state: AppState,
        pending_secrets: Vec<PendingSecret>,
    ) -> ServiceResult<GenerationCandidate> {
        let runtime_yaml = self.render_runtime_yaml(&state, &pending_secrets)?;
        validate_rendered_profile(runtime_yaml.expose_secret())
            .map_err(|_| ServiceError::GeneratedProfileInvalid)?;
        self.runtime
            .validate_candidate(&runtime_yaml)
            .map_err(|_| ServiceError::GeneratedProfileInvalid)?;
        GenerationCandidate::validated(
            state,
            runtime_yaml,
            pending_secrets,
            MIHOMO_STATE_VERSION,
            OffsetDateTime::now_utc(),
        )
        .map_err(|_| ServiceError::GeneratedProfileInvalid)
    }

    fn render_runtime_yaml(
        &self,
        state: &AppState,
        pending_secrets: &[PendingSecret],
    ) -> ServiceResult<SecretValue> {
        let pending = pending_secrets
            .iter()
            .map(|item| (item.reference.id, item))
            .collect::<BTreeMap<_, _>>();

        let mut first_hops = Vec::with_capacity(state.first_hops.len());
        for resource in &state.first_hops {
            let version = resource
                .current_version()
                .ok_or(ServiceError::StateUnavailable)?;
            let config = materialize_version(self.store.as_ref(), &pending, version)?;
            let mut profile = match config {
                ProxyConfig::WireGuard(wireguard) => FirstHopProfile::new(
                    resource.id.clone(),
                    resource.display_name.clone(),
                    wireguard,
                    metadata_from_version(version),
                ),
                ProxyConfig::Vless(vless) => FirstHopProfile::new_vless(
                    resource.id.clone(),
                    resource.display_name.clone(),
                    vless,
                    metadata_from_version(version),
                ),
            }
            .map_err(|_| ServiceError::GeneratedProfileInvalid)?;
            profile.enabled = resource.enabled;
            first_hops.push(profile);
        }

        let mut proton_nodes = Vec::with_capacity(state.proton_nodes.len());
        for resource in &state.proton_nodes {
            let version = resource
                .current_version()
                .ok_or(ServiceError::StateUnavailable)?;
            let config = materialize_version(self.store.as_ref(), &pending, version)?;
            let mut profile = match config {
                ProxyConfig::WireGuard(wireguard) => ProtonProfile::new(
                    resource.id.clone(),
                    resource.display_name.clone(),
                    wireguard,
                    metadata_from_version(version),
                ),
                ProxyConfig::Vless(vless) => ProtonProfile::new_vless(
                    resource.id.clone(),
                    resource.display_name.clone(),
                    vless,
                    metadata_from_version(version),
                ),
            }
            .map_err(|_| ServiceError::GeneratedProfileInvalid)?;
            profile.enabled = resource.enabled;
            proton_nodes.push(profile);
        }

        let lan = LanPolicy {
            enabled: state.lan.enabled,
            cidrs: state
                .lan
                .cidrs
                .iter()
                .map(|value| value.parse::<IpNet>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ServiceError::StateUnavailable)?,
            dns_servers: state
                .lan
                .dns_servers
                .iter()
                .map(|value| value.parse::<IpAddr>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ServiceError::StateUnavailable)?,
            domain_suffixes: state.lan.domain_suffixes.clone(),
        };
        let tailscale = TailscalePolicy {
            enabled: state.tailscale.enabled,
            exit_node_enabled: state.tailscale.exit_node_enabled,
        };
        let selection = RuntimeSelection {
            mode: state.mode,
            first_hop: state.selected_first_hop.clone(),
            proton: state.selected_proton.clone(),
        };
        let runtime = RuntimeOptions::checked(
            true,
            MIXED_PORT,
            CONTROLLER_PORT,
            SecretValue::new(Uuid::new_v4().simple().to_string()),
        )
        .map_err(|_| ServiceError::GeneratedProfileInvalid)?;
        let generated = generate_profile(
            &first_hops,
            &proton_nodes,
            &selection,
            &lan,
            &tailscale,
            &runtime,
        )
        .map_err(|_| ServiceError::GeneratedProfileInvalid)?;
        Ok(SecretValue::new(generated.as_str().to_owned()))
    }
}

struct ParsedImport {
    role: SourceRole,
    id: String,
    display_name: String,
    config: ImportedConfig,
    source_sha256: String,
}

enum ImportedConfig {
    WireGuard(WireGuardConfig),
    Vless(VlessConfig),
}

struct ParsedSource {
    config: ImportedConfig,
    source_sha256: String,
}

fn parse_source(source: &str) -> ServiceResult<ParsedSource> {
    if looks_like_vless_source(source) {
        let parsed = parse_vless(source).map_err(|_| ServiceError::InvalidConfiguration)?;
        Ok(ParsedSource {
            config: ImportedConfig::Vless(resolve_vless_endpoint(parsed.config)?),
            source_sha256: parsed.source_sha256,
        })
    } else {
        let parsed = parse_wireguard(source).map_err(|_| ServiceError::InvalidConfiguration)?;
        Ok(ParsedSource {
            config: ImportedConfig::WireGuard(parsed.config),
            source_sha256: parsed.source_sha256,
        })
    }
}

/// 在候选 generation 阶段把 VLESS 的域名 Endpoint 固定成 IPv4，避免 TUN
/// 捕获第一跳自身的域名解析或建立连接。TLS/Reality 未显式提供 SNI 时，保留
/// 原始域名作为 servername；解析只发生在用户导入或重新生成候选时。
fn resolve_vless_endpoint(config: VlessConfig) -> ServiceResult<VlessConfig> {
    let Some(host) = (match &config.endpoint.host {
        EndpointHost::Domain(domain) => Some(domain.clone()),
        EndpointHost::Ip(_) => None,
    }) else {
        return Ok(config);
    };
    let port = config.endpoint.port;
    let ip = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|_| ServiceError::InvalidConfiguration)?
        .find_map(|address| match address.ip() {
            IpAddr::V4(ip) => Some(IpAddr::V4(ip)),
            IpAddr::V6(_) => None,
        })
        .ok_or(ServiceError::InvalidConfiguration)?;
    let servername = config
        .servername
        .clone()
        .or_else(|| config.tls.then_some(host));
    VlessConfig::checked(
        Endpoint {
            host: EndpointHost::Ip(ip),
            port,
        },
        config.uuid,
        config.network,
        config.udp,
        config.tls,
        config.flow,
        servername,
        config.client_fingerprint,
        config.packet_encoding,
        config.reality_public_key,
        config.reality_short_id,
        config.skip_cert_verify,
        config.dns_servers,
    )
    .map_err(|_| ServiceError::InvalidConfiguration)
}

fn merge_imports(
    existing: Option<AppState>,
    imports: Vec<ParsedImport>,
    imported_at: OffsetDateTime,
) -> ServiceResult<(AppState, Vec<PendingSecret>)> {
    let had_existing = existing.is_some();
    let (
        revision,
        existing_mode,
        existing_first_hop,
        existing_proton,
        mut first_hops,
        mut proton_nodes,
        lan,
        tailscale,
    ) = if let Some(state) = existing {
        (
            state.revision,
            state.mode,
            Some(state.selected_first_hop),
            state.selected_proton,
            state.first_hops,
            state.proton_nodes,
            state.lan,
            state.tailscale,
        )
    } else {
        (
            0,
            OperatingMode::DoubleHop,
            None,
            None,
            Vec::new(),
            Vec::new(),
            LanPolicyRecord {
                enabled: true,
                cidrs: vec!["172.23.0.0/16".to_owned()],
                dns_servers: Vec::new(),
                domain_suffixes: vec!["lan".to_owned(), "local".to_owned()],
            },
            TailscalePolicyRecord::default(),
        )
    };

    let mut pending = Vec::new();
    let mut imported_first_hop = None;
    for import in imports {
        match import.role {
            SourceRole::FirstHop => {
                imported_first_hop = Some(
                    ProfileId::new(import.id.clone())
                        .map_err(|_| ServiceError::InvalidWireGuard)?,
                );
                apply_import(
                    &mut first_hops,
                    ProfileRole::FirstHop,
                    import,
                    imported_at,
                    &mut pending,
                )?;
            }
            SourceRole::Proton => apply_import(
                &mut proton_nodes,
                ProfileRole::Proton,
                import,
                imported_at,
                &mut pending,
            )?,
        }
    }
    first_hops.sort_by(|left, right| left.id.cmp(&right.id));
    proton_nodes.sort_by(|left, right| left.id.cmp(&right.id));
    let selected_first_hop = existing_first_hop
        .filter(|selected| {
            first_hops
                .iter()
                .any(|item| &item.id == selected && item.enabled)
        })
        .or(imported_first_hop)
        .or_else(|| {
            first_hops
                .iter()
                .find(|item| item.enabled)
                .map(|item| item.id.clone())
        })
        .ok_or(ServiceError::MissingFirstHop)?;
    let selected_proton = existing_proton
        .filter(|selected| {
            proton_nodes
                .iter()
                .any(|item| &item.id == selected && item.enabled)
        })
        .or_else(|| {
            proton_nodes
                .iter()
                .find(|item| item.enabled)
                .map(|item| item.id.clone())
        });
    let mode = if selected_proton.is_none() {
        OperatingMode::SingleHop
    } else if had_existing {
        existing_mode
    } else {
        OperatingMode::DoubleHop
    };

    let state = AppState {
        schema_version: STATE_SCHEMA_VERSION,
        revision,
        mode,
        selected_first_hop,
        selected_proton,
        first_hops,
        proton_nodes,
        lan,
        tailscale,
    };
    state
        .validate()
        .map_err(|_| ServiceError::GeneratedProfileInvalid)?;
    Ok((state, pending))
}

fn apply_import(
    resources: &mut Vec<ProfileResourceRecord>,
    role: ProfileRole,
    import: ParsedImport,
    imported_at: OffsetDateTime,
    pending: &mut Vec<PendingSecret>,
) -> ServiceResult<()> {
    let id = ProfileId::new(import.id).map_err(|_| ServiceError::InvalidWireGuard)?;
    if let Some(existing) = resources.iter_mut().find(|item| item.id == id) {
        if existing.role != role {
            return Err(ServiceError::StateUnavailable);
        }
        let current = existing
            .current_version()
            .ok_or(ServiceError::StateUnavailable)?;
        let source_unchanged = current.source_sha256 == import.source_sha256;
        existing.display_name = import.display_name;
        if source_unchanged {
            return Ok(());
        }
        let config_version = existing
            .versions
            .iter()
            .map(|version| version.config_version)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(ServiceError::StateUnavailable)?;
        let metadata = ImportMetadata::new(imported_at, config_version, import.source_sha256);
        let (version, secrets) = profile_version_from_import(import.config, metadata);
        existing.current_version_id = version.version_id;
        existing.versions.push(version);
        pending.extend(secrets);
        return Ok(());
    }

    let metadata = ImportMetadata::new(imported_at, 1, import.source_sha256);
    let (version, secrets) = profile_version_from_import(import.config, metadata);
    let current_version_id = version.version_id;
    resources.push(ProfileResourceRecord {
        id,
        role,
        display_name: import.display_name,
        enabled: true,
        current_version_id,
        versions: vec![version],
    });
    pending.extend(secrets);
    Ok(())
}

fn profile_version_from_import(
    config: ImportedConfig,
    metadata: ImportMetadata,
) -> (ProfileVersionRecord, Vec<PendingSecret>) {
    match config {
        ImportedConfig::WireGuard(config) => ProfileVersionRecord::from_wireguard(config, metadata),
        ImportedConfig::Vless(config) => ProfileVersionRecord::from_vless(config, metadata),
    }
}

fn materialize_version<P: SecretProtector>(
    store: &StateStore<P>,
    pending: &BTreeMap<Uuid, &PendingSecret>,
    version: &ProfileVersionRecord,
) -> ServiceResult<ProxyConfig> {
    match version.kind {
        ProfileVersionKind::WireGuard => {
            let private_key = version
                .private_key
                .as_ref()
                .ok_or(ServiceError::StateUnavailable)
                .and_then(|reference| resolve_secret(store, pending, reference))?;
            let preshared_key = version
                .preshared_key
                .as_ref()
                .map(|reference| resolve_secret(store, pending, reference))
                .transpose()?;
            version
                .materialize(private_key, preshared_key)
                .map(ProxyConfig::WireGuard)
                .map_err(|_| ServiceError::StateUnavailable)
        }
        ProfileVersionKind::Vless => {
            let uuid_ref = version
                .uuid
                .as_ref()
                .ok_or(ServiceError::StateUnavailable)?;
            let uuid = resolve_secret(store, pending, uuid_ref)?;
            version
                .materialize_vless(uuid)
                .map(ProxyConfig::Vless)
                .map_err(|_| ServiceError::StateUnavailable)
        }
    }
}

fn resolve_secret<P: SecretProtector>(
    store: &StateStore<P>,
    pending: &BTreeMap<Uuid, &PendingSecret>,
    reference: &SecretRef,
) -> ServiceResult<SecretValue> {
    if let Some(secret) = pending.get(&reference.id) {
        if secret.reference != *reference {
            return Err(ServiceError::StateUnavailable);
        }
        return Ok(secret.value.clone());
    }
    store.load_secret(reference).map_err(Into::into)
}

fn metadata_from_version(version: &ProfileVersionRecord) -> ImportMetadata {
    ImportMetadata::new(
        version.imported_at,
        version.config_version,
        version.source_sha256.clone(),
    )
}

fn expected_active_path(state: &AppState) -> ServiceResult<Vec<String>> {
    let first_hop = format!("FH-{}", state.selected_first_hop);
    match state.mode {
        OperatingMode::SingleHop => Ok(vec![
            OUTLET_SELECTOR.to_owned(),
            FIRST_HOP_SELECTOR.to_owned(),
            first_hop,
        ]),
        OperatingMode::DoubleHop => {
            let proton = state
                .selected_proton
                .as_ref()
                .ok_or(ServiceError::StateUnavailable)?;
            Ok(vec![
                OUTLET_SELECTOR.to_owned(),
                PROTON_SELECTOR.to_owned(),
                format!("PN-{proton}"),
                FIRST_HOP_SELECTOR.to_owned(),
                first_hop,
            ])
        }
    }
}

fn status_from_state(state: &AppState, runtime: RuntimeView) -> AppStatusDto {
    AppStatusDto {
        configured: true,
        revision: state.revision,
        mode: state.mode.into(),
        first_hops: summaries(&state.first_hops),
        proton_nodes: summaries(&state.proton_nodes),
        selected_first_hop: Some(state.selected_first_hop.to_string()),
        selected_proton: state.selected_proton.as_ref().map(ToString::to_string),
        runtime_state: runtime.state,
        can_connect: runtime.can_connect,
        blocker: runtime.blocker,
        message: runtime.message,
    }
}

fn summaries(resources: &[ProfileResourceRecord]) -> Vec<ProfileSummaryDto> {
    resources
        .iter()
        .map(|resource| ProfileSummaryDto {
            id: resource.id.to_string(),
            display_name: resource.display_name.clone(),
            enabled: resource.enabled,
        })
        .collect()
}

fn unconfigured_status() -> AppStatusDto {
    AppStatusDto {
        configured: false,
        revision: 0,
        mode: UiMode::Single,
        first_hops: Vec::new(),
        proton_nodes: Vec::new(),
        selected_first_hop: None,
        selected_proton: None,
        runtime_state: RuntimeStateDto::Unconfigured,
        can_connect: false,
        blocker: Some(BlockerDto::NotConfigured),
        message: "请先导入本机配置。".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use hk_proton_manager::{Result as ManagerResult, SecretProtector, SecretRef};
    use serde_yaml_ng::Value;
    use tempfile::TempDir;

    use super::*;
    use crate::runtime::{FailClosedRuntime, RuntimeBackend, RuntimeView};
    use crate::scanner::FIRST_HOP_FILE_NAME;

    const FIRST_HOP: &str = include_str!(
        "../../../../crates/hk-proton-core/tests/fixtures/first-hop-hk.synthetic.conf"
    );
    const PROTON: &str =
        include_str!("../../../../crates/hk-proton-core/tests/fixtures/proton-jp.synthetic.conf");
    const VLESS_URI: &str = "vless://55555555-5555-4555-8555-555555555555@203.0.113.47:443?encryption=none&security=reality&sni=example.com&fp=chrome&pbk=9gtLPpU_IgqbuGMC4RQb_hNAK5kil8sHHeaELn1_-z8&sid=01020304&flow=xtls-rprx-vision&type=tcp&packetencoding=xudp&udp=1#synthetic";
    const VLESS_YAML: &str = r#"
proxies:
  - name: synthetic-vless-yaml
    type: vless
    server: 203.0.113.48
    port: 443
    uuid: 66666666-6666-4666-8666-666666666666
    encryption: ""
    udp: true
    tls: true
    flow: xtls-rprx-vision
    packet-encoding: xudp
    servername: example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: 9gtLPpU_IgqbuGMC4RQb_hNAK5kil8sHHeaELn1_-z8
      short-id: 01020304
    network: tcp
"#;

    struct TestProtector;

    struct RejectingCandidateRuntime;

    impl RuntimeBackend for RejectingCandidateRuntime {
        fn is_active(&self) -> bool {
            false
        }

        fn validate_candidate(&mut self, _yaml: &SecretValue) -> Result<(), ()> {
            Err(())
        }

        fn connect(&mut self, _revision: u64) -> RuntimeView {
            unreachable!()
        }

        fn disconnect(&mut self) -> RuntimeView {
            unreachable!()
        }

        fn poll(&mut self) -> RuntimeView {
            RuntimeView {
                state: RuntimeStateDto::Disconnected,
                can_connect: false,
                blocker: None,
                message: String::new(),
            }
        }

        fn configuration_changed(&mut self) -> RuntimeView {
            unreachable!()
        }
    }

    impl SecretProtector for TestProtector {
        fn protect(&self, _reference: &SecretRef, value: &SecretValue) -> ManagerResult<Vec<u8>> {
            Ok(value.expose_secret().as_bytes().to_vec())
        }

        fn unprotect(&self, _reference: &SecretRef, value: &[u8]) -> ManagerResult<SecretValue> {
            let value = String::from_utf8(value.to_vec())
                .map_err(|_| hk_proton_manager::ManagerError::SecretProtection)?;
            Ok(SecretValue::new(value))
        }
    }

    #[test]
    fn imports_synthetic_configs_and_commits_a_real_validated_generation() {
        let source = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        fs::write(source.path().join(FIRST_HOP_FILE_NAME), FIRST_HOP).unwrap();
        fs::create_dir(source.path().join("proton")).unwrap();
        fs::write(source.path().join("proton/proton-jp.conf"), PROTON).unwrap();

        let store = StateStore::open(vault.path(), TestProtector).unwrap();
        let mut service =
            AppService::with_store(source.path().to_path_buf(), store, FailClosedRuntime::new());
        let imported = service.import_existing_configs().unwrap();

        assert!(imported.configured);
        assert_eq!(imported.revision, 1);
        assert_eq!(imported.mode, UiMode::Double);
        assert_eq!(imported.first_hops.len(), 1);
        assert_eq!(imported.proton_nodes.len(), 1);
        assert!(!imported.can_connect);
        assert_eq!(imported.blocker, Some(BlockerDto::LivePreflightRequired));

        let runtime_yaml = service.store.load_runtime_yaml(imported.revision).unwrap();
        let effects = inspect_network_effects(&runtime_yaml).unwrap();
        assert_eq!(effects.mixed_port, MIXED_PORT);
        assert_eq!(effects.external_controller.port(), CONTROLLER_PORT);
        assert_eq!(effects.dns_listener.port(), HK_PROTON_DNS_PORT);

        let validated = service.validate_current().unwrap();
        assert_eq!(validated.revision, 1);
        assert_eq!(validated.message, "当前配置验证通过。");
    }

    #[test]
    fn selected_files_can_be_imported_by_role_and_deleted() {
        let source = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let first_hop = source.path().join("香港.conf");
        let proton = source.path().join("日本-JP-1.conf");
        fs::write(&first_hop, FIRST_HOP).unwrap();
        fs::write(&proton, PROTON).unwrap();

        let store = StateStore::open(vault.path(), TestProtector).unwrap();
        let mut service = AppService::with_store(PathBuf::new(), store, FailClosedRuntime::new());
        let first = service
            .import_config_files(UiProfileRole::FirstHop, vec![first_hop])
            .unwrap();
        assert_eq!(first.mode, UiMode::Single);
        assert_eq!(first.first_hops[0].display_name, "香港");

        let double = service
            .import_config_files(UiProfileRole::Proton, vec![proton])
            .unwrap();
        assert_eq!(double.proton_nodes[0].display_name, "日本-JP-1");
        let proton_id = double.selected_proton.unwrap();
        let deleted = service
            .delete_profile(UiProfileRole::Proton, proton_id)
            .unwrap();
        assert_eq!(deleted.mode, UiMode::Single);
        assert!(deleted.proton_nodes.is_empty());

        assert!(matches!(
            service.delete_profile(UiProfileRole::FirstHop, deleted.selected_first_hop.unwrap()),
            Err(ServiceError::LastFirstHop)
        ));
        let delay_report = service.measure_node_delays().unwrap();
        assert_eq!(delay_report.results.len(), 1);
        assert_eq!(delay_report.results[0].delay_ms, Some(4));
    }

    #[test]
    fn imports_vless_uri_and_mihomo_yaml_for_both_hop_roles() {
        let vault = TempDir::new().unwrap();
        let first_path = vault.path().join("first-hop.txt");
        let proton_path = vault.path().join("second-hop.yaml");
        fs::write(&first_path, VLESS_URI).unwrap();
        fs::write(&proton_path, VLESS_YAML).unwrap();

        let store_root = TempDir::new().unwrap();
        let store = StateStore::open(store_root.path(), TestProtector).unwrap();
        let mut service = AppService::with_store(PathBuf::new(), store, FailClosedRuntime::new());
        let single = service
            .import_config_files(UiProfileRole::FirstHop, vec![first_path])
            .unwrap();
        assert_eq!(single.mode, UiMode::Single);
        let double = service
            .import_config_files(UiProfileRole::Proton, vec![proton_path])
            .unwrap();
        assert_eq!(double.mode, UiMode::Single);
        assert_eq!(double.first_hops.len(), 1);
        assert_eq!(double.proton_nodes.len(), 1);
        let double = service
            .update_selection(
                UiMode::Double,
                double.selected_first_hop.clone().unwrap(),
                double.selected_proton.clone(),
            )
            .unwrap();
        assert_eq!(double.mode, UiMode::Double);

        let runtime = service.store.load_runtime_yaml(double.revision).unwrap();
        let yaml: Value = serde_yaml_ng::from_str(runtime.expose_secret()).unwrap();
        let proxies = yaml["proxies"].as_sequence().unwrap();
        assert!(
            proxies
                .iter()
                .all(|proxy| proxy["type"].as_str() == Some("vless"))
        );
        assert!(
            proxies
                .iter()
                .all(|proxy| proxy["packet-encoding"].as_str() == Some("xudp"))
        );
        assert_eq!(
            proxies
                .iter()
                .find(|proxy| proxy["name"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("PN-"))
                .and_then(|proxy| proxy["dialer-proxy"].as_str()),
            Some(FIRST_HOP_SELECTOR)
        );
    }

    #[test]
    fn rejected_mihomo_candidate_is_never_committed() {
        let source = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        fs::write(source.path().join(FIRST_HOP_FILE_NAME), FIRST_HOP).unwrap();
        fs::write(source.path().join("proton-jp.conf"), PROTON).unwrap();
        let store = StateStore::open(vault.path(), TestProtector).unwrap();
        let mut service = AppService::with_store(
            source.path().to_path_buf(),
            store,
            RejectingCandidateRuntime,
        );

        assert!(matches!(
            service.import_existing_configs(),
            Err(ServiceError::GeneratedProfileInvalid)
        ));
        assert_eq!(service.store.current_revision().unwrap(), None);
    }

    #[test]
    fn selection_update_commits_and_runtime_transitions_fail_closed() {
        let source = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        fs::write(source.path().join(FIRST_HOP_FILE_NAME), FIRST_HOP).unwrap();
        fs::write(source.path().join("proton-jp.conf"), PROTON).unwrap();
        let store = StateStore::open(vault.path(), TestProtector).unwrap();
        let mut service =
            AppService::with_store(source.path().to_path_buf(), store, FailClosedRuntime::new());
        let initial = service.import_existing_configs().unwrap();
        let updated = service
            .update_selection(UiMode::Single, initial.selected_first_hop.unwrap(), None)
            .unwrap();
        assert_eq!(updated.revision, 2);
        assert_eq!(updated.mode, UiMode::Single);

        let blocked = service.connect().unwrap();
        assert_eq!(blocked.runtime_state, RuntimeStateDto::Blocked);
        assert!(!blocked.can_connect);
        let stopped = service.disconnect().unwrap();
        assert_eq!(stopped.runtime_state, RuntimeStateDto::Disconnected);
    }

    #[test]
    fn unconfigured_state_is_a_safe_public_status() {
        let source = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let store = StateStore::open(vault.path(), TestProtector).unwrap();
        let mut service =
            AppService::with_store(source.path().to_path_buf(), store, FailClosedRuntime::new());
        let status = service.get_app_status().unwrap();
        assert!(!status.configured);
        assert_eq!(status.runtime_state, RuntimeStateDto::Unconfigured);
        assert_eq!(status.blocker, Some(BlockerDto::NotConfigured));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "只在本机显式执行真实配置只读审计"]
    fn real_source_imports_into_a_temporary_dpapi_vault() {
        let vault = TempDir::new().unwrap();
        let app_data = vault.path().join("app-data");
        let state_directory =
            WindowsPrivateDirectory::create(&app_data, app_data.join("state-vault")).unwrap();
        let store = Arc::new(StateStore::open_current_user(state_directory.path()).unwrap());
        let runtime =
            crate::live_runtime::LiveRuntime::new(Arc::clone(&store), state_directory).unwrap();
        let mut service = AppService {
            source_root: PathBuf::from(crate::scanner::DEFAULT_CONFIG_ROOT),
            store,
            runtime,
        };
        let imported = service.import_existing_configs().unwrap();
        assert_eq!(imported.first_hops.len(), 1);
        assert_eq!(imported.proton_nodes.len(), 8);
        assert_eq!(
            service.validate_current().unwrap().revision,
            imported.revision
        );

        let runtime_home = service.store.root().join("static-mihomo-audit");
        fs::create_dir(&runtime_home).unwrap();
        let runtime_file = runtime_home.join("profile.yaml");
        let runtime = service.store.load_runtime_yaml(imported.revision).unwrap();
        fs::write(&runtime_file, runtime.expose_secret()).unwrap();
        let plan = service
            .store
            .prepare_offline_launch(imported.revision)
            .unwrap();
        let mihomo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../tools/mihomo/1.19.28/bin/mihomo-windows-amd64-compatible.exe");
        let trusted = hk_proton_manager::TrustedMihomoExecutable::verify_pinned(mihomo).unwrap();
        hk_proton_manager::validate_mihomo_config(
            &trusted,
            vault.path(),
            &runtime_home,
            &runtime_file,
            &plan,
        )
        .unwrap();
        drop(runtime);
        fs::remove_file(runtime_file).unwrap();
    }
}
