use std::{collections::BTreeMap, net::IpAddr, path::PathBuf, sync::Arc};

use hk_proton_core::{
    FIRST_HOP_SELECTOR, FirstHopProfile, HK_PROTON_DNS_PORT, ImportMetadata, LanPolicy,
    OUTLET_SELECTOR, OperatingMode, PROTON_SELECTOR, ProfileId, ProtonProfile, RuntimeOptions,
    RuntimeSelection, SecretValue, TailscalePolicy, WireGuardConfig, generate_profile,
    parse_wireguard, validate_rendered_profile,
};
use hk_proton_manager::{
    AppState, GenerationCandidate, LanPolicyRecord, PendingSecret, ProfileResourceRecord,
    ProfileRole, ProfileVersionRecord, SecretProtector, SecretRef, StateStore,
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

#[cfg(feature = "pyxis")]
use crate::scanner::scan_embedded_pyxis_profiles;

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

    /// 用户首次输入团队名字后，只把该成员可用的内置配置写入当前用户 DPAPI Vault。
    /// 相同成员再次启动时保持已有选择；切换成员时以一次候选验证和原子提交替换资源集合。
    #[cfg(feature = "pyxis")]
    pub fn activate_pyxis_member(&mut self, member: String) -> ServiceResult<AppStatusDto> {
        if self.runtime.is_active() {
            return Err(ServiceError::RuntimeActive);
        }
        let member = member.trim().to_ascii_lowercase();
        let sources = scan_embedded_pyxis_profiles(&member)?;
        let mut imports = Vec::with_capacity(sources.len());
        for source in sources {
            let parsed = parse_wireguard(source.contents.as_str())
                .map_err(|_| ServiceError::InvalidWireGuard)?;
            imports.push(ParsedImport {
                role: source.role,
                id: source.id,
                display_name: source.display_name,
                config: parsed.config,
                source_sha256: parsed.source_sha256,
            });
        }

        let current = self.store.load_current()?;
        if current
            .as_ref()
            .is_some_and(|generation| state_matches_embedded(&generation.state, &imports))
        {
            return self.get_app_status();
        }

        let expected_revision = current.as_ref().map(|generation| generation.state.revision);
        let (mut state, pending) = merge_imports(None, imports, OffsetDateTime::now_utc())?;
        // 团队版首次进入默认选中“香港”；选择其他节点时再由前端原子切换到双跳。
        state.mode = OperatingMode::SingleHop;
        let candidate = self.build_candidate(state, pending)?;
        self.store.commit(candidate, expected_revision)?;
        let runtime = self.runtime.configuration_changed();
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
            let parsed = parse_wireguard(source.contents.as_str())
                .map_err(|_| ServiceError::InvalidWireGuard)?;
            imports.push(ParsedImport {
                role: source.role,
                id: source.id,
                display_name: source.display_name,
                config: parsed.config,
                source_sha256: parsed.source_sha256,
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
            let parsed = parse_wireguard(source.contents.as_str())
                .map_err(|_| ServiceError::InvalidWireGuard)?;
            imports.push(ParsedImport {
                role: source.role,
                id: source.id,
                display_name: source.display_name,
                config: parsed.config,
                source_sha256: parsed.source_sha256,
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
        // 团队定制版只有一个统一节点列表，未连接且当前选中香港时也要能测试全部出口。
        #[cfg(feature = "pyxis")]
        let include_proton = true;
        #[cfg(not(feature = "pyxis"))]
        let include_proton = current.state.mode == OperatingMode::DoubleHop;
        if include_proton {
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
            let wireguard = materialize_version(self.store.as_ref(), &pending, version)?;
            let mut profile = FirstHopProfile::new(
                resource.id.clone(),
                resource.display_name.clone(),
                wireguard,
                metadata_from_version(version),
            )
            .map_err(|_| ServiceError::GeneratedProfileInvalid)?;
            profile.enabled = resource.enabled;
            first_hops.push(profile);
        }

        let mut proton_nodes = Vec::with_capacity(state.proton_nodes.len());
        for resource in &state.proton_nodes {
            let version = resource
                .current_version()
                .ok_or(ServiceError::StateUnavailable)?;
            let wireguard = materialize_version(self.store.as_ref(), &pending, version)?;
            let mut profile = ProtonProfile::new(
                resource.id.clone(),
                resource.display_name.clone(),
                wireguard,
                metadata_from_version(version),
            )
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
    config: WireGuardConfig,
    source_sha256: String,
}

#[cfg(feature = "pyxis")]
fn state_matches_embedded(state: &AppState, imports: &[ParsedImport]) -> bool {
    let expected_first_hops = imports
        .iter()
        .filter(|item| item.role == SourceRole::FirstHop)
        .count();
    let expected_proton = imports
        .iter()
        .filter(|item| item.role == SourceRole::Proton)
        .count();
    if state.first_hops.len() != expected_first_hops || state.proton_nodes.len() != expected_proton
    {
        return false;
    }

    imports.iter().all(|item| {
        let resources = match item.role {
            SourceRole::FirstHop => &state.first_hops,
            SourceRole::Proton => &state.proton_nodes,
        };
        resources.iter().any(|resource| {
            resource.id.as_str() == item.id
                && resource.display_name == item.display_name
                && resource
                    .current_version()
                    .is_some_and(|version| version.source_sha256 == item.source_sha256)
        })
    })
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
        let (version, secrets) = ProfileVersionRecord::from_wireguard(import.config, metadata);
        existing.current_version_id = version.version_id;
        existing.versions.push(version);
        pending.extend(secrets);
        return Ok(());
    }

    let metadata = ImportMetadata::new(imported_at, 1, import.source_sha256);
    let (version, secrets) = ProfileVersionRecord::from_wireguard(import.config, metadata);
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

fn materialize_version<P: SecretProtector>(
    store: &StateStore<P>,
    pending: &BTreeMap<Uuid, &PendingSecret>,
    version: &ProfileVersionRecord,
) -> ServiceResult<WireGuardConfig> {
    let private_key = resolve_secret(store, pending, &version.private_key)?;
    let preshared_key = version
        .preshared_key
        .as_ref()
        .map(|reference| resolve_secret(store, pending, reference))
        .transpose()?;
    version
        .materialize(private_key, preshared_key)
        .map_err(|_| ServiceError::StateUnavailable)
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
    use tempfile::TempDir;

    use super::*;
    use crate::runtime::{FailClosedRuntime, RuntimeBackend, RuntimeView};
    use crate::scanner::FIRST_HOP_FILE_NAME;

    const FIRST_HOP: &str = include_str!(
        "../../../../crates/hk-proton-core/tests/fixtures/first-hop-hk.synthetic.conf"
    );
    const PROTON: &str =
        include_str!("../../../../crates/hk-proton-core/tests/fixtures/proton-jp.synthetic.conf");

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
