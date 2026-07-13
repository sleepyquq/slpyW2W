use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::File,
    io::{BufReader, Read},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use hk_proton_core::SecretValue;
use serde::{Deserialize, de::IgnoredAny};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    ManagerError, PortProtocol, PreflightSnapshot, RequiredPort, Result, evaluate_conflicts,
};

const MAX_RUNTIME_CONFIG_BYTES: usize = 32 * 1024 * 1024;
pub const PINNED_MIHOMO_SHA256: &str =
    "a3799f2d75c623a7c6d307e1faf88269e24dd746c59df3e9f1c84d5cfbff6c92";

/// 已按安装清单固定并校验过哈希的 Mihomo 可执行文件。
///
/// 该类型不会下载或替换文件；调用层只提供路径，SHA-256 固定在当前构建中。
#[derive(Clone)]
pub struct TrustedMihomoExecutable {
    executable: PathBuf,
    expected_sha256: String,
}

impl std::fmt::Debug for TrustedMihomoExecutable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustedMihomoExecutable")
            .field("executable", &self.executable)
            .field("expected_sha256", &self.expected_sha256)
            .finish()
    }
}

impl TrustedMihomoExecutable {
    pub fn verify_pinned(executable: impl Into<PathBuf>) -> Result<Self> {
        let executable = executable.into().canonicalize()?;
        let expected_sha256 = PINNED_MIHOMO_SHA256.to_owned();
        if !executable.is_file() || !is_sha256_hex(&expected_sha256) {
            return Err(ManagerError::InvalidLaunchSpec);
        }
        if sha256_file(&executable)? != expected_sha256 {
            return Err(ManagerError::CandidateChanged);
        }
        Ok(Self {
            executable,
            expected_sha256,
        })
    }
}

/// 与具体 generation 和其端口需求绑定的、无冲突 live 预检证明。
#[derive(Clone, Debug)]
pub struct LivePreflightApproval {
    pub(crate) revision: u64,
    pub(crate) runtime_plaintext_sha256: String,
    pub(crate) network_effects: NetworkEffectProjection,
}

impl LivePreflightApproval {
    /// 只对调用层传入的只读快照做纯计算；不会自行查询进程、端口、路由或网卡。
    pub fn from_snapshot(plan: &OfflineLaunchPlan, snapshot: &PreflightSnapshot) -> Result<Self> {
        let report = evaluate_conflicts(snapshot, &plan.required_ports);
        if !report.can_start() {
            return Err(ManagerError::LivePreflightRejected);
        }
        if !is_sha256_hex(&plan.runtime_plaintext_sha256) {
            return Err(ManagerError::InvalidLaunchSpec);
        }
        Ok(Self {
            revision: plan.revision,
            runtime_plaintext_sha256: plan.runtime_plaintext_sha256.to_ascii_lowercase(),
            network_effects: plan.network_effects.clone(),
        })
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }
}

/// 调用层由明确的用户操作创建此值，表示用户已同意启用 TUN。
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct ExplicitTunAuthorization(());

impl ExplicitTunAuthorization {
    pub fn from_explicit_user_action() -> Self {
        Self(())
    }
}

/// 调用层由明确的用户测速操作创建此值；它只允许启动关闭 TUN 的本机隔离探测会话。
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct ExplicitProbeAuthorization(());

impl ExplicitProbeAuthorization {
    pub fn from_explicit_user_action() -> Self {
        Self(())
    }
}

/// 调用层完成管理员权限确认后创建此值；manager 本身不会探测或提升权限。
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct AdministratorConfirmation(());

impl AdministratorConfirmation {
    pub fn confirmed_by_calling_layer() -> Self {
        Self(())
    }
}

#[derive(Clone)]
pub struct LiveLaunchAuthorization {
    pub(crate) preflight: LivePreflightApproval,
    pub(crate) tun_authorized: bool,
}

#[derive(Clone, Debug)]
pub struct ProbeLaunchAuthorization {
    runtime_plaintext_sha256: String,
    network_effects: NetworkEffectProjection,
}

impl ProbeLaunchAuthorization {
    pub fn from_snapshot(
        runtime_yaml: &SecretValue,
        snapshot: &PreflightSnapshot,
        _user_authorization: ExplicitProbeAuthorization,
    ) -> Result<Self> {
        let network_effects = inspect_network_effects(runtime_yaml)?;
        if network_effects.tun_enabled
            || network_effects.allow_lan
            || network_effects.bind_address != "127.0.0.1"
            || !network_effects.external_controller.ip().is_loopback()
            || (network_effects.dns_enabled && !network_effects.dns_listener.ip().is_loopback())
        {
            return Err(ManagerError::NetworkActivationRequiresUser);
        }
        let required_ports = required_ports_for_projection(&network_effects)?;
        if !evaluate_conflicts(snapshot, &required_ports).can_start() {
            return Err(ManagerError::LivePreflightRejected);
        }
        Ok(Self {
            runtime_plaintext_sha256: sha256_secret(runtime_yaml),
            network_effects,
        })
    }
}

impl std::fmt::Debug for LiveLaunchAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiveLaunchAuthorization")
            .field("revision", &self.preflight.revision)
            .field("tun_authorized", &self.tun_authorized)
            .finish()
    }
}

impl LiveLaunchAuthorization {
    pub fn for_non_tun(preflight: LivePreflightApproval) -> Self {
        Self {
            preflight,
            tun_authorized: false,
        }
    }

    pub fn for_tun(
        preflight: LivePreflightApproval,
        _user_authorization: ExplicitTunAuthorization,
        _administrator_confirmation: AdministratorConfirmation,
    ) -> Self {
        Self {
            preflight,
            tun_authorized: true,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum LaunchMode {
    OfflinePreflight,
    StaticValidation(NetworkEffectProjection),
    Live(LiveLaunchAuthorization),
    Probe(ProbeLaunchAuthorization),
}

#[derive(Clone)]
pub struct CoreLaunchSpec {
    pub(crate) executable: PathBuf,
    pub(crate) expected_executable_sha256: String,
    pub(crate) private_data_root: PathBuf,
    pub(crate) runtime_home: PathBuf,
    pub(crate) config_file: PathBuf,
    pub(crate) expected_config_sha256: String,
    pub(crate) mode: LaunchMode,
}

impl std::fmt::Debug for CoreLaunchSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoreLaunchSpec")
            .field("executable", &self.executable)
            .field(
                "expected_executable_sha256",
                &self.expected_executable_sha256,
            )
            .field("private_data_root", &self.private_data_root)
            .field("runtime_home", &self.runtime_home)
            .field("config_file", &self.config_file)
            .field("expected_config_sha256", &self.expected_config_sha256)
            .field("mode", &self.mode)
            .finish()
    }
}

impl CoreLaunchSpec {
    /// 构造只允许 TUN 关闭的离线校验说明；该说明不能交给 supervisor 启动。
    pub fn offline_preflight(
        executable: impl Into<PathBuf>,
        expected_executable_sha256: impl Into<String>,
        private_data_root: impl Into<PathBuf>,
        runtime_home: impl Into<PathBuf>,
        config_file: impl Into<PathBuf>,
        expected_config_sha256: impl Into<String>,
    ) -> Result<Self> {
        let executable = executable.into().canonicalize()?;
        let private_data_root = private_data_root.into().canonicalize()?;
        let runtime_home = runtime_home.into().canonicalize()?;
        let config_file = config_file.into().canonicalize()?;
        let candidate = Self {
            executable,
            expected_executable_sha256: expected_executable_sha256.into().to_ascii_lowercase(),
            private_data_root,
            runtime_home,
            config_file,
            expected_config_sha256: expected_config_sha256.into().to_ascii_lowercase(),
            mode: LaunchMode::OfflinePreflight,
        };
        let projection = candidate.validate_integrity()?;
        if projection.tun_enabled {
            return Err(ManagerError::NetworkActivationRequiresUser);
        }
        Ok(candidate)
    }

    /// 构造真正可交给受控 driver 的不可变启动说明。
    pub fn live(
        trusted_executable: TrustedMihomoExecutable,
        private_data_root: impl Into<PathBuf>,
        runtime_home: impl Into<PathBuf>,
        config_file: impl Into<PathBuf>,
        authorization: LiveLaunchAuthorization,
    ) -> Result<Self> {
        let private_data_root = private_data_root.into().canonicalize()?;
        let runtime_home = runtime_home.into().canonicalize()?;
        let config_file = config_file.into().canonicalize()?;
        let expected_config_sha256 = authorization
            .preflight
            .runtime_plaintext_sha256
            .to_ascii_lowercase();
        let candidate = Self {
            executable: trusted_executable.executable,
            expected_executable_sha256: trusted_executable.expected_sha256,
            private_data_root,
            runtime_home,
            config_file,
            expected_config_sha256,
            mode: LaunchMode::Live(authorization),
        };
        candidate.validate_for_spawn()?;
        Ok(candidate)
    }

    /// 构造只监听 loopback、明确关闭 TUN 的临时测速启动说明。
    pub fn probe(
        trusted_executable: TrustedMihomoExecutable,
        private_data_root: impl Into<PathBuf>,
        runtime_home: impl Into<PathBuf>,
        config_file: impl Into<PathBuf>,
        authorization: ProbeLaunchAuthorization,
    ) -> Result<Self> {
        let candidate = Self {
            executable: trusted_executable.executable,
            expected_executable_sha256: trusted_executable.expected_sha256,
            private_data_root: private_data_root.into().canonicalize()?,
            runtime_home: runtime_home.into().canonicalize()?,
            config_file: config_file.into().canonicalize()?,
            expected_config_sha256: authorization.runtime_plaintext_sha256.clone(),
            mode: LaunchMode::Probe(authorization),
        };
        candidate.validate_for_spawn()?;
        Ok(candidate)
    }

    pub(crate) fn static_validation(
        trusted_executable: &TrustedMihomoExecutable,
        private_data_root: impl Into<PathBuf>,
        runtime_home: impl Into<PathBuf>,
        config_file: impl Into<PathBuf>,
        plan: &OfflineLaunchPlan,
    ) -> Result<Self> {
        Self::static_validation_with_expectations(
            trusted_executable,
            private_data_root,
            runtime_home,
            config_file,
            &plan.runtime_plaintext_sha256,
            &plan.network_effects,
        )
    }

    /// 构造尚未提交到状态库的候选配置静态校验说明。
    ///
    /// 内存候选、调用层声明的哈希、落地文件和网络投影必须全部一致；因此调用层不能
    /// 通过复用旧 generation 的 `OfflineLaunchPlan` 跳过提交前校验。
    pub(crate) fn candidate_static_validation(
        trusted_executable: &TrustedMihomoExecutable,
        private_data_root: impl Into<PathBuf>,
        runtime_home: impl Into<PathBuf>,
        config_file: impl Into<PathBuf>,
        candidate_yaml: &SecretValue,
        expected_candidate_sha256: &str,
        expected_projection: &NetworkEffectProjection,
    ) -> Result<Self> {
        let expected_candidate_sha256 = expected_candidate_sha256.to_ascii_lowercase();
        if !is_sha256_hex(&expected_candidate_sha256) {
            return Err(ManagerError::InvalidLaunchSpec);
        }
        if sha256_secret(candidate_yaml) != expected_candidate_sha256 {
            return Err(ManagerError::CandidateChanged);
        }
        if inspect_network_effects(candidate_yaml)? != *expected_projection {
            return Err(ManagerError::InvalidLaunchSpec);
        }

        Self::static_validation_with_expectations(
            trusted_executable,
            private_data_root,
            runtime_home,
            config_file,
            &expected_candidate_sha256,
            expected_projection,
        )
    }

    fn static_validation_with_expectations(
        trusted_executable: &TrustedMihomoExecutable,
        private_data_root: impl Into<PathBuf>,
        runtime_home: impl Into<PathBuf>,
        config_file: impl Into<PathBuf>,
        expected_config_sha256: &str,
        expected_projection: &NetworkEffectProjection,
    ) -> Result<Self> {
        let candidate = Self {
            executable: trusted_executable.executable.clone(),
            expected_executable_sha256: trusted_executable.expected_sha256.clone(),
            private_data_root: private_data_root.into().canonicalize()?,
            runtime_home: runtime_home.into().canonicalize()?,
            config_file: config_file.into().canonicalize()?,
            expected_config_sha256: expected_config_sha256.to_ascii_lowercase(),
            mode: LaunchMode::StaticValidation(expected_projection.clone()),
        };
        candidate.validate_for_static_validation()?;
        Ok(candidate)
    }

    fn validate_integrity(&self) -> Result<NetworkEffectProjection> {
        if !self.executable.is_absolute()
            || !self.runtime_home.is_absolute()
            || !self.private_data_root.is_absolute()
            || !self.config_file.is_absolute()
            || !self.executable.is_file()
            || !self.private_data_root.is_dir()
            || !self.runtime_home.is_dir()
            || !self.config_file.is_file()
            || !is_sha256_hex(&self.expected_executable_sha256)
            || !is_sha256_hex(&self.expected_config_sha256)
        {
            return Err(ManagerError::InvalidLaunchSpec);
        }
        let canonical_root = self.private_data_root.canonicalize()?;
        let canonical_runtime_home = self.runtime_home.canonicalize()?;
        let canonical_config = self.config_file.canonicalize()?;
        if !canonical_config.starts_with(&canonical_root)
            || !canonical_runtime_home.starts_with(&canonical_root)
        {
            return Err(ManagerError::InvalidLaunchSpec);
        }
        if sha256_file(&self.executable)? != self.expected_executable_sha256.to_ascii_lowercase() {
            return Err(ManagerError::CandidateChanged);
        }
        if sha256_file(&self.config_file)? != self.expected_config_sha256.to_ascii_lowercase() {
            return Err(ManagerError::CandidateChanged);
        }
        let runtime_yaml = read_secret_file(&self.config_file)?;
        inspect_network_effects(&runtime_yaml)
    }

    pub(crate) fn validate_for_spawn(&self) -> Result<()> {
        let projection = self.validate_integrity()?;
        self.validate_live_paths_and_listeners(&projection)?;
        match &self.mode {
            LaunchMode::Live(authorization) => {
                if authorization.preflight.runtime_plaintext_sha256
                    != self.expected_config_sha256.to_ascii_lowercase()
                    || authorization.preflight.network_effects != projection
                    || authorization.tun_authorized != projection.tun_enabled
                {
                    return Err(ManagerError::LiveAuthorizationMismatch);
                }
            }
            LaunchMode::Probe(authorization) => {
                if authorization.runtime_plaintext_sha256
                    != self.expected_config_sha256.to_ascii_lowercase()
                    || authorization.network_effects != projection
                    || projection.tun_enabled
                    || projection.allow_lan
                    || projection.bind_address != "127.0.0.1"
                    || !projection.external_controller.ip().is_loopback()
                    || (projection.dns_enabled && !projection.dns_listener.ip().is_loopback())
                {
                    return Err(ManagerError::LiveAuthorizationMismatch);
                }
            }
            _ => return Err(ManagerError::LiveAuthorizationMismatch),
        }
        Ok(())
    }

    pub(crate) fn validate_for_static_validation(&self) -> Result<()> {
        let projection = self.validate_integrity()?;
        self.validate_live_paths_and_listeners(&projection)?;
        let LaunchMode::StaticValidation(expected_projection) = &self.mode else {
            return Err(ManagerError::InvalidLaunchSpec);
        };
        if &projection != expected_projection {
            return Err(ManagerError::InvalidLaunchSpec);
        }
        Ok(())
    }

    fn validate_live_paths_and_listeners(
        &self,
        projection: &NetworkEffectProjection,
    ) -> Result<()> {
        if !self.config_file.starts_with(&self.runtime_home)
            || (projection.dns_enabled && !projection.dns_listener.ip().is_loopback())
        {
            return Err(ManagerError::InvalidLaunchSpec);
        }
        Ok(())
    }

    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    pub(crate) fn runtime_home(&self) -> &Path {
        &self.runtime_home
    }

    pub(crate) fn config_file(&self) -> &Path {
        &self.config_file
    }

    pub(crate) fn command_arguments(&self) -> [OsString; 4] {
        [
            OsString::from("-d"),
            self.runtime_home.as_os_str().to_owned(),
            OsString::from("-f"),
            self.config_file.as_os_str().to_owned(),
        ]
    }

    pub(crate) fn validation_arguments(&self) -> [OsString; 5] {
        [
            OsString::from("-t"),
            OsString::from("-d"),
            self.runtime_home.as_os_str().to_owned(),
            OsString::from("-f"),
            self.config_file.as_os_str().to_owned(),
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkEffectProjection {
    pub tun_enabled: bool,
    pub allow_lan: bool,
    pub bind_address: String,
    pub mode: String,
    pub mixed_port: u16,
    pub external_controller: SocketAddr,
    pub dns_enabled: bool,
    pub dns_listener: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LaunchBlockReason {
    LiveConflictSnapshotRequired,
    TrustedCoreArtifactRequired,
    OwnedCoreSessionRequired,
    NetworkActivationAuthorizationRequired,
    NonLoopbackListenerAuthorizationRequired,
}

#[derive(Clone, Debug)]
pub struct OfflineLaunchPlan {
    revision: u64,
    manifest_envelope_sha256: String,
    runtime_plaintext_sha256: String,
    network_effects: NetworkEffectProjection,
    required_ports: Vec<RequiredPort>,
    blockers: BTreeSet<LaunchBlockReason>,
}

impl OfflineLaunchPlan {
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn manifest_envelope_sha256(&self) -> &str {
        &self.manifest_envelope_sha256
    }

    pub fn runtime_plaintext_sha256(&self) -> &str {
        &self.runtime_plaintext_sha256
    }

    pub fn network_effects(&self) -> &NetworkEffectProjection {
        &self.network_effects
    }

    pub fn required_ports(&self) -> &[RequiredPort] {
        &self.required_ports
    }

    pub fn blockers(&self) -> &BTreeSet<LaunchBlockReason> {
        &self.blockers
    }

    pub fn can_spawn(&self) -> bool {
        self.blockers.is_empty()
    }

    pub(crate) fn from_verified_generation(
        revision: u64,
        manifest_envelope_sha256: String,
        runtime_plaintext_sha256: String,
        network_effects: NetworkEffectProjection,
    ) -> Result<Self> {
        let required_ports = required_ports_for_projection(&network_effects)?;

        let mut blockers = BTreeSet::from([
            LaunchBlockReason::LiveConflictSnapshotRequired,
            LaunchBlockReason::TrustedCoreArtifactRequired,
            LaunchBlockReason::OwnedCoreSessionRequired,
        ]);
        if network_effects.tun_enabled {
            blockers.insert(LaunchBlockReason::NetworkActivationAuthorizationRequired);
        }
        if network_effects.dns_enabled && !network_effects.dns_listener.ip().is_loopback() {
            blockers.insert(LaunchBlockReason::NonLoopbackListenerAuthorizationRequired);
        }

        Ok(Self {
            revision,
            manifest_envelope_sha256,
            runtime_plaintext_sha256,
            network_effects,
            required_ports,
            blockers,
        })
    }
}

fn required_ports_for_projection(
    network_effects: &NetworkEffectProjection,
) -> Result<Vec<RequiredPort>> {
    let bind_address = network_effects
        .bind_address
        .parse::<IpAddr>()
        .map_err(|_| ManagerError::InvalidLaunchSpec)?;
    let mut required_ports = vec![
        RequiredPort {
            protocol: PortProtocol::Tcp,
            address: bind_address,
            port: network_effects.mixed_port,
            allowed_owner_pid: None,
        },
        RequiredPort {
            protocol: PortProtocol::Tcp,
            address: network_effects.external_controller.ip(),
            port: network_effects.external_controller.port(),
            allowed_owner_pid: None,
        },
    ];
    if network_effects.dns_enabled {
        for protocol in [PortProtocol::Tcp, PortProtocol::Udp] {
            required_ports.push(RequiredPort {
                protocol,
                address: network_effects.dns_listener.ip(),
                port: network_effects.dns_listener.port(),
                allowed_owner_pid: None,
            });
        }
    }
    Ok(required_ports)
}

/// 只解析生成器允许的固定字段，不保存 YAML 中的密钥。
pub fn inspect_network_effects(yaml: &SecretValue) -> Result<NetworkEffectProjection> {
    hk_proton_core::validate_rendered_profile(yaml.expose_secret())
        .map_err(|_| ManagerError::InvalidLaunchSpec)?;
    let profile: OfflineProfileProjection = serde_yaml_ng::from_str(yaml.expose_secret())
        .map_err(|_| ManagerError::InvalidLaunchSpec)?;
    let external_controller = profile
        .external_controller
        .parse::<SocketAddr>()
        .map_err(|_| ManagerError::InvalidLaunchSpec)?;
    let dns_listener = profile
        .dns
        .listen
        .parse::<SocketAddr>()
        .map_err(|_| ManagerError::InvalidLaunchSpec)?;
    if profile.mixed_port == 0
        || external_controller.port() == 0
        || !external_controller.ip().is_loopback()
        || profile.allow_lan
        || profile.bind_address != "127.0.0.1"
        || profile.mode != "rule"
    {
        return Err(ManagerError::InvalidLaunchSpec);
    }
    Ok(NetworkEffectProjection {
        tun_enabled: profile.tun.enable,
        allow_lan: profile.allow_lan,
        bind_address: profile.bind_address,
        mode: profile.mode,
        mixed_port: profile.mixed_port,
        external_controller,
        dns_enabled: profile.dns.enable,
        dns_listener,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct OfflineProfileProjection {
    mixed_port: u16,
    allow_lan: bool,
    bind_address: String,
    mode: String,
    #[serde(rename = "log-level")]
    _log_level: IgnoredAny,
    #[serde(rename = "ipv6")]
    _ipv6: IgnoredAny,
    external_controller: String,
    #[serde(rename = "secret")]
    _secret: IgnoredAny,
    #[serde(rename = "profile")]
    _profile: IgnoredAny,
    tun: OfflineTunProjection,
    dns: OfflineDnsProjection,
    #[serde(rename = "proxies")]
    _proxies: IgnoredAny,
    #[serde(rename = "proxy-groups")]
    _proxy_groups: IgnoredAny,
    #[serde(rename = "rules")]
    _rules: IgnoredAny,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct OfflineTunProjection {
    enable: bool,
    #[serde(rename = "stack")]
    _stack: IgnoredAny,
    #[serde(rename = "device")]
    _device: IgnoredAny,
    #[serde(rename = "mtu")]
    _mtu: IgnoredAny,
    #[serde(rename = "auto-route")]
    _auto_route: IgnoredAny,
    #[serde(rename = "auto-detect-interface")]
    _auto_detect_interface: IgnoredAny,
    #[serde(rename = "strict-route")]
    _strict_route: IgnoredAny,
    #[serde(rename = "dns-hijack")]
    _dns_hijack: IgnoredAny,
    #[serde(rename = "inet6-address")]
    _inet6_address: IgnoredAny,
    #[serde(rename = "route-address")]
    _route_address: IgnoredAny,
    #[serde(rename = "route-exclude-address")]
    _route_exclude_address: IgnoredAny,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct OfflineDnsProjection {
    enable: bool,
    listen: String,
    #[serde(rename = "ipv6")]
    _ipv6: IgnoredAny,
    #[serde(rename = "enhanced-mode")]
    _enhanced_mode: IgnoredAny,
    #[serde(rename = "fake-ip-range")]
    _fake_ip_range: IgnoredAny,
    #[serde(rename = "use-hosts")]
    _use_hosts: IgnoredAny,
    #[serde(rename = "use-system-hosts")]
    _use_system_hosts: IgnoredAny,
    #[serde(rename = "respect-rules")]
    _respect_rules: IgnoredAny,
    #[serde(rename = "nameserver")]
    _nameserver: IgnoredAny,
    #[serde(default, rename = "nameserver-policy")]
    _nameserver_policy: Option<IgnoredAny>,
    #[serde(default, rename = "direct-nameserver")]
    _direct_nameserver: Option<IgnoredAny>,
    #[serde(rename = "direct-nameserver-follow-policy")]
    _direct_nameserver_follow_policy: IgnoredAny,
    #[serde(rename = "fake-ip-filter")]
    _fake_ip_filter: IgnoredAny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreExit {
    pub code: Option<i32>,
}

pub(crate) mod sealed {
    pub trait Sealed {}
}

pub trait ProcessDriver: sealed::Sealed {
    type Handle;

    fn spawn(&mut self, spec: &CoreLaunchSpec) -> Result<Self::Handle>;
    fn pid(&self, handle: &Self::Handle) -> u32;
    fn try_wait(&mut self, handle: &mut Self::Handle) -> Result<Option<CoreExit>>;
    /// 只允许停止由这个 handle 明确拥有的子进程。
    fn stop_owned(&mut self, handle: &mut Self::Handle) -> Result<CoreExit>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeState {
    Stopped,
    Starting,
    ApiReady,
    ConfigReconciled,
    ManualVerificationRequired,
    Running,
    Failed,
}

pub struct CoreSupervisor<D: ProcessDriver> {
    driver: D,
    handle: Option<D::Handle>,
    state: RuntimeState,
    pid: Option<u32>,
    last_exit: Option<CoreExit>,
}

impl<D: ProcessDriver> CoreSupervisor<D> {
    pub fn new(driver: D) -> Self {
        Self {
            driver,
            handle: None,
            state: RuntimeState::Stopped,
            pid: None,
            last_exit: None,
        }
    }

    pub fn state(&self) -> RuntimeState {
        self.state
    }

    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    pub fn last_exit(&self) -> Option<CoreExit> {
        self.last_exit
    }

    pub fn start(&mut self, spec: &CoreLaunchSpec) -> Result<u32> {
        if self.state != RuntimeState::Stopped || self.handle.is_some() {
            return Err(ManagerError::InvalidRuntimeTransition);
        }
        spec.validate_for_spawn()?;
        let handle = self.driver.spawn(spec)?;
        let pid = self.driver.pid(&handle);
        self.handle = Some(handle);
        self.pid = Some(pid);
        self.last_exit = None;
        self.state = RuntimeState::Starting;
        Ok(pid)
    }

    pub fn poll(&mut self) -> Result<RuntimeState> {
        let Some(handle) = self.handle.as_mut() else {
            return Ok(self.state);
        };
        if let Some(exit) = self.driver.try_wait(handle)? {
            self.handle = None;
            self.pid = None;
            self.last_exit = Some(exit);
            self.state = RuntimeState::Failed;
        }
        Ok(self.state)
    }

    pub fn mark_api_ready(&mut self) -> Result<()> {
        self.transition(RuntimeState::Starting, RuntimeState::ApiReady)
    }

    pub fn mark_config_reconciled(&mut self) -> Result<()> {
        self.transition(RuntimeState::ApiReady, RuntimeState::ConfigReconciled)
    }

    pub fn require_manual_verification(&mut self) -> Result<()> {
        self.transition(
            RuntimeState::ConfigReconciled,
            RuntimeState::ManualVerificationRequired,
        )
    }

    pub fn confirm_manual_verification(&mut self) -> Result<()> {
        self.transition(
            RuntimeState::ManualVerificationRequired,
            RuntimeState::Running,
        )
    }

    pub fn stop_owned(&mut self) -> Result<Option<CoreExit>> {
        let Some(handle) = self.handle.as_mut() else {
            self.state = RuntimeState::Stopped;
            self.pid = None;
            return Ok(None);
        };
        // stop 失败时保留 handle，绝不能丢失仍可能存活的自有子进程。
        let exit = self.driver.stop_owned(handle)?;
        self.handle = None;
        self.pid = None;
        self.last_exit = Some(exit);
        self.state = RuntimeState::Stopped;
        Ok(Some(exit))
    }

    fn transition(&mut self, expected: RuntimeState, next: RuntimeState) -> Result<()> {
        if self.state != expected || self.handle.is_none() {
            return Err(ManagerError::InvalidRuntimeTransition);
        }
        self.state = next;
        Ok(())
    }
}

pub fn redact_known_secrets(line: &str, secrets: &[&SecretValue]) -> String {
    let mut redacted = line.to_owned();
    for secret in secrets {
        let value = secret.expose_secret();
        if !value.is_empty() {
            redacted = redacted.replace(value, "[REDACTED]");
        }
    }
    redacted
}

fn read_secret_file(path: &Path) -> Result<SecretValue> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_RUNTIME_CONFIG_BYTES as u64 {
        return Err(ManagerError::InvalidLaunchSpec);
    }
    let file = File::open(path)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(MAX_RUNTIME_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RUNTIME_CONFIG_BYTES {
        return Err(ManagerError::InvalidLaunchSpec);
    }
    let yaml = std::str::from_utf8(&bytes).map_err(|_| ManagerError::InvalidLaunchSpec)?;
    Ok(SecretValue::new(yaml.to_owned()))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("写入 String 不会失败");
    }
    Ok(output)
}

fn sha256_secret(secret: &SecretValue) -> String {
    let digest = Sha256::digest(secret.expose_secret().as_bytes());
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("写入 String 不会失败");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::fs;

    use hk_proton_core::{
        FirstHopProfile, ImportMetadata, LanPolicy, OperatingMode, ProfileId, ProtonProfile,
        RuntimeOptions, RuntimeSelection, SecretValue, TailscalePolicy, generate_profile,
        parse_wireguard,
    };
    use tempfile::TempDir;
    use time::macros::datetime;

    use super::*;

    const FIRST_HOP: &str =
        include_str!("../../hk-proton-core/tests/fixtures/first-hop-hk.synthetic.conf");
    const PROTON: &str =
        include_str!("../../hk-proton-core/tests/fixtures/proton-jp.synthetic.conf");

    #[derive(Default)]
    struct FakeDriver;

    struct FakeHandle {
        pid: u32,
        owned: bool,
    }

    impl sealed::Sealed for FakeDriver {}

    impl ProcessDriver for FakeDriver {
        type Handle = FakeHandle;

        fn spawn(&mut self, spec: &CoreLaunchSpec) -> Result<Self::Handle> {
            assert_eq!(spec.command_arguments().len(), 4);
            assert_eq!(spec.command_arguments()[0], "-d");
            assert_eq!(spec.command_arguments()[2], "-f");
            Ok(FakeHandle {
                pid: 4242,
                owned: true,
            })
        }

        fn pid(&self, handle: &Self::Handle) -> u32 {
            handle.pid
        }

        fn try_wait(&mut self, _handle: &mut Self::Handle) -> Result<Option<CoreExit>> {
            Ok(None)
        }

        fn stop_owned(&mut self, handle: &mut Self::Handle) -> Result<CoreExit> {
            assert!(handle.owned);
            handle.owned = false;
            Ok(CoreExit { code: Some(0) })
        }
    }

    #[test]
    fn tun_live_spec_requires_clean_bound_preflight_and_typed_authorization() {
        let temporary = TempDir::new().unwrap();
        let executable = temporary.path().join("fake-core.exe");
        let runtime_home = temporary.path().join("runtime");
        let config = runtime_home.join("config.yaml");
        fs::create_dir(&runtime_home).unwrap();
        fs::write(&executable, b"synthetic executable marker").unwrap();
        let runtime = synthetic_runtime(true);
        fs::write(&config, runtime.expose_secret()).unwrap();

        let projection = inspect_network_effects(&runtime).unwrap();
        let config_sha256 = sha256_file(&config).unwrap();
        let plan = OfflineLaunchPlan::from_verified_generation(
            7,
            "2".repeat(64),
            config_sha256,
            projection,
        )
        .unwrap();
        assert!(matches!(
            LivePreflightApproval::from_snapshot(&plan, &PreflightSnapshot::default()),
            Err(ManagerError::LivePreflightRejected)
        ));
        let warning_snapshot = PreflightSnapshot {
            capture_complete: true,
            routes_stable: true,
            clash_like_processes: 1,
            ..PreflightSnapshot::default()
        };
        assert_eq!(
            LivePreflightApproval::from_snapshot(&plan, &warning_snapshot)
                .unwrap()
                .revision(),
            7
        );

        let clean_snapshot = PreflightSnapshot {
            capture_complete: true,
            routes_stable: true,
            ..PreflightSnapshot::default()
        };
        let approval = LivePreflightApproval::from_snapshot(&plan, &clean_snapshot).unwrap();
        assert_eq!(approval.revision(), 7);
        let trusted = TrustedMihomoExecutable {
            executable: executable.canonicalize().unwrap(),
            expected_sha256: sha256_file(&executable).unwrap(),
        };

        assert!(matches!(
            CoreLaunchSpec::live(
                trusted.clone(),
                temporary.path(),
                &runtime_home,
                &config,
                LiveLaunchAuthorization::for_non_tun(approval.clone()),
            ),
            Err(ManagerError::LiveAuthorizationMismatch)
        ));

        let spec = CoreLaunchSpec::live(
            trusted,
            temporary.path(),
            &runtime_home,
            &config,
            LiveLaunchAuthorization::for_tun(
                approval,
                ExplicitTunAuthorization::from_explicit_user_action(),
                AdministratorConfirmation::confirmed_by_calling_layer(),
            ),
        )
        .unwrap();
        let mut supervisor = CoreSupervisor::new(FakeDriver);
        assert_eq!(supervisor.start(&spec).unwrap(), 4242);
        assert_eq!(supervisor.state(), RuntimeState::Starting);
        supervisor.mark_api_ready().unwrap();
        supervisor.mark_config_reconciled().unwrap();
        supervisor.require_manual_verification().unwrap();
        supervisor.confirm_manual_verification().unwrap();
        assert_eq!(supervisor.state(), RuntimeState::Running);
        assert_eq!(supervisor.stop_owned().unwrap().unwrap().code, Some(0));
        assert_eq!(supervisor.state(), RuntimeState::Stopped);
    }

    #[test]
    fn probe_spec_requires_tun_off_and_clean_loopback_ports() {
        let temporary = TempDir::new().unwrap();
        let executable = temporary.path().join("fake-core.exe");
        let runtime_home = temporary.path().join("runtime");
        let config = runtime_home.join("probe.yaml");
        fs::create_dir(&runtime_home).unwrap();
        fs::write(&executable, b"synthetic executable marker").unwrap();

        let tun_runtime = synthetic_runtime(true);
        assert!(matches!(
            ProbeLaunchAuthorization::from_snapshot(
                &tun_runtime,
                &PreflightSnapshot {
                    capture_complete: true,
                    routes_stable: true,
                    ..PreflightSnapshot::default()
                },
                ExplicitProbeAuthorization::from_explicit_user_action(),
            ),
            Err(ManagerError::NetworkActivationRequiresUser)
        ));

        let runtime = synthetic_runtime(false);
        fs::write(&config, runtime.expose_secret()).unwrap();
        let clean_snapshot = PreflightSnapshot {
            capture_complete: true,
            routes_stable: true,
            ..PreflightSnapshot::default()
        };
        let authorization = ProbeLaunchAuthorization::from_snapshot(
            &runtime,
            &clean_snapshot,
            ExplicitProbeAuthorization::from_explicit_user_action(),
        )
        .unwrap();
        let trusted = TrustedMihomoExecutable {
            executable: executable.canonicalize().unwrap(),
            expected_sha256: sha256_file(&executable).unwrap(),
        };
        let spec = CoreLaunchSpec::probe(
            trusted,
            temporary.path(),
            &runtime_home,
            &config,
            authorization,
        )
        .unwrap();
        let mut supervisor = CoreSupervisor::new(FakeDriver);
        assert_eq!(supervisor.start(&spec).unwrap(), 4242);
        assert_eq!(supervisor.stop_owned().unwrap().unwrap().code, Some(0));
    }

    #[test]
    fn precommit_candidate_contract_binds_memory_file_hash_and_projection() {
        let temporary = TempDir::new().unwrap();
        let executable = temporary.path().join("fake-core.exe");
        let runtime_home = temporary.path().join("runtime");
        let config = runtime_home.join("candidate.yaml");
        fs::create_dir(&runtime_home).unwrap();
        fs::write(&executable, b"synthetic executable marker").unwrap();

        let runtime = synthetic_runtime(true);
        fs::write(&config, runtime.expose_secret()).unwrap();
        let expected_hash = sha256_secret(&runtime);
        let projection = inspect_network_effects(&runtime).unwrap();
        let trusted = TrustedMihomoExecutable {
            executable: executable.canonicalize().unwrap(),
            expected_sha256: sha256_file(&executable).unwrap(),
        };

        let spec = CoreLaunchSpec::candidate_static_validation(
            &trusted,
            temporary.path(),
            &runtime_home,
            &config,
            &runtime,
            &expected_hash.to_ascii_uppercase(),
            &projection,
        )
        .unwrap();
        assert_eq!(spec.validation_arguments()[0], "-t");

        assert!(matches!(
            CoreLaunchSpec::candidate_static_validation(
                &trusted,
                temporary.path(),
                &runtime_home,
                &config,
                &runtime,
                &"0".repeat(64),
                &projection,
            ),
            Err(ManagerError::CandidateChanged)
        ));

        let mut mismatched_projection = projection.clone();
        mismatched_projection.mixed_port += 1;
        assert!(matches!(
            CoreLaunchSpec::candidate_static_validation(
                &trusted,
                temporary.path(),
                &runtime_home,
                &config,
                &runtime,
                &expected_hash,
                &mismatched_projection,
            ),
            Err(ManagerError::InvalidLaunchSpec)
        ));

        fs::write(&config, "changed after candidate generation").unwrap();
        assert!(matches!(
            CoreLaunchSpec::candidate_static_validation(
                &trusted,
                temporary.path(),
                &runtime_home,
                &config,
                &runtime,
                &expected_hash,
                &projection,
            ),
            Err(ManagerError::CandidateChanged)
        ));
    }

    #[test]
    fn precommit_candidate_requires_private_runtime_paths_and_loopback_listeners() {
        let temporary = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let executable = temporary.path().join("fake-core.exe");
        let runtime_home = temporary.path().join("runtime");
        let outside_config = outside.path().join("candidate.yaml");
        fs::create_dir(&runtime_home).unwrap();
        fs::write(&executable, b"synthetic executable marker").unwrap();

        let runtime = synthetic_runtime(true);
        fs::write(&outside_config, runtime.expose_secret()).unwrap();
        let expected_hash = sha256_secret(&runtime);
        let projection = inspect_network_effects(&runtime).unwrap();
        let trusted = TrustedMihomoExecutable {
            executable: executable.canonicalize().unwrap(),
            expected_sha256: sha256_file(&executable).unwrap(),
        };

        assert!(matches!(
            CoreLaunchSpec::candidate_static_validation(
                &trusted,
                temporary.path(),
                &runtime_home,
                &outside_config,
                &runtime,
                &expected_hash,
                &projection,
            ),
            Err(ManagerError::InvalidLaunchSpec)
        ));

        let unsafe_runtime = SecretValue::new(
            runtime
                .expose_secret()
                .replace("listen: 127.0.0.1:21053", "listen: 0.0.0.0:21053"),
        );
        fs::write(&outside_config, unsafe_runtime.expose_secret()).unwrap();
        let unsafe_hash = sha256_secret(&unsafe_runtime);
        let unsafe_projection = inspect_network_effects(&unsafe_runtime).unwrap();
        assert!(matches!(
            CoreLaunchSpec::candidate_static_validation(
                &trusted,
                outside.path(),
                outside.path(),
                &outside_config,
                &unsafe_runtime,
                &unsafe_hash,
                &unsafe_projection,
            ),
            Err(ManagerError::InvalidLaunchSpec)
        ));
    }

    fn synthetic_runtime(tun_enabled: bool) -> SecretValue {
        let first_parsed = parse_wireguard(FIRST_HOP).unwrap();
        let proton_parsed = parse_wireguard(PROTON).unwrap();
        let first = FirstHopProfile::new(
            ProfileId::new("fh-hk").unwrap(),
            "香港第一跳",
            first_parsed.config,
            metadata(first_parsed.source_sha256),
        )
        .unwrap();
        let proton = ProtonProfile::new(
            ProfileId::new("proton-jp").unwrap(),
            "Proton JP",
            proton_parsed.config,
            metadata(proton_parsed.source_sha256),
        )
        .unwrap();
        let selection = RuntimeSelection {
            mode: OperatingMode::DoubleHop,
            first_hop: ProfileId::new("fh-hk").unwrap(),
            proton: Some(ProfileId::new("proton-jp").unwrap()),
        };
        let options = RuntimeOptions::checked(
            tun_enabled,
            17890,
            19090,
            SecretValue::new("synthetic-process-controller"),
        )
        .unwrap();
        let generated = generate_profile(
            &[first],
            &[proton],
            &selection,
            &LanPolicy::default(),
            &TailscalePolicy::default(),
            &options,
        )
        .unwrap();
        SecretValue::new(generated.as_str().to_owned())
    }

    fn metadata(source_sha256: String) -> ImportMetadata {
        ImportMetadata::new(datetime!(2026-07-12 00:00 UTC), 1, source_sha256)
    }
}
