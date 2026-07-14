#![cfg(windows)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use hk_proton_core::{
    FIRST_HOP_SELECTOR, HK_PROTON_TUN_DEVICE, OUTLET_SELECTOR, OperatingMode, PROTON_SELECTOR,
    SecretValue,
};
use hk_proton_manager::windows_snapshot::{
    SnapshotProvider, WindowsNativeSnapshotProvider, WindowsSnapshot, capture_port_bindings,
};
use hk_proton_manager::{
    AdapterKind, AdapterSnapshot, AdministratorConfirmation, ApiContractViolation, AppState,
    ConflictDecision, ConflictReason, CoreLaunchSpec, CoreSupervisor, DpapiCurrentUserProtector,
    ExpectedRuntime, ExplicitProbeAuthorization, ExplicitTunAuthorization, LiveLaunchAuthorization,
    LivePreflightApproval, OfflineLaunchPlan, PortBinding, PortProtocol, PreflightSnapshot,
    ProbeLaunchAuthorization, ProcessDriver, RequiredPort, RuntimeState, StateStore,
    TrustedMihomoExecutable, WindowsMihomoDriver, WindowsPrivateDirectory, evaluate_conflicts,
    inspect_network_effects, reconcile_api_snapshot_json_detailed,
    reconcile_api_snapshot_json_with_observed_tun, validate_candidate_mihomo_config,
    validate_mihomo_config,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    dto::{BlockerDto, RuntimeStateDto},
    runtime::{NodeDelayMeasurement, NodeDelayTarget, RuntimeBackend, RuntimeView},
};

const RUNTIME_CONFIG_FILE: &str = "active-profile.yaml";
const CANDIDATE_CONFIG_FILE: &str = "candidate-profile.yaml";
const PROBE_CONFIG_FILE: &str = "probe-profile.yaml";
const DIAGNOSTIC_FLAGS_FILE: &str = "runtime-diagnostic.flags";
const MAX_CONTROLLER_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const CONTROLLER_READY_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROLLER_IO_TIMEOUT: Duration = Duration::from_millis(700);
const CLEANUP_SETTLE_TIMEOUT: Duration = Duration::from_secs(5);
const EMBEDDED_CORE_FILE: &str = "mihomo-1.19.28.exe";
const EMBEDDED_MIHOMO: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tools/mihomo/1.19.28/bin/mihomo-windows-amd64-compatible.exe"
));

pub struct LiveRuntime {
    store: Arc<StateStore<DpapiCurrentUserProtector>>,
    private_directory: WindowsPrivateDirectory,
    runtime_directory: WindowsPrivateDirectory,
    private_root: PathBuf,
    runtime_home: PathBuf,
    runtime_config: PathBuf,
    trusted_core: Option<TrustedMihomoExecutable>,
    supervisor: CoreSupervisor<WindowsMihomoDriver>,
    view: RuntimeView,
}

impl LiveRuntime {
    pub fn new(
        store: Arc<StateStore<DpapiCurrentUserProtector>>,
        private_directory: WindowsPrivateDirectory,
    ) -> hk_proton_manager::Result<Self> {
        private_directory.revalidate()?;
        let runtime_directory = private_directory.create_child("runtime")?;
        let private_root = private_directory.path().to_path_buf();
        let runtime_home = runtime_directory.path().to_path_buf();
        let runtime_config = runtime_home.join(RUNTIME_CONFIG_FILE);
        runtime_directory.remove_regular_file(RUNTIME_CONFIG_FILE)?;
        runtime_directory.remove_regular_file(CANDIDATE_CONFIG_FILE)?;
        runtime_directory.remove_regular_file(PROBE_CONFIG_FILE)?;
        runtime_directory.remove_regular_file(DIAGNOSTIC_FLAGS_FILE)?;

        // 分发包只包含 slpyW2W.exe；内核首次启动时写入受保护的应用私有目录并校验固定哈希。
        let trusted_core = materialize_embedded_mihomo(&private_directory).ok();
        let view = disconnected_view(trusted_core.is_some(), None);
        Ok(Self {
            store,
            private_directory,
            runtime_directory,
            private_root,
            runtime_home,
            runtime_config,
            trusted_core,
            supervisor: CoreSupervisor::new(WindowsMihomoDriver::new()),
            view,
        })
    }

    fn connect_inner(&mut self, revision: u64) -> Result<(), ConnectFailure> {
        if self.is_active() {
            return if self.supervisor.state() == RuntimeState::ManualVerificationRequired {
                Ok(())
            } else {
                Err(ConnectFailure::Launch)
            };
        }
        let trusted = self
            .trusted_core
            .clone()
            .ok_or(ConnectFailure::CoreUnavailable)?;
        let generation = self
            .store
            .load_generation(revision)
            .map_err(|_| ConnectFailure::State)?;
        let plan = self
            .store
            .prepare_offline_launch(revision)
            .map_err(|_| ConnectFailure::State)?;
        let runtime_yaml = self
            .store
            .load_runtime_yaml(revision)
            .map_err(|_| ConnectFailure::State)?;

        write_runtime_config(&self.runtime_directory, RUNTIME_CONFIG_FILE, &runtime_yaml)
            .map_err(|_| ConnectFailure::State)?;
        let diagnostic_file = prepare_diagnostic_file(&self.runtime_directory);
        self.private_directory
            .revalidate()
            .and_then(|_| self.runtime_directory.revalidate())
            .map_err(|_| ConnectFailure::State)?;
        validate_mihomo_config(
            &trusted,
            &self.private_root,
            &self.runtime_home,
            &self.runtime_config,
            &plan,
        )
        .map_err(|_| ConnectFailure::Validation)?;

        let snapshot =
            capture_preflight(plan.required_ports()).map_err(|_| ConnectFailure::Preflight)?;
        let require_ipv6_capture = snapshot_requires_ipv6_capture(&snapshot);
        let report = evaluate_conflicts(&snapshot, plan.required_ports());
        if !report.can_start() {
            let reason = report
                .findings
                .iter()
                .find(|finding| finding.decision == ConflictDecision::Block)
                .map(|finding| finding.reason)
                .unwrap_or(ConflictReason::DetectionIncomplete);
            return Err(ConnectFailure::Conflict(reason));
        }
        let approval = LivePreflightApproval::from_snapshot(&plan, &snapshot)
            .map_err(|_| ConnectFailure::Preflight)?;
        let authorization = if plan.network_effects().tun_enabled {
            LiveLaunchAuthorization::for_tun(
                approval,
                ExplicitTunAuthorization::from_explicit_user_action(),
                AdministratorConfirmation::confirmed_by_calling_layer(),
            )
        } else {
            LiveLaunchAuthorization::for_non_tun(approval)
        };
        let spec = CoreLaunchSpec::live(
            trusted,
            &self.private_root,
            &self.runtime_home,
            &self.runtime_config,
            authorization,
        )
        .map_err(|_| ConnectFailure::Launch)?;

        let core_pid = self
            .supervisor
            .start(&spec)
            .map_err(|_| ConnectFailure::Launch)?;
        if let Err(error) = wait_for_controller(
            &mut self.supervisor,
            &runtime_yaml,
            &generation.state,
            &plan,
            core_pid,
            require_ipv6_capture,
        ) {
            self.supervisor
                .stop_owned()
                .map_err(|_| ConnectFailure::Launch)?;
            if !wait_for_owned_cleanup(core_pid, plan.required_ports()) {
                return Err(ConnectFailure::CleanupPending);
            }
            return Err(error);
        }
        self.supervisor
            .mark_api_ready()
            .and_then(|_| self.supervisor.mark_config_reconciled())
            .and_then(|_| self.supervisor.require_manual_verification())
            .map_err(|_| ConnectFailure::Launch)?;
        if let Some(file) = diagnostic_file {
            spawn_runtime_diagnostic_monitor(&runtime_yaml, file);
        }
        Ok(())
    }

    fn cleanup_after_failure(&mut self) {
        let _ = self.supervisor.stop_owned();
        let _ = remove_runtime_config(&self.runtime_directory, RUNTIME_CONFIG_FILE);
        let _ = remove_runtime_config(&self.runtime_directory, PROBE_CONFIG_FILE);
    }

    fn measure_from_controller(
        targets: &[NodeDelayTarget],
        controller: SocketAddr,
        secret: &SecretValue,
    ) -> Result<Vec<NodeDelayMeasurement>, ()> {
        Ok(targets
            .iter()
            .map(|target| NodeDelayMeasurement {
                profile_id: target.profile_id.clone(),
                delay_ms: measure_warmed_proxy_delay(controller, secret, &target.proxy_name),
            })
            .collect())
    }

    fn measure_disconnected_delays(
        &mut self,
        targets: &[NodeDelayTarget],
    ) -> Result<Vec<NodeDelayMeasurement>, ()> {
        let trusted = self.trusted_core.clone().ok_or(())?;
        let current = self.store.load_current().map_err(|_| ())?.ok_or(())?;
        let runtime_yaml = self
            .store
            .load_runtime_yaml(current.state.revision)
            .map_err(|_| ())?;
        let ports = allocate_probe_ports()?;
        let probe_yaml = build_probe_yaml(&runtime_yaml, ports)?;

        // 临时配置也遵守“语义验证 -> 固定版本 mihomo -t -> 原子落盘 -> 启动”的顺序。
        hk_proton_core::validate_rendered_profile(probe_yaml.expose_secret()).map_err(|_| ())?;
        write_runtime_config(&self.runtime_directory, PROBE_CONFIG_FILE, &probe_yaml)
            .map_err(|_| ())?;
        let probe_path = self.runtime_home.join(PROBE_CONFIG_FILE);
        let result = (|| {
            let expected_sha256 = format!(
                "{:x}",
                Sha256::digest(probe_yaml.expose_secret().as_bytes())
            );
            let projection = inspect_network_effects(&probe_yaml).map_err(|_| ())?;
            validate_candidate_mihomo_config(
                &trusted,
                &self.private_root,
                &self.runtime_home,
                &probe_path,
                &probe_yaml,
                &expected_sha256,
                &projection,
            )
            .map_err(|_| ())?;

            let required_ports = probe_required_ports(&projection)?;
            let snapshot = capture_preflight(&required_ports).map_err(|_| ())?;
            let authorization = ProbeLaunchAuthorization::from_snapshot(
                &probe_yaml,
                &snapshot,
                ExplicitProbeAuthorization::from_explicit_user_action(),
            )
            .map_err(|_| ())?;
            let spec = CoreLaunchSpec::probe(
                trusted,
                &self.private_root,
                &self.runtime_home,
                &probe_path,
                authorization,
            )
            .map_err(|_| ())?;
            self.supervisor.start(&spec).map_err(|_| ())?;

            let (controller, secret) = controller_credentials(&probe_yaml).ok_or(())?;
            wait_for_probe_controller(&mut self.supervisor, controller, &secret)?;
            Self::measure_from_controller(targets, controller, &secret)
        })();

        let stopped = self.supervisor.stop_owned().map_err(|_| ());
        let removed =
            remove_runtime_config(&self.runtime_directory, PROBE_CONFIG_FILE).map_err(|_| ());
        match (result, stopped, removed) {
            (Ok(measurements), Ok(_), Ok(())) => Ok(measurements),
            _ => Err(()),
        }
    }
}

impl RuntimeBackend for LiveRuntime {
    fn is_active(&self) -> bool {
        !matches!(
            self.supervisor.state(),
            RuntimeState::Stopped | RuntimeState::Failed
        )
    }

    fn validate_candidate(&mut self, yaml: &SecretValue) -> Result<(), ()> {
        if self.is_active() {
            return Err(());
        }
        let trusted = self.trusted_core.clone().ok_or(())?;
        let candidate_path = self.runtime_home.join(CANDIDATE_CONFIG_FILE);
        write_runtime_config(&self.runtime_directory, CANDIDATE_CONFIG_FILE, yaml)
            .map_err(|_| ())?;

        let result = (|| {
            let expected_sha256 = format!("{:x}", Sha256::digest(yaml.expose_secret().as_bytes()));
            let projection = inspect_network_effects(yaml).map_err(|_| ())?;
            validate_candidate_mihomo_config(
                &trusted,
                &self.private_root,
                &self.runtime_home,
                &candidate_path,
                yaml,
                &expected_sha256,
                &projection,
            )
            .map_err(|_| ())
        })();
        let removed =
            remove_runtime_config(&self.runtime_directory, CANDIDATE_CONFIG_FILE).map_err(|_| ());
        result.and(removed)
    }

    fn connect(&mut self, revision: u64) -> RuntimeView {
        self.view = RuntimeView {
            state: RuntimeStateDto::Starting,
            can_connect: false,
            blocker: None,
            message: "正在建立连接。".to_owned(),
        };
        match self.connect_inner(revision) {
            Ok(()) => {
                self.view = RuntimeView {
                    state: RuntimeStateDto::ManualVerificationRequired,
                    can_connect: false,
                    blocker: None,
                    message: "内核已启动，请手动检查出口和 DNS。".to_owned(),
                };
            }
            Err(failure) => {
                self.cleanup_after_failure();
                self.view = failure.view(self.trusted_core.is_some());
            }
        }
        self.view.clone()
    }

    fn disconnect(&mut self) -> RuntimeView {
        let cleanup_contract = self.supervisor.pid().and_then(|pid| {
            self.store
                .load_current()
                .ok()
                .flatten()
                .and_then(|generation| {
                    self.store
                        .prepare_offline_launch(generation.state.revision)
                        .ok()
                })
                .map(|plan| (pid, plan.required_ports().to_vec()))
        });
        let stopped = self.supervisor.stop_owned().is_ok();
        let _ = remove_runtime_config(&self.runtime_directory, RUNTIME_CONFIG_FILE);
        let cleaned = stopped
            && cleanup_contract
                .as_ref()
                .is_none_or(|(pid, ports)| wait_for_owned_cleanup(*pid, ports));
        self.view = if cleaned {
            disconnected_view(self.trusted_core.is_some(), Some("已断开。"))
        } else if stopped {
            ConnectFailure::CleanupPending.view(self.trusted_core.is_some())
        } else {
            ConnectFailure::Launch.view(self.trusted_core.is_some())
        };
        self.view.clone()
    }

    fn poll(&mut self) -> RuntimeView {
        if self.is_active() && matches!(self.supervisor.poll(), Ok(RuntimeState::Failed) | Err(_)) {
            let _ = remove_runtime_config(&self.runtime_directory, RUNTIME_CONFIG_FILE);
            self.view = RuntimeView {
                state: RuntimeStateDto::Error,
                can_connect: self.trusted_core.is_some(),
                blocker: None,
                message: "连接已意外停止，可以重试。".to_owned(),
            };
        }
        self.view.clone()
    }

    fn configuration_changed(&mut self) -> RuntimeView {
        if self.is_active() {
            return self.disconnect();
        }
        self.view = disconnected_view(self.trusted_core.is_some(), Some("配置已保存。"));
        self.view.clone()
    }

    fn measure_delays(
        &mut self,
        targets: &[NodeDelayTarget],
    ) -> Result<Vec<NodeDelayMeasurement>, ()> {
        if targets.is_empty() || targets.len() > 128 {
            return Err(());
        }
        if !self.is_active() {
            return self.measure_disconnected_delays(targets);
        }
        let current = self.store.load_current().map_err(|_| ())?.ok_or(())?;
        let yaml = self
            .store
            .load_runtime_yaml(current.state.revision)
            .map_err(|_| ())?;
        let (controller, secret) = controller_credentials(&yaml).ok_or(())?;

        Self::measure_from_controller(targets, controller, &secret)
    }
}

impl Drop for LiveRuntime {
    fn drop(&mut self) {
        let _ = self.supervisor.stop_owned();
        let _ = remove_runtime_config(&self.runtime_directory, RUNTIME_CONFIG_FILE);
        let _ = remove_runtime_config(&self.runtime_directory, PROBE_CONFIG_FILE);
    }
}

#[derive(Clone, Copy)]
enum ConnectFailure {
    CoreUnavailable,
    State,
    Validation,
    Preflight,
    Conflict(ConflictReason),
    Launch,
    PortOwnership,
    ControllerUnavailable,
    ApiMismatch(ApiContractViolation),
    CleanupPending,
}

impl ConnectFailure {
    fn view(self, core_available: bool) -> RuntimeView {
        match self {
            Self::CoreUnavailable => RuntimeView {
                state: RuntimeStateDto::Blocked,
                can_connect: false,
                blocker: Some(BlockerDto::RuntimeUnavailable),
                message: "缺少连接内核，请重新解压完整程序。".to_owned(),
            },
            Self::Conflict(reason) => RuntimeView {
                state: RuntimeStateDto::Blocked,
                can_connect: core_available,
                blocker: Some(BlockerDto::LivePreflightRequired),
                message: conflict_message(reason).to_owned(),
            },
            Self::Preflight => RuntimeView {
                state: RuntimeStateDto::Blocked,
                can_connect: core_available,
                blocker: Some(BlockerDto::LivePreflightRequired),
                message: "无法完整读取当前网络状态，请稍候重试。".to_owned(),
            },
            Self::Validation | Self::State => RuntimeView {
                state: RuntimeStateDto::Error,
                can_connect: core_available,
                blocker: Some(BlockerDto::StateUnavailable),
                message: "当前配置无法使用，请重新导入。".to_owned(),
            },
            Self::Launch => RuntimeView {
                state: RuntimeStateDto::Error,
                can_connect: core_available,
                blocker: None,
                message: "Mihomo 内核未能启动，未保留连接。".to_owned(),
            },
            Self::PortOwnership => RuntimeView {
                state: RuntimeStateDto::Error,
                can_connect: core_available,
                blocker: None,
                message: "内核未完整监听所需端口，已停止。".to_owned(),
            },
            Self::ControllerUnavailable => RuntimeView {
                state: RuntimeStateDto::Error,
                can_connect: core_available,
                blocker: None,
                message: "内核控制接口未就绪，已停止。".to_owned(),
            },
            Self::ApiMismatch(reason) => RuntimeView {
                state: RuntimeStateDto::Error,
                can_connect: core_available,
                blocker: None,
                message: api_mismatch_message(reason).to_owned(),
            },
            Self::CleanupPending => RuntimeView {
                state: RuntimeStateDto::Blocked,
                can_connect: core_available,
                blocker: Some(BlockerDto::LivePreflightRequired),
                message: "上次 slpyW2W TUN 仍在退出，请等待几秒后重试。".to_owned(),
            },
        }
    }
}

fn api_mismatch_message(reason: ApiContractViolation) -> &'static str {
    match reason {
        ApiContractViolation::TunDisabled => {
            "slpyW2W TUN 创建失败，已停止。请确认其他软件的 TUN 已关闭。"
        }
        ApiContractViolation::TunDeviceMismatch => "slpyW2W TUN 网卡名称不一致，已停止。",
        ApiContractViolation::VersionMismatch => "Mihomo 内核版本校验失败，已停止。",
        ApiContractViolation::UnexpectedTunState => "TUN 开关状态异常，已停止。",
        ApiContractViolation::AllowLanEnabled => "运行参数异常：allow-lan，已停止。",
        ApiContractViolation::BindAddressMismatch => "运行参数异常：bind-address，已停止。",
        ApiContractViolation::ModeMismatch => "运行参数异常：mode，已停止。",
        ApiContractViolation::MixedPortMismatch => "运行参数异常：mixed-port，已停止。",
        ApiContractViolation::Ipv6Disabled => "运行参数异常：ipv6，已停止。",
        ApiContractViolation::AutoRouteDisabled => "运行参数异常：auto-route，已停止。",
        ApiContractViolation::StrictRouteDisabled => "运行参数异常：strict-route，已停止。",
        ApiContractViolation::DnsHijackMismatch => "运行参数异常：dns-hijack，已停止。",
        ApiContractViolation::RequiredProxyMissing | ApiContractViolation::SelectorMismatch => {
            "节点选择状态不一致，已停止。"
        }
        ApiContractViolation::SnapshotTooLarge => "内核运行状态响应过大，已停止。",
        ApiContractViolation::InvalidVersionPayload => "内核版本状态读取异常，已停止。",
        ApiContractViolation::InvalidConfigPayload => "内核运行配置读取异常，已停止。",
        ApiContractViolation::InvalidProxiesPayload => "内核节点状态读取异常，已停止。",
    }
}

fn conflict_message(reason: ConflictReason) -> &'static str {
    match reason {
        ConflictReason::DetectionIncomplete => "当前网络状态正在变化，请稍候重试。",
        ConflictReason::OtherPublicTunActive => "检测到其他 TUN 仍在接管公网流量。",
        ConflictReason::TailscaleExitNode => "检测到 Tailscale Exit Node，请先关闭。",
        ConflictReason::StaleOwnArtifact => "上次 slpyW2W TUN 尚未退出，请稍候重试。",
        ConflictReason::ClashProcessPresent => "检测到 Clash 后台进程。",
        ConflictReason::PortConflict => "slpyW2W 所需端口仍被其他程序占用。",
    }
}

fn disconnected_view(core_available: bool, message: Option<&str>) -> RuntimeView {
    RuntimeView {
        state: RuntimeStateDto::Disconnected,
        can_connect: core_available,
        blocker: (!core_available).then_some(BlockerDto::RuntimeUnavailable),
        message: message
            .unwrap_or(if core_available {
                "可以连接。"
            } else {
                "缺少连接内核。"
            })
            .to_owned(),
    }
}

fn materialize_embedded_mihomo(
    private_directory: &WindowsPrivateDirectory,
) -> hk_proton_manager::Result<TrustedMihomoExecutable> {
    private_directory.revalidate()?;
    let core_directory = private_directory.create_child("core")?;
    if let Some(existing) = core_directory.existing_regular_file(EMBEDDED_CORE_FILE)? {
        if let Ok(trusted) = TrustedMihomoExecutable::verify_pinned(existing) {
            return Ok(trusted);
        }
        core_directory.remove_regular_file(EMBEDDED_CORE_FILE)?;
    }

    let (path, mut file) = core_directory.create_new_file(EMBEDDED_CORE_FILE)?;
    if let Err(error) = file
        .write_all(EMBEDDED_MIHOMO)
        .and_then(|_| file.sync_all())
    {
        drop(file);
        let _ = core_directory.remove_regular_file(EMBEDDED_CORE_FILE);
        return Err(error.into());
    }
    drop(file);
    core_directory.revalidate()?;
    TrustedMihomoExecutable::verify_pinned(path)
}

fn write_runtime_config(
    directory: &WindowsPrivateDirectory,
    file_name: &str,
    yaml: &SecretValue,
) -> hk_proton_manager::Result<()> {
    directory.remove_regular_file(file_name)?;
    let (_, mut file) = directory.create_new_file(file_name)?;
    let result = file
        .write_all(yaml.expose_secret().as_bytes())
        .and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = directory.remove_regular_file(file_name);
        return Err(error.into());
    }
    directory
        .existing_regular_file(file_name)?
        .ok_or(hk_proton_manager::ManagerError::UnsafePrivatePath)?;
    directory.revalidate()
}

fn remove_runtime_config(
    directory: &WindowsPrivateDirectory,
    file_name: &str,
) -> hk_proton_manager::Result<()> {
    directory.remove_regular_file(file_name)
}

fn prepare_diagnostic_file(directory: &WindowsPrivateDirectory) -> Option<File> {
    directory.remove_regular_file(DIAGNOSTIC_FLAGS_FILE).ok()?;
    directory
        .create_new_file(DIAGNOSTIC_FLAGS_FILE)
        .ok()
        .map(|(_, file)| file)
}

fn spawn_runtime_diagnostic_monitor(yaml: &SecretValue, file: File) {
    let Some((controller, secret)) = controller_credentials(yaml) else {
        return;
    };
    let _ = thread::Builder::new()
        .name("hk-proton-diagnostic".to_owned())
        .spawn(move || monitor_runtime_diagnostics(controller, &secret, file));
}

/// 只把原始控制器日志在内存中归类为固定标志；文件中不会出现日志原文、地址或密钥。
fn monitor_runtime_diagnostics(address: SocketAddr, secret: &SecretValue, mut file: File) {
    if !address.ip().is_loopback() {
        return;
    }
    let Ok(mut stream) = TcpStream::connect_timeout(&address, CONTROLLER_IO_TIMEOUT) else {
        return;
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .is_err()
        || stream
            .set_write_timeout(Some(CONTROLLER_IO_TIMEOUT))
            .is_err()
    {
        return;
    }
    let request = Zeroizing::new(format!(
        "GET /logs?level=warning HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        secret.expose_secret()
    ));
    if stream.write_all(request.as_bytes()).is_err() {
        return;
    }

    let mut rolling = Zeroizing::new(Vec::<u8>::with_capacity(16 * 1024));
    let mut seen = BTreeSet::new();
    let mut chunk = [0_u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(size) => {
                rolling.extend_from_slice(&chunk[..size]);
                if rolling.len() > 16 * 1024 {
                    let remove = rolling.len() - 8 * 1024;
                    rolling.drain(..remove);
                }
                for flag in classify_runtime_diagnostics(&rolling) {
                    if seen.insert(flag) {
                        let _ = writeln!(file, "{flag}");
                        let _ = file.flush();
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => break,
        }
    }
}

fn classify_runtime_diagnostics(bytes: &[u8]) -> BTreeSet<&'static str> {
    let lowered = Zeroizing::new(String::from_utf8_lossy(bytes).to_ascii_lowercase());
    let mut flags = BTreeSet::new();
    if lowered.contains("[wg]") || lowered.contains("wireguard") {
        flags.insert("wireguard_error");
    }
    if lowered.contains("handshake") {
        flags.insert("handshake_error");
    }
    if lowered.contains("timeout") || lowered.contains("timed out") {
        flags.insert("network_timeout");
    }
    if lowered.contains("dns") && (lowered.contains("error") || lowered.contains("fail")) {
        flags.insert("dns_error");
    }
    if lowered.contains("no route") || lowered.contains("network is unreachable") {
        flags.insert("route_error");
    }
    if lowered.contains("connection refused") {
        flags.insert("connection_refused");
    }
    if lowered.contains("tls") && (lowered.contains("error") || lowered.contains("fail")) {
        flags.insert("tls_error");
    }
    flags
}

fn capture_preflight(required_ports: &[RequiredPort]) -> Result<PreflightSnapshot, ()> {
    let provider = WindowsNativeSnapshotProvider;
    let first = provider.capture().map_err(|_| ())?;
    let first_port_bindings = capture_port_bindings().map_err(|_| ())?;
    let second = provider.capture().map_err(|_| ())?;
    let second_port_bindings = capture_port_bindings().map_err(|_| ())?;
    let routes_stable = route_signature(&first) == route_signature(&second)
        && required_port_signature(required_ports, &first_port_bindings)
            == required_port_signature(required_ports, &second_port_bindings);
    let capture_complete = first.associations_complete() && second.associations_complete();

    let adapters = second
        .interfaces
        .iter()
        .map(|interface| {
            let routes = second
                .routes
                .iter()
                .filter(|route| route.interface_luid == interface.luid)
                .map(|route| route.destination)
                .collect::<Vec<_>>();
            let kind = classify_adapter(
                interface.hardware_interface(),
                interface.connector_present(),
                interface.filter_interface(),
                interface.endpoint_interface(),
                interface.tunnel_type,
                &interface.alias,
                &interface.description,
            );
            AdapterSnapshot {
                interface_id: interface.interface_guid.clone(),
                kind,
                operational_up: interface.operational_up,
                ownership_verified: false,
                routes,
                // 当前快照未执行 BestRoute 探针；路由并集仍会保守识别全局捕获。
                public_best_route_hits: 0,
            }
        })
        .collect();
    let clash_like_processes = second
        .processes
        .iter()
        .filter(|process| {
            let name = process.executable_name.to_ascii_lowercase();
            name.contains("clash") || name.contains("verge") || name.contains("mihomo")
        })
        .count();
    Ok(PreflightSnapshot {
        capture_complete,
        routes_stable,
        clash_like_processes,
        adapters,
        port_bindings: second_port_bindings,
    })
}

fn route_signature(snapshot: &WindowsSnapshot) -> Vec<(u64, u32, String, String, u32)> {
    let mut signature = snapshot
        .routes
        .iter()
        .map(|route| {
            (
                route.interface_luid,
                route.interface_index,
                route.destination.to_string(),
                route.next_hop.to_string(),
                route.metric,
            )
        })
        .collect::<Vec<_>>();
    signature.sort();
    signature
}

fn classify_adapter(
    hardware: bool,
    connector_present: bool,
    filter: bool,
    endpoint: bool,
    tunnel_type: i32,
    alias: &str,
    description: &str,
) -> AdapterKind {
    let name = format!("{alias} {description}").to_ascii_lowercase();
    if name.contains("hk-proton") {
        AdapterKind::OwnedHkProton
    } else if name.contains("tailscale") {
        AdapterKind::Tailscale
    } else if name.contains("wsl") {
        AdapterKind::Wsl
    } else if name.contains("docker") {
        AdapterKind::Docker
    } else if name.contains("hyper-v") || name.contains("vethernet") {
        AdapterKind::HyperV
    } else if name.contains(" tap") || name.starts_with("tap") {
        AdapterKind::Tap
    } else if hardware && connector_present && !filter && !endpoint && tunnel_type == 0 {
        AdapterKind::Physical
    } else {
        AdapterKind::OtherVirtual
    }
}

fn required_port_signature(
    required: &[RequiredPort],
    bindings: &[PortBinding],
) -> Vec<(u8, IpAddr, u16, u32)> {
    let mut signature = bindings
        .iter()
        .filter(|binding| {
            required.iter().any(|port| {
                binding.protocol == port.protocol
                    && binding.port == port.port
                    && port_addresses_conflict(binding.address, port.address)
            })
        })
        .map(|binding| {
            (
                match binding.protocol {
                    PortProtocol::Tcp => 0,
                    PortProtocol::Udp => 1,
                },
                binding.address,
                binding.port,
                binding.owner_pid,
            )
        })
        .collect::<Vec<_>>();
    signature.sort_unstable();
    signature.dedup();
    signature
}

fn port_addresses_conflict(existing: IpAddr, required: IpAddr) -> bool {
    if existing == required || existing.is_unspecified() || required.is_unspecified() {
        return true;
    }
    // IPv6 通配监听可能启用 dual-stack，保守视为与任意 IPv4 同端口冲突。
    (matches!(existing, IpAddr::V6(address) if address.is_unspecified())
        && matches!(required, IpAddr::V4(_)))
        || (matches!(required, IpAddr::V6(address) if address.is_unspecified())
            && matches!(existing, IpAddr::V4(_)))
}

fn wait_for_controller<D: ProcessDriver>(
    supervisor: &mut CoreSupervisor<D>,
    yaml: &SecretValue,
    state: &AppState,
    plan: &OfflineLaunchPlan,
    core_pid: u32,
    require_ipv6_capture: bool,
) -> Result<(), ConnectFailure> {
    let (controller, secret) =
        controller_credentials(yaml).ok_or(ConnectFailure::ControllerUnavailable)?;
    let expected = expected_runtime(state, plan);
    let deadline = Instant::now() + CONTROLLER_READY_TIMEOUT;
    let mut saw_owned_ports = false;
    let mut saw_owned_tun = !expected.tun_enabled;
    let mut saw_controller = false;
    let mut saw_complete_snapshot = false;
    let mut last_mismatch = ApiContractViolation::InvalidVersionPayload;
    loop {
        if matches!(supervisor.poll(), Ok(RuntimeState::Failed) | Err(_)) {
            return Err(ConnectFailure::Launch);
        }
        if expected.tun_enabled && owned_hk_proton_tun_is_ready(yaml, require_ipv6_capture) {
            saw_owned_tun = true;
        }
        if let Ok(bindings) = capture_port_bindings()
            && required_ports_owned_by(plan.required_ports(), &bindings, core_pid)
        {
            saw_owned_ports = true;
            if !saw_owned_tun {
                thread::sleep(Duration::from_millis(250));
                continue;
            }
            if let Ok(version) = controller_get(controller, "/version", &secret) {
                saw_controller = true;
                if let Ok(config) = controller_get(controller, "/configs", &secret)
                    && let Ok(proxies) = controller_get(controller, "/proxies", &secret)
                {
                    saw_complete_snapshot = true;
                    match reconcile_owned_runtime_snapshot(
                        &version,
                        &config,
                        &proxies,
                        &expected,
                        saw_owned_tun,
                    ) {
                        Ok(_) => return Ok(()),
                        Err(reason) => last_mismatch = reason,
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(if !saw_owned_ports {
                ConnectFailure::PortOwnership
            } else if !saw_owned_tun {
                ConnectFailure::ApiMismatch(ApiContractViolation::TunDisabled)
            } else if !saw_controller || !saw_complete_snapshot {
                ConnectFailure::ControllerUnavailable
            } else {
                ConnectFailure::ApiMismatch(last_mismatch)
            });
        }
        thread::sleep(Duration::from_millis(250));
    }
}

/// Mihomo 1.19.28 在 Windows 上可能在专属 TUN 与公网路由已经就绪后，仍为
/// `/configs.tun` 返回默认值。此时以操作系统实况校验 TUN，API 继续校验其余合同。
fn reconcile_owned_runtime_snapshot(
    version: &str,
    config: &str,
    proxies: &str,
    expected: &ExpectedRuntime,
    owned_tun_up: bool,
) -> Result<(), ApiContractViolation> {
    if expected.tun_enabled && owned_tun_up {
        reconcile_api_snapshot_json_with_observed_tun(version, config, proxies, expected)
            .map(|_| ())
    } else {
        reconcile_api_snapshot_json_detailed(version, config, proxies, expected).map(|_| ())
    }
}

fn snapshot_requires_ipv6_capture(snapshot: &PreflightSnapshot) -> bool {
    snapshot.adapters.iter().any(|adapter| {
        adapter.operational_up
            && adapter.kind == AdapterKind::Physical
            && adapter.routes.iter().any(
                |route| matches!(route, ipnet::IpNet::V6(network) if network.prefix_len() == 0),
            )
    })
}

#[derive(Deserialize)]
struct RuntimeRoutePolicyDocument {
    tun: RuntimeRoutePolicy,
}

#[derive(Deserialize)]
struct RuntimeRoutePolicy {
    #[serde(rename = "route-address")]
    route_address: Vec<ipnet::IpNet>,
    #[serde(rename = "route-exclude-address", default)]
    route_exclude_address: Vec<ipnet::IpNet>,
}

fn owned_hk_proton_tun_is_ready(yaml: &SecretValue, require_ipv6_capture: bool) -> bool {
    let Ok(policy) = serde_yaml_ng::from_str::<RuntimeRoutePolicyDocument>(yaml.expose_secret())
        .map(|document| document.tun)
    else {
        return false;
    };
    let provider = WindowsNativeSnapshotProvider;
    provider.capture().is_ok_and(|snapshot| {
        snapshot.interfaces.iter().any(|interface| {
            if !interface.operational_up
                || classify_adapter(
                    interface.hardware_interface(),
                    interface.connector_present(),
                    interface.filter_interface(),
                    interface.endpoint_interface(),
                    interface.tunnel_type,
                    &interface.alias,
                    &interface.description,
                ) != AdapterKind::OwnedHkProton
            {
                return false;
            }

            has_complete_public_capture(
                snapshot
                    .routes
                    .iter()
                    .filter(|route| route.interface_luid == interface.luid)
                    .map(|route| route.destination),
                &policy.route_address,
                &policy.route_exclude_address,
                require_ipv6_capture,
            )
        })
    })
}

/// `route-exclude-address` 会让 Mihomo 把两条 `/1` 拆成很多更小的 CIDR，
/// 因此不能按固定路由名称判断。这里比较实际地址覆盖集合，并保留完整接管要求。
fn has_complete_public_capture(
    destinations: impl IntoIterator<Item = ipnet::IpNet>,
    route_address: &[ipnet::IpNet],
    route_exclude_address: &[ipnet::IpNet],
    require_ipv6_capture: bool,
) -> bool {
    let observed = destinations.into_iter().collect::<Vec<_>>();
    [false, true].into_iter().all(|ipv6| {
        if ipv6 && !require_ipv6_capture {
            return true;
        }
        let included = normalized_address_ranges(route_address, ipv6);
        if included.is_empty() {
            return false;
        }
        let excluded = normalized_address_ranges(route_exclude_address, ipv6);
        let expected = subtract_address_ranges(&included, &excluded);
        let actual = normalized_address_ranges(&observed, ipv6);
        address_ranges_cover(&actual, &expected)
    })
}

fn normalized_address_ranges(networks: &[ipnet::IpNet], ipv6: bool) -> Vec<(u128, u128)> {
    let mut ranges = networks
        .iter()
        .filter_map(|network| match network {
            ipnet::IpNet::V4(network) if !ipv6 => Some((
                u32::from(network.network()) as u128,
                u32::from(network.broadcast()) as u128,
            )),
            ipnet::IpNet::V6(network) if ipv6 => {
                let start = u128::from(network.network());
                let host_bits = 128 - network.prefix_len();
                let end = if host_bits == 128 {
                    u128::MAX
                } else {
                    start | ((1_u128 << host_bits) - 1)
                };
                Some((start, end))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    ranges.sort_unstable();

    let mut normalized: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some((_, previous_end)) = normalized.last_mut()
            && start <= previous_end.saturating_add(1)
        {
            *previous_end = (*previous_end).max(end);
        } else {
            normalized.push((start, end));
        }
    }
    normalized
}

fn subtract_address_ranges(
    included: &[(u128, u128)],
    excluded: &[(u128, u128)],
) -> Vec<(u128, u128)> {
    let mut result = Vec::new();
    for &(include_start, include_end) in included {
        let mut cursor = include_start;
        let mut exhausted = false;
        for &(exclude_start, exclude_end) in excluded {
            if exclude_end < cursor || exclude_start > include_end {
                continue;
            }
            if exclude_start > cursor {
                result.push((cursor, exclude_start - 1));
            }
            let Some(next) = exclude_end.checked_add(1) else {
                exhausted = true;
                break;
            };
            cursor = cursor.max(next);
            if cursor > include_end {
                break;
            }
        }
        if !exhausted && cursor <= include_end {
            result.push((cursor, include_end));
        }
    }
    result
}

fn address_ranges_cover(actual: &[(u128, u128)], expected: &[(u128, u128)]) -> bool {
    expected.iter().all(|&(expected_start, expected_end)| {
        let mut cursor = expected_start;
        for &(actual_start, actual_end) in actual {
            if actual_end < cursor {
                continue;
            }
            if actual_start > cursor {
                return false;
            }
            if actual_end >= expected_end {
                return true;
            }
            let Some(next) = actual_end.checked_add(1) else {
                return true;
            };
            cursor = next;
        }
        false
    })
}

fn wait_for_owned_cleanup(core_pid: u32, required: &[RequiredPort]) -> bool {
    let provider = WindowsNativeSnapshotProvider;
    let deadline = Instant::now() + CLEANUP_SETTLE_TIMEOUT;
    loop {
        let ports_gone = capture_port_bindings().is_ok_and(|bindings| {
            !bindings.iter().any(|binding| {
                binding.owner_pid == core_pid
                    && required.iter().any(|port| {
                        binding.protocol == port.protocol
                            && binding.port == port.port
                            && port_addresses_conflict(binding.address, port.address)
                    })
            })
        });
        let adapter_gone = provider.capture().is_ok_and(|snapshot| {
            !snapshot.interfaces.iter().any(|interface| {
                interface.operational_up
                    && format!("{} {}", interface.alias, interface.description)
                        .to_ascii_lowercase()
                        .contains("hk-proton")
            })
        });
        if ports_gone && adapter_gone {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn required_ports_owned_by(
    required: &[RequiredPort],
    bindings: &[PortBinding],
    owner_pid: u32,
) -> bool {
    required.iter().all(|port| {
        let matching = bindings.iter().filter(|binding| {
            binding.protocol == port.protocol
                && binding.port == port.port
                && port_addresses_conflict(binding.address, port.address)
        });
        let owners = matching
            .map(|binding| binding.owner_pid)
            .collect::<BTreeSet<_>>();
        owners.len() == 1 && owners.contains(&owner_pid)
    })
}

fn allocate_probe_ports() -> Result<[u16; 3], ()> {
    let mut listeners = Vec::with_capacity(3);
    let mut ports = [0_u16; 3];
    for port in &mut ports {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| ())?;
        *port = listener.local_addr().map_err(|_| ())?.port();
        listeners.push(listener);
    }
    drop(listeners);
    Ok(ports)
}

fn build_probe_yaml(runtime_yaml: &SecretValue, ports: [u16; 3]) -> Result<SecretValue, ()> {
    let mut root = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(runtime_yaml.expose_secret())
        .map_err(|_| ())?;
    let mapping = root.as_mapping_mut().ok_or(())?;
    mapping.insert(
        serde_yaml_ng::Value::String("mixed-port".to_owned()),
        serde_yaml_ng::Value::Number(ports[0].into()),
    );
    mapping.insert(
        serde_yaml_ng::Value::String("external-controller".to_owned()),
        serde_yaml_ng::Value::String(format!("127.0.0.1:{}", ports[1])),
    );
    let tun = mapping
        .get_mut(serde_yaml_ng::Value::String("tun".to_owned()))
        .and_then(serde_yaml_ng::Value::as_mapping_mut)
        .ok_or(())?;
    tun.insert(
        serde_yaml_ng::Value::String("enable".to_owned()),
        serde_yaml_ng::Value::Bool(false),
    );
    let dns = mapping
        .get_mut(serde_yaml_ng::Value::String("dns".to_owned()))
        .and_then(serde_yaml_ng::Value::as_mapping_mut)
        .ok_or(())?;
    dns.insert(
        serde_yaml_ng::Value::String("listen".to_owned()),
        serde_yaml_ng::Value::String(format!("127.0.0.1:{}", ports[2])),
    );
    let rendered = serde_yaml_ng::to_string(&root).map_err(|_| ())?;
    Ok(SecretValue::new(rendered))
}

fn probe_required_ports(
    projection: &hk_proton_manager::NetworkEffectProjection,
) -> Result<Vec<RequiredPort>, ()> {
    let bind_address = projection.bind_address.parse::<IpAddr>().map_err(|_| ())?;
    let mut ports = vec![
        RequiredPort {
            protocol: PortProtocol::Tcp,
            address: bind_address,
            port: projection.mixed_port,
            allowed_owner_pid: None,
        },
        RequiredPort {
            protocol: PortProtocol::Tcp,
            address: projection.external_controller.ip(),
            port: projection.external_controller.port(),
            allowed_owner_pid: None,
        },
    ];
    if projection.dns_enabled {
        for protocol in [PortProtocol::Tcp, PortProtocol::Udp] {
            ports.push(RequiredPort {
                protocol,
                address: projection.dns_listener.ip(),
                port: projection.dns_listener.port(),
                allowed_owner_pid: None,
            });
        }
    }
    Ok(ports)
}

fn wait_for_probe_controller(
    supervisor: &mut CoreSupervisor<WindowsMihomoDriver>,
    controller: SocketAddr,
    secret: &SecretValue,
) -> Result<(), ()> {
    let deadline = Instant::now() + CONTROLLER_READY_TIMEOUT;
    while Instant::now() < deadline {
        if controller_get(controller, "/version", secret).is_ok()
            && controller_get(controller, "/proxies", secret).is_ok()
        {
            return Ok(());
        }
        if matches!(supervisor.poll(), Ok(RuntimeState::Failed) | Err(_)) {
            return Err(());
        }
        thread::sleep(Duration::from_millis(60));
    }
    Err(())
}

fn expected_runtime(state: &AppState, plan: &OfflineLaunchPlan) -> ExpectedRuntime {
    let mut required_proxies = state
        .first_hops
        .iter()
        .filter(|profile| profile.enabled)
        .map(|profile| format!("FH-{}", profile.id))
        .chain(
            state
                .proton_nodes
                .iter()
                .filter(|profile| profile.enabled)
                .map(|profile| format!("PN-{}", profile.id)),
        )
        .collect::<BTreeSet<_>>();
    required_proxies.insert(FIRST_HOP_SELECTOR.to_owned());
    required_proxies.insert(OUTLET_SELECTOR.to_owned());

    let first = format!("FH-{}", state.selected_first_hop);
    let mut selectors = BTreeMap::from([(FIRST_HOP_SELECTOR.to_owned(), first)]);
    match state.mode {
        OperatingMode::SingleHop => {
            selectors.insert(OUTLET_SELECTOR.to_owned(), FIRST_HOP_SELECTOR.to_owned());
        }
        OperatingMode::DoubleHop => {
            required_proxies.insert(PROTON_SELECTOR.to_owned());
            if let Some(proton) = &state.selected_proton {
                selectors.insert(PROTON_SELECTOR.to_owned(), format!("PN-{proton}"));
            }
            selectors.insert(OUTLET_SELECTOR.to_owned(), PROTON_SELECTOR.to_owned());
        }
    }
    ExpectedRuntime {
        tun_enabled: plan.network_effects().tun_enabled,
        mixed_port: plan.network_effects().mixed_port,
        tun_device: HK_PROTON_TUN_DEVICE.to_owned(),
        required_proxies,
        selectors,
    }
}

fn controller_credentials(yaml: &SecretValue) -> Option<(SocketAddr, SecretValue)> {
    let mut controller = None;
    let mut secret = None;
    for line in yaml.expose_secret().lines() {
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = unquote_scalar(value.trim());
        match key.trim() {
            "external-controller" => controller = value.parse().ok(),
            "secret" if !value.is_empty() && !value.chars().any(char::is_control) => {
                secret = Some(SecretValue::new(value));
            }
            _ => {}
        }
    }
    Some((controller?, secret?))
}

fn unquote_scalar(value: &str) -> &str {
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

fn controller_get(
    address: SocketAddr,
    path: &str,
    secret: &SecretValue,
) -> Result<Zeroizing<String>, ()> {
    let is_delay_request = is_safe_delay_path(path);
    if !address.ip().is_loopback()
        || (!matches!(path, "/version" | "/configs" | "/proxies") && !is_delay_request)
    {
        return Err(());
    }
    let mut stream = TcpStream::connect_timeout(&address, CONTROLLER_IO_TIMEOUT).map_err(|_| ())?;
    let read_timeout = if is_delay_request {
        Duration::from_secs(6)
    } else {
        CONTROLLER_IO_TIMEOUT
    };
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|_| ())?;
    stream
        .set_write_timeout(Some(CONTROLLER_IO_TIMEOUT))
        .map_err(|_| ())?;
    let request = Zeroizing::new(format!(
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        secret.expose_secret()
    ));
    stream.write_all(request.as_bytes()).map_err(|_| ())?;

    let mut bytes = Vec::new();
    stream
        .take(MAX_CONTROLLER_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_CONTROLLER_RESPONSE_BYTES {
        return Err(());
    }
    let response = std::str::from_utf8(&bytes).map_err(|_| ())?;
    let header_end = response.find("\r\n\r\n").ok_or(())?;
    let headers = &response[..header_end];
    let status = headers.lines().next().ok_or(())?;
    if !status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.0 200 ") {
        return Err(());
    }
    let body = &response[header_end + 4..];
    if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        decode_chunked(body)
    } else {
        Ok(Zeroizing::new(body.to_owned()))
    }
}

#[derive(Deserialize)]
struct ProxyDelayResponse {
    delay: u32,
}

fn measure_proxy_delay(
    controller: SocketAddr,
    secret: &SecretValue,
    proxy_name: &str,
) -> Option<u32> {
    if proxy_name.is_empty()
        || proxy_name.len() > 96
        || !proxy_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return None;
    }
    let path = format!(
        "/proxies/{proxy_name}/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=5000"
    );
    let body = controller_get(controller, &path, secret).ok()?;
    let response = serde_json::from_str::<ProxyDelayResponse>(body.as_str()).ok()?;
    (response.delay > 0 && response.delay <= 60_000).then_some(response.delay)
}

/// 第一次请求负责建立 WireGuard 与 TLS，第二次更接近用户实际使用时的稳定延迟。
/// 若第二次恰好失败但预热成功，仍保留第一次结果，避免把可用节点误报为超时。
fn measure_warmed_proxy_delay(
    controller: SocketAddr,
    secret: &SecretValue,
    proxy_name: &str,
) -> Option<u32> {
    let warmup = measure_proxy_delay(controller, secret, proxy_name);
    let measured = measure_proxy_delay(controller, secret, proxy_name);
    measured.or(warmup)
}

fn is_safe_delay_path(path: &str) -> bool {
    const PREFIX: &str = "/proxies/";
    const SUFFIX: &str = "/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=5000";
    path.strip_prefix(PREFIX)
        .and_then(|value| value.strip_suffix(SUFFIX))
        .is_some_and(|name| {
            !name.is_empty()
                && name.len() <= 96
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn decode_chunked(body: &str) -> Result<Zeroizing<String>, ()> {
    let mut remaining = body;
    let mut decoded = Zeroizing::new(String::new());
    loop {
        let line_end = remaining.find("\r\n").ok_or(())?;
        let size_text = remaining[..line_end].split(';').next().ok_or(())?;
        let size = usize::from_str_radix(size_text.trim(), 16).map_err(|_| ())?;
        remaining = &remaining[line_end + 2..];
        if size == 0 {
            return Ok(decoded);
        }
        if remaining.len() < size + 2 || &remaining[size..size + 2] != "\r\n" {
            return Err(());
        }
        decoded.push_str(&remaining[..size]);
        if decoded.len() as u64 > MAX_CONTROLLER_RESPONSE_BYTES {
            return Err(());
        }
        remaining = &remaining[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Read, net::TcpListener, sync::Mutex};

    use super::*;

    #[test]
    fn embedded_core_matches_the_pinned_mihomo_hash() {
        let digest = Sha256::digest(EMBEDDED_MIHOMO);
        let actual = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual, hk_proton_manager::PINNED_MIHOMO_SHA256);
    }

    #[test]
    fn probe_yaml_changes_only_local_listeners_and_disables_tun() {
        let source = SecretValue::new(
            "mixed-port: 27890\nexternal-controller: 127.0.0.1:29090\ntun:\n  enable: true\ndns:\n  enable: true\n  listen: 127.0.0.1:21053\nproxies: []\n",
        );
        let probe = build_probe_yaml(&source, [31_001, 31_002, 31_003]).unwrap();
        let yaml: serde_yaml_ng::Value = serde_yaml_ng::from_str(probe.expose_secret()).unwrap();
        assert_eq!(yaml["mixed-port"].as_u64(), Some(31_001));
        assert_eq!(
            yaml["external-controller"].as_str(),
            Some("127.0.0.1:31002")
        );
        assert_eq!(yaml["tun"]["enable"].as_bool(), Some(false));
        assert_eq!(yaml["dns"]["enable"].as_bool(), Some(true));
        assert_eq!(yaml["dns"]["listen"].as_str(), Some("127.0.0.1:31003"));
        assert_eq!(yaml["proxies"].as_sequence().map(Vec::len), Some(0));
    }

    #[test]
    fn delay_request_uses_only_the_fixed_loopback_contract() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let size = stream.read(&mut request).unwrap();
            let request = std::str::from_utf8(&request[..size]).unwrap();
            assert!(request.contains("GET /proxies/FH-node-1/delay?"));
            assert!(request.contains("Authorization: Bearer test-token"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\nConnection: close\r\n\r\n{\"delay\":42}",
                )
                .unwrap();
        });

        let delay = measure_proxy_delay(address, &SecretValue::new("test-token"), "FH-node-1");
        server.join().unwrap();
        assert_eq!(delay, Some(42));
        assert!(!is_safe_delay_path("/proxies/../../delay?url=bad"));
        assert_eq!(
            measure_proxy_delay(address, &SecretValue::new("test-token"), "../bad"),
            None
        );
    }

    #[test]
    fn warmed_delay_discards_the_first_handshake_sample() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for delay in [480, 72] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 2048];
                let _ = stream.read(&mut request).unwrap();
                let body = format!("{{\"delay\":{delay}}}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });

        let delay =
            measure_warmed_proxy_delay(address, &SecretValue::new("test-token"), "FH-node-1");
        server.join().unwrap();
        assert_eq!(delay, Some(72));
    }

    #[test]
    fn node_measurements_are_strictly_sequential() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let server_observed = Arc::clone(&observed);
        let server = thread::spawn(move || {
            for delay in [80, 60, 120, 90] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 2048];
                let size = stream.read(&mut request).unwrap();
                let request = std::str::from_utf8(&request[..size]).unwrap();
                let proxy_name = if request.contains("/proxies/FH-alpha/delay?") {
                    "FH-alpha"
                } else if request.contains("/proxies/FH-beta/delay?") {
                    "FH-beta"
                } else {
                    panic!("收到非预期测速目标")
                };
                server_observed.lock().unwrap().push(proxy_name.to_owned());
                let body = format!("{{\"delay\":{delay}}}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });

        let results = LiveRuntime::measure_from_controller(
            &[
                NodeDelayTarget {
                    profile_id: "alpha".to_owned(),
                    proxy_name: "FH-alpha".to_owned(),
                },
                NodeDelayTarget {
                    profile_id: "beta".to_owned(),
                    proxy_name: "FH-beta".to_owned(),
                },
            ],
            address,
            &SecretValue::new("test-token"),
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(results[0].delay_ms, Some(60));
        assert_eq!(results[1].delay_ms, Some(90));
        assert_eq!(
            *observed.lock().unwrap(),
            ["FH-alpha", "FH-alpha", "FH-beta", "FH-beta"]
        );
    }

    #[test]
    fn extracts_only_loopback_controller_credentials() {
        let yaml =
            SecretValue::new("external-controller: 127.0.0.1:19090\nsecret: controller-token\n");
        let (address, secret) = controller_credentials(&yaml).unwrap();
        assert!(address.ip().is_loopback());
        assert_eq!(secret.expose_secret(), "controller-token");
    }

    #[test]
    fn classifies_known_adapters_without_exposing_descriptions() {
        assert_eq!(
            classify_adapter(true, true, false, false, 0, "Ethernet", "Intel"),
            AdapterKind::Physical
        );
        assert_eq!(
            classify_adapter(false, false, false, false, 1, "Tailscale", "Tunnel"),
            AdapterKind::Tailscale
        );
        assert_eq!(
            classify_adapter(false, false, false, false, 1, "HK-Proton", "Wintun"),
            AdapterKind::OwnedHkProton
        );
        assert_eq!(
            classify_adapter(false, false, false, false, 1, "Mihomo", "Meta Tunnel"),
            AdapterKind::OtherVirtual
        );
        assert_eq!(
            classify_adapter(true, false, false, false, 0, "VPN", "Virtual"),
            AdapterKind::OtherVirtual
        );
    }

    #[test]
    fn tun_readiness_accepts_fragmented_complete_routes_but_rejects_partial_capture() {
        let route_address = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
            .map(|value| value.parse::<ipnet::IpNet>().unwrap());
        let partial = ["0.0.0.0/1", "::/1"].map(|value| value.parse::<ipnet::IpNet>().unwrap());
        assert!(!has_complete_public_capture(
            partial,
            &route_address,
            &[],
            true
        ));

        let missing_ipv6_half = ["0.0.0.0/1", "128.0.0.0/1", "::/1"]
            .map(|value| value.parse::<ipnet::IpNet>().unwrap());
        assert!(!has_complete_public_capture(
            missing_ipv6_half,
            &route_address,
            &[],
            true
        ));
        assert!(has_complete_public_capture(
            ["0.0.0.0/1", "128.0.0.0/1"].map(|value| value.parse::<ipnet::IpNet>().unwrap()),
            &route_address,
            &[],
            false
        ));

        let fragmented_complete = [
            "0.0.0.0/2",
            "64.0.0.0/2",
            "128.0.0.0/2",
            "192.0.0.0/2",
            "::/2",
            "4000::/2",
            "8000::/2",
            "c000::/2",
        ]
        .map(|value| value.parse::<ipnet::IpNet>().unwrap());
        assert!(has_complete_public_capture(
            fragmented_complete,
            &route_address,
            &[],
            true
        ));
    }

    #[test]
    fn tun_readiness_accounts_for_intentional_endpoint_exclusions() {
        let route_address =
            ["0.0.0.0/1", "128.0.0.0/1"].map(|value| value.parse::<ipnet::IpNet>().unwrap());
        let exclusions = ["64.0.0.0/2"].map(|value| value.parse::<ipnet::IpNet>().unwrap());
        let observed =
            ["0.0.0.0/2", "128.0.0.0/1"].map(|value| value.parse::<ipnet::IpNet>().unwrap());

        assert!(has_complete_public_capture(
            observed,
            &route_address,
            &exclusions,
            false
        ));
    }

    #[test]
    fn decodes_bounded_chunked_json() {
        let decoded = decode_chunked("7\r\n{\"a\":1}\r\n0\r\n\r\n").unwrap();
        assert_eq!(decoded.as_str(), "{\"a\":1}");
    }

    #[test]
    fn classifies_runtime_errors_without_retaining_log_payloads() {
        let flags = classify_runtime_diagnostics(
            br#"{"type":"error","payload":"[WG](redacted) handshake timed out"}"#,
        );
        assert_eq!(
            flags,
            BTreeSet::from(["handshake_error", "network_timeout", "wireguard_error"])
        );
    }

    #[test]
    fn accepts_only_the_observed_owned_tun_as_a_false_api_enable_fallback() {
        let expected = ExpectedRuntime {
            tun_enabled: true,
            mixed_port: 27_890,
            tun_device: HK_PROTON_TUN_DEVICE.to_owned(),
            required_proxies: BTreeSet::from(["HK-Proton-Outlet".to_owned()]),
            selectors: BTreeMap::from([(
                "HK-Proton-Outlet".to_owned(),
                "FirstHopSelector".to_owned(),
            )]),
        };
        let version = r#"{"meta":true,"version":"v1.19.28"}"#;
        let config = r#"{
            "allow-lan":false,"bind-address":"127.0.0.1","mode":"rule",
            "mixed-port":27890,"ipv6":true,
            "tun":{"enable":false,"device":"","auto-route":false,
            "strict-route":false,"dns-hijack":[]}
        }"#;
        let proxies = r#"{"proxies":{"HK-Proton-Outlet":{
            "type":"Selector","now":"FirstHopSelector","all":["FirstHopSelector"]
        }}}"#;

        assert_eq!(
            reconcile_owned_runtime_snapshot(version, config, proxies, &expected, false),
            Err(ApiContractViolation::TunDisabled)
        );
        assert!(
            reconcile_owned_runtime_snapshot(version, config, proxies, &expected, true).is_ok()
        );
    }

    #[test]
    fn required_port_signature_is_stable_and_keeps_owner_pid() {
        let required = [RequiredPort {
            protocol: PortProtocol::Tcp,
            address: "127.0.0.1".parse().unwrap(),
            port: 19090,
            allowed_owner_pid: None,
        }];
        let bindings = [
            PortBinding {
                protocol: PortProtocol::Tcp,
                address: "0.0.0.0".parse().unwrap(),
                port: 19090,
                owner_pid: 42,
            },
            PortBinding {
                protocol: PortProtocol::Udp,
                address: "127.0.0.1".parse().unwrap(),
                port: 19090,
                owner_pid: 99,
            },
        ];
        assert_eq!(
            required_port_signature(&required, &bindings),
            vec![(0, "0.0.0.0".parse().unwrap(), 19090, 42)]
        );

        let changed_owner = [PortBinding {
            owner_pid: 43,
            ..bindings[0].clone()
        }];
        assert_ne!(
            required_port_signature(&required, &bindings),
            required_port_signature(&required, &changed_owner)
        );
    }

    #[test]
    fn every_required_port_must_belong_only_to_the_started_core() {
        let required = [
            RequiredPort {
                protocol: PortProtocol::Tcp,
                address: "127.0.0.1".parse().unwrap(),
                port: 19090,
                allowed_owner_pid: None,
            },
            RequiredPort {
                protocol: PortProtocol::Udp,
                address: "127.0.0.1".parse().unwrap(),
                port: 1053,
                allowed_owner_pid: None,
            },
        ];
        let owned = vec![
            PortBinding {
                protocol: PortProtocol::Tcp,
                address: "127.0.0.1".parse().unwrap(),
                port: 19090,
                owner_pid: 42,
            },
            PortBinding {
                protocol: PortProtocol::Udp,
                address: "127.0.0.1".parse().unwrap(),
                port: 1053,
                owner_pid: 42,
            },
        ];
        assert!(required_ports_owned_by(&required, &owned, 42));

        let mut stolen = owned.clone();
        stolen.push(PortBinding {
            owner_pid: 7,
            ..owned[0].clone()
        });
        assert!(!required_ports_owned_by(&required, &stolen, 42));
        assert!(!required_ports_owned_by(&required, &owned[..1], 42));
    }
}
