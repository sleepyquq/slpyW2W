//! slpyW2W 管理层。
//!
//! 本 crate 负责配置引擎之外的本机状态：版本、加密 secret blob、
//! generation 提交/回滚，以及后续的 Mihomo 进程和 Windows 冲突管理。

mod api;
mod conflict;
#[cfg(windows)]
mod dpapi;
mod error;
mod process;
mod state;
mod store;
#[cfg(windows)]
mod windows_path;
#[cfg(windows)]
mod windows_process;
#[cfg(windows)]
pub mod windows_snapshot;

pub use api::{
    ApiContractViolation, ExpectedRuntime, PINNED_MIHOMO_VERSION, ProxySnapshot, ReconcileReport,
    RuntimeConfigSnapshot, VersionSnapshot, reconcile_api_snapshot_json,
    reconcile_api_snapshot_json_detailed, reconcile_api_snapshot_json_with_observed_tun,
};
pub use conflict::{
    AdapterKind, AdapterSnapshot, ConflictDecision, ConflictFinding, ConflictReason,
    ConflictReport, PortBinding, PortProtocol, PreflightSnapshot, RequiredPort, evaluate_conflicts,
};
#[cfg(windows)]
pub use dpapi::DpapiCurrentUserProtector;
pub use error::{ManagerError, Result};
pub use process::{
    AdministratorConfirmation, CoreExit, CoreLaunchSpec, CoreSupervisor,
    ExplicitProbeAuthorization, ExplicitTunAuthorization, LaunchBlockReason,
    LiveLaunchAuthorization, LivePreflightApproval, NetworkEffectProjection, OfflineLaunchPlan,
    PINNED_MIHOMO_SHA256, ProbeLaunchAuthorization, ProcessDriver, RuntimeState,
    TrustedMihomoExecutable, inspect_network_effects, redact_known_secrets,
};
pub use state::{
    AppState, EndpointRecord, GenerationCandidate, LanPolicyRecord, PendingSecret,
    ProfileResourceRecord, ProfileRole, ProfileVersionRecord, SecretPurpose, SecretRef,
    TailscalePolicyRecord,
};
pub use store::{CommitReceipt, GenerationManifest, SecretProtector, StateStore, StoredGeneration};
#[cfg(windows)]
pub use windows_path::WindowsPrivateDirectory;
#[cfg(windows)]
pub use windows_process::{
    WindowsMihomoDriver, validate_candidate_mihomo_config, validate_mihomo_config,
};
