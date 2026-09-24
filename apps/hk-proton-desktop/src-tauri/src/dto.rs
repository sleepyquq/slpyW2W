use hk_proton_core::OperatingMode;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UiMode {
    Double,
    Single,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UiProfileRole {
    FirstHop,
    Proton,
}

impl From<OperatingMode> for UiMode {
    fn from(value: OperatingMode) -> Self {
        match value {
            OperatingMode::DoubleHop => Self::Double,
            OperatingMode::SingleHop => Self::Single,
        }
    }
}

impl From<UiMode> for OperatingMode {
    fn from(value: UiMode) -> Self {
        match value {
            UiMode::Double => Self::DoubleHop,
            UiMode::Single => Self::SingleHop,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)] // live runtime 接入后会使用完整状态集合，先固定 IPC 枚举合同。
pub enum RuntimeStateDto {
    Unconfigured,
    Disconnected,
    Starting,
    ManualVerificationRequired,
    Connected,
    Blocked,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockerDto {
    NotConfigured,
    LivePreflightRequired,
    RuntimeUnavailable,
    StateUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSummaryDto {
    pub id: String,
    pub display_name: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStatusDto {
    pub configured: bool,
    pub revision: u64,
    pub mode: UiMode,
    pub first_hops: Vec<ProfileSummaryDto>,
    pub proton_nodes: Vec<ProfileSummaryDto>,
    pub selected_first_hop: Option<String>,
    pub selected_proton: Option<String>,
    pub runtime_state: RuntimeStateDto,
    pub can_connect: bool,
    pub blocker: Option<BlockerDto>,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberPackageImportDto {
    pub member_id: String,
    pub status: AppStatusDto,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeDelayDto {
    pub id: String,
    pub delay_ms: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeDelayReportDto {
    pub results: Vec<NodeDelayDto>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandErrorDto {
    pub code: &'static str,
    pub message: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_status_contract_is_camel_case_and_contains_no_sensitive_fields() {
        let status = AppStatusDto {
            configured: true,
            revision: 7,
            mode: UiMode::Double,
            first_hops: vec![ProfileSummaryDto {
                id: "first-hop-hk-vpn".to_owned(),
                display_name: "香港 WireGuard".to_owned(),
                enabled: true,
            }],
            proton_nodes: Vec::new(),
            selected_first_hop: Some("first-hop-hk-vpn".to_owned()),
            selected_proton: None,
            runtime_state: RuntimeStateDto::Disconnected,
            can_connect: false,
            blocker: Some(BlockerDto::LivePreflightRequired),
            message: "连接前检查尚未完成。".to_owned(),
        };

        let json = serde_json::to_value(status).expect("DTO 应可序列化");
        assert_eq!(json["selectedFirstHop"], "first-hop-hk-vpn");
        assert_eq!(json["runtimeState"], "disconnected");
        for forbidden in [
            "privateKey",
            "presharedKey",
            "endpoint",
            "runtimeYaml",
            "sourcePath",
            "statePath",
        ] {
            assert!(json.get(forbidden).is_none(), "DTO 禁止出现 {forbidden}");
        }
    }

    #[test]
    fn manual_verification_state_is_not_serialized_as_connected() {
        assert_eq!(
            serde_json::to_value(RuntimeStateDto::ManualVerificationRequired).unwrap(),
            "manual-verification-required"
        );
    }
}
