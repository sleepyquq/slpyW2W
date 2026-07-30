use hk_proton_manager::ManagerError;
use thiserror::Error;

use crate::dto::CommandErrorDto;

pub type ServiceResult<T> = Result<T, ServiceError>;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("默认配置目录当前不可读取")]
    SourceUnavailable,
    #[error("配置目录包含不受信任的链接或越界项")]
    UnsafeSourceTree,
    #[error("配置目录超过安全扫描上限")]
    SourceLimitExceeded,
    #[error("缺少固定的第一跳配置")]
    MissingFirstHop,
    #[cfg(test)]
    #[error("固定第一跳配置的位置或数量无效")]
    InvalidFirstHopLayout,
    #[error("WireGuard 配置无效")]
    InvalidWireGuard,
    #[error("配置文件无效或包含不支持的代理类型")]
    InvalidConfiguration,
    #[error("当前选择无效")]
    InvalidSelection,
    #[error("尚未导入配置")]
    Unconfigured,
    #[error("请先断开当前连接")]
    RuntimeActive,
    #[error("节点测速当前不可用")]
    DelayUnavailable,
    #[error("至少需要保留一个第一跳配置")]
    LastFirstHop,
    #[error("本地加密状态不可用")]
    StateUnavailable,
    #[error("生成的运行配置未通过验证")]
    GeneratedProfileInvalid,
    #[error("应用内部状态暂时不可用")]
    Internal,
}

impl From<ManagerError> for ServiceError {
    fn from(_value: ManagerError) -> Self {
        // manager 的底层错误可能包含 schema 细节；IPC 只返回稳定、脱敏的类别。
        Self::StateUnavailable
    }
}

impl From<ServiceError> for CommandErrorDto {
    fn from(value: ServiceError) -> Self {
        match value {
            ServiceError::SourceUnavailable => Self {
                code: "source-unavailable",
                message: "默认配置目录当前不可读取。",
            },
            ServiceError::UnsafeSourceTree => Self {
                code: "unsafe-source-tree",
                message: "配置目录包含不受信任的链接，已停止导入。",
            },
            ServiceError::SourceLimitExceeded => Self {
                code: "source-limit-exceeded",
                message: "配置目录超过安全扫描上限，已停止导入。",
            },
            ServiceError::MissingFirstHop => Self {
                code: "missing-first-hop",
                message: "未找到固定的第一跳配置。",
            },
            #[cfg(test)]
            ServiceError::InvalidFirstHopLayout => Self {
                code: "invalid-first-hop-layout",
                message: "固定第一跳配置的位置或数量不正确。",
            },
            ServiceError::InvalidWireGuard => Self {
                code: "invalid-wireguard",
                message: "至少一个 WireGuard 配置无效，未保存任何更改。",
            },
            ServiceError::InvalidConfiguration => Self {
                code: "invalid-configuration",
                message: "至少一个配置文件无效或包含当前不支持的代理类型，未保存任何更改。",
            },
            ServiceError::InvalidSelection => Self {
                code: "invalid-selection",
                message: "所选线路不存在或当前不可用。",
            },
            ServiceError::Unconfigured => Self {
                code: "not-configured",
                message: "请先导入本机配置。",
            },
            ServiceError::RuntimeActive => Self {
                code: "runtime-active",
                message: "请先断开当前连接。",
            },
            ServiceError::DelayUnavailable => Self {
                code: "delay-unavailable",
                message: "节点测速失败，请稍后重试。",
            },
            ServiceError::LastFirstHop => Self {
                code: "last-first-hop",
                message: "请先导入另一个第一跳配置。",
            },
            ServiceError::StateUnavailable => Self {
                code: "state-unavailable",
                message: "本地加密状态当前不可用。",
            },
            ServiceError::GeneratedProfileInvalid => Self {
                code: "generated-profile-invalid",
                message: "生成的连接配置未通过验证，未保存更改。",
            },
            ServiceError::Internal => Self {
                code: "internal",
                message: "应用内部状态暂时不可用。",
            },
        }
    }
}
