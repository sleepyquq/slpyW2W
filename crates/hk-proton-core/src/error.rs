use thiserror::Error;

pub type Result<T> = std::result::Result<T, ConfigError>;

/// 面向 UI 的错误类型。
///
/// 错误文本不得包含配置原文或密钥值。调用者同样不应把输入文件内容附加到日志。
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigError {
    #[error("WireGuard 配置缺少 [{0}] 段")]
    MissingSection(&'static str),

    #[error("WireGuard 配置包含多个 [Peer]，当前版本只支持单 Peer 配置")]
    MultiplePeers,

    #[error("第 {line} 行不属于受支持的 WireGuard 段")]
    FieldOutsideSection { line: usize },

    #[error("第 {line} 行不是有效的 key=value 格式")]
    InvalidLine { line: usize },

    #[error("字段 {field} 重复出现")]
    DuplicateField { field: &'static str },

    #[error("缺少必填字段 {field}")]
    MissingField { field: &'static str },

    #[error("字段 {field} 的格式无效")]
    InvalidField { field: &'static str },

    #[error("字段 {field} 不允许为空")]
    EmptyField { field: &'static str },

    #[error("检测到 wg-quick 命令字段 {field}；slpyW2W 不执行导入配置中的命令")]
    UnsafeDirective { field: String },

    #[error("配置 ID 无效；只允许 ASCII 字母、数字、短横线和下划线")]
    InvalidProfileId,

    #[error("显示名称不能为空或超过 80 个字符")]
    InvalidDisplayName,

    #[error("至少需要一个已启用的第一跳")]
    NoEnabledFirstHop,

    #[error("当前选择的第一跳不存在或已禁用")]
    SelectedFirstHopUnavailable,

    #[error("双跳模式需要一个已启用的 Proton 节点")]
    NoEnabledProton,

    #[error("当前选择的 Proton 节点不存在或已禁用")]
    SelectedProtonUnavailable,

    #[error("普通 TUN 模式不能与 Tailscale Exit Node 同时启用")]
    TailscaleExitNodeConflict,

    #[error("第一跳 Endpoint 必须是 IP 地址；域名端点需要先由管理器安全解析并固定")]
    FirstHopEndpointNeedsResolution,

    #[error("Proton Endpoint 必须是 IP 地址；域名端点需要先设计无泄漏的启动解析路径")]
    ProtonEndpointNeedsResolution,

    #[error("WireGuard 简化语法最多支持一个 IPv4 和一个 IPv6 Interface Address")]
    TooManyInterfaceAddresses,

    #[error("所选出口配置没有可用的 IP DNS 服务器")]
    MissingEgressDns,

    #[error("端口配置无效或发生冲突")]
    InvalidRuntimePorts,

    #[error("Mihomo 配置序列化失败")]
    YamlSerialize,

    #[error("Mihomo 运行时配置无法解析")]
    YamlParse,

    #[error("Mihomo 运行时配置语义验证失败：{0}")]
    RuntimeValidation(String),
}
