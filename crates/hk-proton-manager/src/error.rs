use thiserror::Error;

pub type Result<T> = std::result::Result<T, ManagerError>;

#[derive(Debug, Error)]
pub enum ManagerError {
    #[error("本地文件操作失败")]
    Io(#[from] std::io::Error),

    #[error("状态 JSON 编解码失败")]
    Json(#[from] serde_json::Error),

    #[error("状态 schema 或资源引用无效：{0}")]
    InvalidState(String),

    #[error("状态 revision 已变化；候选更新必须重新生成")]
    RevisionConflict,

    #[error("generation 不存在或不完整")]
    GenerationNotFound,

    #[error("generation 内容哈希验证失败")]
    GenerationCorrupt,

    #[error("状态签名或 Vault 完整性验证失败")]
    Integrity,

    #[error("secret 引用无效或缺失")]
    SecretUnavailable,

    #[error("secret 保护或解密失败")]
    SecretProtection,

    #[error("状态目录已被另一个 slpyW2W 进程锁定")]
    StoreLocked,

    #[error("私有状态路径包含重解析点或已越过可信目录")]
    UnsafePrivatePath,

    #[error("原子替换当前指针失败")]
    AtomicReplace,

    #[error("Mihomo 启动参数或候选文件无效")]
    InvalidLaunchSpec,

    #[error("Mihomo 候选配置哈希已变化")]
    CandidateChanged,

    #[error("Mihomo 子进程操作失败")]
    Process,

    #[error("Mihomo manager 状态迁移无效")]
    InvalidRuntimeTransition,

    #[error("当前构建禁止自动启动会改变网络的配置；需要显式用户授权流程")]
    NetworkActivationRequiresUser,

    #[error("Mihomo 实时启动预检存在阻断项")]
    LivePreflightRejected,

    #[error("Mihomo 实时启动授权与候选配置不匹配")]
    LiveAuthorizationMismatch,

    #[error("Mihomo 静态配置校验未通过")]
    MihomoConfigValidationFailed,

    #[error("Mihomo API 返回状态或结构与固定合同不一致")]
    ApiContract,
}
