//! slpyW2W 配置引擎。
//!
//! 这个 crate 不启动 Mihomo，也不修改系统路由。它只负责：
//! - 在内存中解析标准 WireGuard 配置；
//! - 建模第一跳与 Proton 节点；
//! - 生成独立的 Mihomo 运行时配置；
//! - 对最终渲染结果做引用与防泄漏语义检查。

mod error;
mod mihomo;
mod model;
mod secret;
mod validation;
mod wireguard;

pub use error::{ConfigError, Result};
pub use mihomo::{
    FIRST_HOP_SELECTOR, GeneratedProfile, HK_PROTON_DNS_PORT, OUTLET_SELECTOR, PROTON_SELECTOR,
    generate_profile,
};
pub use model::{
    Endpoint, EndpointHost, FirstHopProfile, HK_PROTON_TUN_DEVICE, ImportMetadata, LanPolicy,
    OperatingMode, ProbeResult, ProfileId, ProtonProfile, RuntimeOptions, RuntimeSelection,
    TailscalePolicy, WireGuardConfig, WireGuardInterface, WireGuardPeer,
};
pub use secret::SecretValue;
pub use validation::{ValidationReport, validate_rendered_profile};
pub use wireguard::{ImportWarning, ParsedWireGuard, parse_wireguard};
