use std::fmt;

use serde::{Serialize, Serializer};
use zeroize::Zeroizing;

/// 会在释放时清零、且 `Debug`/`Display` 永远脱敏的字符串。
///
/// 它可以序列化，是因为 Mihomo 运行时 YAML 必须包含 WireGuard 密钥或 VLESS UUID；
/// 调用者必须把生成文件放在受 ACL 保护的临时/运行目录中。
#[derive(Clone)]
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Serialize for SecretValue {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.expose_secret())
    }
}
