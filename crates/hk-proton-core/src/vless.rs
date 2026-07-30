use std::{collections::BTreeMap, net::IpAddr, str::FromStr};

use percent_encoding::percent_decode_str;
use serde_yaml_ng::Value;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{ConfigError, Endpoint, ImportWarning, Result, SecretValue, VlessConfig, VlessNetwork};

/// VLESS 配置没有携带 DNS 时使用的最小显式 IPv4 DNS，运行时仍会绑定到最终出口。
const DEFAULT_VLESS_DNS: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));

#[derive(Clone, Debug)]
pub struct ParsedVless {
    pub config: VlessConfig,
    pub source_sha256: String,
    pub display_name: Option<String>,
    pub warnings: Vec<ImportWarning>,
}

/// 仅根据安全的格式标记判断导入器是否应尝试 VLESS 解析。
pub fn looks_like_vless_source(source: &str) -> bool {
    let trimmed = source.trim_start_matches('\u{feff}').trim();
    if trimmed
        .split_whitespace()
        .next()
        .is_some_and(|item| item.to_ascii_lowercase().starts_with("vless://"))
    {
        return true;
    }
    trimmed.lines().any(|line| {
        let line = line.trim().to_ascii_lowercase();
        line == "type: vless" || line.starts_with("- type: vless")
    })
}

/// 解析 VLESS URI 或包含单个 VLESS 代理的 Mihomo YAML。
///
/// 解析只保留程序生成运行节点需要的字段，不执行网络请求，也不把 secret
/// 放入错误信息或警告文本。
pub fn parse_vless(source: &str) -> Result<ParsedVless> {
    let normalized = source.trim_start_matches('\u{feff}').trim();
    let digest = sha256_hex(source.as_bytes());
    if normalized
        .split_whitespace()
        .next()
        .is_some_and(|item| item.to_ascii_lowercase().starts_with("vless://"))
    {
        parse_vless_uri(normalized, digest)
    } else {
        parse_vless_yaml(normalized, digest)
    }
}

fn parse_vless_uri(source: &str, source_sha256: String) -> Result<ParsedVless> {
    let uri = Url::parse(
        source
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .ok_or(ConfigError::EmptyField { field: "VLESS URI" })?,
    )
    .map_err(|_| ConfigError::InvalidField { field: "VLESS URI" })?;
    if !uri.scheme().eq_ignore_ascii_case("vless") || uri.password().is_some() || uri.path() != "" {
        return Err(ConfigError::InvalidField { field: "VLESS URI" });
    }
    let host = uri.host_str().ok_or(ConfigError::MissingField {
        field: "VLESS server",
    })?;
    let port = uri.port().ok_or(ConfigError::MissingField {
        field: "VLESS port",
    })?;
    let endpoint = endpoint_from_host_port(host, port)?;
    let uuid = decode_component(uri.username(), "VLESS UUID")?;

    let mut values = BTreeMap::new();
    for (key, value) in uri.query_pairs() {
        let key = key.to_ascii_lowercase();
        let value = value.into_owned();
        if values.insert(key.clone(), value).is_some() {
            return Err(ConfigError::DuplicateField {
                field: "VLESS query",
            });
        }
    }

    let network = match values.get("type").map(String::as_str).unwrap_or("tcp") {
        "tcp" => VlessNetwork::Tcp,
        _ => {
            return Err(ConfigError::InvalidField {
                field: "VLESS network",
            });
        }
    };
    if values
        .get("headertype")
        .is_some_and(|value| !value.eq_ignore_ascii_case("none"))
    {
        return Err(ConfigError::InvalidField {
            field: "VLESS headerType",
        });
    }
    if values
        .get("encryption")
        .is_some_and(|value| !value.eq_ignore_ascii_case("none"))
    {
        return Err(ConfigError::InvalidField {
            field: "VLESS encryption",
        });
    }

    let security = values
        .get("security")
        .map(String::as_str)
        .unwrap_or("none")
        .to_ascii_lowercase();
    let tls = matches!(security.as_str(), "tls" | "reality");
    if !matches!(security.as_str(), "none" | "tls" | "reality") {
        return Err(ConfigError::InvalidField {
            field: "VLESS security",
        });
    }
    let reality_public_key = values.get("pbk").cloned();
    let reality_short_id = values.get("sid").cloned();
    if security == "reality" && (reality_public_key.is_none() || reality_short_id.is_none()) {
        return Err(ConfigError::InvalidField {
            field: "VLESS reality-opts",
        });
    }
    let skip_cert_verify = values
        .get("allowinsecure")
        .map(|value| parse_bool(value, "VLESS allowInsecure"))
        .transpose()?
        .unwrap_or(false);

    let config = VlessConfig::checked(
        endpoint,
        SecretValue::new(uuid),
        network,
        values
            .get("udp")
            .map(|value| parse_bool(value, "VLESS udp"))
            .transpose()?
            .unwrap_or(true),
        tls,
        first_value(&values, &["flow"]),
        first_value(&values, &["sni", "servername"]),
        first_value(&values, &["fp", "client-fingerprint"]),
        first_value(&values, &["packetencoding", "packet-encoding"]),
        reality_public_key,
        reality_short_id,
        skip_cert_verify,
        vec![DEFAULT_VLESS_DNS],
    )?;

    let display_name = uri
        .fragment()
        .map(|value| percent_decode_str(value).decode_utf8_lossy().into_owned())
        .filter(|value| !value.trim().is_empty());
    Ok(ParsedVless {
        config,
        source_sha256,
        display_name,
        warnings: Vec::new(),
    })
}

fn parse_vless_yaml(source: &str, source_sha256: String) -> Result<ParsedVless> {
    let document: Value = serde_yaml_ng::from_str(source).map_err(|_| ConfigError::YamlParse)?;
    let root = document.as_mapping().ok_or(ConfigError::InvalidField {
        field: "VLESS YAML",
    })?;
    let proxies = map_value(root, "proxies")
        .and_then(Value::as_sequence)
        .ok_or(ConfigError::MissingField {
            field: "VLESS proxies",
        })?;
    let mut candidates = proxies.iter().filter_map(Value::as_mapping).filter(|map| {
        map_string(map, "type").is_some_and(|value| value.eq_ignore_ascii_case("vless"))
    });
    let proxy = candidates.next().ok_or(ConfigError::MissingField {
        field: "VLESS proxy",
    })?;
    if candidates.next().is_some() {
        return Err(ConfigError::RuntimeValidation(
            "VLESS YAML 只能包含一个可导入的 VLESS 代理".to_owned(),
        ));
    }

    let server = map_string(proxy, "server").ok_or(ConfigError::MissingField {
        field: "VLESS server",
    })?;
    let port = map_u16(proxy, "port")?;
    let endpoint = endpoint_from_host_port(&server, port)?;
    let uuid = map_string(proxy, "uuid").ok_or(ConfigError::MissingField {
        field: "VLESS uuid",
    })?;
    if map_string(proxy, "encryption")
        .is_some_and(|value| !value.trim().is_empty() && !value.eq_ignore_ascii_case("none"))
    {
        return Err(ConfigError::InvalidField {
            field: "VLESS encryption",
        });
    }
    let network = match map_string(proxy, "network")
        .unwrap_or_else(|| "tcp".to_owned())
        .to_ascii_lowercase()
        .as_str()
    {
        "tcp" => VlessNetwork::Tcp,
        _ => {
            return Err(ConfigError::InvalidField {
                field: "VLESS network",
            });
        }
    };
    let tls = map_bool(proxy, "tls").unwrap_or(false);
    let reality = map_value(proxy, "reality-opts").and_then(Value::as_mapping);
    let reality_public_key = reality.and_then(|map| map_string(map, "public-key"));
    let reality_short_id = reality.and_then(|map| map_string(map, "short-id"));
    let dns_servers = map_value(root, "dns")
        .and_then(Value::as_mapping)
        .and_then(|dns| map_value(dns, "nameserver"))
        .and_then(Value::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(parse_dns_ip)
                .collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| vec![DEFAULT_VLESS_DNS]);

    let config = VlessConfig::checked(
        endpoint,
        SecretValue::new(uuid),
        network,
        map_bool(proxy, "udp").unwrap_or(true),
        tls,
        map_string(proxy, "flow"),
        map_string(proxy, "servername").or_else(|| map_string(proxy, "sni")),
        map_string(proxy, "client-fingerprint"),
        map_string(proxy, "packet-encoding"),
        reality_public_key,
        reality_short_id,
        map_bool(proxy, "skip-cert-verify").unwrap_or(false),
        dns_servers,
    )?;
    let display_name = map_string(proxy, "name");
    Ok(ParsedVless {
        config,
        source_sha256,
        display_name,
        warnings: Vec::new(),
    })
}

fn endpoint_from_host_port(host: &str, port: u16) -> Result<Endpoint> {
    if port == 0 {
        return Err(ConfigError::InvalidField {
            field: "VLESS port",
        });
    }
    let host = host.trim();
    let value = if host.parse::<IpAddr>().is_ok() && host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Endpoint::from_str(&value)
}

fn decode_component(value: &str, field: &'static str) -> Result<String> {
    let decoded = percent_decode_str(value)
        .decode_utf8()
        .map_err(|_| ConfigError::InvalidField { field })?;
    if decoded.is_empty() || decoded.chars().any(char::is_control) {
        return Err(ConfigError::InvalidField { field });
    }
    Ok(decoded.into_owned())
}

fn first_value(values: &BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| values.get(*key).cloned())
        .filter(|value| !value.trim().is_empty())
}

fn parse_bool(value: &str, field: &'static str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Err(ConfigError::InvalidField { field }),
    }
}

fn map_value<'a>(map: &'a serde_yaml_ng::Mapping, key: &str) -> Option<&'a Value> {
    map.get(Value::String(key.to_owned()))
}

fn map_string(map: &serde_yaml_ng::Mapping, key: &str) -> Option<String> {
    map_value(map, key)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn map_bool(map: &serde_yaml_ng::Mapping, key: &str) -> Option<bool> {
    map_value(map, key).and_then(Value::as_bool)
}

fn map_u16(map: &serde_yaml_ng::Mapping, key: &str) -> Result<u16> {
    map_value(map, key)
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or(ConfigError::InvalidField {
            field: "VLESS port",
        })
}

fn parse_dns_ip(value: &str) -> Option<IpAddr> {
    let value = value
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(value)
        .split('#')
        .next()
        .unwrap_or(value)
        .trim_matches(['[', ']']);
    let host = value
        .rsplit_once(':')
        .and_then(|(host, port)| port.parse::<u16>().ok().map(|_| host))
        .unwrap_or(value);
    host.parse::<IpAddr>().ok().filter(IpAddr::is_ipv4)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("写入 String 不会失败");
    }
    output
}
