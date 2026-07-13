use std::{net::IpAddr, str::FromStr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ipnet::IpNet;
use sha2::{Digest, Sha256};

use crate::{
    ConfigError, Endpoint, Result, SecretValue, WireGuardConfig, WireGuardInterface, WireGuardPeer,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportWarning {
    /// 已知但无需映射到 Mihomo 的字段，例如 ListenPort。
    IgnoredField { section: &'static str, line: usize },
    /// 未识别字段。只记录位置，不回显字段名或值。
    UnsupportedField { section: &'static str, line: usize },
}

#[derive(Clone, Debug)]
pub struct ParsedWireGuard {
    pub config: WireGuardConfig,
    pub source_sha256: String,
    pub warnings: Vec<ImportWarning>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Section {
    Interface,
    Peer,
}

#[derive(Default)]
struct RawInterface {
    private_key: Option<SecretValue>,
    addresses: Vec<String>,
    dns: Vec<String>,
    mtu: Option<String>,
}

#[derive(Default)]
struct RawPeer {
    public_key: Option<String>,
    preshared_key: Option<SecretValue>,
    endpoint: Option<String>,
    allowed_ips: Vec<String>,
    persistent_keepalive: Option<String>,
}

/// 解析单 Peer 的标准 WireGuard `.conf`。
///
/// 此函数不会执行 wg-quick 命令，也不会把任何字段值写入错误文本。
pub fn parse_wireguard(source: &str) -> Result<ParsedWireGuard> {
    let mut section = None;
    let mut saw_interface = false;
    let mut saw_peer = false;
    let mut interface = RawInterface::default();
    let mut peer = RawPeer::default();
    let mut warnings = Vec::new();

    for (index, original_line) in source.trim_start_matches('\u{feff}').lines().enumerate() {
        let line_number = index + 1;
        let line = strip_inline_comment(original_line).trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let name = line[1..line.len() - 1].trim();
            if name.eq_ignore_ascii_case("Interface") {
                if saw_interface {
                    return Err(ConfigError::DuplicateField {
                        field: "[Interface]",
                    });
                }
                saw_interface = true;
                section = Some(Section::Interface);
            } else if name.eq_ignore_ascii_case("Peer") {
                if saw_peer {
                    return Err(ConfigError::MultiplePeers);
                }
                saw_peer = true;
                section = Some(Section::Peer);
            } else {
                return Err(ConfigError::InvalidLine { line: line_number });
            }
            continue;
        }

        let active_section =
            section.ok_or(ConfigError::FieldOutsideSection { line: line_number })?;
        let (key, value) = line
            .split_once('=')
            .ok_or(ConfigError::InvalidLine { line: line_number })?;
        let key = key.trim();
        let value = value.trim();
        if value.is_empty() {
            return Err(ConfigError::InvalidLine { line: line_number });
        }

        let normalized_key = key.to_ascii_lowercase();
        if matches!(
            normalized_key.as_str(),
            "preup" | "postup" | "predown" | "postdown" | "saveconfig" | "table"
        ) {
            return Err(ConfigError::UnsafeDirective {
                field: canonical_directive(&normalized_key).to_owned(),
            });
        }

        match active_section {
            Section::Interface => parse_interface_field(
                &normalized_key,
                value,
                line_number,
                &mut interface,
                &mut warnings,
            )?,
            Section::Peer => parse_peer_field(
                &normalized_key,
                value,
                line_number,
                &mut peer,
                &mut warnings,
            )?,
        }
    }

    if !saw_interface {
        return Err(ConfigError::MissingSection("Interface"));
    }
    if !saw_peer {
        return Err(ConfigError::MissingSection("Peer"));
    }

    let private_key = interface.private_key.ok_or(ConfigError::MissingField {
        field: "PrivateKey",
    })?;
    validate_key(private_key.expose_secret(), "PrivateKey")?;

    let addresses = parse_ip_nets(&interface.addresses, "Address")?;
    if addresses.is_empty() {
        return Err(ConfigError::MissingField { field: "Address" });
    }

    let dns_servers = parse_ip_addresses(&interface.dns, "DNS")?;
    if dns_servers.is_empty() {
        return Err(ConfigError::MissingField { field: "DNS" });
    }

    let mtu = interface
        .mtu
        .map(|value| parse_u16(&value, "MTU", false))
        .transpose()?;

    let public_key = peer
        .public_key
        .ok_or(ConfigError::MissingField { field: "PublicKey" })?;
    validate_key(&public_key, "PublicKey")?;

    if let Some(key) = &peer.preshared_key {
        validate_key(key.expose_secret(), "PresharedKey")?;
    }

    let endpoint = Endpoint::from_str(
        peer.endpoint
            .as_deref()
            .ok_or(ConfigError::MissingField { field: "Endpoint" })?,
    )?;

    let allowed_ips = parse_ip_nets(&peer.allowed_ips, "AllowedIPs")?;
    if allowed_ips.is_empty() {
        return Err(ConfigError::MissingField {
            field: "AllowedIPs",
        });
    }

    let persistent_keepalive = peer
        .persistent_keepalive
        .map(|value| parse_u16(&value, "PersistentKeepalive", true))
        .transpose()?;

    let source_sha256 = hex_sha256(source.as_bytes());
    Ok(ParsedWireGuard {
        config: WireGuardConfig {
            interface: WireGuardInterface {
                private_key,
                addresses,
                dns_servers,
                mtu,
            },
            peer: WireGuardPeer {
                public_key,
                preshared_key: peer.preshared_key,
                endpoint,
                allowed_ips,
                persistent_keepalive,
            },
        },
        source_sha256,
        warnings,
    })
}

fn parse_interface_field(
    key: &str,
    value: &str,
    line: usize,
    raw: &mut RawInterface,
    warnings: &mut Vec<ImportWarning>,
) -> Result<()> {
    match key {
        "privatekey" => set_once_secret(&mut raw.private_key, value, "PrivateKey"),
        "address" => {
            extend_list(&mut raw.addresses, value);
            Ok(())
        }
        "dns" => {
            extend_list(&mut raw.dns, value);
            Ok(())
        }
        "mtu" => set_once(&mut raw.mtu, value, "MTU"),
        "listenport" => {
            warnings.push(ImportWarning::IgnoredField {
                section: "Interface",
                line,
            });
            Ok(())
        }
        _ => {
            warnings.push(ImportWarning::UnsupportedField {
                section: "Interface",
                line,
            });
            Ok(())
        }
    }
}

fn parse_peer_field(
    key: &str,
    value: &str,
    line: usize,
    raw: &mut RawPeer,
    warnings: &mut Vec<ImportWarning>,
) -> Result<()> {
    match key {
        "publickey" => set_once(&mut raw.public_key, value, "PublicKey"),
        "presharedkey" => set_once_secret(&mut raw.preshared_key, value, "PresharedKey"),
        "endpoint" => set_once(&mut raw.endpoint, value, "Endpoint"),
        "allowedips" => {
            extend_list(&mut raw.allowed_ips, value);
            Ok(())
        }
        "persistentkeepalive" => {
            set_once(&mut raw.persistent_keepalive, value, "PersistentKeepalive")
        }
        _ => {
            warnings.push(ImportWarning::UnsupportedField {
                section: "Peer",
                line,
            });
            Ok(())
        }
    }
}

fn set_once(target: &mut Option<String>, value: &str, field: &'static str) -> Result<()> {
    if target.is_some() {
        return Err(ConfigError::DuplicateField { field });
    }
    *target = Some(value.trim().to_owned());
    Ok(())
}

fn set_once_secret(
    target: &mut Option<SecretValue>,
    value: &str,
    field: &'static str,
) -> Result<()> {
    if target.is_some() {
        return Err(ConfigError::DuplicateField { field });
    }
    *target = Some(SecretValue::new(value.trim()));
    Ok(())
}

fn extend_list(target: &mut Vec<String>, value: &str) {
    target.extend(
        value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_owned),
    );
}

fn parse_ip_nets(values: &[String], field: &'static str) -> Result<Vec<IpNet>> {
    values
        .iter()
        .map(|value| {
            value
                .parse::<IpNet>()
                .map_err(|_| ConfigError::InvalidField { field })
        })
        .collect()
}

fn parse_ip_addresses(values: &[String], field: &'static str) -> Result<Vec<IpAddr>> {
    values
        .iter()
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|_| ConfigError::InvalidField { field })
        })
        .collect()
}

fn parse_u16(value: &str, field: &'static str, allow_zero: bool) -> Result<u16> {
    value
        .parse::<u16>()
        .ok()
        .filter(|number| allow_zero || *number > 0)
        .ok_or(ConfigError::InvalidField { field })
}

fn validate_key(value: &str, field: &'static str) -> Result<()> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| ConfigError::InvalidField { field })?;
    if decoded.len() != 32 || decoded.iter().all(|byte| *byte == 0) {
        return Err(ConfigError::InvalidField { field });
    }
    Ok(())
}

fn strip_inline_comment(line: &str) -> &str {
    for (index, character) in line.char_indices() {
        if matches!(character, '#' | ';')
            && (index == 0
                || line[..index]
                    .chars()
                    .next_back()
                    .is_some_and(char::is_whitespace))
        {
            return &line[..index];
        }
    }
    line
}

fn canonical_directive(normalized: &str) -> &'static str {
    match normalized {
        "preup" => "PreUp",
        "postup" => "PostUp",
        "predown" => "PreDown",
        "postdown" => "PostDown",
        "saveconfig" => "SaveConfig",
        "table" => "Table",
        _ => "wg-quick directive",
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("写入 String 不会失败");
    }
    output
}
