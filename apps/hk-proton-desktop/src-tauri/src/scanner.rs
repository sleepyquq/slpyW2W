use std::{
    collections::BTreeSet,
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Take},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{ServiceError, ServiceResult};

#[cfg(test)]
pub const DEFAULT_CONFIG_ROOT: &str = r"E:\Aaaovo\Documents\tools\hk-proton";
#[cfg(test)]
pub const FIRST_HOP_FILE_NAME: &str = "hk-VPN-wireguard.conf";

#[cfg(test)]
const MAX_DIRECTORY_DEPTH: usize = 8;
#[cfg(test)]
const MAX_DIRECTORY_ENTRIES: usize = 2_048;
const MAX_CONFIG_FILES: usize = 128;
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_TOTAL_CONFIG_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceRole {
    FirstHop,
    Proton,
}

#[cfg(feature = "pyxis")]
struct EmbeddedPyxisProfile {
    role: SourceRole,
    display_name: &'static str,
    contents: &'static [u8],
}

#[cfg(feature = "pyxis")]
include!(concat!(env!("OUT_DIR"), "/pyxis_profiles.rs"));

pub struct ScannedSource {
    pub role: SourceRole,
    pub id: String,
    pub display_name: String,
    pub contents: Zeroizing<String>,
}

/// 读取编译进 pyxis EXE 的九份配置。这里只把静态字节复制进 Zeroizing 缓冲区，
/// 后续仍走与手动导入相同的严格解析、候选验证和原子提交链路。
#[cfg(feature = "pyxis")]
pub fn scan_embedded_pyxis_profiles() -> ServiceResult<Vec<ScannedSource>> {
    if EMBEDDED_PYXIS_PROFILES.len() != 9 {
        return Err(ServiceError::SourceLimitExceeded);
    }
    let mut first_hop_count = 0_usize;
    let mut ids = BTreeSet::new();
    let mut scanned = Vec::with_capacity(EMBEDDED_PYXIS_PROFILES.len());
    for profile in EMBEDDED_PYXIS_PROFILES {
        let source =
            std::str::from_utf8(profile.contents).map_err(|_| ServiceError::InvalidWireGuard)?;
        let mut hasher = Sha256::new();
        hasher.update(b"slpyW2W-pyxis\0embedded-profile-v1\0");
        hasher.update(match profile.role {
            SourceRole::FirstHop => {
                first_hop_count += 1;
                b"first-hop\0".as_slice()
            }
            SourceRole::Proton => b"proton\0".as_slice(),
        });
        hasher.update(profile.contents);
        let digest = hasher.finalize();
        let suffix = digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let id = match profile.role {
            SourceRole::FirstHop => format!("first-hop-{suffix}"),
            SourceRole::Proton => format!("proton-{suffix}"),
        };
        if !ids.insert(id.clone()) {
            return Err(ServiceError::InvalidWireGuard);
        }
        scanned.push(ScannedSource {
            role: profile.role,
            id,
            display_name: profile.display_name.to_owned(),
            contents: Zeroizing::new(source.to_owned()),
        });
    }
    if first_hop_count != 1 {
        return Err(ServiceError::MissingFirstHop);
    }
    Ok(scanned)
}

/// 读取用户在原生文件选择器中明确选中的配置文件。
/// 不依赖固定目录，也不会把来源路径写入状态或 IPC。
pub fn scan_selected_files(
    role: SourceRole,
    paths: &[PathBuf],
) -> ServiceResult<Vec<ScannedSource>> {
    if paths.is_empty() || paths.len() > MAX_CONFIG_FILES {
        return Err(ServiceError::SourceLimitExceeded);
    }

    let mut total_bytes = 0_u64;
    let mut ids = BTreeSet::new();
    let mut scanned = Vec::with_capacity(paths.len());
    for path in paths {
        let metadata = fs::symlink_metadata(path).map_err(|_| ServiceError::SourceUnavailable)?;
        if !metadata.is_file() || is_link_or_reparse(&metadata) {
            return Err(ServiceError::UnsafeSourceTree);
        }
        if !path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("conf"))
        {
            return Err(ServiceError::InvalidWireGuard);
        }
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(ServiceError::SourceLimitExceeded);
        }
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or(ServiceError::SourceLimitExceeded)?;
        if total_bytes > MAX_TOTAL_CONFIG_BYTES {
            return Err(ServiceError::SourceLimitExceeded);
        }

        let contents = read_bounded_config(path)?;
        let mut hasher = Sha256::new();
        hasher.update(b"HK-Proton\0selected-file-v1\0");
        hasher.update(match role {
            SourceRole::FirstHop => b"first-hop\0".as_slice(),
            SourceRole::Proton => b"proton\0".as_slice(),
        });
        hasher.update(contents.as_bytes());
        let digest = hasher.finalize();
        let suffix = digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let id = match role {
            SourceRole::FirstHop => format!("first-hop-{suffix}"),
            SourceRole::Proton => format!("proton-{suffix}"),
        };
        if !ids.insert(id.clone()) {
            continue;
        }

        let display_name = path
            .file_stem()
            .and_then(|value| value.to_str())
            .map(str::trim)
            .filter(|value| {
                !value.is_empty()
                    && value.chars().count() <= 80
                    && !value.chars().any(char::is_control)
            })
            .ok_or(ServiceError::UnsafeSourceTree)?;
        scanned.push(ScannedSource {
            role,
            id,
            display_name: display_name.to_owned(),
            contents,
        });
    }
    Ok(scanned)
}

#[cfg(test)]
pub fn scan_config_tree(root: &Path) -> ServiceResult<Vec<ScannedSource>> {
    let root_metadata = fs::symlink_metadata(root).map_err(|_| ServiceError::SourceUnavailable)?;
    if !root_metadata.is_dir() || is_link_or_reparse(&root_metadata) {
        return Err(ServiceError::UnsafeSourceTree);
    }
    let canonical_root = fs::canonicalize(root).map_err(|_| ServiceError::SourceUnavailable)?;

    let mut stack = vec![(root.to_path_buf(), 0_usize)];
    let mut candidates = Vec::<(PathBuf, SourceRole)>::new();
    let mut entry_count = 0_usize;

    while let Some((directory, depth)) = stack.pop() {
        let canonical_directory =
            fs::canonicalize(&directory).map_err(|_| ServiceError::SourceUnavailable)?;
        if !canonical_directory.starts_with(&canonical_root) {
            return Err(ServiceError::UnsafeSourceTree);
        }

        let entries = fs::read_dir(&directory).map_err(|_| ServiceError::SourceUnavailable)?;
        for entry in entries {
            let entry = entry.map_err(|_| ServiceError::SourceUnavailable)?;
            entry_count = entry_count
                .checked_add(1)
                .ok_or(ServiceError::SourceLimitExceeded)?;
            if entry_count > MAX_DIRECTORY_ENTRIES {
                return Err(ServiceError::SourceLimitExceeded);
            }

            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| ServiceError::SourceUnavailable)?;
            if is_link_or_reparse(&metadata) {
                return Err(ServiceError::UnsafeSourceTree);
            }

            if metadata.is_dir() {
                if depth >= MAX_DIRECTORY_DEPTH {
                    return Err(ServiceError::SourceLimitExceeded);
                }
                stack.push((path, depth + 1));
                continue;
            }
            if !metadata.is_file() {
                return Err(ServiceError::UnsafeSourceTree);
            }

            let relative = path
                .strip_prefix(root)
                .map_err(|_| ServiceError::UnsafeSourceTree)?;
            if let Some(role) = classify_relative_path(relative)? {
                let canonical_file =
                    fs::canonicalize(&path).map_err(|_| ServiceError::SourceUnavailable)?;
                if !canonical_file.starts_with(&canonical_root) {
                    return Err(ServiceError::UnsafeSourceTree);
                }
                candidates.push((relative.to_path_buf(), role));
                if candidates.len() > MAX_CONFIG_FILES {
                    return Err(ServiceError::SourceLimitExceeded);
                }
            }
        }
    }

    candidates.sort_by_key(|item| normalized_relative(&item.0));
    let first_hop_count = candidates
        .iter()
        .filter(|(_, role)| *role == SourceRole::FirstHop)
        .count();
    match first_hop_count {
        0 => return Err(ServiceError::MissingFirstHop),
        1 => {}
        _ => return Err(ServiceError::InvalidFirstHopLayout),
    }

    let mut total_bytes = 0_u64;
    let mut ids = BTreeSet::new();
    let mut scanned = Vec::with_capacity(candidates.len());
    for (relative, role) in candidates {
        let path = root.join(&relative);
        let metadata = fs::symlink_metadata(&path).map_err(|_| ServiceError::SourceUnavailable)?;
        if !metadata.is_file() || is_link_or_reparse(&metadata) || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(if metadata.len() > MAX_CONFIG_BYTES {
                ServiceError::SourceLimitExceeded
            } else {
                ServiceError::UnsafeSourceTree
            });
        }
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or(ServiceError::SourceLimitExceeded)?;
        if total_bytes > MAX_TOTAL_CONFIG_BYTES {
            return Err(ServiceError::SourceLimitExceeded);
        }

        let id = stable_profile_id(role, &relative);
        if !ids.insert(id.clone()) {
            return Err(ServiceError::UnsafeSourceTree);
        }
        scanned.push(ScannedSource {
            role,
            id,
            display_name: display_name(role, &relative)?,
            contents: read_bounded_config(&path)?,
        });
    }
    Ok(scanned)
}

#[cfg(test)]
pub fn classify_relative_path(relative: &Path) -> ServiceResult<Option<SourceRole>> {
    let Some(extension) = relative.extension().and_then(|value| value.to_str()) else {
        return Ok(None);
    };
    if !extension.eq_ignore_ascii_case("conf") {
        return Ok(None);
    }
    let file_name = relative
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(ServiceError::UnsafeSourceTree)?;
    if file_name.eq_ignore_ascii_case(FIRST_HOP_FILE_NAME) {
        // 固定文件可能位于安全根目录内的归档子目录；全树唯一性由扫描结束时统一校验。
        Ok(Some(SourceRole::FirstHop))
    } else {
        Ok(Some(SourceRole::Proton))
    }
}

#[cfg(test)]
fn display_name(role: SourceRole, relative: &Path) -> ServiceResult<String> {
    if role == SourceRole::FirstHop {
        return Ok("香港 WireGuard".to_owned());
    }
    let value = relative
        .file_stem()
        .and_then(|value| value.to_str())
        .map(str::trim)
        .ok_or(ServiceError::UnsafeSourceTree)?;
    if value.is_empty() || value.chars().count() > 80 || value.chars().any(char::is_control) {
        return Err(ServiceError::UnsafeSourceTree);
    }
    const LEGACY_PREFIX: &str = "hk-proton-mihomo-";
    if value
        .get(..LEGACY_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(LEGACY_PREFIX))
    {
        let suffix = value[LEGACY_PREFIX.len()..].trim();
        if !suffix.is_empty() {
            return Ok(format!("Proton {suffix}"));
        }
    }
    Ok(value.to_owned())
}

#[cfg(test)]
fn stable_profile_id(role: SourceRole, relative: &Path) -> String {
    if role == SourceRole::FirstHop {
        return "first-hop-hk-vpn".to_owned();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"HK-Proton\0source-path-v1\0proton\0");
    hasher.update(normalized_relative(relative).as_bytes());
    let digest = hasher.finalize();
    let suffix = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("proton-{suffix}")
}

#[cfg(test)]
fn normalized_relative(relative: &Path) -> String {
    relative
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase()
}

fn read_bounded_config(path: &Path) -> ServiceResult<Zeroizing<String>> {
    let file = open_without_following_reparse(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| ServiceError::SourceUnavailable)?;
    if !metadata.is_file() || is_link_or_reparse(&metadata) {
        return Err(ServiceError::UnsafeSourceTree);
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(ServiceError::SourceLimitExceeded);
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    bounded_reader(file)
        .read_to_end(&mut bytes)
        .map_err(|_| ServiceError::SourceUnavailable)?;
    let bytes = Zeroizing::new(bytes);
    if bytes.len() > MAX_CONFIG_BYTES as usize {
        return Err(ServiceError::SourceLimitExceeded);
    }
    let source =
        std::str::from_utf8(bytes.as_slice()).map_err(|_| ServiceError::InvalidWireGuard)?;
    Ok(Zeroizing::new(source.to_owned()))
}

fn bounded_reader(file: File) -> Take<File> {
    file.take(MAX_CONFIG_BYTES + 1)
}

fn open_without_following_reparse(path: &Path) -> ServiceResult<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        // FILE_FLAG_OPEN_REPARSE_POINT：即使检查与打开之间发生替换，也不跟随新链接。
        options.custom_flags(0x0020_0000);
    }
    options
        .open(path)
        .map_err(|_| ServiceError::SourceUnavailable)
}

fn is_link_or_reparse(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        // FILE_ATTRIBUTE_REPARSE_POINT，包括 junction、mount point 与其他重解析对象。
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    const SYNTHETIC_CONFIG: &str = include_str!(
        "../../../../crates/hk-proton-core/tests/fixtures/first-hop-hk.synthetic.conf"
    );

    #[test]
    fn classifies_unique_fixed_name_at_any_safe_depth_as_first_hop() {
        assert_eq!(
            classify_relative_path(Path::new("hk-VPN-wireguard.conf")).unwrap(),
            Some(SourceRole::FirstHop)
        );
        assert_eq!(
            classify_relative_path(Path::new("PROTON-JP.CONF")).unwrap(),
            Some(SourceRole::Proton)
        );
        assert_eq!(
            classify_relative_path(Path::new("notes.txt")).unwrap(),
            None
        );
        assert_eq!(
            classify_relative_path(Path::new("01-原始配置/hk-VPN-wireguard.conf")).unwrap(),
            Some(SourceRole::FirstHop)
        );
    }

    #[test]
    fn proton_id_is_stable_and_does_not_contain_a_path() {
        let relative = Path::new("nodes/Proton-JP.conf");
        let first = stable_profile_id(SourceRole::Proton, relative);
        let second = stable_profile_id(SourceRole::Proton, relative);
        assert_eq!(first, second);
        assert!(first.starts_with("proton-"));
        assert!(!first.contains("nodes"));
        assert!(!first.contains("Proton"));
    }

    #[test]
    fn selected_file_import_is_role_explicit_and_path_independent() {
        let directory = TempDir::new().unwrap();
        let first = directory.path().join("香港.conf");
        let second = directory.path().join("重命名.conf");
        fs::write(&first, SYNTHETIC_CONFIG).unwrap();
        fs::write(&second, SYNTHETIC_CONFIG).unwrap();

        let one = scan_selected_files(SourceRole::FirstHop, &[first]).unwrap();
        let two = scan_selected_files(SourceRole::FirstHop, &[second]).unwrap();
        assert_eq!(one[0].id, two[0].id);
        assert!(one[0].id.starts_with("first-hop-"));
        assert_eq!(one[0].display_name, "香港");
    }
}
