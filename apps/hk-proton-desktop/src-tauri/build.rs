use std::{
    env, fs,
    path::{Path, PathBuf},
};

const PYXIS_MEMBERS: [&str; 5] = [
    "cheyuxuan",
    "yanggengbo",
    "zhenjiabao",
    "zuoanna",
    "zhouwantong",
];
const LEGACY_WIREGUARD_MEMBERS: [&str; 4] = ["cheyuxuan", "yanggengbo", "zhenjiabao", "zuoanna"];
const EXPECTED_PYXIS_PROFILE_COUNT: usize = 51;
const VLESS_SOURCE_RELATIVE_DIR: &str = "vless/HK-Xray-VLESS-10设备独立配置";

const PYXIS_VLESS_FILES: [(&str, &str); 5] = [
    ("zhenjiabao", "mihomo-device-01-zjb.yaml"),
    ("zhouwantong", "mihomo-device-02-zwt.yaml"),
    ("yanggengbo", "mihomo-device-03-ygb.yaml"),
    ("zuoanna", "mihomo-device-04-zan.yaml"),
    ("cheyuxuan", "mihomo-device-05.yaml"),
];

struct PyxisSource {
    member: String,
    role: &'static str,
    display_name: String,
    contents: Vec<u8>,
}

fn main() {
    println!("cargo:rerun-if-env-changed=SLPYW2W_PYXIS_CONFIG_ROOT");
    println!("cargo:rerun-if-env-changed=SLPYW2W_PYXIS_PACKAGE_STAGE");
    if env::var_os("CARGO_FEATURE_PYXIS").is_some() {
        match (
            env::var_os("SLPYW2W_PYXIS_CONFIG_ROOT"),
            env::var_os("SLPYW2W_PYXIS_PACKAGE_STAGE"),
        ) {
            (Some(source_root), Some(package_stage)) => {
                generate_pyxis_bundle(PathBuf::from(source_root), PathBuf::from(package_stage));
            }
            (None, None) => {}
            _ => panic!("pyxis 导入包生成需要同时提供配置来源与暂存目录"),
        }
    }

    if env::var("PROFILE").as_deref() != Ok("release") {
        tauri_build::build();
        return;
    }

    let windows = tauri_build::WindowsAttributes::new().app_manifest(
        r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#,
    );
    let attributes = tauri_build::Attributes::new().windows_attributes(windows);
    tauri_build::try_build(attributes).expect("生成 slpyW2W Tauri 构建资源失败");
}

/// pyxis 打包只在编译期读取指定的只读来源，输出每位成员独立的导入包。
/// 成员密钥不会编入定制客户端本身。
fn generate_pyxis_bundle(source_root: PathBuf, package_stage: PathBuf) {
    let source_root = source_root
        .canonicalize()
        .expect("无法定位 pyxis 配置来源目录");
    let root_metadata = fs::symlink_metadata(&source_root).expect("无法读取 pyxis 配置来源目录");
    assert!(
        root_metadata.is_dir() && !is_reparse(&root_metadata),
        "pyxis 配置来源目录不安全"
    );

    let mut profiles = Vec::new();
    for member in PYXIS_MEMBERS {
        let vless_file = source_root
            .join(VLESS_SOURCE_RELATIVE_DIR)
            .join(pyxis_vless_file_name(member));
        profiles.push(PyxisSource {
            member: member.to_owned(),
            role: "first-hop-and-relay",
            display_name: "香港".to_owned(),
            contents: read_safe_source(&source_root, &vless_file),
        });

        // 香港2 只作为可选的单跳直连节点；双跳转发固定使用上面的香港 VLESS。
        if LEGACY_WIREGUARD_MEMBERS.contains(&member) {
            let direct_hong_kong = source_root.join(format!("{member}.conf"));
            profiles.push(PyxisSource {
                member: member.to_owned(),
                role: "first-hop-direct-only",
                display_name: "香港2".to_owned(),
                contents: read_safe_source(&source_root, &direct_hong_kong),
            });
            println!("cargo:rerun-if-changed={}", direct_hong_kong.display());
        }

        let proton_file = source_root.join(format!("{member}.txt"));
        let proton_source = read_safe_source(&source_root, &proton_file);
        profiles.extend(parse_pyxis_proton_profiles(member, &proton_source));
        println!("cargo:rerun-if-changed={}", vless_file.display());
        println!("cargo:rerun-if-changed={}", proton_file.display());
    }
    assert_eq!(
        profiles.len(),
        EXPECTED_PYXIS_PROFILE_COUNT,
        "pyxis 团队构建必须恰好包含五十一份成员配置"
    );

    let stage_metadata = fs::symlink_metadata(&package_stage).expect("pyxis 导入包暂存目录不存在");
    assert!(
        stage_metadata.is_dir() && !is_reparse(&stage_metadata),
        "pyxis 导入包暂存目录不安全"
    );
    assert!(
        fs::read_dir(&package_stage)
            .expect("无法读取 pyxis 导入包暂存目录")
            .next()
            .is_none(),
        "pyxis 导入包暂存目录必须为空"
    );

    for member in PYXIS_MEMBERS {
        let section_profiles = |role: &str| {
            profiles
                .iter()
                .filter(|profile| profile.member == member && profile.role == role)
                .map(|profile| {
                    assert!(
                        !profile.contents.is_empty() && profile.contents.len() <= 256 * 1024,
                        "pyxis 配置大小无效"
                    );
                    let contents =
                        std::str::from_utf8(&profile.contents).expect("pyxis 配置不是 UTF-8");
                    serde_json::json!({
                        "displayName": &profile.display_name,
                        "contents": contents,
                    })
                })
                .collect::<Vec<_>>()
        };
        let first_hop_and_relay = section_profiles("first-hop-and-relay");
        let first_hop_direct_only = section_profiles("first-hop-direct-only");
        let second_hop = section_profiles("second-hop");
        let member_profile_count =
            first_hop_and_relay.len() + first_hop_direct_only.len() + second_hop.len();
        let expected_count = match member {
            "cheyuxuan" | "yanggengbo" | "zuoanna" => 8,
            "zhenjiabao" => 20,
            "zhouwantong" => 7,
            _ => unreachable!("Pyxis 成员表包含未配置成员"),
        };
        assert_eq!(
            member_profile_count, expected_count,
            "pyxis 成员配置数量不正确"
        );
        let package = serde_json::json!({
            "format": "hk-proton-member-package",
            "schemaVersion": 3,
            "packageVersion": env!("CARGO_PKG_VERSION"),
            "memberId": member,
            "sections": {
                "firstHopAndRelay": first_hop_and_relay,
                "firstHopDirectOnly": first_hop_direct_only,
                "secondHop": second_hop,
            },
        });
        let path = package_stage.join(format!("{member}.hkproton"));
        let bytes = serde_json::to_vec_pretty(&package).expect("无法序列化 pyxis 成员导入包");
        fs::write(path, bytes).expect("无法写入 pyxis 成员导入包");
    }
}

fn pyxis_vless_file_name(member: &str) -> &'static str {
    PYXIS_VLESS_FILES
        .iter()
        .find_map(|(known_member, file_name)| (*known_member == member).then_some(*file_name))
        .expect("pyxis 成员缺少 VLESS 配置映射")
}

fn read_safe_source(root: &Path, path: &Path) -> Vec<u8> {
    let metadata = fs::symlink_metadata(path).expect("无法读取 pyxis 配置元数据");
    assert!(
        metadata.is_file() && !is_reparse(&metadata),
        "pyxis 配置文件不安全"
    );
    assert!(metadata.len() <= 256 * 1024, "pyxis 配置文件过大");
    let canonical = path.canonicalize().expect("无法规范化 pyxis 配置文件");
    assert!(canonical.starts_with(root), "pyxis 配置文件越界");
    fs::read(canonical).expect("无法读取 pyxis 配置")
}

fn parse_pyxis_proton_profiles(member: &str, source: &[u8]) -> Vec<PyxisSource> {
    let source = std::str::from_utf8(source).expect("pyxis Proton 配置不是 UTF-8");
    let mut owner = member.to_owned();
    let mut profiles = Vec::new();
    let mut current = Vec::<String>::new();
    let mut current_node = None::<String>;

    let flush = |profiles: &mut Vec<PyxisSource>,
                 current: &mut Vec<String>,
                 current_node: &mut Option<String>,
                 owner: &str| {
        if current.is_empty() {
            return;
        }
        let node = current_node.take().expect("pyxis Proton 配置缺少节点注释");
        let display_name = pyxis_node_name(member, owner, &node);
        let mut contents = current.join("\n").into_bytes();
        contents.push(b'\n');
        profiles.push(PyxisSource {
            member: member.to_owned(),
            role: "second-hop",
            display_name,
            contents,
        });
        current.clear();
    };

    for raw_line in source.lines() {
        let line = raw_line.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed == "[Interface]" && !current.is_empty() {
            flush(&mut profiles, &mut current, &mut current_node, &owner);
        }
        if let Some(value) = trimmed.strip_prefix("# Key for ") {
            owner = value.trim().to_ascii_lowercase();
            assert!(
                PYXIS_MEMBERS.contains(&owner.as_str()),
                "pyxis 配置包含未知成员"
            );
        }
        if trimmed.starts_with("# TW#") || trimmed.starts_with("# SG#") {
            current_node = Some(trimmed.trim_start_matches('#').trim().to_owned());
        }
        // 文本中的横线只是人工分隔符，不属于 WireGuard 配置。
        if !trimmed.is_empty() && trimmed.chars().all(|value| value == '-') {
            continue;
        }
        current.push(line.to_owned());
    }
    flush(&mut profiles, &mut current, &mut current_node, &owner);

    let expected = if member == "zhenjiabao" { 18 } else { 6 };
    assert_eq!(
        profiles.len(),
        expected,
        "pyxis 成员的 Proton 配置数量不正确"
    );
    profiles
}

fn pyxis_node_name(member: &str, owner: &str, node: &str) -> String {
    let (region, number) = match node {
        "TW#32" => ("台湾", 1),
        "TW#31" => ("台湾", 2),
        "TW#30" => ("台湾", 3),
        "SG#246" => ("新加坡", 1),
        "SG#217" => ("新加坡", 2),
        "SG#213" => ("新加坡", 3),
        _ => panic!("pyxis 包含未知 Proton 节点"),
    };
    if member == "zhenjiabao" {
        let prefix = match owner {
            "cheyuxuan" => "C",
            "yanggengbo" => "Y",
            "zuoanna" => "Z",
            _ => panic!("zhenjiabao 的 Proton 配置来源无效"),
        };
        format!("{region}{prefix}{number}")
    } else {
        assert_eq!(member, owner, "成员 Proton 配置归属不一致");
        format!("{region}{number}")
    }
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}
