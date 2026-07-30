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
const LEGACY_WIREGUARD_MEMBERS: [&str; 4] =
    ["cheyuxuan", "yanggengbo", "zhenjiabao", "zuoanna"];
const EXPECTED_PYXIS_PROFILE_COUNT: usize = 51;
const VLESS_SOURCE_RELATIVE_DIR: &str = "vless/HK-Xray-VLESS-10设备独立配置";

const PYXIS_VLESS_FILES: [(&str, &str); 5] = [
    ("zhenjiabao", "mihomo-device-01-zjb.yaml"),
    ("zhouwantong", "mihomo-device-02-zwt.yaml"),
    ("yanggengbo", "mihomo-device-03-ygb.yaml"),
    ("zuoanna", "mihomo-device-04-zan.yaml"),
    ("cheyuxuan", "mihomo-device-05-cyx.yaml"),
];

struct PyxisSource {
    member: String,
    role: &'static str,
    display_name: String,
    contents: Vec<u8>,
}

fn main() {
    println!("cargo:rerun-if-env-changed=SLPYW2W_PYXIS_CONFIG_ROOT");
    if env::var_os("CARGO_FEATURE_PYXIS").is_some() {
        generate_pyxis_bundle();
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

/// pyxis 构建只在编译期读取指定的只读来源，并把配置写入 Cargo OUT_DIR。
/// OUT_DIR 和最终 EXE 都不进入 Git；生成代码本身只记录内部文件路径和显示名。
fn generate_pyxis_bundle() {
    let source_root = env::var_os("SLPYW2W_PYXIS_CONFIG_ROOT")
        .map(PathBuf::from)
        .expect("pyxis 构建缺少 SLPYW2W_PYXIS_CONFIG_ROOT");
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
            role: "SourceRole::FirstHop",
            display_name: "香港".to_owned(),
            contents: read_safe_source(&source_root, &vless_file),
        });

        // 四位原成员的香港 WireGuard 保留为“香港2”直连节点；它不会被
        // 前端选作第二跳链路的第一跳，第二跳始终固定使用上面的 VLESS 香港。
        if LEGACY_WIREGUARD_MEMBERS.contains(&member) {
            let legacy_first_hop = source_root.join(format!("{member}.conf"));
            profiles.push(PyxisSource {
                member: member.to_owned(),
                role: "SourceRole::FirstHop",
                display_name: "香港2".to_owned(),
                contents: read_safe_source(&source_root, &legacy_first_hop),
            });
            println!("cargo:rerun-if-changed={}", legacy_first_hop.display());
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
        "pyxis 团队构建必须恰好包含四十份成员配置"
    );

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR 缺失"));
    let mut generated =
        String::from("const EMBEDDED_PYXIS_PROFILES: &[EmbeddedPyxisProfile] = &[\n");
    for (index, profile) in profiles.iter().enumerate() {
        let embedded_path = out_dir.join(format!("pyxis-profile-{index}.source"));
        assert!(
            !profile.contents.is_empty() && profile.contents.len() <= 256 * 1024,
            "pyxis 配置大小无效"
        );
        fs::write(&embedded_path, &profile.contents).expect("无法生成 pyxis 内置配置");
        generated.push_str(&format!(
            "    EmbeddedPyxisProfile {{ member: {member:?}, role: {role}, display_name: {display_name:?}, contents: include_bytes!({path:?}) }},\n",
            member = profile.member,
            role = profile.role,
            display_name = profile.display_name,
            path = embedded_path.to_string_lossy(),
        ));
    }
    generated.push_str("];\n");
    fs::write(out_dir.join("pyxis_profiles.rs"), generated).expect("无法生成 pyxis 配置索引");
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
            role: "SourceRole::Proton",
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
