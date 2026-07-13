use std::{
    env, fs,
    path::{Path, PathBuf},
};

const FIRST_HOP_FILE_NAME: &str = "hk-VPN-wireguard.conf";
const EXPECTED_PYXIS_PROFILE_COUNT: usize = 9;

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

    let mut files = Vec::new();
    collect_conf_files(&source_root, &source_root, &mut files);
    files.sort_by_key(|path| {
        path.strip_prefix(&source_root)
            .expect("pyxis 配置路径越界")
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase()
    });
    assert_eq!(
        files.len(),
        EXPECTED_PYXIS_PROFILE_COUNT,
        "pyxis 构建必须恰好包含九份 WireGuard 配置"
    );

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR 缺失"));
    let mut generated =
        String::from("const EMBEDDED_PYXIS_PROFILES: &[EmbeddedPyxisProfile] = &[\n");
    let mut first_hop_count = 0_usize;
    for (index, source) in files.iter().enumerate() {
        let metadata = fs::symlink_metadata(source).expect("无法读取 pyxis 配置元数据");
        assert!(
            metadata.is_file() && !is_reparse(&metadata),
            "pyxis 配置文件不安全"
        );
        let file_name = source
            .file_name()
            .and_then(|value| value.to_str())
            .expect("pyxis 配置文件名不是 UTF-8");
        let is_first_hop = file_name.eq_ignore_ascii_case(FIRST_HOP_FILE_NAME);
        if is_first_hop {
            first_hop_count += 1;
        }
        let display_name = pyxis_display_name(source, is_first_hop);
        let embedded_path = out_dir.join(format!("pyxis-profile-{index}.conf"));
        let contents = fs::read(source).expect("无法读取 pyxis 配置");
        assert!(
            !contents.is_empty() && contents.len() <= 256 * 1024,
            "pyxis 配置大小无效"
        );
        fs::write(&embedded_path, contents).expect("无法生成 pyxis 内置配置");
        println!("cargo:rerun-if-changed={}", source.display());

        let role = if is_first_hop {
            "SourceRole::FirstHop"
        } else {
            "SourceRole::Proton"
        };
        generated.push_str(&format!(
            "    EmbeddedPyxisProfile {{ role: {role}, display_name: {display_name:?}, contents: include_bytes!({path:?}) }},\n",
            path = embedded_path.to_string_lossy(),
        ));
    }
    assert_eq!(first_hop_count, 1, "pyxis 构建必须恰好包含一份转发节点配置");
    generated.push_str("];\n");
    fs::write(out_dir.join("pyxis_profiles.rs"), generated).expect("无法生成 pyxis 配置索引");
}

fn collect_conf_files(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) {
    let canonical_directory = directory.canonicalize().expect("无法规范化 pyxis 配置目录");
    assert!(canonical_directory.starts_with(root), "pyxis 配置目录越界");
    for entry in fs::read_dir(directory).expect("无法枚举 pyxis 配置目录") {
        let entry = entry.expect("无法读取 pyxis 配置目录项");
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).expect("无法读取 pyxis 配置目录项元数据");
        assert!(!is_reparse(&metadata), "pyxis 配置来源包含重解析点");
        if metadata.is_dir() {
            collect_conf_files(root, &path, files);
        } else if metadata.is_file()
            && path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("conf"))
        {
            let canonical_file = path.canonicalize().expect("无法规范化 pyxis 配置文件");
            assert!(canonical_file.starts_with(root), "pyxis 配置文件越界");
            files.push(canonical_file);
        }
    }
}

fn pyxis_display_name(path: &Path, is_first_hop: bool) -> String {
    if is_first_hop {
        return "香港 WireGuard".to_owned();
    }
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .expect("pyxis 配置文件名不是 UTF-8");
    const PREFIX: &str = "hk-proton-mihomo-";
    if stem
        .get(..PREFIX.len())
        .is_some_and(|value| value.eq_ignore_ascii_case(PREFIX))
    {
        return format!("Proton {}", &stem[PREFIX.len()..]);
    }
    stem.to_owned()
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
