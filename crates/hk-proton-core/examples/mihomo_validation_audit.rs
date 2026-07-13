//! 使用官方 Mihomo 对真实配置生成结果执行 `-t`。
//!
//! 运行时 YAML 只短暂写入当前用户的系统临时目录，进程结束后自动删除；
//! Mihomo 的 stdout/stderr 不会被转发，避免未来版本意外回显敏感字段。

use std::{env, ffi::OsString, fs, net::IpAddr, path::Path, process::Command};

use hk_proton_core::{
    FirstHopProfile, ImportMetadata, LanPolicy, OperatingMode, ProfileId, ProtonProfile,
    RuntimeOptions, RuntimeSelection, SecretValue, TailscalePolicy, generate_profile,
    parse_wireguard,
};
use tempfile::Builder;
use time::OffsetDateTime;

fn main() {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    if arguments.len() < 3 {
        eprintln!(
            "用法：mihomo_validation_audit <mihomo.exe> <first-hop.conf> <proton.conf> [...]"
        );
        std::process::exit(2);
    }
    let mihomo = Path::new(&arguments[0]);
    if !mihomo.is_file() {
        eprintln!("FAIL core: Mihomo 文件不存在");
        std::process::exit(1);
    }

    let first_hop = load_first_hop(Path::new(&arguments[1])).unwrap_or_else(|| exit_failed());
    let synthetic_inputs = arguments[1..].iter().all(|path| {
        Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".synthetic.conf"))
    });
    let protons: Vec<_> = arguments[2..]
        .iter()
        .enumerate()
        .map(|(index, path)| {
            load_proton(Path::new(path), index + 1).unwrap_or_else(|| exit_failed())
        })
        .collect();
    let runtime = RuntimeOptions::checked(
        true,
        17890,
        19090,
        SecretValue::new("compatibility-audit-only"),
    )
    .expect("固定运行参数有效");
    let temp = Builder::new()
        .prefix("hk-proton-mihomo-audit-")
        .tempdir()
        .unwrap_or_else(|_| {
            eprintln!("FAIL temp: 无法创建受限临时目录");
            std::process::exit(1);
        });

    let single = RuntimeSelection {
        mode: OperatingMode::SingleHop,
        first_hop: first_hop.id.clone(),
        proton: None,
    };
    let context = AuditContext {
        mihomo,
        temp: temp.path(),
        first_hops: std::slice::from_ref(&first_hop),
        protons: &protons,
        runtime: &runtime,
        synthetic_inputs,
    };
    validate_one(&context, &single, "single-hop");

    for (index, proton) in protons.iter().enumerate() {
        let selection = RuntimeSelection {
            mode: OperatingMode::DoubleHop,
            first_hop: first_hop.id.clone(),
            proton: Some(proton.id.clone()),
        };
        validate_one(&context, &selection, &format!("double-hop #{}", index + 1));
    }
}

struct AuditContext<'a> {
    mihomo: &'a Path,
    temp: &'a Path,
    first_hops: &'a [FirstHopProfile],
    protons: &'a [ProtonProfile],
    runtime: &'a RuntimeOptions,
    synthetic_inputs: bool,
}

fn validate_one(context: &AuditContext<'_>, selection: &RuntimeSelection, label: &str) {
    let generated = generate_profile(
        context.first_hops,
        context.protons,
        selection,
        &audit_lan_policy(),
        &TailscalePolicy::standard(),
        context.runtime,
    )
    .unwrap_or_else(|error| {
        eprintln!("FAIL {label}: {error}");
        std::process::exit(1);
    });
    let profile_path = context.temp.join("candidate.yaml");
    fs::write(&profile_path, generated.as_str().as_bytes()).unwrap_or_else(|_| {
        eprintln!("FAIL {label}: 无法写入临时候选配置");
        std::process::exit(1);
    });

    let output = Command::new(context.mihomo)
        .args(["-t", "-d"])
        .arg(context.temp)
        .arg("-f")
        .arg(&profile_path)
        .output()
        .unwrap_or_else(|_| {
            eprintln!("FAIL {label}: 无法启动 Mihomo");
            std::process::exit(1);
        });
    let _ = fs::remove_file(&profile_path);

    if !output.status.success() {
        if context.synthetic_inputs {
            eprintln!("FAIL {label}: mihomo -t 未通过");
            eprintln!("{}", String::from_utf8_lossy(&output.stdout));
            eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        } else {
            // 真实输入时刻意不转发 core 输出。即使上游改变错误格式，也不会意外泄密。
            eprintln!("FAIL {label}: mihomo -t 未通过（core 输出已抑制）");
        }
        std::process::exit(1);
    }
    println!("OK {label}: internal + mihomo -t");
}

fn audit_lan_policy() -> LanPolicy {
    let mut policy = LanPolicy::preset_172_23();
    policy.dns_servers = vec![
        "172.23.0.1"
            .parse::<IpAddr>()
            .expect("固定合成 LAN DNS 有效"),
    ];
    policy.domain_suffixes.push("corp.example".to_owned());
    policy
}

fn load_first_hop(path: &Path) -> Option<FirstHopProfile> {
    let parsed = load(path)?;
    FirstHopProfile::new(
        ProfileId::new("real-first-hop-audit").expect("固定 ID 有效"),
        "只读兼容检查第一跳",
        parsed.config,
        ImportMetadata::new(OffsetDateTime::now_utc(), 1, parsed.source_sha256),
    )
    .map_err(|error| eprintln!("FAIL first-hop model: {error}"))
    .ok()
}

fn load_proton(path: &Path, index: usize) -> Option<ProtonProfile> {
    let parsed = load(path)?;
    ProtonProfile::new(
        ProfileId::new(format!("real-proton-audit-{index}")).expect("生成的兼容检查 ID 有效"),
        format!("只读兼容检查 Proton {index}"),
        parsed.config,
        ImportMetadata::new(OffsetDateTime::now_utc(), 1, parsed.source_sha256),
    )
    .map_err(|error| eprintln!("FAIL Proton model #{index}: {error}"))
    .ok()
}

fn load(path: &Path) -> Option<hk_proton_core::ParsedWireGuard> {
    let source = fs::read_to_string(path)
        .map_err(|_| eprintln!("FAIL input: 无法读取配置文件"))
        .ok()?;
    parse_wireguard(&source)
        .map_err(|error| eprintln!("FAIL input: {error}"))
        .ok()
}

fn exit_failed() -> ! {
    std::process::exit(1)
}
