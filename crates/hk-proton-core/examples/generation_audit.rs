//! 使用真实配置做内存内生成兼容性检查，但不输出或落盘运行时 YAML。

use std::{env, fs, path::Path};

use hk_proton_core::{
    FirstHopProfile, ImportMetadata, LanPolicy, OperatingMode, ProfileId, ProtonProfile,
    RuntimeOptions, RuntimeSelection, SecretValue, TailscalePolicy, generate_profile,
    parse_wireguard,
};
use time::OffsetDateTime;

fn main() {
    let paths: Vec<_> = env::args_os().skip(1).collect();
    if paths.len() < 2 {
        eprintln!("用法：generation_audit <first-hop.conf> <proton-1.conf> [...]");
        std::process::exit(2);
    }

    let first = load_first_hop(Path::new(&paths[0]));
    let protons: Vec<_> = paths[1..]
        .iter()
        .enumerate()
        .map(|(index, path)| load_proton(Path::new(path), index + 1))
        .collect();
    let (first_hop, protons) = match (first, protons.into_iter().collect::<Option<Vec<_>>>()) {
        (Some(first_hop), Some(protons)) => (first_hop, protons),
        _ => std::process::exit(1),
    };

    let runtime = RuntimeOptions::checked(
        true,
        17890,
        19090,
        SecretValue::new("compatibility-audit-only"),
    )
    .expect("固定运行参数有效");

    let single = RuntimeSelection {
        mode: OperatingMode::SingleHop,
        first_hop: first_hop.id.clone(),
        proton: None,
    };
    match generate_profile(
        std::slice::from_ref(&first_hop),
        &protons,
        &single,
        &LanPolicy::default(),
        &TailscalePolicy::default(),
        &runtime,
    ) {
        Ok(profile) => println!(
            "OK single-hop: proxies={} groups={}",
            profile.validation.proxy_count, profile.validation.group_count
        ),
        Err(error) => {
            eprintln!("FAIL single-hop: {error}");
            std::process::exit(1);
        }
    }

    for (index, proton) in protons.iter().enumerate() {
        let double = RuntimeSelection {
            mode: OperatingMode::DoubleHop,
            first_hop: first_hop.id.clone(),
            proton: Some(proton.id.clone()),
        };
        match generate_profile(
            std::slice::from_ref(&first_hop),
            &protons,
            &double,
            &LanPolicy::default(),
            &TailscalePolicy::default(),
            &runtime,
        ) {
            Ok(profile) => println!(
                "OK double-hop #{}: proxies={} groups={} path-length={}",
                index + 1,
                profile.validation.proxy_count,
                profile.validation.group_count,
                profile.validation.active_path.len()
            ),
            Err(error) => {
                eprintln!("FAIL double-hop #{}: {error}", index + 1);
                std::process::exit(1);
            }
        }
    }
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
