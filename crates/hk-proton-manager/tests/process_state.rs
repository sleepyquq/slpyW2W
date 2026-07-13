use std::fs;

use hk_proton_core::{
    FirstHopProfile, ImportMetadata, LanPolicy, OperatingMode, ProfileId, ProtonProfile,
    RuntimeOptions, RuntimeSelection, SecretValue, TailscalePolicy, generate_profile,
    parse_wireguard,
};
use hk_proton_manager::{
    CoreLaunchSpec, ManagerError, inspect_network_effects, redact_known_secrets,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use time::macros::datetime;

const FIRST_HOP: &str =
    include_str!("../../hk-proton-core/tests/fixtures/first-hop-hk.synthetic.conf");
const PROTON: &str = include_str!("../../hk-proton-core/tests/fixtures/proton-jp.synthetic.conf");

#[test]
fn derives_network_effects_from_yaml_and_blocks_tun_before_any_spawn() {
    let temporary = TempDir::new().unwrap();
    let executable = temporary.path().join("fake-core.exe");
    let runtime_home = temporary.path().join("runtime");
    let config = temporary.path().join("candidate.yaml");
    fs::create_dir(&runtime_home).unwrap();
    fs::write(&executable, b"synthetic executable marker").unwrap();

    let offline = synthetic_runtime(false);
    fs::write(&config, offline.expose_secret()).unwrap();
    let projection = inspect_network_effects(&offline).unwrap();
    assert!(!projection.tun_enabled);
    assert_eq!(
        projection.external_controller.to_string(),
        "127.0.0.1:19090"
    );
    assert_eq!(projection.mixed_port, 17890);
    CoreLaunchSpec::offline_preflight(
        &executable,
        hex_sha256(&fs::read(&executable).unwrap()),
        temporary.path(),
        &runtime_home,
        &config,
        hex_sha256(offline.expose_secret().as_bytes()),
    )
    .unwrap();

    let network_changing = synthetic_runtime(true);
    fs::write(&config, network_changing.expose_secret()).unwrap();
    assert!(matches!(
        CoreLaunchSpec::offline_preflight(
            &executable,
            hex_sha256(&fs::read(&executable).unwrap()),
            temporary.path(),
            &runtime_home,
            &config,
            hex_sha256(network_changing.expose_secret().as_bytes()),
        ),
        Err(ManagerError::NetworkActivationRequiresUser)
    ));
}

#[test]
fn rejects_unknown_runtime_features_and_changed_candidates() {
    let temporary = TempDir::new().unwrap();
    let executable = temporary.path().join("fake-core.exe");
    let runtime_home = temporary.path().join("runtime");
    let config = temporary.path().join("candidate.yaml");
    fs::create_dir(&runtime_home).unwrap();
    fs::write(&executable, b"synthetic executable marker").unwrap();
    let offline = synthetic_runtime(false);
    fs::write(&config, offline.expose_secret()).unwrap();
    let expected_config = hex_sha256(offline.expose_secret().as_bytes());

    fs::write(
        &config,
        format!("ntp:\n  enable: true\n{}", offline.expose_secret()),
    )
    .unwrap();
    assert!(matches!(
        inspect_network_effects(&SecretValue::new(fs::read_to_string(&config).unwrap())),
        Err(ManagerError::InvalidLaunchSpec)
    ));
    assert!(matches!(
        CoreLaunchSpec::offline_preflight(
            &executable,
            hex_sha256(&fs::read(&executable).unwrap()),
            temporary.path(),
            &runtime_home,
            &config,
            expected_config,
        ),
        Err(ManagerError::CandidateChanged)
    ));
}

#[test]
fn redacts_every_known_secret_from_core_output() {
    let first = SecretValue::new("private-key-marker");
    let second = SecretValue::new("controller-token-marker");
    let line = "failed private-key-marker then controller-token-marker";
    let redacted = redact_known_secrets(line, &[&first, &second]);
    assert_eq!(redacted, "failed [REDACTED] then [REDACTED]");
}

fn synthetic_runtime(tun_enabled: bool) -> SecretValue {
    let first_parsed = parse_wireguard(FIRST_HOP).unwrap();
    let proton_parsed = parse_wireguard(PROTON).unwrap();
    let first = FirstHopProfile::new(
        ProfileId::new("fh-hk").unwrap(),
        "香港第一跳",
        first_parsed.config,
        metadata(first_parsed.source_sha256),
    )
    .unwrap();
    let proton = ProtonProfile::new(
        ProfileId::new("proton-jp").unwrap(),
        "Proton JP",
        proton_parsed.config,
        metadata(proton_parsed.source_sha256),
    )
    .unwrap();
    let selection = RuntimeSelection {
        mode: OperatingMode::DoubleHop,
        first_hop: ProfileId::new("fh-hk").unwrap(),
        proton: Some(ProfileId::new("proton-jp").unwrap()),
    };
    let options = RuntimeOptions::checked(
        tun_enabled,
        17890,
        19090,
        SecretValue::new("synthetic-process-controller"),
    )
    .unwrap();
    let generated = generate_profile(
        &[first],
        &[proton],
        &selection,
        &LanPolicy::default(),
        &TailscalePolicy::default(),
        &options,
    )
    .unwrap();
    SecretValue::new(generated.as_str().to_owned())
}

fn metadata(source_sha256: String) -> ImportMetadata {
    ImportMetadata::new(datetime!(2026-07-12 00:00 UTC), 1, source_sha256)
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
