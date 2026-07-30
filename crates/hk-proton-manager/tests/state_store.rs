use std::{fs, path::Path};

use hk_proton_core::{
    FirstHopProfile, ImportMetadata, LanPolicy, OperatingMode, ProfileId, ProtonProfile,
    RuntimeOptions, RuntimeSelection, SecretValue, TailscalePolicy, generate_profile,
    parse_wireguard,
};
use hk_proton_manager::{
    AppState, GenerationCandidate, LanPolicyRecord, LaunchBlockReason, ManagerError, PendingSecret,
    ProfileResourceRecord, ProfileRole, ProfileVersionKind, ProfileVersionRecord, Result,
    SecretProtector, SecretPurpose, SecretRef, StateStore, TailscalePolicyRecord,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use time::macros::datetime;

const FIRST_HOP: &str =
    include_str!("../../hk-proton-core/tests/fixtures/first-hop-hk.synthetic.conf");
const PROTON: &str = include_str!("../../hk-proton-core/tests/fixtures/proton-jp.synthetic.conf");
const VLESS_URI: &str = "vless://33333333-3333-4333-8333-333333333333@203.0.113.45:443?encryption=none&security=tls&sni=example.com&type=tcp#synthetic";

#[test]
fn commits_encrypted_generations_and_rolls_back_the_whole_state() {
    let temporary = TempDir::new().unwrap();
    let store = StateStore::open(temporary.path(), TestProtector).unwrap();
    let (state_v1, pending_v1) = initial_state();

    let receipt_v1 = store
        .commit(candidate(state_v1, pending_v1, "runtime-secret-v1"), None)
        .unwrap();
    assert_eq!(receipt_v1.revision, 1);
    assert_eq!(store.current_revision().unwrap(), Some(1));

    let current_v1 = store.load_current().unwrap().unwrap();
    assert_eq!(current_v1.state.revision, 1);
    assert_eq!(current_v1.state.first_hops[0].versions.len(), 1);
    let plan = store.prepare_offline_launch(1).unwrap();
    assert!(!plan.can_spawn());
    assert!(plan.network_effects().tun_enabled);
    assert!(
        plan.blockers()
            .contains(&LaunchBlockReason::LiveConflictSnapshotRequired)
    );
    assert!(
        plan.blockers()
            .contains(&LaunchBlockReason::NetworkActivationAuthorizationRequired)
    );
    assert!(
        plan.required_ports()
            .iter()
            .all(|port| port.allowed_owner_pid.is_none())
    );
    assert!(
        store
            .load_runtime_yaml(1)
            .unwrap()
            .expose_secret()
            .contains("# runtime-secret-v1")
    );
    assert_workspace_contains_no_plaintext(temporary.path());

    let mut state_v2 = current_v1.state.clone();
    let updated_source = FIRST_HOP.replace("MTU = 1360", "MTU = 1320");
    let updated = parse_wireguard(&updated_source).unwrap();
    let (version_v2, pending_v2) =
        ProfileVersionRecord::from_wireguard(updated.config, metadata(2, updated.source_sha256));
    state_v2.first_hops[0].current_version_id = version_v2.version_id;
    state_v2.first_hops[0].versions.push(version_v2);
    let proton_hash_before = state_v2.proton_nodes[0].versions[0].source_sha256.clone();

    let receipt_v2 = store
        .commit(
            candidate(state_v2, pending_v2, "runtime-secret-v2"),
            Some(1),
        )
        .unwrap();
    assert_eq!(receipt_v2.revision, 2);
    let current_v2 = store.load_current().unwrap().unwrap();
    assert_eq!(current_v2.state.first_hops[0].versions.len(), 2);
    assert_eq!(
        current_v2.state.proton_nodes[0].versions[0].source_sha256, proton_hash_before,
        "第一跳更新不得改变 Proton 版本"
    );

    store.mark_last_known_good(2).unwrap();
    assert_eq!(store.last_known_good_revision().unwrap(), Some(2));

    let rollback = store.rollback(1, 2).unwrap();
    assert_eq!(rollback.revision, 3);
    assert_eq!(store.load_current().unwrap().unwrap().state.revision, 3);
    assert!(
        store
            .load_runtime_yaml(3)
            .unwrap()
            .expose_secret()
            .contains("# runtime-secret-v1")
    );

    // 回滚本身是新 generation；后续提交继续递增，绝不让 HEAD 倒退。
    let rolled_back_state = store.load_current().unwrap().unwrap().state;
    let receipt_v4 = store
        .commit(
            candidate(rolled_back_state, Vec::new(), "runtime-secret-v4"),
            Some(3),
        )
        .unwrap();
    assert_eq!(receipt_v4.revision, 4);
    assert!(matches!(
        store.commit(
            candidate(
                store.load_current().unwrap().unwrap().state,
                Vec::new(),
                "stale-candidate"
            ),
            Some(2)
        ),
        Err(ManagerError::RevisionConflict)
    ));
    assert_workspace_contains_no_plaintext(temporary.path());
}

#[test]
fn falls_back_to_the_previous_valid_head_slot() {
    let temporary = TempDir::new().unwrap();
    let store = StateStore::open(temporary.path(), TestProtector).unwrap();
    let (state, pending) = initial_state();
    store
        .commit(candidate(state, pending, "runtime-secret-v1"), None)
        .unwrap();
    let state_v2 = store.load_current().unwrap().unwrap().state;
    store
        .commit(
            candidate(state_v2, Vec::new(), "runtime-secret-v2"),
            Some(1),
        )
        .unwrap();
    assert_eq!(store.current_revision().unwrap(), Some(2));

    mutate_envelope_mac(&temporary.path().join("current.1"));
    assert_eq!(
        store.load_current().unwrap().unwrap().state.revision,
        1,
        "最新 HEAD 槽损坏时必须回退到上一有效槽"
    );
}

#[test]
fn binds_manifest_signatures_to_their_revision() {
    let temporary = TempDir::new().unwrap();
    let store = StateStore::open(temporary.path(), TestProtector).unwrap();
    let (state, pending) = initial_state();
    store
        .commit(candidate(state, pending, "runtime-secret-v1"), None)
        .unwrap();
    let state_v2 = store.load_current().unwrap().unwrap().state;
    store
        .commit(
            candidate(state_v2, Vec::new(), "runtime-secret-v2"),
            Some(1),
        )
        .unwrap();

    let generations = temporary.path().join("generations");
    fs::copy(
        generations
            .join("00000000000000000001")
            .join("manifest.json"),
        generations
            .join("00000000000000000002")
            .join("manifest.json"),
    )
    .unwrap();
    assert!(matches!(
        store.load_generation(2),
        Err(ManagerError::Integrity)
    ));
}

#[test]
fn reopens_with_the_same_key_and_finishes_pending_bootstrap_metadata() {
    let temporary = TempDir::new().unwrap();
    StateStore::open(temporary.path(), TestProtector).unwrap();
    fs::rename(
        temporary.path().join("store.meta"),
        temporary.path().join(".store.meta.pending"),
    )
    .unwrap();

    let reopened = StateStore::open(temporary.path(), TestProtector).unwrap();
    assert_eq!(reopened.current_revision().unwrap(), None);
    assert!(temporary.path().join("store.meta").is_file());
    assert!(!temporary.path().join(".store.meta.pending").exists());
    let (state, pending) = initial_state();
    reopened
        .commit(candidate(state, pending, "runtime-secret-v1"), None)
        .unwrap();
    drop(reopened);
    assert_eq!(
        StateStore::open(temporary.path(), TestProtector)
            .unwrap()
            .load_current()
            .unwrap()
            .unwrap()
            .state
            .revision,
        1
    );
}

#[test]
fn detects_generation_corruption_before_loading() {
    let temporary = TempDir::new().unwrap();
    let store = StateStore::open(temporary.path(), TestProtector).unwrap();
    let (state, pending) = initial_state();
    store
        .commit(candidate(state, pending, "runtime-secret-v1"), None)
        .unwrap();

    let runtime_path = temporary
        .path()
        .join("generations")
        .join("00000000000000000001")
        .join("profile.yaml.dpapi");
    let mut ciphertext = fs::read(&runtime_path).unwrap();
    ciphertext.push(0xff);
    fs::write(runtime_path, ciphertext).unwrap();

    assert!(matches!(
        store.load_generation(1),
        Err(ManagerError::GenerationCorrupt)
    ));
}

#[test]
fn rejects_manifest_and_head_domain_tampering() {
    let temporary = TempDir::new().unwrap();
    let store = StateStore::open(temporary.path(), TestProtector).unwrap();
    let (state, pending) = initial_state();
    store
        .commit(candidate(state, pending, "runtime-secret-v1"), None)
        .unwrap();

    let manifest_path = temporary
        .path()
        .join("generations")
        .join("00000000000000000001")
        .join("manifest.json");
    let original_manifest = fs::read(&manifest_path).unwrap();
    let mut tampered_manifest = original_manifest.clone();
    let index = tampered_manifest.len() / 2;
    tampered_manifest[index] ^= 1;
    fs::write(&manifest_path, tampered_manifest).unwrap();
    assert!(matches!(
        store.load_generation(1),
        Err(ManagerError::Integrity)
    ));

    fs::write(&manifest_path, original_manifest).unwrap();
    store.mark_last_known_good(1).unwrap();
    fs::copy(
        temporary.path().join("last-known-good.0"),
        temporary.path().join("current.0"),
    )
    .unwrap();
    assert!(matches!(
        store.current_revision(),
        Err(ManagerError::GenerationCorrupt)
    ));
}

#[test]
fn fails_closed_when_authentication_metadata_or_key_is_lost() {
    let temporary = TempDir::new().unwrap();
    {
        let store = StateStore::open(temporary.path(), TestProtector).unwrap();
        let (state, pending) = initial_state();
        store
            .commit(candidate(state, pending, "runtime-secret-v1"), None)
            .unwrap();
    }

    let metadata = fs::read(temporary.path().join("store.meta")).unwrap();
    fs::remove_file(temporary.path().join("store.meta")).unwrap();
    assert!(matches!(
        StateStore::open(temporary.path(), TestProtector),
        Err(ManagerError::InvalidState(_))
    ));

    fs::write(temporary.path().join("store.meta"), metadata).unwrap();
    let key_path = temporary.path().join("vault-auth-key.dpapi");
    let mut protected_key = fs::read(&key_path).unwrap();
    protected_key.push(0xff);
    fs::write(key_path, protected_key).unwrap();
    assert!(matches!(
        StateStore::open(temporary.path(), TestProtector),
        Err(ManagerError::Integrity)
    ));
}

#[test]
fn state_rejects_a_disabled_current_selection() {
    let (mut state, _) = initial_state();
    state.first_hops[0].enabled = false;
    assert!(matches!(
        state.validate(),
        Err(ManagerError::InvalidState(_))
    ));
}

#[test]
fn state_stores_vless_uuid_as_a_separate_secret_and_validates_the_version() {
    let parsed = hk_proton_core::parse_vless(VLESS_URI).unwrap();
    let (version, pending) =
        ProfileVersionRecord::from_vless(parsed.config, metadata(1, parsed.source_sha256));
    assert_eq!(version.kind, ProfileVersionKind::Vless);
    assert_eq!(
        version.uuid.as_ref().map(|reference| reference.purpose),
        Some(SecretPurpose::VlessUuid)
    );
    assert_eq!(pending.len(), 1);

    let id = ProfileId::new("fh-vless").unwrap();
    let state = AppState {
        schema_version: 1,
        revision: 0,
        mode: OperatingMode::SingleHop,
        selected_first_hop: id.clone(),
        selected_proton: None,
        first_hops: vec![ProfileResourceRecord {
            id,
            role: ProfileRole::FirstHop,
            display_name: "VLESS 第一跳".to_owned(),
            enabled: true,
            current_version_id: version.version_id,
            versions: vec![version],
        }],
        proton_nodes: Vec::new(),
        lan: LanPolicyRecord::default(),
        tailscale: TailscalePolicyRecord::default(),
    };
    state.validate().unwrap();
}

fn initial_state() -> (AppState, Vec<PendingSecret>) {
    let first_hop = parse_wireguard(FIRST_HOP).unwrap();
    let proton = parse_wireguard(PROTON).unwrap();
    let (first_hop_version, mut pending) = ProfileVersionRecord::from_wireguard(
        first_hop.config,
        metadata(1, first_hop.source_sha256),
    );
    let (proton_version, proton_pending) =
        ProfileVersionRecord::from_wireguard(proton.config, metadata(1, proton.source_sha256));
    pending.extend(proton_pending);

    let first_hop_id = ProfileId::new("fh-hk").unwrap();
    let proton_id = ProfileId::new("proton-jp").unwrap();
    (
        AppState {
            schema_version: 1,
            revision: 0,
            mode: OperatingMode::DoubleHop,
            selected_first_hop: first_hop_id.clone(),
            selected_proton: Some(proton_id.clone()),
            first_hops: vec![ProfileResourceRecord {
                id: first_hop_id,
                role: ProfileRole::FirstHop,
                display_name: "香港第一跳".to_owned(),
                enabled: true,
                current_version_id: first_hop_version.version_id,
                versions: vec![first_hop_version],
            }],
            proton_nodes: vec![ProfileResourceRecord {
                id: proton_id,
                role: ProfileRole::Proton,
                display_name: "Proton JP".to_owned(),
                enabled: true,
                current_version_id: proton_version.version_id,
                versions: vec![proton_version],
            }],
            lan: LanPolicyRecord::default(),
            tailscale: TailscalePolicyRecord::default(),
        },
        pending,
    )
}

fn metadata(version: u64, source_sha256: String) -> ImportMetadata {
    ImportMetadata::new(datetime!(2026-07-12 00:00 UTC), version, source_sha256)
}

fn candidate(
    state: AppState,
    pending_secrets: Vec<PendingSecret>,
    runtime: &str,
) -> GenerationCandidate {
    GenerationCandidate::validated(
        state,
        synthetic_runtime(runtime),
        pending_secrets,
        "1.19.28",
        datetime!(2026-07-12 00:00 UTC),
    )
    .unwrap()
}

fn synthetic_runtime(label: &str) -> SecretValue {
    let first_parsed = parse_wireguard(FIRST_HOP).unwrap();
    let proton_parsed = parse_wireguard(PROTON).unwrap();
    let first = FirstHopProfile::new(
        ProfileId::new("fh-hk").unwrap(),
        "香港第一跳",
        first_parsed.config,
        metadata(1, first_parsed.source_sha256),
    )
    .unwrap();
    let proton = ProtonProfile::new(
        ProfileId::new("proton-jp").unwrap(),
        "Proton JP",
        proton_parsed.config,
        metadata(1, proton_parsed.source_sha256),
    )
    .unwrap();
    let selection = RuntimeSelection {
        mode: OperatingMode::DoubleHop,
        first_hop: ProfileId::new("fh-hk").unwrap(),
        proton: Some(ProfileId::new("proton-jp").unwrap()),
    };
    let options = RuntimeOptions::checked(
        true,
        17890,
        19090,
        SecretValue::new("synthetic-state-store-controller"),
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
    SecretValue::new(format!("{}\n# {label}\n", generated.as_str()))
}

fn assert_workspace_contains_no_plaintext(root: &Path) {
    let forbidden = [
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
        "runtime-secret-v1",
        "runtime-secret-v2",
        "runtime-secret-v4",
    ];
    for file in recursive_files(root) {
        let bytes = fs::read(&file).unwrap();
        for marker in forbidden {
            assert!(
                !bytes
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes()),
                "状态库不得保存明文 secret"
            );
        }
    }
}

fn recursive_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut directories = vec![root.to_owned()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                directories.push(entry.path());
            } else {
                files.push(entry.path());
            }
        }
    }
    files
}

fn mutate_envelope_mac(path: &Path) {
    let mut envelope: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let mac = envelope["hmac_sha256_base64"].as_str().unwrap();
    let replacement = if mac.starts_with('A') { 'B' } else { 'A' };
    let mut changed = mac.to_owned();
    changed.replace_range(..1, &replacement.to_string());
    envelope["hmac_sha256_base64"] = serde_json::Value::String(changed);
    fs::write(path, serde_json::to_vec(&envelope).unwrap()).unwrap();
}

struct TestProtector;

impl SecretProtector for TestProtector {
    fn protect(&self, reference: &SecretRef, plaintext: &SecretValue) -> Result<Vec<u8>> {
        let key = reference.id.as_bytes();
        let mut output = b"HKP-TEST-CIPHER\0".to_vec();
        output.extend(test_tag(reference, plaintext.expose_secret().as_bytes()));
        output.extend(
            plaintext
                .expose_secret()
                .as_bytes()
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ key[index % key.len()] ^ 0xa5),
        );
        Ok(output)
    }

    fn unprotect(&self, reference: &SecretRef, ciphertext: &[u8]) -> Result<SecretValue> {
        let body = ciphertext
            .strip_prefix(b"HKP-TEST-CIPHER\0")
            .ok_or(ManagerError::SecretProtection)?;
        if body.len() < 32 {
            return Err(ManagerError::SecretProtection);
        }
        let (tag, body) = body.split_at(32);
        let key = reference.id.as_bytes();
        let plaintext: Vec<u8> = body
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[index % key.len()] ^ 0xa5)
            .collect();
        if tag != test_tag(reference, &plaintext) {
            return Err(ManagerError::SecretProtection);
        }
        String::from_utf8(plaintext)
            .map(SecretValue::new)
            .map_err(|_| ManagerError::SecretProtection)
    }
}

fn test_tag(reference: &SecretRef, plaintext: &[u8]) -> [u8; 32] {
    let purpose = match reference.purpose {
        SecretPurpose::WireGuardPrivateKey => 1,
        SecretPurpose::WireGuardPresharedKey => 2,
        SecretPurpose::VlessUuid => 3,
        SecretPurpose::RuntimeProfile => 4,
        SecretPurpose::ManifestHmac => 5,
    };
    let mut hasher = Sha256::new();
    hasher.update(reference.id.as_bytes());
    hasher.update(reference.envelope_version.to_le_bytes());
    hasher.update([purpose]);
    hasher.update(plaintext);
    hasher.finalize().into()
}
