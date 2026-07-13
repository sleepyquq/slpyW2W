use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use fs2::FileExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    AppState, GenerationCandidate, ManagerError, OfflineLaunchPlan, Result, SecretPurpose,
    SecretRef, inspect_network_effects,
};
use hk_proton_core::SecretValue;

#[cfg(windows)]
use crate::{DpapiCurrentUserProtector, WindowsPrivateDirectory};

const STATE_FILE: &str = "state.json";
const RUNTIME_FILE: &str = "profile.yaml.dpapi";
const MANIFEST_FILE: &str = "manifest.json";
const STORE_META_FILE: &str = "store.meta";
const STORE_META_PENDING_FILE: &str = ".store.meta.pending";
const AUTH_KEY_FILE: &str = "vault-auth-key.dpapi";
const INTEGRITY_FORMAT: &str = "hmac-sha256-envelope-v1";
const MANIFEST_HMAC_DOMAIN: &[u8] = b"HK-Proton\0manifest-v1\0";
const HEAD_HMAC_DOMAIN: &[u8] = b"HK-Proton\0head-v1\0";
const MAX_SIGNED_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const MAX_SIGNED_ENVELOPE_BYTES: usize = 12 * 1024 * 1024;
const MAX_HEAD_ENVELOPE_BYTES: usize = 64 * 1024;
const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_SECRET_CIPHERTEXT_BYTES: usize = 1024 * 1024;
const MAX_STATE_BYTES: usize = 32 * 1024 * 1024;
const MAX_RUNTIME_CIPHERTEXT_BYTES: usize = 32 * 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

pub trait SecretProtector: Send + Sync {
    fn protect(&self, reference: &SecretRef, plaintext: &SecretValue) -> Result<Vec<u8>>;
    fn unprotect(&self, reference: &SecretRef, ciphertext: &[u8]) -> Result<SecretValue>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenerationManifest {
    pub schema_version: u32,
    pub revision: u64,
    pub parent_revision: Option<u64>,
    pub created_at: OffsetDateTime,
    pub mihomo_version: String,
    pub state_sha256: String,
    pub runtime_ciphertext_sha256: String,
    pub runtime_secret_ref: SecretRef,
    pub secret_refs: Vec<SecretRef>,
}

#[derive(Clone, Debug)]
pub struct StoredGeneration {
    pub manifest: GenerationManifest,
    pub state: AppState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    pub revision: u64,
    pub parent_revision: Option<u64>,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct GenerationPointer {
    head_epoch: u64,
    revision: u64,
    manifest_sha256: String,
}

#[derive(Serialize, Deserialize)]
struct StoreMetadata {
    schema_version: u32,
    integrity_format: String,
    auth_key_ref: SecretRef,
}

#[derive(Serialize, Deserialize)]
struct SignedEnvelope {
    envelope_version: u16,
    payload_base64: String,
    hmac_sha256_base64: String,
}

#[cfg(windows)]
#[derive(Serialize, Deserialize)]
struct VaultMetadata {
    schema_version: u32,
    vault_id: Uuid,
}

pub struct StateStore<P> {
    root: PathBuf,
    protector: P,
    auth_key: Zeroizing<Vec<u8>>,
}

#[cfg(windows)]
impl StateStore<DpapiCurrentUserProtector> {
    /// 打开或初始化当前 Windows 用户专属的 DPAPI Vault。
    pub fn open_current_user(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        let root_scope = WindowsPrivateDirectory::create(&root, &root)?;
        let root = root_scope.path().to_path_buf();
        let metadata_path = root.join("vault.meta");
        let metadata = if root_scope.existing_regular_file("vault.meta")?.is_some() {
            read_vault_metadata(&metadata_path)?
        } else {
            root_scope.revalidate()?;
            if fs::read_dir(&root)?.next().is_some() {
                return Err(ManagerError::InvalidState(
                    "vault.meta 缺失，但状态目录并非空 Vault".to_owned(),
                ));
            }
            let candidate = VaultMetadata {
                schema_version: 1,
                vault_id: Uuid::new_v4(),
            };
            let bytes = serde_json::to_vec_pretty(&candidate)?;
            match write_new_synced(&metadata_path, &bytes) {
                Ok(()) => candidate,
                Err(ManagerError::Io(error))
                    if error.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    root_scope
                        .existing_regular_file("vault.meta")?
                        .ok_or(ManagerError::UnsafePrivatePath)?;
                    read_vault_metadata(&metadata_path)?
                }
                Err(error) => return Err(error),
            }
        };
        Self::open(root, DpapiCurrentUserProtector::new(metadata.vault_id))
    }
}

impl<P: SecretProtector> StateStore<P> {
    pub fn open(root: impl Into<PathBuf>, protector: P) -> Result<Self> {
        let root = root.into();
        #[cfg(windows)]
        let root = {
            let root_scope = WindowsPrivateDirectory::create(&root, &root)?;
            for child in ["generations", "secrets", ".staging"] {
                root_scope.create_child(child)?;
            }
            root_scope.revalidate()?;
            root_scope.path().to_path_buf()
        };
        #[cfg(not(windows))]
        {
            fs::create_dir_all(root.join("generations"))?;
            fs::create_dir_all(root.join("secrets"))?;
            fs::create_dir_all(root.join(".staging"))?;
        }
        let initialization_lock = open_store_lock(&root)?;
        initialization_lock
            .try_lock_exclusive()
            .map_err(|_| ManagerError::StoreLocked)?;
        let auth_key = load_or_initialize_auth_key(&root, &protector)?;
        drop(initialization_lock);
        Ok(Self {
            root,
            protector,
            auth_key,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn current_revision(&self) -> Result<Option<u64>> {
        let _lock = self.lock()?;
        Ok(self.read_head("current")?.map(|pointer| pointer.revision))
    }

    pub fn commit(
        &self,
        mut candidate: GenerationCandidate,
        expected_revision: Option<u64>,
    ) -> Result<CommitReceipt> {
        let _lock = self.lock()?;
        let current = self.read_head("current")?;
        if current.as_ref().map(|pointer| pointer.revision) != expected_revision {
            return Err(ManagerError::RevisionConflict);
        }
        let revision = self.next_revision()?;
        candidate.state.revision = revision;
        candidate.state.validate()?;

        let required_secrets = collect_state_secret_refs(&candidate.state)?;
        self.write_pending_secrets(&required_secrets, candidate.pending_secrets)?;
        self.verify_required_secrets(&required_secrets)?;

        let state_bytes = serde_json::to_vec_pretty(&candidate.state)?;
        let runtime_secret_ref = SecretRef::random(SecretPurpose::RuntimeProfile);
        let runtime_ciphertext = self
            .protector
            .protect(&runtime_secret_ref, &candidate.runtime_yaml)?;
        let secret_refs = required_secrets.into_values().collect::<Vec<_>>();
        let manifest = GenerationManifest {
            schema_version: 1,
            revision,
            parent_revision: current.as_ref().map(|pointer| pointer.revision),
            created_at: candidate.created_at,
            mihomo_version: candidate.mihomo_version,
            state_sha256: sha256_hex(&state_bytes),
            runtime_ciphertext_sha256: sha256_hex(&runtime_ciphertext),
            runtime_secret_ref,
            secret_refs,
        };
        let manifest_payload = serde_json::to_vec_pretty(&manifest)?;
        let manifest_bytes =
            self.sign_envelope(&manifest_hmac_domain(revision), &manifest_payload)?;
        let manifest_sha256 = sha256_hex(&manifest_bytes);

        let staging = self
            .root
            .join(".staging")
            .join(format!("generation-{revision:020}-{}", Uuid::new_v4()));
        fs::create_dir(&staging)?;
        write_new_synced(&staging.join(STATE_FILE), &state_bytes)?;
        write_new_synced(&staging.join(RUNTIME_FILE), &runtime_ciphertext)?;
        write_new_synced(&staging.join(MANIFEST_FILE), &manifest_bytes)?;

        let generation_path = self.generation_path(revision);
        fs::rename(&staging, &generation_path)?;
        self.write_head("current", revision, &manifest_sha256)?;

        Ok(CommitReceipt {
            revision,
            parent_revision: manifest.parent_revision,
            manifest_sha256,
        })
    }

    pub fn load_current(&self) -> Result<Option<StoredGeneration>> {
        let _lock = self.lock()?;
        let Some(pointer) = self.read_head("current")? else {
            return Ok(None);
        };
        let generation = self.read_generation_unlocked(pointer.revision)?;
        self.verify_pointer(&pointer)?;
        Ok(Some(generation))
    }

    pub fn load_generation(&self, revision: u64) -> Result<StoredGeneration> {
        let _lock = self.lock()?;
        self.read_generation_unlocked(revision)
    }

    pub fn load_runtime_yaml(&self, revision: u64) -> Result<SecretValue> {
        let _lock = self.lock()?;
        let generation = self.read_generation_unlocked(revision)?;
        let ciphertext = read_bounded(
            &self.generation_path(revision).join(RUNTIME_FILE),
            MAX_RUNTIME_CIPHERTEXT_BYTES,
        )?;
        self.protector
            .unprotect(&generation.manifest.runtime_secret_ref, &ciphertext)
    }

    /// 从已验签 generation 生成纯离线启动计划；不会采集网络、打开端口或启动进程。
    pub fn prepare_offline_launch(&self, revision: u64) -> Result<OfflineLaunchPlan> {
        let _lock = self.lock()?;
        let generation = self.read_generation_unlocked(revision)?;
        let generation_path = self.generation_path(revision);
        let manifest_bytes = read_bounded(
            &generation_path.join(MANIFEST_FILE),
            MAX_SIGNED_ENVELOPE_BYTES,
        )?;
        let runtime_ciphertext = read_bounded(
            &generation_path.join(RUNTIME_FILE),
            MAX_RUNTIME_CIPHERTEXT_BYTES,
        )?;
        let runtime = self
            .protector
            .unprotect(&generation.manifest.runtime_secret_ref, &runtime_ciphertext)
            .map_err(|_| ManagerError::GenerationCorrupt)?;
        let network_effects = inspect_network_effects(&runtime)?;
        OfflineLaunchPlan::from_verified_generation(
            revision,
            sha256_hex(&manifest_bytes),
            sha256_hex(runtime.expose_secret().as_bytes()),
            network_effects,
        )
    }

    pub fn load_secret(&self, reference: &SecretRef) -> Result<SecretValue> {
        let _lock = self.lock()?;
        let ciphertext = read_bounded(&self.secret_path(reference), MAX_SECRET_CIPHERTEXT_BYTES)
            .map_err(|_| ManagerError::SecretUnavailable)?;
        self.protector.unprotect(reference, &ciphertext)
    }

    pub fn rollback(&self, target_revision: u64, expected_revision: u64) -> Result<CommitReceipt> {
        if !self.is_ancestor_or_current(target_revision, expected_revision)? {
            return Err(ManagerError::InvalidState(
                "回滚目标不在当前 generation 的父链中".to_owned(),
            ));
        }
        let target = self.load_generation(target_revision)?;
        let runtime_yaml = self.load_runtime_yaml(target_revision)?;
        let candidate = GenerationCandidate::validated(
            target.state,
            runtime_yaml,
            Vec::new(),
            target.manifest.mihomo_version,
            OffsetDateTime::now_utc(),
        )?;
        self.commit(candidate, Some(expected_revision))
    }

    pub fn mark_last_known_good(&self, revision: u64) -> Result<()> {
        let _lock = self.lock()?;
        let current = self
            .read_head("current")?
            .ok_or(ManagerError::GenerationNotFound)?;
        if current.revision != revision {
            return Err(ManagerError::RevisionConflict);
        }
        let generation = self.read_generation_unlocked(revision)?;
        let manifest_bytes = read_bounded(
            &self.generation_path(revision).join(MANIFEST_FILE),
            MAX_SIGNED_ENVELOPE_BYTES,
        )?;
        self.write_head(
            "last-known-good",
            generation.manifest.revision,
            &sha256_hex(&manifest_bytes),
        )
    }

    pub fn last_known_good_revision(&self) -> Result<Option<u64>> {
        let _lock = self.lock()?;
        Ok(self
            .read_head("last-known-good")?
            .map(|pointer| pointer.revision))
    }

    fn is_ancestor_or_current(&self, target: u64, current: u64) -> Result<bool> {
        let mut cursor = Some(current);
        let mut visited = BTreeSet::new();
        while let Some(revision) = cursor {
            if !visited.insert(revision) {
                return Err(ManagerError::GenerationCorrupt);
            }
            if revision == target {
                return Ok(true);
            }
            cursor = self.load_generation(revision)?.manifest.parent_revision;
        }
        Ok(false)
    }

    fn read_generation_unlocked(&self, revision: u64) -> Result<StoredGeneration> {
        let path = self.generation_path(revision);
        if !path.is_dir() {
            return Err(ManagerError::GenerationNotFound);
        }
        let manifest_bytes = read_bounded(&path.join(MANIFEST_FILE), MAX_SIGNED_ENVELOPE_BYTES)?;
        let state_bytes = read_bounded(&path.join(STATE_FILE), MAX_STATE_BYTES)?;
        let runtime_ciphertext =
            read_bounded(&path.join(RUNTIME_FILE), MAX_RUNTIME_CIPHERTEXT_BYTES)?;
        let manifest_payload = self
            .verify_envelope(&manifest_hmac_domain(revision), &manifest_bytes)
            .map_err(|_| ManagerError::Integrity)?;
        let manifest: GenerationManifest = serde_json::from_slice(&manifest_payload)
            .map_err(|_| ManagerError::GenerationCorrupt)?;
        if manifest.schema_version != 1
            || manifest.revision != revision
            || manifest.state_sha256 != sha256_hex(&state_bytes)
            || manifest.runtime_ciphertext_sha256 != sha256_hex(&runtime_ciphertext)
            || manifest.runtime_secret_ref.purpose != SecretPurpose::RuntimeProfile
            || manifest.runtime_secret_ref.envelope_version != 1
        {
            return Err(ManagerError::GenerationCorrupt);
        }
        let state: AppState = serde_json::from_slice(&state_bytes)?;
        if state.revision != revision {
            return Err(ManagerError::GenerationCorrupt);
        }
        state.validate()?;
        let required = collect_state_secret_refs(&state)?;
        let mut manifest_refs = BTreeMap::new();
        for reference in &manifest.secret_refs {
            if manifest_refs
                .insert(reference.id, reference.clone())
                .is_some()
            {
                return Err(ManagerError::GenerationCorrupt);
            }
        }
        if required != manifest_refs {
            return Err(ManagerError::GenerationCorrupt);
        }
        for reference in required.values() {
            let ciphertext =
                read_bounded(&self.secret_path(reference), MAX_SECRET_CIPHERTEXT_BYTES)
                    .map_err(|_| ManagerError::GenerationCorrupt)?;
            self.protector
                .unprotect(reference, &ciphertext)
                .map_err(|_| ManagerError::GenerationCorrupt)?;
        }
        self.protector
            .unprotect(&manifest.runtime_secret_ref, &runtime_ciphertext)
            .map_err(|_| ManagerError::GenerationCorrupt)?;
        Ok(StoredGeneration { manifest, state })
    }

    fn write_pending_secrets(
        &self,
        required: &BTreeMap<Uuid, SecretRef>,
        pending: Vec<crate::PendingSecret>,
    ) -> Result<()> {
        let mut seen = BTreeSet::new();
        let mut validated = Vec::with_capacity(pending.len());
        for secret in pending {
            let Some(expected) = required.get(&secret.reference.id) else {
                return Err(ManagerError::SecretUnavailable);
            };
            if expected != &secret.reference || !seen.insert(secret.reference.id) {
                return Err(ManagerError::SecretUnavailable);
            }
            let path = self.secret_path(&secret.reference);
            if path.exists() {
                let ciphertext = read_bounded(&path, MAX_SECRET_CIPHERTEXT_BYTES)?;
                let existing = self
                    .protector
                    .unprotect(&secret.reference, &ciphertext)
                    .map_err(|_| ManagerError::SecretUnavailable)?;
                if existing.expose_secret() != secret.value.expose_secret() {
                    return Err(ManagerError::SecretUnavailable);
                }
                continue;
            }
            validated.push(secret);
        }

        for (id, reference) in required {
            if !self.secret_path(reference).is_file() && !seen.contains(id) {
                return Err(ManagerError::SecretUnavailable);
            }
        }

        if validated.is_empty() {
            return Ok(());
        }

        // 先把整批密文写入私有 staging，再逐个发布；崩溃后可用相同候选幂等重试。
        let staging = self
            .root
            .join(".staging")
            .join(format!("secrets-{}", Uuid::new_v4()));
        fs::create_dir(&staging)?;
        for secret in &validated {
            let ciphertext = self.protector.protect(&secret.reference, &secret.value)?;
            write_new_synced(
                &staging.join(secret_file_name(&secret.reference)),
                &ciphertext,
            )?;
        }
        for secret in &validated {
            fs::rename(
                staging.join(secret_file_name(&secret.reference)),
                self.secret_path(&secret.reference),
            )?;
        }
        fs::remove_dir(&staging)?;
        Ok(())
    }

    fn verify_required_secrets(&self, required: &BTreeMap<Uuid, SecretRef>) -> Result<()> {
        for reference in required.values() {
            let ciphertext =
                read_bounded(&self.secret_path(reference), MAX_SECRET_CIPHERTEXT_BYTES)
                    .map_err(|_| ManagerError::SecretUnavailable)?;
            self.protector
                .unprotect(reference, &ciphertext)
                .map_err(|_| ManagerError::SecretUnavailable)?;
        }
        Ok(())
    }

    fn verify_pointer(&self, pointer: &GenerationPointer) -> Result<()> {
        let manifest = read_bounded(
            &self.generation_path(pointer.revision).join(MANIFEST_FILE),
            MAX_SIGNED_ENVELOPE_BYTES,
        )?;
        if pointer.manifest_sha256 != sha256_hex(&manifest) {
            return Err(ManagerError::GenerationCorrupt);
        }
        Ok(())
    }

    fn next_revision(&self) -> Result<u64> {
        let mut maximum = 0_u64;
        for entry in fs::read_dir(self.root.join("generations"))? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            if let Some(value) = entry.file_name().to_str().and_then(parse_revision_name) {
                maximum = maximum.max(value);
            }
        }
        maximum
            .checked_add(1)
            .ok_or_else(|| ManagerError::InvalidState("revision 溢出".to_owned()))
    }

    fn generation_path(&self, revision: u64) -> PathBuf {
        self.root
            .join("generations")
            .join(format!("{revision:020}"))
    }

    fn secret_path(&self, reference: &SecretRef) -> PathBuf {
        self.root.join("secrets").join(secret_file_name(reference))
    }

    fn lock(&self) -> Result<File> {
        let file = open_store_lock(&self.root)?;
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                ManagerError::StoreLocked
            } else {
                ManagerError::Io(error)
            }
        })?;
        Ok(file)
    }

    fn read_head(&self, name: &str) -> Result<Option<GenerationPointer>> {
        let (_, valid) = self.valid_head_slots(name)?;
        Ok(valid
            .into_iter()
            .max_by_key(|(_, pointer)| pointer.head_epoch)
            .map(|(_, pointer)| pointer))
    }

    fn write_head(&self, name: &str, revision: u64, manifest_sha256: &str) -> Result<()> {
        let (_, valid) = self.valid_head_slots(name)?;
        let next_epoch = valid
            .iter()
            .map(|(_, pointer)| pointer.head_epoch)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ManagerError::InvalidState("HEAD epoch 溢出".to_owned()))?;
        let occupied: BTreeSet<_> = valid.iter().map(|(slot, _)| *slot).collect();
        let target_slot = if !occupied.contains(&0) {
            0
        } else if !occupied.contains(&1) {
            1
        } else {
            valid
                .iter()
                .min_by_key(|(_, pointer)| pointer.head_epoch)
                .map(|(slot, _)| *slot)
                .ok_or(ManagerError::GenerationCorrupt)?
        };
        let pointer = GenerationPointer {
            head_epoch: next_epoch,
            revision,
            manifest_sha256: manifest_sha256.to_owned(),
        };
        let payload = serde_json::to_vec(&pointer)?;
        let bytes = self.sign_envelope(&head_hmac_domain(name), &payload)?;
        let temporary = self
            .root
            .join(format!(".{name}.{target_slot}.{}.tmp", Uuid::new_v4()));
        write_new_synced(&temporary, &bytes)?;
        atomic_replace(&temporary, &self.root.join(format!("{name}.{target_slot}")))
    }

    fn valid_head_slots(&self, name: &str) -> Result<(bool, Vec<(usize, GenerationPointer)>)> {
        let mut saw_slot = false;
        let mut valid = Vec::new();
        for slot in 0..=1 {
            let path = self.root.join(format!("{name}.{slot}"));
            if !path.exists() {
                continue;
            }
            saw_slot = true;
            let candidate = read_bounded(&path, MAX_HEAD_ENVELOPE_BYTES)
                .ok()
                .and_then(|bytes| self.verify_envelope(&head_hmac_domain(name), &bytes).ok())
                .and_then(|payload| serde_json::from_slice::<GenerationPointer>(&payload).ok());
            if let Some(pointer) = candidate {
                if self.verify_pointer(&pointer).is_ok()
                    && self.read_generation_unlocked(pointer.revision).is_ok()
                {
                    valid.push((slot, pointer));
                }
            }
        }
        if valid.len() == 2
            && valid[0].1.head_epoch == valid[1].1.head_epoch
            && valid[0].1 != valid[1].1
        {
            return Err(ManagerError::GenerationCorrupt);
        }
        if saw_slot && valid.is_empty() {
            return Err(ManagerError::GenerationCorrupt);
        }
        Ok((saw_slot, valid))
    }

    fn sign_envelope(&self, domain: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() > MAX_SIGNED_PAYLOAD_BYTES {
            return Err(ManagerError::Integrity);
        }
        let mut mac = HmacSha256::new_from_slice(self.auth_key.as_slice())
            .map_err(|_| ManagerError::Integrity)?;
        update_framed_hmac(&mut mac, domain, payload);
        let envelope = SignedEnvelope {
            envelope_version: 1,
            payload_base64: STANDARD.encode(payload),
            hmac_sha256_base64: STANDARD.encode(mac.finalize().into_bytes()),
        };
        let bytes = serde_json::to_vec(&envelope)?;
        if bytes.len() > MAX_SIGNED_ENVELOPE_BYTES {
            return Err(ManagerError::Integrity);
        }
        Ok(bytes)
    }

    fn verify_envelope(&self, domain: &[u8], bytes: &[u8]) -> Result<Vec<u8>> {
        if bytes.len() > MAX_SIGNED_ENVELOPE_BYTES {
            return Err(ManagerError::Integrity);
        }
        let envelope: SignedEnvelope =
            serde_json::from_slice(bytes).map_err(|_| ManagerError::Integrity)?;
        if envelope.envelope_version != 1 {
            return Err(ManagerError::Integrity);
        }
        let payload = STANDARD
            .decode(envelope.payload_base64)
            .map_err(|_| ManagerError::Integrity)?;
        if payload.len() > MAX_SIGNED_PAYLOAD_BYTES {
            return Err(ManagerError::Integrity);
        }
        let tag = STANDARD
            .decode(envelope.hmac_sha256_base64)
            .map_err(|_| ManagerError::Integrity)?;
        if tag.len() != 32 {
            return Err(ManagerError::Integrity);
        }
        let mut mac = HmacSha256::new_from_slice(self.auth_key.as_slice())
            .map_err(|_| ManagerError::Integrity)?;
        update_framed_hmac(&mut mac, domain, &payload);
        mac.verify_slice(&tag)
            .map_err(|_| ManagerError::Integrity)?;
        Ok(payload)
    }
}

#[cfg(windows)]
fn read_vault_metadata(path: &Path) -> Result<VaultMetadata> {
    let metadata: VaultMetadata = serde_json::from_slice(&read_bounded(path, MAX_METADATA_BYTES)?)?;
    if metadata.schema_version != 1 || metadata.vault_id.is_nil() {
        return Err(ManagerError::InvalidState(
            "不支持的 vault metadata".to_owned(),
        ));
    }
    Ok(metadata)
}

fn open_store_lock(root: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join("store.lock"))?)
}

fn load_or_initialize_auth_key<P: SecretProtector>(
    root: &Path,
    protector: &P,
) -> Result<Zeroizing<Vec<u8>>> {
    let metadata_path = root.join(STORE_META_FILE);
    let pending_metadata_path = root.join(STORE_META_PENDING_FILE);
    let auth_key_path = root.join(AUTH_KEY_FILE);
    if metadata_path.exists() {
        if pending_metadata_path.exists() {
            return Err(ManagerError::Integrity);
        }
        return load_auth_key(&metadata_path, &auth_key_path, protector);
    }

    if pending_metadata_path.exists() {
        match load_auth_key(&pending_metadata_path, &auth_key_path, protector) {
            Ok(key) => {
                atomic_replace(&pending_metadata_path, &metadata_path)?;
                return Ok(key);
            }
            Err(_) if store_is_pristine(root, true, true)? => {
                // 初始化尚未提交且没有任何状态，可以安全丢弃损坏的 bootstrap 临时文件。
                fs::remove_file(&pending_metadata_path)?;
                if auth_key_path.exists() {
                    fs::remove_file(&auth_key_path)?;
                }
            }
            Err(_) => return Err(ManagerError::Integrity),
        }
    }

    if auth_key_path.exists() {
        if !store_is_pristine(root, true, false)? {
            return Err(ManagerError::InvalidState(
                "store.meta 缺失，但状态库包含既有数据".to_owned(),
            ));
        }
        // `store.meta` 是初始化提交标记；只有完全空的 Vault 才能清理此前中断留下的孤立 key。
        fs::remove_file(&auth_key_path)?;
    }
    if !store_is_pristine(root, false, false)? {
        return Err(ManagerError::InvalidState(
            "store.meta 缺失，但状态库包含既有数据".to_owned(),
        ));
    }

    let auth_key_ref = SecretRef::random(SecretPurpose::ManifestHmac);
    let mut key = Zeroizing::new(vec![0_u8; 32]);
    getrandom::fill(key.as_mut_slice()).map_err(|_| ManagerError::SecretProtection)?;
    let protected_key = SecretValue::new(STANDARD.encode(key.as_slice()));

    let ciphertext = protector.protect(&auth_key_ref, &protected_key)?;
    write_new_synced(&auth_key_path, &ciphertext)?;
    let metadata = StoreMetadata {
        schema_version: 1,
        integrity_format: INTEGRITY_FORMAT.to_owned(),
        auth_key_ref,
    };
    write_new_synced(
        &pending_metadata_path,
        &serde_json::to_vec_pretty(&metadata)?,
    )?;
    atomic_replace(&pending_metadata_path, &metadata_path)?;
    Ok(key)
}

fn load_auth_key<P: SecretProtector>(
    metadata_path: &Path,
    auth_key_path: &Path,
    protector: &P,
) -> Result<Zeroizing<Vec<u8>>> {
    let metadata: StoreMetadata =
        serde_json::from_slice(&read_bounded(metadata_path, MAX_METADATA_BYTES)?)
            .map_err(|_| ManagerError::Integrity)?;
    if metadata.schema_version != 1
        || metadata.integrity_format != INTEGRITY_FORMAT
        || metadata.auth_key_ref.id.is_nil()
        || metadata.auth_key_ref.purpose != SecretPurpose::ManifestHmac
        || metadata.auth_key_ref.envelope_version != 1
        || !auth_key_path.is_file()
    {
        return Err(ManagerError::Integrity);
    }
    let ciphertext = read_bounded(auth_key_path, MAX_SECRET_CIPHERTEXT_BYTES)?;
    let encoded = protector
        .unprotect(&metadata.auth_key_ref, &ciphertext)
        .map_err(|_| ManagerError::Integrity)?;
    decode_auth_key(&encoded)
}

fn decode_auth_key(encoded: &SecretValue) -> Result<Zeroizing<Vec<u8>>> {
    let decoded = STANDARD
        .decode(encoded.expose_secret())
        .map_err(|_| ManagerError::Integrity)?;
    let canonical = SecretValue::new(STANDARD.encode(&decoded));
    if decoded.len() != 32 || canonical.expose_secret() != encoded.expose_secret() {
        return Err(ManagerError::Integrity);
    }
    Ok(Zeroizing::new(decoded))
}

fn store_is_pristine(
    root: &Path,
    allow_orphan_auth_key: bool,
    allow_pending_metadata: bool,
) -> Result<bool> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Ok(false);
        };
        match name {
            "generations" | "secrets" | ".staging" => {
                if !entry.file_type()?.is_dir() || fs::read_dir(entry.path())?.next().is_some() {
                    return Ok(false);
                }
            }
            "store.lock" | "vault.meta" => {
                if !entry.file_type()?.is_file() {
                    return Ok(false);
                }
            }
            AUTH_KEY_FILE if allow_orphan_auth_key => {
                if !entry.file_type()?.is_file() {
                    return Ok(false);
                }
            }
            STORE_META_PENDING_FILE if allow_pending_metadata => {
                if !entry.file_type()?.is_file() {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
    }
    Ok(true)
}

fn head_hmac_domain(name: &str) -> Vec<u8> {
    let mut domain = Vec::with_capacity(HEAD_HMAC_DOMAIN.len() + name.len());
    domain.extend_from_slice(HEAD_HMAC_DOMAIN);
    domain.extend_from_slice(name.as_bytes());
    domain
}

fn manifest_hmac_domain(revision: u64) -> Vec<u8> {
    let mut domain = Vec::with_capacity(MANIFEST_HMAC_DOMAIN.len() + 8);
    domain.extend_from_slice(MANIFEST_HMAC_DOMAIN);
    domain.extend_from_slice(&revision.to_le_bytes());
    domain
}

fn update_framed_hmac(mac: &mut HmacSha256, domain: &[u8], payload: &[u8]) {
    mac.update(b"HK-Proton-HMAC-envelope-v1\0");
    mac.update(&(domain.len() as u64).to_le_bytes());
    mac.update(domain);
    mac.update(&(payload.len() as u64).to_le_bytes());
    mac.update(payload);
}

fn secret_file_name(reference: &SecretRef) -> String {
    format!("{}.dpapi", reference.id)
}

fn collect_state_secret_refs(state: &AppState) -> Result<BTreeMap<Uuid, SecretRef>> {
    let mut references = BTreeMap::new();
    for version in state
        .first_hops
        .iter()
        .chain(state.proton_nodes.iter())
        .flat_map(|resource| resource.versions.iter())
    {
        insert_secret_ref(&mut references, &version.private_key)?;
        if let Some(reference) = &version.preshared_key {
            insert_secret_ref(&mut references, reference)?;
        }
    }
    Ok(references)
}

fn insert_secret_ref(
    references: &mut BTreeMap<Uuid, SecretRef>,
    reference: &SecretRef,
) -> Result<()> {
    if let Some(existing) = references.insert(reference.id, reference.clone()) {
        if existing.purpose != reference.purpose {
            return Err(ManagerError::SecretUnavailable);
        }
    }
    Ok(())
}

fn parse_revision_name(value: &str) -> Option<u64> {
    (value.len() == 20).then(|| value.parse().ok()).flatten()
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(ManagerError::Integrity);
    }
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(maximum));
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(ManagerError::Integrity);
    }
    Ok(bytes)
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
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

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: 两个 UTF-16 缓冲区均以 NUL 结尾，并在调用期间保持有效。
    let success = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if success == 0 {
        return Err(ManagerError::AtomicReplace);
    }
    Ok(())
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination).map_err(|_| ManagerError::AtomicReplace)
}
