use std::{ffi::c_void, ptr, slice};

use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
};
use zeroize::Zeroizing;

use crate::{ManagerError, Result, SecretProtector, SecretPurpose, SecretRef};
use hk_proton_core::SecretValue;

/// 使用当前 Windows 登录用户作用域的 DPAPI。
///
/// 有意不提供 LocalMachine 开关，避免把“同机任意用户可解密”误当成服务隔离。
pub struct DpapiCurrentUserProtector {
    vault_id: Uuid,
}

impl DpapiCurrentUserProtector {
    pub fn new(vault_id: Uuid) -> Self {
        Self { vault_id }
    }

    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    fn entropy(&self, reference: &SecretRef) -> Vec<u8> {
        let purpose = match reference.purpose {
            SecretPurpose::WireGuardPrivateKey => "wireguard-private-key",
            SecretPurpose::WireGuardPresharedKey => "wireguard-preshared-key",
            SecretPurpose::VlessUuid => "vless-uuid",
            SecretPurpose::RuntimeProfile => "runtime-profile",
            SecretPurpose::ManifestHmac => "manifest-hmac",
        };
        format!(
            "HK-Proton\0secret-v{}\0{}\0{}\0{purpose}",
            reference.envelope_version, self.vault_id, reference.id
        )
        .into_bytes()
    }
}

impl SecretProtector for DpapiCurrentUserProtector {
    fn protect(&self, reference: &SecretRef, plaintext: &SecretValue) -> Result<Vec<u8>> {
        if reference.envelope_version != 1 {
            return Err(ManagerError::SecretProtection);
        }
        let bytes = plaintext.expose_secret().as_bytes();
        if bytes.is_empty() || bytes.len() > u32::MAX as usize {
            return Err(ManagerError::SecretProtection);
        }
        let entropy = self.entropy(reference);
        let input = blob_from_slice(bytes)?;
        let entropy_blob = blob_from_slice(&entropy)?;
        let mut output = LocalBlob::new(false);

        // SAFETY: input/entropy 指向调用期间有效的只读缓冲区；output 是有效的空 DATA_BLOB。
        let success = unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                &entropy_blob,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.blob,
            )
        };
        if success == 0 {
            return Err(ManagerError::SecretProtection);
        }
        output.copy_bytes()
    }

    fn unprotect(&self, reference: &SecretRef, ciphertext: &[u8]) -> Result<SecretValue> {
        if reference.envelope_version != 1
            || ciphertext.is_empty()
            || ciphertext.len() > u32::MAX as usize
        {
            return Err(ManagerError::SecretProtection);
        }
        let entropy = self.entropy(reference);
        let input = blob_from_slice(ciphertext)?;
        let entropy_blob = blob_from_slice(&entropy)?;
        let mut output = LocalBlob::new(true);

        // SAFETY: input/entropy 指向调用期间有效的缓冲区；不请求 description 或 UI。
        let success = unsafe {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                &entropy_blob,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.blob,
            )
        };
        if success == 0 {
            return Err(ManagerError::SecretProtection);
        }
        let bytes = Zeroizing::new(output.copy_bytes()?);
        let text =
            std::str::from_utf8(bytes.as_slice()).map_err(|_| ManagerError::SecretProtection)?;
        Ok(SecretValue::new(text.to_owned()))
    }
}

fn blob_from_slice(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB> {
    let length = u32::try_from(bytes.len()).map_err(|_| ManagerError::SecretProtection)?;
    Ok(CRYPT_INTEGER_BLOB {
        cbData: length,
        pbData: bytes.as_ptr().cast_mut(),
    })
}

struct LocalBlob {
    blob: CRYPT_INTEGER_BLOB,
    sensitive: bool,
}

impl LocalBlob {
    fn new(sensitive: bool) -> Self {
        Self {
            blob: CRYPT_INTEGER_BLOB::default(),
            sensitive,
        }
    }

    fn copy_bytes(&self) -> Result<Vec<u8>> {
        if self.blob.cbData == 0 {
            return Ok(Vec::new());
        }
        if self.blob.pbData.is_null() && self.blob.cbData != 0 {
            return Err(ManagerError::SecretProtection);
        }
        // SAFETY: DPAPI 成功后保证 pbData 指向至少 cbData 字节，直至 LocalFree。
        let bytes = unsafe { slice::from_raw_parts(self.blob.pbData, self.blob.cbData as usize) };
        Ok(bytes.to_vec())
    }
}

impl Drop for LocalBlob {
    fn drop(&mut self) {
        if self.blob.pbData.is_null() {
            return;
        }
        if self.sensitive {
            for index in 0..self.blob.cbData as usize {
                // SAFETY: 缓冲区由 DPAPI 分配，长度为 cbData；volatile 防止清零被优化掉。
                unsafe { ptr::write_volatile(self.blob.pbData.add(index), 0) };
            }
        }
        // SAFETY: pbData 由 DPAPI 使用 LocalAlloc 分配，官方要求以 LocalFree 释放。
        unsafe {
            LocalFree(self.blob.pbData.cast::<c_void>());
        }
        self.blob.pbData = ptr::null_mut();
        self.blob.cbData = 0;
    }
}
