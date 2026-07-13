#![cfg(windows)]

use hk_proton_core::SecretValue;
use hk_proton_manager::{
    DpapiCurrentUserProtector, ManagerError, SecretProtector, SecretPurpose, SecretRef,
};
use uuid::Uuid;

#[test]
fn current_user_dpapi_round_trips_and_binds_context() {
    let protector = DpapiCurrentUserProtector::new(
        Uuid::parse_str("018f7f8e-7d80-7c2f-b5ab-6bc801234567").unwrap(),
    );
    let reference = SecretRef::random(SecretPurpose::WireGuardPrivateKey);
    let marker = "SYNTHETIC-DPAPI-SECRET-MUST-NOT-APPEAR";
    let encrypted = protector
        .protect(&reference, &SecretValue::new(marker))
        .unwrap();
    assert!(
        !encrypted
            .windows(marker.len())
            .any(|item| item == marker.as_bytes())
    );
    assert_eq!(
        protector
            .unprotect(&reference, &encrypted)
            .unwrap()
            .expose_secret(),
        marker
    );

    let wrong_reference = SecretRef::random(SecretPurpose::WireGuardPrivateKey);
    assert!(matches!(
        protector.unprotect(&wrong_reference, &encrypted),
        Err(ManagerError::SecretProtection)
    ));

    let wrong_purpose = SecretRef {
        id: reference.id,
        purpose: SecretPurpose::WireGuardPresharedKey,
        envelope_version: reference.envelope_version,
    };
    assert!(matches!(
        protector.unprotect(&wrong_purpose, &encrypted),
        Err(ManagerError::SecretProtection)
    ));

    let wrong_vault = DpapiCurrentUserProtector::new(Uuid::new_v4());
    assert!(matches!(
        wrong_vault.unprotect(&reference, &encrypted),
        Err(ManagerError::SecretProtection)
    ));
}

#[test]
fn current_user_dpapi_rejects_tampering() {
    let protector = DpapiCurrentUserProtector::new(Uuid::new_v4());
    let reference = SecretRef::random(SecretPurpose::RuntimeProfile);
    let mut encrypted = protector
        .protect(&reference, &SecretValue::new("synthetic-runtime-yaml"))
        .unwrap();
    let middle = encrypted.len() / 2;
    encrypted[middle] ^= 0x5a;
    assert!(matches!(
        protector.unprotect(&reference, &encrypted),
        Err(ManagerError::SecretProtection)
    ));
}
