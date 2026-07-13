use std::collections::{BTreeMap, BTreeSet};

use hk_proton_manager::{
    ApiContractViolation, ExpectedRuntime, ManagerError, reconcile_api_snapshot_json,
    reconcile_api_snapshot_json_detailed,
};

#[test]
fn reconciles_static_api_snapshots_without_opening_a_socket() {
    let expected = expected_runtime();
    let report = reconcile_api_snapshot_json(
        r#"{"meta":true,"version":"v1.19.28"}"#,
        CONFIG_RESPONSE,
        PROXIES_RESPONSE,
        &expected,
    )
    .unwrap();
    assert_eq!(report.version.version, "v1.19.28");
    assert_eq!(report.proxy_count, 5);
    assert_eq!(report.selectors, expected.selectors);
}

#[test]
fn rejects_wrong_version_unsafe_config_and_malformed_json() {
    let expected = expected_runtime();
    assert!(matches!(
        reconcile_api_snapshot_json(
            r#"{"meta":true,"version":"v1.19.29"}"#,
            CONFIG_RESPONSE,
            PROXIES_RESPONSE,
            &expected,
        ),
        Err(ManagerError::ApiContract)
    ));
    assert!(matches!(
        reconcile_api_snapshot_json(
            r#"{"meta":true,"version":"v1.19.28"}"#,
            &CONFIG_RESPONSE.replace("\"allow-lan\": false", "\"allow-lan\": true"),
            PROXIES_RESPONSE,
            &expected,
        ),
        Err(ManagerError::ApiContract)
    ));
    assert!(matches!(
        reconcile_api_snapshot_json("{", CONFIG_RESPONSE, PROXIES_RESPONSE, &expected),
        Err(ManagerError::ApiContract)
    ));
}

#[test]
fn classifies_tun_creation_failure_without_exposing_runtime_data() {
    let expected = expected_runtime();
    let disabled = CONFIG_RESPONSE.replace("\"enable\": true", "\"enable\": false");
    assert_eq!(
        reconcile_api_snapshot_json_detailed(
            r#"{"meta":true,"version":"v1.19.28"}"#,
            &disabled,
            PROXIES_RESPONSE,
            &expected,
        ),
        Err(ApiContractViolation::TunDisabled)
    );
}

#[test]
fn identifies_the_api_endpoint_with_an_incompatible_payload() {
    let expected = expected_runtime();
    assert_eq!(
        reconcile_api_snapshot_json_detailed(
            r#"{"meta":true,"version":"v1.19.28"}"#,
            "{}",
            PROXIES_RESPONSE,
            &expected,
        ),
        Err(ApiContractViolation::InvalidConfigPayload)
    );
    assert_eq!(
        reconcile_api_snapshot_json_detailed(
            r#"{"meta":true,"version":"v1.19.28"}"#,
            CONFIG_RESPONSE,
            r#"{"proxies":null}"#,
            &expected,
        ),
        Err(ApiContractViolation::InvalidProxiesPayload)
    );
}

fn expected_runtime() -> ExpectedRuntime {
    ExpectedRuntime {
        tun_enabled: true,
        mixed_port: 17890,
        tun_device: "HK-Proton".to_owned(),
        required_proxies: BTreeSet::from([
            "FH-fh-hk".to_owned(),
            "PN-proton-jp".to_owned(),
            "FirstHopSelector".to_owned(),
            "ProtonNodes".to_owned(),
            "HK-Proton-Outlet".to_owned(),
        ]),
        selectors: BTreeMap::from([
            ("FirstHopSelector".to_owned(), "FH-fh-hk".to_owned()),
            ("ProtonNodes".to_owned(), "PN-proton-jp".to_owned()),
            ("HK-Proton-Outlet".to_owned(), "ProtonNodes".to_owned()),
        ]),
    }
}

const PROXIES_RESPONSE: &str = r#"
{
  "proxies": {
    "FH-fh-hk": {"type":"WireGuard","all":[]},
    "PN-proton-jp": {"type":"WireGuard","all":[]},
    "FirstHopSelector": {"type":"Selector","now":"FH-fh-hk","all":["FH-fh-hk"]},
    "ProtonNodes": {"type":"Selector","now":"PN-proton-jp","all":["PN-proton-jp"]},
    "HK-Proton-Outlet": {"type":"Selector","now":"ProtonNodes","all":["ProtonNodes"]}
  }
}
"#;

const CONFIG_RESPONSE: &str = r#"
{
  "allow-lan": false,
  "bind-address": "127.0.0.1",
  "mode": "rule",
  "mixed-port": 17890,
  "ipv6": true,
  "tun": {
    "enable": true,
    "device": "HK-Proton",
    "auto-route": true,
    "strict-route": true,
    "dns-hijack": ["any:53", "tcp://any:53"]
  }
}
"#;
