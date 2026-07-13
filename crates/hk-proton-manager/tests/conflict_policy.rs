use std::net::IpAddr;

use hk_proton_manager::{
    AdapterKind, AdapterSnapshot, ConflictDecision, ConflictReason, PortBinding, PortProtocol,
    PreflightSnapshot, RequiredPort, evaluate_conflicts,
};

#[test]
fn blocks_a_current_style_public_capture_but_ignores_internal_overlays() {
    let snapshot = PreflightSnapshot {
        capture_complete: true,
        routes_stable: true,
        clash_like_processes: 3,
        adapters: vec![
            adapter(
                "meta-tunnel",
                AdapterKind::OtherVirtual,
                true,
                &["0.0.0.0/3", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1"],
                4,
            ),
            adapter(
                "tailscale",
                AdapterKind::Tailscale,
                true,
                &["100.64.0.0/10", "fd7a:115c:a1e0::/48"],
                0,
            ),
            adapter("wsl", AdapterKind::Wsl, true, &["172.28.0.0/20"], 0),
            // 断开的 TAP 即使残留 /0 也不阻断。
            adapter("old-tap", AdapterKind::Tap, false, &["0.0.0.0/0"], 0),
        ],
        port_bindings: Vec::new(),
    };
    let report = evaluate_conflicts(&snapshot, &[]);
    assert_eq!(report.decision, ConflictDecision::Block);
    assert!(report.findings.iter().any(|finding| {
        finding.reason == ConflictReason::OtherPublicTunActive
            && finding.interface_id.as_deref() == Some("meta-tunnel")
    }));
    assert!(!report.can_start());
}

#[test]
fn blocks_split_public_capture_even_without_best_route_samples() {
    let snapshot = PreflightSnapshot {
        capture_complete: true,
        routes_stable: true,
        adapters: vec![adapter(
            "split-tunnel",
            AdapterKind::OtherVirtual,
            true,
            &["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"],
            0,
        )],
        ..PreflightSnapshot::default()
    };

    let report = evaluate_conflicts(&snapshot, &[]);
    assert_eq!(report.decision, ConflictDecision::Block);
    assert!(report.findings.iter().any(|finding| {
        finding.reason == ConflictReason::OtherPublicTunActive
            && finding.interface_id.as_deref() == Some("split-tunnel")
    }));
}

#[test]
fn allows_physical_default_and_warns_for_clash_without_an_active_tun() {
    let snapshot = PreflightSnapshot {
        capture_complete: true,
        routes_stable: true,
        clash_like_processes: 1,
        adapters: vec![adapter(
            "wifi",
            AdapterKind::Physical,
            true,
            &["0.0.0.0/0"],
            4,
        )],
        port_bindings: Vec::new(),
    };
    let report = evaluate_conflicts(&snapshot, &[]);
    assert_eq!(report.decision, ConflictDecision::Warn);
    assert!(report.can_start());
    assert_eq!(
        report.findings[0].reason,
        ConflictReason::ClashProcessPresent
    );
}

#[test]
fn distinguishes_tailscale_exit_node_and_stale_owned_artifacts() {
    let exit_node = PreflightSnapshot {
        capture_complete: true,
        routes_stable: true,
        adapters: vec![adapter(
            "tailscale",
            AdapterKind::Tailscale,
            true,
            &["0.0.0.0/0", "::/0"],
            4,
        )],
        ..PreflightSnapshot::default()
    };
    let report = evaluate_conflicts(&exit_node, &[]);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.reason == ConflictReason::TailscaleExitNode)
    );

    let stale = PreflightSnapshot {
        capture_complete: true,
        routes_stable: true,
        adapters: vec![AdapterSnapshot {
            interface_id: "claimed-hk-proton".to_owned(),
            kind: AdapterKind::OwnedHkProton,
            operational_up: true,
            ownership_verified: false,
            routes: vec!["0.0.0.0/0".parse().unwrap()],
            public_best_route_hits: 4,
        }],
        ..PreflightSnapshot::default()
    };
    let report = evaluate_conflicts(&stale, &[]);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.reason == ConflictReason::StaleOwnArtifact)
    );
}

#[test]
fn blocks_incomplete_detection_and_external_port_bindings() {
    let snapshot = PreflightSnapshot {
        capture_complete: false,
        routes_stable: false,
        port_bindings: vec![PortBinding {
            protocol: PortProtocol::Tcp,
            address: "0.0.0.0".parse::<IpAddr>().unwrap(),
            port: 19090,
            owner_pid: 1234,
        }],
        ..PreflightSnapshot::default()
    };
    let required = [RequiredPort {
        protocol: PortProtocol::Tcp,
        address: "127.0.0.1".parse().unwrap(),
        port: 19090,
        allowed_owner_pid: None,
    }];
    let report = evaluate_conflicts(&snapshot, &required);
    assert_eq!(report.decision, ConflictDecision::Block);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.reason == ConflictReason::DetectionIncomplete)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.reason == ConflictReason::PortConflict)
    );
}

#[test]
fn only_allows_a_port_owned_by_the_exact_active_session() {
    let snapshot = PreflightSnapshot {
        capture_complete: true,
        routes_stable: true,
        port_bindings: vec![PortBinding {
            protocol: PortProtocol::Tcp,
            address: "127.0.0.1".parse().unwrap(),
            port: 19090,
            owner_pid: 4242,
        }],
        ..PreflightSnapshot::default()
    };
    let initial_start = [RequiredPort {
        protocol: PortProtocol::Tcp,
        address: "127.0.0.1".parse().unwrap(),
        port: 19090,
        allowed_owner_pid: None,
    }];
    assert_eq!(
        evaluate_conflicts(&snapshot, &initial_start).decision,
        ConflictDecision::Block
    );

    let active_session = [RequiredPort {
        allowed_owner_pid: Some(4242),
        ..initial_start[0].clone()
    }];
    assert_eq!(
        evaluate_conflicts(&snapshot, &active_session).decision,
        ConflictDecision::Allow
    );
}

fn adapter(
    id: &str,
    kind: AdapterKind,
    up: bool,
    routes: &[&str],
    public_best_route_hits: u8,
) -> AdapterSnapshot {
    AdapterSnapshot {
        interface_id: id.to_owned(),
        kind,
        operational_up: up,
        ownership_verified: false,
        routes: routes.iter().map(|route| route.parse().unwrap()).collect(),
        public_best_route_hits,
    }
}
