use std::net::IpAddr;

use ipnet::IpNet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterKind {
    OwnedHkProton,
    Physical,
    Tailscale,
    Wsl,
    Docker,
    HyperV,
    Tap,
    OtherVirtual,
}

#[derive(Clone, Debug)]
pub struct AdapterSnapshot {
    pub interface_id: String,
    pub kind: AdapterKind,
    pub operational_up: bool,
    pub ownership_verified: bool,
    pub routes: Vec<IpNet>,
    /// 对一组分散公网样本执行只读 BestRoute 后，命中该接口的数量。
    pub public_best_route_hits: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Debug)]
pub struct PortBinding {
    pub protocol: PortProtocol,
    pub address: IpAddr,
    pub port: u16,
    pub owner_pid: u32,
}

#[derive(Clone, Debug)]
pub struct RequiredPort {
    pub protocol: PortProtocol,
    pub address: IpAddr,
    pub port: u16,
    /// 初次启动必须为 `None`，因此任何占用都会阻断；运行中只允许精确的自有 session PID。
    pub allowed_owner_pid: Option<u32>,
}

#[derive(Clone, Debug, Default)]
pub struct PreflightSnapshot {
    pub capture_complete: bool,
    pub routes_stable: bool,
    pub clash_like_processes: usize,
    pub adapters: Vec<AdapterSnapshot>,
    pub port_bindings: Vec<PortBinding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConflictDecision {
    Allow,
    Warn,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictReason {
    DetectionIncomplete,
    OtherPublicTunActive,
    TailscaleExitNode,
    StaleOwnArtifact,
    ClashProcessPresent,
    PortConflict,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictFinding {
    pub decision: ConflictDecision,
    pub reason: ConflictReason,
    /// 只保存稳定接口 ID，不记录完整进程路径或配置内容。
    pub interface_id: Option<String>,
    pub port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictReport {
    pub decision: ConflictDecision,
    pub findings: Vec<ConflictFinding>,
}

impl ConflictReport {
    pub fn can_start(&self) -> bool {
        self.decision != ConflictDecision::Block
    }
}

pub fn evaluate_conflicts(
    snapshot: &PreflightSnapshot,
    required_ports: &[RequiredPort],
) -> ConflictReport {
    let mut findings = Vec::new();
    if !snapshot.capture_complete || !snapshot.routes_stable {
        findings.push(finding(
            ConflictDecision::Block,
            ConflictReason::DetectionIncomplete,
            None,
            None,
        ));
    }

    let mut external_public_capture = false;
    for adapter in &snapshot.adapters {
        if !adapter.operational_up {
            continue;
        }
        if adapter.kind == AdapterKind::OwnedHkProton {
            if !adapter.ownership_verified {
                findings.push(finding(
                    ConflictDecision::Block,
                    ConflictReason::StaleOwnArtifact,
                    Some(adapter.interface_id.clone()),
                    None,
                ));
            }
            continue;
        }
        if adapter.kind == AdapterKind::Physical {
            continue;
        }

        let ipv4_coverage = merged_ipv4_coverage(&adapter.routes);
        // 路由表本身已经是只读、权威的本机捕获范围。不能要求 BestRoute
        // 样本同时命中，否则由多条 /2、/3 等拆分出的全局 TUN 会被漏放。
        // 半数公网覆盖已足以按保守策略阻断；BestRoute 命中仍可独立触发。
        let captures_ipv4 = ipv4_coverage >= (1_u64 << 31) || adapter.public_best_route_hits >= 3;
        let captures_ipv6 = captures_global_ipv6(&adapter.routes);
        if captures_ipv4 || captures_ipv6 {
            external_public_capture = true;
            let reason = if adapter.kind == AdapterKind::Tailscale {
                ConflictReason::TailscaleExitNode
            } else {
                ConflictReason::OtherPublicTunActive
            };
            findings.push(finding(
                ConflictDecision::Block,
                reason,
                Some(adapter.interface_id.clone()),
                None,
            ));
        }
    }

    if snapshot.clash_like_processes > 0 && !external_public_capture {
        findings.push(finding(
            ConflictDecision::Warn,
            ConflictReason::ClashProcessPresent,
            None,
            None,
        ));
    }

    for required in required_ports {
        if snapshot.port_bindings.iter().any(|binding| {
            binding.protocol == required.protocol
                && binding.port == required.port
                && addresses_conflict(binding.address, required.address)
                && required.allowed_owner_pid != Some(binding.owner_pid)
        }) {
            findings.push(finding(
                ConflictDecision::Block,
                ConflictReason::PortConflict,
                None,
                Some(required.port),
            ));
        }
    }

    let decision = findings
        .iter()
        .map(|finding| finding.decision)
        .max()
        .unwrap_or(ConflictDecision::Allow);
    ConflictReport { decision, findings }
}

fn finding(
    decision: ConflictDecision,
    reason: ConflictReason,
    interface_id: Option<String>,
    port: Option<u16>,
) -> ConflictFinding {
    ConflictFinding {
        decision,
        reason,
        interface_id,
        port,
    }
}

fn merged_ipv4_coverage(routes: &[IpNet]) -> u64 {
    let mut ranges: Vec<(u64, u64)> = routes
        .iter()
        .filter_map(|route| match route {
            IpNet::V4(network) => Some((
                u32::from(network.network()) as u64,
                u32::from(network.broadcast()) as u64,
            )),
            IpNet::V6(_) => None,
        })
        .collect();
    ranges.sort_unstable();
    let mut total = 0_u64;
    let mut current: Option<(u64, u64)> = None;
    for (start, end) in ranges {
        match current {
            None => current = Some((start, end)),
            Some((current_start, current_end)) if start <= current_end.saturating_add(1) => {
                current = Some((current_start, current_end.max(end)));
            }
            Some((current_start, current_end)) => {
                total += current_end - current_start + 1;
                current = Some((start, end));
            }
        }
    }
    if let Some((start, end)) = current {
        total += end - start + 1;
    }
    total
}

fn captures_global_ipv6(routes: &[IpNet]) -> bool {
    routes.iter().any(|route| match route {
        IpNet::V4(_) => false,
        IpNet::V6(network) => network.prefix_len() <= 2,
    })
}

fn addresses_conflict(existing: IpAddr, required: IpAddr) -> bool {
    if existing == required || existing.is_unspecified() || required.is_unspecified() {
        return true;
    }
    // IPv6 通配监听可能启用 dual-stack，保守视为与任意 IPv4 同端口冲突。
    (matches!(existing, IpAddr::V6(address) if address.is_unspecified())
        && matches!(required, IpAddr::V4(_)))
        || (matches!(required, IpAddr::V6(address) if address.is_unspecified())
            && matches!(existing, IpAddr::V4(_)))
}
