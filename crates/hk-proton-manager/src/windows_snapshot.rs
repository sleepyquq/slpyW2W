//! Windows 原生只读快照。
//!
//! 本模块只封装 `GetIfTable2`、`GetIpForwardTable2`、扩展 TCP/UDP 表与 ToolHelp 进程枚举；
//! 不包含任何修改网卡、路由、DNS、防火墙或进程状态的 API。

#![cfg(windows)]

use std::{
    collections::HashSet,
    ffi::c_void,
    fmt,
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr::{NonNull, addr_of, copy_nonoverlapping},
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use windows_sys::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES, GetLastError, HANDLE,
            INVALID_HANDLE_VALUE,
        },
        NetworkManagement::{
            IpHelper::{
                FreeMibTable, GetExtendedTcpTable, GetExtendedUdpTable, GetIfTable2,
                GetIpForwardTable2, MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IPFORWARD_ROW2,
                MIB_IPFORWARD_TABLE2, MIB_TCP_STATE_LISTEN, MIB_TCP6ROW_OWNER_PID,
                MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
                MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID,
                MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER, UDP_TABLE_OWNER_PID,
            },
            Ndis::IfOperStatusUp,
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET},
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
    },
    core::GUID,
};

use crate::{PortBinding, PortProtocol};

/// `MIB_IF_ROW2.InterfaceAndOperStatusFlags` 中的位。
pub const INTERFACE_FLAG_HARDWARE: u8 = 0x01;
pub const INTERFACE_FLAG_FILTER: u8 = 0x02;
pub const INTERFACE_FLAG_CONNECTOR_PRESENT: u8 = 0x04;
pub const INTERFACE_FLAG_NOT_AUTHENTICATED: u8 = 0x08;
pub const INTERFACE_FLAG_NOT_MEDIA_CONNECTED: u8 = 0x10;
pub const INTERFACE_FLAG_PAUSED: u8 = 0x20;
pub const INTERFACE_FLAG_LOW_POWER: u8 = 0x40;
pub const INTERFACE_FLAG_ENDPOINT: u8 = 0x80;

const MAX_EXTENDED_TABLE_BYTES: u32 = 32 * 1024 * 1024;
const EXTENDED_TABLE_ATTEMPTS: usize = 4;

#[derive(Clone, Debug)]
pub struct WindowsInterfaceSnapshot {
    /// 当前系统快照内用于关联路由的 LUID，不作为跨重启持久 ID。
    pub luid: u64,
    /// Windows 接口索引可能在禁用、启用后变化，只用于当前快照交叉校验。
    pub interface_index: u32,
    /// 规范化后的接口 GUID，供上层作为稳定接口 ID 使用。
    pub interface_guid: String,
    pub alias: String,
    pub description: String,
    pub mtu: u32,
    pub interface_type: u32,
    pub tunnel_type: i32,
    pub media_type: i32,
    pub physical_medium_type: i32,
    pub interface_flags: u8,
    pub oper_status: i32,
    pub admin_status: i32,
    pub media_connect_state: i32,
    pub operational_up: bool,
}

impl WindowsInterfaceSnapshot {
    pub fn hardware_interface(&self) -> bool {
        self.interface_flags & INTERFACE_FLAG_HARDWARE != 0
    }

    pub fn filter_interface(&self) -> bool {
        self.interface_flags & INTERFACE_FLAG_FILTER != 0
    }

    pub fn connector_present(&self) -> bool {
        self.interface_flags & INTERFACE_FLAG_CONNECTOR_PRESENT != 0
    }

    pub fn endpoint_interface(&self) -> bool {
        self.interface_flags & INTERFACE_FLAG_ENDPOINT != 0
    }
}

#[derive(Clone, Debug)]
pub struct WindowsRouteSnapshot {
    pub interface_luid: u64,
    pub interface_index: u32,
    pub destination: IpNet,
    pub next_hop: IpAddr,
    pub site_prefix_length: u8,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub metric: u32,
    pub protocol: i32,
    pub loopback: bool,
    pub autoconfigure_address: bool,
    pub publish: bool,
    pub immortal: bool,
    pub age: u32,
    pub origin: i32,
}

#[derive(Clone, Debug)]
pub struct WindowsProcessSnapshot {
    pub pid: u32,
    pub parent_pid: u32,
    pub thread_count: u32,
    pub base_priority: i32,
    /// ToolHelp 只返回可执行文件名；这里不会读取命令行、环境或配置文件。
    pub executable_name: String,
}

#[derive(Clone, Debug)]
pub struct UnmatchedRouteInterface {
    pub luid: u64,
    pub interface_index: u32,
}

#[derive(Clone, Debug)]
pub struct WindowsSnapshot {
    pub interfaces: Vec<WindowsInterfaceSnapshot>,
    pub routes: Vec<WindowsRouteSnapshot>,
    pub processes: Vec<WindowsProcessSnapshot>,
    /// 两张系统表不是原子快照；非空表示采集期间可能发生了接口或路由变化。
    pub unmatched_route_interfaces: Vec<UnmatchedRouteInterface>,
}

impl WindowsSnapshot {
    pub fn associations_complete(&self) -> bool {
        self.unmatched_route_interfaces.is_empty()
    }
}

pub trait SnapshotProvider {
    fn capture(&self) -> Result<WindowsSnapshot, WindowsSnapshotError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsNativeSnapshotProvider;

impl SnapshotProvider for WindowsNativeSnapshotProvider {
    fn capture(&self) -> Result<WindowsSnapshot, WindowsSnapshotError> {
        let interfaces = capture_interfaces()?;
        let routes = capture_routes()?;
        let processes = capture_processes()?;

        let interface_keys: HashSet<(u64, u32)> = interfaces
            .iter()
            .map(|interface| (interface.luid, interface.interface_index))
            .collect();
        let mut unmatched_keys: Vec<(u64, u32)> = routes
            .iter()
            .map(|route| (route.interface_luid, route.interface_index))
            .filter(|key| !interface_keys.contains(key))
            .collect();
        unmatched_keys.sort_unstable();
        unmatched_keys.dedup();

        Ok(WindowsSnapshot {
            interfaces,
            routes,
            processes,
            unmatched_route_interfaces: unmatched_keys
                .into_iter()
                .map(|(luid, interface_index)| UnmatchedRouteInterface {
                    luid,
                    interface_index,
                })
                .collect(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WindowsSnapshotError {
    Win32 { api: &'static str, code: u32 },
    InvalidData { field: &'static str },
}

impl WindowsSnapshotError {
    fn win32(api: &'static str, code: u32) -> Self {
        Self::Win32 { api, code }
    }

    fn invalid_data(field: &'static str) -> Self {
        Self::InvalidData { field }
    }
}

impl fmt::Display for WindowsSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Win32 { api, code } => write!(formatter, "{api} 失败，Win32 错误码 {code}"),
            Self::InvalidData { field } => write!(formatter, "Windows 返回了无效字段：{field}"),
        }
    }
}

impl std::error::Error for WindowsSnapshotError {}

/// IP Helper 分配的表只能由 `FreeMibTable` 释放。
struct OwnedMibTable<T>(NonNull<T>);

impl<T> OwnedMibTable<T> {
    fn new(pointer: *mut T, api: &'static str) -> Result<Self, WindowsSnapshotError> {
        NonNull::new(pointer)
            .map(Self)
            .ok_or_else(|| WindowsSnapshotError::invalid_data(api))
    }

    fn as_ptr(&self) -> *mut T {
        self.0.as_ptr()
    }
}

impl<T> Drop for OwnedMibTable<T> {
    fn drop(&mut self) {
        // SAFETY: 指针仅来自成功的 IP Helper 表分配，并且本所有者只释放一次。
        unsafe {
            FreeMibTable(self.0.as_ptr().cast::<c_void>());
        }
    }
}

/// ToolHelp 快照句柄只能由 `CloseHandle` 关闭。
struct OwnedSnapshotHandle(HANDLE);

impl OwnedSnapshotHandle {
    fn new(handle: HANDLE) -> Result<Self, WindowsSnapshotError> {
        if handle == INVALID_HANDLE_VALUE {
            // SAFETY: 紧跟在失败的 Win32 调用之后读取线程本地错误码。
            return Err(WindowsSnapshotError::win32(
                "CreateToolhelp32Snapshot",
                unsafe { GetLastError() },
            ));
        }
        Ok(Self(handle))
    }
}

impl Drop for OwnedSnapshotHandle {
    fn drop(&mut self) {
        // SAFETY: 构造函数已排除 INVALID_HANDLE_VALUE，句柄仅由本所有者关闭一次。
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn capture_interfaces() -> Result<Vec<WindowsInterfaceSnapshot>, WindowsSnapshotError> {
    let mut raw_table = std::ptr::null_mut();
    // SAFETY: 传入有效的输出指针；函数只读取本机接口表，不修改网络状态。
    let result = unsafe { GetIfTable2(&mut raw_table) };
    if result != 0 {
        return Err(WindowsSnapshotError::win32("GetIfTable2", result));
    }
    let table = OwnedMibTable::<MIB_IF_TABLE2>::new(raw_table, "GetIfTable2.Table")?;

    // SAFETY: 成功返回的表至少包含有效头部，生命周期由 `table` 守护。
    let entry_count = unsafe { (*table.as_ptr()).NumEntries as usize };
    // 不可用 `NumEntries` 后直接加四字节；Table 字段前可能存在 ABI 对齐填充。
    let first_entry = unsafe { addr_of!((*table.as_ptr()).Table).cast::<MIB_IF_ROW2>() };

    let mut interfaces = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        // SAFETY: Windows 为 NumEntries 个连续 MIB_IF_ROW2 预留了空间。
        let row = unsafe { &*first_entry.add(index) };
        // SAFETY: GetIfTable2 已初始化 NET_LUID union，读取其 Value 分支有效。
        let luid = unsafe { row.InterfaceLuid.Value };
        let interface_flags = row.InterfaceAndOperStatusFlags._bitfield;

        interfaces.push(WindowsInterfaceSnapshot {
            luid,
            interface_index: row.InterfaceIndex,
            interface_guid: format_guid(&row.InterfaceGuid),
            alias: wide_z(&row.Alias),
            description: wide_z(&row.Description),
            mtu: row.Mtu,
            interface_type: row.Type,
            tunnel_type: row.TunnelType,
            media_type: row.MediaType,
            physical_medium_type: row.PhysicalMediumType,
            interface_flags,
            oper_status: row.OperStatus,
            admin_status: row.AdminStatus,
            media_connect_state: row.MediaConnectState,
            operational_up: row.OperStatus == IfOperStatusUp,
        });
    }

    Ok(interfaces)
}

fn capture_routes() -> Result<Vec<WindowsRouteSnapshot>, WindowsSnapshotError> {
    let mut raw_table = std::ptr::null_mut();
    // SAFETY: 传入有效的输出指针；AF_UNSPEC 只请求 IPv4/IPv6 只读路由表。
    let result = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut raw_table) };
    if result != 0 {
        return Err(WindowsSnapshotError::win32("GetIpForwardTable2", result));
    }
    let table = OwnedMibTable::<MIB_IPFORWARD_TABLE2>::new(raw_table, "GetIpForwardTable2.Table")?;

    // SAFETY: 成功返回的表至少包含有效头部，生命周期由 `table` 守护。
    let entry_count = unsafe { (*table.as_ptr()).NumEntries as usize };
    let first_entry = unsafe { addr_of!((*table.as_ptr()).Table).cast::<MIB_IPFORWARD_ROW2>() };

    let mut routes = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        // SAFETY: Windows 为 NumEntries 个连续 MIB_IPFORWARD_ROW2 预留了空间。
        let row = unsafe { &*first_entry.add(index) };
        // SAFETY: GetIpForwardTable2 已初始化 NET_LUID union，读取其 Value 分支有效。
        let interface_luid = unsafe { row.InterfaceLuid.Value };
        let destination_address = decode_sockaddr(&row.DestinationPrefix.Prefix)?;
        let destination = match destination_address {
            IpAddr::V4(address) => Ipv4Net::new(address, row.DestinationPrefix.PrefixLength)
                .map(IpNet::V4)
                .map_err(|_| WindowsSnapshotError::invalid_data("DestinationPrefix.IPv4"))?,
            IpAddr::V6(address) => Ipv6Net::new(address, row.DestinationPrefix.PrefixLength)
                .map(IpNet::V6)
                .map_err(|_| WindowsSnapshotError::invalid_data("DestinationPrefix.IPv6"))?,
        };

        routes.push(WindowsRouteSnapshot {
            interface_luid,
            interface_index: row.InterfaceIndex,
            destination,
            next_hop: decode_sockaddr(&row.NextHop)?,
            site_prefix_length: row.SitePrefixLength,
            valid_lifetime: row.ValidLifetime,
            preferred_lifetime: row.PreferredLifetime,
            metric: row.Metric,
            protocol: row.Protocol,
            loopback: row.Loopback,
            autoconfigure_address: row.AutoconfigureAddress,
            publish: row.Publish,
            immortal: row.Immortal,
            age: row.Age,
            origin: row.Origin,
        });
    }

    Ok(routes)
}

fn capture_processes() -> Result<Vec<WindowsProcessSnapshot>, WindowsSnapshotError> {
    // SAFETY: 仅请求系统进程列表快照，不打开、终止或修改任何进程。
    let raw_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let snapshot = OwnedSnapshotHandle::new(raw_handle)?;

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    // SAFETY: entry 指向按 API 要求初始化了 dwSize 的可写结构。
    if unsafe { Process32FirstW(snapshot.0, &mut entry) } == 0 {
        // SAFETY: 紧跟在失败的 Win32 调用之后读取线程本地错误码。
        let error = unsafe { GetLastError() };
        if error == ERROR_NO_MORE_FILES {
            return Ok(Vec::new());
        }
        return Err(WindowsSnapshotError::win32("Process32FirstW", error));
    }

    let mut processes = Vec::new();
    loop {
        processes.push(WindowsProcessSnapshot {
            pid: entry.th32ProcessID,
            parent_pid: entry.th32ParentProcessID,
            thread_count: entry.cntThreads,
            base_priority: entry.pcPriClassBase,
            executable_name: wide_z(&entry.szExeFile),
        });

        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        // SAFETY: snapshot 仍有效，entry 是满足 API 尺寸要求的可写结构。
        if unsafe { Process32NextW(snapshot.0, &mut entry) } == 0 {
            // SAFETY: 紧跟在失败的 Win32 调用之后读取线程本地错误码。
            let error = unsafe { GetLastError() };
            if error == ERROR_NO_MORE_FILES {
                break;
            }
            return Err(WindowsSnapshotError::win32("Process32NextW", error));
        }
    }

    Ok(processes)
}

/// 只读采集系统当前的 IPv4/IPv6 TCP 与 UDP 本地端点及其所有者 PID。
///
/// 本函数仅调用 IP Helper 查询 API，不创建监听 socket，也不修改端口、进程或网络状态。
/// TCP 只查询 `TCP_TABLE_OWNER_PID_LISTENER`，避免把 `TIME_WAIT` 等已关闭连接的
/// 本地端口误判成监听冲突；相同的
/// `(协议, 地址, 端口, PID)` 会被折叠，便于上层对所需端口做稳定性比较。
pub fn capture_port_bindings() -> Result<Vec<PortBinding>, WindowsSnapshotError> {
    let mut bindings = Vec::new();
    bindings.extend(capture_tcp_v4_bindings()?);
    bindings.extend(capture_tcp_v6_bindings()?);
    bindings.extend(capture_udp_v4_bindings()?);
    bindings.extend(capture_udp_v6_bindings()?);
    bindings.sort_by_key(|binding| {
        (
            protocol_sort_key(binding.protocol),
            binding.address,
            binding.port,
            binding.owner_pid,
        )
    });
    bindings.dedup_by(|left, right| {
        left.protocol == right.protocol
            && left.address == right.address
            && left.port == right.port
            && left.owner_pid == right.owner_pid
    });
    Ok(bindings)
}

fn capture_tcp_v4_bindings() -> Result<Vec<PortBinding>, WindowsSnapshotError> {
    let buffer = query_extended_table("GetExtendedTcpTable(IPv4)", |table, size| {
        // SAFETY: 缓冲区和尺寸指针由 query_extended_table 管理；该 API 仅查询端点表。
        unsafe {
            GetExtendedTcpTable(
                table,
                size,
                0,
                u32::from(AF_INET),
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        }
    })?;
    let rows = parse_extended_rows::<MIB_TCPROW_OWNER_PID>(
        &buffer,
        offset_of!(MIB_TCPTABLE_OWNER_PID, table),
        "GetExtendedTcpTable(IPv4).Table",
    )?;
    Ok(rows.iter().filter_map(tcp_v4_binding).collect())
}

fn capture_tcp_v6_bindings() -> Result<Vec<PortBinding>, WindowsSnapshotError> {
    let buffer = query_extended_table("GetExtendedTcpTable(IPv6)", |table, size| {
        // SAFETY: 缓冲区和尺寸指针由 query_extended_table 管理；该 API 仅查询端点表。
        unsafe {
            GetExtendedTcpTable(
                table,
                size,
                0,
                u32::from(AF_INET6),
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        }
    })?;
    let rows = parse_extended_rows::<MIB_TCP6ROW_OWNER_PID>(
        &buffer,
        offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
        "GetExtendedTcpTable(IPv6).Table",
    )?;
    Ok(rows.iter().filter_map(tcp_v6_binding).collect())
}

fn capture_udp_v4_bindings() -> Result<Vec<PortBinding>, WindowsSnapshotError> {
    let buffer = query_extended_table("GetExtendedUdpTable(IPv4)", |table, size| {
        // SAFETY: 缓冲区和尺寸指针由 query_extended_table 管理；该 API 仅查询端点表。
        unsafe { GetExtendedUdpTable(table, size, 0, u32::from(AF_INET), UDP_TABLE_OWNER_PID, 0) }
    })?;
    let rows = parse_extended_rows::<MIB_UDPROW_OWNER_PID>(
        &buffer,
        offset_of!(MIB_UDPTABLE_OWNER_PID, table),
        "GetExtendedUdpTable(IPv4).Table",
    )?;
    Ok(rows.iter().map(udp_v4_binding).collect())
}

fn capture_udp_v6_bindings() -> Result<Vec<PortBinding>, WindowsSnapshotError> {
    let buffer = query_extended_table("GetExtendedUdpTable(IPv6)", |table, size| {
        // SAFETY: 缓冲区和尺寸指针由 query_extended_table 管理；该 API 仅查询端点表。
        unsafe { GetExtendedUdpTable(table, size, 0, u32::from(AF_INET6), UDP_TABLE_OWNER_PID, 0) }
    })?;
    let rows = parse_extended_rows::<MIB_UDP6ROW_OWNER_PID>(
        &buffer,
        offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
        "GetExtendedUdpTable(IPv6).Table",
    )?;
    Ok(rows.iter().map(udp_v6_binding).collect())
}

fn query_extended_table(
    api: &'static str,
    mut query: impl FnMut(*mut c_void, *mut u32) -> u32,
) -> Result<Vec<u8>, WindowsSnapshotError> {
    let mut size = 0_u32;
    let initial_result = query(std::ptr::null_mut(), &mut size);
    if initial_result != 0 && initial_result != ERROR_INSUFFICIENT_BUFFER {
        return Err(WindowsSnapshotError::win32(api, initial_result));
    }
    validate_extended_table_size(size, api)?;

    for _ in 0..EXTENDED_TABLE_ATTEMPTS {
        let allocated_size = size;
        let mut buffer = vec![0_u8; allocated_size as usize];
        let mut returned_size = allocated_size;
        let result = query(buffer.as_mut_ptr().cast::<c_void>(), &mut returned_size);
        if result == 0 {
            if returned_size > allocated_size {
                return Err(WindowsSnapshotError::invalid_data(api));
            }
            // 某些系统版本在成功时保留传入尺寸；两种形式都只暴露已分配的内存。
            if returned_size != 0 {
                buffer.truncate(returned_size as usize);
            }
            return Ok(buffer);
        }
        if result != ERROR_INSUFFICIENT_BUFFER {
            return Err(WindowsSnapshotError::win32(api, result));
        }
        validate_extended_table_size(returned_size, api)?;
        size = returned_size;
    }

    Err(WindowsSnapshotError::win32(api, ERROR_INSUFFICIENT_BUFFER))
}

fn validate_extended_table_size(
    size: u32,
    field: &'static str,
) -> Result<(), WindowsSnapshotError> {
    if size < size_of::<u32>() as u32 || size > MAX_EXTENDED_TABLE_BYTES {
        return Err(WindowsSnapshotError::invalid_data(field));
    }
    Ok(())
}

/// 仅为由本模块列出的 Win32 表行实现；这些结构全部由整数和定长字节数组组成，
/// 因而任意由 Windows 写入的位模式均可按值读取。
trait ExtendedTableRow: Copy {}

impl ExtendedTableRow for MIB_TCPROW_OWNER_PID {}
impl ExtendedTableRow for MIB_TCP6ROW_OWNER_PID {}
impl ExtendedTableRow for MIB_UDPROW_OWNER_PID {}
impl ExtendedTableRow for MIB_UDP6ROW_OWNER_PID {}

fn parse_extended_rows<T: ExtendedTableRow>(
    buffer: &[u8],
    table_offset: usize,
    field: &'static str,
) -> Result<Vec<T>, WindowsSnapshotError> {
    if buffer.len() < size_of::<u32>() || table_offset < size_of::<u32>() {
        return Err(WindowsSnapshotError::invalid_data(field));
    }
    // SAFETY: 已确认至少有四字节；read_unaligned 不要求 Vec<u8> 提供 u32 对齐。
    let entry_count = unsafe { buffer.as_ptr().cast::<u32>().read_unaligned() as usize };
    let rows_size = entry_count
        .checked_mul(size_of::<T>())
        .ok_or_else(|| WindowsSnapshotError::invalid_data(field))?;
    let required_size = table_offset
        .checked_add(rows_size)
        .ok_or_else(|| WindowsSnapshotError::invalid_data(field))?;
    if required_size > buffer.len() {
        return Err(WindowsSnapshotError::invalid_data(field));
    }

    let mut rows = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let offset = table_offset + index * size_of::<T>();
        // SAFETY: 上面的长度检查覆盖全部行；T 受私有 trait 限制为纯整数 Win32 行结构。
        let row = unsafe { buffer.as_ptr().add(offset).cast::<T>().read_unaligned() };
        rows.push(row);
    }
    Ok(rows)
}

fn tcp_v4_binding(row: &MIB_TCPROW_OWNER_PID) -> Option<PortBinding> {
    (row.dwState == MIB_TCP_STATE_LISTEN as u32).then(|| PortBinding {
        protocol: PortProtocol::Tcp,
        address: IpAddr::V4(decode_table_ipv4(row.dwLocalAddr)),
        port: decode_table_port(row.dwLocalPort),
        owner_pid: row.dwOwningPid,
    })
}

fn tcp_v6_binding(row: &MIB_TCP6ROW_OWNER_PID) -> Option<PortBinding> {
    (row.dwState == MIB_TCP_STATE_LISTEN as u32).then(|| PortBinding {
        protocol: PortProtocol::Tcp,
        address: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
        port: decode_table_port(row.dwLocalPort),
        owner_pid: row.dwOwningPid,
    })
}

fn udp_v4_binding(row: &MIB_UDPROW_OWNER_PID) -> PortBinding {
    PortBinding {
        protocol: PortProtocol::Udp,
        address: IpAddr::V4(decode_table_ipv4(row.dwLocalAddr)),
        port: decode_table_port(row.dwLocalPort),
        owner_pid: row.dwOwningPid,
    }
}

fn udp_v6_binding(row: &MIB_UDP6ROW_OWNER_PID) -> PortBinding {
    PortBinding {
        protocol: PortProtocol::Udp,
        address: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
        port: decode_table_port(row.dwLocalPort),
        owner_pid: row.dwOwningPid,
    }
}

fn decode_table_ipv4(raw: u32) -> Ipv4Addr {
    // IP Helper 的 IPv4 字段按网络地址的内存字节顺序存放。
    Ipv4Addr::from(raw.to_ne_bytes())
}

fn decode_table_port(raw: u32) -> u16 {
    // IP Helper 仅使用 DWORD 低 16 位，并以网络字节序存放端口。
    u16::from_be(raw as u16)
}

fn protocol_sort_key(protocol: PortProtocol) -> u8 {
    match protocol {
        PortProtocol::Tcp => 0,
        PortProtocol::Udp => 1,
    }
}

fn decode_sockaddr(sockaddr: &SOCKADDR_INET) -> Result<IpAddr, WindowsSnapshotError> {
    // SAFETY: SOCKADDR_INET 的所有 union 分支都以 ADDRESS_FAMILY 开头。
    let family = unsafe { sockaddr.si_family };
    match family {
        AF_INET => {
            // SAFETY: family 已确认是 AF_INET，可以读取 Ipv4 分支。
            let address = unsafe { sockaddr.Ipv4.sin_addr };
            let mut bytes = [0_u8; 4];
            // Windows sockaddr 中的地址按网络字节序存放，直接复制其内存字节。
            // SAFETY: IN_ADDR 恰好包含四个地址字节，目标缓冲区长度一致。
            unsafe {
                copy_nonoverlapping(
                    addr_of!(address).cast::<u8>(),
                    bytes.as_mut_ptr(),
                    bytes.len(),
                );
            }
            Ok(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        AF_INET6 => {
            // SAFETY: family 已确认是 AF_INET6，可以读取 Ipv6 分支。
            let address = unsafe { sockaddr.Ipv6.sin6_addr };
            let mut bytes = [0_u8; 16];
            // SAFETY: IN6_ADDR 恰好包含十六个地址字节，目标缓冲区长度一致。
            unsafe {
                copy_nonoverlapping(
                    addr_of!(address).cast::<u8>(),
                    bytes.as_mut_ptr(),
                    bytes.len(),
                );
            }
            Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => Err(WindowsSnapshotError::invalid_data(
            "SOCKADDR_INET.si_family",
        )),
    }
}

fn wide_z(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|code_unit| *code_unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..length])
}

fn format_guid(guid: &GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7],
    )
}

#[cfg(test)]
mod tests {
    use std::mem::size_of_val;

    use super::*;

    #[test]
    fn owner_pid_rows_decode_network_order_without_socket_operations() {
        let tcp = MIB_TCPROW_OWNER_PID {
            dwState: MIB_TCP_STATE_LISTEN as u32,
            dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwLocalPort: u32::from(9090_u16.to_be()),
            dwOwningPid: 4242,
            ..Default::default()
        };
        let binding = tcp_v4_binding(&tcp).expect("监听行必须成为端口绑定");
        assert_eq!(binding.protocol, PortProtocol::Tcp);
        assert_eq!(binding.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(binding.port, 9090);
        assert_eq!(binding.owner_pid, 4242);

        let time_wait = MIB_TCPROW_OWNER_PID {
            dwState: 11,
            dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwLocalPort: u32::from(9090_u16.to_be()),
            dwOwningPid: 4242,
            ..Default::default()
        };
        assert!(
            tcp_v4_binding(&time_wait).is_none(),
            "TIME_WAIT 不得被误判为监听端口冲突"
        );

        let udp = MIB_UDP6ROW_OWNER_PID {
            ucLocalAddr: Ipv6Addr::LOCALHOST.octets(),
            dwLocalPort: u32::from(53_u16.to_be()),
            dwOwningPid: 5353,
            ..Default::default()
        };
        let binding = udp_v6_binding(&udp);
        assert_eq!(binding.protocol, PortProtocol::Udp);
        assert_eq!(binding.address, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(binding.port, 53);
        assert_eq!(binding.owner_pid, 5353);
    }

    #[test]
    fn extended_table_parser_reads_unaligned_rows_with_owner_pid() {
        let rows = [
            MIB_UDPROW_OWNER_PID {
                dwLocalAddr: u32::from_ne_bytes([0, 0, 0, 0]),
                dwLocalPort: u32::from(7890_u16.to_be()),
                dwOwningPid: 100,
            },
            MIB_UDPROW_OWNER_PID {
                dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
                dwLocalPort: u32::from(7891_u16.to_be()),
                dwOwningPid: 101,
            },
        ];
        let table_offset = offset_of!(MIB_UDPTABLE_OWNER_PID, table);
        let mut buffer = vec![0_u8; table_offset + size_of_val(&rows)];
        buffer[..size_of::<u32>()].copy_from_slice(&(rows.len() as u32).to_ne_bytes());
        // SAFETY: 目标缓冲区按 rows 的精确字节数分配，两个区域不重叠。
        unsafe {
            copy_nonoverlapping(
                rows.as_ptr().cast::<u8>(),
                buffer.as_mut_ptr().add(table_offset),
                size_of_val(&rows),
            );
        }

        let parsed = parse_extended_rows::<MIB_UDPROW_OWNER_PID>(
            &buffer,
            table_offset,
            "synthetic UDP table",
        )
        .unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].dwOwningPid, 100);
        assert_eq!(decode_table_port(parsed[1].dwLocalPort), 7891);
    }

    #[test]
    fn extended_table_parser_rejects_truncated_or_oversized_layout() {
        let table_offset = offset_of!(MIB_TCPTABLE_OWNER_PID, table);
        let mut truncated = vec![0_u8; table_offset];
        truncated[..size_of::<u32>()].copy_from_slice(&1_u32.to_ne_bytes());
        assert!(matches!(
            parse_extended_rows::<MIB_TCPROW_OWNER_PID>(
                &truncated,
                table_offset,
                "synthetic TCP table"
            ),
            Err(WindowsSnapshotError::InvalidData { .. })
        ));
        assert!(validate_extended_table_size(0, "synthetic table").is_err());
        assert!(
            validate_extended_table_size(MAX_EXTENDED_TABLE_BYTES + 1, "synthetic table").is_err()
        );
    }

    #[test]
    #[ignore = "只在本机显式执行只读 Windows 端口表审计"]
    fn native_port_table_snapshot_can_be_captured_read_only() {
        let bindings = capture_port_bindings().expect("Windows 端口表应可只读采集");
        assert!(bindings.len() < 1_000_000);
    }
}
