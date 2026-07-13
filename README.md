# slpyW2W

slpyW2W 是面向 Windows 的独立 WireGuard 桌面客户端，使用 Tauri 2、React、Rust 与固定版本 Mihomo：

```text
双跳：本机 → 第一跳 WireGuard → Proton WireGuard → 目标网站
单跳：本机 → 第一跳 WireGuard → 目标网站
```

当前版本已经打通可执行的桌面流程：只读导入现有配置、加密保存状态、选择单跳或双跳、生成并静态校验 Mihomo 配置、冲突预检，以及启动和停止应用自己拥有的 Mihomo 子进程。它不再是仅展示界面的预览版。

真实出口、握手和泄漏测试尚未执行。按照本项目的网络安全约束，这些测试必须由用户在本机手动发起。

## 已实现

- 从 `E:\Aaaovo\Documents\tools\hk-proton` 只读导入 1 份第一跳和多份 Proton WireGuard 配置；不会向来源目录写入文件。
- 严格解析单 Peer WireGuard 配置，拒绝执行 `PreUp`、`PostUp`、`PreDown`、`PostDown` 等命令字段。
- 使用 Windows CurrentUser DPAPI 加密密钥与 generation，并以 HMAC 签名 manifest 和 current/LKG HEAD。
- 在应用本地数据目录生成运行状态；导入验证和连接期间才短暂落地运行 YAML，完成、断开或异常退出时清理。
- 提供真实 Tauri commands：状态查询、导入、选择更新、静态验证、连接、断开和状态轮询。
- 使用固定的 Mihomo v1.19.28；导入或切换时先校验可执行文件 SHA-256 并执行 `mihomo -t`，通过后才提交新 generation。
- 连接前只读检查网卡、路由、进程和必需端口；启动后核对所有监听端口都属于刚创建的子进程。
- 使用独立 loopback 端口：DNS `21053`、mixed `27890`、controller `29090`；为兼容已有配置和冲突识别，TUN 内部名称暂时保留为 `HK-Proton`。Clash 后台可以继续运行，只阻断实际处于公网接管状态的其他 TUN。
- 管理员进程拒绝在 symlink、junction 或其他重解析状态目录中写入或删除文件。
- 只停止 slpyW2W 自己创建的子进程；Windows Job Object 用于避免应用退出后遗留内核进程。
- 仅访问自有 loopback controller 的 `/version`、`/configs` 和 `/proxies`，核对实际版本、TUN 配置和 selector。

slpyW2W 不读取、修改或依赖 Clash Verge Dev 的 profiles、Merge、Script 或配置目录，也不会自动切换系统代理、修改防火墙或终止其他代理/VPN。只有用户明确点击“连接”后，应用才会启动自有 Mihomo TUN；连接前若已有外部 TUN，请用户手动关闭后重试。

## 便携版

生成便携目录：

```powershell
.\scripts\package-portable.ps1
```

输出位于 `release\slpyW2W\`：

- `slpyW2W.exe`
- `manifest.json`

固定版本 Mihomo 已嵌入主程序，不需要额外携带 `mihomo.exe`。运行 `slpyW2W.exe` 后：

1. 在“配置”页点击导入现有配置；
2. 选择单跳或双跳以及对应节点；
3. 如本机已有 Clash、Mihomo 或其他 TUN，请先手动关闭；
4. 回到首页点击连接；
5. 连接后手动检查出口 IP、DNS、IPv6/WebRTC 和所需应用；测试完成后点击断开。

Release 构建会请求管理员权限，以允许用户主动连接 TUN。首次实网测试前，请确保能在本机恢复原有网络；不要在只能依赖当前远程连接的情况下直接测试。

## 本地验证

```powershell
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
npm --prefix .\apps\hk-proton-desktop run build
```

固定 Mihomo 的获取与校验：

```powershell
.\scripts\fetch-mihomo.ps1
```

当前通过 54 项常规 Rust 离线测试；另有 2 项默认忽略的本机审计已显式执行：真实配置生产导入链路与 Windows 只读端口表。真实 9 份配置已在临时 DPAPI vault 中通过提交前和提交后的固定 Mihomo 静态 `-t` 校验。静态校验、进程启动和 controller 就绪都不等于真实 WireGuard 健康，详情见 [验证记录](docs/verification.md)。

## 技术路线

项目采用最小 Tauri 2 桌面壳、React UI、Rust 安全边界和官方 Mihomo sidecar，没有直接 fork Clash Verge Rev、Clash Nyanpasu 等通用客户端。后者的订阅、Merge/Script、多内核和复杂代理组会增加删改与长期维护成本。详见 [开源基座评估](docs/open-source-basis.md)。

安全边界与未完成验收见 [SECURITY.md](SECURITY.md)。
