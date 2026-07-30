# slpyW2W

slpyW2W is a Windows desktop client for chained proxy forwarding. It is designed for multi-hop routing, team network access, and environments where traffic must enter through one relay and leave through another.

## Traffic Modes

```text
Direct:  Device → relay → Destination
Forward: Device → relay → exit → Destination
```

The relay and exit are independent configurations. Each hop can use a standard WireGuard `.conf` or a VLESS URI / Mihomo YAML file. VLESS currently supports the TCP form used by VLESS Reality configurations. Their DNS settings and routing roles are kept separate.

## Requirements

- Windows 10 or Windows 11 (64-bit)
- Administrator permission for creating the TUN adapter
- Valid WireGuard or VLESS configuration files
- Other software's TUN mode disabled before connecting

slpyW2W manages only its own Mihomo process. It does not modify other proxy clients, the Windows system proxy, or firewall rules.

## Usage

1. Start `slpyW2W` from the Start menu after installation.
2. Use the configuration menu to import the required `.conf`, `.txt`, `.yaml`, or `.yml` files.
3. Select `Direct` for a single hop or `Forward` for chained forwarding.
4. Select the relay node and, in forwarding mode, the exit node.
5. Use the lightning button to test node latency if needed.
6. Press the large connection button to connect. Press it again to disconnect.

Closing the window keeps the application running in the system tray. Use the tray menu to reopen or exit it.

## Build

```powershell
npm --prefix .\apps\hk-proton-desktop install
.\scripts\fetch-mihomo.ps1
.\scripts\package-installer.ps1
```

The NSIS installer is written to `release\slpyW2W-installer\`. Mihomo is embedded in the installed application and does not need to be distributed separately. The installer uses a per-machine installation mode because the application needs administrator permission for the TUN adapter.

To enable signed in-app updates, keep the private signing key outside the repository and provide the public update metadata only through the build environment:

```powershell
$env:HK_PROTON_UPDATER_ENDPOINT = 'https://updates.example.invalid/slpyW2W/{{target}}/{{arch}}/{{current_version}}'
$env:HK_PROTON_UPDATER_PUBLIC_KEY_FILE = 'C:\secure\slpyW2W-public.key'
$env:TAURI_SIGNING_PRIVATE_KEY = 'path-or-content-provided-by-your-secret-store'
.\scripts\package-installer.ps1 -EnableUpdater
```

For a later release, increase the semantic version in `tauri.conf.json` and run the installer build again. Running the new `*-setup.exe` over the existing installation updates the program while preserving the local encrypted state. The signed mode additionally produces the updater signature and enables the in-app “检查更新” action. No portable package is produced by the release script.

## Configuration Safety

Real VPN configurations and release binaries are excluded from Git. Imported configuration data is stored in the current user's local application data and protected with Windows DPAPI.

Customized builds may embed configurations directly into the executable during compilation. Treat such executables as sensitive files and distribute them only to intended users.
