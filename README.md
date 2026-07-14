# slpyW2W

slpyW2W is a Windows desktop client for WireGuard-to-WireGuard (W2W) forwarding. It is designed for multi-hop routing, team network access, and environments where traffic must enter through one WireGuard peer and leave through another.

## Traffic Modes

```text
Direct:  Device → WireGuard relay → Destination
Forward: Device → WireGuard relay → WireGuard exit → Destination
```

The relay and exit are independent WireGuard configurations. Their DNS settings and routing roles are kept separate.

## Requirements

- Windows 10 or Windows 11 (64-bit)
- Administrator permission for creating the TUN adapter
- Valid WireGuard configuration files
- Other software's TUN mode disabled before connecting

slpyW2W manages only its own Mihomo process. It does not modify other proxy clients, the Windows system proxy, or firewall rules.

## Usage

1. Start `slpyW2W.exe`.
2. Use the configuration menu to import the required `.conf` files.
3. Select `Direct` for a single WireGuard hop or `Forward` for W2W forwarding.
4. Select the relay node and, in forwarding mode, the exit node.
5. Use the lightning button to test node latency if needed.
6. Press the large connection button to connect. Press it again to disconnect.

Closing the window keeps the application running in the system tray. Use the tray menu to reopen or exit it.

## Build

```powershell
npm --prefix .\apps\hk-proton-desktop install
.\scripts\fetch-mihomo.ps1
.\scripts\package-portable.ps1
```

The portable build is written to `release\slpyW2W\`. Mihomo is embedded in the executable and does not need to be distributed separately.

## Configuration Safety

Real VPN configurations and release binaries are excluded from Git. Imported configuration data is stored in the current user's local application data and protected with Windows DPAPI.

Customized builds may embed configurations directly into the executable during compilation. Treat such executables as sensitive files and distribute them only to intended users.
