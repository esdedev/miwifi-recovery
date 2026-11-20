# MiWiFi Recovery

[Español](README.es.md)

An open-source replacement for Xiaomi's "MiWiFi Repair Tool". It reinstalls the official
firmware on a Xiaomi router that no longer starts, using the router's built-in recovery mode.

- **Guided, in English or Spanish.** It shows what to do on the PC and on the router before it starts.
- **Checks the firmware before sending it.** If the router would refuse the file, the tool says
  why: older version than installed (anti-rollback), wrong model, or damaged download.
- **Sets up the PC for you** (Windows, optional). It gives the Ethernet adapter the address the
  router looks for, and puts your settings back at the end. Prefer to do it by hand? It shows how.
- **Small and auditable.** About 3,000 lines of Rust and plain HTML/CSS/JS, half of it the bilingual interface. No telemetry, no downloads, no
  installers inside installers.

> Use it only on your own devices. Recovery erases the router's settings.
> Read the [legal notice](LEGAL.md).

## Download

Get the latest build from [Releases](https://github.com/esdedev/miwifi-recovery/releases):

| File | What it is |
|---|---|
| `MiWiFi-Recovery_x.y.z_x64-setup.exe` | Windows installer |
| `miwifi-recovery.exe` | Windows, portable (no install) |
| `miwifi-recovery-cli-*` | Command-line version for Windows, Linux and macOS |
| `SHA256SUMS.txt` | Checksums of all files |

Releases are built by [GitHub Actions](.github/workflows/release.yml) from the tagged source, so
anyone can check how each binary was made. The Windows app needs WebView2, which comes with
Windows 10 and 11.

## How to use it

1. **Firmware.** Choose the official `.bin` for your model. Type the model code from the label under
   the router (e.g. `RD15`) and, if you know it, the version installed now.
2. **This PC.** Plug the cable from the PC into a **LAN** port of the router. Pick that network
   adapter and click *Set it up for me* (one Windows permission prompt). You can also set
   `192.168.31.100 / 255.255.255.0` yourself.
3. **Router.** Read the steps: power off, hold Reset, power on, release when the light blinks orange.
4. **Recovery.** The tool waits, gives the router an address and sends the firmware (about 15 s).
5. **Result.** The router checks the signature and writes the flash (1–5 min):
   - **blinking blue**: done. Power-cycle it. The tool tells you when 192.168.31.1 answers;
   - **steady orange/red**: refused. Nothing was written. The screen lists the usual causes.

Command line (any OS; on Linux/macOS run with `sudo` because ports 67/69 are privileged):

```sh
miwifi-recovery-cli --firmware miwifi_rd15_firmware_0321a_1.0.87.bin --model RD15 --installed 1.0.87
miwifi-recovery-cli --firmware fw.bin --model RD15 --check     # only analyse the file
```

## Why the router refuses a file

The checks come from reverse-engineering the bootloader of the Xiaomi BE3600 2.5G (RD15). Other
models are similar but not verified. Details in [docs/how-it-works.md](docs/how-it-works.md).

| Cause | What the bootloader does | What this tool does |
|---|---|---|
| Version older than the installed one | `not permit upgrade!`, steady light | Compares versions with the same rule and blocks the file |
| Firmware for another model | `Mismatch trx model` | Compares the image model with your label |
| Damaged or incomplete file | CRC / signature error | Verifies the image checksum |
| Not a Xiaomi image (OpenWrt, backup, .zip) | Header error | Detects the missing `HDR1` header |
| Not signed by Xiaomi | `Image verify failed!` | Cannot be checked offline; the router decides |

There is no way around the signature check: recovery only installs official Xiaomi firmware.

## Compared with the official tool

The official `MIWIFIRepairTool.x86.exe` is a rebranded **Tftpd32 4.61** (2019) with a Chinese-only
interface. This project does the same network job and adds the checks and guidance:

| | Official tool | MiWiFi Recovery |
|---|---|---|
| DHCP server, address pool from 192.168.31.101 | ✓ | ✓ |
| TFTP server, any requested filename | ✓ | ✓ (also `blksize`, `tsize`, `timeout`) |
| Language | Chinese | English, Spanish |
| Step-by-step guide for PC and router | — | ✓ |
| Checks model, version (anti-rollback) and integrity before flashing | — | ✓ |
| Explains why the router refused the file | — | ✓ |
| Sets and restores the PC's IP address | — | ✓ (Windows) |
| Detects when the router is back up | — | ✓ |
| Firmware download list | Asks `api.miwifi.com`, which lists only 3 old models (R4, R4Q, R4C) | Links to Xiaomi's official pages |
| Ships Microsoft *debug* runtime DLLs | Yes (`ucrtbased.dll`, `vcruntime140d.dll`) | No |
| Source code | Closed | GPL-3.0 |

The comparison comes from the tool's strings and its own `tftp.log`. It was not run. This project
makes no claim about malware in the official tool. Antivirus detections of repackaged Tftpd32
builds are often heuristic.

## Build from source

Requirements: Rust (stable), the Tauri CLI 2 (`cargo install tauri-cli --version "^2"`), and on
Windows the MSVC build tools.

```sh
cargo test --workspace                       # core + app tests
cargo build --release -p miwifi-recovery-cli # CLI
cd app/src-tauri && cargo tauri build        # GUI + Windows installer
```

Layout:

```
crates/core      DHCP, TFTP, firmware parsing, version rule (no GUI, no unsafe)
crates/cli       command-line front end
app/src-tauri    desktop app: Tauri commands, Windows network setup
app/ui           interface (HTML/CSS/JS, no frameworks, no CDN)
```

To test against real images:
`MIWIFI_TEST_FIRMWARE="/path/a.bin;/path/b.bin" cargo test -p miwifi-recovery-core`.

## What the Windows network setup changes

Only when you click *Set it up for me*:

1. It saves the adapter's current IPv4 settings to `%APPDATA%\io.github.esdedev.miwifi-recovery\network-restore.json`.
2. It starts itself elevated (UAC) and runs `netsh`:
   - `interface ipv4 set address name=<index> source=static address=192.168.31.100 mask=255.255.255.0 gateway=none`;
   - `advfirewall firewall add rule name=MiWiFiRecoveryTemporary dir=in action=allow protocol=UDP profile=any program="<this exe>"`.
3. *Restore my network settings* puts back DHCP or your previous static addresses and deletes
   the rule. If the app is closed first, it offers to restore on the next start.

The exact commands are in [`app/src-tauri/src/net.rs`](app/src-tauri/src/net.rs).

## License

Copyright (C) 2026 Esdedev. GNU General Public License v3.0 or later ([LICENSE](LICENSE)).

Not affiliated with Xiaomi. "Xiaomi" and "MiWiFi" are trademarks of their owners and are used
only to say which devices this works with.
