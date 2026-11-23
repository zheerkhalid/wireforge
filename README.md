<div align="center">

<img src="docs/assets/wireforge-icon.png" alt="WireForge logo" width="128" height="128" />

# WireForge

### See everything about your network, in one place.

A network and Wi-Fi monitor for Windows, written in **Rust**.
Live traffic, per-app usage, every connection, a simple app firewall, nearby Wi-Fi and channels, saved Wi-Fi passwords, the devices on your network, a speed test and nine diagnostic tools.

<p>
  <img alt="Platform" src="https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?style=for-the-badge&logo=windows11&logoColor=white" />
  <img alt="Rust" src="https://img.shields.io/badge/Rust-stable-B7410E?style=for-the-badge&logo=rust&logoColor=white" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-1E9BFF?style=for-the-badge" />
  <img alt="EXE size" src="https://img.shields.io/badge/EXE-6.8%20MB-2F5BEA?style=for-the-badge" />
</p>

<p>
  <img alt="No driver" src="https://img.shields.io/badge/kernel%20driver-none-10C98F?style=flat-square" />
  <img alt="Local" src="https://img.shields.io/badge/data-stays%20on%20this%20PC-10C98F?style=flat-square" />
  <img alt="Setup and portable" src="https://img.shields.io/badge/setup%20%2B%20portable-no%20runtimes-10C98F?style=flat-square" />
  <img alt="No telemetry" src="https://img.shields.io/badge/telemetry-none-10C98F?style=flat-square" />
  <img alt="Tests" src="https://img.shields.io/badge/tests-466%20passing-10C98F?style=flat-square" />
  <img alt="Made by Zheer Khalid" src="https://img.shields.io/badge/made%20by-Zheer%20Khalid-FF5A4E?style=flat-square" />
</p>

[**Features**](#-features) ·
[**Screenshots**](#%EF%B8%8F-screenshots) ·
[**Download**](#-download) ·
[**Privacy**](#-privacy) ·
[**Limits**](#-good-to-know) ·
[**Developer**](#-developer)

<img src="docs/screenshots/overview.png" alt="WireForge overview" width="900" />

</div>

---

## ✨ Features

<table>
<tr>
<td width="50%" valign="top">

### 📈 Traffic and apps
- Live download and upload rates with history graphs
- Totals for today, this month and this session; optional data allowance alert
- Per-app live rates and usage history (run as administrator for byte counts)
- Every TCP and UDP connection with its program, addresses and state
- Tray icon and an optional floating meter

</td>
<td width="50%" valign="top">

### 📶 Wi-Fi analyzer
- Nearby networks: signal, channel, band (2.4 / 5 / 6 GHz), width, Wi-Fi generation, security, vendor
- Channel occupancy per band with a best-channel suggestion
- Signal over time for your own network
- Full details of the current link

</td>
</tr>
<tr>
<td valign="top">

### 🛡️ App firewall
- **Block an app from the internet in one click**: right-click it on the Apps or Connections page, or pick any `.exe`
- Block for 1 hour, until restart or always; outgoing, and optionally incoming; on all networks or only some
- Built on Windows Defender Firewall: blocks keep working while WireForge is closed
- Shows the firewall state of each network profile and, read-only, every other rule that affects an app
- Every change is journaled and can be undone; "Remove all WireForge rules" in one step

</td>
<td valign="top">

### 🔔 New-app alerts and lockdown
- Optional (off by default): the first time a program connects to the internet, WireForge asks **Allow** or **Block** and remembers the answer
- The list of known programs can be changed at any time
- Optional **lockdown**: block all outgoing traffic except an allow list, clearly warned, with an always-visible **End lockdown** button
- Ending lockdown puts the previous firewall defaults back exactly
- Administrator permission is asked only for the change itself, never for the whole app

</td>
</tr>
<tr>
<td valign="top">

### 🔑 Saved Wi-Fi networks
- Every network saved on this PC, with its **password**
- Hidden until you press reveal; copy with one click
- QR code to share a network with a phone
- Export, with a clear warning that the file contains passwords
- Says why when a password cannot be shown (for example, work networks that sign in with an account)

</td>
<td valign="top">

### 🖥️ Devices on your network
- Scans your own local network and lists each device: IP, MAC, vendor, name
- First seen and last seen; name and star the ones you know
- Alert when a new device appears
- Only ever scans the network you are directly connected to

</td>
</tr>
<tr>
<td valign="top">

### 🧰 Tools
- Ping with a live graph, and traceroute
- DNS lookup with record types and a chosen server
- Port check, Wake-on-LAN, whois, subnet calculator
- Full interface report
- Flush DNS and renew lease, each behind a confirmation

</td>
<td valign="top">

### ⚡ Speed test
- Download, upload, latency and jitter with a history graph
- Uses Measurement Lab's open NDT7 test
- Asks for consent first, because M-Lab publishes test results (see [Privacy](#-privacy))
- Export any page to CSV, HTML or JSON

</td>
</tr>
</table>

## 🖼️ Screenshots

<table>
<tr>
<td width="50%" align="center"><b>Firewall</b><br><img src="docs/screenshots/firewall.png" alt="Firewall" /></td>
<td width="50%" align="center"><b>New app on the internet</b><br><img src="docs/screenshots/firewall-alert.png" alt="New-app alert" /></td>
</tr>
<tr>
<td width="50%" align="center"><b>Block an app</b><br><img src="docs/screenshots/firewall-block.png" alt="Block dialog" /></td>
<td width="50%" align="center"><b>Lockdown</b><br><img src="docs/screenshots/firewall-lockdown.png" alt="Lockdown dialog" /></td>
</tr>
<tr>
<td width="50%" align="center"><b>Apps</b><br><img src="docs/screenshots/apps.png" alt="Apps" /></td>
<td width="50%" align="center"><b>Connections</b><br><img src="docs/screenshots/connections.png" alt="Connections" /></td>
</tr>
<tr>
<td width="50%" align="center"><b>Wi-Fi networks</b><br><img src="docs/screenshots/wifi.png" alt="Wi-Fi networks" /></td>
<td width="50%" align="center"><b>Wi-Fi channels</b><br><img src="docs/screenshots/wifi-channels.png" alt="Wi-Fi channels" /></td>
</tr>
<tr>
<td width="50%" align="center"><b>Saved networks and passwords</b><br><img src="docs/screenshots/saved.png" alt="Saved networks" /></td>
<td width="50%" align="center"><b>Share by QR code</b><br><img src="docs/screenshots/saved-qr.png" alt="QR code" /></td>
</tr>
<tr>
<td width="50%" align="center"><b>Devices</b><br><img src="docs/screenshots/devices.png" alt="Devices" /></td>
<td width="50%" align="center"><b>Speed test</b><br><img src="docs/screenshots/speed.png" alt="Speed test" /></td>
</tr>
<tr>
<td width="50%" align="center"><b>Ping</b><br><img src="docs/screenshots/tools-ping.png" alt="Ping" /></td>
<td width="50%" align="center"><b>Traceroute</b><br><img src="docs/screenshots/tools-trace.png" alt="Traceroute" /></td>
</tr>
<tr>
<td width="50%" align="center"><b>Data usage</b><br><img src="docs/screenshots/usage.png" alt="Usage" /></td>
<td width="50%" align="center"><b>Light theme</b><br><img src="docs/screenshots/light-theme.png" alt="Light theme" /></td>
</tr>
</table>

<sub>Screenshots use the built-in demo mode (<code>WireForge.exe --demo</code>). Every network, device, address and password in them is invented.</sub>

## 📥 Download

Get it from the [**latest release**](https://github.com/zheerkhalid/wireforge/releases/latest):

| File | What it is |
|---|---|
| `WireForge-Setup.exe` | Per-user installer with shortcuts and an uninstaller |
| `WireForge-x.y.z-portable-x64.zip` | Portable: unzip and run |
| `WireForge.exe` | The bare 6.8 MB EXE |

WireForge runs without administrator rights. **Restart as administrator** unlocks per-app byte counts and details of every process. Firewall changes ask for administrator permission one change at a time (the window itself stays a normal app).

## 🔒 Privacy

Everything WireForge collects stays on your PC. It makes a network request only when you start one:

| Action | Service | What is sent |
|---|---|---|
| Speed test | [Measurement Lab](https://www.measurementlab.net/) NDT7 | Test traffic. **M-Lab publishes results, including your IP address, as open data.** WireForge asks for consent before the first test |
| Show public IP | ipify | A request that reveals your public IP address to that service |
| Ping, traceroute, DNS, whois, port check | The host you name | The request itself |

Saved Wi-Fi passwords are read from Windows on this PC and never leave it. WireForge never changes or deletes saved networks. The firewall feature sends nothing anywhere: it reads the local connection table and writes Windows Defender Firewall rules on this PC. See [`PRIVACY.txt`](PRIVACY.txt).

Use the device scan and port check only on networks and equipment that are yours or that you are allowed to test.

## 📌 Good to know

- **Per-app byte counts** need administrator rights. In this first release that part has been tested with sample data only, not yet against live traffic.
- Without administrator rights, the Apps page shows connections per app instead of bytes.
- Per-app totals are slightly below adapter totals, because they count payload bytes only.
- The tray tooltip and floating meter show live rates; the tray icon itself does not change.
- Connections are labelled This PC, Local network or Internet; there is no country lookup.
- No kernel driver is installed. Blocking is done by Windows Defender Firewall through ordinary rules in the group **WireForge** (for example `WireForge: block example.exe (outgoing) #1a2b3c4d`), visible in `wf.msc`. Nothing shapes or throttles traffic.

### 🛡️ How the firewall works (and what was tested)

- **Rules are per program path.** A program that moves or updates to a new folder needs blocking again. Programs without a readable path (protected system processes) cannot be blocked from WireForge.
- **A block wins over an allow.** That is how Windows Defender Firewall works; the Firewall page lists the other rules that affect an app so you can see why something is allowed or blocked. If a profile has the firewall turned off, no rule applies there.
- **Temporary blocks** ("for 1 hour", "until restart") end through a one-time scheduled task in `\WireForge\` that runs only `netsh.exe` and `schtasks.exe` from System32 (never WireForge.exe, which lives in a folder you can write to). If that task cannot run, the Firewall page shows the block as "Time is up" and offers to remove it.
- **New-app alerts** watch the connection table every two seconds while WireForge runs. A program that connects and disconnects between two looks can be missed; an alert asks after the program already connected once.
- **Lockdown** sets each profile's default for outgoing traffic to block and adds allow rules for the chosen programs. The previous defaults are stored in a disabled WireForge rule, so they can be restored exactly even if WireForge's settings folder is lost. Windows' own enabled outgoing rules (such as Core Networking for DNS and DHCP) still apply.
- **Undo:** every change is written to `%LOCALAPPDATA%\WireForge\firewall-journal.jsonl` with all its steps. A failed step reverses the steps before it. The uninstaller offers to remove all WireForge rules (and end lockdown).
- **Testing, honestly:** the planning, naming, journal/undo, temporary-block expiry, lockdown save/restore, new-app detection and command-line parsing are covered by unit tests against an in-memory firewall. Against the real Windows Defender Firewall, this release was checked **read-only** (firewall state and rules are read in a test, and the command line refuses changes without administrator rights). Adding and removing real rules, the elevation prompt, the scheduled tasks and lockdown were **not** exercised on a real PC before release.

## 🏗️ Build from source

Requires Rust (stable, MSVC toolchain) on Windows.

```powershell
git clone https://github.com/zheerkhalid/wireforge
cd wireforge
cargo build --release
# -> target\release\WireForge.exe
cargo test --workspace
```

| Command | What it does |
|---|---|
| `WireForge.exe --demo` | Invented networks, devices and traffic |
| `WireForge.exe --selftest` | Run each collector once and print only success and counts |
| `WireForge.exe --screenshot out.png` | Render the window to a PNG and exit |

### Firewall from the command line

Changes need an administrator terminal (the window asks for permission by itself). `<exe>` is a full path.

| Command | What it does |
|---|---|
| `WireForge.exe --fw-list` | Firewall state per profile and the apps WireForge blocks (no rights needed) |
| `WireForge.exe --fw-block <exe>` | Block a program's outgoing connections. Options: `--for 1h` (or `30m`, `2d`), `--until-restart`, `--inbound`, `--profiles all\|domain,private,public` |
| `WireForge.exe --fw-unblock <exe>` | Remove WireForge's block of a program |
| `WireForge.exe --fw-lockdown on [--allow <exe>]...` | Block all outgoing traffic except the allowed programs |
| `WireForge.exe --fw-lockdown off` | End lockdown and restore the previous defaults |
| `WireForge.exe --fw-allow <exe>` / `--fw-disallow <exe>` | Change the lockdown allow list |
| `WireForge.exe --fw-undo <id>` | Undo a change from the journal |
| `WireForge.exe --fw-expire` | Remove temporary blocks whose time is up |
| `WireForge.exe --fw-remove-all` | Remove every WireForge rule and end lockdown |

```
crates/
  wf-firewall  app firewall on Windows Defender Firewall: rules, plans, journal, alerts
  wf-traffic   adapters, connections, per-app usage
  wf-wifi      Wi-Fi scan, saved profiles, device discovery, vendor table
  wf-tools     ping, traceroute, DNS, ports, whois, speed test
src/           the egui interface, charts, tray, export
```

The MAC vendor table comes from the public IEEE listing; see [`NOTICE`](NOTICE). The icon is drawn in code at build time. The C runtime is linked statically, so the EXE runs on a clean Windows install.

## 👨‍💻 Developer

<table>
<tr>
<td align="center" width="140">
  <a href="https://zheer.dev">
    <img src="docs/assets/zheer-logo.png" alt="Zheer Khalid logo" width="110" />
  </a>
</td>
<td>

**Designed and developed by [Zheer Khalid](https://zheer.dev)**

🌐 Website: **[zheer.dev](https://zheer.dev)**  
🐙 GitHub: **[@zheerkhalid](https://github.com/zheerkhalid)**  
🧩 Also by Zheer: **[SnapForge](https://github.com/zheerkhalid/snapforge)**, **[ReelForge](https://github.com/zheerkhalid/reelforge)**, **[UnForge](https://github.com/zheerkhalid/unforge)**, **[KeepForge](https://github.com/zheerkhalid/keepforge)**, **[ShredForge](https://github.com/zheerkhalid/shredforge)** and **[BootForge](https://github.com/zheerkhalid/bootforge)**

If WireForge is useful to you, a ⭐ on the repo is appreciated.

</td>
</tr>
</table>

## 📄 License

MIT © 2026 [Zheer Khalid](https://zheer.dev). See [`LICENSE`](LICENSE).

<div align="center">
<sub>Built with 🦀 Rust and ❤️ by <a href="https://zheer.dev">zheer.dev</a></sub>
</div>
