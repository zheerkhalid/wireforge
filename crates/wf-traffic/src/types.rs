//! The data model the user interface is written against.
//!
//! CONTRACT: the UI and the demo data use these names and fields. Fields and
//! types may be ADDED (every struct implements `Default`, and the UI builds
//! values with `..Default::default()`), but existing public names, field names
//! and field types must not be renamed, removed or changed.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Bytes received / sent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    pub rx: u64,
    pub tx: u64,
}

impl Totals {
    pub fn sum(&self) -> u64 {
        self.rx.saturating_add(self.tx)
    }
}

/// A transfer rate in bytes per second.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Rate {
    pub down: f64,
    pub up: f64,
}

/// A calendar day in local time.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Day {
    pub y: i32,
    pub m: u32,
    pub d: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterKind {
    Ethernet,
    WiFi,
    Cellular,
    Bluetooth,
    Virtual,
    Tunnel,
    Loopback,
    #[default]
    Other,
}

impl AdapterKind {
    pub fn label(self) -> &'static str {
        match self {
            AdapterKind::Ethernet => "Ethernet",
            AdapterKind::WiFi => "Wi-Fi",
            AdapterKind::Cellular => "Cellular",
            AdapterKind::Bluetooth => "Bluetooth",
            AdapterKind::Virtual => "Virtual",
            AdapterKind::Tunnel => "Tunnel",
            AdapterKind::Loopback => "Loopback",
            AdapterKind::Other => "Other",
        }
    }
}

/// An IPv4 address with its prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V4Net {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

/// An IPv6 address with its prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V6Net {
    pub addr: Ipv6Addr,
    pub prefix: u8,
}

/// Everything known about one network adapter (GetAdaptersAddresses + GetIfEntry2).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AdapterInfo {
    pub luid: u64,
    pub index: u32,
    /// `{XXXXXXXX-XXXX-...}`; matches the Native Wifi interface GUID for Wi-Fi adapters.
    pub guid: String,
    /// The name shown in Windows ("Wi-Fi", "Ethernet 2").
    pub name: String,
    /// The driver description ("Intel(R) Wi-Fi 6 AX201 160MHz").
    pub description: String,
    pub kind: AdapterKind,
    /// Operational status is "up".
    pub up: bool,
    /// A real network card (not virtual / software).
    pub physical: bool,
    /// This adapter carries the default route with the best metric.
    pub is_default: bool,
    /// `AA:BB:CC:DD:EE:FF`, empty when the adapter has none.
    pub mac: String,
    pub mtu: u32,
    /// Link speeds in bits per second (0 when unknown).
    pub tx_link_bps: u64,
    pub rx_link_bps: u64,
    pub ipv4: Vec<V4Net>,
    pub ipv6: Vec<V6Net>,
    pub gateways: Vec<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub dns_suffix: String,
    pub dhcp_enabled: bool,
    pub dhcp_server: Option<IpAddr>,
    /// Unix seconds.
    pub lease_obtained: Option<i64>,
    pub lease_expires: Option<i64>,
    pub ipv4_metric: u32,
    /// Counters since the adapter came up.
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub packets_rx: u64,
    pub packets_tx: u64,
    pub errors_rx: u64,
    pub errors_tx: u64,
    pub discards_rx: u64,
    pub discards_tx: u64,
}

/// Byte counters of one adapter, cheap enough to read every second.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub luid: u64,
    pub rx: u64,
    pub tx: u64,
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum Proto {
    #[default]
    Tcp,
    Udp,
}

impl Proto {
    pub fn label(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnState {
    Listening,
    Established,
    SynSent,
    SynReceived,
    FinWait,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
    /// UDP endpoints have no state.
    #[default]
    Stateless,
}

impl ConnState {
    pub fn label(self) -> &'static str {
        match self {
            ConnState::Listening => "Listening",
            ConnState::Established => "Established",
            ConnState::SynSent => "Connecting",
            ConnState::SynReceived => "Accepting",
            ConnState::FinWait => "Closing (FIN wait)",
            ConnState::CloseWait => "Close wait",
            ConnState::Closing => "Closing",
            ConnState::LastAck => "Last ACK",
            ConnState::TimeWait => "Time wait",
            ConnState::Closed => "Closed",
            ConnState::Stateless => "Bound",
        }
    }
}

/// One row of the TCP / UDP tables.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Connection {
    pub proto: Proto,
    pub local: IpAddr,
    pub local_port: u16,
    /// `None` for listeners and UDP endpoints.
    pub remote: Option<IpAddr>,
    pub remote_port: u16,
    pub state: ConnState,
    pub pid: u32,
    /// Executable file name ("chrome.exe"), "System" for PID 4, empty when unknown.
    pub process: String,
    /// Full path when it could be read (may be empty for protected processes).
    pub path: String,
    /// Unix seconds, when Windows reports it.
    pub created: Option<i64>,
}

impl Default for Connection {
    fn default() -> Self {
        Connection {
            proto: Proto::Tcp,
            local: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: 0,
            remote: None,
            remote_port: 0,
            state: ConnState::Stateless,
            pid: 0,
            process: String::new(),
            path: String::new(),
            created: None,
        }
    }
}

/// A 32-bit RGBA image (program icon).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IconImage {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// Why per-app byte counts are or are not available.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PerAppMode {
    /// The kernel network trace is running: real byte counts per process.
    Etw,
    /// No trace (the string says why, for example "needs administrator rights"):
    /// only connection counts per process are known.
    ConnectionsOnly(String),
    #[default]
    Starting,
}

/// A remote endpoint an app talks to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Endpoint {
    pub proto: Proto,
    pub addr: IpAddr,
    pub port: u16,
    /// Reverse-DNS name when it was looked up.
    pub host: Option<String>,
    /// Bytes this session (zero in connections-only mode).
    pub rx: u64,
    pub tx: u64,
}

/// Live view of one application (all processes sharing an executable).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AppLive {
    /// Executable file name, used as the key everywhere ("chrome.exe").
    pub name: String,
    pub path: String,
    pub pids: Vec<u32>,
    pub rate: Rate,
    /// Bytes since monitoring started.
    pub session: Totals,
    /// Bytes today (from the usage database plus this session).
    pub today: Totals,
    pub connections: u32,
    pub endpoints: Vec<Endpoint>,
    /// Last 60 samples, one per second, oldest first.
    pub history: Vec<Rate>,
}

/// Live view of one adapter.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AdapterLive {
    pub luid: u64,
    pub name: String,
    pub kind: AdapterKind,
    pub up: bool,
    pub rate: Rate,
    pub session: Totals,
}

/// What the monitor thread publishes once per second.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub taken_unix: i64,
    /// Sum over the physical adapters that are up.
    pub rate: Rate,
    /// Highest total rate seen this session.
    pub peak: Rate,
    /// Up to 300 samples, one per second, oldest first.
    pub history: Vec<Rate>,
    pub adapters: Vec<AdapterLive>,
    pub apps: Vec<AppLive>,
    pub per_app_mode: PerAppMode,
    pub session: Totals,
    pub today: Totals,
    pub month: Totals,
}

/// One row of a usage report.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageRow {
    /// Day, app name or adapter name depending on the report.
    pub key: String,
    pub totals: Totals,
}

/// The monthly data allowance and how much of it is used.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CapStatus {
    pub used: u64,
    pub cap: u64,
    /// 0.0 ..= 1.0 and beyond when over the cap.
    pub fraction: f64,
    pub warn: bool,
    pub exceeded: bool,
}
