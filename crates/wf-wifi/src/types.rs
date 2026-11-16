//! The data model the user interface is written against.
//!
//! CONTRACT: the UI and the demo data use these names and fields. Fields and
//! types may be ADDED (every struct implements `Default`, and the UI builds
//! values with `..Default::default()`), but existing public names, field names
//! and field types must not be renamed, removed or changed.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WlanError {
    /// The WLAN service is not running or the PC has no Wi-Fi adapter.
    NoWifi(String),
    /// Windows refused the scan data: location access is turned off for
    /// desktop apps (Windows 11 24H2 and later require it for BSSIDs).
    LocationDenied,
    AccessDenied,
    Other(String),
}

impl std::fmt::Display for WlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WlanError::NoWifi(e) => write!(f, "No Wi-Fi adapter is available ({e})."),
            WlanError::LocationDenied => f.write_str(
                "Windows only shows nearby networks to apps when location access is on \
                 (Settings > Privacy & security > Location > Let desktop apps access your location).",
            ),
            WlanError::AccessDenied => f.write_str("Windows denied access to the Wi-Fi service."),
            WlanError::Other(e) => f.write_str(e),
        }
    }
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum Band {
    #[default]
    B24,
    B5,
    B6,
}

impl Band {
    pub fn label(self) -> &'static str {
        match self {
            Band::B24 => "2.4 GHz",
            Band::B5 => "5 GHz",
            Band::B6 => "6 GHz",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WlanInterface {
    /// `{XXXXXXXX-XXXX-...}`
    pub guid: String,
    pub description: String,
    pub connected: bool,
    /// "Connected", "Disconnected", "Scanning"...
    pub state: String,
    pub radio_on: bool,
}

/// One access point (BSS) seen in a scan.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Bss {
    /// Empty for hidden networks.
    pub ssid: String,
    /// `AA:BB:CC:DD:EE:FF`
    pub bssid: String,
    pub rssi_dbm: i32,
    /// 0..=100
    pub quality: u8,
    pub freq_mhz: u32,
    pub channel: u16,
    pub band: Band,
    /// Channel width in MHz when the beacon says (20/40/80/160/320).
    pub width_mhz: Option<u16>,
    /// "802.11ax"
    pub phy: String,
    /// Wi-Fi generation 4..=7 when known.
    pub generation: Option<u8>,
    /// "WPA2-Personal", "WPA3-Personal", "WPA2/WPA3-Personal", "WPA2-Enterprise", "Open", "WEP", "OWE"...
    pub security: String,
    /// Vendor from the MAC prefix.
    pub vendor: Option<String>,
    /// This is the access point the PC is connected to.
    pub connected: bool,
    pub beacon_interval_ms: Option<u32>,
    /// Highest basic / supported rate in Mbit/s from the rate set.
    pub max_rate_mbps: Option<f32>,
    /// From the BSS Load element when present.
    pub stations: Option<u16>,
    /// Channel utilisation 0..=100 from the BSS Load element.
    pub utilization: Option<u8>,
    /// Two-letter country code from the Country element.
    pub country: Option<String>,
    /// Centre of the whole (possibly bonded) channel in MHz when the beacon
    /// says; for a 20 MHz network this equals `freq_mhz`.
    #[serde(default)]
    pub center_mhz: Option<u32>,
}

/// The current association.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Link {
    pub interface_guid: String,
    pub interface: String,
    pub profile: String,
    pub ssid: String,
    pub bssid: String,
    pub phy: String,
    pub generation: Option<u8>,
    pub rssi_dbm: i32,
    pub quality: u8,
    pub rx_rate_mbps: f32,
    pub tx_rate_mbps: f32,
    pub freq_mhz: u32,
    pub channel: u16,
    pub band: Band,
    pub width_mhz: Option<u16>,
    /// "WPA2-Personal"
    pub security: String,
    /// "CCMP (AES)"
    pub cipher: String,
    /// MCS index when the driver exposes it.
    pub mcs: Option<u8>,
    /// Spatial streams when exposed.
    pub streams: Option<u8>,
    pub vendor: Option<String>,
}

/// Why the key of a saved network is or is not shown.
///
/// `Debug` is written by hand so that a key never ends up in a log line.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    /// An open network: there is no password.
    Open,
    /// The saved password / key in clear text.
    Key(String),
    /// Windows returned the key encrypted: administrator rights are needed.
    NeedsAdmin,
    /// 802.1X / enterprise: the profile holds no shared key (credentials are per user).
    Enterprise,
    /// Anything else, with the reason.
    #[default]
    Unknown,
    Unavailable(String),
}

impl std::fmt::Debug for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyState::Open => f.write_str("Open"),
            KeyState::Key(_) => f.write_str("Key(<hidden>)"),
            KeyState::NeedsAdmin => f.write_str("NeedsAdmin"),
            KeyState::Enterprise => f.write_str("Enterprise"),
            KeyState::Unknown => f.write_str("Unknown"),
            KeyState::Unavailable(reason) => write!(f, "Unavailable({reason:?})"),
        }
    }
}

/// A saved Wi-Fi profile.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedProfile {
    /// Profile name (usually the SSID).
    pub name: String,
    pub ssid: String,
    /// Display name: "WPA2-Personal", "WPA3-Personal", "WPA2-Enterprise", "Open", "WEP"...
    pub security: String,
    /// Raw `authentication` value from the profile XML ("WPA2PSK").
    pub auth: String,
    /// Raw `encryption` value ("AES").
    pub cipher: String,
    pub auto_connect: bool,
    /// The profile connects even when the network does not broadcast its name.
    pub hidden: bool,
    pub key: KeyState,
    /// "passPhrase" or "networkKey" (64 hex digits) when a key exists.
    pub key_type: String,
    /// Saved for all users of the PC (not only the current one).
    pub all_users: bool,
    pub interface_guid: String,
    /// "enabled"/"disabled" MAC randomisation when the profile says.
    pub random_mac: Option<bool>,
    /// 0 = most preferred.
    pub priority: u32,
}

/// The parts of a WLAN profile XML document this program reads.
///
/// `Debug` is written by hand so that the key material is never printed.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ParsedProfile {
    pub name: String,
    pub ssid: String,
    pub auth: String,
    pub cipher: String,
    pub use_one_x: bool,
    pub auto_connect: bool,
    pub hidden: bool,
    /// "passPhrase" / "networkKey"
    pub key_type: String,
    /// `<protected>` value.
    pub key_protected: Option<bool>,
    pub key_material: Option<String>,
    pub random_mac: Option<bool>,
    /// A second authentication listed for transition mode (WPA2 + WPA3).
    pub transition_auth: Option<String>,
}

impl std::fmt::Debug for ParsedProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedProfile")
            .field("name", &self.name)
            .field("ssid", &self.ssid)
            .field("auth", &self.auth)
            .field("cipher", &self.cipher)
            .field("use_one_x", &self.use_one_x)
            .field("auto_connect", &self.auto_connect)
            .field("hidden", &self.hidden)
            .field("key_type", &self.key_type)
            .field("key_protected", &self.key_protected)
            .field(
                "key_material",
                &self.key_material.as_ref().map(|_| "<hidden>"),
            )
            .field("random_mac", &self.random_mac)
            .field("transition_auth", &self.transition_auth)
            .finish()
    }
}

/// Networks on one channel and how crowded it is.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ChannelLoad {
    pub channel: u16,
    /// Access points whose primary channel this is.
    pub networks: u32,
    /// Interference score: overlapping access points weighted by signal (0 = free).
    pub score: f32,
    /// Strongest signal on the channel in dBm (`None` when empty).
    pub strongest_dbm: Option<i32>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ChannelSuggestion {
    pub band: Band,
    pub channel: u16,
    /// One plain sentence explaining the pick.
    pub reason: String,
}

/// A directly attached IPv4 network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subnet {
    /// Any address inside the network (it is masked when used).
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundDevice {
    /// Dotted IPv4 address.
    pub ip: String,
    /// `AA:BB:CC:DD:EE:FF`, empty when ARP gave none.
    pub mac: String,
    pub vendor: Option<String>,
    /// Best name found.
    pub name: Option<String>,
    /// "mDNS", "NetBIOS", "SSDP", "DNS".
    pub name_source: Option<String>,
    /// Extra hints such as an SSDP device type or mDNS service ("printer", "_googlecast").
    pub kind_hint: Option<String>,
    pub is_gateway: bool,
    pub is_self: bool,
    /// The MAC is locally administered (a private / randomised address).
    pub random_mac: bool,
    pub rtt_ms: Option<u32>,
}

/// A device remembered between scans.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KnownDevice {
    pub mac: String,
    /// The name the user gave it (empty when none).
    pub label: String,
    /// The user marked it as known / trusted.
    pub known: bool,
    /// Unix seconds.
    pub first_seen: i64,
    pub last_seen: i64,
    pub last_ip: String,
    pub vendor: Option<String>,
    pub name: Option<String>,
    pub name_source: Option<String>,
    pub kind_hint: Option<String>,
    pub is_gateway: bool,
    pub is_self: bool,
    pub random_mac: bool,
    /// Seen in the most recent scan.
    pub online: bool,
    pub rtt_ms: Option<u32>,
}
