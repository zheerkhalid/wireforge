//! Native Wifi: interfaces, scans, the current link.
//!
//! Read-only apart from `request_scan`, which only asks the driver to refresh
//! its list of nearby networks. Nothing here connects, disconnects or edits
//! a profile.

use crate::types::*;
use crate::{channels, ie, oui};
use std::collections::HashMap;
use std::ffi::c_void;
use windows::core::GUID;
use windows::Win32::Foundation::{BOOL, HANDLE};
use windows::Win32::NetworkManagement::WiFi::{
    dot11_BSS_type_any, dot11_radio_state_off, wlan_interface_state_connected,
    wlan_intf_opcode_channel_number, wlan_intf_opcode_current_connection,
    wlan_intf_opcode_radio_state, WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory,
    WlanGetAvailableNetworkList, WlanGetNetworkBssList, WlanOpenHandle, WlanQueryInterface,
    WlanScan, WLAN_AVAILABLE_NETWORK, WLAN_AVAILABLE_NETWORK_LIST, WLAN_BSS_ENTRY, WLAN_BSS_LIST,
    WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO, WLAN_INTERFACE_INFO_LIST, WLAN_INTF_OPCODE,
    WLAN_RADIO_STATE,
};

pub use crate::ie::{parse as parse_ies, security_from_ies, IeInfo};

pub(crate) const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_DATA: u32 = 13;
const ERROR_NOT_SUPPORTED: u32 = 50;
const ERROR_SERVICE_DISABLED: u32 = 1058;
const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;
const ERROR_NOT_FOUND: u32 = 1168;
const ERROR_INVALID_STATE: u32 = 5023;
/// Not in the `windows` 0.58 bindings: Windows 11 24H2 and later.
const OPCODE_REALTIME_CONNECTION_QUALITY: WLAN_INTF_OPCODE = WLAN_INTF_OPCODE(19);

/// An open Native Wifi client handle, closed on drop.
pub(crate) struct Client(pub(crate) HANDLE);

impl Client {
    pub(crate) fn open() -> Result<Client, WlanError> {
        let mut negotiated = 0u32;
        let mut handle = HANDLE::default();
        // SAFETY: both out pointers are valid for the duration of the call.
        let rc = unsafe { WlanOpenHandle(2, None, &mut negotiated, &mut handle) };
        if rc != 0 {
            return Err(classify(rc, "opening the Wi-Fi service", false));
        }
        Ok(Client(handle))
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // SAFETY: the handle came from WlanOpenHandle and is closed exactly once.
        unsafe {
            WlanCloseHandle(self.0, None);
        }
    }
}

/// Frees a Native Wifi allocation when it goes out of scope.
pub(crate) struct WlanMemory<T>(pub(crate) *mut T);

impl<T> Drop for WlanMemory<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer was allocated by a Wlan* function and is freed once.
            unsafe { WlanFreeMemory(self.0 as *const c_void) };
        }
    }
}

/// Turns a Win32 error from a Wlan* call into this crate's error.
/// `location_gated`: the call is one Windows 11 24H2+ refuses without
/// location access, so "access denied" means exactly that.
pub(crate) fn classify(code: u32, doing: &str, location_gated: bool) -> WlanError {
    match code {
        ERROR_ACCESS_DENIED if location_gated => WlanError::LocationDenied,
        ERROR_ACCESS_DENIED => WlanError::AccessDenied,
        ERROR_SERVICE_NOT_ACTIVE | ERROR_SERVICE_DISABLED => {
            WlanError::NoWifi("the WLAN AutoConfig service is not running".into())
        }
        ERROR_NOT_SUPPORTED => WlanError::NoWifi("Wi-Fi is not supported on this PC".into()),
        ERROR_NOT_FOUND => WlanError::NoWifi("the Wi-Fi adapter is no longer there".into()),
        _ => WlanError::Other(format!("Windows reported error {code} while {doing}.")),
    }
}

/// Parses `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` (braces optional).
pub(crate) fn parse_guid(text: &str) -> Option<GUID> {
    let t = text.trim().trim_start_matches('{').trim_end_matches('}');
    let parts: Vec<&str> = t.split('-').collect();
    let lens = [8usize, 4, 4, 4, 12];
    if parts.len() != 5
        || parts
            .iter()
            .zip(lens)
            .any(|(p, l)| p.len() != l || !p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    let d1 = u32::from_str_radix(parts.first()?, 16).ok()?;
    let d2 = u16::from_str_radix(parts.get(1)?, 16).ok()?;
    let d3 = u16::from_str_radix(parts.get(2)?, 16).ok()?;
    let tail = format!("{}{}", parts.get(3)?, parts.get(4)?);
    let mut d4 = [0u8; 8];
    for (i, byte) in d4.iter_mut().enumerate() {
        *byte = u8::from_str_radix(tail.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(GUID::from_values(d1, d2, d3, d4))
}

pub(crate) fn format_guid(g: &GUID) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7]
    )
}

/// A NUL-terminated UTF-16 buffer as text.
pub(crate) fn wide_to_string(wide: &[u16]) -> String {
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(wide.get(..end).unwrap_or(&[]))
}

fn bad_guid() -> WlanError {
    WlanError::Other("The Wi-Fi adapter identifier is not valid.".into())
}

/// The interfaces as the service lists them.
pub(crate) fn enum_interfaces(client: &Client) -> Result<Vec<WLAN_INTERFACE_INFO>, WlanError> {
    let mut list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
    // SAFETY: `list` is a valid out pointer; the result is freed by the guard below.
    let rc = unsafe { WlanEnumInterfaces(client.0, None, &mut list) };
    let guard = WlanMemory(list);
    if rc != 0 {
        return Err(classify(rc, "listing the Wi-Fi adapters", false));
    }
    if guard.0.is_null() {
        return Ok(Vec::new());
    }
    // SAFETY: on success the service returns a list whose header is followed
    // by `dwNumberOfItems` entries; they are copied out before the guard frees it.
    let out = unsafe {
        let count = ((*guard.0).dwNumberOfItems as usize).min(64);
        let first = std::ptr::addr_of!((*guard.0).InterfaceInfo) as *const WLAN_INTERFACE_INFO;
        (0..count)
            .map(|i| std::ptr::read_unaligned(first.add(i)))
            .collect()
    };
    Ok(out)
}

/// Reads one fixed-size value with WlanQueryInterface.
fn query<T: Copy>(client: &Client, guid: &GUID, opcode: WLAN_INTF_OPCODE) -> Result<T, u32> {
    let bytes = query_bytes(client, guid, opcode)?;
    if bytes.len() < std::mem::size_of::<T>() {
        return Err(ERROR_INVALID_DATA);
    }
    // SAFETY: the buffer holds at least size_of::<T>() bytes written by the
    // service for this opcode, and T is a plain-data Win32 struct or integer.
    Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) })
}

/// Reads the raw answer of a WlanQueryInterface opcode.
fn query_bytes(client: &Client, guid: &GUID, opcode: WLAN_INTF_OPCODE) -> Result<Vec<u8>, u32> {
    let mut size = 0u32;
    let mut data: *mut c_void = std::ptr::null_mut();
    // SAFETY: the out pointers are valid; the returned buffer is freed by the guard.
    let rc =
        unsafe { WlanQueryInterface(client.0, guid, opcode, None, &mut size, &mut data, None) };
    let guard = WlanMemory(data);
    if rc != 0 {
        return Err(rc);
    }
    if guard.0.is_null() || size == 0 || size > 1 << 20 {
        return Err(ERROR_INVALID_DATA);
    }
    // SAFETY: the service returned `size` readable bytes at `data`.
    Ok(unsafe { std::slice::from_raw_parts(guard.0 as *const u8, size as usize) }.to_vec())
}

fn state_word(state: i32) -> &'static str {
    match state {
        0 => "Not ready",
        1 => "Connected",
        2 => "Ad hoc network formed",
        3 => "Disconnecting",
        4 => "Disconnected",
        5 => "Associating",
        6 => "Scanning",
        7 => "Authenticating",
        _ => "Unknown",
    }
}

/// Every Wi-Fi adapter. No adapter at all is `WlanError::NoWifi`.
pub fn interfaces() -> Result<Vec<WlanInterface>, WlanError> {
    let client = Client::open()?;
    let infos = enum_interfaces(&client)?;
    if infos.is_empty() {
        return Err(WlanError::NoWifi("no Wi-Fi adapter was found".into()));
    }
    Ok(infos
        .iter()
        .map(|info| {
            let radio_on = match query::<WLAN_RADIO_STATE>(
                &client,
                &info.InterfaceGuid,
                wlan_intf_opcode_radio_state,
            ) {
                Ok(radio) => {
                    let count = (radio.dwNumberOfPhys as usize).min(radio.PhyRadioState.len());
                    let phys = radio.PhyRadioState.get(..count).unwrap_or(&[]);
                    phys.is_empty()
                        || phys.iter().any(|p| {
                            p.dot11SoftwareRadioState != dot11_radio_state_off
                                && p.dot11HardwareRadioState != dot11_radio_state_off
                        })
                }
                Err(_) => true,
            };
            WlanInterface {
                guid: format_guid(&info.InterfaceGuid),
                description: wide_to_string(&info.strInterfaceDescription),
                connected: info.isState == wlan_interface_state_connected,
                state: state_word(info.isState.0).to_string(),
                radio_on,
            }
        })
        .collect())
}

/// Asks the driver for a fresh scan (results arrive within about four seconds).
pub fn request_scan(interface_guid: &str) -> Result<(), WlanError> {
    let guid = parse_guid(interface_guid).ok_or_else(bad_guid)?;
    let client = Client::open()?;
    // SAFETY: the GUID pointer is valid for the call; no SSID or IE data is passed.
    let rc = unsafe { WlanScan(client.0, &guid, None, None, None) };
    if rc != 0 {
        return Err(classify(rc, "asking for a Wi-Fi scan", true));
    }
    Ok(())
}

/// One BSS entry as Windows reports it, before interpretation.
#[derive(Clone, Debug, Default)]
pub struct RawBss<'a> {
    pub ssid: &'a [u8],
    pub bssid: [u8; 6],
    pub rssi_dbm: i32,
    pub link_quality: u32,
    /// `ulChCenterFrequency`, kHz.
    pub freq_khz: u32,
    /// Beacon period in time units of 1.024 ms.
    pub beacon_period_tu: u16,
    pub capability: u16,
    /// `dot11BssPhyType`.
    pub phy_type: i32,
    /// `WLAN_RATE_SET` values: units of 0.5 Mbit/s, top bit marks a basic rate.
    pub rates: &'a [u16],
    /// The information elements of the beacon / probe response.
    pub ies: &'a [u8],
}

/// PHY name and Wi-Fi generation for a `DOT11_PHY_TYPE`.
pub fn phy_name(phy_type: i32) -> (&'static str, Option<u8>) {
    match phy_type {
        1 => ("802.11 (FHSS)", None),
        2 => ("802.11 (DSSS)", None),
        4 => ("802.11a", None),
        5 => ("802.11b", None),
        6 => ("802.11g", None),
        7 => ("802.11n", Some(4)),
        8 => ("802.11ac", Some(5)),
        9 => ("802.11ad", None),
        10 => ("802.11ax", Some(6)),
        11 => ("802.11be", Some(7)),
        _ => ("", None),
    }
}

/// Display name for a `DOT11_AUTH_ALGORITHM` (with the cipher deciding
/// between "Open" and "WEP").
pub fn auth_label(auth: i32, cipher: i32) -> &'static str {
    match auth {
        1 => match cipher {
            1 | 5 | 257 => "WEP",
            _ => "Open",
        },
        2 => "WEP",
        3 => "WPA-Enterprise",
        4 => "WPA-Personal",
        6 => "WPA2-Enterprise",
        7 => "WPA2-Personal",
        8 => "WPA3-Enterprise (192-bit)",
        9 => "WPA3-Personal",
        10 => "OWE",
        11 => "WPA3-Enterprise",
        _ => "Unknown",
    }
}

/// Display name for a `DOT11_CIPHER_ALGORITHM`.
pub fn cipher_label(cipher: i32) -> &'static str {
    match cipher {
        0 => "None",
        1 => "WEP-40",
        2 => "TKIP",
        4 => "CCMP (AES)",
        5 => "WEP-104",
        8 => "GCMP",
        9 => "GCMP-256",
        10 => "CCMP-256",
        257 => "WEP",
        _ => "Unknown",
    }
}

/// Interprets one BSS entry (pure). `fallback_security` is used when the
/// entry carries no information elements.
pub fn bss_from_raw(raw: &RawBss<'_>, fallback_security: Option<&str>) -> Bss {
    let freq_mhz = raw.freq_khz / 1000;
    let (band, channel) = channels::channel_from_freq(freq_mhz).unwrap_or((
        if freq_mhz >= 5925 {
            Band::B6
        } else if freq_mhz >= 4900 {
            Band::B5
        } else {
            Band::B24
        },
        0,
    ));
    let info = ie::parse(raw.ies, raw.capability, freq_mhz);
    let (phy, generation) = if raw.ies.is_empty() {
        let (name, generation) = phy_name(raw.phy_type);
        (name.to_string(), generation)
    } else {
        (info.phy.clone(), info.generation)
    };
    let security = match (raw.ies.is_empty(), fallback_security) {
        (true, Some(s)) => s.to_string(),
        _ => info.security.clone(),
    };
    let set_max = raw
        .rates
        .iter()
        .map(|r| r & 0x7FFF)
        .filter(|r| (1..=108).contains(r))
        .max()
        .map(|r| f32::from(r) / 2.0);
    let max_rate_mbps = match (info.max_rate_mbps, set_max) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    let bssid = oui::format_mac(&raw.bssid);
    let rssi_dbm = raw.rssi_dbm.clamp(-127, 20);
    Bss {
        ssid: ssid_text(raw.ssid),
        vendor: oui::vendor(&bssid).map(str::to_string),
        bssid,
        rssi_dbm,
        quality: if raw.link_quality <= 100 && raw.link_quality > 0 {
            raw.link_quality as u8
        } else {
            channels::quality_from_rssi(rssi_dbm)
        },
        freq_mhz,
        channel,
        band,
        width_mhz: info.width_mhz,
        phy,
        generation,
        security,
        connected: false,
        beacon_interval_ms: (raw.beacon_period_tu > 0)
            .then(|| (u32::from(raw.beacon_period_tu) * 1024 + 500) / 1000),
        max_rate_mbps,
        stations: info.stations,
        utilization: info.utilization,
        country: info.country,
        center_mhz: info.center_mhz,
    }
}

/// SSID bytes as text; hidden networks (empty or all-zero names) give "".
pub fn ssid_text(ssid: &[u8]) -> String {
    if ssid.iter().all(|&b| b == 0) {
        return String::new();
    }
    String::from_utf8_lossy(ssid).into_owned()
}

fn ssid_bytes(ssid: &windows::Win32::NetworkManagement::WiFi::DOT11_SSID) -> &[u8] {
    let len = (ssid.uSSIDLength as usize).min(ssid.ucSSID.len());
    ssid.ucSSID.get(..len).unwrap_or(&[])
}

/// Security per SSID from the available-network list (used for entries
/// without information elements).
fn available_security(client: &Client, guid: &GUID) -> Result<HashMap<Vec<u8>, &'static str>, u32> {
    let mut list: *mut WLAN_AVAILABLE_NETWORK_LIST = std::ptr::null_mut();
    // SAFETY: valid out pointer; the list is freed by the guard.
    let rc = unsafe { WlanGetAvailableNetworkList(client.0, guid, 0, None, &mut list) };
    let guard = WlanMemory(list);
    if rc != 0 {
        return Err(rc);
    }
    let mut out = HashMap::new();
    if guard.0.is_null() {
        return Ok(out);
    }
    // SAFETY: on success the header is followed by `dwNumberOfItems` entries,
    // each copied out before the guard frees the list.
    unsafe {
        let count = ((*guard.0).dwNumberOfItems as usize).min(4096);
        let first = std::ptr::addr_of!((*guard.0).Network) as *const WLAN_AVAILABLE_NETWORK;
        for i in 0..count {
            let net = std::ptr::read_unaligned(first.add(i));
            let label = if net.bSecurityEnabled.as_bool() {
                auth_label(
                    net.dot11DefaultAuthAlgorithm.0,
                    net.dot11DefaultCipherAlgorithm.0,
                )
            } else {
                "Open"
            };
            out.entry(ssid_bytes(&net.dot11Ssid).to_vec())
                .or_insert(label);
        }
    }
    Ok(out)
}

/// The driver's BSS list, interpreted.
fn bss_list(client: &Client, guid: &GUID) -> Result<Vec<Bss>, u32> {
    let mut list: *mut WLAN_BSS_LIST = std::ptr::null_mut();
    // SAFETY: valid out pointer; no SSID filter; the list is freed by the guard.
    let rc = unsafe {
        WlanGetNetworkBssList(
            client.0,
            guid,
            None,
            dot11_BSS_type_any,
            BOOL(0),
            None,
            &mut list,
        )
    };
    let guard = WlanMemory(list);
    if rc != 0 {
        return Err(rc);
    }
    if guard.0.is_null() {
        return Ok(Vec::new());
    }
    let fallback = available_security(client, guid).unwrap_or_default();
    let mut out = Vec::new();
    // SAFETY: the list is `dwTotalSize` bytes long: a header, `dwNumberOfItems`
    // fixed-size entries, then the information elements each entry points to
    // by an offset from its own start. Every offset is checked against the
    // total size before it is used, and entries are copied out unaligned.
    unsafe {
        let total = (*guard.0).dwTotalSize as usize;
        let base = guard.0 as *const u8;
        let first = std::ptr::addr_of!((*guard.0).wlanBssEntries) as *const WLAN_BSS_ENTRY;
        let entries_at = first as usize - base as usize;
        let entry_size = std::mem::size_of::<WLAN_BSS_ENTRY>();
        let fits = total.saturating_sub(entries_at) / entry_size;
        let count = ((*guard.0).dwNumberOfItems as usize).min(fits).min(4096);
        for i in 0..count {
            let entry = std::ptr::read_unaligned(first.add(i));
            let entry_at = entries_at + i * entry_size;
            let ie_len = entry.ulIeSize as usize;
            let ies: &[u8] = match entry_at
                .checked_add(entry.ulIeOffset as usize)
                .and_then(|start| start.checked_add(ie_len).map(|end| (start, end)))
            {
                Some((start, end)) if ie_len > 0 && end <= total => {
                    std::slice::from_raw_parts(base.add(start), ie_len)
                }
                _ => &[],
            };
            let ssid = ssid_bytes(&entry.dot11Ssid);
            let rate_count = (entry.wlanRateSet.uRateSetLength as usize / 2)
                .min(entry.wlanRateSet.usRateSet.len());
            let raw = RawBss {
                ssid,
                bssid: entry.dot11Bssid,
                rssi_dbm: entry.lRssi,
                link_quality: entry.uLinkQuality,
                freq_khz: entry.ulChCenterFrequency,
                beacon_period_tu: entry.usBeaconPeriod,
                capability: entry.usCapabilityInformation,
                phy_type: entry.dot11BssPhyType.0,
                rates: entry.wlanRateSet.usRateSet.get(..rate_count).unwrap_or(&[]),
                ies,
            };
            out.push(bss_from_raw(&raw, fallback.get(ssid).copied()));
        }
    }
    Ok(out)
}

fn current_attributes(
    client: &Client,
    guid: &GUID,
) -> Result<Option<WLAN_CONNECTION_ATTRIBUTES>, u32> {
    match query::<WLAN_CONNECTION_ATTRIBUTES>(client, guid, wlan_intf_opcode_current_connection) {
        Ok(a) if a.isState == wlan_interface_state_connected => Ok(Some(a)),
        Ok(_) | Err(ERROR_INVALID_STATE) => Ok(None),
        Err(code) => Err(code),
    }
}

/// The access points currently in the driver's list, strongest first.
pub fn scan_results(interface_guid: &str) -> Result<Vec<Bss>, WlanError> {
    let guid = parse_guid(interface_guid).ok_or_else(bad_guid)?;
    let client = Client::open()?;
    let mut list = bss_list(&client, &guid)
        .map_err(|code| classify(code, "reading the list of nearby networks", true))?;
    if let Ok(Some(attrs)) = current_attributes(&client, &guid) {
        let bssid = oui::format_mac(&attrs.wlanAssociationAttributes.dot11Bssid);
        for bss in list.iter_mut().filter(|b| b.bssid == bssid) {
            bss.connected = true;
        }
    }
    list.sort_by(|a, b| {
        b.rssi_dbm
            .cmp(&a.rssi_dbm)
            .then_with(|| a.ssid.cmp(&b.ssid))
    });
    Ok(list)
}

/// What `wlan_intf_opcode_realtime_connection_quality` reports for the
/// first link (Windows 11 24H2 and later).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Realtime {
    pub rx_kbps: u32,
    pub tx_kbps: u32,
    pub freq_mhz: u32,
    pub width_mhz: Option<u16>,
    pub rssi_dbm: i32,
}

/// Reads a `WLAN_REALTIME_CONNECTION_QUALITY` blob. The structure is not in
/// the bindings this crate uses, so the bytes are read by offset and every
/// value is checked for plausibility; anything odd gives `None`.
pub(crate) fn parse_realtime(bytes: &[u8]) -> Option<Realtime> {
    let u32_at = |at: usize| -> Option<u32> {
        let b = bytes.get(at..at.checked_add(4)?)?;
        Some(u32::from_le_bytes([
            *b.first()?,
            *b.get(1)?,
            *b.get(2)?,
            *b.get(3)?,
        ]))
    };
    // Header: PHY type, link quality, receive rate, transmit rate, MLO flag, link count.
    let phy = u32_at(0)?;
    let quality = u32_at(4)?;
    let rx_kbps = u32_at(8)?;
    let tx_kbps = u32_at(12)?;
    let links = u32_at(20)?;
    if phy > 32 || quality > 100 || links == 0 || links > 16 {
        return None;
    }
    // First link: link id (padded to 4), centre frequency, bandwidth, RSSI.
    let mut freq = u32_at(28)?;
    let mut width = u32_at(32)?;
    let rssi = u32_at(36)? as i32;
    if freq > 100_000 {
        freq /= 1000;
    }
    if width >= 20_000 {
        width /= 1000;
    }
    channels::channel_from_freq(freq)?;
    if !(-120..=0).contains(&rssi) {
        return None;
    }
    Some(Realtime {
        rx_kbps,
        tx_kbps,
        freq_mhz: freq,
        width_mhz: matches!(width, 20 | 40 | 80 | 160 | 320).then_some(width as u16),
        rssi_dbm: rssi,
    })
}

/// The current association, `None` when not connected.
///
/// `mcs` and `streams` stay `None`: Native Wifi does not expose them (the
/// real-time connection quality of Windows 11 24H2 carries rates, RSSI and
/// bandwidth, but no MCS index or stream count).
pub fn current_link(interface_guid: &str) -> Result<Option<Link>, WlanError> {
    let guid = parse_guid(interface_guid).ok_or_else(bad_guid)?;
    let client = Client::open()?;
    let attrs = match current_attributes(&client, &guid) {
        Ok(Some(a)) => a,
        Ok(None) => return Ok(None),
        Err(code) => return Err(classify(code, "reading the Wi-Fi connection", true)),
    };
    let assoc = attrs.wlanAssociationAttributes;
    let sec = attrs.wlanSecurityAttributes;
    let description = enum_interfaces(&client)
        .unwrap_or_default()
        .iter()
        .find(|i| i.InterfaceGuid == guid)
        .map(|i| wide_to_string(&i.strInterfaceDescription))
        .unwrap_or_default();
    let bssid = oui::format_mac(&assoc.dot11Bssid);
    let (phy, generation) = phy_name(assoc.dot11PhyType.0);
    let quality = assoc.wlanSignalQuality.min(100) as u8;
    let mut link = Link {
        interface_guid: format_guid(&guid),
        interface: description,
        profile: wide_to_string(&attrs.strProfileName),
        ssid: ssid_text(ssid_bytes(&assoc.dot11Ssid)),
        vendor: oui::vendor(&bssid).map(str::to_string),
        bssid,
        phy: phy.to_string(),
        generation,
        rssi_dbm: channels::rssi_from_quality(quality),
        quality,
        rx_rate_mbps: assoc.ulRxRate as f32 / 1000.0,
        tx_rate_mbps: assoc.ulTxRate as f32 / 1000.0,
        security: if sec.bSecurityEnabled.as_bool() {
            auth_label(sec.dot11AuthAlgorithm.0, sec.dot11CipherAlgorithm.0).to_string()
        } else {
            "Open".to_string()
        },
        cipher: cipher_label(sec.dot11CipherAlgorithm.0).to_string(),
        ..Link::default()
    };

    // The matching scan entry knows the frequency, the width and the real RSSI.
    let mut have_frequency = false;
    if let Ok(list) = bss_list(&client, &guid) {
        if let Some(bss) = list.iter().find(|b| b.bssid == link.bssid) {
            link.rssi_dbm = bss.rssi_dbm;
            link.freq_mhz = bss.freq_mhz;
            link.channel = bss.channel;
            link.band = bss.band;
            link.width_mhz = bss.width_mhz;
            if !bss.phy.is_empty() && link.phy.is_empty() {
                link.phy = bss.phy.clone();
                link.generation = bss.generation;
            }
            have_frequency = bss.freq_mhz > 0;
        }
    }
    let channel_number = query::<u32>(&client, &guid, wlan_intf_opcode_channel_number)
        .ok()
        .and_then(|c| u16::try_from(c).ok())
        .filter(|c| *c > 0);
    if !have_frequency {
        if let Some(ch) = channel_number {
            // A bare channel number cannot tell 5 GHz from 6 GHz; 5 GHz is
            // assumed unless the real-time data below says otherwise.
            let band = if ch <= 14 { Band::B24 } else { Band::B5 };
            link.channel = ch;
            link.band = band;
            link.freq_mhz = channels::freq_from_channel(band, ch).unwrap_or(0);
        }
    }
    if let Some(rt) = query_bytes(&client, &guid, OPCODE_REALTIME_CONNECTION_QUALITY)
        .ok()
        .and_then(|bytes| parse_realtime(&bytes))
    {
        // Trusted only when it agrees with the channel Windows reports.
        let rt_channel = channels::channel_from_freq(rt.freq_mhz);
        let agrees = match (rt_channel, channel_number) {
            (Some((_, ch)), Some(reported)) => ch == reported,
            (Some(_), None) => have_frequency && rt.freq_mhz == link.freq_mhz,
            _ => false,
        };
        if agrees {
            if let Some((band, ch)) = rt_channel {
                link.freq_mhz = rt.freq_mhz;
                link.band = band;
                link.channel = ch;
            }
            link.rssi_dbm = rt.rssi_dbm;
            if link.width_mhz.is_none() {
                link.width_mhz = rt.width_mhz;
            }
            if rt.rx_kbps > 0 && rt.tx_kbps > 0 {
                link.rx_rate_mbps = rt.rx_kbps as f32 / 1000.0;
                link.tx_rate_mbps = rt.tx_kbps as f32 / 1000.0;
            }
        }
    }
    Ok(Some(link))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ie::testdata::*;

    #[test]
    fn guid_round_trip() {
        let text = "{01234567-89AB-CDEF-0123-456789ABCDEF}";
        let guid = parse_guid(text);
        assert!(guid.is_some());
        assert_eq!(guid.map(|g| format_guid(&g)).as_deref(), Some(text));
        assert_eq!(
            parse_guid("01234567-89ab-cdef-0123-456789abcdef")
                .map(|g| format_guid(&g))
                .as_deref(),
            Some(text)
        );
        for bad in [
            "",
            "{}",
            "hello",
            "{01234567-89AB-CDEF-0123-456789ABCDE}",
            "{0123456Z-89AB-CDEF-0123-456789ABCDEF}",
            "{+1234567-89AB-CDEF-0123-456789ABCDEF}",
        ] {
            assert!(parse_guid(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn error_mapping() {
        assert_eq!(classify(5, "x", true), WlanError::LocationDenied);
        assert_eq!(classify(5, "x", false), WlanError::AccessDenied);
        assert!(matches!(classify(1062, "x", true), WlanError::NoWifi(_)));
        assert!(matches!(classify(1168, "x", false), WlanError::NoWifi(_)));
        assert!(matches!(classify(87, "x", false), WlanError::Other(_)));
    }

    #[test]
    fn wide_strings() {
        assert_eq!(wide_to_string(&[0x48, 0x69, 0, 0x21]), "Hi");
        assert_eq!(wide_to_string(&[0x48, 0x69]), "Hi");
        assert_eq!(wide_to_string(&[]), "");
    }

    #[test]
    fn raw_entry_becomes_a_bss() {
        let ies = [
            rates(&[0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C]),
            ie(7, b"NL "),
            ie(11, &[3, 0, 51, 0, 0]),
            ht_cap(),
            ht_op(100, 1),
            vht_cap(),
            vht_op(1, 106, 0),
            rsn(&[2, 8], 0x80),
            he_cap(),
            he_op(None),
        ]
        .concat();
        let raw = RawBss {
            ssid: b"Maple-Home",
            bssid: [0x02, 0x00, 0x5E, 0x00, 0x53, 0x01],
            rssi_dbm: -58,
            link_quality: 84,
            freq_khz: 5_500_000,
            beacon_period_tu: 100,
            capability: 0x0011,
            phy_type: 8,
            rates: &[0x800C, 0x0012, 0x006C],
            ies: &ies,
        };
        let bss = bss_from_raw(&raw, Some("WPA2-Personal"));
        assert_eq!(bss.ssid, "Maple-Home");
        assert_eq!(bss.bssid, "02:00:5E:00:53:01");
        assert_eq!((bss.band, bss.channel, bss.freq_mhz), (Band::B5, 100, 5500));
        assert_eq!((bss.width_mhz, bss.center_mhz), (Some(80), Some(5530)));
        assert_eq!((bss.phy.as_str(), bss.generation), ("802.11ax", Some(6)));
        assert_eq!(bss.security, "WPA2/WPA3-Personal");
        assert_eq!((bss.rssi_dbm, bss.quality), (-58, 84));
        assert_eq!(bss.beacon_interval_ms, Some(102));
        assert_eq!(bss.max_rate_mbps, Some(54.0));
        assert_eq!((bss.stations, bss.utilization), (Some(3), Some(20)));
        assert_eq!(bss.country.as_deref(), Some("NL"));
        assert_eq!(bss.vendor, None);
        assert!(!bss.connected);
    }

    #[test]
    fn entry_without_elements_uses_the_fallbacks() {
        let raw = RawBss {
            ssid: &[0, 0, 0, 0],
            bssid: [0x02, 0x00, 0x5E, 0x00, 0x53, 0x02],
            rssi_dbm: -80,
            link_quality: 0,
            freq_khz: 2_437_000,
            phy_type: 7,
            rates: &[0x8002, 0x0016],
            ..RawBss::default()
        };
        let bss = bss_from_raw(&raw, Some("WPA2-Personal"));
        assert_eq!(bss.ssid, "");
        assert_eq!((bss.band, bss.channel), (Band::B24, 6));
        assert_eq!((bss.phy.as_str(), bss.generation), ("802.11n", Some(4)));
        assert_eq!(bss.security, "WPA2-Personal");
        assert_eq!(bss.width_mhz, None);
        assert_eq!(bss.quality, 40);
        assert_eq!(bss.max_rate_mbps, Some(11.0));
        assert_eq!(bss.beacon_interval_ms, None);
        // Without a fallback the privacy bit decides.
        assert_eq!(bss_from_raw(&raw, None).security, "Open");
    }

    #[test]
    fn odd_raw_values_do_not_panic() {
        let raw = RawBss {
            ssid: &[0xFF, 0xFE, 0x80],
            rssi_dbm: i32::MIN,
            link_quality: u32::MAX,
            freq_khz: u32::MAX,
            beacon_period_tu: u16::MAX,
            capability: u16::MAX,
            phy_type: i32::MIN,
            rates: &[u16::MAX, 0],
            ies: &[255, 255, 255],
            ..RawBss::default()
        };
        let bss = bss_from_raw(&raw, None);
        assert_eq!(bss.channel, 0);
        assert_eq!(bss.quality, 0);
        assert!(!bss.ssid.is_empty());
    }

    #[test]
    fn labels() {
        assert_eq!(auth_label(1, 0), "Open");
        assert_eq!(auth_label(1, 1), "WEP");
        assert_eq!(auth_label(7, 4), "WPA2-Personal");
        assert_eq!(auth_label(9, 4), "WPA3-Personal");
        assert_eq!(auth_label(6, 4), "WPA2-Enterprise");
        assert_eq!(auth_label(10, 4), "OWE");
        assert_eq!(auth_label(999, 4), "Unknown");
        assert_eq!(cipher_label(4), "CCMP (AES)");
        assert_eq!(cipher_label(-5), "Unknown");
        assert_eq!(phy_name(10), ("802.11ax", Some(6)));
        assert_eq!(phy_name(-1), ("", None));
    }

    fn realtime_blob(freq: u32, width: u32, rssi: i32, links: u32) -> Vec<u8> {
        let mut b = Vec::new();
        for v in [10u32, 90, 866_700, 720_600, 0, links] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.extend_from_slice(&freq.to_le_bytes());
        b.extend_from_slice(&width.to_le_bytes());
        b.extend_from_slice(&rssi.to_le_bytes());
        b.extend_from_slice(&[0u8; 256]);
        b
    }

    #[test]
    fn realtime_quality_is_read_only_when_plausible() {
        let rt = parse_realtime(&realtime_blob(5500, 80, -57, 1));
        assert_eq!(
            rt,
            Some(Realtime {
                rx_kbps: 866_700,
                tx_kbps: 720_600,
                freq_mhz: 5500,
                width_mhz: Some(80),
                rssi_dbm: -57
            })
        );
        assert_eq!(
            parse_realtime(&realtime_blob(5_500_000, 80_000, -57, 1))
                .map(|r| (r.freq_mhz, r.width_mhz)),
            Some((5500, Some(80)))
        );
        assert_eq!(
            parse_realtime(&realtime_blob(5500, 33, -57, 1)).and_then(|r| r.width_mhz),
            None
        );
        assert_eq!(parse_realtime(&realtime_blob(1234, 80, -57, 1)), None);
        assert_eq!(parse_realtime(&realtime_blob(5500, 80, 40, 1)), None);
        assert_eq!(parse_realtime(&realtime_blob(5500, 80, -57, 0)), None);
        assert_eq!(parse_realtime(&realtime_blob(5500, 80, -57, 9999)), None);
        let full = realtime_blob(5500, 80, -57, 1);
        for cut in 0..40 {
            assert_eq!(parse_realtime(full.get(..cut).unwrap_or(&[])), None);
        }
        assert_eq!(parse_realtime(&[0xFF; 300]), None);
    }
}
