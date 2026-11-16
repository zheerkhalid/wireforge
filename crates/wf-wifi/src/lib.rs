//! WireForge Wi-Fi and local-network collectors: Native Wifi (scan, link,
//! saved profiles), channel maths, MAC vendors, device discovery, QR codes.
//!
//! The public paths and signatures here are the contract with the user
//! interface. Everything is read-only with respect to the PC's network
//! configuration: the only requests sent are a Wi-Fi scan request and, when
//! the user starts a device scan, probes of the directly attached private
//! subnet.

pub mod types;
pub use types::*;

/// Frequencies, channels, signal maths, occupancy (pure, unit-tested).
pub mod channels;
/// Devices on the local network.
pub mod devices;
/// 802.11 information elements (pure, unit-tested).
pub mod ie;
/// MAC address helpers and the vendor table.
pub mod oui;
/// Saved Wi-Fi profiles and their keys.
pub mod profiles;
/// `WIFI:` QR codes.
pub mod qr;
/// Native Wifi: interfaces, scans, the current link.
pub mod wlan;
mod xml;

fn count<T>(items: &[T], test: impl Fn(&T) -> bool) -> usize {
    items.iter().filter(|i| test(i)).count()
}

/// Runs each collector once and reports what it found, as counts only (no
/// names, addresses or keys). The device scan is not run.
pub fn selftest() -> Vec<(String, Result<String, String>)> {
    let mut out: Vec<(String, Result<String, String>)> = Vec::new();

    let interfaces = wlan::interfaces();
    out.push((
        "interfaces".into(),
        interfaces
            .as_ref()
            .map(|list| {
                format!(
                    "{} adapters: {} connected, {} with the radio on",
                    list.len(),
                    count(list, |i| i.connected),
                    count(list, |i| i.radio_on)
                )
            })
            .map_err(|e| e.to_string()),
    ));
    let interfaces = interfaces.unwrap_or_default();

    let mut scan: Result<String, String> = Err("no Wi-Fi adapter to ask".into());
    let mut link: Result<String, String> = Err("no Wi-Fi adapter to ask".into());
    let mut link_found = false;
    for (index, interface) in interfaces.iter().enumerate() {
        match wlan::scan_results(&interface.guid) {
            Ok(list) => {
                let bands = [Band::B24, Band::B5, Band::B6]
                    .iter()
                    .filter(|b| list.iter().any(|n| n.band == **b))
                    .count();
                let summary = format!(
                    "{} networks, {} bands; {} with a vendor, {} hidden, {} with a channel width, {} Wi-Fi 6 or newer, {} with a station count, {} open, {} connected",
                    list.len(),
                    bands,
                    count(&list, |n| n.vendor.is_some()),
                    count(&list, |n| n.ssid.is_empty()),
                    count(&list, |n| n.width_mhz.is_some()),
                    count(&list, |n| n.generation.is_some_and(|g| g >= 6)),
                    count(&list, |n| n.stations.is_some()),
                    count(&list, |n| n.security == "Open"),
                    count(&list, |n| n.connected),
                );
                if index == 0 || scan.is_err() {
                    scan = Ok(summary);
                }
            }
            Err(e) => {
                if index == 0 {
                    scan = Err(e.to_string());
                }
            }
        }
        if !link_found {
            match wlan::current_link(&interface.guid) {
                Ok(Some(l)) => {
                    link_found = true;
                    link = Ok(format!(
                        "connected: frequency {}, channel width {}, signal {}, rates {}, security {}, vendor {}, MCS {}",
                        if l.freq_mhz > 0 { "known" } else { "unknown" },
                        if l.width_mhz.is_some() { "known" } else { "unknown" },
                        if l.rssi_dbm < 0 { "known" } else { "unknown" },
                        if l.rx_rate_mbps > 0.0 && l.tx_rate_mbps > 0.0 { "known" } else { "unknown" },
                        if l.security.is_empty() { "unknown" } else { "known" },
                        if l.vendor.is_some() { "known" } else { "unknown" },
                        if l.mcs.is_some() { "known" } else { "not exposed" },
                    ));
                }
                Ok(None) => {
                    if index == 0 || link.is_err() {
                        link = Ok("not connected".into());
                    }
                }
                Err(e) => {
                    if index == 0 {
                        link = Err(e.to_string());
                    }
                }
            }
        }
    }
    out.push(("scan results".into(), scan));
    out.push(("current link".into(), link));

    out.push((
        "saved profiles".into(),
        profiles::saved_profiles()
            .map(|list| {
                format!(
                    "{} profiles: {} with a readable key, {} needing administrator rights, {} enterprise, {} open, {} unavailable; {} for all users, {} auto-connect, {} hidden",
                    list.len(),
                    count(&list, |p| matches!(p.key, KeyState::Key(_))),
                    count(&list, |p| p.key == KeyState::NeedsAdmin),
                    count(&list, |p| p.key == KeyState::Enterprise),
                    count(&list, |p| p.key == KeyState::Open),
                    count(&list, |p| matches!(p.key, KeyState::Unavailable(_) | KeyState::Unknown)),
                    count(&list, |p| p.all_users),
                    count(&list, |p| p.auto_connect),
                    count(&list, |p| p.hidden),
                )
            })
            .map_err(|e| e.to_string()),
    ));

    out.push((
        "vendor table".into(),
        if oui::table_len() > 0 && oui::vendor("00:00:0C:00:00:01").is_some() {
            Ok(format!(
                "{} prefixes, {} vendor names",
                oui::table_len(),
                oui::vendor_count()
            ))
        } else {
            Err("the embedded vendor table is empty or damaged".into())
        },
    ));

    let payload = qr::wifi_payload(
        "Maple-Home",
        "correct horse battery",
        "WPA2-Personal",
        false,
    );
    out.push((
        "qr matrix".into(),
        match qr::matrix(payload.as_bytes()) {
            Some(m) => Ok(format!(
                "{} x {} modules, {} dark (sample network)",
                m.width,
                m.width,
                count(&m.dark, |d| *d)
            )),
            None => Err("the sample code could not be built".into()),
        },
    ));

    let networks = devices::attached_networks();
    out.push((
        "attached networks".into(),
        Ok(format!(
            "{} IPv4 networks: {} that may be scanned, {} with a gateway, {} on Wi-Fi (the device scan was not run)",
            networks.len(),
            count(&networks, |n| n.subnet.scan_refusal().is_none()),
            count(&networks, |n| n.gateway.is_some()),
            count(&networks, |n| n.wifi),
        )),
    ));
    out
}
