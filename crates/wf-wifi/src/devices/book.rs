//! Devices remembered between scans.

use crate::types::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Format version written to the file.
const VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct BookFile {
    version: u32,
    devices: Vec<KnownDevice>,
}

fn write_then_rename(tmp: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(tmp, path)
}

/// Devices remembered between scans, with the user's names for them.
///
/// A device is identified by its MAC address. A device for which no MAC is
/// known is identified by its IP address instead: its `mac` field is empty
/// and `set_label` / `set_known` / `forget` accept the IP in place of the MAC.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceBook {
    pub devices: Vec<KnownDevice>,
}

impl DeviceBook {
    /// A missing or damaged file gives an empty book.
    pub fn load(path: &Path) -> DeviceBook {
        let Ok(bytes) = std::fs::read(path) else {
            return DeviceBook::default();
        };
        match serde_json::from_slice::<BookFile>(&bytes) {
            // A file from a newer version of the program is left alone
            // (reading it could silently drop what this version does not know).
            Ok(file) if file.version <= VERSION => DeviceBook {
                devices: file.devices,
            },
            _ => DeviceBook::default(),
        }
    }

    /// Writes the book as JSON: first to a temporary file next to `path`,
    /// then renamed over it, so a crash never leaves half a file.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let file = BookFile {
            version: VERSION,
            devices: self.devices.clone(),
        };
        let json = serde_json::to_vec_pretty(&file)
            .map_err(|e| format!("The device list could not be prepared for saving ({e})."))?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    format!("The folder for the device list could not be created ({e}).")
                })?;
            }
        }
        let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
        tmp_name.push(format!(".{}.tmp", std::process::id()));
        let tmp = path.with_file_name(tmp_name);
        write_then_rename(&tmp, path, &json).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("The device list could not be saved ({e}).")
        })
    }

    fn position(&self, key: &str) -> Option<usize> {
        let key = key.trim();
        if key.is_empty() {
            return None;
        }
        self.devices
            .iter()
            .position(|d| !d.mac.is_empty() && d.mac.eq_ignore_ascii_case(key))
            .or_else(|| {
                self.devices
                    .iter()
                    .position(|d| d.mac.is_empty() && d.last_ip == key)
            })
    }

    /// Folds a scan result in (keyed by MAC, by IP when there is no MAC):
    /// updates last seen / IP / names, marks everything else offline and
    /// returns the MACs that were never seen before. The very first scan
    /// (empty book) returns no "new" devices.
    ///
    /// A label and the "known" mark are never touched. A name, vendor or
    /// hint is only replaced when the scan found one. A device first seen
    /// without a MAC and later, at the same address, with one keeps its
    /// entry (and label) and is not reported as new. This PC itself is never
    /// reported as new.
    pub fn merge(&mut self, found: &[FoundDevice], now_unix: i64) -> Vec<String> {
        let first_scan = self.devices.is_empty();
        for d in &mut self.devices {
            d.online = false;
        }
        let mut new_macs = Vec::new();
        for f in found {
            let mac = f.mac.trim().to_ascii_uppercase();
            let index = if mac.is_empty() {
                if f.ip.is_empty() {
                    continue;
                }
                self.devices
                    .iter()
                    .position(|d| d.mac.is_empty() && d.last_ip == f.ip)
            } else {
                self.devices
                    .iter()
                    .position(|d| d.mac.eq_ignore_ascii_case(&mac))
                    .or_else(|| {
                        // Seen before at this address, but without a MAC.
                        self.devices
                            .iter()
                            .position(|d| d.mac.is_empty() && !f.ip.is_empty() && d.last_ip == f.ip)
                    })
            };
            let index = match index {
                Some(i) => i,
                None => {
                    if !first_scan && !mac.is_empty() && !f.is_self && !new_macs.contains(&mac) {
                        new_macs.push(mac.clone());
                    }
                    self.devices.push(KnownDevice {
                        first_seen: now_unix,
                        ..KnownDevice::default()
                    });
                    self.devices.len() - 1
                }
            };
            let Some(d) = self.devices.get_mut(index) else {
                continue;
            };
            if !mac.is_empty() {
                d.mac = mac;
            }
            d.last_seen = now_unix;
            if !f.ip.is_empty() {
                d.last_ip = f.ip.clone();
            }
            if f.vendor.is_some() {
                d.vendor = f.vendor.clone();
            }
            if f.name.is_some() {
                d.name = f.name.clone();
                d.name_source = f.name_source.clone();
            }
            if f.kind_hint.is_some() {
                d.kind_hint = f.kind_hint.clone();
            }
            d.is_gateway = f.is_gateway;
            d.is_self = f.is_self;
            d.random_mac = f.random_mac;
            d.online = true;
            d.rtt_ms = f.rtt_ms;
        }
        new_macs
    }

    /// Sets the user's name for a device (MAC, or IP for a device without one).
    pub fn set_label(&mut self, mac: &str, label: &str) {
        if let Some(d) = self.position(mac).and_then(|i| self.devices.get_mut(i)) {
            d.label = label.trim().to_string();
        }
    }

    pub fn set_known(&mut self, mac: &str, known: bool) {
        if let Some(d) = self.position(mac).and_then(|i| self.devices.get_mut(i)) {
            d.known = known;
        }
    }

    pub fn forget(&mut self, mac: &str) {
        if let Some(i) = self.position(mac) {
            self.devices.remove(i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(ip: &str, mac: &str) -> FoundDevice {
        FoundDevice {
            ip: ip.into(),
            mac: mac.into(),
            ..Default::default()
        }
    }

    const A: &str = "00:00:5E:00:53:0A";
    const B: &str = "00:00:5E:00:53:0B";
    const C: &str = "00:00:5E:00:53:0C";

    #[test]
    fn first_scan_reports_nothing_new() {
        let mut book = DeviceBook::default();
        let new = book.merge(&[found("192.0.2.1", A), found("192.0.2.2", B)], 1000);
        assert!(new.is_empty());
        assert_eq!(book.devices.len(), 2);
        assert!(book
            .devices
            .iter()
            .all(|d| d.online && d.first_seen == 1000 && d.last_seen == 1000 && !d.known));
    }

    #[test]
    fn later_unknown_mac_is_new() {
        let mut book = DeviceBook::default();
        book.merge(&[found("192.0.2.1", A)], 1000);
        let new = book.merge(
            &[
                found("192.0.2.1", A),
                found("192.0.2.3", "00:00:5e:00:53:0c"),
            ],
            2000,
        );
        assert_eq!(new, vec![C.to_string()]);
        // Seen again: not new any more.
        let new = book.merge(&[found("192.0.2.1", A), found("192.0.2.3", C)], 3000);
        assert!(new.is_empty());
        let c = book
            .devices
            .iter()
            .find(|d| d.mac == C)
            .cloned()
            .unwrap_or_default();
        assert_eq!((c.first_seen, c.last_seen), (2000, 3000));
        // The same new MAC listed twice is reported once.
        let new = book.merge(&[found("192.0.2.9", B), found("192.0.2.9", B)], 4000);
        assert_eq!(new, vec![B.to_string()]);
        assert_eq!(book.devices.iter().filter(|d| d.mac == B).count(), 1);
    }

    #[test]
    fn this_pc_is_never_new() {
        let mut book = DeviceBook::default();
        book.merge(&[found("192.0.2.1", A)], 1000);
        let me = FoundDevice {
            is_self: true,
            ..found("192.0.2.50", B)
        };
        assert!(book.merge(&[found("192.0.2.1", A), me], 2000).is_empty());
        assert!(book.devices.iter().any(|d| d.mac == B && d.is_self));
    }

    #[test]
    fn label_and_known_survive() {
        let mut book = DeviceBook::default();
        book.merge(&[found("192.0.2.1", A)], 1000);
        book.set_label("00-00-5e-00-53-0a", "  Kitchen speaker ");
        book.set_label(A, "Kitchen speaker");
        book.set_known(A, true);
        let scan = FoundDevice {
            name: Some("speaker-7".into()),
            name_source: Some("mDNS".into()),
            vendor: Some("Example Audio".into()),
            kind_hint: Some("AirPlay speaker".into()),
            rtt_ms: Some(4),
            ..found("192.0.2.1", A)
        };
        book.merge(&[scan], 2000);
        // A later scan without a name keeps the one found before.
        book.merge(&[found("192.0.2.1", A)], 3000);
        let d = book.devices.first().cloned().unwrap_or_default();
        assert_eq!(d.label, "Kitchen speaker");
        assert!(d.known);
        assert_eq!(d.name.as_deref(), Some("speaker-7"));
        assert_eq!(d.name_source.as_deref(), Some("mDNS"));
        assert_eq!(d.vendor.as_deref(), Some("Example Audio"));
        assert_eq!(d.kind_hint.as_deref(), Some("AirPlay speaker"));
        assert_eq!(d.rtt_ms, None);
        assert_eq!((d.first_seen, d.last_seen), (1000, 3000));
        // Labelling an unknown device does nothing.
        book.set_label(B, "ghost");
        book.set_label("", "ghost");
        assert_eq!(book.devices.len(), 1);
    }

    #[test]
    fn missing_devices_go_offline_and_come_back() {
        let mut book = DeviceBook::default();
        book.merge(&[found("192.0.2.1", A), found("192.0.2.2", B)], 1000);
        book.merge(&[found("192.0.2.1", A)], 2000);
        let b = book
            .devices
            .iter()
            .find(|d| d.mac == B)
            .cloned()
            .unwrap_or_default();
        assert!(!b.online);
        assert_eq!(b.last_seen, 1000);
        assert!(book.devices.iter().any(|d| d.mac == A && d.online));
        book.merge(&[], 3000);
        assert!(book.devices.iter().all(|d| !d.online));
        assert_eq!(book.devices.len(), 2);
        assert!(book.merge(&[found("192.0.2.2", B)], 4000).is_empty());
        assert!(book
            .devices
            .iter()
            .any(|d| d.mac == B && d.online && d.last_seen == 4000));
    }

    #[test]
    fn device_without_mac_is_keyed_by_ip() {
        let mut book = DeviceBook::default();
        book.merge(&[found("192.0.2.1", A)], 1000);
        let new = book.merge(&[found("192.0.2.1", A), found("192.0.2.7", "")], 2000);
        assert!(new.is_empty(), "only MACs are reported as new");
        assert_eq!(book.devices.len(), 2);
        book.set_label("192.0.2.7", "Mystery box");
        book.merge(&[found("192.0.2.7", "")], 3000);
        assert_eq!(book.devices.len(), 2);
        let d = book
            .devices
            .iter()
            .find(|d| d.last_ip == "192.0.2.7")
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            (d.label.as_str(), d.first_seen, d.last_seen, d.online),
            ("Mystery box", 2000, 3000, true)
        );
        // Another address without a MAC is another entry.
        book.merge(&[found("192.0.2.8", "")], 4000);
        assert_eq!(book.devices.len(), 3);
        // The MAC turns up later at the same address: same entry, not new.
        let new = book.merge(&[found("192.0.2.7", B)], 5000);
        assert!(new.is_empty());
        assert_eq!(book.devices.len(), 3);
        let d = book
            .devices
            .iter()
            .find(|d| d.mac == B)
            .cloned()
            .unwrap_or_default();
        assert_eq!(d.label, "Mystery box");
        // Entries with neither MAC nor IP are ignored.
        book.merge(&[found("", "")], 6000);
        assert_eq!(book.devices.len(), 3);
        book.forget("192.0.2.8");
        assert_eq!(book.devices.len(), 2);
    }

    #[test]
    fn ip_change_of_a_known_mac() {
        let mut book = DeviceBook::default();
        book.merge(&[found("192.0.2.1", A), found("192.0.2.2", B)], 1000);
        book.set_label(B, "Laptop");
        let new = book.merge(&[found("192.0.2.1", A), found("192.0.2.99", B)], 2000);
        assert!(new.is_empty());
        assert_eq!(book.devices.len(), 2);
        let b = book
            .devices
            .iter()
            .find(|d| d.mac == B)
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            (b.last_ip.as_str(), b.label.as_str(), b.first_seen),
            ("192.0.2.99", "Laptop", 1000)
        );
        // Two devices swapping addresses stay two devices.
        book.merge(&[found("192.0.2.99", A), found("192.0.2.1", B)], 3000);
        assert_eq!(book.devices.len(), 2);
        assert!(book
            .devices
            .iter()
            .any(|d| d.mac == A && d.last_ip == "192.0.2.99"));
    }

    #[test]
    fn forget_and_known() {
        let mut book = DeviceBook::default();
        book.merge(&[found("192.0.2.1", A), found("192.0.2.2", B)], 1000);
        book.set_known(B, true);
        book.set_known(B, false);
        assert!(book.devices.iter().all(|d| !d.known));
        book.forget(A);
        book.forget(C);
        assert_eq!(book.devices.len(), 1);
        // A forgotten device that shows up again is new again.
        assert_eq!(
            book.merge(&[found("192.0.2.1", A)], 2000),
            vec![A.to_string()]
        );
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("wf-wifi-book-test-{}", std::process::id()));
        let path = dir.join("nested").join("devices.json");
        let mut book = DeviceBook::default();
        book.merge(
            &[
                FoundDevice {
                    name: Some("caf\u{e9} \u{1F4F6}".into()),
                    ..found("192.0.2.1", A)
                },
                found("192.0.2.2", ""),
            ],
            1000,
        );
        book.set_label(A, "Kitchen \"speaker\"");
        book.set_known(A, true);
        assert_eq!(book.save(&path), Ok(()));
        assert_eq!(
            book.save(&path),
            Ok(()),
            "saving over an existing file works"
        );
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(text.contains("\"version\": 1"));
        assert_eq!(DeviceBook::load(&path), book);
        // No temporary file is left behind.
        let leftovers = std::fs::read_dir(dir.join("nested"))
            .map(|d| d.count())
            .unwrap_or(0);
        assert_eq!(leftovers, 1);

        // Missing, damaged, and too-new files all give an empty book.
        assert_eq!(
            DeviceBook::load(&dir.join("absent.json")),
            DeviceBook::default()
        );
        let _ = std::fs::write(&path, b"{ not json");
        assert_eq!(DeviceBook::load(&path), DeviceBook::default());
        let _ = std::fs::write(&path, b"{\"version\": 99, \"devices\": [{\"mac\": \"x\"}]}");
        assert_eq!(DeviceBook::load(&path), DeviceBook::default());
        // Unknown fields and missing fields are tolerated.
        let _ = std::fs::write(&path, b"{\"version\": 1, \"future\": true, \"devices\": [{\"mac\": \"00:00:5E:00:53:0A\", \"extra\": 1}]}");
        let loaded = DeviceBook::load(&path);
        assert_eq!(loaded.devices.len(), 1);
        assert_eq!(loaded.devices.first().map(|d| d.mac.as_str()), Some(A));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
