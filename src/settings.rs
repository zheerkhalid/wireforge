//! User settings, stored as JSON in `%LOCALAPPDATA%\WireForge\settings.json`.
//! Everything WireForge stores lives in that one folder.

use crate::fmt::Units;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemeChoice {
    Dark,
    Light,
    System,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: ThemeChoice,
    pub units: Units,
    /// Show an icon with live rates in the notification area.
    pub tray_icon: bool,
    /// Closing the window keeps WireForge running in the tray.
    pub close_to_tray: bool,
    /// The small always-on-top meter.
    pub mini_meter: bool,
    pub meter_pos: Option<(i32, i32)>,
    /// Count bytes per app when running as administrator.
    pub per_app: bool,
    /// Look up host names of remote addresses (sends reverse-DNS queries to
    /// your DNS server). Off by default.
    pub resolve_hosts: bool,
    /// Days of usage history to keep (0 = forever).
    pub keep_days: u32,
    /// Monthly data allowance.
    pub cap_enabled: bool,
    pub cap_gb: f64,
    /// Day of the month the allowance starts again (1..=28).
    pub cap_start_day: u32,
    /// Warn at this percentage of the allowance.
    pub cap_warn_pct: u32,
    /// Tell me when a device that was never seen before joins the network.
    pub alert_new_device: bool,
    pub alert_cap: bool,
    /// Ask about each program the first time it connects to the internet
    /// (app firewall). Off by default.
    pub fw_alerts: bool,
    /// Ask the Wi-Fi adapter for a fresh scan every minute while the Wi-Fi page is open.
    pub wifi_auto_scan: bool,
    /// Rescan the local network for devices every ten minutes while WireForge runs.
    pub devices_auto_scan: bool,
    /// Agreed to the measurement service's data policy (asked before the first test).
    pub speed_consent: bool,
    /// The billing period (`2026-11-01`) for which the warning / exceeded
    /// alerts were already shown, so they appear once per period.
    pub cap_warned_period: String,
    pub cap_exceeded_period: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            theme: ThemeChoice::Dark,
            units: Units::Bytes,
            tray_icon: true,
            close_to_tray: false,
            mini_meter: false,
            meter_pos: None,
            per_app: true,
            resolve_hosts: false,
            keep_days: 400,
            cap_enabled: false,
            cap_gb: 100.0,
            cap_start_day: 1,
            cap_warn_pct: 80,
            alert_new_device: true,
            alert_cap: true,
            fw_alerts: false,
            wifi_auto_scan: true,
            devices_auto_scan: false,
            speed_consent: false,
            cap_warned_period: String::new(),
            cap_exceeded_period: String::new(),
        }
    }
}

impl Settings {
    /// Brings hand-edited values back into range.
    pub fn sanitized(mut self) -> Settings {
        if !self.cap_gb.is_finite() || self.cap_gb < 0.1 {
            self.cap_gb = 0.1;
        }
        self.cap_gb = self.cap_gb.min(100_000.0);
        self.cap_start_day = self.cap_start_day.clamp(1, 28);
        self.cap_warn_pct = self.cap_warn_pct.clamp(10, 100);
        self.keep_days = self.keep_days.min(3660);
        self
    }

    pub fn cap_bytes(&self) -> u64 {
        (self.cap_gb * 1024.0 * 1024.0 * 1024.0) as u64
    }

    pub fn load(dir: &Path) -> Settings {
        std::fs::read_to_string(dir.join("settings.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<Settings>(&t).ok())
            .unwrap_or_default()
            .sanitized()
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        let tmp = dir.join("settings.json.tmp");
        std::fs::write(&tmp, json).map_err(|e| format!("Could not save settings: {e}"))?;
        std::fs::rename(&tmp, dir.join("settings.json"))
            .map_err(|e| format!("Could not save settings: {e}"))
    }
}

/// `%LOCALAPPDATA%\WireForge`
pub fn data_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("WireForge")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_repair() {
        let dir = std::env::temp_dir().join(format!("wireforge-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(Settings::load(&dir), Settings::default());
        let s = Settings {
            theme: ThemeChoice::Light,
            units: Units::Bits,
            cap_enabled: true,
            cap_gb: 250.0,
            meter_pos: Some((-40, 900)),
            ..Default::default()
        };
        s.save(&dir).unwrap();
        assert_eq!(Settings::load(&dir), s);
        // Unknown and missing fields are tolerated; wild values are clamped.
        std::fs::write(
            dir.join("settings.json"),
            r#"{"theme":"Dark","cap_gb":-4,"cap_start_day":31,"cap_warn_pct":0,"future":1}"#,
        )
        .unwrap();
        let s = Settings::load(&dir);
        assert_eq!(s.cap_gb, 0.1);
        assert_eq!(s.cap_start_day, 28);
        assert_eq!(s.cap_warn_pct, 10);
        std::fs::write(dir.join("settings.json"), "not json").unwrap();
        assert_eq!(Settings::load(&dir), Settings::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cap_in_bytes() {
        let s = Settings {
            cap_gb: 1.5,
            ..Default::default()
        };
        assert_eq!(s.cap_bytes(), 1_610_612_736);
    }
}
