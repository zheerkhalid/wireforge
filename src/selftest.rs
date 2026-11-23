//! `--selftest`: runs every collector once and reports success or failure
//! with counts only (never addresses, names or keys).
//!
//! It does not scan the network for devices, does not run a speed test, does
//! not ask for the public IP address and changes nothing on the PC.

/// One line per check: `(name, Ok(summary) | Err(reason))`.
pub type Check = (String, Result<String, String>);

fn own_checks() -> Vec<Check> {
    let mut out: Vec<Check> = Vec::new();

    // Settings round trip in a scratch folder (the real settings are not touched).
    let dir = std::env::temp_dir().join(format!("wireforge-selftest-{}", std::process::id()));
    let result = (|| {
        let s = crate::settings::Settings {
            cap_enabled: true,
            ..Default::default()
        };
        s.save(&dir)?;
        if crate::settings::Settings::load(&dir) != s {
            return Err("settings did not round-trip".to_string());
        }
        Ok("saved and loaded in a scratch folder".to_string())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    out.push(("app: settings".into(), result));

    // Windows Defender Firewall, read only: counts only, nothing is changed.
    out.push((
        "app: firewall (read only)".into(),
        crate::firewall::read_view().map(|v| {
            format!(
                "{} profiles ({} on), {} rules, {} WireForge rules, lockdown {}",
                v.status.profiles.len(),
                v.status.profiles.iter().filter(|p| p.enabled).count(),
                v.rules.len(),
                v.rules
                    .iter()
                    .filter(|r| wf_firewall::naming::is_ours(r))
                    .count(),
                if v.lockdown.is_some() { "on" } else { "off" }
            )
        }),
    ));

    // The interface report over the real adapters: shape only.
    out.push((
        "app: interface report".into(),
        wf_traffic::adapters::list_adapters().map(|adapters| {
            let now = crate::sys::now_unix();
            let text = crate::report::text(&adapters, "", now, crate::sys::utc_offset());
            let tables = crate::report::tables(&adapters, now, 0);
            format!(
                "{} adapters, {} lines, {} tables",
                adapters.len(),
                text.lines().count(),
                tables.len()
            )
        }),
    ));

    // Export writers over invented profiles.
    let profiles = vec![
        wf_wifi::SavedProfile {
            name: "Maple-Home".into(),
            ssid: "Maple-Home".into(),
            security: "WPA2-Personal".into(),
            key: wf_wifi::KeyState::Key("maple-kettle-2041".into()),
            ..Default::default()
        },
        wf_wifi::SavedProfile {
            name: "Corner Cafe".into(),
            ssid: "Corner Cafe".into(),
            security: "Open".into(),
            key: wf_wifi::KeyState::Open,
            ..Default::default()
        },
    ];
    let table = crate::export::saved_networks_table(&profiles, false);
    let csv = crate::export::to_csv(std::slice::from_ref(&table));
    let leaked = profiles.iter().any(|p| match &p.key {
        wf_wifi::KeyState::Key(k) => csv.contains(k.as_str()),
        _ => false,
    });
    out.push((
        "app: export masking".into(),
        if leaked {
            Err("a password appeared in a masked export".into())
        } else {
            Ok(format!(
                "{} invented profiles exported with passwords masked",
                table.rows.len()
            ))
        },
    ));

    out.push((
        "app: startup entry".into(),
        Ok(format!(
            "start with Windows is {} (read only, not changed)",
            if crate::sys::startup_enabled() {
                "on"
            } else {
                "off"
            }
        )),
    ));
    out.push((
        "app: rights".into(),
        Ok(if crate::sys::is_elevated() {
            "running as administrator".to_string()
        } else {
            "running with standard rights (per-app byte counts need administrator rights)"
                .to_string()
        }),
    ));
    out
}

/// Runs everything. Takes a few seconds; never call it on the UI thread.
pub fn run() -> Vec<Check> {
    let mut out: Vec<Check> = Vec::new();
    for (prefix, checks) in [
        ("traffic", wf_traffic::selftest()),
        ("wifi", wf_wifi::selftest()),
        ("tools", wf_tools::selftest()),
    ] {
        for (name, result) in checks {
            out.push((format!("{prefix}: {name}"), result));
        }
    }
    out.extend(own_checks());
    out
}

/// Checks that are expected to fail without administrator rights; the
/// self-test reports them but does not count them as failures.
pub fn needs_admin(name: &str, reason: &str) -> bool {
    name.starts_with("traffic: etw") && reason.to_lowercase().contains("administrator")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_only_checks_are_recognised() {
        assert!(needs_admin("traffic: etw", "needs administrator rights"));
        assert!(!needs_admin("traffic: etw", "the session could not start"));
        assert!(!needs_admin(
            "wifi: interfaces",
            "needs administrator rights"
        ));
    }
}
