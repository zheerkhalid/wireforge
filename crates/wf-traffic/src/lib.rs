//! WireForge traffic collectors: adapters, rates, connections, per-process
//! byte counts and the local usage database.
//!
//! The public paths and signatures of this crate are the contract with the
//! user interface; items are only ever added.

pub mod types;
pub use types::*;

mod util;

/// Adapter inventory (IP Helper).
pub mod adapters;
/// TCP / UDP tables with owning processes.
pub mod connections;
/// Per-process byte counts from the kernel network trace (needs administrator rights).
pub mod etw;
/// The background sampler that feeds the Overview and Apps pages.
pub mod monitor;
/// Processes: names, icons, ending one.
pub mod procs;
/// Turning counter samples into rates (pure, unit-tested).
pub mod rates;
/// Reverse DNS for remote endpoints (only used when the user turns it on).
pub mod rdns;
/// The local usage database: bytes by day, adapter and app.
pub mod usage;

/// Runs every collector once and reports `(collector, Ok(summary) | Err(reason))`.
///
/// The summaries contain counts only, never addresses, names or paths, so the
/// result can be shown or logged as it is. Takes a few seconds (the monitor
/// and the trace are each observed for a moment). Makes no network request.
pub fn selftest() -> Vec<(String, Result<String, String>)> {
    let mut out: Vec<(String, Result<String, String>)> = Vec::new();
    let mut push =
        |name: &str, result: Result<String, String>| out.push((name.to_string(), result));

    push(
        "adapters",
        adapters::list_adapters().map(|list| {
            format!(
                "{} adapters, {} up, {} physical, {} default, {} with a DHCP lease",
                list.len(),
                list.iter().filter(|a| a.up).count(),
                list.iter().filter(|a| a.physical).count(),
                list.iter().filter(|a| a.is_default).count(),
                list.iter().filter(|a| a.lease_expires.is_some()).count(),
            )
        }),
    );

    push(
        "counters",
        adapters::read_counters().map(|list| {
            format!(
                "{} interfaces, {} with traffic",
                list.len(),
                list.iter().filter(|c| c.rx != 0 || c.tx != 0).count()
            )
        }),
    );

    push(
        "connections",
        connections::list_connections().map(|list| {
            format!(
                "{} rows ({} TCP, {} UDP), {} with a process name, {} with a path, {} with a creation time",
                list.len(),
                list.iter().filter(|c| c.proto == Proto::Tcp).count(),
                list.iter().filter(|c| c.proto == Proto::Udp).count(),
                list.iter().filter(|c| !c.process.is_empty()).count(),
                list.iter().filter(|c| !c.path.is_empty()).count(),
                list.iter().filter(|c| c.created.is_some()).count(),
            )
        }),
    );

    push("processes", {
        let listed = procs::snapshot_names().len();
        match procs::process_name(std::process::id()) {
            Some((name, path)) if !name.is_empty() && !path.is_empty() => Ok(format!(
                "own process resolved with a path, {listed} processes listed"
            )),
            Some(_) => Ok(format!(
                "own process resolved without a path, {listed} processes listed"
            )),
            None => Err("the own process could not be resolved".to_string()),
        }
    });

    push("icons", {
        let own = procs::process_name(std::process::id())
            .map(|(_, path)| path)
            .unwrap_or_default();
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        procs::exe_icon(&format!("{root}\\explorer.exe"), 32)
            .or_else(|| procs::exe_icon(&own, 32))
            .map(|icon| {
                format!(
                    "{}x{} icon, {} visible pixels",
                    icon.width,
                    icon.height,
                    icon.rgba
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .filter(|p| p[3] != 0)
                        .count()
                )
            })
            .ok_or_else(|| "no icon could be extracted".to_string())
    });

    push(
        "etw",
        match etw::EtwSession::start() {
            Ok(session) => {
                std::thread::sleep(std::time::Duration::from_millis(2500));
                let flows = session.drain();
                Ok(format!(
                    "trace running, {} data events, {} flows from {} processes",
                    session.events_seen(),
                    flows.len(),
                    {
                        let mut pids: Vec<u32> = flows.iter().map(|f| f.pid).collect();
                        pids.sort_unstable();
                        pids.dedup();
                        pids.len()
                    }
                ))
            }
            Err(etw::EtwError::NeedsAdmin) => Err("needs administrator rights".to_string()),
            Err(etw::EtwError::Other(why)) => Err(why),
        },
    );

    push("usage", {
        let today = Day::today();
        let mut db = usage::UsageDb::default();
        db.add_adapter(today, "selftest", 1000, 100);
        db.add_app(today, "selftest.exe", "selftest", 600, 60);
        db.add_adapter(today.minus_days(1), "selftest", 10, 1);
        let path = std::env::temp_dir().join(format!("wf-selftest-{}.json", std::process::id()));
        let result = db.save(&path).and_then(|_| {
            let back = usage::UsageDb::try_load(&path)?;
            if back == db {
                Ok(format!(
                    "{} rows saved and loaded, today is a valid date: {}",
                    back.records().len(),
                    today.is_valid()
                ))
            } else {
                Err("the saved database did not load back identically".to_string())
            }
        });
        let _ = std::fs::remove_file(&path);
        result
    });

    push("rdns", {
        // Loopback only: answered by the local resolver, nothing leaves the PC.
        let name = rdns::reverse_dns(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        Ok(format!(
            "loopback lookup returned {}",
            if name.is_some() { "a name" } else { "no name" }
        ))
    });

    push("monitor", {
        let monitor = monitor::Monitor::start(monitor::MonitorConfig::default());
        std::thread::sleep(std::time::Duration::from_millis(3300));
        let snap = monitor.snapshot();
        drop(monitor);
        if snap.taken_unix == 0 {
            Err("no snapshot was published".to_string())
        } else {
            Ok(format!(
                "{} samples, {} adapters ({} up), {} apps, {} connections, mode {}",
                snap.history.len(),
                snap.adapters.len(),
                snap.adapters.iter().filter(|a| a.up).count(),
                snap.apps.len(),
                snap.apps.iter().map(|a| a.connections as u64).sum::<u64>(),
                match snap.per_app_mode {
                    PerAppMode::Etw => "trace",
                    PerAppMode::ConnectionsOnly(_) => "connections only",
                    PerAppMode::Starting => "starting",
                }
            ))
        }
    });

    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn selftest_reports_every_collector_with_counts_only() {
        let report = super::selftest();
        let names: Vec<&str> = report.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "adapters",
                "counters",
                "connections",
                "processes",
                "icons",
                "etw",
                "usage",
                "rdns",
                "monitor"
            ]
        );
        for (name, result) in &report {
            match result {
                Ok(summary) => {
                    assert!(!summary.is_empty(), "{name}");
                    // No address, MAC or path may leak into a summary.
                    assert!(!summary.contains('\\'), "{name}");
                    assert!(!summary.contains("::"), "{name}");
                }
                // Without administrator rights only the trace may fail.
                Err(why) => assert_eq!(name, "etw", "{name} failed: {why}"),
            }
        }
    }
}
