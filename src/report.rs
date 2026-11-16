//! The full interface report: every adapter with everything known about it,
//! in the spirit of `ipconfig /all`, as text and as export tables.

use crate::export::{yes_no, Table};
use crate::fmt;
use wf_traffic::AdapterInfo;

fn join<T: ToString>(items: &[T]) -> String {
    items
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// `(label, value)` pairs for one adapter, in display order. Empty values are kept
/// out so the report stays short.
pub fn adapter_fields(a: &AdapterInfo, now: i64, offset: i64) -> Vec<(&'static str, String)> {
    let mut f: Vec<(&'static str, String)> = vec![
        ("Description", a.description.clone()),
        ("Type", a.kind.label().to_string()),
        (
            "Status",
            if a.up { "Connected" } else { "Not connected" }.to_string(),
        ),
        ("Physical address (MAC)", a.mac.clone()),
        (
            "Link speed",
            if !a.up {
                String::new()
            } else if a.rx_link_bps == a.tx_link_bps {
                fmt::link_speed(a.rx_link_bps)
            } else {
                format!(
                    "{} down, {} up",
                    fmt::link_speed(a.rx_link_bps),
                    fmt::link_speed(a.tx_link_bps)
                )
            },
        ),
        (
            "MTU",
            if a.mtu > 0 {
                a.mtu.to_string()
            } else {
                String::new()
            },
        ),
        (
            "IPv4 address",
            a.ipv4
                .iter()
                .map(|n| format!("{}/{}", n.addr, n.prefix))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        (
            "Subnet mask",
            a.ipv4
                .first()
                .map(|n| prefix_to_mask(n.prefix))
                .unwrap_or_default(),
        ),
        (
            "IPv6 address",
            a.ipv6
                .iter()
                .map(|n| format!("{}/{}", n.addr, n.prefix))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        ("Default gateway", join(&a.gateways)),
        ("DNS servers", join(&a.dns_servers)),
        ("DNS suffix", a.dns_suffix.clone()),
        (
            "DHCP",
            if a.ipv4.is_empty() && !a.up {
                String::new()
            } else {
                yes_no(a.dhcp_enabled)
            },
        ),
        (
            "DHCP server",
            a.dhcp_server.map(|s| s.to_string()).unwrap_or_default(),
        ),
        (
            "Lease obtained",
            a.lease_obtained
                .map(|t| fmt::date_time(t, offset))
                .unwrap_or_default(),
        ),
        (
            "Lease expires",
            a.lease_expires
                .map(|t| {
                    if t > now {
                        format!(
                            "{} (in {})",
                            fmt::date_time(t, offset),
                            fmt::duration(t - now)
                        )
                    } else {
                        fmt::date_time(t, offset)
                    }
                })
                .unwrap_or_default(),
        ),
        (
            "Route metric",
            if a.ipv4_metric > 0 {
                a.ipv4_metric.to_string()
            } else {
                String::new()
            },
        ),
        (
            "Default route",
            if a.is_default {
                "Yes (internet traffic uses this adapter)".to_string()
            } else {
                String::new()
            },
        ),
        (
            "Received",
            if a.bytes_rx > 0 {
                format!(
                    "{} in {} packets",
                    fmt::bytes(a.bytes_rx),
                    fmt::thousands(a.packets_rx)
                )
            } else {
                String::new()
            },
        ),
        (
            "Sent",
            if a.bytes_tx > 0 {
                format!(
                    "{} in {} packets",
                    fmt::bytes(a.bytes_tx),
                    fmt::thousands(a.packets_tx)
                )
            } else {
                String::new()
            },
        ),
        (
            "Errors / discards",
            if a.errors_rx + a.errors_tx + a.discards_rx + a.discards_tx > 0 {
                format!(
                    "{} / {} received, {} / {} sent",
                    a.errors_rx, a.discards_rx, a.errors_tx, a.discards_tx
                )
            } else {
                String::new()
            },
        ),
        ("Interface index", a.index.to_string()),
        ("Interface GUID", a.guid.clone()),
    ];
    f.retain(|(_, v)| !v.is_empty());
    f
}

/// `24` -> `255.255.255.0`
pub fn prefix_to_mask(prefix: u8) -> String {
    let p = prefix.min(32) as u32;
    let mask: u32 = if p == 0 { 0 } else { u32::MAX << (32 - p) };
    std::net::Ipv4Addr::from(mask).to_string()
}

/// The whole report as plain text.
pub fn text(adapters: &[AdapterInfo], host: &str, now: i64, offset: i64) -> String {
    let mut out = String::new();
    out.push_str("WireForge interface report\r\n");
    out.push_str(&format!("Created: {}\r\n", fmt::date_time(now, offset)));
    if !host.is_empty() {
        out.push_str(&format!("Computer: {host}\r\n"));
    }
    let mut sorted: Vec<&AdapterInfo> = adapters.iter().collect();
    sorted.sort_by_key(|a| (!a.is_default, !a.up, !a.physical, a.name.to_lowercase()));
    for a in sorted {
        out.push_str("\r\n");
        out.push_str(&a.name);
        out.push_str("\r\n");
        out.push_str(&"-".repeat(a.name.chars().count().max(8)));
        out.push_str("\r\n");
        for (label, value) in adapter_fields(a, now, offset) {
            let dots = 27usize.saturating_sub(label.chars().count()) / 2;
            out.push_str(&format!(
                "  {label} {} : {value}\r\n",
                ". ".repeat(dots).trim_end()
            ));
        }
    }
    out
}

/// The report as export tables (one per adapter).
pub fn tables(adapters: &[AdapterInfo], now: i64, offset: i64) -> Vec<Table> {
    adapters
        .iter()
        .map(|a| {
            let mut t = Table::new(&a.name, &["Property", "Value"]);
            for (label, value) in adapter_fields(a, now, offset) {
                t.push(vec![label.to_string(), value]);
            }
            t
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert_eq!(prefix_to_mask(0), "0.0.0.0");
        assert_eq!(prefix_to_mask(8), "255.0.0.0");
        assert_eq!(prefix_to_mask(20), "255.255.240.0");
        assert_eq!(prefix_to_mask(24), "255.255.255.0");
        assert_eq!(prefix_to_mask(32), "255.255.255.255");
        assert_eq!(prefix_to_mask(77), "255.255.255.255");
    }

    #[test]
    fn report_shape() {
        let now = 1_800_000_000;
        let adapters = crate::demo::adapters(now);
        let report = text(&adapters, "DEMO-PC", now, 0);
        // The default adapter comes first, disconnected ones keep only what is known.
        let wifi = report.find("\r\nWi-Fi\r\n").unwrap();
        let eth = report.find("\r\nEthernet\r\n").unwrap();
        assert!(wifi < eth);
        assert!(report.contains("IPv4 address . . . . . . . : 192.168.50.23/24"));
        assert!(report.contains("Subnet mask . . . . . . . . : 255.255.255.0"));
        assert!(report.contains("Lease expires"));
        assert!(report.contains("Computer: DEMO-PC"));
        let eth_part = &report[eth..];
        let eth_part = &eth_part[..eth_part[2..]
            .find("\r\n\r\n")
            .map(|i| i + 2)
            .unwrap_or(eth_part.len())];
        assert!(eth_part.contains("Not connected"));
        assert!(!eth_part.contains("IPv4 address"));
        assert!(!eth_part.contains("Link speed"));
        let tables = tables(&adapters, now, 0);
        assert_eq!(tables.len(), adapters.len());
        assert!(tables[0]
            .rows
            .iter()
            .all(|r| r.len() == 2 && !r[1].is_empty()));
    }
}
