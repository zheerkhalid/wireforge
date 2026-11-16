//! Invented results for the Tools and Speed test pages in `--demo`.
//! Addresses come from private and documentation ranges (RFC 1918 / 5737 /
//! 3849), names from `example.org`: nothing here was ever measured.

use super::Lcg;
use wf_tools::{
    DnsAnswer, DnsRecord, Hop, PingReply, PortResult, PortState, SpeedPhase, SpeedProgress,
    SpeedResult,
};

/// The router of the invented home network.
pub const GATEWAY: &str = "192.168.50.1";
/// The host the invented traceroute, DNS lookup and whois are about.
pub const HOST: &str = "example.org";
/// An invented network card address (locally administered range).
pub const WAKE_MAC: &str = "02:00:5E:10:20:30";
pub const WAKE_BROADCAST: &str = "192.168.50.255";
pub const SUBNET: &str = "192.168.50.23/24";
pub const PORTS: &str = "22, 53, 80, 443, 8080";

/// About a minute of pings to the router, with two lost replies.
pub fn ping_replies() -> Vec<PingReply> {
    let mut rng = Lcg(41);
    (1..=60u32)
        .map(|seq| {
            if seq == 23 || seq == 47 {
                return PingReply {
                    seq,
                    status: "Timed out".into(),
                    ..Default::default()
                };
            }
            let spike = if seq % 17 == 0 { 9.0 } else { 0.0 };
            let rtt = 1.6 + rng.next() * 2.4 + spike * rng.next();
            PingReply {
                seq,
                from: Some(GATEWAY.into()),
                rtt_ms: Some((rtt * 100.0).round() as f32 / 100.0),
                ttl: Some(64),
                status: "Reply".into(),
                ok: true,
            }
        })
        .collect()
}

fn hop(ttl: u8, addr: &str, host: &str, rtts: [f32; 3], reached: bool) -> Hop {
    let min = rtts.iter().copied().fold(f32::MAX, f32::min);
    let max = rtts.iter().copied().fold(0.0, f32::max);
    Hop {
        ttl,
        addr: Some(addr.into()),
        host: (!host.is_empty()).then(|| host.to_string()),
        sent: 3,
        received: 3,
        rtts_ms: rtts.iter().map(|r| Some(*r)).collect(),
        loss_pct: 0.0,
        min_ms: Some(min),
        avg_ms: Some(rtts.iter().sum::<f32>() / 3.0),
        max_ms: Some(max),
        reached,
    }
}

/// Nine hops to `example.org`; the fifth router stays silent.
pub fn trace_hops() -> Vec<Hop> {
    vec![
        hop(1, GATEWAY, "router.home.example", [1.8, 2.1, 1.7], false),
        hop(2, "10.24.0.1", "", [8.9, 9.4, 10.2], false),
        hop(
            3,
            "198.51.100.17",
            "access-3.north.isp.example",
            [9.8, 11.5, 10.1],
            false,
        ),
        hop(
            4,
            "198.51.100.65",
            "core-1.north.isp.example",
            [12.4, 12.0, 13.9],
            false,
        ),
        Hop {
            ttl: 5,
            sent: 3,
            received: 0,
            rtts_ms: vec![None, None, None],
            loss_pct: 100.0,
            ..Default::default()
        },
        hop(
            6,
            "198.51.100.129",
            "peering-2.exchange.example",
            [15.2, 14.8, 21.6],
            false,
        ),
        hop(
            7,
            "203.0.113.9",
            "edge-4.transit.example",
            [18.7, 19.3, 18.5],
            false,
        ),
        hop(
            8,
            "203.0.113.41",
            "dc-gw.hosting.example",
            [19.9, 20.4, 19.6],
            false,
        ),
        hop(9, "203.0.113.80", HOST, [20.3, 20.1, 20.8], true),
    ]
}

fn record(name: &str, rtype: &str, ttl: u32, data: &str) -> DnsRecord {
    DnsRecord {
        name: name.into(),
        rtype: rtype.into(),
        ttl,
        data: data.into(),
    }
}

/// An answer with address and mail records for `example.org`.
pub fn dns_answer() -> DnsAnswer {
    DnsAnswer {
        server: format!("{GATEWAY}:53"),
        rcode: "NOERROR".into(),
        elapsed_ms: 18.4,
        authoritative: false,
        truncated: false,
        transport: "UDP".into(),
        answers: vec![
            record(HOST, "A", 3600, "203.0.113.80"),
            record(HOST, "A", 3600, "203.0.113.81"),
            record(HOST, "AAAA", 3600, "2001:db8:40::80"),
            record(HOST, "MX", 7200, "10 mail.example.org"),
            record(HOST, "MX", 7200, "20 backup-mail.example.org"),
        ],
        authority: vec![
            record(HOST, "NS", 86_400, "ns1.example.org"),
            record(HOST, "NS", 86_400, "ns2.example.org"),
        ],
        additional: vec![
            record("mail.example.org", "A", 3600, "203.0.113.25"),
            record("ns1.example.org", "A", 86_400, "198.51.100.53"),
        ],
    }
}

/// A port check of the router: web pages and DNS are open.
pub fn port_results() -> Vec<PortResult> {
    let row = |port: u16, service: &str, state: PortState, ms: Option<f32>| PortResult {
        port,
        service: service.into(),
        state,
        connect_ms: ms,
    };
    vec![
        row(22, "SSH", PortState::Closed, Some(2.2)),
        row(53, "DNS", PortState::Open, Some(1.9)),
        row(80, "HTTP", PortState::Open, Some(2.4)),
        row(443, "HTTPS", PortState::Open, Some(2.1)),
        row(8080, "HTTP alt", PortState::NoAnswer, None),
    ]
}

/// Whois text in the usual `key: value` shape, written for the demo.
pub fn whois_text() -> String {
    [
        "% Demo answer. Nothing was asked from any server.",
        "",
        "Domain Name: example.org",
        "Registry Domain ID: DEMO-0000000001",
        "Registrar WHOIS Server: whois.registrar.example",
        "Registrar URL: https://registrar.example",
        "Updated Date: 2026-08-14T07:16:25Z",
        "Creation Date: 1995-08-31T04:00:00Z",
        "Registry Expiry Date: 2027-08-30T04:00:00Z",
        "Registrar: Example Registrar Ltd.",
        "Registrar Abuse Contact Email: abuse@registrar.example",
        "Registrar Abuse Contact Phone: +1.5550100",
        "Domain Status: clientTransferProhibited",
        "Domain Status: serverDeleteProhibited",
        "Registrant Organization: Example Organisation",
        "Registrant Country: ZZ",
        "Name Server: ns1.example.org",
        "Name Server: ns2.example.org",
        "DNSSEC: signedDelegation",
        "",
        ">>> Last update of this demo text: 2026-11-16T09:00:00Z <<<",
    ]
    .join("\n")
}

/// Three weeks of speed tests on a 250 / 40 Mbit/s line, oldest first,
/// with a few slow evenings.
pub fn speed_history(now: i64) -> Vec<SpeedResult> {
    let mut rng = Lcg(7);
    let servers = [
        "Frankfurt, DE",
        "Frankfurt, DE",
        "Amsterdam, NL",
        "Frankfurt, DE",
    ];
    let count = 24;
    (0..count)
        .map(|i| {
            // Newest about forty minutes ago, the rest spread over 21 days.
            let age_hours = (count - 1 - i) as f64 * 21.9 + 0.7 + rng.next() * 3.0;
            let slow = matches!(i, 5 | 12 | 13 | 19);
            let download = if slow {
                118.0 + rng.next() * 60.0
            } else {
                236.0 + rng.next() * 22.0
            };
            let upload = if slow {
                27.0 + rng.next() * 8.0
            } else {
                38.0 + rng.next() * 3.5
            };
            let latency = if slow { 19.0 } else { 11.0 } + rng.next() * 5.0;
            let jitter = if slow { 4.0 } else { 0.8 } + rng.next() * 1.8;
            SpeedResult {
                when_unix: now - (age_hours * 3600.0) as i64,
                provider: "M-Lab NDT7".into(),
                server: servers[i % servers.len()].into(),
                download_mbps: (download * 10.0).round() / 10.0,
                upload_mbps: (upload * 10.0).round() / 10.0,
                latency_ms: (latency * 10.0).round() / 10.0,
                jitter_ms: (jitter * 10.0).round() / 10.0,
                bytes_down: (download * 1.25e6) as u64,
                bytes_up: (upload * 1.25e6) as u64,
                adapter: if i % 9 == 4 { "Ethernet" } else { "Wi-Fi" }.into(),
            }
        })
        .collect()
}

/// A test caught in the middle of its download phase.
pub fn speed_progress() -> SpeedProgress {
    SpeedProgress {
        phase: SpeedPhase::Download,
        fraction: 0.62,
        current: 243.6,
        server: "Frankfurt, DE".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_has_two_losses() {
        let replies = ping_replies();
        assert_eq!(replies.len(), 60);
        assert_eq!(replies.iter().filter(|r| !r.ok).count(), 2);
        assert!(replies.iter().filter(|r| r.ok).all(|r| r.rtt_ms.is_some()));
    }

    #[test]
    fn trace_shape() {
        let hops = trace_hops();
        assert_eq!(hops.len(), 9);
        assert_eq!(hops.iter().filter(|h| h.addr.is_none()).count(), 1);
        assert!(hops.last().is_some_and(|h| h.reached));
        assert!(hops
            .iter()
            .enumerate()
            .all(|(i, h)| h.ttl as usize == i + 1));
    }

    #[test]
    fn speed_history_is_ordered_and_recent() {
        let now = 1_800_000_000;
        let h = speed_history(now);
        assert_eq!(h.len(), 24);
        assert!(h.windows(2).all(|w| w[0].when_unix < w[1].when_unix));
        assert!(h.iter().all(|r| r.when_unix < now));
        assert!(now - h[0].when_unix <= 22 * 86_400);
        assert!(h.iter().all(|r| r.download_mbps > r.upload_mbps));
    }

    #[test]
    fn only_documentation_addresses() {
        let text = format!("{:?}{:?}{}", trace_hops(), dns_answer(), whois_text());
        assert!(!text.contains("8.8.8.8") && !text.contains("1.1.1.1"));
        assert!(
            port_results()
                .iter()
                .filter(|p| p.state == PortState::Open)
                .count()
                == 3
        );
    }
}
