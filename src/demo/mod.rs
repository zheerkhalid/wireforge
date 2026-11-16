//! Invented data for `--demo`: nothing here comes from this PC or its
//! network. Screenshots are made from it.

pub mod tools;
pub mod wifi;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use wf_traffic::usage::UsageDb;
use wf_traffic::{
    AdapterInfo, AdapterKind, AdapterLive, AppLive, ConnState, Connection, Day, Endpoint,
    PerAppMode, Proto, Rate, Snapshot, Totals, V4Net, V6Net,
};
use wf_wifi::{Band, Link};

/// An address from the documentation range (RFC 5737), not a real one.
pub const PUBLIC_IP: &str = "203.0.113.84";

const MB: f64 = 1024.0 * 1024.0;
const GB: u64 = 1024 * 1024 * 1024;

/// A small deterministic generator so every run draws the same picture.
pub struct Lcg(pub u64);

impl Lcg {
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((self.0 >> 33) as f64) / ((1u64 << 31) as f64)
    }
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn v6(text: &str) -> Ipv6Addr {
    text.parse().unwrap_or(Ipv6Addr::UNSPECIFIED)
}

pub fn adapters(now: i64) -> Vec<AdapterInfo> {
    vec![
        AdapterInfo {
            luid: 1,
            index: 12,
            guid: "{5D1F0A52-7C1B-4E0E-9B7A-2F6C1D3E4A10}".into(),
            name: "Wi-Fi".into(),
            description: "Wi-Fi 6E AX 2x2 160 MHz Wireless Adapter".into(),
            kind: AdapterKind::WiFi,
            up: true,
            physical: true,
            is_default: true,
            mac: "3C:9A:77:2B:19:5C".into(),
            mtu: 1500,
            tx_link_bps: 1_201_000_000,
            rx_link_bps: 1_201_000_000,
            ipv4: vec![V4Net {
                addr: Ipv4Addr::new(192, 168, 50, 23),
                prefix: 24,
            }],
            ipv6: vec![
                V6Net {
                    addr: v6("2001:db8:50:0:8c1e:44ff:fe2b:195c"),
                    prefix: 64,
                },
                V6Net {
                    addr: v6("fe80::8c1e:44ff:fe2b:195c"),
                    prefix: 64,
                },
            ],
            gateways: vec![v4(192, 168, 50, 1)],
            dns_servers: vec![v4(192, 168, 50, 1), v4(9, 9, 9, 9)],
            dns_suffix: "home.arpa".into(),
            dhcp_enabled: true,
            dhcp_server: Some(v4(192, 168, 50, 1)),
            lease_obtained: Some(now - 5 * 3600 - 12 * 60),
            lease_expires: Some(now + 18 * 3600 + 48 * 60),
            ipv4_metric: 35,
            bytes_rx: 18 * GB + 411_000_000,
            bytes_tx: 2 * GB + 96_000_000,
            packets_rx: 14_882_310,
            packets_tx: 6_120_774,
            errors_rx: 0,
            errors_tx: 0,
            discards_rx: 12,
            discards_tx: 0,
        },
        AdapterInfo {
            luid: 2,
            index: 7,
            guid: "{A2B4C6D8-1357-4246-8A9B-0C1D2E3F4A5B}".into(),
            name: "Ethernet".into(),
            description: "2.5 Gigabit Ethernet Controller".into(),
            kind: AdapterKind::Ethernet,
            up: false,
            physical: true,
            mac: "3C:9A:77:2B:19:5B".into(),
            mtu: 1500,
            dhcp_enabled: true,
            ..Default::default()
        },
        AdapterInfo {
            luid: 3,
            index: 31,
            guid: "{0F1E2D3C-4B5A-4978-8695-A4B3C2D1E0F9}".into(),
            name: "vEthernet (Default Switch)".into(),
            description: "Virtual Ethernet Adapter".into(),
            kind: AdapterKind::Virtual,
            up: true,
            physical: false,
            mac: "00:15:5D:3A:6E:01".into(),
            mtu: 1500,
            tx_link_bps: 10_000_000_000,
            rx_link_bps: 10_000_000_000,
            ipv4: vec![V4Net {
                addr: Ipv4Addr::new(172, 28, 96, 1),
                prefix: 20,
            }],
            ipv4_metric: 5000,
            bytes_rx: 4_100_000,
            bytes_tx: 9_800_000,
            packets_rx: 21_004,
            packets_tx: 40_310,
            ..Default::default()
        },
    ]
}

/// A believable evening: browsing, then a large download, a video call.
fn rate_curve(samples: usize, seed: u64, scale_down: f64, scale_up: f64) -> Vec<Rate> {
    let mut rng = Lcg(seed);
    (0..samples)
        .map(|i| {
            let t = i as f64 / samples.max(1) as f64;
            let burst = if (0.32..0.62).contains(&t) {
                // The download: ramps up, holds, tails off.
                let u = (t - 0.32) / 0.30;
                (u * 8.0).min(1.0) * ((1.0 - u) * 6.0).min(1.0)
            } else {
                0.0
            };
            let wave = 0.5 + 0.5 * (t * 21.0).sin();
            let noise = rng.next();
            let down =
                scale_down * (0.05 + 0.10 * wave * noise + 0.85 * burst * (0.86 + 0.14 * noise));
            let call = if t > 0.70 {
                0.55 + 0.1 * rng.next()
            } else {
                0.04 * rng.next()
            };
            let up = scale_up * (call + 0.08 * burst);
            Rate { down, up }
        })
        .collect()
}

struct DemoApp {
    name: &'static str,
    path: &'static str,
    share: f64,
    up_share: f64,
    connections: u32,
    pids: &'static [u32],
    today: (u64, u64),
    hosts: &'static [(&'static str, [u8; 4], u16)],
}

const APPS: &[DemoApp] = &[
    DemoApp {
        name: "lumen.exe",
        path: "C:\\Program Files\\Lumen Browser\\lumen.exe",
        share: 0.46,
        up_share: 0.10,
        connections: 38,
        pids: &[4212, 4388, 4520, 9120],
        today: (3_420, 212),
        hosts: &[
            ("cdn.videonest.example", [198, 51, 100, 14], 443),
            ("www.wikiatlas.example", [198, 51, 100, 77], 443),
            ("static.newsharbor.example", [203, 0, 113, 9], 443),
        ],
    },
    DemoApp {
        name: "gamehub.exe",
        path: "C:\\Program Files\\GameHub\\gamehub.exe",
        share: 0.31,
        up_share: 0.03,
        connections: 9,
        pids: &[7716],
        today: (6_150, 48),
        hosts: &[
            ("dl-eu3.gamehub.example", [198, 51, 100, 201], 443),
            ("dl-eu5.gamehub.example", [198, 51, 100, 203], 443),
        ],
    },
    DemoApp {
        name: "frameloop.exe",
        path: "C:\\Users\\Alex\\AppData\\Local\\Frameloop\\frameloop.exe",
        share: 0.11,
        up_share: 0.62,
        connections: 6,
        pids: &[10844, 10912],
        today: (940, 705),
        hosts: &[
            ("media-fra2.frameloop.example", [203, 0, 113, 140], 3478),
            ("signal.frameloop.example", [203, 0, 113, 141], 443),
        ],
    },
    DemoApp {
        name: "cloudnest.exe",
        path: "C:\\Program Files\\CloudNest\\cloudnest.exe",
        share: 0.05,
        up_share: 0.17,
        connections: 4,
        pids: &[3396],
        today: (310, 1_240),
        hosts: &[("sync.cloudnest.example", [198, 51, 100, 60], 443)],
    },
    DemoApp {
        name: "tidewave.exe",
        path: "C:\\Program Files\\Tidewave\\tidewave.exe",
        share: 0.03,
        up_share: 0.01,
        connections: 3,
        pids: &[8820],
        today: (268, 6),
        hosts: &[("audio-edge.tidewave.example", [203, 0, 113, 52], 443)],
    },
    DemoApp {
        name: "parley.exe",
        path: "C:\\Users\\Alex\\AppData\\Local\\Parley\\parley.exe",
        share: 0.015,
        up_share: 0.03,
        connections: 5,
        pids: &[6120, 6204],
        today: (84, 31),
        hosts: &[("gateway.parley.example", [198, 51, 100, 118], 443)],
    },
    DemoApp {
        name: "codeharbor.exe",
        path: "C:\\Program Files\\CodeHarbor\\codeharbor.exe",
        share: 0.01,
        up_share: 0.02,
        connections: 7,
        pids: &[11520],
        today: (156, 22),
        hosts: &[("packages.codeharbor.example", [203, 0, 113, 201], 443)],
    },
    DemoApp {
        name: "mailwing.exe",
        path: "C:\\Program Files\\Mailwing\\mailwing.exe",
        share: 0.006,
        up_share: 0.01,
        connections: 2,
        pids: &[5008],
        today: (41, 9),
        hosts: &[("imap.mailwing.example", [198, 51, 100, 25], 993)],
    },
    DemoApp {
        name: "svchost.exe",
        path: "C:\\Windows\\System32\\svchost.exe",
        share: 0.006,
        up_share: 0.01,
        connections: 14,
        pids: &[1180, 1420, 2264, 3012],
        today: (512, 37),
        hosts: &[("updates.windows.example", [203, 0, 113, 30], 443)],
    },
    DemoApp {
        name: "vaultsync.exe",
        path: "C:\\Program Files\\VaultSync\\vaultsync.exe",
        share: 0.002,
        up_share: 0.01,
        connections: 1,
        pids: &[9644],
        today: (12, 88),
        hosts: &[("backup.vaultsync.example", [198, 51, 100, 190], 443)],
    },
    DemoApp {
        name: "System",
        path: "",
        share: 0.001,
        up_share: 0.01,
        connections: 11,
        pids: &[4],
        today: (9, 4),
        hosts: &[],
    },
];

pub fn snapshot(now: i64) -> Snapshot {
    let history = rate_curve(300, 7, 11.5 * MB, 1.6 * MB);
    let rate = history.last().copied().unwrap_or_default();
    // The header reads better with a lively "now": take a point from the download.
    let rate = Rate {
        down: history.get(170).map(|r| r.down).unwrap_or(rate.down),
        up: rate.up,
    };
    let peak = history.iter().fold(Rate::default(), |m, r| Rate {
        down: m.down.max(r.down),
        up: m.up.max(r.up),
    });
    let apps = APPS
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let curve = rate_curve(
                60,
                100 + i as u64,
                rate.down * a.share * 1.3,
                rate.up * a.up_share * 1.6,
            );
            let live = Rate {
                down: rate.down * a.share,
                up: rate.up * a.up_share,
            };
            let session = Totals {
                rx: (a.today.0 as f64 * MB * 0.42) as u64,
                tx: (a.today.1 as f64 * MB * 0.42) as u64,
            };
            AppLive {
                name: a.name.into(),
                path: a.path.into(),
                pids: a.pids.to_vec(),
                rate: live,
                session,
                today: Totals {
                    rx: (a.today.0 as f64 * MB) as u64,
                    tx: (a.today.1 as f64 * MB) as u64,
                },
                connections: a.connections,
                endpoints: a
                    .hosts
                    .iter()
                    .enumerate()
                    .map(|(k, (host, ip, port))| Endpoint {
                        proto: if *port == 3478 {
                            Proto::Udp
                        } else {
                            Proto::Tcp
                        },
                        addr: v4(ip[0], ip[1], ip[2], ip[3]),
                        port: *port,
                        host: Some(host.to_string()),
                        rx: session.rx / (k as u64 + 1) / 2,
                        tx: session.tx / (k as u64 + 1) / 2,
                    })
                    .collect(),
                history: curve,
            }
        })
        .collect();
    let session = Totals {
        rx: 4 * GB + 730_000_000,
        tx: GB + 12_000_000,
    };
    let db = usage();
    let today = Day::today();
    Snapshot {
        taken_unix: now,
        rate,
        peak,
        history,
        adapters: vec![
            AdapterLive {
                luid: 1,
                name: "Wi-Fi".into(),
                kind: AdapterKind::WiFi,
                up: true,
                rate,
                session,
            },
            AdapterLive {
                luid: 2,
                name: "Ethernet".into(),
                kind: AdapterKind::Ethernet,
                up: false,
                ..Default::default()
            },
            AdapterLive {
                luid: 3,
                name: "vEthernet (Default Switch)".into(),
                kind: AdapterKind::Virtual,
                up: true,
                rate: Rate {
                    down: 320.0,
                    up: 1100.0,
                },
                session: Totals {
                    rx: 4_100_000,
                    tx: 9_800_000,
                },
            },
        ],
        apps,
        per_app_mode: PerAppMode::Etw,
        session,
        today: db.day_total(today),
        month: db.month_total(today.y, today.m),
    }
}

/// Ninety days of invented usage, weekends heavier.
pub fn usage() -> UsageDb {
    let mut db = UsageDb::default();
    let today = Day::today();
    let mut rng = Lcg(42);
    for back in (0..90u32).rev() {
        let day = today.minus_days(back);
        let weekend = day.weekday() >= 5;
        let base = if weekend { 1.7 } else { 1.0 };
        let mut day_rx = 0u64;
        let mut day_tx = 0u64;
        for a in APPS {
            let wobble = 0.35 + 1.3 * rng.next();
            // Today matches the Apps page exactly.
            let (rx, tx) = if back == 0 {
                (
                    (a.today.0 as f64 * MB) as u64,
                    (a.today.1 as f64 * MB) as u64,
                )
            } else {
                (
                    (a.today.0 as f64 * MB * base * wobble) as u64,
                    (a.today.1 as f64 * MB * base * wobble) as u64,
                )
            };
            // Now and then a day is spent on the cable.
            let adapter = if back % 11 == 4 { "Ethernet" } else { "Wi-Fi" };
            db.add_app(day, a.name, adapter, rx, tx);
            day_rx += rx;
            day_tx += tx;
        }
        let adapter = if back % 11 == 4 { "Ethernet" } else { "Wi-Fi" };
        // A little traffic belongs to no listed app.
        db.add_adapter(day, adapter, day_rx + day_rx / 40, day_tx + day_tx / 30);
    }
    db
}

pub fn link() -> Link {
    Link {
        interface_guid: "{5D1F0A52-7C1B-4E0E-9B7A-2F6C1D3E4A10}".into(),
        interface: "Wi-Fi 6E AX 2x2 160 MHz Wireless Adapter".into(),
        profile: "Maple-Home".into(),
        ssid: "Maple-Home".into(),
        bssid: "D4:6E:0E:5A:21:90".into(),
        phy: "802.11ax".into(),
        generation: Some(6),
        rssi_dbm: -52,
        quality: 96,
        rx_rate_mbps: 1201.0,
        tx_rate_mbps: 1201.0,
        freq_mhz: 5180,
        channel: 36,
        band: Band::B5,
        width_mhz: Some(80),
        security: "WPA3-Personal".into(),
        cipher: "CCMP (AES)".into(),
        mcs: Some(11),
        streams: Some(2),
        vendor: Some("Orbitlink Networks".into()),
    }
}

/// Signal in dBm, one sample per two seconds: steady, one walk to the kitchen.
pub fn signal_history() -> Vec<f64> {
    let mut rng = Lcg(9);
    (0..300)
        .map(|i| {
            let dip = if (150..215).contains(&i) {
                let u = (i - 150) as f64 / 65.0;
                -17.0 * (u * std::f64::consts::PI).sin()
            } else {
                0.0
            };
            (-52.0 + dip + (rng.next() - 0.5) * 3.0).round()
        })
        .collect()
}

pub fn connections(now: i64) -> Vec<Connection> {
    let local = v4(192, 168, 50, 23);
    let mut out = Vec::new();
    let mut rng = Lcg(3);
    let mut port = 49_700u16;
    for a in APPS {
        for (k, (_, ip, rport)) in a.hosts.iter().enumerate() {
            let copies = (a.connections as usize / a.hosts.len().max(1)).clamp(1, 4);
            for c in 0..copies {
                port += 1 + (rng.next() * 40.0) as u16;
                let udp = *rport == 3478;
                out.push(Connection {
                    proto: if udp { Proto::Udp } else { Proto::Tcp },
                    local,
                    local_port: port,
                    remote: (!udp).then(|| v4(ip[0], ip[1], ip[2], ip[3].wrapping_add(c as u8))),
                    remote_port: if udp { 0 } else { *rport },
                    state: if udp {
                        ConnState::Stateless
                    } else if (k + c) % 7 == 6 {
                        ConnState::TimeWait
                    } else {
                        ConnState::Established
                    },
                    pid: a.pids[c % a.pids.len()],
                    process: a.name.into(),
                    path: a.path.into(),
                    created: Some(now - 40 - (rng.next() * 5400.0) as i64),
                });
            }
        }
    }
    // Listeners and a few system endpoints.
    let any = v4(0, 0, 0, 0);
    for (proto, addr, lport, pid, name, path) in [
        (
            Proto::Tcp,
            any,
            135u16,
            1180u32,
            "svchost.exe",
            "C:\\Windows\\System32\\svchost.exe",
        ),
        (Proto::Tcp, any, 445, 4, "System", ""),
        (
            Proto::Tcp,
            any,
            5040,
            3012,
            "svchost.exe",
            "C:\\Windows\\System32\\svchost.exe",
        ),
        (
            Proto::Tcp,
            v4(127, 0, 0, 1),
            6463,
            6120,
            "parley.exe",
            "C:\\Users\\Alex\\AppData\\Local\\Parley\\parley.exe",
        ),
        (
            Proto::Tcp,
            v4(127, 0, 0, 1),
            5173,
            11520,
            "codeharbor.exe",
            "C:\\Program Files\\CodeHarbor\\codeharbor.exe",
        ),
        (
            Proto::Udp,
            any,
            5353,
            4212,
            "lumen.exe",
            "C:\\Program Files\\Lumen Browser\\lumen.exe",
        ),
        (
            Proto::Udp,
            any,
            5355,
            1420,
            "svchost.exe",
            "C:\\Windows\\System32\\svchost.exe",
        ),
        (Proto::Udp, local, 137, 4, "System", ""),
        (
            Proto::Udp,
            local,
            1900,
            2264,
            "svchost.exe",
            "C:\\Windows\\System32\\svchost.exe",
        ),
        (
            Proto::Udp,
            any,
            500,
            2264,
            "svchost.exe",
            "C:\\Windows\\System32\\svchost.exe",
        ),
    ] {
        out.push(Connection {
            proto,
            local: addr,
            local_port: lport,
            remote: None,
            remote_port: 0,
            state: if proto == Proto::Tcp {
                ConnState::Listening
            } else {
                ConnState::Stateless
            },
            pid,
            process: name.into(),
            path: path.into(),
            created: Some(now - 86_400 + lport as i64),
        });
    }
    out.push(Connection {
        proto: Proto::Tcp,
        local: IpAddr::V6(v6("2001:db8:50:0:8c1e:44ff:fe2b:195c")),
        local_port: 50_112,
        remote: Some(IpAddr::V6(v6("2001:db8:a0:11::2e"))),
        remote_port: 443,
        state: ConnState::Established,
        pid: 4388,
        process: "lumen.exe".into(),
        path: "C:\\Program Files\\Lumen Browser\\lumen.exe".into(),
        created: Some(now - 312),
    });
    out
}

/// A reverse-DNS name for a demo address, so the Connections page can show
/// host names without asking anyone.
pub fn host_for(addr: &IpAddr) -> Option<String> {
    let IpAddr::V4(ip) = addr else {
        return Some("edge-6.wikiatlas.example".into());
    };
    let o = ip.octets();
    APPS.iter()
        .flat_map(|a| a.hosts.iter())
        .find(|(_, h, _)| {
            h[0] == o[0] && h[1] == o[1] && h[2] == o[2] && o[3].wrapping_sub(h[3]) < 4
        })
        .map(|(host, _, _)| host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_data_is_invented_and_consistent() {
        let now = 1_800_000_000;
        let snap = snapshot(now);
        assert_eq!(snap.history.len(), 300);
        assert!(snap.apps.len() >= 10);
        assert!(snap.apps.iter().all(|a| a.history.len() == 60));
        assert!(snap.rate.down > 0.0 && snap.peak.down >= snap.rate.down);
        let adapters = adapters(now);
        assert_eq!(adapters.iter().filter(|a| a.is_default).count(), 1);
        // Only private, documentation or loopback addresses appear anywhere.
        let ok = |ip: &IpAddr| match ip {
            IpAddr::V4(v) => {
                let o = v.octets();
                v.is_private()
                    || v.is_loopback()
                    || v.is_unspecified()
                    || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                    || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                    || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                    || *v == Ipv4Addr::new(9, 9, 9, 9)
            }
            IpAddr::V6(v) => {
                let s = v.segments();
                (s[0] == 0x2001 && s[1] == 0xdb8) || s[0] == 0xfe80
            }
        };
        for c in connections(now) {
            assert!(ok(&c.local), "{:?}", c.local);
            if let Some(r) = &c.remote {
                assert!(ok(r), "{r:?}");
            }
        }
        for a in &snap.apps {
            for e in &a.endpoints {
                assert!(ok(&e.addr));
                assert!(e.host.as_deref().unwrap_or("").ends_with(".example"));
            }
        }
        assert!(PUBLIC_IP.starts_with("203.0.113."));
        assert_eq!(signal_history().len(), 300);
    }
}
