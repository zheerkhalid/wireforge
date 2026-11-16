//! Devices on the local network.

mod book;
mod names;
mod net;
pub mod packets;

pub use book::DeviceBook;
pub use net::{attached_networks, AttachedNetwork};

use crate::oui;
use crate::types::*;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Mutex;

/// The largest network that is scanned: a /22 (1,024 addresses).
pub const MIN_SCAN_PREFIX: u8 = 22;
const SWEEP_THREADS: usize = 64;
/// A host that answered ARP: address, MAC, ping time.
type Live = (Ipv4Addr, [u8; 6], Option<u32>);

impl Subnet {
    fn mask(&self) -> u32 {
        match self.prefix.min(32) {
            0 => 0,
            p => u32::MAX << (32 - u32::from(p)),
        }
    }

    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) & self.mask())
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) | !self.mask())
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.addr) & self.mask()
    }

    /// Usable host addresses (network and broadcast excluded).
    ///
    /// A /31 has two hosts and a /32 one. Networks larger than a /16 give an
    /// empty list instead of millions of addresses.
    pub fn hosts(&self) -> Vec<Ipv4Addr> {
        let prefix = self.prefix.min(32);
        if prefix < 16 {
            return Vec::new();
        }
        let first = u32::from(self.network());
        let last = u32::from(self.broadcast());
        match prefix {
            32 => vec![Ipv4Addr::from(first)],
            31 => vec![Ipv4Addr::from(first), Ipv4Addr::from(last)],
            _ => (first + 1..last).map(Ipv4Addr::from).collect(),
        }
    }

    /// `192.168.1.0/24`
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.network(), self.prefix.min(32))
    }

    /// Why this network must not be scanned (not private address space, or
    /// more than 1,024 hosts), or `None` when scanning is fine.
    pub fn scan_refusal(&self) -> Option<String> {
        let private = [
            Subnet {
                addr: Ipv4Addr::new(10, 0, 0, 0),
                prefix: 8,
            },
            Subnet {
                addr: Ipv4Addr::new(172, 16, 0, 0),
                prefix: 12,
            },
            Subnet {
                addr: Ipv4Addr::new(192, 168, 0, 0),
                prefix: 16,
            },
            Subnet {
                addr: Ipv4Addr::new(169, 254, 0, 0),
                prefix: 16,
            },
        ];
        let inside = private.iter().any(|p| {
            self.prefix >= p.prefix && p.contains(self.network()) && p.contains(self.broadcast())
        });
        if !inside {
            return Some(format!(
                "{} is not a private network, and only home and office networks (10.x.x.x, 172.16-31.x.x, 192.168.x.x and 169.254.x.x) are scanned.",
                self.cidr()
            ));
        }
        if self.prefix < MIN_SCAN_PREFIX {
            return Some(format!(
                "{} is too large to scan: only networks of up to 1,024 addresses (/22 or smaller) are scanned.",
                self.cidr()
            ));
        }
        None
    }
}

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub subnet: Subnet,
    /// This PC's address in the subnet.
    pub self_ip: Option<Ipv4Addr>,
    pub self_mac: String,
    pub gateway: Option<Ipv4Addr>,
    /// Ask mDNS / NetBIOS / SSDP / reverse DNS for names.
    pub resolve_names: bool,
}

impl ScanOptions {
    /// Options for scanning a network this PC is attached to.
    pub fn for_network(network: &AttachedNetwork, resolve_names: bool) -> ScanOptions {
        ScanOptions {
            subnet: network.subnet,
            self_ip: Some(network.self_ip),
            self_mac: network.self_mac.clone(),
            gateway: network.gateway,
            resolve_names,
        }
    }
}

/// The attached network a scan would most likely be wanted for: the first
/// one that may be scanned, networks with a default gateway first.
pub fn default_network() -> Option<AttachedNetwork> {
    attached_networks()
        .into_iter()
        .find(|n| n.subnet.scan_refusal().is_none())
}

/// ARP + ping sweep of a directly attached private subnet, then name
/// lookups. `progress(done, total)` is called as hosts are probed.
/// Refuses networks for which `scan_refusal` gives a reason, and networks
/// this PC has no address in. A cancelled scan returns an error (a partial
/// list would make absent devices look offline).
pub fn scan(
    options: &ScanOptions,
    cancel: &AtomicBool,
    progress: &(dyn Fn(u32, u32) + Sync),
) -> Result<Vec<FoundDevice>, String> {
    const CANCELLED: &str = "The scan was cancelled.";
    let subnet = options.subnet;
    if let Some(reason) = subnet.scan_refusal() {
        return Err(reason);
    }
    // The network must be one this PC is directly attached to.
    let attached = attached_networks();
    let adapter = attached
        .iter()
        .filter(|n| n.subnet.contains(subnet.network()) && n.subnet.contains(subnet.broadcast()))
        .find(|n| options.self_ip.is_none_or(|ip| ip == n.self_ip))
        .or_else(|| {
            attached.iter().find(|n| {
                n.subnet.contains(subnet.network()) && n.subnet.contains(subnet.broadcast())
            })
        })
        .ok_or_else(|| {
            format!(
                "{} is not a network this PC is directly connected to, so it is not scanned.",
                subnet.cidr()
            )
        })?;
    let self_ip = adapter.self_ip;

    let hosts: Vec<Ipv4Addr> = subnet
        .hosts()
        .into_iter()
        .filter(|ip| *ip != self_ip)
        .collect();
    let total = hosts.len() as u32;
    let next = AtomicUsize::new(0);
    let done = AtomicU32::new(0);
    let live: Mutex<Vec<Live>> = Mutex::new(Vec::new());
    let worker = || {
        let pinger = net::Pinger::new();
        loop {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let Some(&ip) = hosts.get(next.fetch_add(1, Ordering::Relaxed)) else {
                break;
            };
            if let Some(mac) = net::arp(ip, self_ip) {
                let rtt = pinger.as_ref().and_then(|p| p.ping(ip, 400));
                live.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((ip, mac, rtt));
            }
            progress(done.fetch_add(1, Ordering::Relaxed) + 1, total);
        }
    };
    std::thread::scope(|scope| {
        for _ in 1..SWEEP_THREADS.min(hosts.len()) {
            let spawned = std::thread::Builder::new()
                .name("wf-sweep".into())
                .stack_size(256 * 1024)
                .spawn_scoped(scope, worker);
            if spawned.is_err() {
                break;
            }
        }
        // This thread works too, so the sweep runs even if no thread could start.
        worker();
    });
    if cancel.load(Ordering::Relaxed) {
        return Err(CANCELLED.into());
    }

    let mut devices: BTreeMap<Ipv4Addr, FoundDevice> = BTreeMap::new();
    let device = |ip: Ipv4Addr, mac: Option<[u8; 6]>, rtt: Option<u32>| {
        let mac = mac.map(|m| oui::format_mac(&m)).unwrap_or_default();
        FoundDevice {
            ip: ip.to_string(),
            vendor: oui::vendor(&mac).map(str::to_string),
            random_mac: oui::is_random(&mac),
            is_gateway: options.gateway == Some(ip) || adapter.gateway == Some(ip),
            is_self: ip == self_ip,
            rtt_ms: rtt,
            mac,
            ..FoundDevice::default()
        }
    };
    for (ip, mac, rtt) in live.into_inner().unwrap_or_else(|e| e.into_inner()) {
        devices.insert(ip, device(ip, Some(mac), rtt));
    }
    // Devices that answered Windows earlier but slept through the sweep.
    for (ip, mac) in net::neighbours(&subnet, adapter.if_index) {
        if ip != self_ip {
            devices
                .entry(ip)
                .or_insert_with(|| device(ip, Some(mac), None));
        }
    }
    if subnet.contains(self_ip) {
        let own_mac =
            oui::parse_mac(&adapter.self_mac).or_else(|| oui::parse_mac(&options.self_mac));
        devices.insert(self_ip, device(self_ip, own_mac, Some(0)));
    }

    if options.resolve_names {
        let ips: Vec<Ipv4Addr> = devices
            .keys()
            .copied()
            .filter(|ip| *ip != self_ip)
            .collect();
        let found = names::resolve(self_ip, subnet, &ips, cancel);
        if cancel.load(Ordering::Relaxed) {
            return Err(CANCELLED.into());
        }
        for (ip, d) in devices.iter_mut() {
            if let Some((name, source)) = found.name.get(ip) {
                d.name = Some(name.clone());
                d.name_source = Some((*source).to_string());
            }
            d.kind_hint = found.hint.get(ip).cloned();
        }
    }
    progress(total, total);
    Ok(devices.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> Subnet {
        Subnet {
            addr: Ipv4Addr::new(a, b, c, d),
            prefix,
        }
    }

    #[test]
    fn network_and_broadcast() {
        let s = net(192, 168, 1, 77, 24);
        assert_eq!(s.network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(s.broadcast(), Ipv4Addr::new(192, 168, 1, 255));
        assert_eq!(s.cidr(), "192.168.1.0/24");
        let s = net(10, 20, 30, 40, 22);
        assert_eq!(s.network(), Ipv4Addr::new(10, 20, 28, 0));
        assert_eq!(s.broadcast(), Ipv4Addr::new(10, 20, 31, 255));
        assert_eq!(s.cidr(), "10.20.28.0/22");
        let s = net(172, 16, 5, 130, 26);
        assert_eq!(s.network(), Ipv4Addr::new(172, 16, 5, 128));
        assert_eq!(s.broadcast(), Ipv4Addr::new(172, 16, 5, 191));
        let all = net(198, 51, 100, 7, 0);
        assert_eq!(all.network(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(all.broadcast(), Ipv4Addr::new(255, 255, 255, 255));
        let one = net(198, 51, 100, 7, 32);
        assert_eq!((one.network(), one.broadcast()), (one.addr, one.addr));
        // A prefix beyond 32 is treated as 32.
        let odd = net(198, 51, 100, 7, 99);
        assert_eq!(
            (odd.network(), odd.cidr()),
            (odd.addr, "198.51.100.7/32".to_string())
        );
    }

    #[test]
    fn contains() {
        let s = net(192, 168, 1, 77, 24);
        assert!(s.contains(Ipv4Addr::new(192, 168, 1, 0)));
        assert!(s.contains(Ipv4Addr::new(192, 168, 1, 255)));
        assert!(!s.contains(Ipv4Addr::new(192, 168, 2, 1)));
        assert!(!s.contains(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(net(0, 0, 0, 0, 0).contains(Ipv4Addr::new(203, 0, 113, 9)));
        let one = net(198, 51, 100, 7, 32);
        assert!(one.contains(one.addr) && !one.contains(Ipv4Addr::new(198, 51, 100, 8)));
    }

    #[test]
    fn hosts() {
        let h = net(192, 168, 1, 77, 24).hosts();
        assert_eq!(h.len(), 254);
        assert_eq!(h.first(), Some(&Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(h.last(), Some(&Ipv4Addr::new(192, 168, 1, 254)));
        assert_eq!(net(10, 0, 0, 0, 22).hosts().len(), 1022);
        assert_eq!(
            net(10, 0, 0, 9, 30).hosts(),
            vec![Ipv4Addr::new(10, 0, 0, 9), Ipv4Addr::new(10, 0, 0, 10)]
        );
        assert_eq!(
            net(10, 0, 0, 9, 31).hosts(),
            vec![Ipv4Addr::new(10, 0, 0, 8), Ipv4Addr::new(10, 0, 0, 9)]
        );
        assert_eq!(
            net(10, 0, 0, 9, 32).hosts(),
            vec![Ipv4Addr::new(10, 0, 0, 9)]
        );
        assert_eq!(net(10, 0, 0, 0, 16).hosts().len(), 65534);
        assert!(net(10, 0, 0, 0, 8).hosts().is_empty());
        assert!(net(0, 0, 0, 0, 0).hosts().is_empty());
        assert_eq!(net(255, 255, 255, 255, 24).hosts().len(), 254);
    }

    #[test]
    fn private_networks_may_be_scanned() {
        for s in [
            net(192, 168, 1, 10, 24),
            net(192, 168, 0, 0, 22),
            net(10, 0, 0, 1, 24),
            net(10, 255, 255, 1, 22),
            net(172, 16, 0, 1, 24),
            net(172, 31, 255, 1, 24),
            net(169, 254, 12, 1, 24),
            net(192, 168, 1, 10, 30),
            net(192, 168, 1, 10, 32),
        ] {
            assert_eq!(s.scan_refusal(), None, "{}", s.cidr());
        }
    }

    #[test]
    fn public_networks_are_refused() {
        for s in [
            net(8, 8, 8, 8, 24),
            net(192, 0, 2, 1, 24),
            net(198, 51, 100, 1, 24),
            net(203, 0, 113, 1, 24),
            net(172, 15, 0, 1, 24),
            net(172, 32, 0, 1, 24),
            net(192, 167, 1, 1, 24),
            net(192, 169, 1, 1, 24),
            net(169, 253, 1, 1, 24),
            net(100, 64, 0, 1, 24),
            net(127, 0, 0, 1, 24),
            net(224, 0, 0, 1, 24),
            net(11, 0, 0, 1, 24),
            net(0, 0, 0, 0, 0),
        ] {
            let reason = s.scan_refusal().unwrap_or_default();
            assert!(
                reason.contains("not a private network"),
                "{}: {reason}",
                s.cidr()
            );
            assert!(reason.ends_with('.'));
        }
    }

    #[test]
    fn large_networks_are_refused() {
        for s in [
            net(10, 0, 0, 1, 8),
            net(10, 0, 0, 1, 16),
            net(10, 0, 0, 1, 21),
            net(192, 168, 0, 1, 16),
            net(172, 16, 0, 1, 12),
            net(169, 254, 0, 1, 16),
        ] {
            let reason = s.scan_refusal().unwrap_or_default();
            assert!(reason.contains("too large"), "{}: {reason}", s.cidr());
        }
        // Wider than the private block itself: not private at all.
        assert!(net(192, 168, 0, 1, 15)
            .scan_refusal()
            .unwrap_or_default()
            .contains("not a private"));
        assert!(net(10, 0, 0, 1, 7)
            .scan_refusal()
            .unwrap_or_default()
            .contains("not a private"));
    }

    #[test]
    fn scan_refuses_before_touching_the_network() {
        let cancel = AtomicBool::new(false);
        let calls = AtomicU32::new(0);
        let progress = |_: u32, _: u32| {
            calls.fetch_add(1, Ordering::Relaxed);
        };
        let options = |subnet| ScanOptions {
            subnet,
            self_ip: None,
            self_mac: String::new(),
            gateway: None,
            resolve_names: false,
        };
        // Public (documentation) range.
        let err = scan(&options(net(198, 51, 100, 1, 24)), &cancel, &progress)
            .err()
            .unwrap_or_default();
        assert!(err.contains("not a private network"));
        // Too large.
        let err = scan(&options(net(10, 0, 0, 1, 16)), &cancel, &progress)
            .err()
            .unwrap_or_default();
        assert!(err.contains("too large"));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
}
