//! Name lookups for the devices a sweep found: mDNS, NetBIOS, SSDP and
//! reverse DNS, run side by side with short time limits.
//!
//! Everything is sent from a socket bound to this PC's own address in the
//! scanned network, to that network's hosts or to link-local multicast
//! groups. SSDP LOCATION URLs are never fetched.

use super::net;
use super::packets::{self, RData};
use crate::types::Subnet;
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

/// What the lookups found, per address.
#[derive(Default)]
pub(crate) struct Names {
    /// Best name and where it came from ("mDNS", "NetBIOS", "SSDP", "DNS").
    pub name: HashMap<Ipv4Addr, (String, &'static str)>,
    pub hint: HashMap<Ipv4Addr, String>,
}

fn bind(self_ip: Ipv4Addr) -> Option<UdpSocket> {
    let socket = UdpSocket::bind(SocketAddrV4::new(self_ip, 0)).ok()?;
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok()?;
    Some(socket)
}

/// Receives until `until`, handing each IPv4 datagram to `on_packet`.
fn listen(
    socket: &UdpSocket,
    until: Instant,
    cancel: &AtomicBool,
    mut on_packet: impl FnMut(Ipv4Addr, &[u8]),
) {
    let mut buf = vec![0u8; 9000];
    let mut hard_errors = 0u32;
    while Instant::now() < until && !cancel.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((n, SocketAddr::V4(from))) => on_packet(*from.ip(), buf.get(..n).unwrap_or(&[])),
            Ok(_) => {}
            Err(e) => match e.kind() {
                // A timeout is the normal idle case. "Connection reset" is
                // Windows reporting an ICMP "port unreachable" for an
                // earlier send: the socket is still fine.
                ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::ConnectionReset => {}
                _ => {
                    hard_errors += 1;
                    if hard_errors > 200 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            },
        }
    }
}

type MdnsResult = (HashMap<Ipv4Addr, String>, HashMap<Ipv4Addr, Vec<String>>);

fn mdns(self_ip: Ipv4Addr, subnet: Subnet, hosts: &[Ipv4Addr], cancel: &AtomicBool) -> MdnsResult {
    let mut names: HashMap<Ipv4Addr, String> = HashMap::new();
    let mut services: HashMap<Ipv4Addr, Vec<String>> = HashMap::new();
    let Some(socket) = bind(self_ip) else {
        return (names, services);
    };
    net::set_multicast_interface(&socket, self_ip);
    // 224.0.0.251 is link-local: routers never forward it whatever the TTL,
    // and mDNS responders expect 255.
    let _ = socket.set_multicast_ttl_v4(255);
    let _ = socket.set_multicast_loop_v4(false);
    let group = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);
    let start = Instant::now();

    // Which service types exist on the link (unicast responses wanted).
    let _ = socket.send_to(
        &packets::build_query(0, &[(packets::SERVICES_NAME, packets::TYPE_PTR, true)]),
        group,
    );
    // "Who is <address>?" to the group, a dozen questions per packet...
    for chunk in hosts.chunks(12) {
        let names: Vec<String> = chunk.iter().map(|ip| packets::reverse_name(*ip)).collect();
        let questions: Vec<(&str, u16, bool)> = names
            .iter()
            .map(|n| (n.as_str(), packets::TYPE_PTR, true))
            .collect();
        let _ = socket.send_to(&packets::build_query(0, &questions), group);
    }
    // ...and directly to each device, which many responders answer more readily.
    for (i, ip) in hosts.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return (names, services);
        }
        let name = packets::reverse_name(*ip);
        let query = packets::build_query(0, &[(name.as_str(), packets::TYPE_PTR, true)]);
        let _ = socket.send_to(&query, SocketAddrV4::new(*ip, 5353));
        if i % 32 == 31 {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    let mut service_names: Vec<String> = Vec::new();
    let mut handle = |from: Ipv4Addr, packet: &[u8], service_names: &mut Vec<String>| {
        if !subnet.contains(from) {
            return;
        }
        let Some(records) = packets::parse_response(packet) else {
            return;
        };
        for record in records {
            match &record.data {
                RData::Ptr(target) => {
                    if record.name.eq_ignore_ascii_case(packets::SERVICES_NAME) {
                        if let Some(kind) = packets::service_type(target) {
                            let list = services.entry(from).or_default();
                            if list.len() < 32 && !list.contains(&kind) {
                                list.push(kind);
                            }
                        }
                        if service_names.len() < 24
                            && target.to_ascii_lowercase().ends_with(".local")
                            && !service_names.iter().any(|s| s.eq_ignore_ascii_case(target))
                        {
                            service_names.push(target.clone());
                        }
                    } else if let Some(ip) = packets::ip_from_reverse_name(&record.name) {
                        if subnet.contains(ip) {
                            if let Some(host) = packets::host_from_mdns(target) {
                                names.insert(ip, host);
                            }
                        }
                    }
                }
                RData::A(ip) if *ip == from => {
                    if let Some(host) = packets::host_from_mdns(&record.name) {
                        names.entry(*ip).or_insert(host);
                    }
                }
                _ => {}
            }
        }
    };

    listen(
        &socket,
        start + Duration::from_millis(900),
        cancel,
        |from, p| handle(from, p, &mut service_names),
    );
    // Ask for each service type that was announced: the answers carry the
    // host names (address records) of devices that ignored the reverse lookup.
    let asked = service_names.clone();
    for service in &asked {
        let query = packets::build_query(0, &[(service.as_str(), packets::TYPE_PTR, true)]);
        let _ = socket.send_to(&query, group);
    }
    listen(
        &socket,
        start + Duration::from_millis(2400),
        cancel,
        |from, p| handle(from, p, &mut service_names),
    );
    (names, services)
}

fn netbios(
    self_ip: Ipv4Addr,
    hosts: &[Ipv4Addr],
    cancel: &AtomicBool,
) -> HashMap<Ipv4Addr, String> {
    let mut names = HashMap::new();
    let Some(socket) = bind(self_ip) else {
        return names;
    };
    let wanted: HashSet<Ipv4Addr> = hosts.iter().copied().collect();
    let query = packets::build_nbstat_query(0x5746);
    for (i, ip) in hosts.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return names;
        }
        let _ = socket.send_to(&query, SocketAddrV4::new(*ip, 137));
        if i % 32 == 31 {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    listen(
        &socket,
        Instant::now() + Duration::from_millis(1500),
        cancel,
        |from, p| {
            if !wanted.contains(&from) {
                return;
            }
            if let Some(name) = packets::parse_nbstat_response(p)
                .as_deref()
                .and_then(packets::nbstat_best_name)
            {
                names.insert(from, name);
            }
        },
    );
    names
}

type SsdpResult = (HashMap<Ipv4Addr, String>, HashMap<Ipv4Addr, Vec<String>>);

/// Server headers and search targets per address.
fn ssdp(self_ip: Ipv4Addr, subnet: Subnet, cancel: &AtomicBool) -> SsdpResult {
    let mut servers: HashMap<Ipv4Addr, String> = HashMap::new();
    let mut targets: HashMap<Ipv4Addr, Vec<String>> = HashMap::new();
    let Some(socket) = bind(self_ip) else {
        return (servers, targets);
    };
    net::set_multicast_interface(&socket, self_ip);
    // TTL 1: the search stays on the attached link.
    let _ = socket.set_multicast_ttl_v4(1);
    let _ = socket.set_multicast_loop_v4(false);
    let group = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);
    let search = packets::build_msearch("ssdp:all", 1);
    let start = Instant::now();
    let mut handle = |from: Ipv4Addr, packet: &[u8]| {
        if !subnet.contains(from) {
            return;
        }
        let Some(info) = packets::parse_ssdp(packet) else {
            return;
        };
        if let Some(server) = info.server {
            servers.entry(from).or_insert(server);
        }
        if let Some(target) = info.target {
            let list = targets.entry(from).or_default();
            if list.len() < 32 && !list.contains(&target) {
                list.push(target);
            }
        }
    };
    let _ = socket.send_to(&search, group);
    listen(
        &socket,
        start + Duration::from_millis(400),
        cancel,
        &mut handle,
    );
    let _ = socket.send_to(&search, group);
    listen(
        &socket,
        start + Duration::from_millis(2500),
        cancel,
        &mut handle,
    );
    (servers, targets)
}

/// Reverse DNS on worker threads that are not waited for beyond the time
/// limit (the system resolver cannot be interrupted).
fn dns(hosts: &[Ipv4Addr], cancel: &AtomicBool) -> HashMap<Ipv4Addr, String> {
    let mut names = HashMap::new();
    if hosts.is_empty() {
        return names;
    }
    let queue = Arc::new(Mutex::new(hosts.to_vec()));
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<(Ipv4Addr, Option<String>)>();
    for _ in 0..hosts.len().min(16) {
        let (queue, stop, tx) = (Arc::clone(&queue), Arc::clone(&stop), tx.clone());
        let spawned = std::thread::Builder::new()
            .name("wf-rdns".into())
            .stack_size(256 * 1024)
            .spawn(move || loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let next = queue.lock().unwrap_or_else(|e| e.into_inner()).pop();
                let Some(ip) = next else { break };
                if tx.send((ip, net::reverse_dns(ip))).is_err() {
                    break;
                }
            });
        if spawned.is_err() {
            break;
        }
    }
    drop(tx);
    let deadline = Instant::now() + Duration::from_millis(3000);
    let mut answered = 0usize;
    while answered < hosts.len() && !cancel.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match rx.recv_timeout((deadline - now).min(Duration::from_millis(100))) {
            Ok((ip, name)) => {
                answered += 1;
                if let Some(name) = name {
                    names.insert(ip, name);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    stop.store(true, Ordering::Relaxed);
    names
}

/// Runs every lookup in parallel and keeps the best name per address
/// (mDNS, then NetBIOS, then SSDP, then DNS).
pub(crate) fn resolve(
    self_ip: Ipv4Addr,
    subnet: Subnet,
    hosts: &[Ipv4Addr],
    cancel: &AtomicBool,
) -> Names {
    let mut out = Names::default();
    if hosts.is_empty() {
        return out;
    }
    let (mdns_result, netbios_names, ssdp_result, dns_names) = std::thread::scope(|scope| {
        let m = scope.spawn(|| mdns(self_ip, subnet, hosts, cancel));
        let n = scope.spawn(|| netbios(self_ip, hosts, cancel));
        let s = scope.spawn(|| ssdp(self_ip, subnet, cancel));
        let d = dns(hosts, cancel);
        (
            m.join().unwrap_or_default(),
            n.join().unwrap_or_default(),
            s.join().unwrap_or_default(),
            d,
        )
    });
    let (mdns_names, mdns_services) = mdns_result;
    let (ssdp_servers, ssdp_targets) = ssdp_result;

    for (ip, name) in dns_names {
        out.name.insert(ip, (name, "DNS"));
    }
    for (ip, server) in &ssdp_servers {
        if let Some(name) = packets::ssdp_name(server) {
            out.name.insert(*ip, (name, "SSDP"));
        }
    }
    for (ip, name) in netbios_names {
        out.name.insert(ip, (name, "NetBIOS"));
    }
    for (ip, name) in mdns_names {
        out.name.insert(ip, (name, "mDNS"));
    }
    for (ip, targets) in &ssdp_targets {
        if let Some(kind) = packets::ssdp_kind(targets) {
            out.hint.insert(*ip, kind);
        }
    }
    for (ip, services) in &mdns_services {
        if let Some(kind) = packets::service_hint(services) {
            out.hint.insert(*ip, kind);
        }
    }
    out
}
