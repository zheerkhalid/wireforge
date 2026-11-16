//! Adapter inventory (IP Helper).

use crate::types::*;
use crate::util;
use std::collections::HashMap;
use std::net::IpAddr;
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetAdaptersAddresses, GetAdaptersInfo, GetIfEntry2, GetIfTable2,
    GetIpForwardTable2, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX,
    IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_INFO, MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IPFORWARD_TABLE2,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::AF_UNSPEC;

const ERROR_BUFFER_OVERFLOW: u32 = 111;
const IP_ADAPTER_DHCP_ENABLED: u32 = 0x4;

const IF_TYPE_ETHERNET: u32 = 6;
const IF_TYPE_PPP: u32 = 23;
const IF_TYPE_LOOPBACK: u32 = 24;
const IF_TYPE_PROP_VIRTUAL: u32 = 53;
const IF_TYPE_IEEE80211: u32 = 71;
const IF_TYPE_TUNNEL: u32 = 131;
const IF_TYPE_WWANPP: u32 = 243;
const IF_TYPE_WWANPP2: u32 = 244;

// Bits of MIB_IF_ROW2.InterfaceAndOperStatusFlags.
const IF_FLAG_HARDWARE: u8 = 0x01;
const IF_FLAG_FILTER: u8 = 0x02;
const IF_FLAG_CONNECTOR_PRESENT: u8 = 0x04;

/// Driver descriptions / names that mark a software adapter even when the
/// interface type says Ethernet. Lower case.
const VIRTUAL_MARKERS: &[&str] = &[
    "hyper-v virtual",
    "vethernet",
    "vmware",
    "virtualbox",
    "wsl",
    "tap-windows",
    "tap-win32",
    "tap adapter",
    "wintun",
    "wireguard",
    "openvpn",
    "tailscale",
    "zerotier",
    "nordlynx",
    "docker",
    "npcap loopback",
    "pseudo-interface",
    "virtual adapter",
    "virtual ethernet",
    "virtual network",
    "wi-fi direct virtual",
    "wan miniport",
    "vpn",
    "kernel debug",
    "sandbox",
];

/// The kind of an adapter from its interface type and a few name heuristics.
/// Pure, unit-tested.
pub fn classify_adapter(if_type: u32, description: &str, name: &str) -> AdapterKind {
    if if_type == IF_TYPE_LOOPBACK {
        return AdapterKind::Loopback;
    }
    if if_type == IF_TYPE_TUNNEL {
        return AdapterKind::Tunnel;
    }
    let desc = description.to_lowercase();
    let name = name.to_lowercase();
    if VIRTUAL_MARKERS
        .iter()
        .any(|m| desc.contains(m) || name.contains(m))
    {
        return AdapterKind::Virtual;
    }
    if desc.contains("bluetooth") || name.contains("bluetooth") {
        return AdapterKind::Bluetooth;
    }
    match if_type {
        IF_TYPE_IEEE80211 => AdapterKind::WiFi,
        IF_TYPE_ETHERNET => AdapterKind::Ethernet,
        IF_TYPE_WWANPP | IF_TYPE_WWANPP2 => AdapterKind::Cellular,
        IF_TYPE_PPP => AdapterKind::Tunnel,
        IF_TYPE_PROP_VIRTUAL => AdapterKind::Virtual,
        _ => AdapterKind::Other,
    }
}

/// `02:00:5E:10:00:01`; empty for an empty or all-zero address.
pub fn format_mac(bytes: &[u8]) -> String {
    if bytes.is_empty() || bytes.iter().all(|&b| b == 0) {
        return String::new();
    }
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// One default route (destination prefix length 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DefaultRoute {
    pub luid: u64,
    pub v6: bool,
    pub metric: u32,
}

/// What the default-route choice needs to know about an adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteCandidate {
    pub luid: u64,
    pub up: bool,
    pub v4_metric: u32,
    pub v6_metric: u32,
}

/// The adapter that carries the default route with the lowest effective
/// metric (route metric + interface metric). IPv4 routes win over IPv6 ones;
/// adapters that are down are ignored. Pure, unit-tested.
pub fn pick_default_adapter(routes: &[DefaultRoute], adapters: &[RouteCandidate]) -> Option<u64> {
    let best = |want_v6: bool| -> Option<u64> {
        routes
            .iter()
            .filter(|r| r.v6 == want_v6)
            .filter_map(|r| {
                let a = adapters.iter().find(|a| a.luid == r.luid && a.up)?;
                let if_metric = if want_v6 { a.v6_metric } else { a.v4_metric };
                Some((r.metric as u64 + if_metric as u64, r.luid))
            })
            .min()
            .map(|(_, luid)| luid)
    };
    best(false).or_else(|| best(true))
}

/// What GetIfEntry2 knows about one interface.
#[derive(Clone, Copy, Debug, Default)]
struct IfSnap {
    hardware: bool,
    connector: bool,
    rx: u64,
    tx: u64,
    packets_rx: u64,
    packets_tx: u64,
    errors_rx: u64,
    errors_tx: u64,
    discards_rx: u64,
    discards_tx: u64,
}

/// Frees a table returned by an IP Helper `Get...Table2` function on drop.
struct MibTable<T>(*mut T);

impl<T> Drop for MibTable<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an IP Helper table function and is
            // freed exactly once.
            unsafe { FreeMibTable(self.0 as *const core::ffi::c_void) };
        }
    }
}

/// Calls `f` for every row of GetIfTable2 that is not a filter layer.
fn for_each_if_row(mut f: impl FnMut(&MIB_IF_ROW2)) -> Result<(), String> {
    let mut raw: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: `raw` is a valid out pointer; the table is freed by `MibTable`.
    let err = unsafe { GetIfTable2(&mut raw) };
    let table = MibTable(raw);
    if err.0 != 0 || table.0.is_null() {
        return Err(format!(
            "GetIfTable2 failed with error {}",
            if err.0 != 0 { err.0 } else { 1 }
        ));
    }
    // SAFETY: on success the table holds `NumEntries` consecutive rows
    // starting at `Table`; it stays alive until `table` is dropped.
    unsafe {
        let count = (*table.0).NumEntries as usize;
        let first = std::ptr::addr_of!((*table.0).Table) as *const MIB_IF_ROW2;
        for i in 0..count {
            let row = &*first.add(i);
            if row.InterfaceAndOperStatusFlags._bitfield & IF_FLAG_FILTER != 0 {
                continue;
            }
            f(row);
        }
    }
    Ok(())
}

/// Byte counters of every adapter (GetIfTable2); called once per second.
///
/// The whole table also holds filter and miniport layers, and Windows can
/// take long to produce it while a driver is busy. When the adapters of
/// interest are known, `read_counters_for` is the cheaper, steadier choice
/// (the monitor uses it).
pub fn read_counters() -> Result<Vec<Counters>, String> {
    let mut out = Vec::with_capacity(64);
    for_each_if_row(|row| {
        out.push(Counters {
            // SAFETY: NET_LUID_LH is a union of a u64 and its bit fields; the
            // u64 view is always valid.
            luid: unsafe { row.InterfaceLuid.Value },
            rx: row.InOctets,
            tx: row.OutOctets,
        });
    })?;
    Ok(out)
}

/// Byte counters and the "operational status is up" flag of the given
/// adapters only (one GetIfEntry2 call each, cheaper than the whole table
/// when only a handful of adapters matter). Adapters that no longer exist
/// are left out.
pub fn read_counters_for(luids: &[u64]) -> Vec<(Counters, bool)> {
    let mut out = Vec::with_capacity(luids.len());
    let mut row = MIB_IF_ROW2::default();
    for &luid in luids {
        row.InterfaceLuid.Value = luid;
        row.InterfaceIndex = 0;
        // SAFETY: `row` is a writable MIB_IF_ROW2 with the LUID filled in,
        // which is how GetIfEntry2 identifies the interface.
        if unsafe { GetIfEntry2(&mut row) }.0 != 0 {
            continue;
        }
        out.push((
            Counters {
                luid,
                rx: row.InOctets,
                tx: row.OutOctets,
            },
            row.OperStatus == IfOperStatusUp,
        ));
    }
    out
}

/// Flags and counters of one interface (GetIfEntry2); zeros when it is gone.
fn if_snap(luid: u64) -> IfSnap {
    let mut row = MIB_IF_ROW2::default();
    row.InterfaceLuid.Value = luid;
    // SAFETY: `row` is a writable MIB_IF_ROW2 with the LUID filled in.
    if unsafe { GetIfEntry2(&mut row) }.0 != 0 {
        return IfSnap::default();
    }
    let flags = row.InterfaceAndOperStatusFlags._bitfield;
    IfSnap {
        hardware: flags & IF_FLAG_HARDWARE != 0,
        connector: flags & IF_FLAG_CONNECTOR_PRESENT != 0,
        rx: row.InOctets,
        tx: row.OutOctets,
        packets_rx: row.InUcastPkts.saturating_add(row.InNUcastPkts),
        packets_tx: row.OutUcastPkts.saturating_add(row.OutNUcastPkts),
        errors_rx: row.InErrors,
        errors_tx: row.OutErrors,
        discards_rx: row.InDiscards,
        discards_tx: row.OutDiscards,
    }
}

/// DHCP lease times by interface index (GetAdaptersInfo, IPv4 only).
fn lease_times() -> HashMap<u32, (i64, i64)> {
    let mut map = HashMap::new();
    let mut size: u32 = 16 * 1024;
    for _ in 0..4 {
        // u64 elements keep the buffer aligned for IP_ADAPTER_INFO.
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: the buffer is at least `size` bytes and suitably aligned.
        let err =
            unsafe { GetAdaptersInfo(Some(buf.as_mut_ptr() as *mut IP_ADAPTER_INFO), &mut size) };
        if err == ERROR_BUFFER_OVERFLOW {
            continue; // `size` now holds the needed size
        }
        if err != 0 {
            break; // ERROR_NO_DATA and friends: no IPv4 adapters
        }
        let mut p = buf.as_ptr() as *const IP_ADAPTER_INFO;
        let mut guard = 0;
        // SAFETY: on success the buffer holds a linked list of entries that
        // all live inside `buf`, which outlives this loop.
        unsafe {
            while !p.is_null() && guard < 1024 {
                let a = &*p;
                if a.DhcpEnabled != 0 && a.LeaseObtained > 0 && a.LeaseExpires > 0 {
                    map.insert(a.Index, (a.LeaseObtained, a.LeaseExpires));
                }
                p = a.Next;
                guard += 1;
            }
        }
        break;
    }
    map
}

fn default_routes() -> Vec<DefaultRoute> {
    let mut out = Vec::new();
    let mut raw: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: `raw` is a valid out pointer; the table is freed by `MibTable`.
    let err = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut raw) };
    let table = MibTable(raw);
    if err.0 != 0 || table.0.is_null() {
        return out;
    }
    // SAFETY: the table holds `NumEntries` consecutive rows and is alive until
    // `table` is dropped; `si_family` is valid for every SOCKADDR_INET.
    unsafe {
        let count = (*table.0).NumEntries as usize;
        let first = std::ptr::addr_of!((*table.0).Table)
            as *const windows::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2;
        for i in 0..count {
            let row = &*first.add(i);
            if row.DestinationPrefix.PrefixLength != 0 {
                continue;
            }
            let family = row.DestinationPrefix.Prefix.si_family.0;
            out.push(DefaultRoute {
                luid: row.InterfaceLuid.Value,
                v6: family == 23,
                metric: row.Metric,
            });
        }
    }
    out
}

/// Every adapter with addresses, gateway, DNS, DHCP lease and counters.
pub fn list_adapters() -> Result<Vec<AdapterInfo>, String> {
    let leases = lease_times();
    let now = util::unix_now();

    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX;
    let mut size: u32 = 32 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    let mut ok = false;
    let mut last_err = 0u32;
    for _ in 0..6 {
        // u64 elements keep the buffer aligned for IP_ADAPTER_ADDRESSES_LH.
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: the buffer is at least `size` bytes and suitably aligned.
        last_err = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };
        if last_err == ERROR_BUFFER_OVERFLOW {
            size = size.saturating_add(8 * 1024);
            continue;
        }
        ok = last_err == 0;
        break;
    }
    if !ok {
        // ERROR_NO_DATA (232): the machine has no adapters at all.
        if last_err == 232 {
            return Ok(Vec::new());
        }
        return Err(format!("GetAdaptersAddresses failed with error {last_err}"));
    }

    let mut out: Vec<AdapterInfo> = Vec::new();
    let mut candidates: Vec<RouteCandidate> = Vec::new();
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    let mut guard = 0;
    // SAFETY: on success the buffer holds a linked list of adapter entries;
    // every pointer inside them points into `buf`, which outlives this loop.
    // Lists are walked with a bound in case of a corrupt `Next` chain.
    unsafe {
        while !p.is_null() && guard < 4096 {
            let a = &*p;
            guard += 1;
            p = a.Next;

            let luid = a.Luid.Value;
            let name = util::from_wide_ptr(a.FriendlyName.0, 512);
            let description = util::from_wide_ptr(a.Description.0, 512);
            let kind = classify_adapter(a.IfType, &description, &name);
            let snap = if_snap(luid);
            let mac_len = (a.PhysicalAddressLength as usize).min(a.PhysicalAddress.len());

            let mut info = AdapterInfo {
                luid,
                index: if a.Anonymous1.Anonymous.IfIndex != 0 {
                    a.Anonymous1.Anonymous.IfIndex
                } else {
                    a.Ipv6IfIndex
                },
                guid: util::from_ansi_ptr(a.AdapterName.0, 128),
                name,
                description,
                kind,
                up: a.OperStatus == IfOperStatusUp,
                physical: (snap.hardware || snap.connector)
                    && !matches!(
                        kind,
                        AdapterKind::Virtual | AdapterKind::Tunnel | AdapterKind::Loopback
                    ),
                is_default: false,
                mac: format_mac(&a.PhysicalAddress[..mac_len]),
                mtu: if a.Mtu == u32::MAX { 0 } else { a.Mtu },
                tx_link_bps: if a.TransmitLinkSpeed == u64::MAX {
                    0
                } else {
                    a.TransmitLinkSpeed
                },
                rx_link_bps: if a.ReceiveLinkSpeed == u64::MAX {
                    0
                } else {
                    a.ReceiveLinkSpeed
                },
                dns_suffix: util::from_wide_ptr(a.DnsSuffix.0, 512),
                dhcp_enabled: a.Anonymous2.Flags & IP_ADAPTER_DHCP_ENABLED != 0,
                dhcp_server: util::sockaddr_ip(
                    a.Dhcpv4Server.lpSockaddr,
                    a.Dhcpv4Server.iSockaddrLength,
                )
                .filter(|ip| !ip.is_unspecified()),
                ipv4_metric: a.Ipv4Metric,
                bytes_rx: snap.rx,
                bytes_tx: snap.tx,
                packets_rx: snap.packets_rx,
                packets_tx: snap.packets_tx,
                errors_rx: snap.errors_rx,
                errors_tx: snap.errors_tx,
                discards_rx: snap.discards_rx,
                discards_tx: snap.discards_tx,
                ..AdapterInfo::default()
            };

            // Unicast addresses; remember the DHCP lifetimes of the first
            // DHCP-assigned IPv4 address as a fallback for the lease times.
            let mut lease_fallback: Option<(i64, i64)> = None;
            let mut u = a.FirstUnicastAddress;
            let mut n = 0;
            while !u.is_null() && n < 1024 {
                let ua = &*u;
                n += 1;
                u = ua.Next;
                match util::sockaddr_ip(ua.Address.lpSockaddr, ua.Address.iSockaddrLength) {
                    Some(IpAddr::V4(addr)) => {
                        info.ipv4.push(V4Net {
                            addr,
                            prefix: ua.OnLinkPrefixLength.min(32),
                        });
                        // IpPrefixOriginDhcp == 3
                        if ua.PrefixOrigin.0 == 3
                            && lease_fallback.is_none()
                            && ua.ValidLifetime != u32::MAX
                            && ua.LeaseLifetime != u32::MAX
                            && ua.LeaseLifetime != 0
                        {
                            let expires = now + ua.ValidLifetime as i64;
                            lease_fallback = Some((expires - ua.LeaseLifetime as i64, expires));
                        }
                    }
                    Some(IpAddr::V6(addr)) => info.ipv6.push(V6Net {
                        addr,
                        prefix: ua.OnLinkPrefixLength.min(128),
                    }),
                    None => {}
                }
            }

            let mut g = a.FirstGatewayAddress;
            n = 0;
            while !g.is_null() && n < 256 {
                let ga = &*g;
                n += 1;
                g = ga.Next;
                if let Some(ip) =
                    util::sockaddr_ip(ga.Address.lpSockaddr, ga.Address.iSockaddrLength)
                {
                    if !info.gateways.contains(&ip) {
                        info.gateways.push(ip);
                    }
                }
            }

            let mut d = a.FirstDnsServerAddress;
            n = 0;
            while !d.is_null() && n < 256 {
                let da = &*d;
                n += 1;
                d = da.Next;
                if let Some(ip) =
                    util::sockaddr_ip(da.Address.lpSockaddr, da.Address.iSockaddrLength)
                {
                    if !info.dns_servers.contains(&ip) {
                        info.dns_servers.push(ip);
                    }
                }
            }

            if info.dhcp_enabled && info.up {
                let lease = leases.get(&info.index).copied().or(lease_fallback);
                if let Some((obtained, expires)) = lease {
                    info.lease_obtained = Some(obtained);
                    info.lease_expires = Some(expires);
                }
            }
            if !info.dhcp_enabled {
                info.dhcp_server = None;
            }

            candidates.push(RouteCandidate {
                luid,
                up: info.up,
                v4_metric: a.Ipv4Metric,
                v6_metric: a.Ipv6Metric,
            });
            out.push(info);
        }
    }

    if let Some(luid) = pick_default_adapter(&default_routes(), &candidates) {
        if let Some(a) = out.iter_mut().find(|a| a.luid == luid) {
            a.is_default = true;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_by_type() {
        assert_eq!(
            classify_adapter(71, "Example Wi-Fi 6 AX 160MHz", "Wi-Fi"),
            AdapterKind::WiFi
        );
        assert_eq!(
            classify_adapter(6, "Example Gigabit Network Connection", "Ethernet"),
            AdapterKind::Ethernet
        );
        assert_eq!(
            classify_adapter(
                24,
                "Software Loopback Interface 1",
                "Loopback Pseudo-Interface 1"
            ),
            AdapterKind::Loopback
        );
        assert_eq!(
            classify_adapter(131, "Microsoft Teredo Tunneling Adapter", "Teredo"),
            AdapterKind::Tunnel
        );
        assert_eq!(
            classify_adapter(243, "Example LTE Modem", "Cellular"),
            AdapterKind::Cellular
        );
        assert_eq!(
            classify_adapter(244, "Example 5G Modem", "Cellular 2"),
            AdapterKind::Cellular
        );
        assert_eq!(
            classify_adapter(23, "Example PPP link", "Broadband Connection"),
            AdapterKind::Tunnel
        );
        assert_eq!(
            classify_adapter(53, "Something proprietary", "Local Area Connection* 3"),
            AdapterKind::Virtual
        );
        assert_eq!(
            classify_adapter(144, "1394 Net Adapter", "1394"),
            AdapterKind::Other
        );
    }

    #[test]
    fn classification_by_description() {
        let virtuals = [
            (
                6,
                "Hyper-V Virtual Ethernet Adapter",
                "vEthernet (Default Switch)",
            ),
            (6, "Hyper-V Virtual Ethernet Adapter #2", "vEthernet (WSL)"),
            (
                6,
                "VMware Virtual Ethernet Adapter for VMnet8",
                "VMware Network Adapter VMnet8",
            ),
            (6, "VirtualBox Host-Only Ethernet Adapter", "Ethernet 3"),
            (6, "TAP-Windows Adapter V9", "Ethernet 4"),
            (53, "WireGuard Tunnel", "wg0"),
            (53, "Wintun Userspace Tunnel", "Local Area Connection"),
            (53, "Tailscale Tunnel", "Tailscale"),
            (6, "ZeroTier Virtual Port", "ZeroTier One"),
            (
                71,
                "Microsoft Wi-Fi Direct Virtual Adapter",
                "Local Area Connection* 1",
            ),
            (6, "Example Secure VPN Adapter", "Ethernet 5"),
            (6, "Npcap Loopback Adapter", "Npcap Loopback Adapter"),
        ];
        for (ty, desc, name) in virtuals {
            assert_eq!(
                classify_adapter(ty, desc, name),
                AdapterKind::Virtual,
                "{desc}"
            );
        }
        assert_eq!(
            classify_adapter(
                6,
                "Bluetooth Device (Personal Area Network)",
                "Bluetooth Network Connection"
            ),
            AdapterKind::Bluetooth
        );
        // The synthetic NIC inside a Hyper-V guest is that guest's real card.
        assert_eq!(
            classify_adapter(6, "Microsoft Hyper-V Network Adapter", "Ethernet"),
            AdapterKind::Ethernet
        );
    }

    #[test]
    fn mac_formatting() {
        assert_eq!(
            format_mac(&[0x02, 0x00, 0x5E, 0x10, 0x00, 0xAB]),
            "02:00:5E:10:00:AB"
        );
        assert_eq!(format_mac(&[]), "");
        assert_eq!(format_mac(&[0, 0, 0, 0, 0, 0]), "");
        assert_eq!(format_mac(&[0x0A]), "0A");
    }

    fn cand(luid: u64, up: bool, v4: u32, v6: u32) -> RouteCandidate {
        RouteCandidate {
            luid,
            up,
            v4_metric: v4,
            v6_metric: v6,
        }
    }
    fn route(luid: u64, v6: bool, metric: u32) -> DefaultRoute {
        DefaultRoute { luid, v6, metric }
    }

    #[test]
    fn default_adapter_is_lowest_effective_metric() {
        let adapters = [
            cand(1, true, 25, 25),
            cand(2, true, 35, 35),
            cand(3, false, 1, 1),
        ];
        // Route metric + interface metric: 25 vs 35.
        let routes = [route(2, false, 0), route(1, false, 0)];
        assert_eq!(pick_default_adapter(&routes, &adapters), Some(1));
        // A high route metric outweighs a low interface metric.
        let routes = [route(2, false, 0), route(1, false, 100)];
        assert_eq!(pick_default_adapter(&routes, &adapters), Some(2));
        // Adapters that are down are ignored.
        let routes = [route(3, false, 0), route(2, false, 50)];
        assert_eq!(pick_default_adapter(&routes, &adapters), Some(2));
    }

    #[test]
    fn default_adapter_prefers_ipv4_and_falls_back_to_ipv6() {
        let adapters = [cand(1, true, 50, 5), cand(2, true, 60, 60)];
        let routes = [route(1, true, 0), route(2, false, 0)];
        assert_eq!(pick_default_adapter(&routes, &adapters), Some(2));
        let routes = [route(1, true, 0), route(2, true, 0)];
        assert_eq!(pick_default_adapter(&routes, &adapters), Some(1));
        assert_eq!(pick_default_adapter(&[], &adapters), None);
        assert_eq!(pick_default_adapter(&routes, &[]), None);
        // Metrics near the top of the range must not overflow.
        let routes = [route(1, false, u32::MAX)];
        let adapters = [cand(1, true, u32::MAX, 0)];
        assert_eq!(pick_default_adapter(&routes, &adapters), Some(1));
    }

    #[test]
    fn live_collectors_run() {
        // Shapes only: never print real values.
        let adapters = list_adapters().expect("list_adapters");
        let counters = read_counters().expect("read_counters");
        assert!(adapters.iter().filter(|a| a.is_default).count() <= 1);
        for a in &adapters {
            assert!(a.guid.is_empty() || a.guid.starts_with('{'));
            assert!(counters.iter().any(|c| c.luid == a.luid) || a.luid == 0);
            if a.physical {
                assert!(!matches!(
                    a.kind,
                    AdapterKind::Virtual | AdapterKind::Tunnel | AdapterKind::Loopback
                ));
            }
        }
    }
}
