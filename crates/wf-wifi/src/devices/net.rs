//! The operating-system side of device discovery: local adapters, ARP,
//! ping, the neighbour cache and reverse DNS.

use crate::oui;
use crate::types::Subnet;
use std::ffi::c_void;
use std::net::{Ipv4Addr, UdpSocket};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetAdaptersAddresses, GetIpNetTable2, IcmpCloseHandle, IcmpCreateFile,
    IcmpSendEcho, SendARP, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, ICMP_ECHO_REPLY, IP_ADAPTER_ADDRESSES_LH,
    MIB_IPNET_ROW2, MIB_IPNET_TABLE2,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{
    setsockopt, socklen_t, GetNameInfoW, NlnsDelay, NlnsProbe, NlnsReachable, NlnsStale,
    WSAStartup, AF_INET, IPPROTO_IP, IP_MULTICAST_IF, NI_NAMEREQD, SOCKADDR, SOCKADDR_IN, SOCKET,
    WSADATA,
};

const ERROR_BUFFER_OVERFLOW: u32 = 111;
const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
const IF_TYPE_IEEE80211: u32 = 71;

/// An IPv4 network this PC has an address in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachedNetwork {
    pub subnet: Subnet,
    /// This PC's address in the network.
    pub self_ip: Ipv4Addr,
    /// `AA:BB:CC:DD:EE:FF`, empty when the adapter has none.
    pub self_mac: String,
    /// The default gateway when it lies inside the network.
    pub gateway: Option<Ipv4Addr>,
    /// The adapter's friendly name ("Wi-Fi", "Ethernet").
    pub adapter: String,
    pub wifi: bool,
    pub if_index: u32,
}

fn ipv4_of(sockaddr: *const SOCKADDR, len: i32) -> Option<Ipv4Addr> {
    if sockaddr.is_null() || (len as usize) < std::mem::size_of::<SOCKADDR_IN>() {
        return None;
    }
    // SAFETY: the pointer is non-null and the caller's length says a full
    // SOCKADDR_IN is readable; it is copied out unaligned.
    let sin = unsafe { std::ptr::read_unaligned(sockaddr as *const SOCKADDR_IN) };
    if sin.sin_family != AF_INET {
        return None;
    }
    // SAFETY: every bit pattern is a valid u32 for this plain-data union.
    let raw = unsafe { sin.sin_addr.S_un.S_addr };
    Some(Ipv4Addr::from(raw.to_ne_bytes()))
}

/// The IPv4 networks of every adapter that is up (loopback excluded),
/// networks with a default gateway first.
pub fn attached_networks() -> Vec<AttachedNetwork> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 32 * 1024;
    // u64 elements keep the buffer aligned for the adapter structures.
    let mut buffer: Vec<u64> = Vec::new();
    let mut ok = false;
    for _ in 0..4 {
        buffer = vec![0u64; size as usize / 8 + 1];
        // SAFETY: the buffer is at least `size` bytes and suitably aligned;
        // `size` is updated when it is too small.
        let rc = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_INET.0),
                flags,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };
        if rc == 0 {
            ok = true;
            break;
        }
        if rc != ERROR_BUFFER_OVERFLOW {
            break;
        }
    }
    let mut out = Vec::new();
    if !ok {
        return out;
    }
    // SAFETY: on success the buffer holds a linked list of adapter records
    // whose pointers all lie inside the buffer, which outlives this walk.
    // Each list is walked with a bound in case of a damaged chain.
    unsafe {
        let mut adapter = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        let mut adapters_left = 512;
        while !adapter.is_null() && adapters_left > 0 {
            adapters_left -= 1;
            let a = &*adapter;
            adapter = a.Next;
            if a.OperStatus != IfOperStatusUp || a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                continue;
            }
            let mut gateways = Vec::new();
            let mut gw = a.FirstGatewayAddress;
            let mut left = 32;
            while !gw.is_null() && left > 0 {
                left -= 1;
                let g = &*gw;
                gw = g.Next;
                if let Some(ip) = ipv4_of(g.Address.lpSockaddr, g.Address.iSockaddrLength) {
                    gateways.push(ip);
                }
            }
            let mac_len = (a.PhysicalAddressLength as usize).min(a.PhysicalAddress.len());
            let self_mac = match a.PhysicalAddress.get(..mac_len) {
                Some(&[m0, m1, m2, m3, m4, m5]) => oui::format_mac(&[m0, m1, m2, m3, m4, m5]),
                _ => String::new(),
            };
            let friendly = if a.FriendlyName.is_null() {
                String::new()
            } else {
                String::from_utf16_lossy(a.FriendlyName.as_wide())
            };
            let if_index = a.Anonymous1.Anonymous.IfIndex;
            let mut unicast = a.FirstUnicastAddress;
            let mut left = 64;
            while !unicast.is_null() && left > 0 {
                left -= 1;
                let u = &*unicast;
                unicast = u.Next;
                let Some(ip) = ipv4_of(u.Address.lpSockaddr, u.Address.iSockaddrLength) else {
                    continue;
                };
                if ip.is_loopback() || ip.is_unspecified() || u.OnLinkPrefixLength > 32 {
                    continue;
                }
                let subnet = Subnet {
                    addr: ip,
                    prefix: u.OnLinkPrefixLength,
                };
                out.push(AttachedNetwork {
                    subnet: Subnet {
                        addr: subnet.network(),
                        prefix: subnet.prefix,
                    },
                    self_ip: ip,
                    self_mac: self_mac.clone(),
                    gateway: gateways.iter().copied().find(|g| subnet.contains(*g)),
                    adapter: friendly.clone(),
                    wifi: a.IfType == IF_TYPE_IEEE80211,
                    if_index,
                });
            }
        }
    }
    out.sort_by_key(|n| n.gateway.is_none());
    out
}

/// Asks who has `dest` on the local link. The answer proves the device is there.
pub(crate) fn arp(dest: Ipv4Addr, src: Ipv4Addr) -> Option<[u8; 6]> {
    let mut mac = [0u8; 8];
    let mut len = 6u32;
    // SAFETY: `mac` has room for the six bytes announced in `len`.
    let rc = unsafe {
        SendARP(
            u32::from_ne_bytes(dest.octets()),
            u32::from_ne_bytes(src.octets()),
            mac.as_mut_ptr() as *mut c_void,
            &mut len,
        )
    };
    let [m0, m1, m2, m3, m4, m5, _, _] = mac;
    let mac = [m0, m1, m2, m3, m4, m5];
    (rc == 0 && len == 6 && usable_mac(&mac)).then_some(mac)
}

/// Not all zero, not broadcast, not a multicast address.
pub(crate) fn usable_mac(mac: &[u8; 6]) -> bool {
    mac.iter().any(|&b| b != 0) && mac[0] & 0x01 == 0
}

/// An ICMP handle for echo requests, closed on drop.
pub(crate) struct Pinger(HANDLE);

impl Pinger {
    pub(crate) fn new() -> Option<Pinger> {
        // SAFETY: no arguments; the handle is closed in Drop.
        unsafe { IcmpCreateFile() }.ok().map(Pinger)
    }

    /// Round-trip time in milliseconds, `None` when there is no reply.
    pub(crate) fn ping(&self, dest: Ipv4Addr, timeout_ms: u32) -> Option<u32> {
        let payload = *b"wfwfwfwf";
        // Room for one reply, the echoed payload and an ICMP error (aligned).
        let mut reply = [0u64; 16];
        // SAFETY: the request and reply buffers are valid for the sizes given.
        let count = unsafe {
            IcmpSendEcho(
                self.0,
                u32::from_ne_bytes(dest.octets()),
                payload.as_ptr() as *const c_void,
                payload.len() as u16,
                None,
                reply.as_mut_ptr() as *mut c_void,
                std::mem::size_of_val(&reply) as u32,
                timeout_ms,
            )
        };
        if count == 0 {
            return None;
        }
        // SAFETY: on success the buffer starts with an ICMP_ECHO_REPLY.
        let first = unsafe { std::ptr::read(reply.as_ptr() as *const ICMP_ECHO_REPLY) };
        (first.Status == 0).then_some(first.RoundTripTime)
    }
}

impl Drop for Pinger {
    fn drop(&mut self) {
        // SAFETY: the handle came from IcmpCreateFile and is closed once.
        unsafe {
            let _ = IcmpCloseHandle(self.0);
        }
    }
}

/// Devices Windows already knows on the link (they answered recently).
pub(crate) fn neighbours(subnet: &Subnet, if_index: u32) -> Vec<(Ipv4Addr, [u8; 6])> {
    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    // SAFETY: valid out pointer; the table is freed below.
    let rc = unsafe { GetIpNetTable2(AF_INET, &mut table) };
    let mut out = Vec::new();
    if rc.0 != 0 || table.is_null() {
        return out;
    }
    // SAFETY: on success the header is followed by `NumEntries` rows; they
    // are copied out before the table is freed exactly once.
    unsafe {
        let count = ((*table).NumEntries as usize).min(65_536);
        let first = std::ptr::addr_of!((*table).Table) as *const MIB_IPNET_ROW2;
        for i in 0..count {
            let row = std::ptr::read_unaligned(first.add(i));
            if row.Address.si_family != AF_INET || (if_index != 0 && row.InterfaceIndex != if_index)
            {
                continue;
            }
            let state = row.State;
            if state != NlnsReachable
                && state != NlnsStale
                && state != NlnsDelay
                && state != NlnsProbe
            {
                continue;
            }
            let ip = Ipv4Addr::from(row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
            let mac = match row
                .PhysicalAddress
                .get(..(row.PhysicalAddressLength as usize).min(32))
            {
                Some(&[m0, m1, m2, m3, m4, m5]) => [m0, m1, m2, m3, m4, m5],
                _ => continue,
            };
            if usable_mac(&mac)
                && subnet.contains(ip)
                && ip != subnet.network()
                && ip != subnet.broadcast()
            {
                out.push((ip, mac));
            }
        }
        FreeMibTable(table as *const c_void);
    }
    out
}

/// Starts Winsock for the calls made outside `std::net` (idempotent).
pub(crate) fn winsock_init() {
    static START: std::sync::Once = std::sync::Once::new();
    START.call_once(|| {
        // SAFETY: WSADATA is plain data that WSAStartup fills in.
        unsafe {
            let mut data: WSADATA = std::mem::zeroed();
            let _ = WSAStartup(0x0202, &mut data);
        }
    });
}

/// The name the configured DNS server has for an address. May block for a
/// few seconds, so callers run it on a thread they do not wait for forever.
pub(crate) fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    winsock_init();
    let mut addr = SOCKADDR_IN {
        sin_family: AF_INET,
        ..Default::default()
    };
    addr.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
    let mut host = [0u16; 1025];
    // SAFETY: `addr` is a valid SOCKADDR_IN of the size given; `host` is writable.
    let rc = unsafe {
        GetNameInfoW(
            &addr as *const SOCKADDR_IN as *const SOCKADDR,
            socklen_t(std::mem::size_of::<SOCKADDR_IN>() as i32),
            Some(&mut host),
            None,
            NI_NAMEREQD as i32,
        )
    };
    if rc != 0 {
        return None;
    }
    let end = host.iter().position(|&c| c == 0).unwrap_or(host.len());
    let name = String::from_utf16_lossy(host.get(..end)?);
    // An address echoed back is not a name.
    if name.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    super::packets::clean_name(&name)
}

/// Makes multicast packets from this socket leave through the adapter that
/// owns `local` (binding alone does not decide that on Windows).
pub(crate) fn set_multicast_interface(socket: &UdpSocket, local: Ipv4Addr) {
    use std::os::windows::io::AsRawSocket;
    // SAFETY: the socket is open for the duration of the call and the option
    // value is the four address bytes the option expects.
    unsafe {
        let _ = setsockopt(
            SOCKET(socket.as_raw_socket() as usize),
            IPPROTO_IP.0,
            IP_MULTICAST_IF,
            Some(&local.octets()),
        );
    }
}
