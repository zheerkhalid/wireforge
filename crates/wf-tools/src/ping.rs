//! ICMP echo (IcmpSendEcho2 / Icmp6SendEcho2).

use crate::types::*;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Once;
use std::time::{Duration, Instant};
use windows::core::HSTRING;
use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::*;

/// Winsock is started once per process and left running.
pub(crate) fn winsock_init() {
    static START: Once = Once::new();
    START.call_once(|| {
        let mut data = WSADATA::default();
        // SAFETY: `data` is a valid out buffer. Winsock is never cleaned up:
        // it is needed for the life of the process.
        unsafe {
            let _ = WSAStartup(0x0202, &mut data);
        }
    });
}

/// Reads an address out of a socket address the system handed back.
///
/// # Safety
/// `sa` must be null or point to at least `len` readable bytes.
pub(crate) unsafe fn sockaddr_to_ip(sa: *const SOCKADDR, len: usize) -> Option<(IpAddr, u32)> {
    if sa.is_null() || len < std::mem::size_of::<u16>() {
        return None;
    }
    let family = std::ptr::read_unaligned(sa as *const u16);
    if family == AF_INET.0 && len >= std::mem::size_of::<SOCKADDR_IN>() {
        let v4 = std::ptr::read_unaligned(sa as *const SOCKADDR_IN);
        // S_addr holds the address in network byte order.
        let octets = v4.sin_addr.S_un.S_addr.to_ne_bytes();
        Some((IpAddr::V4(Ipv4Addr::from(octets)), 0))
    } else if family == AF_INET6.0 && len >= std::mem::size_of::<SOCKADDR_IN6>() {
        let v6 = std::ptr::read_unaligned(sa as *const SOCKADDR_IN6);
        let scope = v6.Anonymous.sin6_scope_id;
        Some((IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.u.Byte)), scope))
    } else {
        None
    }
}

fn to_sockaddr_in6(addr: Ipv6Addr, scope: u32) -> SOCKADDR_IN6 {
    let mut sa = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        ..Default::default()
    };
    sa.sin6_addr.u.Byte = addr.octets();
    sa.Anonymous.sin6_scope_id = scope;
    sa
}

/// Resolves a host name or parses an address (IPv4 first).
pub fn resolve(host: &str) -> Result<Vec<IpAddr>, String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("Enter a host name or an address.".into());
    }
    let literal = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = literal.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    if host.len() > 253 || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("That is not a valid host name.".into());
    }
    winsock_init();
    let name = HSTRING::from(host);
    let hints = ADDRINFOW {
        ai_family: i32::from(AF_UNSPEC.0),
        ai_socktype: SOCK_STREAM.0,
        ..Default::default()
    };
    let mut list: *mut ADDRINFOW = std::ptr::null_mut();
    // SAFETY: `name` and `hints` outlive the call; `list` receives a list that
    // is freed below with FreeAddrInfoW.
    let code = unsafe { GetAddrInfoW(&name, None, Some(&hints), &mut list) };
    if code != 0 || list.is_null() {
        return Err(format!("Could not find the address of \"{host}\"."));
    }
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut node = list;
    let mut guard = 0;
    // SAFETY: the list nodes are valid until FreeAddrInfoW; each ai_addr has
    // ai_addrlen readable bytes.
    unsafe {
        while !node.is_null() && guard < 256 {
            let info = &*node;
            if let Some((ip, _)) = sockaddr_to_ip(info.ai_addr, info.ai_addrlen) {
                let bucket = if ip.is_ipv4() { &mut v4 } else { &mut v6 };
                if !bucket.contains(&ip) {
                    bucket.push(ip);
                }
            }
            node = info.ai_next;
            guard += 1;
        }
        FreeAddrInfoW(Some(list));
    }
    v4.append(&mut v6);
    if v4.is_empty() {
        return Err(format!("Could not find the address of \"{host}\"."));
    }
    Ok(v4)
}

/// The name an address points back to, if it has one. May take a few seconds.
pub fn reverse_lookup(addr: IpAddr) -> Option<String> {
    winsock_init();
    let mut name = [0u16; 1025];
    // SAFETY: the socket address structs are valid locals of the stated size
    // and `name` is a live buffer.
    let code = unsafe {
        match addr {
            IpAddr::V4(v4) => {
                let mut sa = SOCKADDR_IN {
                    sin_family: AF_INET,
                    ..Default::default()
                };
                sa.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
                GetNameInfoW(
                    &sa as *const SOCKADDR_IN as *const SOCKADDR,
                    socklen_t(std::mem::size_of::<SOCKADDR_IN>() as i32),
                    Some(&mut name),
                    None,
                    NI_NAMEREQD as i32,
                )
            }
            IpAddr::V6(v6) => {
                let sa = to_sockaddr_in6(v6, 0);
                GetNameInfoW(
                    &sa as *const SOCKADDR_IN6 as *const SOCKADDR,
                    socklen_t(std::mem::size_of::<SOCKADDR_IN6>() as i32),
                    Some(&mut name),
                    None,
                    NI_NAMEREQD as i32,
                )
            }
        }
    };
    if code != 0 {
        return None;
    }
    let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    let text = String::from_utf16_lossy(name.get(..end).unwrap_or(&[]));
    let text = text.trim().trim_end_matches('.').to_string();
    (!text.is_empty() && text.parse::<IpAddr>().is_err()).then_some(text)
}

/// `reverse_lookup` with a time limit (the lookup itself cannot be stopped,
/// so it finishes on a helper thread and its late answer is dropped).
pub fn reverse_lookup_timeout(addr: IpAddr, timeout_ms: u32) -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("wf-rdns".into())
        .spawn(move || {
            let _ = tx.send(reverse_lookup(addr));
        })
        .ok()?;
    rx.recv_timeout(Duration::from_millis(u64::from(timeout_ms)))
        .ok()
        .flatten()
}

const IP_SUCCESS: u32 = 0;
const IP_STATUS_BASE: u32 = 11000;
const IP_REQ_TIMED_OUT: u32 = 11010;
const IP_GENERAL_FAILURE: u32 = 11050;

/// Plain words for an `IP_STATUS` code (pure, unit-tested).
pub fn status_text(code: u32) -> &'static str {
    match code {
        0 => "Reply",
        11001 => "Reply buffer too small",
        11002 => "Destination network unreachable",
        11003 => "Destination host unreachable",
        11004 => "Destination protocol unreachable",
        11005 => "Destination port unreachable",
        11006 => "Out of resources",
        11007 => "Bad option",
        11008 => "Hardware error",
        11009 => "Packet too big",
        11010 => "Timed out",
        11011 => "Bad request",
        11012 => "Bad route",
        11013 => "TTL expired",
        11014 => "TTL expired during reassembly",
        11015 => "Parameter problem",
        11016 => "Source quench",
        11017 => "Option too big",
        11018 => "Bad destination",
        11032 => "Negotiating IPsec",
        11040 => "Destination unreachable",
        11041 => "Time exceeded",
        11042 => "Bad header",
        11043 => "Unrecognized next header",
        11044 => "ICMP error",
        11045 => "Destination scope mismatch",
        11050 => "General failure",
        // Win32 errors that the echo functions report directly.
        5 => "Access denied",
        87 => "Invalid parameter",
        1231 => "Network unreachable",
        1232 => "Host unreachable",
        _ => "Failed",
    }
}

/// Whether a code is one of the ICMP status values that still carries the
/// address of whoever answered.
fn is_ip_status(code: u32) -> bool {
    (IP_STATUS_BASE..=IP_GENERAL_FAILURE).contains(&code)
}

struct IcmpHandle(HANDLE);

impl Drop for IcmpHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from Icmp(6)CreateFile and is closed once.
        unsafe {
            let _ = IcmpCloseHandle(self.0);
        }
    }
}

fn failed(seq: u32, status: &str) -> PingReply {
    PingReply {
        seq,
        status: status.to_string(),
        ..Default::default()
    }
}

fn payload(seq: u32, size: u16) -> Vec<u8> {
    let size = usize::from(size.min(65_500));
    (0..size)
        .map(|i| b'a' + ((i + seq as usize) % 23) as u8)
        .collect()
}

/// Uses the local timer when the system reports a whole-millisecond zero.
fn pick_rtt(reported_ms: u32, measured: Duration) -> f32 {
    if reported_ms == 0 {
        (measured.as_secs_f32() * 1000.0).min(1.0)
    } else {
        reported_ms as f32
    }
}

/// One echo request. Never fails: problems are described in `status`.
pub fn ping_once(addr: IpAddr, seq: u32, timeout_ms: u32, ttl: u8, size: u16) -> PingReply {
    let timeout_ms = timeout_ms.clamp(1, 60_000);
    let ttl = ttl.max(1);
    match addr {
        IpAddr::V4(v4) => ping_v4(v4, seq, timeout_ms, ttl, size),
        IpAddr::V6(v6) => ping_v6(v6, seq, timeout_ms, ttl, size),
    }
}

fn ping_v4(addr: Ipv4Addr, seq: u32, timeout_ms: u32, ttl: u8, size: u16) -> PingReply {
    // SAFETY: no arguments; the result is checked.
    let handle = match unsafe { IcmpCreateFile() } {
        Ok(h) => IcmpHandle(h),
        Err(_) => return failed(seq, "Could not open ICMP"),
    };
    let data = payload(seq, size);
    let options = IP_OPTION_INFORMATION {
        Ttl: ttl,
        ..Default::default()
    };
    // Room for the reply, the echoed data, an ICMP error (8 bytes) and the
    // I/O status block the API appends.
    let reply_size = std::mem::size_of::<ICMP_ECHO_REPLY>() + data.len() + 8 + 16;
    // u64 elements keep the buffer aligned for ICMP_ECHO_REPLY.
    let mut buffer = vec![0u64; reply_size.div_ceil(8)];
    let started = Instant::now();
    // SAFETY: the request data, options and reply buffer are live for the
    // whole blocking call and the sizes passed match them.
    let count = unsafe {
        IcmpSendEcho2(
            handle.0,
            HANDLE::default(),
            None,
            None,
            u32::from_ne_bytes(addr.octets()),
            data.as_ptr() as *const c_void,
            data.len() as u16,
            Some(&options),
            buffer.as_mut_ptr() as *mut c_void,
            (buffer.len() * 8) as u32,
            timeout_ms,
        )
    };
    let measured = started.elapsed();
    // SAFETY: read immediately after the call, before anything else can
    // change the thread's last-error value.
    let last_error = unsafe { GetLastError().0 };
    // SAFETY: the buffer is at least as large as one ICMP_ECHO_REPLY, aligned
    // to 8 bytes, and zero-initialised if the call wrote nothing.
    let reply = unsafe { std::ptr::read(buffer.as_ptr() as *const ICMP_ECHO_REPLY) };
    let status = if count > 0 {
        reply.Status
    } else if last_error == IP_SUCCESS {
        IP_REQ_TIMED_OUT
    } else {
        last_error
    };
    if count == 0 && !is_ip_status(status) {
        return failed(seq, status_text(status));
    }
    let from = (reply.Address != 0).then(|| Ipv4Addr::from(reply.Address.to_ne_bytes()));
    let answered = from.is_some() && status != IP_REQ_TIMED_OUT;
    PingReply {
        seq,
        from: from.map(|a| a.to_string()),
        rtt_ms: answered.then(|| pick_rtt(reply.RoundTripTime, measured)),
        ttl: (status == IP_SUCCESS).then_some(reply.Options.Ttl),
        status: status_text(status).to_string(),
        ok: status == IP_SUCCESS,
    }
}

fn ping_v6(addr: Ipv6Addr, seq: u32, timeout_ms: u32, ttl: u8, size: u16) -> PingReply {
    // SAFETY: no arguments; the result is checked.
    let handle = match unsafe { Icmp6CreateFile() } {
        Ok(h) => IcmpHandle(h),
        Err(_) => return failed(seq, "Could not open ICMPv6"),
    };
    let data = payload(seq, size);
    let options = IP_OPTION_INFORMATION {
        Ttl: ttl,
        ..Default::default()
    };
    let source = to_sockaddr_in6(Ipv6Addr::UNSPECIFIED, 0);
    let dest = to_sockaddr_in6(addr, 0);
    let reply_size = std::mem::size_of::<ICMPV6_ECHO_REPLY_LH>() + data.len() + 8 + 16;
    let mut buffer = vec![0u64; reply_size.div_ceil(8)];
    let started = Instant::now();
    // SAFETY: the addresses, request data, options and reply buffer are live
    // for the whole blocking call and the sizes passed match them.
    let count = unsafe {
        Icmp6SendEcho2(
            handle.0,
            HANDLE::default(),
            None,
            None,
            &source,
            &dest,
            data.as_ptr() as *const c_void,
            data.len() as u16,
            Some(&options),
            buffer.as_mut_ptr() as *mut c_void,
            (buffer.len() * 8) as u32,
            timeout_ms,
        )
    };
    let measured = started.elapsed();
    // SAFETY: read immediately after the call.
    let last_error = unsafe { GetLastError().0 };
    // SAFETY: the buffer is at least as large as one reply struct, aligned to
    // 8 bytes, and zero-initialised if the call wrote nothing.
    let reply = unsafe { std::ptr::read(buffer.as_ptr() as *const ICMPV6_ECHO_REPLY_LH) };
    // Copy out of the packed address before using it.
    let words: [u16; 8] = reply.Address.sin6_addr;
    let reply_status = reply.Status;
    let reply_rtt = reply.RoundTripTime;
    let status = if count > 0 {
        reply_status
    } else if last_error == IP_SUCCESS {
        IP_REQ_TIMED_OUT
    } else {
        last_error
    };
    if count == 0 && !is_ip_status(status) {
        return failed(seq, status_text(status));
    }
    // Each u16 holds two address bytes in memory order.
    let mut octets = [0u8; 16];
    for (pair, word) in octets.as_chunks_mut::<2>().0.iter_mut().zip(words) {
        *pair = word.to_ne_bytes();
    }
    let from = Ipv6Addr::from(octets);
    let from = (!from.is_unspecified()).then_some(from);
    let answered = from.is_some() && status != IP_REQ_TIMED_OUT;
    PingReply {
        seq,
        from: from.map(|a| a.to_string()),
        rtt_ms: answered.then(|| pick_rtt(reply_rtt, measured)),
        // The IPv6 reply does not carry the hop limit.
        ttl: None,
        status: status_text(status).to_string(),
        ok: status == IP_SUCCESS,
    }
}

/// Statistics over a run (pure, unit-tested).
pub fn stats(replies: &[PingReply]) -> PingStats {
    let sent = replies.len() as u32;
    let times: Vec<f32> = replies
        .iter()
        .filter(|r| r.ok)
        .filter_map(|r| r.rtt_ms)
        .filter(|t| t.is_finite())
        .collect();
    let received = replies.iter().filter(|r| r.ok).count() as u32;
    let loss_pct = if sent == 0 {
        0.0
    } else {
        (sent - received) as f32 * 100.0 / sent as f32
    };
    if times.is_empty() {
        return PingStats {
            sent,
            received,
            loss_pct,
            ..Default::default()
        };
    }
    let n = times.len() as f32;
    let min_ms = times.iter().copied().fold(f32::INFINITY, f32::min);
    let max_ms = times.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let avg_ms = times.iter().sum::<f32>() / n;
    let jitter_ms = if times.len() < 2 {
        0.0
    } else {
        times
            .windows(2)
            .map(|w| match w {
                [a, b] => (b - a).abs(),
                _ => 0.0,
            })
            .sum::<f32>()
            / (n - 1.0)
    };
    let variance = times.iter().map(|t| (t - avg_ms).powi(2)).sum::<f32>() / n;
    PingStats {
        sent,
        received,
        loss_pct,
        min_ms,
        avg_ms,
        max_ms,
        jitter_ms,
        stddev_ms: variance.sqrt(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(seq: u32, ms: f32) -> PingReply {
        PingReply {
            seq,
            from: Some("192.0.2.1".into()),
            rtt_ms: Some(ms),
            ttl: Some(64),
            status: "Reply".into(),
            ok: true,
        }
    }

    fn lost(seq: u32) -> PingReply {
        PingReply {
            seq,
            status: "Timed out".into(),
            ..Default::default()
        }
    }

    #[test]
    fn stats_empty() {
        assert_eq!(stats(&[]), PingStats::default());
    }

    #[test]
    fn stats_all_lost() {
        let s = stats(&[lost(1), lost(2), lost(3)]);
        assert_eq!((s.sent, s.received), (3, 0));
        assert_eq!(s.loss_pct, 100.0);
        assert_eq!((s.min_ms, s.avg_ms, s.max_ms), (0.0, 0.0, 0.0));
        assert_eq!((s.jitter_ms, s.stddev_ms), (0.0, 0.0));
    }

    #[test]
    fn stats_mixed() {
        let s = stats(&[ok(1, 10.0), lost(2), ok(3, 14.0), ok(4, 12.0)]);
        assert_eq!((s.sent, s.received), (4, 3));
        assert_eq!(s.loss_pct, 25.0);
        assert_eq!((s.min_ms, s.avg_ms, s.max_ms), (10.0, 12.0, 14.0));
        // |14-10| and |12-14| -> mean 3.
        assert_eq!(s.jitter_ms, 3.0);
        assert!((s.stddev_ms - (8.0f32 / 3.0).sqrt()).abs() < 1e-4);
    }

    #[test]
    fn stats_single_reply() {
        let s = stats(&[ok(1, 7.5)]);
        assert_eq!((s.min_ms, s.avg_ms, s.max_ms), (7.5, 7.5, 7.5));
        assert_eq!((s.jitter_ms, s.stddev_ms, s.loss_pct), (0.0, 0.0, 0.0));
    }

    #[test]
    fn stats_ignores_router_answers() {
        // A TTL-expired answer has a time but did not reach the target.
        let mut expired = ok(1, 3.0);
        expired.ok = false;
        expired.status = "TTL expired".into();
        let s = stats(&[expired, ok(2, 9.0)]);
        assert_eq!((s.sent, s.received), (2, 1));
        assert_eq!(s.min_ms, 9.0);
    }

    #[test]
    fn status_words() {
        assert_eq!(status_text(0), "Reply");
        assert_eq!(status_text(11010), "Timed out");
        assert_eq!(status_text(11013), "TTL expired");
        assert_eq!(status_text(11003), "Destination host unreachable");
        assert_eq!(status_text(11002), "Destination network unreachable");
        assert_eq!(status_text(11050), "General failure");
        assert_eq!(status_text(424242), "Failed");
        for code in 11001..=11050 {
            assert!(!status_text(code).is_empty());
        }
    }

    #[test]
    fn sub_millisecond_times_use_the_local_timer() {
        assert_eq!(pick_rtt(12, Duration::from_micros(300)), 12.0);
        let t = pick_rtt(0, Duration::from_micros(300));
        assert!((t - 0.3).abs() < 1e-3);
        // A slow call that the system still calls 0 ms stays below 1 ms.
        assert_eq!(pick_rtt(0, Duration::from_millis(40)), 1.0);
    }

    #[test]
    fn payload_shape() {
        assert_eq!(payload(1, 32).len(), 32);
        assert_eq!(payload(1, 0).len(), 0);
        assert!(payload(7, 64).iter().all(u8::is_ascii_lowercase));
    }

    #[test]
    fn resolve_literals() {
        assert_eq!(
            resolve("192.0.2.7").unwrap(),
            vec!["192.0.2.7".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            resolve(" [2001:db8::1] ").unwrap(),
            vec!["2001:db8::1".parse::<IpAddr>().unwrap()]
        );
        assert!(resolve("").is_err());
        assert!(resolve("bad host").is_err());
    }

    #[test]
    fn loopback_ping() {
        let r = ping_once(IpAddr::V4(Ipv4Addr::LOCALHOST), 1, 1000, 64, 32);
        assert!(r.ok, "{}", r.status);
        assert_eq!(r.from.as_deref(), Some("127.0.0.1"));
        assert!(r.rtt_ms.is_some_and(|t| t > 0.0));
    }

    #[test]
    fn loopback_ping_v6() {
        let r = ping_once(IpAddr::V6(Ipv6Addr::LOCALHOST), 1, 1000, 64, 32);
        // IPv6 may be disabled on a machine; when it answers it must be right.
        if r.ok {
            assert_eq!(r.from.as_deref(), Some("::1"));
            assert!(r.rtt_ms.is_some());
        } else {
            assert!(!r.status.is_empty());
        }
    }
}
