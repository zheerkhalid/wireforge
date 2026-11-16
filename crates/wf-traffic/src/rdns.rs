//! Reverse DNS for remote endpoints (only used when the user turns it on).

use crate::util;
use std::net::IpAddr;
use std::sync::Once;
use windows::Win32::Networking::WinSock::{socklen_t, GetNameInfoW, WSAStartup, SOCKADDR, WSADATA};

const NI_NAMEREQD: i32 = 4;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;

static WINSOCK: Once = Once::new();

fn init_winsock() {
    WINSOCK.call_once(|| {
        let mut data = WSADATA::default();
        // SAFETY: `data` is a writable WSADATA. Winsock stays initialised for
        // the life of the process (no matching WSACleanup on purpose).
        unsafe {
            let _ = WSAStartup(0x0202, &mut data);
        }
    });
}

/// The raw bytes of a `SOCKADDR_IN` / `SOCKADDR_IN6` for `ip` (port 0),
/// in a buffer aligned for either.
fn sockaddr_bytes(ip: IpAddr) -> ([u32; 7], i32) {
    let mut bytes = [0u8; 28];
    let len = match ip {
        IpAddr::V4(v4) => {
            bytes[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
            bytes[4..8].copy_from_slice(&v4.octets());
            16
        }
        IpAddr::V6(v6) => {
            bytes[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            bytes[8..24].copy_from_slice(&v6.octets());
            28
        }
    };
    let mut words = [0u32; 7];
    for (w, chunk) in words.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *w = u32::from_ne_bytes(*chunk);
    }
    (words, len)
}

/// Blocking; `None` when there is no name.
pub fn reverse_dns(ip: IpAddr) -> Option<String> {
    init_winsock();
    let (addr, len) = sockaddr_bytes(ip);
    // NI_MAXHOST
    let mut host = [0u16; 1025];
    // SAFETY: `addr` holds a complete, aligned socket address of `len` bytes
    // and `host` is a writable buffer whose length is passed along.
    let rc = unsafe {
        GetNameInfoW(
            addr.as_ptr() as *const SOCKADDR,
            socklen_t(len),
            Some(&mut host),
            None,
            NI_NAMEREQD,
        )
    };
    if rc != 0 {
        return None;
    }
    let name = util::from_wide_buf(&host);
    let name = name.trim().trim_end_matches('.');
    // With NI_NAMEREQD a numeric answer should not happen; be defensive.
    if name.is_empty() || name.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_layout() {
        let (w, len) = sockaddr_bytes("192.0.2.9".parse().expect("literal"));
        assert_eq!(len, 16);
        let bytes: Vec<u8> = w.iter().flat_map(|x| x.to_ne_bytes()).collect();
        assert_eq!(
            util::sockaddr_bytes_ip(&bytes[..16]),
            Some("192.0.2.9".parse().expect("literal"))
        );
        let (w, len) = sockaddr_bytes("2001:db8::77".parse().expect("literal"));
        assert_eq!(len, 28);
        let bytes: Vec<u8> = w.iter().flat_map(|x| x.to_ne_bytes()).collect();
        assert_eq!(
            util::sockaddr_bytes_ip(&bytes),
            Some("2001:db8::77".parse().expect("literal"))
        );
    }

    #[test]
    fn loopback_lookup_does_not_touch_the_network_and_does_not_crash() {
        // The answer depends on the hosts file; only the call path is checked.
        let _ = reverse_dns("127.0.0.1".parse().expect("literal"));
    }
}
