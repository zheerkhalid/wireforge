//! Small shared helpers: wide strings, time conversions, socket addresses.

use crate::types::Day;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows::Win32::Networking::WinSock::SOCKADDR;

/// Seconds between 1601-01-01 (FILETIME epoch) and 1970-01-01.
const FILETIME_UNIX_DIFF_SECS: i64 = 11_644_473_600;

/// UTF-16, NUL terminated.
pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The text of a UTF-16 buffer up to the first NUL (or the whole buffer).
pub(crate) fn from_wide_buf(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// Reads a NUL-terminated UTF-16 string (at most `max` units).
///
/// # Safety
/// `p` must be null or point to a readable, NUL-terminated UTF-16 string.
pub(crate) unsafe fn from_wide_ptr(p: *const u16, max: usize) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: the caller guarantees the string is NUL terminated; reading
    // stops at the terminator or at `max`.
    while len < max && unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` units were just read successfully.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

/// Reads a NUL-terminated ANSI string (at most `max` bytes).
///
/// # Safety
/// `p` must be null or point to a readable, NUL-terminated byte string.
pub(crate) unsafe fn from_ansi_ptr(p: *const u8, max: usize) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: as above, bounded by the terminator or `max`.
    while len < max && unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` bytes were just read successfully.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(p, len) }).into_owned()
}

/// Locks a mutex, ignoring poisoning (the data are plain counters and stay
/// usable; the release build aborts on panic anyway).
pub(crate) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A FILETIME value (100 ns ticks since 1601) as Unix seconds; `None` for zero
/// or anything before 1970.
pub(crate) fn filetime_to_unix(ticks: i64) -> Option<i64> {
    if ticks <= 0 {
        return None;
    }
    let secs = ticks / 10_000_000 - FILETIME_UNIX_DIFF_SECS;
    (secs > 0).then_some(secs)
}

/// The local calendar day of a Unix time stamp, using the time zone rules of
/// this PC (including daylight saving time at that date).
pub(crate) fn unix_to_local_day(unix: i64) -> Option<Day> {
    let ticks = unix
        .checked_add(FILETIME_UNIX_DIFF_SECS)?
        .checked_mul(10_000_000)?;
    if ticks < 0 {
        return None;
    }
    let ft = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    // SAFETY: all pointers refer to live stack values of the right types; a
    // null time zone means "the current one".
    unsafe {
        windows::Win32::System::Time::FileTimeToSystemTime(&ft, &mut utc).ok()?;
        windows::Win32::System::Time::SystemTimeToTzSpecificLocalTime(None, &utc, &mut local)
            .ok()?;
    }
    let day = Day {
        y: local.wYear as i32,
        m: local.wMonth as u32,
        d: local.wDay as u32,
    };
    day.is_valid().then_some(day)
}

/// The IP address inside a `SOCKADDR`.
///
/// # Safety
/// `sa` must be null or point to at least `len` readable bytes.
pub(crate) unsafe fn sockaddr_ip(sa: *const SOCKADDR, len: i32) -> Option<IpAddr> {
    if sa.is_null() || len < 2 {
        return None;
    }
    // SAFETY: the caller guarantees `len` readable bytes at `sa`.
    let bytes = unsafe { std::slice::from_raw_parts(sa as *const u8, len as usize) };
    sockaddr_bytes_ip(bytes)
}

/// The IP address inside the raw bytes of a `SOCKADDR_IN` / `SOCKADDR_IN6`.
pub(crate) fn sockaddr_bytes_ip(bytes: &[u8]) -> Option<IpAddr> {
    let family = u16::from_ne_bytes([*bytes.first()?, *bytes.get(1)?]);
    match family {
        2 => {
            // AF_INET: family(2) port(2) addr(4)
            let a: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(a)))
        }
        23 => {
            // AF_INET6: family(2) port(2) flowinfo(4) addr(16) scope(4)
            let a: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

/// Loopback, unspecified and multicast / broadcast destinations never leave
/// the machine as "usage" worth attributing to a remote endpoint.
pub(crate) fn is_loopback_or_unspecified(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|m| m.is_loopback() || m.is_unspecified())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_round_trip() {
        let w = wide("Wi-Fi 2");
        assert_eq!(w.last(), Some(&0));
        assert_eq!(from_wide_buf(&w), "Wi-Fi 2");
        assert_eq!(from_wide_buf(&[0x41, 0x42]), "AB");
        // SAFETY: `w` is NUL terminated and alive.
        assert_eq!(unsafe { from_wide_ptr(w.as_ptr(), 100) }, "Wi-Fi 2");
        // SAFETY: bounded by `max` before the terminator.
        assert_eq!(unsafe { from_wide_ptr(w.as_ptr(), 2) }, "Wi");
        // SAFETY: null is allowed.
        assert_eq!(unsafe { from_wide_ptr(std::ptr::null(), 10) }, "");
        // SAFETY: NUL-terminated literal.
        assert_eq!(
            unsafe { from_ansi_ptr(c"{ABC}".as_ptr() as *const u8, 64) },
            "{ABC}"
        );
    }

    #[test]
    fn filetime_conversion() {
        assert_eq!(filetime_to_unix(0), None);
        assert_eq!(filetime_to_unix(-5), None);
        // 2026-11-16 00:00:00 UTC
        let unix = 1_794_787_200i64;
        let ticks = (unix + FILETIME_UNIX_DIFF_SECS) * 10_000_000;
        assert_eq!(filetime_to_unix(ticks), Some(unix));
    }

    #[test]
    fn sockaddr_parsing() {
        let mut v4 = [0u8; 16];
        v4[0..2].copy_from_slice(&2u16.to_ne_bytes());
        v4[4..8].copy_from_slice(&[192, 0, 2, 7]);
        assert_eq!(
            sockaddr_bytes_ip(&v4),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)))
        );
        let mut v6 = [0u8; 28];
        v6[0..2].copy_from_slice(&23u16.to_ne_bytes());
        let addr: Ipv6Addr = "2001:db8::5".parse().expect("literal");
        v6[8..24].copy_from_slice(&addr.octets());
        assert_eq!(sockaddr_bytes_ip(&v6), Some(IpAddr::V6(addr)));
        assert_eq!(sockaddr_bytes_ip(&v6[..20]), None);
        assert_eq!(sockaddr_bytes_ip(&[]), None);
        assert_eq!(sockaddr_bytes_ip(&[9, 0, 0, 0, 0, 0, 0, 0]), None);
    }

    #[test]
    fn loopback_detection() {
        let yes = [
            "127.0.0.1",
            "127.9.9.9",
            "0.0.0.0",
            "::1",
            "::",
            "::ffff:127.0.0.1",
        ];
        for s in yes {
            let ip: IpAddr = s.parse().expect("literal");
            assert!(is_loopback_or_unspecified(&ip), "{s}");
        }
        for s in ["192.0.2.1", "2001:db8::1", "::ffff:198.51.100.4"] {
            let ip: IpAddr = s.parse().expect("literal");
            assert!(!is_loopback_or_unspecified(&ip), "{s}");
        }
    }
}
