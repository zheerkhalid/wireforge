//! TCP / UDP tables with owning processes.
//!
//! The tables are fetched with the `OWNER_MODULE` classes (a superset of the
//! `OWNER_PID` ones that also carries the creation time of each socket) and
//! parsed from raw bytes by pure functions.

use crate::procs;
use crate::types::*;
use crate::util;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_MODULE_ALL, UDP_TABLE_OWNER_MODULE,
};

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

// Layout of the table buffers (all rows are 8-byte aligned, so the first row
// follows the 4-byte entry count at offset 8). Verified against the `windows`
// crate definitions in the tests below.
const TABLE_HEADER: usize = 8;
const TCP4_ROW: usize = 160;
const TCP6_ROW: usize = 192;
const UDP4_ROW: usize = 160;
const UDP6_ROW: usize = 176;

/// A table row before the process name is filled in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawRow {
    pub proto: Proto,
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: Option<IpAddr>,
    pub remote_port: u16,
    pub state: ConnState,
    pub pid: u32,
    pub created: Option<i64>,
}

/// Maps a `MIB_TCP_STATE` value.
pub fn tcp_state(raw: u32) -> ConnState {
    match raw {
        1 => ConnState::Closed,
        2 => ConnState::Listening,
        3 => ConnState::SynSent,
        4 => ConnState::SynReceived,
        5 => ConnState::Established,
        6 | 7 => ConnState::FinWait,
        8 => ConnState::CloseWait,
        9 => ConnState::Closing,
        10 => ConnState::LastAck,
        11 => ConnState::TimeWait,
        // 12 = delete TCB, anything else is unknown: the connection is gone.
        _ => ConnState::Closed,
    }
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn i64_at(b: &[u8], off: usize) -> Option<i64> {
    Some(i64::from_ne_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// The tables store a port in the low 16 bits of a DWORD in network byte
/// order, so the first two bytes in memory are the big-endian port.
fn port_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn v4_at(b: &[u8], off: usize) -> Option<IpAddr> {
    let a: [u8; 4] = b.get(off..off + 4)?.try_into().ok()?;
    Some(IpAddr::V4(Ipv4Addr::from(a)))
}

fn v6_at(b: &[u8], off: usize) -> Option<IpAddr> {
    let a: [u8; 16] = b.get(off..off + 16)?.try_into().ok()?;
    Some(IpAddr::V6(Ipv6Addr::from(a)))
}

/// The rows of a table buffer: the count is clamped to what the buffer holds.
fn rows(buf: &[u8], row_size: usize) -> impl Iterator<Item = &[u8]> {
    let count = u32_at(buf, 0).unwrap_or(0) as usize;
    let body = buf.get(TABLE_HEADER..).unwrap_or(&[]);
    body.chunks_exact(row_size).take(count)
}

fn tcp_row(
    state: u32,
    local: IpAddr,
    local_port: u16,
    remote: IpAddr,
    remote_port: u16,
    pid: u32,
    created: i64,
) -> RawRow {
    let state = tcp_state(state);
    let listening = state == ConnState::Listening;
    RawRow {
        proto: Proto::Tcp,
        local,
        local_port,
        remote: (!listening).then_some(remote),
        remote_port: if listening { 0 } else { remote_port },
        state,
        pid,
        created: util::filetime_to_unix(created),
    }
}

/// Parses a `MIB_TCPTABLE_OWNER_MODULE` buffer.
pub fn parse_tcp4_table(buf: &[u8]) -> Vec<RawRow> {
    rows(buf, TCP4_ROW)
        .filter_map(|r| {
            Some(tcp_row(
                u32_at(r, 0)?,
                v4_at(r, 4)?,
                port_at(r, 8)?,
                v4_at(r, 12)?,
                port_at(r, 16)?,
                u32_at(r, 20)?,
                i64_at(r, 24)?,
            ))
        })
        .collect()
}

/// Parses a `MIB_TCP6TABLE_OWNER_MODULE` buffer.
pub fn parse_tcp6_table(buf: &[u8]) -> Vec<RawRow> {
    rows(buf, TCP6_ROW)
        .filter_map(|r| {
            Some(tcp_row(
                u32_at(r, 48)?,
                v6_at(r, 0)?,
                port_at(r, 20)?,
                v6_at(r, 24)?,
                port_at(r, 44)?,
                u32_at(r, 52)?,
                i64_at(r, 56)?,
            ))
        })
        .collect()
}

fn udp_row(local: IpAddr, local_port: u16, pid: u32, created: i64) -> RawRow {
    RawRow {
        proto: Proto::Udp,
        local,
        local_port,
        remote: None,
        remote_port: 0,
        state: ConnState::Stateless,
        pid,
        created: util::filetime_to_unix(created),
    }
}

/// Parses a `MIB_UDPTABLE_OWNER_MODULE` buffer.
pub fn parse_udp4_table(buf: &[u8]) -> Vec<RawRow> {
    rows(buf, UDP4_ROW)
        .filter_map(|r| {
            Some(udp_row(
                v4_at(r, 0)?,
                port_at(r, 4)?,
                u32_at(r, 8)?,
                i64_at(r, 16)?,
            ))
        })
        .collect()
}

/// Parses a `MIB_UDP6TABLE_OWNER_MODULE` buffer.
pub fn parse_udp6_table(buf: &[u8]) -> Vec<RawRow> {
    rows(buf, UDP6_ROW)
        .filter_map(|r| {
            Some(udp_row(
                v6_at(r, 0)?,
                port_at(r, 20)?,
                u32_at(r, 24)?,
                i64_at(r, 32)?,
            ))
        })
        .collect()
}

/// Calls a `GetExtended*Table`-style function until the buffer is big enough.
fn fetch(mut call: impl FnMut(*mut core::ffi::c_void, &mut u32) -> u32) -> Result<Vec<u8>, u32> {
    let mut size: u32 = 0;
    let mut err = call(std::ptr::null_mut(), &mut size);
    for _ in 0..6 {
        if err != ERROR_INSUFFICIENT_BUFFER {
            break;
        }
        // The table can grow between the two calls: leave some room.
        size = size.saturating_add(4096);
        let mut buf = vec![0u8; size as usize];
        err = call(buf.as_mut_ptr() as *mut core::ffi::c_void, &mut size);
        if err == 0 {
            buf.truncate((size as usize).min(buf.len()));
            return Ok(buf);
        }
    }
    if err == 0 {
        Ok(Vec::new()) // an empty table fitted into zero bytes
    } else {
        Err(err)
    }
}

fn fetch_tcp(family: u32) -> Result<Vec<u8>, u32> {
    fetch(|ptr, size| {
        let table = (!ptr.is_null()).then_some(ptr);
        // SAFETY: `ptr` is null (size query) or points to `*size` writable
        // bytes owned by `fetch`.
        unsafe { GetExtendedTcpTable(table, size, false, family, TCP_TABLE_OWNER_MODULE_ALL, 0) }
    })
}

fn fetch_udp(family: u32) -> Result<Vec<u8>, u32> {
    fetch(|ptr, size| {
        let table = (!ptr.is_null()).then_some(ptr);
        // SAFETY: as in `fetch_tcp`.
        unsafe { GetExtendedUdpTable(table, size, false, family, UDP_TABLE_OWNER_MODULE, 0) }
    })
}

/// IPv4 and IPv6, TCP and UDP rows without process names (cheap).
pub fn list_raw() -> Result<Vec<RawRow>, String> {
    let tcp4 =
        fetch_tcp(AF_INET).map_err(|e| format!("GetExtendedTcpTable failed with error {e}"))?;
    let mut out = parse_tcp4_table(&tcp4);
    // IPv6 can be switched off; the IPv4 tables are still useful then.
    if let Ok(buf) = fetch_tcp(AF_INET6) {
        out.extend(parse_tcp6_table(&buf));
    }
    let udp4 =
        fetch_udp(AF_INET).map_err(|e| format!("GetExtendedUdpTable failed with error {e}"))?;
    out.extend(parse_udp4_table(&udp4));
    if let Ok(buf) = fetch_udp(AF_INET6) {
        out.extend(parse_udp6_table(&buf));
    }
    Ok(out)
}

/// Like `list_connections`, with the process lookup supplied by the caller
/// (`pid` -> `(file name, full path)`), so a long-lived cache can be used.
pub fn list_connections_with(
    resolve: &mut dyn FnMut(u32) -> Option<(String, String)>,
) -> Result<Vec<Connection>, String> {
    let raw = list_raw()?;
    Ok(raw
        .into_iter()
        .map(|r| {
            let (process, path) = resolve(r.pid).unwrap_or_default();
            Connection {
                proto: r.proto,
                local: r.local,
                local_port: r.local_port,
                remote: r.remote,
                remote_port: r.remote_port,
                state: r.state,
                pid: r.pid,
                process,
                path,
                created: r.created,
            }
        })
        .collect())
}

/// IPv4 and IPv6, TCP and UDP, with process names filled in.
///
/// Names come from a short-lived process-wide cache
/// (`procs::process_name_cached`), so calling this every second or two is cheap.
pub fn list_connections() -> Result<Vec<Connection>, String> {
    // Each PID is resolved once per call, whatever the shared cache does.
    let mut seen: HashMap<u32, Option<(String, String)>> = HashMap::new();
    list_connections_with(&mut |pid| {
        seen.entry(pid)
            .or_insert_with(|| procs::process_name_cached(pid))
            .clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};
    use windows::Win32::NetworkManagement::IpHelper::{
        MIB_TCP6ROW_OWNER_MODULE, MIB_TCP6TABLE_OWNER_MODULE, MIB_TCPROW_OWNER_MODULE,
        MIB_TCPTABLE_OWNER_MODULE, MIB_UDP6ROW_OWNER_MODULE, MIB_UDP6TABLE_OWNER_MODULE,
        MIB_UDPROW_OWNER_MODULE, MIB_UDPTABLE_OWNER_MODULE,
    };

    #[test]
    fn layout_matches_the_windows_definitions() {
        assert_eq!(size_of::<MIB_TCPROW_OWNER_MODULE>(), TCP4_ROW);
        assert_eq!(size_of::<MIB_TCP6ROW_OWNER_MODULE>(), TCP6_ROW);
        assert_eq!(size_of::<MIB_UDPROW_OWNER_MODULE>(), UDP4_ROW);
        assert_eq!(size_of::<MIB_UDP6ROW_OWNER_MODULE>(), UDP6_ROW);
        assert_eq!(offset_of!(MIB_TCPTABLE_OWNER_MODULE, table), TABLE_HEADER);
        assert_eq!(offset_of!(MIB_TCP6TABLE_OWNER_MODULE, table), TABLE_HEADER);
        assert_eq!(offset_of!(MIB_UDPTABLE_OWNER_MODULE, table), TABLE_HEADER);
        assert_eq!(offset_of!(MIB_UDP6TABLE_OWNER_MODULE, table), TABLE_HEADER);

        assert_eq!(offset_of!(MIB_TCPROW_OWNER_MODULE, dwState), 0);
        assert_eq!(offset_of!(MIB_TCPROW_OWNER_MODULE, dwLocalAddr), 4);
        assert_eq!(offset_of!(MIB_TCPROW_OWNER_MODULE, dwLocalPort), 8);
        assert_eq!(offset_of!(MIB_TCPROW_OWNER_MODULE, dwRemoteAddr), 12);
        assert_eq!(offset_of!(MIB_TCPROW_OWNER_MODULE, dwRemotePort), 16);
        assert_eq!(offset_of!(MIB_TCPROW_OWNER_MODULE, dwOwningPid), 20);
        assert_eq!(offset_of!(MIB_TCPROW_OWNER_MODULE, liCreateTimestamp), 24);

        assert_eq!(offset_of!(MIB_TCP6ROW_OWNER_MODULE, ucLocalAddr), 0);
        assert_eq!(offset_of!(MIB_TCP6ROW_OWNER_MODULE, dwLocalPort), 20);
        assert_eq!(offset_of!(MIB_TCP6ROW_OWNER_MODULE, ucRemoteAddr), 24);
        assert_eq!(offset_of!(MIB_TCP6ROW_OWNER_MODULE, dwRemotePort), 44);
        assert_eq!(offset_of!(MIB_TCP6ROW_OWNER_MODULE, dwState), 48);
        assert_eq!(offset_of!(MIB_TCP6ROW_OWNER_MODULE, dwOwningPid), 52);
        assert_eq!(offset_of!(MIB_TCP6ROW_OWNER_MODULE, liCreateTimestamp), 56);

        assert_eq!(offset_of!(MIB_UDPROW_OWNER_MODULE, dwLocalAddr), 0);
        assert_eq!(offset_of!(MIB_UDPROW_OWNER_MODULE, dwLocalPort), 4);
        assert_eq!(offset_of!(MIB_UDPROW_OWNER_MODULE, dwOwningPid), 8);
        assert_eq!(offset_of!(MIB_UDPROW_OWNER_MODULE, liCreateTimestamp), 16);

        assert_eq!(offset_of!(MIB_UDP6ROW_OWNER_MODULE, ucLocalAddr), 0);
        assert_eq!(offset_of!(MIB_UDP6ROW_OWNER_MODULE, dwLocalPort), 20);
        assert_eq!(offset_of!(MIB_UDP6ROW_OWNER_MODULE, dwOwningPid), 24);
        assert_eq!(offset_of!(MIB_UDP6ROW_OWNER_MODULE, liCreateTimestamp), 32);
    }

    const CREATED_UNIX: i64 = 1_794_787_200;

    fn filetime(unix: i64) -> i64 {
        (unix + 11_644_473_600) * 10_000_000
    }

    fn table(count: u32, rows: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = vec![0u8; TABLE_HEADER];
        buf[0..4].copy_from_slice(&count.to_ne_bytes());
        for r in rows {
            buf.extend_from_slice(r);
        }
        buf
    }

    fn put_port(row: &mut [u8], off: usize, port: u16) {
        // Network byte order in the low word of the DWORD.
        row[off..off + 2].copy_from_slice(&port.to_be_bytes());
    }

    fn tcp4(
        state: u32,
        local: [u8; 4],
        lport: u16,
        remote: [u8; 4],
        rport: u16,
        pid: u32,
    ) -> Vec<u8> {
        let mut r = vec![0u8; TCP4_ROW];
        r[0..4].copy_from_slice(&state.to_ne_bytes());
        r[4..8].copy_from_slice(&local);
        put_port(&mut r, 8, lport);
        r[12..16].copy_from_slice(&remote);
        put_port(&mut r, 16, rport);
        r[20..24].copy_from_slice(&pid.to_ne_bytes());
        r[24..32].copy_from_slice(&filetime(CREATED_UNIX).to_ne_bytes());
        r
    }

    #[test]
    fn tcp4_rows() {
        let buf = table(
            2,
            &[
                tcp4(5, [192, 0, 2, 10], 50_123, [198, 51, 100, 7], 443, 4321),
                tcp4(2, [0, 0, 0, 0], 8080, [0, 0, 0, 0], 0, 800),
            ],
        );
        let rows = parse_tcp4_table(&buf);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            RawRow {
                proto: Proto::Tcp,
                local: "192.0.2.10".parse().expect("literal"),
                local_port: 50_123,
                remote: Some("198.51.100.7".parse().expect("literal")),
                remote_port: 443,
                state: ConnState::Established,
                pid: 4321,
                created: Some(CREATED_UNIX),
            }
        );
        // Listeners have no remote side.
        assert_eq!(rows[1].state, ConnState::Listening);
        assert_eq!(rows[1].remote, None);
        assert_eq!(rows[1].remote_port, 0);
        assert_eq!(rows[1].local_port, 8080);
    }

    #[test]
    fn tcp6_rows() {
        let local: Ipv6Addr = "2001:db8::10".parse().expect("literal");
        let remote: Ipv6Addr = "2001:db8:ffff::1".parse().expect("literal");
        let mut r = vec![0u8; TCP6_ROW];
        r[0..16].copy_from_slice(&local.octets());
        put_port(&mut r, 20, 51_000);
        r[24..40].copy_from_slice(&remote.octets());
        put_port(&mut r, 44, 853);
        r[48..52].copy_from_slice(&8u32.to_ne_bytes());
        r[52..56].copy_from_slice(&77u32.to_ne_bytes());
        // No creation time.
        let rows = parse_tcp6_table(&table(1, &[r]));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].local, IpAddr::V6(local));
        assert_eq!(rows[0].local_port, 51_000);
        assert_eq!(rows[0].remote, Some(IpAddr::V6(remote)));
        assert_eq!(rows[0].remote_port, 853);
        assert_eq!(rows[0].state, ConnState::CloseWait);
        assert_eq!(rows[0].pid, 77);
        assert_eq!(rows[0].created, None);
    }

    #[test]
    fn udp_rows() {
        let mut r4 = vec![0u8; UDP4_ROW];
        r4[0..4].copy_from_slice(&[192, 0, 2, 10]);
        put_port(&mut r4, 4, 5353);
        r4[8..12].copy_from_slice(&1500u32.to_ne_bytes());
        r4[16..24].copy_from_slice(&filetime(CREATED_UNIX).to_ne_bytes());
        let rows = parse_udp4_table(&table(1, &[r4]));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].proto, Proto::Udp);
        assert_eq!(rows[0].local_port, 5353);
        assert_eq!(rows[0].pid, 1500);
        assert_eq!(rows[0].state, ConnState::Stateless);
        assert_eq!(rows[0].remote, None);
        assert_eq!(rows[0].created, Some(CREATED_UNIX));

        let local: Ipv6Addr = "2001:db8::abcd".parse().expect("literal");
        let mut r6 = vec![0u8; UDP6_ROW];
        r6[0..16].copy_from_slice(&local.octets());
        put_port(&mut r6, 20, 546);
        r6[24..28].copy_from_slice(&2468u32.to_ne_bytes());
        let rows = parse_udp6_table(&table(1, &[r6]));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].local, IpAddr::V6(local));
        assert_eq!(rows[0].local_port, 546);
        assert_eq!(rows[0].pid, 2468);
        assert_eq!(rows[0].created, None);
    }

    #[test]
    fn ports_are_host_order() {
        // Port 443 is stored as bytes 01 BB.
        let row = tcp4(5, [192, 0, 2, 1], 443, [192, 0, 2, 2], 80, 1);
        assert_eq!(&row[8..10], &[0x01, 0xBB]);
        let rows = parse_tcp4_table(&table(1, &[row]));
        assert_eq!(rows[0].local_port, 443);
        assert_eq!(rows[0].remote_port, 80);
    }

    #[test]
    fn damaged_buffers_do_not_panic() {
        assert!(parse_tcp4_table(&[]).is_empty());
        assert!(parse_tcp4_table(&[1, 0]).is_empty());
        assert!(parse_udp6_table(&[5, 0, 0, 0, 0, 0, 0, 0]).is_empty());
        // The count claims more rows than the buffer holds.
        let buf = table(1000, &[tcp4(5, [192, 0, 2, 1], 1, [192, 0, 2, 2], 2, 3)]);
        assert_eq!(parse_tcp4_table(&buf).len(), 1);
        // A truncated last row is dropped.
        let mut buf = table(2, &[tcp4(5, [192, 0, 2, 1], 1, [192, 0, 2, 2], 2, 3)]);
        buf.extend_from_slice(&[0u8; 50]);
        assert_eq!(parse_tcp4_table(&buf).len(), 1);
        // The count limits the rows read.
        let buf = table(
            1,
            &[
                tcp4(5, [192, 0, 2, 1], 1, [192, 0, 2, 2], 2, 3),
                tcp4(5, [192, 0, 2, 1], 1, [192, 0, 2, 2], 2, 3),
            ],
        );
        assert_eq!(parse_tcp4_table(&buf).len(), 1);
    }

    #[test]
    fn states() {
        assert_eq!(tcp_state(1), ConnState::Closed);
        assert_eq!(tcp_state(2), ConnState::Listening);
        assert_eq!(tcp_state(3), ConnState::SynSent);
        assert_eq!(tcp_state(4), ConnState::SynReceived);
        assert_eq!(tcp_state(5), ConnState::Established);
        assert_eq!(tcp_state(6), ConnState::FinWait);
        assert_eq!(tcp_state(7), ConnState::FinWait);
        assert_eq!(tcp_state(8), ConnState::CloseWait);
        assert_eq!(tcp_state(9), ConnState::Closing);
        assert_eq!(tcp_state(10), ConnState::LastAck);
        assert_eq!(tcp_state(11), ConnState::TimeWait);
        assert_eq!(tcp_state(12), ConnState::Closed);
        assert_eq!(tcp_state(0), ConnState::Closed);
        assert_eq!(tcp_state(999), ConnState::Closed);
    }

    #[test]
    fn live_tables_have_a_sane_shape() {
        // Shapes only: never print real values.
        let conns = list_connections().expect("list_connections");
        for c in &conns {
            match c.proto {
                Proto::Udp => {
                    assert_eq!(c.state, ConnState::Stateless);
                    assert_eq!(c.remote, None);
                }
                Proto::Tcp => {
                    assert_ne!(c.state, ConnState::Stateless);
                    assert_eq!(c.remote.is_none(), c.state == ConnState::Listening);
                }
            }
            if c.pid == 4 {
                assert_eq!(c.process, "System");
            }
            if !c.path.is_empty() {
                assert!(c.path.ends_with(&c.process));
            }
        }
    }
}
