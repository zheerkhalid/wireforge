//! TCP port check for a host the user names.
//!
//! This is a connect check against one host, not a scanner: there is no way
//! to give it a range of hosts, and at most `MAX_PORTS` ports per run.

use crate::types::*;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// A short list of common ports: `(port, service)`.
pub const COMMON_PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (135, "RPC"),
    (139, "NetBIOS"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (554, "RTSP"),
    (587, "SMTP submission"),
    (631, "IPP"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1883, "MQTT"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (5900, "VNC"),
    (8080, "HTTP alt"),
    (8443, "HTTPS alt"),
    (9100, "Printing"),
];

/// The most ports one run may check.
pub const MAX_PORTS: usize = 256;

/// How many connections are tried at the same time.
const PARALLEL: usize = 16;

/// Parses "22, 80, 443, 8000-8010" (pure, unit-tested); at most 256 ports.
/// The result is sorted and has no duplicates.
pub fn parse_ports(text: &str) -> Result<Vec<u16>, String> {
    let parse_one = |part: &str| -> Result<u16, String> {
        match part.trim().parse::<u32>() {
            Ok(n) if (1..=65_535).contains(&n) => Ok(n as u16),
            Ok(_) => Err(format!("\"{}\" is not a port (1 to 65535).", part.trim())),
            Err(_) => Err(format!("\"{}\" is not a port number.", part.trim())),
        }
    };
    let mut ports: Vec<u16> = Vec::new();
    let too_many = || format!("That is more than {MAX_PORTS} ports. Check fewer at a time.");
    for part in text.split([',', ';', ' ', '\t', '\n', '\r']) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('-') {
            Some((a, b)) => {
                let (first, last) = (parse_one(a)?, parse_one(b)?);
                if first > last {
                    return Err(format!("The range \"{part}\" is backwards."));
                }
                if usize::from(last - first) >= MAX_PORTS {
                    return Err(too_many());
                }
                ports.extend(first..=last);
            }
            None => ports.push(parse_one(part)?),
        }
        if ports.len() > MAX_PORTS * 4 {
            return Err(too_many());
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err("Enter at least one port, for example 22, 80, 443.".into());
    }
    if ports.len() > MAX_PORTS {
        return Err(too_many());
    }
    Ok(ports)
}

pub fn service_name(port: u16) -> &'static str {
    COMMON_PORTS
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, name)| *name)
        .unwrap_or("")
}

pub fn check_port(addr: IpAddr, port: u16, timeout_ms: u32) -> PortResult {
    let timeout = Duration::from_millis(u64::from(timeout_ms.clamp(50, 60_000)));
    let started = Instant::now();
    let outcome = TcpStream::connect_timeout(&SocketAddr::new(addr, port), timeout);
    let elapsed = started.elapsed().as_secs_f32() * 1000.0;
    let (state, connect_ms) = match outcome {
        Ok(_) => (PortState::Open, Some(elapsed)),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => (PortState::Closed, None),
        Err(_) => (PortState::NoAnswer, None),
    };
    PortResult {
        port,
        service: service_name(port).to_string(),
        state,
        connect_ms,
    }
}

/// Checks the ports a few at a time; `on_result` is called for each as it
/// finishes. The returned list is in the order of `ports` (ascending when it
/// came from `parse_ports`); ports skipped because of `cancel` are left out.
/// Only the first `MAX_PORTS` ports are checked.
pub fn check_ports(
    addr: IpAddr,
    ports: &[u16],
    timeout_ms: u32,
    cancel: &AtomicBool,
    on_result: &mut dyn FnMut(&PortResult),
) -> Vec<PortResult> {
    let ports = ports.get(..ports.len().min(MAX_PORTS)).unwrap_or(ports);
    let next = AtomicUsize::new(0);
    let mut slots: Vec<Option<PortResult>> = vec![None; ports.len()];
    std::thread::scope(|scope| {
        let (tx, rx) = mpsc::channel::<(usize, PortResult)>();
        for _ in 0..PARALLEL.min(ports.len()) {
            let tx = tx.clone();
            let next = &next;
            scope.spawn(move || loop {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(&port) = ports.get(index) else {
                    break;
                };
                if tx
                    .send((index, check_port(addr, port, timeout_ms)))
                    .is_err()
                {
                    break;
                }
            });
        }
        drop(tx);
        for (index, result) in rx {
            on_result(&result);
            if let Some(slot) = slots.get_mut(index) {
                *slot = Some(result);
            }
        }
    });
    slots.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    #[test]
    fn common_list() {
        assert_eq!(COMMON_PORTS.len(), 25);
        assert!(COMMON_PORTS.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(service_name(443), "HTTPS");
        assert_eq!(service_name(3389), "RDP");
        assert_eq!(service_name(9100), "Printing");
        assert_eq!(service_name(4), "");
    }

    #[test]
    fn parse_lists_and_ranges() {
        assert_eq!(
            parse_ports("22, 80, 443, 8000-8003").unwrap(),
            vec![22, 80, 443, 8000, 8001, 8002, 8003]
        );
        assert_eq!(parse_ports("443 80;80\n22").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("65535").unwrap(), vec![65535]);
        assert_eq!(parse_ports("7-7").unwrap(), vec![7]);
        assert_eq!(parse_ports("1-256").unwrap().len(), 256);
    }

    #[test]
    fn parse_rejects() {
        for bad in [
            "", " , ", "0", "65536", "abc", "80-", "-80", "90-80", "1-257", "1-65535", "80,x",
            "-1", "1.5", "22-80-90",
        ] {
            assert!(parse_ports(bad).is_err(), "{bad:?}");
        }
        // 257 distinct ports in pieces.
        assert!(parse_ports("1-200, 300-356").is_err());
        assert!(parse_ports("1-200, 300-355").is_ok());
    }

    fn closed_port() -> u16 {
        // Bind and release: the port is very unlikely to be reused at once.
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn open_and_closed_on_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        let closed = closed_port();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let r = check_port(lo, open, 1000);
        assert_eq!(r.state, PortState::Open);
        assert!(r.connect_ms.is_some());
        let r = check_port(lo, closed, 3000);
        assert_eq!(r.state, PortState::Closed);
        assert_eq!(r.connect_ms, None);
    }

    #[test]
    fn many_ports_in_order() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        let closed = closed_port();
        let cancel = AtomicBool::new(false);
        let mut seen = 0;
        let ports = [closed, open];
        let results = check_ports(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &ports,
            3000,
            &cancel,
            &mut |_| seen += 1,
        );
        assert_eq!(seen, 2);
        assert_eq!(
            results.iter().map(|r| r.port).collect::<Vec<_>>(),
            vec![closed, open]
        );
        assert_eq!(results[0].state, PortState::Closed);
        assert_eq!(results[1].state, PortState::Open);
    }

    #[test]
    fn cancel_and_empty() {
        let cancel = AtomicBool::new(true);
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(check_ports(lo, &[1, 2, 3], 100, &cancel, &mut |_| {}).is_empty());
        let cancel = AtomicBool::new(false);
        assert!(check_ports(lo, &[], 100, &cancel, &mut |_| {}).is_empty());
    }
}
