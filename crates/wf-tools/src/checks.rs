//! A quick self-test of the tools that are safe to run anywhere: nothing here
//! contacts the internet or changes the system, and the summaries carry
//! counts only (never addresses or names from this PC).

use crate::types::*;
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::atomic::AtomicBool;

type Check = Result<String, String>;
type Named = (&'static str, fn() -> Check);

fn ping_loopback() -> Check {
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let replies: Vec<PingReply> = (1..=3)
        .map(|seq| crate::ping::ping_once(lo, seq, 1000, 64, 32))
        .collect();
    let stats = crate::ping::stats(&replies);
    if stats.received == 0 {
        let status = replies
            .first()
            .map(|r| r.status.clone())
            .unwrap_or_default();
        return Err(format!("no reply from loopback ({status})"));
    }
    Ok(format!(
        "{}/{} replies, avg {:.2} ms",
        stats.received, stats.sent, stats.avg_ms
    ))
}

fn resolve_localhost() -> Check {
    let addrs = crate::ping::resolve("localhost")?;
    if !addrs.iter().all(IpAddr::is_loopback) {
        return Err("localhost resolved to a non-loopback address".into());
    }
    let v4 = addrs.iter().filter(|a| a.is_ipv4()).count();
    Ok(format!("{} IPv4, {} IPv6", v4, addrs.len() - v4))
}

fn dns_round_trip() -> Check {
    let query = crate::dns::build_query("example.org", "MX", 0x4242)?;
    // Turn the query into an answer: response bit, one record whose owner
    // points back at the question name.
    let mut packet = query.clone();
    match packet.get_mut(2) {
        Some(flags) => *flags |= 0x80,
        None => return Err("query too short".into()),
    }
    match packet.get_mut(7) {
        Some(count) => *count = 1,
        None => return Err("query too short".into()),
    }
    packet.extend_from_slice(&[0xc0, 12, 0, 15, 0, 1, 0, 0, 0, 60, 0, 9]);
    packet.extend_from_slice(&[0, 10, 4, b'm', b'a', b'i', b'l', 0xc0, 12]);
    let message = crate::dns::parse_message(&packet)?;
    let question_ok =
        message.id == 0x4242 && message.question == Some(("example.org".to_string(), 15));
    let data_ok = message
        .answer
        .answers
        .first()
        .is_some_and(|r| r.rtype == "MX" && r.data == "10 mail.example.org" && r.ttl == 60);
    if !question_ok || !data_ok {
        return Err("the parsed packet does not match what was built".into());
    }
    if crate::dns::parse_response(&query).is_ok() {
        return Err("a query was accepted as a response".into());
    }
    Ok(format!(
        "{} byte query, {} byte answer, {} record",
        query.len(),
        packet.len(),
        message.answer.answers.len()
    ))
}

fn dns_servers() -> Check {
    let servers = crate::dns::system_servers();
    if servers.iter().any(|s| s.trim().is_empty()) {
        return Err("an empty server entry".into());
    }
    Ok(format!("{} configured", servers.len()))
}

fn port_check() -> Check {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| format!("listen: {e}"))?;
    let open = listener
        .local_addr()
        .map_err(|e| format!("listen: {e}"))?
        .port();
    // Bind and release a second port to get one that nothing listens on.
    let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|l| l.local_addr())
        .map_err(|e| format!("listen: {e}"))?
        .port();
    let cancel = AtomicBool::new(false);
    let mut calls = 0;
    let results = crate::ports::check_ports(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        &[open, closed],
        3000,
        &cancel,
        &mut |_| calls += 1,
    );
    let states: Vec<PortState> = results.iter().map(|r| r.state).collect();
    if states != [PortState::Open, PortState::Closed] || calls != 2 {
        return Err(format!(
            "expected Open and Closed, got {}",
            states
                .iter()
                .map(|s| s.label())
                .collect::<Vec<_>>()
                .join(" and ")
        ));
    }
    let parsed = crate::ports::parse_ports("22, 80, 443, 8000-8010")?;
    Ok(format!(
        "1 open, 1 closed; list of {} parsed; {} common ports",
        parsed.len(),
        crate::ports::COMMON_PORTS.len()
    ))
}

fn wol_packet() -> Check {
    let packet = crate::wol::magic_packet("00-11-22-33-44-55")?;
    let header_ok = packet.get(..6) == Some(&[0xff; 6][..]);
    let body_ok = packet.get(6..).is_some_and(|b| {
        b.chunks(6)
            .all(|c| c == [0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    });
    if packet.len() != 102 || !header_ok || !body_ok {
        return Err("wrong packet shape".into());
    }
    if crate::wol::magic_packet("not a mac").is_ok() {
        return Err("a bad MAC address was accepted".into());
    }
    if crate::wol::allowed_target(Ipv4Addr::new(198, 51, 100, 255)) {
        return Err("a public target was allowed".into());
    }
    Ok(format!("{} bytes, 16 repeats", packet.len()))
}

fn subnet_maths() -> Check {
    let s = crate::subnet::calculate("192.168.1.10/24")?;
    if s.network != "192.168.1.0" || s.broadcast != "192.168.1.255" || s.hosts != 254 {
        return Err("wrong /24 result".into());
    }
    let p2p = crate::subnet::calculate("192.0.2.4/31")?;
    let host = crate::subnet::calculate("192.0.2.4/32")?;
    if p2p.hosts != 2 || host.hosts != 1 {
        return Err("wrong /31 or /32 result".into());
    }
    Ok(format!(
        "/24 = {} hosts, /31 = {}, /32 = {}",
        s.hosts, p2p.hosts, host.hosts
    ))
}

/// Builds the flush / renew commands and checks them. Nothing is run.
fn system_commands() -> Check {
    let flush = crate::sysactions::flush_dns();
    let renew = crate::sysactions::renew_lease(Some("Example Adapter"));
    let all = crate::sysactions::renew_lease(None);
    let is_ipconfig = |c: &SystemCommand| {
        c.program
            .to_ascii_lowercase()
            .ends_with("\\system32\\ipconfig.exe")
    };
    let shape_ok = flush.args == ["/flushdns"]
        && renew.len() == 2
        && all.len() == 2
        && renew
            .first()
            .is_some_and(|c| c.args == ["/release", "Example Adapter"])
        && renew
            .get(1)
            .is_some_and(|c| c.args == ["/renew", "Example Adapter"])
        && all.first().is_some_and(|c| c.args == ["/release"])
        && all.get(1).is_some_and(|c| c.args == ["/renew"]);
    if !shape_ok || !is_ipconfig(&flush) || !renew.iter().chain(&all).all(is_ipconfig) {
        return Err("a command was built wrongly".into());
    }
    Ok(format!(
        "{} commands built, none run",
        1 + renew.len() + all.len()
    ))
}

/// Runs the safe checks once: `(name, Ok(summary) or Err(reason))`.
/// Loopback only; no internet, no change to the system.
pub fn selftest() -> Vec<(String, Result<String, String>)> {
    let checks: [Named; 8] = [
        ("Ping 127.0.0.1", ping_loopback),
        ("Resolve localhost", resolve_localhost),
        ("DNS packet round trip", dns_round_trip),
        ("System DNS servers", dns_servers),
        ("Port check on loopback", port_check),
        ("Wake-on-LAN packet", wol_packet),
        ("Subnet maths", subnet_maths),
        ("Flush / renew commands (not run)", system_commands),
    ];
    checks
        .into_iter()
        .map(|(name, check)| (name.to_string(), check()))
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn selftest_passes() {
        let results = super::selftest();
        assert_eq!(results.len(), 8);
        for (name, result) in results {
            assert!(result.is_ok(), "{name}: {result:?}");
        }
    }
}
