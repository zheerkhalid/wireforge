//! Traceroute built on TTL-limited echoes.

use crate::types::*;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, Debug)]
pub struct TraceOptions {
    pub max_hops: u8,
    pub probes: u32,
    pub timeout_ms: u32,
    pub resolve_names: bool,
}

impl Default for TraceOptions {
    fn default() -> Self {
        TraceOptions {
            max_hops: 30,
            probes: 3,
            timeout_ms: 1500,
            resolve_names: true,
        }
    }
}

/// Folds the probes of one hop into a `Hop` (pure, unit-tested).
pub fn summarize_hop(ttl: u8, dest: &str, probes: &[PingReply]) -> Hop {
    let sent = probes.len() as u32;
    let rtts_ms: Vec<Option<f32>> = probes
        .iter()
        .map(|p| p.rtt_ms.filter(|t| t.is_finite()))
        .collect();
    let answered: Vec<&PingReply> = probes.iter().filter(|p| p.from.is_some()).collect();
    let received = answered.len() as u32;
    let times: Vec<f32> = rtts_ms.iter().flatten().copied().collect();
    let (min_ms, avg_ms, max_ms) = if times.is_empty() {
        (None, None, None)
    } else {
        (
            Some(times.iter().copied().fold(f32::INFINITY, f32::min)),
            Some(times.iter().sum::<f32>() / times.len() as f32),
            Some(times.iter().copied().fold(f32::NEG_INFINITY, f32::max)),
        )
    };
    let same_as_dest = |from: &str| match (from.parse::<IpAddr>(), dest.parse::<IpAddr>()) {
        (Ok(a), Ok(b)) => a == b,
        _ => from == dest,
    };
    let reached = probes
        .iter()
        .any(|p| p.ok || p.from.as_deref().is_some_and(same_as_dest));
    // The destination's own answer names the hop when there is one.
    let addr = probes
        .iter()
        .find(|p| p.ok)
        .or_else(|| answered.first().copied())
        .and_then(|p| p.from.clone());
    Hop {
        ttl,
        addr,
        host: None,
        sent,
        received,
        rtts_ms,
        loss_pct: if sent == 0 {
            0.0
        } else {
            (sent - received) as f32 * 100.0 / sent as f32
        },
        min_ms,
        avg_ms,
        max_ms,
        reached,
    }
}

/// The name of a hop: a PTR query to the system DNS server first (quick and
/// bounded), then, for addresses inside the local network only, the system's
/// own lookup, which also knows names that are not in DNS.
fn hop_name(ip: IpAddr, server: Option<std::net::SocketAddr>) -> Option<String> {
    if let Some(name) = server.and_then(|s| crate::dns::reverse(ip, s, 800)) {
        return Some(name);
    }
    let local = match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    };
    if local {
        crate::ping::reverse_lookup_timeout(ip, 1200)
    } else {
        None
    }
}

/// `on_hop` is called as each hop completes. Stops at the destination,
/// at `max_hops` or when `cancel` is set.
pub fn trace(
    dest: IpAddr,
    options: TraceOptions,
    cancel: &AtomicBool,
    on_hop: &mut dyn FnMut(&Hop),
) -> Vec<Hop> {
    let max_hops = options.max_hops.max(1);
    let probes = options.probes.clamp(1, 10);
    let timeout_ms = options.timeout_ms.clamp(100, 10_000);
    let dest_text = dest.to_string();
    let mut hops = Vec::new();
    let mut seq = 0u32;
    let name_server = if options.resolve_names {
        crate::dns::default_server()
    } else {
        None
    };
    'hops: for ttl in 1..=max_hops {
        let mut replies = Vec::with_capacity(probes as usize);
        for _ in 0..probes {
            if cancel.load(Ordering::Relaxed) {
                break 'hops;
            }
            seq = seq.wrapping_add(1);
            replies.push(crate::ping::ping_once(dest, seq, timeout_ms, ttl, 32));
        }
        let mut hop = summarize_hop(ttl, &dest_text, &replies);
        if options.resolve_names && !cancel.load(Ordering::Relaxed) {
            if let Some(ip) = hop.addr.as_deref().and_then(|a| a.parse::<IpAddr>().ok()) {
                hop.host = hop_name(ip, name_server);
            }
        }
        on_hop(&hop);
        let reached = hop.reached;
        hops.push(hop);
        if reached {
            break;
        }
    }
    hops
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(from: Option<&str>, ms: Option<f32>, ok: bool) -> PingReply {
        PingReply {
            seq: 1,
            from: from.map(str::to_string),
            rtt_ms: ms,
            ttl: None,
            status: if ok { "Reply" } else { "TTL expired" }.into(),
            ok,
        }
    }

    #[test]
    fn router_hop() {
        let h = summarize_hop(
            3,
            "198.51.100.9",
            &[
                probe(Some("192.0.2.1"), Some(4.0), false),
                probe(None, None, false),
                probe(Some("192.0.2.1"), Some(8.0), false),
            ],
        );
        assert_eq!(h.ttl, 3);
        assert_eq!(h.addr.as_deref(), Some("192.0.2.1"));
        assert_eq!((h.sent, h.received), (3, 2));
        assert_eq!(h.rtts_ms, vec![Some(4.0), None, Some(8.0)]);
        assert!((h.loss_pct - 33.333).abs() < 0.01);
        assert_eq!(
            (h.min_ms, h.avg_ms, h.max_ms),
            (Some(4.0), Some(6.0), Some(8.0))
        );
        assert!(!h.reached);
        assert_eq!(h.host, None);
    }

    #[test]
    fn silent_hop() {
        let h = summarize_hop(5, "198.51.100.9", &vec![probe(None, None, false); 3]);
        assert_eq!(h.addr, None);
        assert_eq!((h.sent, h.received, h.loss_pct), (3, 0, 100.0));
        assert_eq!((h.min_ms, h.avg_ms, h.max_ms), (None, None, None));
        assert!(!h.reached);
    }

    #[test]
    fn destination_hop() {
        let h = summarize_hop(
            9,
            "198.51.100.9",
            &[
                probe(Some("192.0.2.77"), Some(20.0), false),
                probe(Some("198.51.100.9"), Some(21.0), true),
            ],
        );
        assert!(h.reached);
        assert_eq!(h.addr.as_deref(), Some("198.51.100.9"));
        assert_eq!(h.loss_pct, 0.0);
    }

    #[test]
    fn destination_recognised_by_address_even_when_unreachable() {
        // The target itself answering with an error still ends the trace.
        let h = summarize_hop(
            4,
            "2001:db8::9",
            &[probe(Some("2001:db8:0:0::9"), Some(2.0), false)],
        );
        assert!(h.reached);
    }

    #[test]
    fn empty_probe_list() {
        let h = summarize_hop(1, "192.0.2.1", &[]);
        assert_eq!((h.sent, h.received, h.loss_pct), (0, 0, 0.0));
        assert!(h.rtts_ms.is_empty());
    }

    #[test]
    fn loopback_trace_is_one_hop() {
        let cancel = AtomicBool::new(false);
        let mut seen = 0;
        let hops = trace(
            "127.0.0.1".parse().unwrap(),
            TraceOptions {
                resolve_names: false,
                probes: 2,
                ..Default::default()
            },
            &cancel,
            &mut |_| seen += 1,
        );
        assert_eq!(hops.len(), 1);
        assert_eq!(seen, 1);
        assert!(hops.first().is_some_and(|h| h.reached));
    }

    #[test]
    fn cancel_stops_before_the_first_probe() {
        let cancel = AtomicBool::new(true);
        let hops = trace(
            "127.0.0.1".parse().unwrap(),
            TraceOptions::default(),
            &cancel,
            &mut |_| {},
        );
        assert!(hops.is_empty());
    }
}
