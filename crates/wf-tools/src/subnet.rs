//! Subnet calculator (pure, unit-tested).

use crate::types::*;
use std::net::Ipv4Addr;

/// Shown as the broadcast address of a /31, which has none (RFC 3021).
pub const NO_BROADCAST: &str = "None (RFC 3021)";

fn mask_of(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => u32::MAX << (32 - u32::from(p)),
    }
}

fn parse_addr(text: &str) -> Result<Ipv4Addr, String> {
    let text = text.trim();
    if text.contains(':') {
        return Err("Only IPv4 addresses are supported here.".into());
    }
    text.parse::<Ipv4Addr>()
        .map_err(|_| format!("\"{text}\" is not an IPv4 address (for example 192.168.1.10)."))
}

/// A prefix length written as a number (`24`) or as a mask (`255.255.255.0`).
fn parse_prefix(text: &str) -> Result<u8, String> {
    let text = text.trim().trim_start_matches('/');
    if let Ok(n) = text.parse::<u8>() {
        return if n <= 32 {
            Ok(n)
        } else {
            Err("The prefix length must be between 0 and 32.".into())
        };
    }
    let mask: u32 = text
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("\"{text}\" is not a prefix length or a subnet mask."))?
        .into();
    // A mask is ones followed by zeros.
    if mask.leading_ones() + mask.trailing_zeros() != 32 {
        return Err(format!(
            "\"{text}\" is not a valid subnet mask (the ones must come first)."
        ));
    }
    Ok(mask.leading_ones() as u8)
}

fn class_of(first: u8) -> &'static str {
    match first {
        0..=127 => "A",
        128..=191 => "B",
        192..=223 => "C",
        224..=239 => "D",
        _ => "E",
    }
}

fn classful_prefix(first: u8) -> u8 {
    match class_of(first) {
        "A" => 8,
        "B" => 16,
        "C" => 24,
        // Multicast and reserved space has no network part.
        _ => 32,
    }
}

/// What kind of address this is, in words.
pub fn scope_of(addr: Ipv4Addr) -> &'static str {
    let [a, b, c, _] = addr.octets();
    match (a, b, c) {
        _ if addr.is_broadcast() => "Limited broadcast",
        (0, ..) => "This network",
        (10, ..) | (192, 168, _) => "Private (RFC 1918)",
        (172, 16..=31, _) => "Private (RFC 1918)",
        (100, 64..=127, _) => "CGNAT (RFC 6598)",
        (127, ..) => "Loopback",
        (169, 254, _) => "Link-local",
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113) => "Documentation (RFC 5737)",
        (198, 18..=19, _) => "Benchmarking (RFC 2544)",
        (224..=239, ..) => "Multicast",
        (240..=255, ..) => "Reserved",
        _ => "Public",
    }
}

fn bits(value: u32) -> String {
    let [a, b, c, d] = value.to_be_bytes();
    format!("{a:08b}.{b:08b}.{c:08b}.{d:08b}")
}

/// Accepts `192.168.1.10/24`, `192.168.1.10 255.255.255.0` and a bare
/// address (classful default prefix).
pub fn calculate(text: &str) -> Result<SubnetInfo, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("Enter an address, for example 192.168.1.10/24.".into());
    }
    let (addr, prefix) = if let Some((addr, prefix)) = text.split_once('/') {
        (parse_addr(addr)?, parse_prefix(prefix)?)
    } else {
        let mut parts = text.split_whitespace();
        let addr = parse_addr(parts.next().unwrap_or(""))?;
        let prefix = match parts.next() {
            Some(mask) => parse_prefix(mask)?,
            None => classful_prefix(*addr.octets().first().unwrap_or(&0)),
        };
        if parts.next().is_some() {
            return Err("Enter one address and one mask.".into());
        }
        (addr, prefix)
    };
    let address = u32::from(addr);
    let mask = mask_of(prefix);
    let network = address & mask;
    let last = network | !mask;
    let total = 1u64 << (32 - u32::from(prefix));
    let (first_host, last_host, hosts, broadcast) = match prefix {
        // A single host.
        32 => (network, last, 1, Ipv4Addr::from(last).to_string()),
        // Point-to-point link: both addresses are hosts (RFC 3021).
        31 => (network, last, 2, NO_BROADCAST.to_string()),
        _ => (
            network + 1,
            last - 1,
            total - 2,
            Ipv4Addr::from(last).to_string(),
        ),
    };
    Ok(SubnetInfo {
        address: addr.to_string(),
        prefix,
        mask: Ipv4Addr::from(mask).to_string(),
        wildcard: Ipv4Addr::from(!mask).to_string(),
        network: Ipv4Addr::from(network).to_string(),
        broadcast,
        first_host: Ipv4Addr::from(first_host).to_string(),
        last_host: Ipv4Addr::from(last_host).to_string(),
        hosts,
        total,
        scope: scope_of(addr).to_string(),
        class: class_of(*addr.octets().first().unwrap_or(&0)).to_string(),
        address_bits: bits(address),
        mask_bits: bits(mask),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_24() {
        let s = calculate("192.168.1.10/24").unwrap();
        assert_eq!(s.address, "192.168.1.10");
        assert_eq!(s.prefix, 24);
        assert_eq!(s.mask, "255.255.255.0");
        assert_eq!(s.wildcard, "0.0.0.255");
        assert_eq!(s.network, "192.168.1.0");
        assert_eq!(s.broadcast, "192.168.1.255");
        assert_eq!(s.first_host, "192.168.1.1");
        assert_eq!(s.last_host, "192.168.1.254");
        assert_eq!((s.hosts, s.total), (254, 256));
        assert_eq!(s.scope, "Private (RFC 1918)");
        assert_eq!(s.class, "C");
        assert_eq!(s.address_bits, "11000000.10101000.00000001.00001010");
        assert_eq!(s.mask_bits, "11111111.11111111.11111111.00000000");
    }

    #[test]
    fn mask_forms_agree() {
        let a = calculate("10.20.30.40/20").unwrap();
        assert_eq!(calculate("10.20.30.40 255.255.240.0").unwrap(), a);
        assert_eq!(calculate("10.20.30.40/255.255.240.0").unwrap(), a);
        assert_eq!(calculate("  10.20.30.40   /20 ").unwrap(), a);
        assert_eq!(calculate("10.20.30.40 /20").unwrap(), a);
        assert_eq!(a.network, "10.20.16.0");
        assert_eq!(a.broadcast, "10.20.31.255");
        assert_eq!((a.hosts, a.total), (4094, 4096));
    }

    #[test]
    fn classful_defaults() {
        assert_eq!(calculate("10.1.2.3").unwrap().prefix, 8);
        assert_eq!(calculate("172.20.1.1").unwrap().prefix, 16);
        assert_eq!(calculate("192.0.2.9").unwrap().prefix, 24);
        assert_eq!(calculate("224.0.0.5").unwrap().prefix, 32);
        assert_eq!(calculate("10.1.2.3").unwrap().class, "A");
        assert_eq!(calculate("172.20.1.1").unwrap().class, "B");
        assert_eq!(calculate("224.0.0.5").unwrap().class, "D");
        assert_eq!(calculate("250.0.0.5").unwrap().class, "E");
    }

    #[test]
    fn slash_31_and_32() {
        let s = calculate("192.0.2.4/31").unwrap();
        assert_eq!((s.hosts, s.total), (2, 2));
        assert_eq!(s.network, "192.0.2.4");
        assert_eq!(
            (s.first_host.as_str(), s.last_host.as_str()),
            ("192.0.2.4", "192.0.2.5")
        );
        assert_eq!(s.broadcast, NO_BROADCAST);
        assert_eq!(s.mask, "255.255.255.254");

        let s = calculate("192.0.2.7/32").unwrap();
        assert_eq!((s.hosts, s.total), (1, 1));
        assert_eq!(s.network, "192.0.2.7");
        assert_eq!(s.broadcast, "192.0.2.7");
        assert_eq!(
            (s.first_host.as_str(), s.last_host.as_str()),
            ("192.0.2.7", "192.0.2.7")
        );
        assert_eq!(s.wildcard, "0.0.0.0");
    }

    #[test]
    fn extremes() {
        let s = calculate("198.51.100.1/0").unwrap();
        assert_eq!(s.mask, "0.0.0.0");
        assert_eq!(s.network, "0.0.0.0");
        assert_eq!(s.broadcast, "255.255.255.255");
        assert_eq!(s.total, 1 << 32);
        assert_eq!(s.hosts, (1u64 << 32) - 2);
        let s = calculate("198.51.100.1/30").unwrap();
        assert_eq!((s.hosts, s.total), (2, 4));
        assert_eq!(
            (s.first_host.as_str(), s.last_host.as_str()),
            ("198.51.100.1", "198.51.100.2")
        );
    }

    #[test]
    fn scopes() {
        for (addr, scope) in [
            ("10.0.0.1", "Private (RFC 1918)"),
            ("172.16.0.1", "Private (RFC 1918)"),
            ("172.31.255.1", "Private (RFC 1918)"),
            ("172.32.0.1", "Public"),
            ("192.168.0.1", "Private (RFC 1918)"),
            ("127.0.0.1", "Loopback"),
            ("169.254.10.1", "Link-local"),
            ("100.64.0.1", "CGNAT (RFC 6598)"),
            ("100.127.255.1", "CGNAT (RFC 6598)"),
            ("100.128.0.1", "Public"),
            ("192.0.2.1", "Documentation (RFC 5737)"),
            ("198.51.100.1", "Documentation (RFC 5737)"),
            ("203.0.113.1", "Documentation (RFC 5737)"),
            ("198.18.0.1", "Benchmarking (RFC 2544)"),
            ("224.0.0.1", "Multicast"),
            ("240.0.0.1", "Reserved"),
            ("255.255.255.255", "Limited broadcast"),
            ("0.0.0.0", "This network"),
            ("1.1.1.1", "Public"),
        ] {
            assert_eq!(
                calculate(&format!("{addr}/32")).unwrap().scope,
                scope,
                "{addr}"
            );
        }
    }

    #[test]
    fn rejects() {
        for bad in [
            "",
            "hello",
            "192.168.1",
            "192.168.1.256/24",
            "192.168.1.1/33",
            "192.168.1.1/-1",
            "192.168.1.1/",
            "192.168.1.1 255.0.255.0",
            "192.168.1.1 255.255.255.0 extra",
            "192.168.1.1/24/8",
            "2001:db8::1/64",
        ] {
            assert!(calculate(bad).is_err(), "{bad:?}");
        }
    }
}
