//! Wake-on-LAN.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

/// Parses a MAC address written with `:`, `-`, `.` or no separators.
pub fn parse_mac(mac: &str) -> Result<[u8; 6], String> {
    let bad =
        || "A MAC address has 12 hexadecimal digits, for example 00:11:22:33:44:55.".to_string();
    let mac = mac.trim();
    let mut digits = Vec::with_capacity(12);
    for c in mac.chars() {
        match c {
            ':' | '-' | '.' => {}
            _ => digits.push(c.to_digit(16).ok_or_else(bad)? as u8),
        }
    }
    if digits.len() != 12 {
        return Err(bad());
    }
    // With separators the groups must be regular: six pairs or three fours.
    let groups: Vec<usize> = mac.split([':', '-', '.']).map(str::len).collect();
    let regular = groups.len() == 1
        || (groups.len() == 6 && groups.iter().all(|g| *g == 2))
        || (groups.len() == 3 && groups.iter().all(|g| *g == 4));
    if !regular {
        return Err(bad());
    }
    let mut out = [0u8; 6];
    for (byte, [high, low]) in out.iter_mut().zip(digits.as_chunks::<2>().0) {
        *byte = (high << 4) | low;
    }
    Ok(out)
}

/// 6 x 0xFF followed by the MAC 16 times (pure, unit-tested).
pub fn magic_packet(mac: &str) -> Result<Vec<u8>, String> {
    let mac = parse_mac(mac)?;
    let mut packet = Vec::with_capacity(102);
    packet.extend_from_slice(&[0xff; 6]);
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }
    Ok(packet)
}

/// Whether a wake packet may be sent to this address: the limited broadcast
/// address or something inside a private or link-local network.
pub fn allowed_target(addr: Ipv4Addr) -> bool {
    addr.is_broadcast() || addr.is_private() || addr.is_link_local()
}

/// Sends the packet to `broadcast` (for example 192.168.1.255) on UDP port 9.
pub fn send(mac: &str, broadcast: Ipv4Addr) -> Result<(), String> {
    let packet = magic_packet(mac)?;
    if !allowed_target(broadcast) {
        return Err(
            "Wake-on-LAN packets are only sent inside your own network (a private or \
             link-local broadcast address, or 255.255.255.255)."
                .into(),
        );
    }
    let io = |e: std::io::Error| format!("Could not send the wake packet ({e}).");
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(io)?;
    socket.set_broadcast(true).map_err(io)?;
    let sent = socket
        .send_to(&packet, SocketAddrV4::new(broadcast, 9))
        .map_err(io)?;
    if sent != packet.len() {
        return Err("Could not send the whole wake packet.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_shape() {
        let p = magic_packet("00:11:22:aa:BB:cc").unwrap();
        assert_eq!(p.len(), 102);
        assert_eq!(&p[..6], &[0xff; 6]);
        for chunk in p[6..].chunks(6) {
            assert_eq!(chunk, &[0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc]);
        }
    }

    #[test]
    fn separators() {
        let want = [0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc];
        for text in [
            "00:11:22:AA:BB:CC",
            "00-11-22-aa-bb-cc",
            "001122aabbcc",
            "0011.22aa.bbcc",
            "  00:11:22:aa:bb:cc  ",
        ] {
            assert_eq!(parse_mac(text).unwrap(), want, "{text}");
        }
    }

    #[test]
    fn rejects() {
        for bad in [
            "",
            "00:11:22:aa:bb",
            "00:11:22:aa:bb:cc:dd",
            "00:11:22:aa:bb:cg",
            "0:011:22:aa:bb:cc",
            "001122aabbc",
            "00 11 22 aa bb cc",
            "00:11:22:aa:bb:cc:",
        ] {
            assert!(magic_packet(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn targets() {
        for ok in [
            "255.255.255.255",
            "192.168.1.255",
            "10.255.255.255",
            "172.16.3.255",
            "169.254.255.255",
        ] {
            assert!(allowed_target(ok.parse().unwrap()), "{ok}");
        }
        for no in [
            "192.0.2.255",
            "198.51.100.1",
            "172.32.0.255",
            "127.0.0.1",
            "0.0.0.0",
        ] {
            assert!(!allowed_target(no.parse().unwrap()), "{no}");
            assert!(send("00:11:22:aa:bb:cc", no.parse().unwrap()).is_err());
        }
        // A bad MAC is refused before anything is sent.
        assert!(send("nope", "192.168.1.255".parse().unwrap()).is_err());
    }
}
