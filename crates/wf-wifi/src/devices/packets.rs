//! Packet builders and parsers for name discovery (pure, unit-tested).
//!
//! Every parser here reads bytes that arrived from the network: nothing
//! indexes, nothing loops without a bound, and a damaged packet gives `None`
//! or a shorter result, never a panic.

use std::net::Ipv4Addr;

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_NBSTAT: u16 = 0x21;
/// The DNS-SD name that lists every service type on the link.
pub const SERVICES_NAME: &str = "_services._dns-sd._udp.local";

fn u16_at(p: &[u8], at: usize) -> Option<u16> {
    let b = p.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
}

/// Removes control characters and surrounding white space from a name that
/// came from the network and caps its length. `None` when nothing is left.
pub fn clean_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && *c != '\u{fffd}')
        .take(64)
        .collect();
    let cleaned = cleaned.trim().trim_end_matches('.').trim();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.to_string())
    }
}

// ---------------------------------------------------------------- DNS / mDNS

/// `4.3.2.1.in-addr.arpa` for 1.2.3.4.
pub fn reverse_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// The address a reverse name stands for.
pub fn ip_from_reverse_name(name: &str) -> Option<Ipv4Addr> {
    let lower = name.trim_end_matches('.').to_ascii_lowercase();
    let head = lower.strip_suffix(".in-addr.arpa")?;
    let parts: Vec<&str> = head.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut o = [0u8; 4];
    for (slot, part) in o.iter_mut().rev().zip(&parts) {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    Some(Ipv4Addr::from(o))
}

/// A domain name in wire format. `None` when a label is empty or longer
/// than 63 bytes, or the whole name exceeds 255 bytes.
pub fn encode_name(name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None;
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    if out.len() > 255 {
        return None;
    }
    Some(out)
}

/// A DNS query. Each question is (name, type, ask for a unicast response).
/// Questions whose name cannot be encoded are left out.
pub fn build_query(id: u16, questions: &[(&str, u16, bool)]) -> Vec<u8> {
    let encoded: Vec<(Vec<u8>, u16, bool)> = questions
        .iter()
        .filter_map(|(name, qtype, unicast)| Some((encode_name(name)?, *qtype, *unicast)))
        .take(usize::from(u16::MAX))
        .collect();
    let mut out = Vec::with_capacity(12 + encoded.iter().map(|q| q.0.len() + 4).sum::<usize>());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0, 0]); // standard query
    out.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    for (name, qtype, unicast) in encoded {
        out.extend_from_slice(&name);
        out.extend_from_slice(&qtype.to_be_bytes());
        // Class IN; the top bit asks mDNS responders to answer directly.
        let class: u16 = if unicast { 0x8001 } else { 0x0001 };
        out.extend_from_slice(&class.to_be_bytes());
    }
    out
}

/// Reads a possibly compressed name starting at `pos`. Returns the name and
/// the position after it in the original run of bytes.
pub fn read_name(p: &[u8], pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut at = pos;
    let mut after: Option<usize> = None;
    let mut jumps = 0u32;
    let mut total = 0usize;
    loop {
        let len = usize::from(*p.get(at)?);
        if len == 0 {
            at += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let low = usize::from(*p.get(at + 1)?);
            if after.is_none() {
                after = Some(at + 2);
            }
            jumps += 1;
            if jumps > 32 {
                return None;
            }
            at = (len & 0x3F) << 8 | low;
            continue;
        }
        if len > 63 {
            return None;
        }
        let label = p.get(at + 1..at + 1 + len)?;
        total += len + 1;
        if total > 255 {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label));
        at += 1 + len;
    }
    Some((name, after.unwrap_or(at)))
}

/// The payload of a resource record this program cares about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Ptr(String),
    Srv { port: u16, target: String },
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub data: RData,
}

/// The records of a DNS response (answers, authority and additional
/// sections together). `None` for queries and for packets too damaged to
/// read at all; a packet cut off part-way gives the records before the cut.
pub fn parse_response(p: &[u8]) -> Option<Vec<DnsRecord>> {
    let flags = u16_at(p, 2)?;
    if flags & 0x8000 == 0 {
        return None;
    }
    let questions = usize::from(u16_at(p, 4)?);
    let records =
        usize::from(u16_at(p, 6)?) + usize::from(u16_at(p, 8)?) + usize::from(u16_at(p, 10)?);
    let mut at = 12usize;
    for _ in 0..questions {
        let (_, next) = read_name(p, at)?;
        at = next.checked_add(4)?;
        if at > p.len() {
            return None;
        }
    }
    let mut out = Vec::new();
    for _ in 0..records.min(512) {
        let Some((name, next)) = read_name(p, at) else {
            break;
        };
        let (Some(rtype), Some(rdlen)) = (u16_at(p, next), u16_at(p, next + 8)) else {
            break;
        };
        let start = next + 10;
        let end = start + usize::from(rdlen);
        let Some(rdata) = p.get(start..end) else {
            break;
        };
        let data = match rtype {
            TYPE_A => match rdata {
                &[a, b, c, d] => RData::A(Ipv4Addr::new(a, b, c, d)),
                _ => RData::Other,
            },
            TYPE_PTR => match read_name(p, start) {
                Some((target, _)) => RData::Ptr(target),
                None => RData::Other,
            },
            TYPE_SRV => match (u16_at(p, start + 4), read_name(p, start + 6)) {
                (Some(port), Some((target, _))) if rdata.len() > 6 => RData::Srv { port, target },
                _ => RData::Other,
            },
            _ => RData::Other,
        };
        out.push(DnsRecord { name, rtype, data });
        at = end;
    }
    Some(out)
}

/// `"Maple-iMac.local."` -> `"Maple-iMac"`.
pub fn host_from_mdns(name: &str) -> Option<String> {
    let trimmed = name.trim_end_matches('.');
    let lower = trimmed.to_ascii_lowercase();
    let host = if lower.ends_with(".local") {
        trimmed.get(..trimmed.len() - 6)?
    } else {
        trimmed
    };
    clean_name(host)
}

/// `"_googlecast._tcp.local"` -> `"_googlecast"`.
pub fn service_type(name: &str) -> Option<String> {
    let first = name.split('.').next()?;
    if first.len() < 2 || !first.starts_with('_') {
        return None;
    }
    clean_name(first)
}

/// A plain word for what a device probably is, from the mDNS service types
/// it announces. Unknown services give the first service type itself.
pub fn service_hint(services: &[String]) -> Option<String> {
    const KNOWN: &[(&str, &str)] = &[
        ("_ipp", "printer"),
        ("_ipps", "printer"),
        ("_printer", "printer"),
        ("_pdl-datastream", "printer"),
        ("_uscan", "scanner"),
        ("_scanner", "scanner"),
        ("_googlecast", "Google Cast device"),
        ("_androidtvremote2", "Android TV"),
        ("_airplay", "AirPlay device"),
        ("_raop", "AirPlay speaker"),
        ("_sonos", "Sonos speaker"),
        ("_spotify-connect", "Spotify Connect speaker"),
        ("_amzn-wplay", "Amazon Fire device"),
        ("_hap", "HomeKit accessory"),
        ("_homekit", "HomeKit accessory"),
        ("_matter", "Matter smart-home device"),
        ("_hue", "Philips Hue bridge"),
        ("_esphomelib", "ESPHome device"),
        ("_home-assistant", "Home Assistant"),
        ("_nvstream", "gaming PC"),
        ("_smb", "file sharing"),
        ("_afpovertcp", "file sharing"),
        ("_nfs", "file sharing"),
        ("_rfb", "remote desktop"),
        ("_ssh", "computer"),
        ("_sftp-ssh", "computer"),
        ("_workstation", "computer"),
        ("_companion-link", "Apple device"),
        ("_apple-mobdev2", "Apple mobile device"),
        ("_device-info", "computer"),
        ("_http", "web interface"),
    ];
    for (service, word) in KNOWN {
        if services.iter().any(|s| s.eq_ignore_ascii_case(service)) {
            return Some((*word).to_string());
        }
    }
    services.first().cloned()
}

// ------------------------------------------------------------------ NetBIOS

/// A NetBIOS node status request (the wildcard name `*`).
pub fn build_nbstat_query(id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(50);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    out.push(0x20);
    // "*" followed by 15 NULs, each byte as two letters ('A' + nibble).
    out.extend_from_slice(b"CK");
    out.extend_from_slice(&[b'A'; 30]);
    out.push(0);
    out.extend_from_slice(&TYPE_NBSTAT.to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    out
}

/// One entry of a NetBIOS name table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NbName {
    pub name: String,
    /// The sixteenth byte: 0x00 workstation, 0x20 file server...
    pub suffix: u8,
    pub group: bool,
}

/// The name table of a node status response.
pub fn parse_nbstat_response(p: &[u8]) -> Option<Vec<NbName>> {
    let flags = u16_at(p, 2)?;
    if flags & 0x8000 == 0 {
        return None;
    }
    let questions = usize::from(u16_at(p, 4)?);
    if u16_at(p, 6)? == 0 {
        return None;
    }
    let mut at = 12usize;
    for _ in 0..questions.min(4) {
        let (_, next) = read_name(p, at)?;
        at = next.checked_add(4)?;
    }
    let (_, next) = read_name(p, at)?;
    if u16_at(p, next)? != TYPE_NBSTAT {
        return None;
    }
    let rdlen = usize::from(u16_at(p, next + 8)?);
    let rdata = p.get(next + 10..)?;
    let rdata = rdata.get(..rdlen.min(rdata.len()))?;
    let (&count, table) = rdata.split_first()?;
    let mut out = Vec::new();
    for entry in table.as_chunks::<18>().0.iter().take(usize::from(count)) {
        let raw = entry.get(..15)?;
        let name: String = raw
            .iter()
            .map(|&b| {
                if (0x20..0x7F).contains(&b) {
                    b as char
                } else {
                    ' '
                }
            })
            .collect();
        let flags = u16::from_be_bytes([*entry.get(16)?, *entry.get(17)?]);
        out.push(NbName {
            name: name.trim().to_string(),
            suffix: *entry.get(15)?,
            group: flags & 0x8000 != 0,
        });
    }
    Some(out)
}

/// The computer name from a NetBIOS name table: the unique workstation
/// name, else the unique file-server name.
pub fn nbstat_best_name(names: &[NbName]) -> Option<String> {
    let usable = |n: &&NbName| {
        !n.group
            && !n.name.is_empty()
            && !n.name.starts_with("IS~")
            && !n.name.contains("__MSBROWSE__")
    };
    [0x00u8, 0x20]
        .iter()
        .find_map(|suffix| names.iter().filter(usable).find(|n| n.suffix == *suffix))
        .and_then(|n| clean_name(&n.name))
}

// --------------------------------------------------------------------- SSDP

/// An SSDP search request. `mx` is the number of seconds devices may wait
/// before answering.
pub fn build_msearch(search_target: &str, mx: u8) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: {}\r\nST: {}\r\n\r\n",
        mx.clamp(1, 5),
        search_target
    )
    .into_bytes()
}

/// The headers of an SSDP response or announcement this program reads.
/// The LOCATION header is deliberately not kept: it is never fetched.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SsdpInfo {
    pub server: Option<String>,
    /// `ST` of a search response, `NT` of an announcement.
    pub target: Option<String>,
    pub usn: Option<String>,
}

pub fn parse_ssdp(p: &[u8]) -> Option<SsdpInfo> {
    let text = String::from_utf8_lossy(p.get(..p.len().min(4096))?);
    let mut lines = text.lines();
    let first = lines.next()?.trim();
    let is_response =
        first.starts_with("HTTP/1.") && first.split_whitespace().nth(1) == Some("200");
    let is_notify = first.starts_with("NOTIFY ");
    if !is_response && !is_notify {
        return None;
    }
    let mut info = SsdpInfo::default();
    for line in lines.take(64) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = clean_name_long(value);
        match key.trim().to_ascii_uppercase().as_str() {
            "SERVER" => info.server = value,
            "ST" | "NT" => info.target = value,
            "USN" => info.usn = value,
            _ => {}
        }
    }
    Some(info)
}

fn clean_name_long(raw: &str) -> Option<String> {
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).take(200).collect();
    let cleaned = cleaned.trim();
    (!cleaned.is_empty()).then(|| cleaned.to_string())
}

/// A plain word for the kind of device from the search targets it answered with.
pub fn ssdp_kind(targets: &[String]) -> Option<String> {
    const KNOWN: &[(&str, &str)] = &[
        ("internetgatewaydevice", "router"),
        ("wanipconnection", "router"),
        ("wanpppconnection", "router"),
        ("wfadevice", "Wi-Fi access point"),
        ("zoneplayer", "Sonos speaker"),
        ("printer", "printer"),
        ("scanner", "scanner"),
        ("dial-multiscreen", "TV or streaming device"),
        ("mediarenderer", "media player"),
        ("mediaserver", "media server"),
        ("roku", "Roku device"),
        ("lighting", "smart light"),
        ("basic:1", "UPnP device"),
    ];
    for (needle, word) in KNOWN {
        if targets
            .iter()
            .any(|t| t.to_ascii_lowercase().contains(needle))
        {
            return Some((*word).to_string());
        }
    }
    // An unknown device type: "urn:schemas-upnp-org:device:Foo:1" -> "Foo".
    targets.iter().find_map(|t| {
        let mut parts = t.split(':');
        let kind = parts.by_ref().skip_while(|p| *p != "device").nth(1)?;
        clean_name(kind)
    })
}

/// A product name from an SSDP SERVER header ("Linux/5.4 UPnP/1.0 Maple/2.1"
/// -> "Maple"): the last product token that is neither the operating system
/// nor the UPnP library.
pub fn ssdp_name(server: &str) -> Option<String> {
    const GENERIC: &[&str] = &[
        "upnp",
        "dlnadoc",
        "linux",
        "windows",
        "microsoft-windows",
        "microsoft-windows-nt",
        "darwin",
        "freebsd",
        "unix",
        "posix",
        "os",
        "sdk",
        "devices",
        "miniupnpd",
        "libupnp",
        "portable",
        "ipos",
        "android",
        "debian",
        "ubuntu",
        "http",
        "server",
        "unspecified",
        "system",
        "mac",
        "osx",
        "macos",
        "upnp-device-host",
        "microsoft-httpapi",
        "neptune",
        "platinum",
        "cling",
        "ssdp",
        "custom",
        "embedded",
        "net-os",
        "vxworks",
        "kernel",
        "allegro-software-rompager",
        "ucos-ii",
    ];
    server
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter_map(|token| {
            let (product, version) = token.split_once('/')?;
            if version.is_empty() || product.len() < 2 {
                return None;
            }
            let lower = product.to_ascii_lowercase();
            if GENERIC.contains(&lower.as_str())
                || lower.chars().all(|c| c.is_ascii_digit() || c == '.')
            {
                return None;
            }
            clean_name(product)
        })
        .next_back()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- helpers that build fabricated packets ----

    fn record(name: &[u8], rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut out = name.to_vec();
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0, 120]);
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    fn response(answers: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![0, 0, 0x84, 0, 0, 0];
        out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        for a in answers {
            out.extend_from_slice(a);
        }
        out
    }

    fn wire(name: &str) -> Vec<u8> {
        encode_name(name).unwrap_or_default()
    }

    #[test]
    fn reverse_names() {
        let ip = Ipv4Addr::new(192, 0, 2, 17);
        assert_eq!(reverse_name(ip), "17.2.0.192.in-addr.arpa");
        assert_eq!(ip_from_reverse_name("17.2.0.192.in-addr.arpa"), Some(ip));
        assert_eq!(ip_from_reverse_name("17.2.0.192.IN-ADDR.ARPA."), Some(ip));
        for bad in [
            "",
            "in-addr.arpa",
            "2.0.192.in-addr.arpa",
            "a.2.0.192.in-addr.arpa",
            "999.2.0.192.in-addr.arpa",
            "1.17.2.0.192.in-addr.arpa",
            "17.2.0.192.ip6.arpa",
            "+1.2.0.192.in-addr.arpa",
        ] {
            assert_eq!(ip_from_reverse_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn name_encoding() {
        assert_eq!(wire("a.bc"), vec![1, b'a', 2, b'b', b'c', 0]);
        assert_eq!(wire("a.bc."), vec![1, b'a', 2, b'b', b'c', 0]);
        assert_eq!(encode_name(""), None);
        assert_eq!(encode_name("a..b"), None);
        assert_eq!(encode_name(&"x".repeat(64)), None);
        assert!(encode_name(&"x".repeat(63)).is_some());
        let long = vec!["abcdefgh"; 40].join(".");
        assert_eq!(encode_name(&long), None);
    }

    #[test]
    fn query_layout() {
        let q = build_query(
            0x1234,
            &[
                ("17.2.0.192.in-addr.arpa", TYPE_PTR, true),
                ("bad..name", TYPE_PTR, false),
                (SERVICES_NAME, TYPE_PTR, false),
            ],
        );
        assert_eq!(q.get(..2), Some(&[0x12, 0x34][..]));
        assert_eq!(u16_at(&q, 2), Some(0));
        assert_eq!(
            u16_at(&q, 4),
            Some(2),
            "the unencodable question is left out"
        );
        let (name, next) = read_name(&q, 12).unwrap_or_default();
        assert_eq!(name, "17.2.0.192.in-addr.arpa");
        assert_eq!(u16_at(&q, next), Some(TYPE_PTR));
        assert_eq!(u16_at(&q, next + 2), Some(0x8001));
        let (name, next) = read_name(&q, next + 4).unwrap_or_default();
        assert_eq!(name, SERVICES_NAME);
        assert_eq!(u16_at(&q, next + 2), Some(0x0001));
        assert_eq!(next + 4, q.len());
        // A query is not a response.
        assert_eq!(parse_response(&q), None);
    }

    #[test]
    fn ptr_and_a_records() {
        let host = wire("Maple-iMac.local");
        let packet = response(&[
            record(&wire("17.2.0.192.in-addr.arpa"), TYPE_PTR, &host),
            record(&host, TYPE_A, &[192, 0, 2, 17]),
            record(
                &wire(SERVICES_NAME),
                TYPE_PTR,
                &wire("_googlecast._tcp.local"),
            ),
            record(&wire("x.local"), TYPE_TXT, b"\x03a=b"),
        ]);
        let records = parse_response(&packet).unwrap_or_default();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].data, RData::Ptr("Maple-iMac.local".into()));
        assert_eq!(
            ip_from_reverse_name(&records[0].name),
            Some(Ipv4Addr::new(192, 0, 2, 17))
        );
        assert_eq!(records[1].data, RData::A(Ipv4Addr::new(192, 0, 2, 17)));
        assert_eq!(records[2].data, RData::Ptr("_googlecast._tcp.local".into()));
        assert_eq!(records[3].data, RData::Other);
        assert_eq!(
            host_from_mdns("Maple-iMac.local."),
            Some("Maple-iMac".into())
        );
        assert_eq!(
            host_from_mdns("Maple-iMac.LOCAL"),
            Some("Maple-iMac".into())
        );
        assert_eq!(
            host_from_mdns("printer.example"),
            Some("printer.example".into())
        );
        assert_eq!(host_from_mdns(".local"), None);
        assert_eq!(
            service_type("_googlecast._tcp.local"),
            Some("_googlecast".into())
        );
        assert_eq!(service_type("googlecast._tcp.local"), None);
    }

    #[test]
    fn compressed_names_and_srv() {
        // Answer 1 owns "tv.local" at offset 12; the SRV target points back at it.
        let mut packet = vec![0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0];
        packet.extend_from_slice(&record(&wire("tv.local"), TYPE_A, &[192, 0, 2, 40]));
        let mut srv = vec![0, 0, 0, 0, 0x1F, 0x49];
        srv.extend_from_slice(&[0xC0, 12]);
        packet.extend_from_slice(&record(&[0xC0, 12], TYPE_SRV, &srv));
        let records = parse_response(&packet).unwrap_or_default();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].name, "tv.local");
        assert_eq!(
            records[1].data,
            RData::Srv {
                port: 8009,
                target: "tv.local".into()
            }
        );
    }

    #[test]
    fn pointer_loops_end() {
        // A name that points at itself, and two names pointing at each other.
        let mut packet = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        packet.extend_from_slice(&[0xC0, 12]);
        assert_eq!(read_name(&packet, 12), None);
        assert_eq!(parse_response(&packet), Some(vec![]));
        let mut packet = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        packet.extend_from_slice(&[0xC0, 14, 0xC0, 12]);
        assert_eq!(read_name(&packet, 12), None);
        // A pointer past the end, a label past the end, a reserved label type.
        assert_eq!(read_name(&[0xC0, 0xFF], 0), None);
        assert_eq!(read_name(&[5, b'a'], 0), None);
        assert_eq!(read_name(&[0x80, 1, 2], 0), None);
        assert_eq!(read_name(&[], 0), None);
        assert_eq!(read_name(&[0], 7), None);
    }

    #[test]
    fn truncated_and_noisy_packets_never_panic() {
        let host = wire("Maple-iMac.local");
        let full = response(&[
            record(&wire("17.2.0.192.in-addr.arpa"), TYPE_PTR, &host),
            record(&host, TYPE_A, &[192, 0, 2, 17]),
        ]);
        for cut in 0..full.len() {
            let part = full.get(..cut).unwrap_or(&[]);
            if let Some(records) = parse_response(part) {
                assert!(records.len() <= 2);
            }
            let _ = parse_nbstat_response(part);
            let _ = parse_ssdp(part);
        }
        // Counts that promise far more than the packet holds.
        let liar = [
            0u8, 0, 0x84, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,
        ];
        let _ = parse_response(&liar);
        let _ = parse_nbstat_response(&liar);
        // Deterministic noise.
        let mut state = 0x9E37_79B9u32;
        let mut noise = Vec::new();
        for _ in 0..900 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            noise.push((state >> 16) as u8);
        }
        for start in 0..noise.len() {
            let mut blob = noise.get(start..).unwrap_or(&[]).to_vec();
            if let Some(b) = blob.get_mut(2) {
                *b |= 0x80; // make it look like a response so the parsers go deep
            }
            let _ = parse_response(&blob);
            let _ = parse_nbstat_response(&blob);
            let _ = parse_ssdp(&blob);
            let _ = read_name(&blob, 0);
        }
    }

    fn nb_entry(name: &str, suffix: u8, flags: u16) -> Vec<u8> {
        let mut e = format!("{name:<15}").into_bytes();
        e.truncate(15);
        e.push(suffix);
        e.extend_from_slice(&flags.to_be_bytes());
        e
    }

    fn nbstat_response(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
        out.push(0x20);
        out.extend_from_slice(b"CK");
        out.extend_from_slice(&[b'A'; 30]);
        out.push(0);
        out.extend_from_slice(&[0, 0x21, 0, 1, 0, 0, 0, 0]);
        let mut rdata = vec![entries.len() as u8];
        for e in entries {
            rdata.extend_from_slice(e);
        }
        rdata.extend_from_slice(&[0u8; 46]); // statistics
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
        out
    }

    #[test]
    fn nbstat_query_layout() {
        let q = build_nbstat_query(0xBEEF);
        assert_eq!(q.len(), 50);
        assert_eq!(q.get(..2), Some(&[0xBE, 0xEF][..]));
        assert_eq!(u16_at(&q, 4), Some(1));
        assert_eq!(q.get(12), Some(&0x20));
        assert_eq!(q.get(13..15), Some(&b"CK"[..]));
        assert_eq!(u16_at(&q, 46), Some(TYPE_NBSTAT));
        assert_eq!(u16_at(&q, 48), Some(1));
        assert_eq!(parse_nbstat_response(&q), None);
    }

    #[test]
    fn nbstat_name_table() {
        let packet = nbstat_response(&[
            nb_entry("WORKGROUP", 0x00, 0x8400),
            nb_entry("MAPLE-PC", 0x00, 0x0400),
            nb_entry("MAPLE-PC", 0x20, 0x0400),
            nb_entry("\u{1}\u{2}__MSBROWSE__\u{2}", 0x01, 0x8400),
        ]);
        let names = parse_nbstat_response(&packet).unwrap_or_default();
        assert_eq!(names.len(), 4);
        assert_eq!(
            names[0],
            NbName {
                name: "WORKGROUP".into(),
                suffix: 0,
                group: true
            }
        );
        assert_eq!(
            names[1],
            NbName {
                name: "MAPLE-PC".into(),
                suffix: 0,
                group: false
            }
        );
        assert_eq!(nbstat_best_name(&names), Some("MAPLE-PC".into()));
        // Only a file-server name.
        let packet = nbstat_response(&[
            nb_entry("WORKGROUP", 0x00, 0x8400),
            nb_entry("NAS-BOX", 0x20, 0x0400),
        ]);
        let names = parse_nbstat_response(&packet).unwrap_or_default();
        assert_eq!(nbstat_best_name(&names), Some("NAS-BOX".into()));
        // Only group names: nothing to show.
        let packet = nbstat_response(&[nb_entry("WORKGROUP", 0x00, 0x8400)]);
        assert_eq!(
            nbstat_best_name(&parse_nbstat_response(&packet).unwrap_or_default()),
            None
        );
        assert_eq!(nbstat_best_name(&[]), None);
    }

    #[test]
    fn nbstat_truncated_or_lying() {
        let full = nbstat_response(&[
            nb_entry("MAPLE-PC", 0x00, 0x0400),
            nb_entry("MAPLE-PC", 0x20, 0x0400),
        ]);
        for cut in 0..full.len() {
            let names = parse_nbstat_response(full.get(..cut).unwrap_or(&[]));
            assert!(names.map_or(0, |n| n.len()) <= 2);
        }
        // Claims 200 names but carries one.
        let mut liar = nbstat_response(&[nb_entry("MAPLE-PC", 0x00, 0x0400)]);
        if let Some(count) = liar.get_mut(56) {
            *count = 200;
        }
        assert!(parse_nbstat_response(&liar).map_or(0, |n| n.len()) <= 4);
        // Wrong record type.
        let mut other = full.clone();
        if let Some(b) = other.get_mut(47) {
            *b = 0x20;
        }
        assert_eq!(parse_nbstat_response(&other), None);
    }

    #[test]
    fn msearch_text() {
        let text = String::from_utf8(build_msearch("ssdp:all", 1)).unwrap_or_default();
        assert!(text.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(text.contains("\r\nHOST: 239.255.255.250:1900\r\n"));
        assert!(text.contains("\r\nMAN: \"ssdp:discover\"\r\n"));
        assert!(text.contains("\r\nMX: 1\r\n"));
        assert!(text.contains("\r\nST: ssdp:all\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
        assert!(String::from_utf8(build_msearch("x", 200))
            .unwrap_or_default()
            .contains("MX: 5"));
    }

    #[test]
    fn ssdp_responses() {
        let packet = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.0.2.1:5000/rootDesc.xml\r\nServer: Linux/5.4 UPnP/1.0 MapleRouter/2.1\r\nst: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:00000000-0000-0000-0000-000000000001::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
        let info = parse_ssdp(packet).unwrap_or_default();
        assert_eq!(
            info.server.as_deref(),
            Some("Linux/5.4 UPnP/1.0 MapleRouter/2.1")
        );
        assert_eq!(
            info.target.as_deref(),
            Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1")
        );
        assert!(info.usn.is_some());
        assert_eq!(
            ssdp_kind(&[info.target.unwrap_or_default()]),
            Some("router".into())
        );
        assert_eq!(
            ssdp_name(&info.server.unwrap_or_default()),
            Some("MapleRouter".into())
        );

        let notify = b"NOTIFY * HTTP/1.1\nHOST: 239.255.255.250:1900\nNT: urn:schemas-upnp-org:device:MediaRenderer:1\nSERVER: Windows/10.0 UPnP/1.0\n\n";
        let info = parse_ssdp(notify).unwrap_or_default();
        assert_eq!(
            ssdp_kind(&[info.target.unwrap_or_default()]),
            Some("media player".into())
        );
        assert_eq!(ssdp_name(&info.server.unwrap_or_default()), None);

        assert_eq!(
            parse_ssdp(b"M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n"),
            None
        );
        assert_eq!(parse_ssdp(b"HTTP/1.1 404 Not Found\r\n\r\n"), None);
        assert_eq!(parse_ssdp(b""), None);
        assert_eq!(parse_ssdp(&[0xFF, 0xFE, 0x00, 0x0A]), None);
        // Headers without a colon or with control characters are harmless.
        let odd = parse_ssdp(
            b"HTTP/1.1 200 OK\r\nnonsense\r\nSERVER:\x07 \r\nST: \x01upnp:rootdevice\r\n\r\n",
        )
        .unwrap_or_default();
        assert_eq!(odd.server, None);
        assert_eq!(odd.target.as_deref(), Some("upnp:rootdevice"));
    }

    #[test]
    fn ssdp_words() {
        let t = |s: &str| vec![s.to_string()];
        assert_eq!(
            ssdp_kind(&t("urn:dial-multiscreen-org:service:dial:1")),
            Some("TV or streaming device".into())
        );
        assert_eq!(
            ssdp_kind(&t("urn:schemas-upnp-org:device:ZonePlayer:1")),
            Some("Sonos speaker".into())
        );
        assert_eq!(
            ssdp_kind(&t("urn:schemas-example-org:device:Thermostat:1")),
            Some("Thermostat".into())
        );
        assert_eq!(ssdp_kind(&t("upnp:rootdevice")), None);
        assert_eq!(ssdp_kind(&[]), None);
        // The router wins over the generic types it also answers with.
        assert_eq!(
            ssdp_kind(&[
                "upnp:rootdevice".to_string(),
                "urn:schemas-upnp-org:device:Basic:1".to_string(),
                "urn:schemas-upnp-org:service:WANIPConnection:1".to_string()
            ]),
            Some("router".into())
        );
        assert_eq!(
            ssdp_name("Linux UPnP/1.0 Sonos/70.3-35220 (ZPS9)"),
            Some("Sonos".into())
        );
        assert_eq!(
            ssdp_name("Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0"),
            None
        );
        assert_eq!(ssdp_name(""), None);
        assert_eq!(ssdp_name("1.0/2.0 x/1"), None);
    }

    #[test]
    fn service_hints() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(service_hint(&s(&["_http", "_ipp"])), Some("printer".into()));
        assert_eq!(
            service_hint(&s(&["_GoogleCast"])),
            Some("Google Cast device".into())
        );
        assert_eq!(
            service_hint(&s(&["_maple-sync"])),
            Some("_maple-sync".into())
        );
        assert_eq!(service_hint(&[]), None);
    }

    #[test]
    fn names_are_cleaned() {
        assert_eq!(clean_name("  Maple\u{7}-PC\r\n"), Some("Maple-PC".into()));
        assert_eq!(clean_name("host.example."), Some("host.example".into()));
        assert_eq!(clean_name("\u{0}\u{1} "), None);
        assert_eq!(clean_name(&"x".repeat(500)).map(|n| n.len()), Some(64));
    }
}
