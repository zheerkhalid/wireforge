//! DNS lookups with a chosen record type and server.
//!
//! The client is written here on plain UDP / TCP sockets so the server the
//! user picked is really the one that is asked.

use crate::types::*;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

/// Record types offered in the UI.
pub const RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CAA",
];

/// Well-known public resolvers offered next to "System default": `(label, address)`.
pub const PUBLIC_SERVERS: &[(&str, &str)] = &[
    ("Cloudflare", "1.1.1.1"),
    ("Google", "8.8.8.8"),
    ("Quad9", "9.9.9.9"),
];

/// How long one attempt waits for an answer.
pub const TIMEOUT_MS: u32 = 2500;

const TYPES: &[(&str, u16)] = &[
    ("A", 1),
    ("NS", 2),
    ("CNAME", 5),
    ("SOA", 6),
    ("PTR", 12),
    ("MX", 15),
    ("TXT", 16),
    ("AAAA", 28),
    ("SRV", 33),
    ("CAA", 257),
];

/// The number of a record type name ("MX" -> 15, "TYPE65" -> 65).
pub fn type_code(rtype: &str) -> Option<u16> {
    let upper = rtype.trim().to_ascii_uppercase();
    if let Some((_, code)) = TYPES.iter().find(|(name, _)| *name == upper) {
        return Some(*code);
    }
    upper.strip_prefix("TYPE")?.parse::<u16>().ok()
}

/// The name of a record type number (15 -> "MX", 65 -> "TYPE65").
pub fn type_name(code: u16) -> String {
    match TYPES.iter().find(|(_, c)| *c == code) {
        Some((name, _)) => (*name).to_string(),
        None => format!("TYPE{code}"),
    }
}

/// The name of a response code (3 -> "NXDOMAIN").
pub fn rcode_name(code: u8) -> String {
    match code {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        6 => "YXDOMAIN".into(),
        7 => "YXRRSET".into(),
        8 => "NXRRSET".into(),
        9 => "NOTAUTH".into(),
        10 => "NOTZONE".into(),
        other => format!("RCODE{other}"),
    }
}

/// The reverse-lookup name of an address (pure, unit-tested).
pub fn reverse_name(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let mut out = String::with_capacity(72);
            for byte in v6.octets().iter().rev() {
                out.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
            }
            out.push_str("ip6.arpa");
            out
        }
    }
}

/// The name that is really asked for (PTR turns addresses into arpa names).
fn query_name(name: &str, code: u16) -> String {
    let name = name.trim();
    if code == 12 {
        let literal = name
            .strip_prefix('[')
            .and_then(|n| n.strip_suffix(']'))
            .unwrap_or(name);
        if let Ok(ip) = literal.parse::<IpAddr>() {
            return reverse_name(ip);
        }
    }
    name.to_string()
}

fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        out.push(0);
        return Ok(());
    }
    if name.len() > 253 {
        return Err("The name is too long (253 characters at most).".into());
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err("The name has an empty part (two dots in a row).".into());
        }
        if !label.is_ascii() {
            return Err(
                "Names with non-English letters must be entered in their xn-- (punycode) form."
                    .into(),
            );
        }
        if label.len() > 63 {
            return Err("One part of the name is longer than 63 characters.".into());
        }
        if label
            .bytes()
            .any(|b| b <= b' ' || b == 0x7f || b == b'\\' || b == b'"')
        {
            return Err("The name has a character that is not allowed.".into());
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// A DNS query packet (pure, unit-tested). For "PTR" an IP address is
/// turned into its in-addr.arpa / ip6.arpa name.
pub fn build_query(name: &str, rtype: &str, id: u16) -> Result<Vec<u8>, String> {
    let code = type_code(rtype).ok_or_else(|| format!("Unknown record type \"{rtype}\"."))?;
    let name = query_name(name, code);
    if name.is_empty() {
        return Err("Enter a name to look up.".into());
    }
    let mut out = Vec::with_capacity(name.len() + 18);
    out.extend_from_slice(&id.to_be_bytes());
    // Standard query, recursion desired.
    out.extend_from_slice(&[0x01, 0x00]);
    // One question, no other records.
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    encode_name(&name, &mut out)?;
    out.extend_from_slice(&code.to_be_bytes());
    // Class IN.
    out.extend_from_slice(&[0, 1]);
    Ok(out)
}

/// A bounds-checked reader over a packet.
struct Reader<'a> {
    packet: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or("packet too short")?;
        let slice = self.packet.get(self.pos..end).ok_or("packet too short")?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.bytes(1)?.first().copied().unwrap_or(0))
    }

    fn u16(&mut self) -> Result<u16, String> {
        match self.bytes(2)? {
            [a, b] => Ok(u16::from_be_bytes([*a, *b])),
            _ => Err("packet too short".into()),
        }
    }

    fn u32(&mut self) -> Result<u32, String> {
        match self.bytes(4)? {
            [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => Err("packet too short".into()),
        }
    }

    /// Reads a possibly compressed name. Pointers may only point backwards,
    /// so a loop is impossible; the hop and length limits are a second guard.
    fn name(&mut self) -> Result<String, String> {
        let mut out = String::new();
        let mut cursor = self.pos;
        let mut resume: Option<usize> = None;
        let mut jumps = 0;
        let mut wire_len = 0usize;
        loop {
            let len = *self.packet.get(cursor).ok_or("name runs past the packet")?;
            match len & 0xc0 {
                0x00 => {
                    cursor += 1;
                    if len == 0 {
                        break;
                    }
                    let end = cursor + usize::from(len);
                    let label = self
                        .packet
                        .get(cursor..end)
                        .ok_or("name runs past the packet")?;
                    wire_len += 1 + label.len();
                    if wire_len > 254 {
                        return Err("name is too long".into());
                    }
                    if !out.is_empty() {
                        out.push('.');
                    }
                    escape_into(label, true, &mut out);
                    cursor = end;
                }
                0xc0 => {
                    let low = *self
                        .packet
                        .get(cursor + 1)
                        .ok_or("name runs past the packet")?;
                    let target = (usize::from(len & 0x3f) << 8) | usize::from(low);
                    if target >= cursor {
                        return Err("name compression loop".into());
                    }
                    jumps += 1;
                    if jumps > 64 {
                        return Err("name compression loop".into());
                    }
                    if resume.is_none() {
                        resume = Some(cursor + 2);
                    }
                    cursor = target;
                }
                _ => return Err("unsupported name label".into()),
            }
        }
        self.pos = resume.unwrap_or(cursor);
        if out.is_empty() {
            out.push('.');
        }
        Ok(out)
    }
}

/// Writes bytes as presentation text: printable ASCII as is, the rest as
/// `\DDD`; backslash, quote (and the dot inside a label) get a backslash.
fn escape_into(bytes: &[u8], in_label: bool, out: &mut String) {
    for &b in bytes {
        match b {
            b'\\' | b'"' => {
                out.push('\\');
                out.push(b as char);
            }
            b'.' if in_label => out.push_str("\\."),
            0x20..=0x7e if !(in_label && b == b' ') => out.push(b as char),
            _ => out.push_str(&format!("\\{b:03}")),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Renders record data. `start..end` is the data inside `packet` (names in it
/// may point elsewhere in the packet).
fn render(packet: &[u8], code: u16, start: usize, end: usize) -> Result<String, String> {
    let data = packet
        .get(start..end)
        .ok_or("record runs past the packet")?;
    let mut r = Reader {
        packet: packet.get(..end).unwrap_or(packet),
        pos: start,
    };
    let text = match code {
        1 => {
            let octets: [u8; 4] = data.try_into().map_err(|_| "bad A record")?;
            Ipv4Addr::from(octets).to_string()
        }
        28 => {
            let octets: [u8; 16] = data.try_into().map_err(|_| "bad AAAA record")?;
            Ipv6Addr::from(octets).to_string()
        }
        2 | 5 | 12 => r.name()?,
        15 => {
            let preference = r.u16()?;
            format!("{preference} {}", r.name()?)
        }
        16 => {
            let mut parts = Vec::new();
            while r.pos < end {
                let len = usize::from(r.u8()?);
                let mut part = String::from("\"");
                escape_into(r.bytes(len)?, false, &mut part);
                part.push('"');
                parts.push(part);
            }
            parts.join(" ")
        }
        6 => {
            let mname = r.name()?;
            let rname = r.name()?;
            let serial = r.u32()?;
            let refresh = r.u32()?;
            let retry = r.u32()?;
            let expire = r.u32()?;
            let minimum = r.u32()?;
            format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}")
        }
        33 => {
            let priority = r.u16()?;
            let weight = r.u16()?;
            let port = r.u16()?;
            format!("{priority} {weight} {port} {}", r.name()?)
        }
        257 => {
            let flags = r.u8()?;
            let tag_len = usize::from(r.u8()?);
            let mut tag = String::new();
            escape_into(r.bytes(tag_len)?, false, &mut tag);
            let mut value = String::new();
            escape_into(r.bytes(end - r.pos)?, false, &mut value);
            format!("{flags} {tag} \"{value}\"")
        }
        _ => hex(data),
    };
    Ok(text)
}

/// A parsed response with the parts `lookup` checks against its query.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ParsedMessage {
    pub id: u16,
    /// The first question: `(name, type number)`.
    pub question: Option<(String, u16)>,
    pub answer: DnsAnswer,
}

/// Parses a DNS response packet (pure, unit-tested; must survive
/// malformed input and compression loops).
pub fn parse_response(packet: &[u8]) -> Result<DnsAnswer, String> {
    parse_message(packet).map(|m| m.answer)
}

/// `parse_response` that also returns the id and the question.
pub fn parse_message(packet: &[u8]) -> Result<ParsedMessage, String> {
    let fail = |e: String| format!("The answer could not be read ({e}).");
    let mut r = Reader { packet, pos: 0 };
    let id = r.u16().map_err(fail)?;
    let flags = r.u16().map_err(fail)?;
    let counts = [
        r.u16().map_err(fail)?,
        r.u16().map_err(fail)?,
        r.u16().map_err(fail)?,
        r.u16().map_err(fail)?,
    ];
    if flags & 0x8000 == 0 {
        return Err(fail("not a response".into()));
    }
    let truncated = flags & 0x0200 != 0;
    let mut message = ParsedMessage {
        id,
        question: None,
        answer: DnsAnswer {
            rcode: rcode_name((flags & 0x000f) as u8),
            authoritative: flags & 0x0400 != 0,
            truncated,
            ..Default::default()
        },
    };
    let [questions, answers, authority, additional] = counts;
    for _ in 0..questions {
        let name = r.name().map_err(fail)?;
        let code = r.u16().map_err(fail)?;
        let _class = r.u16().map_err(fail)?;
        if message.question.is_none() {
            message.question = Some((name, code));
        }
    }
    let sections = [answers, authority, additional];
    for (index, count) in sections.into_iter().enumerate() {
        for _ in 0..count {
            let record = match read_record(&mut r) {
                Ok(record) => record,
                // A truncated answer legitimately stops in the middle.
                Err(_) if truncated => return Ok(message),
                Err(e) => return Err(fail(e)),
            };
            match index {
                0 => message.answer.answers.push(record),
                1 => message.answer.authority.push(record),
                _ => message.answer.additional.push(record),
            }
        }
    }
    Ok(message)
}

fn read_record(r: &mut Reader<'_>) -> Result<DnsRecord, String> {
    let name = r.name()?;
    let code = r.u16()?;
    let _class = r.u16()?;
    let ttl = r.u32()?;
    let len = usize::from(r.u16()?);
    let start = r.pos;
    r.bytes(len)?;
    let end = r.pos;
    // Data that does not fit its type is shown raw instead of failing the
    // whole answer.
    let data = match render(r.packet, code, start, end) {
        Ok(text) => text,
        Err(_) => hex(r.packet.get(start..end).unwrap_or(&[])),
    };
    Ok(DnsRecord {
        name,
        rtype: type_name(code),
        ttl,
        data,
    })
}

/// The DNS servers Windows is configured to use.
pub fn system_servers() -> Vec<String> {
    use windows::Win32::NetworkManagement::IpHelper::*;
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    let flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_FRIENDLY_NAME;
    let mut size: u32 = 16 * 1024;
    let mut buffer: Vec<u64> = Vec::new();
    let mut found = false;
    for _ in 0..4 {
        // u64 elements keep the buffer aligned for the adapter structs.
        buffer = vec![0u64; (size as usize).div_ceil(8)];
        size = (buffer.len() * 8) as u32;
        // SAFETY: the buffer is live and `size` is its length in bytes.
        let code = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                flags,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };
        if code == 0 {
            found = true;
            break;
        }
        // ERROR_BUFFER_OVERFLOW: `size` now holds what is needed.
        if code != 111 {
            return Vec::new();
        }
        size = size.saturating_add(4096);
    }
    if !found {
        return Vec::new();
    }
    let mut servers: Vec<String> = Vec::new();
    // SAFETY: on success the buffer holds a linked list of adapter structs
    // whose pointers all point inside the buffer, which is alive for the
    // whole block. Loop guards bound the walk.
    unsafe {
        let mut adapter = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        let mut adapters = 0;
        while !adapter.is_null() && adapters < 512 {
            let a = &*adapter;
            if a.OperStatus == IfOperStatusUp && a.IfType != IF_TYPE_SOFTWARE_LOOPBACK {
                let mut dns = a.FirstDnsServerAddress as *const IP_ADAPTER_DNS_SERVER_ADDRESS_XP;
                let mut entries = 0;
                while !dns.is_null() && entries < 64 {
                    let d = &*dns;
                    let len = usize::try_from(d.Address.iSockaddrLength).unwrap_or(0);
                    if let Some((ip, scope)) =
                        crate::ping::sockaddr_to_ip(d.Address.lpSockaddr, len)
                    {
                        if let Some(text) = server_text(ip, scope) {
                            if !servers.contains(&text) {
                                servers.push(text);
                            }
                        }
                    }
                    dns = d.Next;
                    entries += 1;
                }
            }
            adapter = a.Next;
            adapters += 1;
        }
    }
    servers
}

/// How a configured server is written; `None` for the placeholder site-local
/// addresses Windows lists on adapters that have no IPv6 DNS server.
fn server_text(ip: IpAddr, scope: u32) -> Option<String> {
    match ip {
        IpAddr::V4(v4) if v4.is_unspecified() => None,
        IpAddr::V4(v4) => Some(v4.to_string()),
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            if v6.is_unspecified() || matches!(seg, [0xfec0, 0, 0, 0xffff, ..]) {
                None
            } else if seg.first().is_some_and(|s| s & 0xffc0 == 0xfe80) && scope != 0 {
                Some(format!("{v6}%{scope}"))
            } else {
                Some(v6.to_string())
            }
        }
    }
}

/// Parses a server as the UI gives it: an address, optionally `%scope`.
fn parse_server(text: &str) -> Result<SocketAddr, String> {
    let text = text.trim();
    let text = text
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .unwrap_or(text);
    let bad = || format!("\"{text}\" is not a DNS server address.");
    if let Some((addr, scope)) = text.split_once('%') {
        let v6: Ipv6Addr = addr.parse().map_err(|_| bad())?;
        let scope: u32 = scope.parse().map_err(|_| bad())?;
        return Ok(SocketAddr::V6(SocketAddrV6::new(v6, 53, 0, scope)));
    }
    let ip: IpAddr = text.parse().map_err(|_| bad())?;
    Ok(SocketAddr::new(ip, 53))
}

fn new_id() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    // RandomState is seeded from the system's random source.
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    hasher.finish() as u16
}

fn names_match(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

/// Whether `packet` answers the query `(id, name, code)`.
fn accept(packet: &[u8], id: u16, name: &str, code: u16) -> Option<DnsAnswer> {
    let message = parse_message(packet).ok()?;
    if message.id != id {
        return None;
    }
    match &message.question {
        Some((qname, qcode)) if *qcode == code && names_match(qname, name) => {}
        // Some servers leave the question out of error answers.
        None if message.answer.rcode != "NOERROR" => {}
        _ => return None,
    }
    Some(message.answer)
}

fn ask_udp(
    server: SocketAddr,
    query: &[u8],
    id: u16,
    name: &str,
    code: u16,
    timeout: Duration,
) -> Result<DnsAnswer, String> {
    let local: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let io = |e: std::io::Error| format!("Could not ask the server ({e}).");
    let socket = UdpSocket::bind(local).map_err(io)?;
    socket.connect(server).map_err(io)?;
    socket.send(query).map_err(io)?;
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("The server did not answer in time.".into());
        }
        socket.set_read_timeout(Some(left)).map_err(io)?;
        match socket.recv(&mut buf) {
            Ok(n) => {
                // Anything that is not the answer to this query is ignored.
                if let Some(answer) = accept(buf.get(..n).unwrap_or(&[]), id, name, code) {
                    return Ok(answer);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Err("The server did not answer in time.".into());
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                return Err("The server refused the question (nothing listens on port 53).".into());
            }
            Err(e) => return Err(io(e)),
        }
    }
}

fn ask_tcp(
    server: SocketAddr,
    query: &[u8],
    id: u16,
    name: &str,
    code: u16,
    timeout: Duration,
) -> Result<DnsAnswer, String> {
    let io = |e: std::io::Error| format!("Could not ask the server over TCP ({e}).");
    let mut stream = TcpStream::connect_timeout(&server, timeout).map_err(io)?;
    stream.set_read_timeout(Some(timeout)).map_err(io)?;
    stream.set_write_timeout(Some(timeout)).map_err(io)?;
    let len = u16::try_from(query.len()).map_err(|_| "The question is too long.".to_string())?;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    stream.write_all(&framed).map_err(io)?;
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).map_err(io)?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(head))];
    stream.read_exact(&mut body).map_err(io)?;
    accept(&body, id, name, code)
        .ok_or_else(|| "The server's answer did not match the question.".to_string())
}

/// Asks `server` (an IP address; `None` = the first system server) over
/// UDP, retrying over TCP when the answer is truncated.
pub fn lookup(name: &str, rtype: &str, server: Option<&str>) -> Result<DnsAnswer, String> {
    let server = match server.map(str::trim).filter(|s| !s.is_empty()) {
        Some(text) => parse_server(text)?,
        None => {
            let first = system_servers()
                .into_iter()
                .next()
                .ok_or("Windows has no DNS server configured.")?;
            parse_server(&first)?
        }
    };
    lookup_at(name, rtype, server, TIMEOUT_MS)
}

/// `lookup` against a full socket address (any port) with a chosen timeout
/// per attempt. One retry over UDP, then TCP if the answer was truncated.
pub fn lookup_at(
    name: &str,
    rtype: &str,
    server: SocketAddr,
    timeout_ms: u32,
) -> Result<DnsAnswer, String> {
    lookup_impl(name, rtype, server, timeout_ms, 2)
}

/// The system DNS server that `lookup(.., None)` would ask.
pub fn default_server() -> Option<SocketAddr> {
    system_servers()
        .first()
        .and_then(|first| parse_server(first).ok())
}

/// The PTR name of an address, asked once of `server` with a short wait.
/// Unlike the system's own reverse lookup this cannot stall for seconds.
pub fn reverse(addr: IpAddr, server: SocketAddr, timeout_ms: u32) -> Option<String> {
    let answer = lookup_impl(&addr.to_string(), "PTR", server, timeout_ms, 1).ok()?;
    answer
        .answers
        .iter()
        .find(|r| r.rtype == "PTR")
        .map(|r| r.data.trim_end_matches('.').to_string())
        .filter(|name| !name.is_empty())
}

fn lookup_impl(
    name: &str,
    rtype: &str,
    server: SocketAddr,
    timeout_ms: u32,
    attempts: u32,
) -> Result<DnsAnswer, String> {
    let code = type_code(rtype).ok_or_else(|| format!("Unknown record type \"{rtype}\"."))?;
    let asked = query_name(name, code);
    let timeout = Duration::from_millis(u64::from(timeout_ms.clamp(100, 30_000)));
    let started = Instant::now();
    let mut last_error = String::new();
    let mut answer = None;
    for _attempt in 0..attempts.max(1) {
        // A fresh id (and source port) for every attempt.
        let id = new_id();
        let query = build_query(name, rtype, id)?;
        match ask_udp(server, &query, id, &asked, code, timeout) {
            Ok(a) => {
                answer = Some(a);
                break;
            }
            Err(e) => last_error = e,
        }
    }
    let mut answer = answer.ok_or(last_error)?;
    answer.transport = "UDP".into();
    if answer.truncated {
        let id = new_id();
        let query = build_query(name, rtype, id)?;
        // If TCP fails the partial UDP answer is still worth showing.
        if let Ok(mut full) = ask_tcp(server, &query, id, &asked, code, timeout) {
            full.transport = "TCP".into();
            answer = full;
        }
    }
    answer.elapsed_ms = started.elapsed().as_secs_f32() * 1000.0;
    answer.server = match server {
        SocketAddr::V6(v6) if v6.scope_id() != 0 => format!("{}%{}", v6.ip(), v6.scope_id()),
        other => other.ip().to_string(),
    };
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds response packets for the tests.
    struct Packet(Vec<u8>);

    impl Packet {
        fn new(id: u16, flags: u16, counts: [u16; 4]) -> Packet {
            let mut p = Vec::new();
            p.extend_from_slice(&id.to_be_bytes());
            p.extend_from_slice(&flags.to_be_bytes());
            for c in counts {
                p.extend_from_slice(&c.to_be_bytes());
            }
            Packet(p)
        }

        fn name(mut self, name: &str) -> Packet {
            encode_name(name, &mut self.0).unwrap();
            self
        }

        fn raw(mut self, bytes: &[u8]) -> Packet {
            self.0.extend_from_slice(bytes);
            self
        }

        fn question(self, name: &str, code: u16) -> Packet {
            self.name(name).raw(&code.to_be_bytes()).raw(&[0, 1])
        }

        /// A record whose owner is a pointer to offset 12 (the question name).
        fn record(self, code: u16, ttl: u32, data: &[u8]) -> Packet {
            self.raw(&[0xc0, 12])
                .raw(&code.to_be_bytes())
                .raw(&[0, 1])
                .raw(&ttl.to_be_bytes())
                .raw(&(data.len() as u16).to_be_bytes())
                .raw(data)
        }
    }

    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        encode_name(name, &mut out).unwrap();
        out
    }

    #[test]
    fn query_layout() {
        let q = build_query("example.org", "A", 0x1234).unwrap();
        assert_eq!(&q[..12], &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&q[12..25], b"\x07example\x03org\x00");
        assert_eq!(&q[25..], &[0, 1, 0, 1]);
    }

    #[test]
    fn query_types_and_trailing_dot() {
        let q = build_query("example.org.", "mx", 1).unwrap();
        assert_eq!(&q[q.len() - 4..], &[0, 15, 0, 1]);
        let q = build_query("example.org", "CAA", 1).unwrap();
        assert_eq!(&q[q.len() - 4..], &[1, 1, 0, 1]);
        let q = build_query("example.org", "TYPE65", 1).unwrap();
        assert_eq!(&q[q.len() - 4..], &[0, 65, 0, 1]);
        for t in RECORD_TYPES {
            assert!(build_query("example.org", t, 1).is_ok(), "{t}");
            assert_eq!(type_name(type_code(t).unwrap()), *t);
        }
    }

    #[test]
    fn query_rejects_bad_names() {
        assert!(build_query("", "A", 1).is_err());
        assert!(build_query("example..org", "A", 1).is_err());
        assert!(build_query("exa mple.org", "A", 1).is_err());
        assert!(build_query("example.org", "BOGUS", 1).is_err());
        assert!(build_query(&format!("{}.org", "a".repeat(64)), "A", 1).is_err());
        assert!(build_query(&"abcdefgh.".repeat(40), "A", 1).is_err());
        let e = build_query("bücher.example", "A", 1).unwrap_err();
        assert!(e.contains("xn--"), "{e}");
        assert!(build_query("xn--bcher-kva.example", "A", 1).is_ok());
        // The root is a valid name.
        let q = build_query(".", "NS", 1).unwrap();
        assert_eq!(&q[12..], &[0, 0, 2, 0, 1]);
    }

    #[test]
    fn ptr_names() {
        assert_eq!(
            reverse_name("192.0.2.25".parse().unwrap()),
            "25.2.0.192.in-addr.arpa"
        );
        assert_eq!(
            reverse_name("2001:db8::567:89ab".parse().unwrap()),
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        let q = build_query("192.0.2.25", "PTR", 9).unwrap();
        assert_eq!(
            &q[12..q.len() - 4],
            &wire_name("25.2.0.192.in-addr.arpa")[..]
        );
        // Already an arpa name: used as given.
        let q = build_query("25.2.0.192.in-addr.arpa", "PTR", 9).unwrap();
        assert_eq!(
            &q[12..q.len() - 4],
            &wire_name("25.2.0.192.in-addr.arpa")[..]
        );
        // An address with another type is asked for literally.
        let q = build_query("192.0.2.25", "A", 9).unwrap();
        assert_eq!(&q[12..q.len() - 4], &wire_name("192.0.2.25")[..]);
    }

    #[test]
    fn round_trip_of_a_query_is_not_a_response() {
        let q = build_query("example.org", "A", 7).unwrap();
        assert!(parse_response(&q).is_err());
        // With the response bit set it parses and gives the question back.
        let mut r = q.clone();
        r[2] |= 0x80;
        let m = parse_message(&r).unwrap();
        assert_eq!(m.id, 7);
        assert_eq!(m.question, Some(("example.org".to_string(), 1)));
        assert_eq!(m.answer.rcode, "NOERROR");
        assert!(m.answer.answers.is_empty());
    }

    #[test]
    fn parse_a_and_aaaa() {
        let p = Packet::new(1, 0x8180, [1, 2, 0, 0])
            .question("example.org", 1)
            .record(1, 300, &[192, 0, 2, 10])
            .record(
                28,
                60,
                &"2001:db8::10".parse::<Ipv6Addr>().unwrap().octets(),
            );
        let a = parse_response(&p.0).unwrap();
        assert_eq!(a.rcode, "NOERROR");
        assert!(!a.authoritative && !a.truncated);
        assert_eq!(
            a.answers,
            vec![
                DnsRecord {
                    name: "example.org".into(),
                    rtype: "A".into(),
                    ttl: 300,
                    data: "192.0.2.10".into()
                },
                DnsRecord {
                    name: "example.org".into(),
                    rtype: "AAAA".into(),
                    ttl: 60,
                    data: "2001:db8::10".into()
                },
            ]
        );
    }

    #[test]
    fn parse_names_with_compression() {
        // CNAME data "www" + pointer to the question name; NS and PTR plain.
        let mut cname = vec![3];
        cname.extend_from_slice(b"www");
        cname.extend_from_slice(&[0xc0, 12]);
        let p = Packet::new(1, 0x8580, [1, 1, 1, 1])
            .question("example.org", 5)
            .record(5, 10, &cname)
            .record(2, 20, &wire_name("ns1.example.net"))
            .record(12, 30, &wire_name("host.example.org"));
        let a = parse_response(&p.0).unwrap();
        assert!(a.authoritative);
        assert_eq!(a.answers[0].data, "www.example.org");
        assert_eq!(a.answers[0].rtype, "CNAME");
        assert_eq!(a.authority[0].data, "ns1.example.net");
        assert_eq!(a.authority[0].rtype, "NS");
        assert_eq!(a.additional[0].data, "host.example.org");
        assert_eq!(a.additional[0].rtype, "PTR");
    }

    #[test]
    fn parse_mx_soa_srv() {
        let mut mx = vec![0, 10];
        mx.extend_from_slice(&wire_name("mail.example.org"));
        let mut soa = wire_name("ns1.example.org");
        soa.extend_from_slice(&wire_name("hostmaster.example.org"));
        for v in [2024010101u32, 7200, 3600, 1209600, 300] {
            soa.extend_from_slice(&v.to_be_bytes());
        }
        let mut srv = vec![0, 5, 0, 20, 0x14, 0x66];
        srv.extend_from_slice(&wire_name("sip.example.org"));
        let p = Packet::new(1, 0x8180, [1, 3, 0, 0])
            .question("example.org", 15)
            .record(15, 1, &mx)
            .record(6, 1, &soa)
            .record(33, 1, &srv);
        let a = parse_response(&p.0).unwrap();
        assert_eq!(a.answers[0].data, "10 mail.example.org");
        assert_eq!(
            a.answers[1].data,
            "ns1.example.org hostmaster.example.org 2024010101 7200 3600 1209600 300"
        );
        assert_eq!(a.answers[2].data, "5 20 5222 sip.example.org");
        assert_eq!(a.answers[2].rtype, "SRV");
    }

    #[test]
    fn parse_txt_multi_string_and_escapes() {
        let mut txt = vec![5];
        txt.extend_from_slice(b"v=one");
        txt.push(7);
        txt.extend_from_slice(b"a\"b\\c\x01\xff");
        txt.push(0);
        let p = Packet::new(1, 0x8180, [1, 1, 0, 0])
            .question("example.org", 16)
            .record(16, 1, &txt);
        let a = parse_response(&p.0).unwrap();
        assert_eq!(a.answers[0].data, r#""v=one" "a\"b\\c\001\255" """#);
    }

    #[test]
    fn parse_caa() {
        let mut caa = vec![0, 5];
        caa.extend_from_slice(b"issue");
        caa.extend_from_slice(b"ca.example.net");
        let p = Packet::new(1, 0x8180, [1, 1, 0, 0])
            .question("example.org", 257)
            .record(257, 1, &caa);
        let a = parse_response(&p.0).unwrap();
        assert_eq!(a.answers[0].rtype, "CAA");
        assert_eq!(a.answers[0].data, r#"0 issue "ca.example.net""#);
    }

    #[test]
    fn unknown_type_and_misfit_data_are_hex() {
        let p = Packet::new(1, 0x8180, [1, 2, 0, 0])
            .question("example.org", 1)
            .record(65, 1, &[0xde, 0xad, 0xbe, 0xef])
            // An A record with three bytes of data.
            .record(1, 1, &[1, 2, 3]);
        let a = parse_response(&p.0).unwrap();
        assert_eq!(a.answers[0].rtype, "TYPE65");
        assert_eq!(a.answers[0].data, "deadbeef");
        assert_eq!(a.answers[1].rtype, "A");
        assert_eq!(a.answers[1].data, "010203");
    }

    #[test]
    fn rcodes() {
        for (code, name) in [
            (0u16, "NOERROR"),
            (2, "SERVFAIL"),
            (3, "NXDOMAIN"),
            (5, "REFUSED"),
            (13, "RCODE13"),
        ] {
            let p = Packet::new(1, 0x8180 | code, [1, 0, 0, 0]).question("example.org", 1);
            assert_eq!(parse_response(&p.0).unwrap().rcode, name);
        }
    }

    #[test]
    fn truncated_flag_tolerates_a_cut_packet() {
        let full = Packet::new(1, 0x8380, [1, 2, 0, 0])
            .question("example.org", 1)
            .record(1, 1, &[192, 0, 2, 1])
            .record(1, 1, &[192, 0, 2, 2]);
        let cut = &full.0[..full.0.len() - 3];
        let a = parse_response(cut).unwrap();
        assert!(a.truncated);
        assert_eq!(a.answers.len(), 1);
        // The same cut without the TC flag is an error.
        let mut plain = cut.to_vec();
        plain[2] &= !0x02;
        assert!(parse_response(&plain).is_err());
    }

    #[test]
    fn every_prefix_of_a_packet_is_handled() {
        let mut mx = vec![0, 10];
        mx.extend_from_slice(&wire_name("mail.example.org"));
        let full = Packet::new(1, 0x8180, [1, 2, 0, 0])
            .question("example.org", 15)
            .record(15, 1, &mx)
            .record(16, 1, b"\x03abc");
        for n in 0..full.0.len() {
            assert!(parse_response(&full.0[..n]).is_err(), "prefix {n}");
        }
        assert!(parse_response(&full.0).is_ok());
    }

    #[test]
    fn compression_loops_are_refused() {
        // A name that points at itself.
        let p = Packet::new(1, 0x8180, [1, 0, 0, 0]).raw(&[0xc0, 12, 0, 1, 0, 1]);
        assert!(parse_response(&p.0).unwrap_err().contains("loop"));
        // Two pointers that point at each other (the second is forward).
        let p = Packet::new(1, 0x8180, [1, 0, 0, 0]).raw(&[0xc0, 14, 0xc0, 12, 0, 1, 0, 1]);
        assert!(parse_response(&p.0).is_err());
        // A pointer past the end of the packet.
        let p = Packet::new(1, 0x8180, [1, 0, 0, 0]).raw(&[0xff, 0xff, 0, 1, 0, 1]);
        assert!(parse_response(&p.0).is_err());
        // A record whose data is a looping name: shown as hex, not a hang.
        let p = Packet::new(1, 0x8180, [1, 1, 0, 0])
            .question("example.org", 5)
            .record(5, 1, &[0xc0, 40]);
        let a = parse_response(&p.0).unwrap();
        assert_eq!(a.answers[0].data, "c028");
    }

    #[test]
    fn overlong_names_are_refused() {
        // 5 labels of 63 bytes exceed the 255-byte limit.
        let mut p = Packet::new(1, 0x8180, [1, 0, 0, 0]);
        for _ in 0..5 {
            p = p.raw(&[63]).raw(&[b'a'; 63]);
        }
        let p = p.raw(&[0, 0, 1, 0, 1]);
        assert!(parse_response(&p.0).is_err());
    }

    #[test]
    fn garbage_never_panics() {
        assert!(parse_response(&[]).is_err());
        assert!(parse_response(&[0xff; 5]).is_err());
        // Deterministic pseudo-random packets of many sizes.
        let mut state = 0x2545f4914f6cdd1du64;
        for len in 0..600 {
            let mut packet = Vec::with_capacity(len);
            for _ in 0..len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                packet.push(state as u8);
            }
            let _ = parse_response(&packet);
            // And with a plausible header in front.
            if let Some(head) = packet.get_mut(..12) {
                head.copy_from_slice(&[0, 1, 0x81, 0x80, 0, 1, 0, 3, 0, 1, 0, 1]);
            }
            let _ = parse_response(&packet);
        }
        // Huge counts with no data.
        let p = Packet::new(1, 0x8180, [0xffff, 0xffff, 0xffff, 0xffff]);
        assert!(parse_response(&p.0).is_err());
    }

    #[test]
    fn label_escaping() {
        let p = Packet::new(1, 0x8180, [1, 0, 0, 0])
            .raw(&[4, b'a', b'.', b'b', 0x07, 3, b'o', b'r', b'g', 0])
            .raw(&[0, 1, 0, 1]);
        let m = parse_message(&p.0).unwrap();
        assert_eq!(m.question.unwrap().0, "a\\.b\\007.org");
        // The root name.
        let p = Packet::new(1, 0x8180, [1, 0, 0, 0]).raw(&[0, 0, 2, 0, 1]);
        assert_eq!(parse_message(&p.0).unwrap().question.unwrap().0, ".");
    }

    #[test]
    fn answers_are_matched_to_the_question() {
        let p = Packet::new(77, 0x8180, [1, 1, 0, 0])
            .question("Example.ORG", 1)
            .record(1, 1, &[192, 0, 2, 1]);
        assert!(accept(&p.0, 77, "example.org", 1).is_some());
        assert!(accept(&p.0, 78, "example.org", 1).is_none());
        assert!(accept(&p.0, 77, "example.net", 1).is_none());
        assert!(accept(&p.0, 77, "example.org", 28).is_none());
        // No question at all is only accepted for an error answer.
        let p = Packet::new(77, 0x8180, [0, 0, 0, 0]);
        assert!(accept(&p.0, 77, "example.org", 1).is_none());
        let p = Packet::new(77, 0x8182, [0, 0, 0, 0]);
        assert!(accept(&p.0, 77, "example.org", 1).is_some());
    }

    #[test]
    fn server_addresses() {
        assert_eq!(
            parse_server("192.0.2.53").unwrap().to_string(),
            "192.0.2.53:53"
        );
        assert_eq!(
            parse_server("2001:db8::53").unwrap().to_string(),
            "[2001:db8::53]:53"
        );
        match parse_server("fe80::1%7").unwrap() {
            SocketAddr::V6(v6) => assert_eq!(v6.scope_id(), 7),
            other => panic!("{other}"),
        }
        assert!(parse_server("dns.example.org").is_err());
        assert!(parse_server("").is_err());
        assert_eq!(
            server_text("192.0.2.53".parse().unwrap(), 0).unwrap(),
            "192.0.2.53"
        );
        assert_eq!(
            server_text("fe80::1".parse().unwrap(), 7).unwrap(),
            "fe80::1%7"
        );
        assert_eq!(server_text("fec0:0:0:ffff::1".parse().unwrap(), 1), None);
        assert_eq!(server_text("0.0.0.0".parse().unwrap(), 0), None);
    }

    type TcpAnswer = Box<dyn Fn(&[u8]) -> Vec<u8> + Send>;

    /// A one-shot fake DNS server on loopback.
    fn fake_server(
        respond: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
        tcp: Option<TcpAnswer>,
    ) -> SocketAddr {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        let listener = tcp
            .is_some()
            .then(|| std::net::TcpListener::bind(addr).unwrap());
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            if let Ok((n, from)) = udp.recv_from(&mut buf) {
                for packet in respond(&buf[..n]) {
                    let _ = udp.send_to(&packet, from);
                }
            }
            if let (Some(listener), Some(tcp)) = (listener, tcp) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut head = [0u8; 2];
                    if stream.read_exact(&mut head).is_ok() {
                        let mut q = vec![0u8; usize::from(u16::from_be_bytes(head))];
                        if stream.read_exact(&mut q).is_ok() {
                            let answer = tcp(&q);
                            let _ = stream.write_all(&(answer.len() as u16).to_be_bytes());
                            let _ = stream.write_all(&answer);
                        }
                    }
                }
            }
        });
        addr
    }

    fn answer_for(query: &[u8], flags: u16, addrs: &[[u8; 4]]) -> Vec<u8> {
        let id = u16::from_be_bytes([query[0], query[1]]);
        let mut p = Packet::new(id, flags, [1, addrs.len() as u16, 0, 0]).raw(&query[12..]);
        for a in addrs {
            p = p.record(1, 60, a);
        }
        p.0
    }

    #[test]
    fn lookup_over_udp_ignores_spoofed_answers() {
        let server = fake_server(
            |q| {
                // First a packet with the wrong id, then the real one.
                let mut wrong = answer_for(q, 0x8180, &[[198, 51, 100, 66]]);
                wrong[0] ^= 0xff;
                vec![wrong, answer_for(q, 0x8180, &[[192, 0, 2, 1]])]
            },
            None,
        );
        let a = lookup_at("example.org", "A", server, 2000).unwrap();
        assert_eq!(a.transport, "UDP");
        assert_eq!(a.server, "127.0.0.1");
        assert_eq!(a.answers.len(), 1);
        assert_eq!(a.answers[0].data, "192.0.2.1");
        assert!(a.elapsed_ms >= 0.0);
    }

    #[test]
    fn lookup_falls_back_to_tcp_when_truncated() {
        let server = fake_server(
            |q| vec![answer_for(q, 0x8380, &[])],
            Some(Box::new(|q| {
                answer_for(q, 0x8180, &[[192, 0, 2, 1], [192, 0, 2, 2]])
            })),
        );
        let a = lookup_at("example.org", "A", server, 2000).unwrap();
        assert_eq!(a.transport, "TCP");
        assert!(!a.truncated);
        assert_eq!(a.answers.len(), 2);
    }

    #[test]
    fn lookup_times_out_or_is_refused_on_a_dead_port() {
        // Bind and drop to find a loopback port nothing listens on.
        let port = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(lookup_at("example.org", "A", port, 200).is_err());
        assert!(lookup("example.org", "A", Some("not an address")).is_err());
        assert!(lookup("example.org", "NOPE", Some("192.0.2.1")).is_err());
    }
}
