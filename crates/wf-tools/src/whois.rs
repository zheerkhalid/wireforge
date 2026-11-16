//! Whois over TCP port 43.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// The registry of registries: it answers for domains, addresses and AS
/// numbers and names the server that knows more.
pub const IANA: &str = "whois.iana.org";

/// The most text kept from one server.
pub const MAX_ANSWER: usize = 64 * 1024;

/// The whois server to ask first for a query (pure, unit-tested).
pub fn first_server(query: &str) -> &'static str {
    let _ = query;
    IANA
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && !host.starts_with(['.', '-'])
        && !host.ends_with('-')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Finds a `refer:` / `whois:` referral in an answer (pure, unit-tested).
pub fn referral(answer: &str) -> Option<String> {
    let find = |key: &str| {
        answer.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if !name.trim().eq_ignore_ascii_case(key) {
                return None;
            }
            let value = value.trim();
            let value = value
                .strip_prefix("whois://")
                .or_else(|| value.strip_prefix("//"))
                .unwrap_or(value);
            let host = value
                .split(['/', ':', ' ', '\t'])
                .next()
                .unwrap_or("")
                .trim_end_matches('.')
                .to_ascii_lowercase();
            valid_host(&host).then_some(host)
        })
    };
    find("refer").or_else(|| find("whois"))
}

/// Checks and tidies what the user typed (pure, unit-tested).
pub fn clean_query(query: &str) -> Result<String, String> {
    let query = query.trim();
    if query.is_empty() {
        return Err("Enter a domain name, an IP address or an AS number.".into());
    }
    if query.len() > 255 {
        return Err("That is too long for a whois query.".into());
    }
    if query.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("A whois query is one word: no spaces.".into());
    }
    if !query.is_ascii() {
        return Err(
            "Names with non-English letters must be entered in their xn-- (punycode) form.".into(),
        );
    }
    Ok(query.to_ascii_lowercase())
}

fn ask(server: &str, query: &str) -> Result<String, String> {
    let io = |e: std::io::Error| format!("Could not ask {server} ({e}).");
    let timeout = Duration::from_secs(8);
    let addrs: Vec<_> = (server, 43).to_socket_addrs().map_err(io)?.collect();
    let mut last = format!("Could not find {server}.");
    let mut stream = None;
    // A couple of addresses at most, so a dead server cannot stall for long.
    for addr in addrs.iter().take(2) {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last = io(e),
        }
    }
    let mut stream = stream.ok_or(last)?;
    stream.set_read_timeout(Some(timeout)).map_err(io)?;
    stream.set_write_timeout(Some(timeout)).map_err(io)?;
    stream
        .write_all(format!("{query}\r\n").as_bytes())
        .map_err(io)?;
    let started = Instant::now();
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    while out.len() < MAX_ANSWER && started.elapsed() < Duration::from_secs(20) {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
            // Keep what arrived if the server stalls part-way.
            Err(_) if !out.is_empty() => break,
            Err(e) => return Err(io(e)),
        }
    }
    out.truncate(MAX_ANSWER);
    Ok(tidy(&String::from_utf8_lossy(&out)))
}

/// Normalises line ends and drops control characters.
fn tidy(text: &str) -> String {
    text.replace("\r\n", "\n")
        .chars()
        .filter(|c| *c == '\n' || *c == '\t' || !c.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

/// Asks IANA, follows one referral, returns the text (capped in size).
pub fn whois(query: &str) -> Result<String, String> {
    let query = clean_query(query)?;
    let first = first_server(&query);
    let answer = ask(first, &query)?;
    match referral(&answer) {
        Some(next) if next != first => match ask(&next, &query) {
            Ok(detail) if !detail.is_empty() => Ok(format!("% Answer from {next}\n\n{detail}")),
            // The registry did not answer: the first answer is better than nothing.
            _ => Ok(format!("% Answer from {first}\n\n{answer}")),
        },
        _ => Ok(format!("% Answer from {first}\n\n{answer}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_iana() {
        assert_eq!(first_server("example.org"), "whois.iana.org");
        assert_eq!(first_server("192.0.2.1"), "whois.iana.org");
        assert_eq!(first_server("AS64496"), "whois.iana.org");
    }

    #[test]
    fn finds_refer() {
        let answer = "% IANA WHOIS server\n\nrefer:        whois.example-registry.org\n\ndomain:       ORG\n";
        assert_eq!(
            referral(answer).as_deref(),
            Some("whois.example-registry.org")
        );
    }

    #[test]
    fn refer_wins_over_whois_and_forms_are_cleaned() {
        let answer = "whois: whois.second.example\nRefer: WHOIS.First.Example.\n";
        assert_eq!(referral(answer).as_deref(), Some("whois.first.example"));
        assert_eq!(
            referral("whois:   whois://whois.example.net:43/path").as_deref(),
            Some("whois.example.net")
        );
        assert_eq!(
            referral("  Whois:\twhois.example.net extra").as_deref(),
            Some("whois.example.net")
        );
    }

    #[test]
    fn no_referral() {
        assert_eq!(referral(""), None);
        assert_eq!(referral("domain: EXAMPLE\nstatus: ACTIVE"), None);
        assert_eq!(referral("refer:"), None);
        assert_eq!(referral("refer: not a host"), None);
        assert_eq!(referral("refer: localhost"), None);
        assert_eq!(referral("refer: bad_host.example"), None);
        assert_eq!(referral("refer: -bad.example"), None);
        assert_eq!(referral("remarks: refer: whois.example.net"), None);
    }

    #[test]
    fn queries() {
        assert_eq!(clean_query("  Example.ORG ").unwrap(), "example.org");
        assert_eq!(clean_query("2001:db8::1").unwrap(), "2001:db8::1");
        for bad in [
            "",
            "   ",
            "example.org extra",
            "a\r\nb",
            "a\tb",
            "bücher.example",
        ] {
            assert!(clean_query(bad).is_err(), "{bad:?}");
        }
        assert!(clean_query(&"a".repeat(300)).is_err());
        // Refused before any connection is made.
        assert!(whois("two words").is_err());
    }

    #[test]
    fn tidy_text() {
        assert_eq!(tidy("a\r\nb\x07c\r\n\r\n"), "a\nbc");
    }
}
