//! The public IP address of this connection (asked for only on a click).
//!
//! The service is ipify (<https://www.ipify.org>): a public API made to be
//! called by programs, which states it can be used without limit and that no
//! visitor information is logged.

use std::net::IpAddr;

const URL: &str = "https://api.ipify.org";

/// The service that is asked: `(name, URL shown to the user)`.
pub fn service() -> (&'static str, &'static str) {
    ("ipify", URL)
}

/// Pulls the address out of the service's answer (pure, unit-tested).
/// Understands a bare address, a `ip=...` line and `{"ip":"..."}`.
pub fn parse(body: &str) -> Option<String> {
    let body = body.trim().trim_start_matches('\u{feff}');
    if body.len() > 4096 {
        return None;
    }
    let valid = |text: &str| {
        let text = text.trim();
        text.parse::<IpAddr>().ok().map(|ip| ip.to_string())
    };
    if let Some(ip) = valid(body) {
        return Some(ip);
    }
    if let Some(ip) = body
        .lines()
        .find_map(|line| line.trim().strip_prefix("ip=").and_then(valid))
    {
        return Some(ip);
    }
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    json.get("ip").and_then(|v| v.as_str()).and_then(valid)
}

pub fn fetch() -> Result<String, String> {
    let response = crate::http::get(
        URL,
        crate::http::Options {
            max_body: 4096,
            timeout_ms: 8_000,
            deadline_ms: 15_000,
            ..Default::default()
        },
    )
    .map_err(|e| e.to_string())?;
    if response.status != 200 {
        return Err(format!(
            "The address service answered with an error (HTTP {}).",
            response.status
        ));
    }
    parse(&response.text())
        .ok_or_else(|| "The address service sent an answer that is not an address.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_address() {
        assert_eq!(parse("198.51.100.7").as_deref(), Some("198.51.100.7"));
        assert_eq!(parse(" 198.51.100.7\r\n").as_deref(), Some("198.51.100.7"));
        assert_eq!(parse("2001:DB8::7").as_deref(), Some("2001:db8::7"));
    }

    #[test]
    fn trace_and_json_forms() {
        let trace = "fl=1f1\nh=example.org\nip=198.51.100.7\nts=1.0\nloc=XX\n";
        assert_eq!(parse(trace).as_deref(), Some("198.51.100.7"));
        assert_eq!(
            parse(r#"{"ip":"2001:db8::7"}"#).as_deref(),
            Some("2001:db8::7")
        );
    }

    #[test]
    fn rejects_everything_else() {
        for bad in [
            "",
            "hello",
            "<html><body>198.51.100.7</body></html>",
            "198.51.100",
            "999.1.1.1",
            "ip=not-an-address",
            r#"{"ip":42}"#,
            r#"{"address":"198.51.100.7"}"#,
            "198.51.100.7 198.51.100.8",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
        assert_eq!(parse(&"1".repeat(10_000)), None);
    }

    #[test]
    fn service_is_https() {
        let (name, url) = service();
        assert!(!name.is_empty());
        assert!(crate::http::parse_url(url).is_ok());
    }
}
