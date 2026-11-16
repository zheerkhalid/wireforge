//! `WIFI:` QR codes.

/// What the `T:` field of a `WIFI:` code says.
fn kind(security: &str, password: &str) -> &'static str {
    let s = security.trim().to_ascii_lowercase();
    if s.contains("wep") || s == "shared" {
        if password.is_empty() {
            "nopass"
        } else {
            "WEP"
        }
    } else if password.is_empty()
        || s.is_empty()
        || s == "open"
        || s == "none"
        || s == "nopass"
        || s == "owe"
        || s.starts_with("open ")
    {
        "nopass"
    } else {
        // WPA, WPA2, WPA3 (SAE) and the transition modes: phones accept
        // `T:WPA` for all of them and pick the strongest the network offers.
        "WPA"
    }
}

/// Backslash-escapes the characters that have a meaning inside a `WIFI:` code.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 4);
    for c in text.chars() {
        if matches!(c, '\\' | ';' | ',' | ':' | '"') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The text phone cameras understand as "join this network". `security` is
/// a display name or raw authentication value; `hidden` adds `H:true`.
///
/// WPA2 and WPA3 personal networks are both written as `T:WPA`. A 64-digit
/// hexadecimal key is passed on as it is. Enterprise (802.1X) networks cannot
/// be expressed this way; the caller should not offer a code for them.
pub fn wifi_payload(ssid: &str, password: &str, security: &str, hidden: bool) -> String {
    let kind = kind(security, password);
    let mut out = String::from("WIFI:T:");
    out.push_str(kind);
    out.push_str(";S:");
    out.push_str(&escape(ssid));
    out.push(';');
    if kind != "nopass" {
        out.push_str("P:");
        out.push_str(&escape(password));
        out.push(';');
    }
    if hidden {
        out.push_str("H:true;");
    }
    out.push(';');
    out
}

/// A QR code as a square grid of dark (true) and light modules.
///
/// The grid has no quiet zone: draw at least four light modules around it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Matrix {
    pub width: usize,
    pub dark: Vec<bool>,
}

impl Matrix {
    /// Whether the module at column `x`, row `y` is dark (false outside the grid).
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        if x >= self.width {
            return false;
        }
        self.dark.get(y * self.width + x).copied().unwrap_or(false)
    }
}

/// `None` when the data is too long for a QR code.
pub fn matrix(data: &[u8]) -> Option<Matrix> {
    let code = qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::M).ok()?;
    let width = code.width();
    let dark: Vec<bool> = code
        .to_colors()
        .into_iter()
        .map(|c| c == qrcode::Color::Dark)
        .collect();
    if width == 0 || dark.len() != width * width {
        return None;
    }
    Some(Matrix { width, dark })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_wpa2() {
        assert_eq!(
            wifi_payload("Maple-Home", "correct horse", "WPA2-Personal", false),
            "WIFI:T:WPA;S:Maple-Home;P:correct horse;;"
        );
        assert_eq!(
            wifi_payload("Maple-Home", "correct horse", "WPA2PSK", false),
            "WIFI:T:WPA;S:Maple-Home;P:correct horse;;"
        );
    }

    #[test]
    fn wpa3_and_transition_use_wpa() {
        for security in [
            "WPA3-Personal",
            "WPA3SAE",
            "WPA2/WPA3-Personal",
            "SAE",
            "WPA-Personal",
        ] {
            assert_eq!(
                wifi_payload("Maple-Home", "pw", security, false),
                "WIFI:T:WPA;S:Maple-Home;P:pw;;",
                "{security}"
            );
        }
    }

    #[test]
    fn open_networks_have_no_password_field() {
        for security in ["Open", "open", "", "nopass", "OWE", "none"] {
            assert_eq!(
                wifi_payload("Cafe Guest", "", security, false),
                "WIFI:T:nopass;S:Cafe Guest;;",
                "{security:?}"
            );
        }
        // No password at all is always "nopass", whatever the label says.
        assert_eq!(
            wifi_payload("Cafe Guest", "", "WPA2-Personal", false),
            "WIFI:T:nopass;S:Cafe Guest;;"
        );
        // An open network never carries a password field.
        assert_eq!(
            wifi_payload("Cafe Guest", "stray", "Open", false),
            "WIFI:T:nopass;S:Cafe Guest;;"
        );
    }

    #[test]
    fn wep() {
        assert_eq!(
            wifi_payload("Old-Router", "abcde", "WEP", false),
            "WIFI:T:WEP;S:Old-Router;P:abcde;;"
        );
        assert_eq!(
            wifi_payload("Old-Router", "abcde", "shared", false),
            "WIFI:T:WEP;S:Old-Router;P:abcde;;"
        );
    }

    #[test]
    fn hidden_flag() {
        assert_eq!(
            wifi_payload("Quiet", "pw", "WPA2-Personal", true),
            "WIFI:T:WPA;S:Quiet;P:pw;H:true;;"
        );
        assert_eq!(
            wifi_payload("Quiet", "", "Open", true),
            "WIFI:T:nopass;S:Quiet;H:true;;"
        );
    }

    #[test]
    fn special_characters_are_escaped() {
        assert_eq!(escape(r#"a\b;c,d:e"f"#), r#"a\\b\;c\,d\:e\"f"#);
        assert_eq!(
            wifi_payload(
                r#"My;Net,work:"1"\"#,
                r#"p;a,s:s"w\d"#,
                "WPA2-Personal",
                false
            ),
            r#"WIFI:T:WPA;S:My\;Net\,work\:\"1\"\\;P:p\;a\,s\:s\"w\\d;;"#
        );
    }

    #[test]
    fn other_characters_pass_through() {
        assert_eq!(
            wifi_payload(
                "Caf\u{e9} \u{1F4F6} <&>'",
                "p\u{e4}ss w\u{f6}rd \u{1F511}",
                "WPA2-Personal",
                false
            ),
            "WIFI:T:WPA;S:Caf\u{e9} \u{1F4F6} <&>';P:p\u{e4}ss w\u{f6}rd \u{1F511};;"
        );
        // Leading and trailing spaces belong to the name and the password.
        assert_eq!(
            wifi_payload(" lead", "trail ", "WPA2-Personal", false),
            "WIFI:T:WPA;S: lead;P:trail ;;"
        );
    }

    #[test]
    fn hex_key_is_passed_as_is() {
        let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            wifi_payload("Maple-Home", key, "WPA2-Personal", false),
            format!("WIFI:T:WPA;S:Maple-Home;P:{key};;")
        );
    }

    #[test]
    fn matrix_shape() {
        let payload = wifi_payload("Maple-Home", "correct horse", "WPA2-Personal", false);
        let m = matrix(payload.as_bytes()).unwrap_or_default();
        assert!(m.width >= 21);
        assert_eq!((m.width - 21) % 4, 0);
        assert_eq!(m.dark.len(), m.width * m.width);
        // The three finder patterns have dark corners.
        assert!(m.is_dark(0, 0));
        assert!(m.is_dark(m.width - 1, 0));
        assert!(m.is_dark(0, m.width - 1));
        assert!(!m.is_dark(m.width, 0));
        assert!(m.dark.iter().any(|d| !d));
    }

    #[test]
    fn matrix_refuses_oversized_data() {
        assert!(matrix(&vec![b'x'; 5000]).is_none());
        assert!(matrix(b"").is_some());
    }
}
