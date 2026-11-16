//! Export of tables to CSV, HTML and JSON, and the masking of private values.
//!
//! Every page builds [`Table`]s; the writers here turn them into files.
//! Nothing is ever uploaded: an export is a file the user chose to save.

use std::path::{Path, PathBuf};
use wf_wifi::{KeyState, SavedProfile};

/// A named table of text cells.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Table {
    pub title: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(title: &str, columns: &[&str]) -> Table {
        Table {
            title: title.to_string(),
            columns: columns.iter().map(|c| c.to_string()).collect(),
            rows: Vec::new(),
        }
    }

    pub fn push(&mut self, row: Vec<String>) {
        self.rows.push(row);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Csv,
    Html,
    Json,
}

impl Format {
    /// From a file name; anything unknown is CSV.
    pub fn from_path(path: &Path) -> Format {
        match path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref()
        {
            Some("html") | Some("htm") => Format::Html,
            Some("json") => Format::Json,
            _ => Format::Csv,
        }
    }
}

/// What stands in for a hidden secret. Always the same length, so the mask
/// says nothing about the secret.
pub const MASK: &str = "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";

/// Hides a secret completely.
pub fn mask_secret(secret: &str) -> String {
    if secret.is_empty() {
        String::new()
    } else {
        MASK.to_string()
    }
}

/// Keeps the vendor half of a MAC address: `AA:BB:CC:xx:xx:xx`.
pub fn mask_mac(mac: &str) -> String {
    let parts: Vec<&str> = mac.split([':', '-']).collect();
    if parts.len() == 6 {
        format!("{}:{}:{}:xx:xx:xx", parts[0], parts[1], parts[2])
    } else if mac.is_empty() {
        String::new()
    } else {
        "xx:xx:xx:xx:xx:xx".to_string()
    }
}

/// Keeps the first half of an IPv4 address (`192.168.x.x`) and the first two
/// groups of an IPv6 address.
pub fn mask_ip(ip: &str) -> String {
    let v4: Vec<&str> = ip.split('.').collect();
    if v4.len() == 4 && v4.iter().all(|p| p.parse::<u8>().is_ok()) {
        return format!("{}.{}.x.x", v4[0], v4[1]);
    }
    if ip.contains(':') {
        let groups: Vec<&str> = ip.split(':').collect();
        return format!(
            "{}:{}:x:x",
            groups.first().copied().unwrap_or(""),
            groups.get(1).copied().unwrap_or("")
        );
    }
    if ip.is_empty() {
        String::new()
    } else {
        "x".to_string()
    }
}

/// The saved Wi-Fi networks as a table. Passwords are written only when
/// `include_passwords` is set (the UI asks first and warns); otherwise they
/// are masked.
pub fn saved_networks_table(profiles: &[SavedProfile], include_passwords: bool) -> Table {
    let mut t = Table::new(
        "Saved Wi-Fi networks",
        &[
            "Network (SSID)",
            "Security",
            "Password",
            "Connects automatically",
            "Hidden network",
            "Saved for",
        ],
    );
    for p in profiles {
        let password = match &p.key {
            KeyState::Key(k) if include_passwords => k.clone(),
            KeyState::Key(k) => mask_secret(k),
            KeyState::Open => "(none: open network)".to_string(),
            KeyState::NeedsAdmin => "(needs administrator rights)".to_string(),
            KeyState::Enterprise => "(enterprise sign-in: no shared password)".to_string(),
            KeyState::Unavailable(_) | KeyState::Unknown => "(not available)".to_string(),
        };
        t.push(vec![
            if p.ssid.is_empty() {
                p.name.clone()
            } else {
                p.ssid.clone()
            },
            p.security.clone(),
            password,
            yes_no(p.auto_connect),
            yes_no(p.hidden),
            if p.all_users {
                "All users".into()
            } else {
                "This user".into()
            },
        ]);
    }
    t
}

pub fn yes_no(b: bool) -> String {
    if b { "Yes" } else { "No" }.to_string()
}

/// `-67 dBm`, `+1.5`, `-5`: a signed number with an optional unit is data, not a formula.
fn is_signed_number(cell: &str) -> bool {
    let rest = &cell[1..];
    let (number, unit) = match rest.split_once(' ') {
        Some((n, u)) => (n, u),
        None => (rest, ""),
    };
    !number.is_empty()
        && number
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == ',')
        && unit
            .chars()
            .all(|c| c.is_ascii_alphabetic() || c == '/' || c == '%')
}

fn csv_cell(cell: &str) -> String {
    // Spreadsheet programs run cells that start with these as formulas.
    let guarded = match cell.chars().next() {
        Some('+') | Some('-') if is_signed_number(cell) => cell.to_string(),
        Some('=') | Some('+') | Some('-') | Some('@') | Some('\t') | Some('\r') => {
            format!("'{cell}")
        }
        _ => cell.to_string(),
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

/// CSV with a byte-order mark so Excel reads it as UTF-8. Several tables are
/// separated by a blank line and a title line.
pub fn to_csv(tables: &[Table]) -> String {
    let mut out = String::from("\u{feff}");
    for (i, t) in tables.iter().enumerate() {
        if tables.len() > 1 {
            if i > 0 {
                out.push_str("\r\n");
            }
            out.push_str(&csv_cell(&t.title));
            out.push_str("\r\n");
        }
        let line = |cells: &[String]| {
            cells
                .iter()
                .map(|c| csv_cell(c))
                .collect::<Vec<_>>()
                .join(",")
        };
        out.push_str(&line(&t.columns));
        out.push_str("\r\n");
        for row in &t.rows {
            out.push_str(&line(row));
            out.push_str("\r\n");
        }
    }
    out
}

/// JSON: a list of `{ "title", "rows": [ { column: value } ] }`.
pub fn to_json(tables: &[Table]) -> String {
    let list: Vec<serde_json::Value> = tables
        .iter()
        .map(|t| {
            let rows: Vec<serde_json::Value> = t
                .rows
                .iter()
                .map(|row| {
                    let mut obj = serde_json::Map::new();
                    for (c, v) in t.columns.iter().zip(row) {
                        obj.insert(c.clone(), serde_json::Value::String(v.clone()));
                    }
                    serde_json::Value::Object(obj)
                })
                .collect();
            serde_json::json!({ "title": t.title, "rows": rows })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "generator": "WireForge",
        "tables": list,
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// A self-contained HTML page (no scripts, no external resources).
pub fn to_html(tables: &[Table], heading: &str, generated: &str) -> String {
    let mut out = String::new();
    out.push_str("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n<title>");
    out.push_str(&html_escape(heading));
    out.push_str(
        "</title>\n<style>\n\
         body{font-family:'Segoe UI',system-ui,sans-serif;margin:32px;color:#141f29;background:#f3f6f8}\n\
         h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}\n\
         p.meta{color:#566572;margin:0 0 8px}\n\
         table{border-collapse:collapse;background:#fff;border:1px solid #d9e1e7;border-radius:8px}\n\
         th,td{text-align:left;padding:7px 14px;border-bottom:1px solid #e6ecf0;font-size:14px;vertical-align:top}\n\
         th{color:#566572;font-weight:600;background:#f8fafb}\n\
         tr:last-child td{border-bottom:none}\n\
         </style></head><body>\n<h1>",
    );
    out.push_str(&html_escape(heading));
    out.push_str("</h1>\n<p class=\"meta\">Created by WireForge on ");
    out.push_str(&html_escape(generated));
    out.push_str("</p>\n");
    for t in tables {
        out.push_str("<h2>");
        out.push_str(&html_escape(&t.title));
        out.push_str("</h2>\n<table><thead><tr>");
        for c in &t.columns {
            out.push_str("<th>");
            out.push_str(&html_escape(c));
            out.push_str("</th>");
        }
        out.push_str("</tr></thead><tbody>\n");
        for row in &t.rows {
            out.push_str("<tr>");
            for cell in row {
                out.push_str("<td>");
                out.push_str(&html_escape(cell));
                out.push_str("</td>");
            }
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table>\n");
    }
    out.push_str("</body></html>\n");
    out
}

/// Writes the tables in the format the file name asks for.
pub fn save(tables: &[Table], heading: &str, generated: &str, path: &Path) -> Result<(), String> {
    let text = match Format::from_path(path) {
        Format::Csv => to_csv(tables),
        Format::Html => to_html(tables, heading, generated),
        Format::Json => to_json(tables),
    };
    std::fs::write(path, text).map_err(|e| format!("Could not write the file: {e}"))
}

/// Asks where to save (CSV, HTML or JSON by file type) and writes the file.
/// `Ok(None)` when the user cancelled.
pub fn save_with_dialog(
    tables: &[Table],
    heading: &str,
    default_name: &str,
) -> Result<Option<PathBuf>, String> {
    let picked = rfd::FileDialog::new()
        .set_title(format!("Export: {heading}"))
        .set_file_name(format!("{default_name}.csv"))
        .add_filter("CSV (spreadsheet)", &["csv"])
        .add_filter("HTML (web page)", &["html"])
        .add_filter("JSON", &["json"])
        .save_file();
    let Some(path) = picked else { return Ok(None) };
    let generated = crate::fmt::date_time(crate::sys::now_unix(), crate::sys::utc_offset());
    save(tables, heading, &generated, &path)?;
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(ssid: &str, key: KeyState) -> SavedProfile {
        SavedProfile {
            name: ssid.to_string(),
            ssid: ssid.to_string(),
            security: "WPA2-Personal".into(),
            auto_connect: true,
            key,
            ..Default::default()
        }
    }

    #[test]
    fn masks() {
        assert_eq!(mask_secret(""), "");
        assert_eq!(mask_secret("a"), MASK);
        assert_eq!(mask_secret("a much longer passphrase"), MASK);
        assert_eq!(mask_mac("02:00:5E:10:20:30"), "02:00:5E:xx:xx:xx");
        assert_eq!(mask_mac("02-00-5E-10-20-30"), "02:00:5E:xx:xx:xx");
        assert_eq!(mask_mac("garbage"), "xx:xx:xx:xx:xx:xx");
        assert_eq!(mask_mac(""), "");
        assert_eq!(mask_ip("192.0.2.77"), "192.0.x.x");
        assert_eq!(mask_ip("2001:db8:1:2::9"), "2001:db8:x:x");
        assert_eq!(mask_ip("host"), "x");
        assert_eq!(mask_ip(""), "");
    }

    #[test]
    fn passwords_are_masked_unless_asked_for() {
        let profiles = vec![
            profile("Maple-Home", KeyState::Key("correct horse".into())),
            profile("Cafe", KeyState::Open),
            profile("Office", KeyState::Enterprise),
            profile("Shared", KeyState::NeedsAdmin),
            profile("Odd", KeyState::Unavailable("why".into())),
        ];
        let masked = saved_networks_table(&profiles, false);
        for text in [
            to_csv(std::slice::from_ref(&masked)),
            to_json(std::slice::from_ref(&masked)),
            to_html(std::slice::from_ref(&masked), "Saved", "now"),
        ] {
            assert!(!text.contains("correct horse"));
            assert!(text.contains("Maple-Home"));
        }
        assert_eq!(masked.rows[0][2], MASK);
        assert!(masked.rows[1][2].contains("open network"));
        assert!(masked.rows[2][2].contains("enterprise"));
        assert!(masked.rows[3][2].contains("administrator"));
        assert_eq!(masked.rows[4][2], "(not available)");

        let clear = saved_networks_table(&profiles, true);
        assert_eq!(clear.rows[0][2], "correct horse");
        assert!(to_csv(&[clear]).contains("correct horse"));
    }

    #[test]
    fn csv_quoting_and_formula_guard() {
        let mut t = Table::new("T", &["Name", "Value"]);
        t.push(vec!["plain".into(), "a,b".into()]);
        t.push(vec!["say \"hi\"".into(), "line\nbreak".into()]);
        t.push(vec!["=SUM(A1)".into(), "-5".into()]);
        t.push(vec!["@cmd".into(), "+1+cmd".into()]);
        t.push(vec!["-67 dBm".into(), "+1.5".into()]);
        let csv = to_csv(&[t]);
        assert!(csv.starts_with('\u{feff}'));
        let body = csv.trim_start_matches('\u{feff}');
        let lines: Vec<&str> = body.split("\r\n").collect();
        assert_eq!(lines[0], "Name,Value");
        assert_eq!(lines[1], "plain,\"a,b\"");
        assert_eq!(lines[2], "\"say \"\"hi\"\"\",\"line\nbreak\"");
        assert_eq!(lines[3], "'=SUM(A1),-5");
        assert_eq!(lines[4], "'@cmd,'+1+cmd");
        assert_eq!(lines[5], "-67 dBm,+1.5");
    }

    #[test]
    fn html_and_json_are_escaped() {
        let mut t = Table::new("A <b> & \"c\"", &["<Col>"]);
        t.push(vec!["<script>alert('x')</script>".into()]);
        let html = to_html(std::slice::from_ref(&t), "H & <i>", "2026-01-01");
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"));
        assert!(html.contains("H &amp; &lt;i&gt;"));
        let json = to_json(&[t]);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["tables"][0]["rows"][0]["<Col>"],
            "<script>alert('x')</script>"
        );
    }

    #[test]
    fn format_from_file_name() {
        assert_eq!(Format::from_path(Path::new("a.csv")), Format::Csv);
        assert_eq!(Format::from_path(Path::new("a.HTML")), Format::Html);
        assert_eq!(Format::from_path(Path::new("a.json")), Format::Json);
        assert_eq!(Format::from_path(Path::new("a")), Format::Csv);
    }

    #[test]
    fn several_tables_in_one_csv() {
        let mut a = Table::new("First", &["x"]);
        a.push(vec!["1".into()]);
        let mut b = Table::new("Second", &["y"]);
        b.push(vec!["2".into()]);
        let csv = to_csv(&[a, b]);
        assert_eq!(
            csv.trim_start_matches('\u{feff}'),
            "First\r\nx\r\n1\r\n\r\nSecond\r\ny\r\n2\r\n"
        );
    }
}
