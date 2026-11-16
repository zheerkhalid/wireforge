//! MAC address helpers and the embedded vendor table.
//!
//! The table is `data/oui.bin`, generated from the IEEE MA-L registry by
//! `examples/gen_oui.rs` (see `data/SOURCE.txt`). Layout, little endian:
//!
//! ```text
//! "WFOUI\x01"            6 bytes
//! prefix count P         u32
//! name count N           u32
//! prefixes               P x 3 bytes, sorted ascending
//! name index per prefix  P x u16
//! name lengths           N x u8
//! names                  UTF-8, back to back
//! ```

use std::sync::OnceLock;

static DATA: &[u8] = include_bytes!("../data/oui.bin");

/// Magic bytes at the start of the table file.
pub const TABLE_MAGIC: &[u8; 6] = b"WFOUI\x01";

struct Table {
    prefixes: &'static [u8],
    indices: &'static [u8],
    names: &'static [u8],
    /// Start of each name inside `names`, plus one final end offset.
    offsets: Vec<u32>,
}

fn read_u32(data: &[u8], at: usize) -> Option<usize> {
    let b = data.get(at..at + 4)?;
    Some(u32::from_le_bytes([*b.first()?, *b.get(1)?, *b.get(2)?, *b.get(3)?]) as usize)
}

fn load(data: &'static [u8]) -> Option<Table> {
    if data.get(..6)? != TABLE_MAGIC {
        return None;
    }
    let count = read_u32(data, 6)?;
    let names_count = read_u32(data, 10)?;
    let prefixes_at = 14usize;
    let indices_at = prefixes_at.checked_add(count.checked_mul(3)?)?;
    let lengths_at = indices_at.checked_add(count.checked_mul(2)?)?;
    let names_at = lengths_at.checked_add(names_count)?;
    let prefixes = data.get(prefixes_at..indices_at)?;
    let indices = data.get(indices_at..lengths_at)?;
    let lengths = data.get(lengths_at..names_at)?;
    let names = data.get(names_at..)?;
    let mut offsets = Vec::with_capacity(names_count + 1);
    let mut at = 0u32;
    offsets.push(0);
    for &len in lengths {
        at = at.checked_add(u32::from(len))?;
        offsets.push(at);
    }
    if at as usize > names.len() {
        return None;
    }
    Some(Table {
        prefixes,
        indices,
        names,
        offsets,
    })
}

fn table() -> Option<&'static Table> {
    static TABLE: OnceLock<Option<Table>> = OnceLock::new();
    TABLE.get_or_init(|| load(DATA)).as_ref()
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The hex digits of a MAC-like text, separators (`:`, `-`, `.`, spaces)
/// dropped. `None` when anything else is in the text.
fn hex_digits(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(12);
    for &b in text.trim().as_bytes() {
        match b {
            b':' | b'-' | b'.' | b' ' => {}
            _ => out.push(hex_value(b)?),
        }
        if out.len() > 12 {
            return None;
        }
    }
    Some(out)
}

/// Parses `AA:BB:CC:DD:EE:FF`, `AA-BB-...` or `aabbccddeeff`.
pub fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let digits = hex_digits(text)?;
    if digits.len() != 12 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (byte, pair) in mac.iter_mut().zip(digits.chunks(2)) {
        *byte = (pair.first()? << 4) | pair.get(1)?;
    }
    Some(mac)
}

/// `AA:BB:CC:DD:EE:FF`
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// The first three bytes of a MAC address or of a bare prefix (`AA:BB:CC`).
fn prefix_of(text: &str) -> Option<[u8; 3]> {
    let digits = hex_digits(text)?;
    if digits.len() != 12 && digits.len() != 6 {
        return None;
    }
    let mut prefix = [0u8; 3];
    for (byte, pair) in prefix.iter_mut().zip(digits.chunks(2)) {
        *byte = (pair.first()? << 4) | pair.get(1)?;
    }
    Some(prefix)
}

/// The vendor that owns a three-byte prefix, when it is in the embedded table.
pub fn vendor_of_prefix(prefix: [u8; 3]) -> Option<&'static str> {
    let table = table()?;
    let count = table.prefixes.len() / 3;
    let (mut lo, mut hi) = (0usize, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let entry = table.prefixes.get(mid * 3..mid * 3 + 3)?;
        match entry.cmp(&prefix[..]) {
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
            std::cmp::Ordering::Equal => {
                let idx = table.indices.get(mid * 2..mid * 2 + 2)?;
                let idx = u16::from_le_bytes([*idx.first()?, *idx.get(1)?]) as usize;
                let start = *table.offsets.get(idx)? as usize;
                let end = *table.offsets.get(idx + 1)? as usize;
                return std::str::from_utf8(table.names.get(start..end)?).ok();
            }
        }
    }
    None
}

/// The vendor that owns the MAC prefix, when it is in the embedded table.
/// Locally administered (randomised) addresses have no vendor. A bare
/// three-byte prefix (`AA:BB:CC`) is accepted as well.
pub fn vendor(mac: &str) -> Option<&'static str> {
    let prefix = prefix_of(mac)?;
    if prefix[0] & 0x02 != 0 {
        return None;
    }
    vendor_of_prefix(prefix)
}

/// Locally administered (private / randomised) address.
pub fn is_random(mac: &str) -> bool {
    prefix_of(mac).is_some_and(|p| p[0] & 0x02 != 0)
}

/// Number of prefixes in the embedded table.
pub fn table_len() -> usize {
    table().map_or(0, |t| t.prefixes.len() / 3)
}

/// Number of distinct vendor names in the embedded table.
pub fn vendor_count() -> usize {
    table().map_or(0, |t| t.offsets.len().saturating_sub(1))
}

/// Longest vendor name kept in the table, in bytes.
pub const MAX_VENDOR_LEN: usize = 32;

/// Legal-form words that say nothing about who made a device.
const SUFFIXES: &[&str] = &[
    "co",
    "ltd",
    "limited",
    "inc",
    "incorporated",
    "corporation",
    "corp",
    "corporate",
    "llc",
    "gmbh",
    "mbh",
    "ag",
    "sa",
    "spa",
    "bv",
    "nv",
    "ab",
    "as",
    "a/s",
    "oy",
    "oyj",
    "plc",
    "pte",
    "pty",
    "kg",
    "srl",
    "sas",
    "kk",
    "company",
    "sro",
    "lp",
    "llp",
    "sdn",
    "bhd",
    "coltd",
    "cokg",
    "&",
    "and",
    "+",
];

fn tidy_case(token: &str, shout_whole_name: bool, lower_whole_name: bool) -> String {
    // Hyphenated names are fixed part by part ("TP-LINK" stays, "HEWLETT-PACKARD" does not).
    token
        .split('-')
        .map(|part| {
            let letters = part.chars().filter(|c| c.is_alphabetic()).count();
            let all_upper = letters > 0 && !part.chars().any(|c| c.is_lowercase());
            let all_lower = letters > 0 && !part.chars().any(|c| c.is_uppercase());
            if (all_upper && letters > 4) || (all_upper && shout_whole_name && letters > 3) {
                title(part)
            } else if all_lower && lower_whole_name {
                if letters <= 3 {
                    part.to_uppercase()
                } else {
                    title(part)
                }
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

fn title(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    let mut first = true;
    for c in word.chars() {
        if c.is_alphabetic() {
            if first {
                out.extend(c.to_uppercase());
                first = false;
            } else {
                out.extend(c.to_lowercase());
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Tidies a registry organisation name for display: legal-form suffixes
/// ("Co., Ltd.", "Inc.", "Corporation") go, shouting names become title case,
/// and the result is at most [`MAX_VENDOR_LEN`] bytes.
pub fn tidy_vendor_name(raw: &str) -> String {
    let mut tokens: Vec<&str> = raw
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
        .collect();
    // Drop legal forms from the end ("Hon Hai Precision Ind. Co.,Ltd." -> "Hon Hai Precision Ind").
    while tokens.len() > 1 {
        let Some(last) = tokens.last() else { break };
        let key: String = last
            .chars()
            .filter(|c| !matches!(c, '.' | '(' | ')'))
            .collect::<String>()
            .to_lowercase();
        if key.is_empty() || SUFFIXES.contains(&key.as_str()) {
            tokens.pop();
        } else {
            break;
        }
    }
    let letters: Vec<char> = tokens
        .iter()
        .flat_map(|t| t.chars())
        .filter(|c| c.is_alphabetic())
        .collect();
    let multi = tokens.len() > 1;
    let shout = multi && !letters.is_empty() && !letters.iter().any(|c| c.is_lowercase());
    let lower = !letters.is_empty() && !letters.iter().any(|c| c.is_uppercase());
    let mut words: Vec<String> = tokens.iter().map(|t| tidy_case(t, shout, lower)).collect();
    // Keep whole words while the name fits.
    let mut name = words.join(" ");
    while name.len() > MAX_VENDOR_LEN && words.len() > 1 {
        words.pop();
        name = words.join(" ");
    }
    if name.len() > MAX_VENDOR_LEN {
        let mut cut = MAX_VENDOR_LEN;
        while cut > 0 && !name.is_char_boundary(cut) {
            cut -= 1;
        }
        name.truncate(cut);
    }
    name.trim_matches(|c: char| c.is_whitespace() || matches!(c, '.' | ',' | '&' | '-' | ';'))
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_the_usual_spellings() {
        let want = Some([0x02, 0x00, 0x5E, 0x10, 0xAB, 0xFF]);
        assert_eq!(parse_mac("02:00:5E:10:AB:FF"), want);
        assert_eq!(parse_mac("02-00-5e-10-ab-ff"), want);
        assert_eq!(parse_mac("02005e10abff"), want);
        assert_eq!(parse_mac("0200.5e10.abff"), want);
        assert_eq!(parse_mac("  02:00:5E:10:AB:FF  "), want);
    }

    #[test]
    fn parse_rejects_nonsense() {
        for text in [
            "",
            "02:00:5E:10:AB",
            "02:00:5E:10:AB:FF:00",
            "02:00:5E:10:AB:GG",
            "hello world!",
            "02005e10abff0",
            "\u{1F600}",
        ] {
            assert_eq!(parse_mac(text), None, "{text:?}");
        }
    }

    #[test]
    fn format_round_trip() {
        let mac = [0x02, 0x00, 0x5E, 0x0A, 0xB0, 0x0F];
        assert_eq!(format_mac(&mac), "02:00:5E:0A:B0:0F");
        assert_eq!(parse_mac(&format_mac(&mac)), Some(mac));
    }

    #[test]
    fn random_bit() {
        assert!(is_random("02:00:5E:10:AB:FF"));
        assert!(is_random("DA:A1:19:00:00:01"));
        assert!(is_random("da-a1-19-00-00-01"));
        assert!(!is_random("00:00:5E:00:53:01"));
        assert!(!is_random("3C:22:FB:00:00:01"));
        assert!(!is_random("not a mac"));
        assert!(!is_random(""));
    }

    #[test]
    fn random_addresses_have_no_vendor() {
        assert_eq!(vendor("02:00:5E:10:AB:FF"), None);
        assert_eq!(vendor("garbage"), None);
    }

    #[test]
    fn table_is_loaded_sorted_and_complete() {
        let t = table();
        assert!(t.is_some(), "embedded table must parse");
        let Some(t) = t else { return };
        let count = t.prefixes.len() / 3;
        assert_eq!(count, table_len());
        assert!(
            count > 1000,
            "the table should hold the registry, got {count}"
        );
        assert!(DATA.len() < 700 * 1024, "table is {} bytes", DATA.len());
        let mut previous: Option<&[u8]> = None;
        for chunk in t.prefixes.chunks(3) {
            if let Some(p) = previous {
                assert!(p < chunk, "prefixes must be strictly ascending");
            }
            previous = Some(chunk);
        }
        // Every prefix resolves to a non-empty, short, valid name.
        for chunk in t.prefixes.chunks(3) {
            let prefix = [chunk[0], chunk[1], chunk[2]];
            let name = vendor_of_prefix(prefix);
            assert!(name.is_some_and(|n| !n.is_empty() && n.len() <= MAX_VENDOR_LEN));
        }
        assert!(vendor_count() > 100);
    }

    #[test]
    fn well_known_prefixes() {
        // Long-standing public registry assignments.
        assert_eq!(vendor("00:00:0C:12:34:56"), Some("Cisco Systems"));
        assert_eq!(vendor("00000c"), Some("Cisco Systems"));
        assert_eq!(vendor("00:03:93:00:00:01"), Some("Apple"));
        assert_eq!(vendor("00:1B:63:00:00:01"), Some("Apple"));
        assert_eq!(vendor("B8:27:EB:00:00:01"), Some("Raspberry Pi Foundation"));
        assert_eq!(vendor("00:50:F2:00:00:01"), Some("Microsoft"));
    }

    #[test]
    fn tidy_names() {
        assert_eq!(tidy_vendor_name("Apple, Inc."), "Apple");
        assert_eq!(tidy_vendor_name("Cisco Systems, Inc"), "Cisco Systems");
        assert_eq!(
            tidy_vendor_name("Samsung Electronics Co.,Ltd"),
            "Samsung Electronics"
        );
        assert_eq!(
            tidy_vendor_name("HUAWEI TECHNOLOGIES CO.,LTD"),
            "Huawei Technologies"
        );
        assert_eq!(tidy_vendor_name("Intel Corporate"), "Intel");
        assert_eq!(tidy_vendor_name("zte corporation"), "ZTE");
        assert_eq!(
            tidy_vendor_name("TP-LINK TECHNOLOGIES CO.,LTD."),
            "TP-Link Technologies"
        );
        assert_eq!(tidy_vendor_name("Espressif Inc."), "Espressif");
        assert_eq!(tidy_vendor_name("Microsoft Corporation"), "Microsoft");
        assert_eq!(tidy_vendor_name("AVM GmbH"), "AVM");
        assert_eq!(tidy_vendor_name("IBM Corp"), "IBM");
        assert_eq!(tidy_vendor_name("NETGEAR"), "Netgear");
        assert_eq!(
            tidy_vendor_name("Hon Hai Precision Ind. Co.,Ltd."),
            "Hon Hai Precision Ind"
        );
        assert_eq!(tidy_vendor_name("  Nokia  "), "Nokia");
        assert_eq!(tidy_vendor_name(""), "");
        assert_eq!(tidy_vendor_name("Ltd"), "Ltd");
    }

    #[test]
    fn tidy_caps_the_length() {
        let long = "Guangdong Example Mobile Telecommunications Equipment Manufacturing Works";
        let name = tidy_vendor_name(long);
        assert!(name.len() <= MAX_VENDOR_LEN);
        assert_eq!(name, "Guangdong Example Mobile");
        let one_word = "X".repeat(80);
        assert_eq!(tidy_vendor_name(&one_word).len(), MAX_VENDOR_LEN);
        // Never cuts inside a multi-byte character.
        let wide = "\u{00e9}".repeat(40);
        assert!(tidy_vendor_name(&wide).len() <= MAX_VENDOR_LEN);
    }
}
