//! Regenerates `data/oui.bin` from the IEEE MA-L registry.
//!
//! 1. Download <https://standards-oui.ieee.org/oui/oui.csv> to a folder
//!    outside the repository.
//! 2. `cargo run -p wf-wifi --example gen_oui -- <path to oui.csv> crates/wf-wifi/data/oui.bin`
//! 3. Update `data/SOURCE.txt` with the date and the counts this prints.
//!
//! The raw CSV is not kept in the repository. The file layout is described at
//! the top of `src/oui.rs`.

use std::collections::BTreeMap;
use std::collections::HashMap;

/// Splits CSV text into records, honouring quoted fields (which may contain
/// commas, doubled quotes and line breaks).
fn csv_records(text: &str) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut record: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    quoted = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            ',' => record.push(std::mem::take(&mut field)),
            '\r' => {}
            '\n' => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    records
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (Some(input), Some(output)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: gen_oui <oui.csv> <oui.bin>");
        std::process::exit(2);
    };
    let text = match std::fs::read(input) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) => {
            eprintln!("cannot read the registry file: {e}");
            std::process::exit(1);
        }
    };

    // prefix -> tidied vendor name (BTreeMap keeps the prefixes sorted).
    let mut by_prefix: BTreeMap<[u8; 3], String> = BTreeMap::new();
    let (mut rows, mut skipped) = (0u32, 0u32);
    for record in csv_records(&text).iter().skip(1) {
        let (Some(registry), Some(assignment), Some(organisation)) =
            (record.first(), record.get(1), record.get(2))
        else {
            continue;
        };
        if registry.trim() != "MA-L" {
            continue;
        }
        rows += 1;
        let Some(mac) = wf_wifi::oui::parse_mac(&format!("{}000000", assignment.trim())) else {
            skipped += 1;
            continue;
        };
        let name = wf_wifi::oui::tidy_vendor_name(organisation);
        // "Private" hides the owner, and blocks held by the IEEE Registration
        // Authority are split among many small vendors: neither names a maker.
        let lower = name.to_lowercase();
        if name.is_empty() || lower == "private" || lower.starts_with("ieee registration") {
            skipped += 1;
            continue;
        }
        by_prefix.insert([mac[0], mac[1], mac[2]], name);
    }

    let mut names: Vec<String> = Vec::new();
    let mut name_index: HashMap<String, u16> = HashMap::new();
    let mut prefixes: Vec<u8> = Vec::with_capacity(by_prefix.len() * 3);
    let mut indices: Vec<u8> = Vec::with_capacity(by_prefix.len() * 2);
    for (prefix, name) in &by_prefix {
        let index = match name_index.get(name) {
            Some(&i) => i,
            None => {
                let Ok(i) = u16::try_from(names.len()) else {
                    eprintln!(
                        "more than 65,535 distinct vendor names: the format needs a wider index"
                    );
                    std::process::exit(1);
                };
                names.push(name.clone());
                name_index.insert(name.clone(), i);
                i
            }
        };
        prefixes.extend_from_slice(prefix);
        indices.extend_from_slice(&index.to_le_bytes());
    }

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(wf_wifi::oui::TABLE_MAGIC);
    out.extend_from_slice(&(by_prefix.len() as u32).to_le_bytes());
    out.extend_from_slice(&(names.len() as u32).to_le_bytes());
    out.extend_from_slice(&prefixes);
    out.extend_from_slice(&indices);
    for name in &names {
        out.push(name.len().min(255) as u8);
    }
    for name in &names {
        out.extend_from_slice(name.as_bytes());
    }
    if let Err(e) = std::fs::write(output, &out) {
        eprintln!("cannot write the table: {e}");
        std::process::exit(1);
    }
    println!(
        "{rows} MA-L rows read, {skipped} skipped (private or registry-held), {} prefixes kept, {} distinct vendor names, {} bytes written",
        by_prefix.len(),
        names.len(),
        out.len()
    );
}
