//! The journal: one JSON line per change WireForge made to the firewall,
//! with every step, so each change can be undone and audited. Stored in
//! `%LOCALAPPDATA%\WireForge\firewall-journal.jsonl`.

use crate::plan::Op;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const FILE: &str = "firewall-journal.jsonl";
/// Older entries are dropped beyond this many.
const KEEP: usize = 500;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Unique: Unix milliseconds when the change was made.
    pub id: u64,
    pub time: i64,
    /// "Blocked example.exe for 1 hour"
    pub summary: String,
    pub ops: Vec<Op>,
    /// Set on the entry that was undone (the undo itself is a new entry).
    #[serde(default)]
    pub undone: bool,
    /// For an undo entry: the id of the entry it reversed.
    #[serde(default)]
    pub undoes: Option<u64>,
}

pub fn path(dir: &Path) -> PathBuf {
    dir.join(FILE)
}

/// All entries, oldest first. Damaged lines are skipped.
pub fn load(dir: &Path) -> Vec<Entry> {
    let text = std::fs::read_to_string(path(dir)).unwrap_or_default();
    let mut list: Vec<Entry> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
        .collect();
    // An undo marks its target as undone.
    let undone: Vec<u64> = list.iter().filter_map(|e| e.undoes).collect();
    for e in &mut list {
        if undone.contains(&e.id) {
            e.undone = true;
        }
    }
    list
}

pub fn append(dir: &Path, entry: &Entry) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("Could not write the journal: {e}"))?;
    let line = serde_json::to_string(entry).map_err(|e| e.to_string())?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path(dir))
        .map_err(|e| format!("Could not write the journal: {e}"))?;
    writeln!(f, "{line}").map_err(|e| format!("Could not write the journal: {e}"))?;
    drop(f);
    trim(dir);
    Ok(())
}

fn trim(dir: &Path) {
    let text = std::fs::read_to_string(path(dir)).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() > KEEP + 50 {
        let keep = lines[lines.len() - KEEP..].join("\n") + "\n";
        let tmp = dir.join(format!("{FILE}.tmp"));
        if std::fs::write(&tmp, keep).is_ok() {
            let _ = std::fs::rename(&tmp, path(dir));
        }
    }
}

/// The newest entry that can still be undone (not undone, not an undo).
pub fn last_undoable(entries: &[Entry]) -> Option<&Entry> {
    entries
        .iter()
        .rev()
        .find(|e| !e.undone && e.undoes.is_none() && !e.ops.is_empty())
}

pub fn find(entries: &[Entry], id: u64) -> Option<&Entry> {
    entries.iter().find(|e| e.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use crate::naming;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wf-journal-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn entry(id: u64) -> Entry {
        Entry {
            id,
            time: id as i64,
            summary: format!("Blocked example.exe ({id})"),
            ops: vec![Op::AddRule(naming::block_rule(
                "C:\\x\\example.exe",
                Direction::Out,
                Profiles::ALL,
                Lifetime::Always,
                1,
            ))],
            undone: false,
            undoes: None,
        }
    }

    #[test]
    fn append_load_and_undo_marks() {
        let d = dir("basic");
        assert!(load(&d).is_empty());
        append(&d, &entry(1)).unwrap();
        append(&d, &entry(2)).unwrap();
        // A damaged line does not lose the rest.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(path(&d))
            .unwrap();
        writeln!(f, "{{not json").unwrap();
        drop(f);
        let list = load(&d);
        assert_eq!(list.len(), 2);
        assert_eq!(last_undoable(&list).unwrap().id, 2);
        let undo = Entry {
            id: 3,
            summary: "Undo".into(),
            undoes: Some(2),
            ..entry(3)
        };
        append(&d, &undo).unwrap();
        let list = load(&d);
        assert!(find(&list, 2).unwrap().undone);
        assert_eq!(last_undoable(&list).unwrap().id, 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn journal_is_trimmed() {
        let d = dir("trim");
        for i in 0..(KEEP as u64 + 60) {
            append(&d, &entry(i)).unwrap();
        }
        let list = load(&d);
        assert!(list.len() <= KEEP + 50);
        assert_eq!(list.last().unwrap().id, KEEP as u64 + 59);
        let _ = std::fs::remove_dir_all(&d);
    }
}
