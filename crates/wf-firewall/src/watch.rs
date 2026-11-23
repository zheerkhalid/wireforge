//! New-app alerts: the first time a program makes an internet connection,
//! WireForge asks whether to allow or block it and remembers the answer.
//! The list of known programs is kept in
//! `%LOCALAPPDATA%\WireForge\firewall-apps.json` and can be edited.

use crate::model::{file_name, norm_path};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const FILE: &str = "firewall-apps.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Already connecting when alerts were turned on; never asked.
    Seen,
    Allowed,
    Blocked,
    /// An alert is waiting for an answer.
    Pending,
}

impl Decision {
    pub fn label(self) -> &'static str {
        match self {
            Decision::Seen => "Known",
            Decision::Allowed => "Allowed",
            Decision::Blocked => "Blocked",
            Decision::Pending => "Waiting for you",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownApp {
    pub path: String,
    pub name: String,
    pub first_seen: i64,
    pub decision: Decision,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KnownApps {
    pub apps: Vec<KnownApp>,
    /// The programs connecting when alerts were first turned on were recorded
    /// silently, so turning alerts on does not set off a burst of questions.
    pub baseline_done: bool,
}

/// A program seen in one connection snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub path: String,
    /// The remote end is on the internet (not this PC or the local network).
    pub internet: bool,
}

impl KnownApps {
    pub fn load(dir: &Path) -> KnownApps {
        std::fs::read_to_string(dir.join(FILE))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        let tmp = dir.join(format!("{FILE}.tmp"));
        std::fs::write(&tmp, json).map_err(|e| format!("Could not save the app list: {e}"))?;
        std::fs::rename(&tmp, dir.join(FILE))
            .map_err(|e| format!("Could not save the app list: {e}"))
    }

    pub fn get(&self, path: &str) -> Option<&KnownApp> {
        let n = norm_path(path);
        self.apps.iter().find(|a| norm_path(&a.path) == n)
    }

    pub fn set(&mut self, path: &str, decision: Decision, now: i64) {
        let n = norm_path(path);
        match self.apps.iter_mut().find(|a| norm_path(&a.path) == n) {
            Some(a) => a.decision = decision,
            None => self.apps.push(KnownApp {
                path: path.to_string(),
                name: file_name(path),
                first_seen: now,
                decision,
            }),
        }
    }

    pub fn forget(&mut self, path: &str) {
        let n = norm_path(path);
        self.apps.retain(|a| norm_path(&a.path) != n);
    }

    pub fn pending(&self) -> Vec<&KnownApp> {
        self.apps
            .iter()
            .filter(|a| a.decision == Decision::Pending)
            .collect()
    }

    /// Feeds one connection snapshot. Returns the programs seen on the
    /// internet for the first time (now recorded as pending). The first
    /// call only records a baseline and returns nothing.
    pub fn observe(&mut self, snapshot: &[Seen], now: i64) -> Vec<KnownApp> {
        let fresh = new_programs(self, snapshot);
        if !self.baseline_done {
            self.baseline_done = true;
            for path in fresh {
                self.set(&path, Decision::Seen, now);
            }
            return Vec::new();
        }
        let mut out = Vec::new();
        for path in fresh {
            self.set(&path, Decision::Pending, now);
            if let Some(a) = self.get(&path) {
                out.push(a.clone());
            }
        }
        out
    }
}

/// Programs in the snapshot with an internet connection that the list does
/// not know yet; each once, in first-seen order. Programs without a path
/// (protected system processes) cannot be blocked by path and are skipped.
pub fn new_programs(known: &KnownApps, snapshot: &[Seen]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in snapshot {
        if !s.internet || s.path.trim().is_empty() {
            continue;
        }
        let n = norm_path(&s.path);
        if known.get(&s.path).is_some() || out.iter().any(|o| norm_path(o) == n) {
            continue;
        }
        out.push(s.path.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(path: &str, internet: bool) -> Seen {
        Seen {
            path: path.into(),
            internet,
        }
    }

    #[test]
    fn baseline_then_new_apps_once() {
        let mut k = KnownApps::default();
        let first = vec![seen("C:\\a\\old.exe", true), seen("C:\\a\\lan.exe", false)];
        assert!(k.observe(&first, 1).is_empty(), "the baseline is silent");
        assert_eq!(k.get("c:/A/OLD.exe").unwrap().decision, Decision::Seen);
        assert!(
            k.get("C:\\a\\lan.exe").is_none(),
            "local-only traffic is not recorded"
        );

        let second = vec![
            seen("C:\\a\\old.exe", true),
            seen("C:\\a\\new.exe", true),
            seen("C:\\A\\NEW.EXE", true),
            seen("", true),
            seen("C:\\a\\lan.exe", false),
        ];
        let found = k.observe(&second, 2);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "new.exe");
        assert_eq!(found[0].decision, Decision::Pending);
        assert_eq!(k.pending().len(), 1);
        // Seen again: no second alert.
        assert!(k.observe(&second, 3).is_empty());

        // The answer is remembered; forgetting makes it new again.
        k.set("C:\\a\\new.exe", Decision::Blocked, 4);
        assert!(k.pending().is_empty());
        assert_eq!(k.get("C:\\a\\new.exe").unwrap().first_seen, 2);
        k.forget("C:\\a\\new.exe");
        assert_eq!(k.observe(&second, 5).len(), 1);
    }

    #[test]
    fn list_round_trips() {
        let d = std::env::temp_dir().join(format!("wf-known-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(KnownApps::load(&d), KnownApps::default());
        let mut k = KnownApps::default();
        k.set("C:\\a\\x.exe", Decision::Allowed, 9);
        k.baseline_done = true;
        k.save(&d).unwrap();
        assert_eq!(KnownApps::load(&d), k);
        let _ = std::fs::remove_dir_all(&d);
    }
}
