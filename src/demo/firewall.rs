//! Invented firewall data for `--demo`: an in-memory firewall with a few
//! blocked programs, some rules "from other programs", known apps, a
//! waiting new-app alert and a short journal. Nothing here is read from
//! this PC, and demo mode never touches the real firewall.

use wf_firewall::cli::{Duration, FwCommand};
use wf_firewall::journal::Entry;
use wf_firewall::watch::{Decision, KnownApps};
use wf_firewall::{Direction, FwAction, FwRule, MockFirewall, Profiles};

pub const BLOCKED: [&str; 3] = [
    "C:\\Program Files\\Pixelpatch\\pixelpatch.exe",
    "C:\\Users\\Alex\\AppData\\Local\\Tunebox\\tunebox.exe",
    "C:\\Program Files\\Quillnote\\quillnote-updater.exe",
];

pub const NEW_APP: &str = "C:\\Users\\Alex\\AppData\\Local\\Driftcast\\driftcast.exe";

fn other(name: &str, program: &str, dir: Direction, action: FwAction, group: &str) -> FwRule {
    FwRule {
        name: name.into(),
        group: group.into(),
        program: program.into(),
        direction: dir,
        action,
        protocol: 6,
        profiles: Profiles(6),
        ..Default::default()
    }
}

pub fn firewall(now: i64) -> (MockFirewall, KnownApps, Vec<Entry>) {
    let mut fw = MockFirewall::new();
    fw.rules = vec![
        other(
            "Tunebox (TCP-In)",
            BLOCKED[1],
            Direction::In,
            FwAction::Allow,
            "",
        ),
        other(
            "Tunebox (TCP-Out)",
            BLOCKED[1],
            Direction::Out,
            FwAction::Allow,
            "",
        ),
        other(
            "Lumen Browser (mDNS-In)",
            "C:\\Program Files\\Lumen Browser\\lumen.exe",
            Direction::In,
            FwAction::Allow,
            "Lumen Browser",
        ),
    ];
    let mut journal = Vec::new();
    let steps: [(FwCommand, i64); 3] = [
        (
            FwCommand::Block {
                path: BLOCKED[0].into(),
                duration: Duration::Always,
                inbound: true,
                profiles: Profiles::ALL,
            },
            now - 3 * 86_400 - 5000,
        ),
        (
            FwCommand::Block {
                path: BLOCKED[2].into(),
                duration: Duration::UntilRestart,
                inbound: false,
                profiles: Profiles::ALL,
            },
            now - 5400,
        ),
        (
            FwCommand::Block {
                path: BLOCKED[1].into(),
                duration: Duration::Seconds(3600),
                inbound: false,
                profiles: Profiles(6),
            },
            now - 1080,
        ),
    ];
    let boot = now - 7200;
    for (cmd, at) in steps {
        if let Ok((_, Some(mut e))) = crate::firewall::execute(&mut fw, &cmd, &journal, at, boot) {
            e.id = at as u64 * 1000;
            journal.push(e);
        }
    }
    let mut known = KnownApps {
        baseline_done: true,
        ..Default::default()
    };
    for (path, decision, age) in [
        (
            "C:\\Program Files\\Lumen Browser\\lumen.exe",
            Decision::Allowed,
            40 * 86_400,
        ),
        (
            "C:\\Program Files\\CloudNest\\cloudnest.exe",
            Decision::Seen,
            40 * 86_400,
        ),
        (
            "C:\\Users\\Alex\\AppData\\Local\\Parley\\parley.exe",
            Decision::Allowed,
            12 * 86_400,
        ),
        (BLOCKED[0], Decision::Blocked, 3 * 86_400),
        (BLOCKED[1], Decision::Blocked, 2 * 86_400),
        (NEW_APP, Decision::Pending, 40),
    ] {
        known.set(path, decision, now - age);
    }
    (fw, known, journal)
}

/// The lockdown dialog's list in the screenshot.
pub fn lockdown_candidates() -> Vec<(String, bool)> {
    [
        ("C:\\Program Files\\CloudNest\\cloudnest.exe", false),
        ("C:\\Program Files\\CodeHarbor\\codeharbor.exe", false),
        ("C:\\Program Files\\Lumen Browser\\lumen.exe", true),
        ("C:\\Program Files\\Mailwing\\mailwing.exe", true),
        ("C:\\Users\\Alex\\AppData\\Local\\Parley\\parley.exe", true),
        ("C:\\Program Files\\Tidewave\\tidewave.exe", false),
    ]
    .iter()
    .map(|(p, on)| (p.to_string(), *on))
    .collect()
}
