//! The app firewall glue: runs a firewall command (in this process when it
//! already has administrator rights, otherwise through an elevated copy of
//! WireForge.exe started for that one command), records it in the journal,
//! and implements `--fw-list` and friends on the command line.

use crate::sys;
use std::path::{Path, PathBuf};
use wf_firewall::cli::{self, Duration, FwCommand, Invocation};
use wf_firewall::journal::{self, Entry};
use wf_firewall::plan::{self, BlockOptions, Op};
use wf_firewall::{naming, BlockedApp, FirewallApi, FwRule, FwStatus, Lifetime, Lockdown};

/// Everything the Firewall page shows, read in one go (no rights needed).
#[derive(Clone, Debug, Default)]
pub struct FwView {
    pub status: FwStatus,
    pub rules: Vec<FwRule>,
    pub blocked: Vec<BlockedApp>,
    pub lockdown: Option<Lockdown>,
    /// When Windows last started (Unix time).
    pub boot: i64,
}

impl FwView {
    pub fn from(status: FwStatus, rules: Vec<FwRule>, boot: i64) -> FwView {
        FwView {
            blocked: naming::blocked_apps(&rules),
            lockdown: naming::lockdown(&rules),
            status,
            rules,
            boot,
        }
    }

    pub fn blocked(&self, path: &str) -> Option<&BlockedApp> {
        if path.is_empty() {
            return None;
        }
        self.blocked
            .iter()
            .find(|a| wf_firewall::same_path(&a.path, path))
    }
}

/// Reads the real firewall.
pub fn read_view() -> Result<FwView, String> {
    let fw = wf_firewall::com::ComFirewall::open()?;
    let now = sys::now_unix();
    Ok(FwView::from(
        fw.status()?,
        fw.rules()?,
        wf_firewall::com::boot_time(now),
    ))
}

fn duration_text(d: Duration) -> String {
    match d {
        Duration::Always => "always".into(),
        Duration::UntilRestart => "until restart".into(),
        Duration::Seconds(s) if s % 3600 == 0 && s / 3600 == 1 => "for 1 hour".into(),
        Duration::Seconds(s) if s % 3600 == 0 => format!("for {} hours", s / 3600),
        Duration::Seconds(s) => format!("for {} minutes", s / 60),
    }
}

/// Plans and applies one command. Returns a message for the user and the
/// journal entry to record (none for read-only commands or no-ops).
pub fn execute(
    api: &mut dyn FirewallApi,
    command: &FwCommand,
    journal: &[Entry],
    now: i64,
    boot: i64,
) -> Result<(String, Option<Entry>), String> {
    let rules = api.rules()?;
    let status = api.status()?;
    let name = |p: &str| wf_firewall::file_name(p);
    let (ops, summary, undoes): (Vec<Op>, String, Option<u64>) = match command {
        FwCommand::List => return Ok((list_text(&FwView::from(status, rules, boot), now), None)),
        FwCommand::Block {
            path,
            duration,
            inbound,
            profiles,
        } => {
            let lifetime = match duration {
                Duration::Always => Lifetime::Always,
                Duration::Seconds(s) => Lifetime::Until(now + s),
                Duration::UntilRestart => Lifetime::UntilRestart { boot },
            };
            let opts = BlockOptions {
                lifetime,
                inbound: *inbound,
                profiles: *profiles,
            };
            let ops = plan::plan_block(&rules, path, opts, now)?;
            let dirs = if *inbound {
                "outgoing and incoming"
            } else {
                "outgoing"
            };
            (
                ops,
                format!(
                    "Blocked {} ({dirs}, {}, {})",
                    name(path),
                    duration_text(*duration),
                    profiles.label().to_lowercase()
                ),
                None,
            )
        }
        FwCommand::Unblock { path } => (
            plan::plan_unblock(&rules, path)?,
            format!("Unblocked {}", name(path)),
            None,
        ),
        FwCommand::Expire => (
            plan::plan_expire(&rules, now, boot),
            "Removed blocks whose time was up".into(),
            None,
        ),
        FwCommand::RemoveAll => (
            plan::plan_remove_all(&status, &rules),
            "Removed all WireForge rules".into(),
            None,
        ),
        FwCommand::LockdownOn { allow } => (
            plan::plan_lockdown_on(&status, &rules, allow, now)?,
            format!("Started lockdown ({} programs allowed)", allow.len()),
            None,
        ),
        FwCommand::LockdownOff => (
            plan::plan_lockdown_off(&status, &rules)?,
            "Ended lockdown and restored the previous settings".into(),
            None,
        ),
        FwCommand::Allow { path } => (
            plan::plan_allow(&rules, path, now)?,
            format!("Allowed {} during lockdown", name(path)),
            None,
        ),
        FwCommand::Disallow { path } => (
            plan::plan_disallow(&rules, path)?,
            format!("Removed {} from the lockdown allow list", name(path)),
            None,
        ),
        FwCommand::Undo { id } => {
            let entry = journal::find(journal, *id).ok_or("That change is not in the journal.")?;
            if entry.undone {
                return Err("That change was already undone.".into());
            }
            (
                plan::undo_ops(&entry.ops, now, boot),
                format!("Undid: {}", entry.summary),
                Some(entry.id),
            )
        }
    };
    if ops.is_empty() {
        return Ok(("Nothing needed to change.".into(), None));
    }
    plan::apply(api, &ops)?;
    let entry = Entry {
        id: (now.max(0) as u64) * 1000 + (std::process::id() as u64 % 1000),
        time: now,
        summary: summary.clone(),
        ops,
        undone: false,
        undoes,
    };
    Ok((format!("{summary}."), Some(entry)))
}

pub fn lifetime_text(l: Lifetime, now: i64) -> String {
    match l {
        Lifetime::Always => "Always".into(),
        Lifetime::UntilRestart { .. } => "Until restart".into(),
        Lifetime::Until(t) if t <= now => "Time is up".into(),
        Lifetime::Until(t) => {
            let left = t - now;
            if left >= 3600 {
                format!("{} h {:02} min left", left / 3600, (left % 3600) / 60)
            } else if left >= 60 {
                format!("{} min left", left / 60 + i64::from(left % 60 != 0))
            } else {
                format!("{left} s left")
            }
        }
    }
}

/// The text `--fw-list` prints.
pub fn list_text(v: &FwView, now: i64) -> String {
    let mut s = String::from("Windows Defender Firewall\n");
    for p in &v.status.profiles {
        s.push_str(&format!(
            "  {:<8} {}  incoming: {}  outgoing: {}{}\n",
            p.profile.label(),
            if p.enabled { "on " } else { "OFF" },
            p.default_in.label().to_lowercase(),
            p.default_out.label().to_lowercase(),
            if p.active { "  (connected)" } else { "" }
        ));
    }
    if let Some(l) = &v.lockdown {
        s.push_str(&format!(
            "\nLockdown is ON: outgoing connections are blocked except for {} allowed programs.\n\
             End it with: WireForge.exe --fw-lockdown off\n",
            l.allowed.len()
        ));
    }
    s.push_str(&format!("\nBlocked by WireForge: {}\n", v.blocked.len()));
    for a in &v.blocked {
        s.push_str(&format!(
            "  {}  [{}{}; {}; {}]\n",
            a.path,
            if a.outbound { "out" } else { "" },
            if a.inbound { ", in" } else { "" },
            a.profiles.label().to_lowercase(),
            lifetime_text(a.lifetime, now).to_lowercase()
        ));
    }
    s
}

/// The command line entry point (`WireForge.exe --fw-...`). Returns the exit code.
pub fn run_cli(inv: Invocation) -> i32 {
    let data_dir = inv
        .data_dir
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(crate::settings::data_dir);
    let result = (|| {
        let mut fw = wf_firewall::com::ComFirewall::open()?;
        if inv.command.changes() && !sys::is_elevated() {
            return Err(
                "Changing the firewall needs administrator rights. Run this from an \
                        administrator terminal, or use the Firewall page in WireForge."
                    .to_string(),
            );
        }
        let now = sys::now_unix();
        let entries = journal::load(&data_dir);
        let (msg, entry) = execute(
            &mut fw,
            &inv.command,
            &entries,
            now,
            wf_firewall::com::boot_time(now),
        )?;
        if let Some(e) = entry {
            if let Err(err) = journal::append(&data_dir, &e) {
                return Ok(format!("{msg} (The journal could not be written: {err})"));
            }
        }
        Ok(msg)
    })();
    let (code, msg) = match result {
        Ok(m) => (0, m),
        Err(e) => (1, e),
    };
    if let Some(f) = &inv.result_file {
        let _ = std::fs::write(f, &msg);
    }
    if code == 0 {
        println!("{msg}");
    } else {
        eprintln!("{msg}");
    }
    code
}

/// Starts `WireForge.exe <command>` with administrator rights (one UAC
/// prompt), waits for it and returns its message.
pub fn run_elevated(command: FwCommand, data_dir: &Path) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let result_file = std::env::temp_dir().join(format!(
        "wireforge-fw-{}-{}.txt",
        std::process::id(),
        sys::now_unix()
    ));
    let _ = std::fs::remove_file(&result_file);
    let inv = Invocation {
        command,
        data_dir: Some(data_dir.to_string_lossy().into_owned()),
        result_file: Some(result_file.to_string_lossy().into_owned()),
    };
    let code = sys::run_elevated_and_wait(&exe.to_string_lossy(), &cli::command_line(&inv))?;
    let msg = std::fs::read_to_string(&result_file).unwrap_or_default();
    let _ = std::fs::remove_file(&result_file);
    match code {
        0 => Ok(if msg.trim().is_empty() {
            "Done.".into()
        } else {
            msg.trim().to_string()
        }),
        _ if msg.trim().is_empty() => Err(format!(
            "The firewall change did not complete (code {code}). Nothing was changed."
        )),
        _ => Err(msg.trim().to_string()),
    }
}

/// Runs a change: directly when WireForge already runs as administrator,
/// otherwise through the elevated helper.
pub fn change(command: FwCommand, data_dir: &Path) -> Result<String, String> {
    if !sys::is_elevated() {
        return run_elevated(command, data_dir);
    }
    let mut fw = wf_firewall::com::ComFirewall::open()?;
    let now = sys::now_unix();
    let entries = journal::load(data_dir);
    let (msg, entry) = execute(
        &mut fw,
        &command,
        &entries,
        now,
        wf_firewall::com::boot_time(now),
    )?;
    if let Some(e) = entry {
        let _ = journal::append(data_dir, &e);
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wf_firewall::{MockFirewall, Profiles};

    const P: &str = "C:\\Program Files\\Example\\example.exe";

    #[test]
    fn execute_records_and_undoes() {
        let mut fw = MockFirewall::new();
        let mut journal: Vec<Entry> = Vec::new();
        let block = FwCommand::Block {
            path: P.into(),
            duration: Duration::Seconds(3600),
            inbound: true,
            profiles: Profiles::ALL,
        };
        let (msg, entry) = execute(&mut fw, &block, &journal, 1000, 1).unwrap();
        assert_eq!(
            msg,
            "Blocked example.exe (outgoing and incoming, for 1 hour, all networks)."
        );
        let entry = entry.unwrap();
        journal.push(entry.clone());
        assert_eq!(fw.rules.len(), 2);
        assert_eq!(fw.tasks.len(), 1);
        assert_eq!(fw.tasks[0].at, Some(4600));

        let (_, undo) = execute(
            &mut fw,
            &FwCommand::Undo { id: entry.id },
            &journal,
            1100,
            1,
        )
        .unwrap();
        let undo = undo.unwrap();
        assert_eq!(undo.undoes, Some(entry.id));
        assert!(fw.rules.is_empty() && fw.tasks.is_empty());
        journal[0].undone = true;
        assert!(execute(
            &mut fw,
            &FwCommand::Undo { id: entry.id },
            &journal,
            1200,
            1
        )
        .is_err());
        assert!(execute(&mut fw, &FwCommand::Undo { id: 7 }, &journal, 1200, 1).is_err());
    }

    #[test]
    fn lockdown_through_commands() {
        let mut fw = MockFirewall::new();
        let before = fw.status.clone();
        let (_, e) = execute(
            &mut fw,
            &FwCommand::LockdownOn {
                allow: vec![P.into()],
            },
            &[],
            10,
            1,
        )
        .unwrap();
        assert!(e.is_some());
        let view = FwView::from(fw.status.clone(), fw.rules.clone(), 1);
        assert!(view.lockdown.is_some());
        assert!(list_text(&view, 10).contains("Lockdown is ON"));
        execute(&mut fw, &FwCommand::LockdownOff, &[], 11, 1).unwrap();
        assert_eq!(fw.status, before);
        let (msg, e) = execute(&mut fw, &FwCommand::RemoveAll, &[], 12, 1).unwrap();
        assert_eq!(msg, "Nothing needed to change.");
        assert!(e.is_none());
    }

    #[test]
    fn list_and_lifetimes() {
        let mut fw = MockFirewall::new();
        execute(
            &mut fw,
            &FwCommand::Block {
                path: P.into(),
                duration: Duration::UntilRestart,
                inbound: false,
                profiles: Profiles(4),
            },
            &[],
            50,
            1,
        )
        .unwrap();
        let (text, entry) = execute(&mut fw, &FwCommand::List, &[], 60, 1).unwrap();
        assert!(entry.is_none());
        assert!(text.contains("Blocked by WireForge: 1"));
        assert!(text.contains("[out; public; until restart]"));
        assert_eq!(lifetime_text(Lifetime::Until(100), 40), "1 min left");
        assert_eq!(lifetime_text(Lifetime::Until(10_000), 0), "2 h 46 min left");
        assert_eq!(lifetime_text(Lifetime::Until(10), 20), "Time is up");
        assert_eq!(lifetime_text(Lifetime::Until(30), 0), "30 s left");
    }
}
