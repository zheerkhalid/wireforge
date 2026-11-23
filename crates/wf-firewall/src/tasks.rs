//! Temporary blocks end through a scheduled task that Windows runs once:
//! at the expiry time ("for 1 hour") or at the next start ("until restart").
//!
//! The task runs only programs from `System32` (`netsh.exe` to delete the
//! rules, then `schtasks.exe` to delete the task itself), never
//! WireForge.exe: a per-user install folder is writable without
//! administrator rights, so running it from a SYSTEM task would hand out
//! administrator rights to anything that can replace the file.

use serde::{Deserialize, Serialize};

/// One scheduled removal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expiry {
    /// `\WireForge\Unblock <id>`
    pub task: String,
    /// The rules to delete.
    pub rules: Vec<String>,
    /// Unix time; `None` = at the next Windows start.
    pub at: Option<i64>,
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// `2026-11-24T15:04:05Z` for a Unix time.
pub fn iso_utc(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// The task definition (Task Scheduler XML schema 1.2).
pub fn task_xml(e: &Expiry) -> String {
    let trigger = match e.at {
        Some(t) => format!(
            "<TimeTrigger><StartBoundary>{}</StartBoundary><Enabled>true</Enabled></TimeTrigger>",
            iso_utc(t)
        ),
        None => "<BootTrigger><Enabled>true</Enabled></BootTrigger>".to_string(),
    };
    let mut actions = String::new();
    for rule in &e.rules {
        actions.push_str(&format!(
            "<Exec><Command>%SystemRoot%\\System32\\netsh.exe</Command>\
             <Arguments>{}</Arguments></Exec>",
            xml_escape(&format!("advfirewall firewall delete rule name=\"{rule}\""))
        ));
    }
    actions.push_str(&format!(
        "<Exec><Command>%SystemRoot%\\System32\\schtasks.exe</Command>\
         <Arguments>{}</Arguments></Exec>",
        xml_escape(&format!("/Delete /TN \"{}\" /F", e.task))
    ));
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n\
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\
<RegistrationInfo><Author>WireForge</Author><Description>Ends a temporary WireForge firewall block.</Description></RegistrationInfo>\
<Triggers>{trigger}</Triggers>\
<Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>\
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\
<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\
<StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT10M</ExecutionTimeLimit>\
<Enabled>true</Enabled><Hidden>false</Hidden></Settings>\
<Actions Context=\"Author\">{actions}</Actions></Task>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_times() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(1_764_000_000), "2025-11-24T16:00:00Z");
        assert_eq!(iso_utc(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn task_runs_only_system_programs() {
        let e = Expiry {
            task: "\\WireForge\\Unblock 0badc0de".into(),
            rules: vec![
                "WireForge: block a&b.exe (outgoing) #0badc0de".into(),
                "WireForge: block a&b.exe (incoming) #0badc0de".into(),
            ],
            at: Some(1_764_000_000),
        };
        let xml = task_xml(&e);
        assert!(xml.contains("<StartBoundary>2025-11-24T16:00:00Z</StartBoundary>"));
        assert!(xml.contains("a&amp;b.exe"));
        assert!(!xml.contains("a&b"));
        assert_eq!(xml.matches("netsh.exe").count(), 2);
        assert_eq!(xml.matches("<Exec>").count(), 3);
        assert!(xml.contains("/Delete /TN &quot;\\WireForge\\Unblock 0badc0de&quot; /F"));
        assert!(!xml.to_lowercase().contains("wireforge.exe"));
        assert!(xml.contains("<UserId>S-1-5-18</UserId>"));
        let boot = task_xml(&Expiry { at: None, ..e });
        assert!(boot.contains("<BootTrigger>") && !boot.contains("TimeTrigger"));
    }
}
