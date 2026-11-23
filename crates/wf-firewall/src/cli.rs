//! The firewall command line. The window never runs as administrator;
//! each change starts `WireForge.exe` elevated (one UAC prompt) with exactly
//! one of these narrow commands. They also work from a terminal.
//!
//! ```text
//! --fw-block <exe> [--for 1h | --until-restart] [--inbound] [--profiles all|domain,private,public]
//! --fw-unblock <exe>
//! --fw-list
//! --fw-lockdown on [--allow <exe>]...  |  --fw-lockdown off
//! --fw-allow <exe>   --fw-disallow <exe>
//! --fw-undo <journal id>   --fw-expire   --fw-remove-all
//! common: [--data-dir <folder>] [--result <file>]
//! ```

use crate::model::Profiles;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Duration {
    Always,
    Seconds(i64),
    UntilRestart,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FwCommand {
    Block {
        path: String,
        duration: Duration,
        inbound: bool,
        profiles: Profiles,
    },
    Unblock {
        path: String,
    },
    List,
    RemoveAll,
    Expire,
    LockdownOn {
        allow: Vec<String>,
    },
    LockdownOff,
    Allow {
        path: String,
    },
    Disallow {
        path: String,
    },
    Undo {
        id: u64,
    },
}

impl FwCommand {
    /// Whether the command changes the firewall (and so needs administrator rights).
    pub fn changes(&self) -> bool {
        !matches!(self, FwCommand::List)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    pub command: FwCommand,
    /// Where the journal goes (the caller's `%LOCALAPPDATA%\WireForge`).
    pub data_dir: Option<String>,
    /// A file that receives a one-line result for the window that asked.
    pub result_file: Option<String>,
}

/// Refuses anything that is not a plain, absolute path to an `.exe`.
pub fn check_program_path(path: &str) -> Result<(), String> {
    let p = path.trim();
    let bad = || Err(format!("Not a full path to a program: {p}"));
    if p.is_empty() || p.len() > 1024 {
        return bad();
    }
    if p.chars()
        .any(|c| c.is_control() || matches!(c, '"' | '*' | '?' | '<' | '>' | '|'))
    {
        return bad();
    }
    let b = p.as_bytes();
    let drive = b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    let unc = p.starts_with("\\\\") && p.len() > 4;
    if !(drive || unc) {
        return bad();
    }
    if p.split('\\').any(|part| part == "..") {
        return bad();
    }
    if !p.to_ascii_lowercase().ends_with(".exe") {
        return Err(format!("Only programs (.exe files) can be blocked: {p}"));
    }
    Ok(())
}

/// `1h`, `30m`, `90s`, `2d` or plain seconds; one minute to 30 days.
pub fn parse_duration(text: &str) -> Result<i64, String> {
    let t = text.trim().to_ascii_lowercase();
    let (num, mul) = match t.chars().last() {
        Some('s') => (&t[..t.len() - 1], 1),
        Some('m') => (&t[..t.len() - 1], 60),
        Some('h') => (&t[..t.len() - 1], 3600),
        Some('d') => (&t[..t.len() - 1], 86_400),
        _ => (t.as_str(), 1),
    };
    let n: i64 = num
        .trim()
        .parse()
        .map_err(|_| format!("Not a duration: '{text}' (use 1h, 30m or 2d)."))?;
    let secs = n.saturating_mul(mul);
    if !(60..=30 * 86_400).contains(&secs) {
        return Err("A temporary block lasts from one minute to 30 days.".into());
    }
    Ok(secs)
}

/// Parses the arguments. `None` when they contain no firewall command.
pub fn parse(args: &[String]) -> Option<Result<Invocation, String>> {
    if !args.iter().any(|a| a.starts_with("--fw-")) {
        return None;
    }
    Some(parse_inner(args))
}

fn parse_inner(args: &[String]) -> Result<Invocation, String> {
    let mut command: Option<FwCommand> = None;
    let mut data_dir = None;
    let mut result_file = None;
    let mut duration = Duration::Always;
    let mut inbound = false;
    let mut profiles = Profiles::ALL;
    let mut allow: Vec<String> = Vec::new();
    let mut i = 0;
    let set = |c: FwCommand, command: &mut Option<FwCommand>| -> Result<(), String> {
        if command.is_some() {
            return Err("Give one firewall command at a time.".into());
        }
        *command = Some(c);
        Ok(())
    };
    while i < args.len() {
        let a = args[i].as_str();
        let mut value = |what: &str| -> Result<String, String> {
            i += 1;
            args.get(i)
                .filter(|v| !v.starts_with("--"))
                .cloned()
                .ok_or_else(|| format!("{a} needs {what}."))
        };
        match a {
            "--fw-block" => {
                let path = value("a program path")?;
                check_program_path(&path)?;
                set(
                    FwCommand::Block {
                        path,
                        duration: Duration::Always,
                        inbound: false,
                        profiles: Profiles::ALL,
                    },
                    &mut command,
                )?;
            }
            "--fw-unblock" | "--fw-allow" | "--fw-disallow" => {
                let path = value("a program path")?;
                check_program_path(&path)?;
                let c = match a {
                    "--fw-unblock" => FwCommand::Unblock { path },
                    "--fw-allow" => FwCommand::Allow { path },
                    _ => FwCommand::Disallow { path },
                };
                set(c, &mut command)?;
            }
            "--fw-list" => set(FwCommand::List, &mut command)?,
            "--fw-remove-all" => set(FwCommand::RemoveAll, &mut command)?,
            "--fw-expire" => set(FwCommand::Expire, &mut command)?,
            "--fw-lockdown" => {
                let v = value("on or off")?;
                let c = match v.to_ascii_lowercase().as_str() {
                    "on" => FwCommand::LockdownOn { allow: Vec::new() },
                    "off" => FwCommand::LockdownOff,
                    _ => return Err("--fw-lockdown takes on or off.".into()),
                };
                set(c, &mut command)?;
            }
            "--fw-undo" => {
                let v = value("a journal id")?;
                let id = v
                    .parse::<u64>()
                    .map_err(|_| format!("Not a journal id: {v}"))?;
                set(FwCommand::Undo { id }, &mut command)?;
            }
            "--for" => duration = Duration::Seconds(parse_duration(&value("a duration")?)?),
            "--until-restart" => duration = Duration::UntilRestart,
            "--inbound" => inbound = true,
            "--profiles" => profiles = Profiles::parse(&value("profiles")?)?,
            "--allow" => {
                let p = value("a program path")?;
                check_program_path(&p)?;
                allow.push(p);
            }
            "--data-dir" => data_dir = Some(value("a folder")?),
            "--result" => result_file = Some(value("a file")?),
            other => return Err(format!("Unknown option for a firewall command: {other}")),
        }
        i += 1;
    }
    let mut command = command.ok_or("No firewall command given.")?;
    let block_opts = duration != Duration::Always || inbound || profiles != Profiles::ALL;
    match &mut command {
        FwCommand::Block {
            duration: d,
            inbound: inb,
            profiles: p,
            ..
        } => {
            *d = duration;
            *inb = inbound;
            *p = profiles;
        }
        _ if block_opts => {
            return Err(
                "--for, --until-restart, --inbound and --profiles go with --fw-block.".into(),
            )
        }
        FwCommand::LockdownOn { allow: list } => *list = allow,
        _ if !allow.is_empty() => return Err("--allow goes with --fw-lockdown on.".into()),
        _ => {}
    }
    Ok(Invocation {
        command,
        data_dir,
        result_file,
    })
}

/// Quotes one argument the way `CommandLineToArgvW` reads it back.
pub fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// The argument list for an invocation (the inverse of [`parse`]).
pub fn to_args(inv: &Invocation) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    match &inv.command {
        FwCommand::Block {
            path,
            duration,
            inbound,
            profiles,
        } => {
            v.extend(["--fw-block".into(), path.clone()]);
            match duration {
                Duration::Always => {}
                Duration::Seconds(s) => v.extend(["--for".into(), s.to_string()]),
                Duration::UntilRestart => v.push("--until-restart".into()),
            }
            if *inbound {
                v.push("--inbound".into());
            }
            if *profiles != Profiles::ALL {
                v.extend(["--profiles".into(), profiles.arg()]);
            }
        }
        FwCommand::Unblock { path } => v.extend(["--fw-unblock".into(), path.clone()]),
        FwCommand::Allow { path } => v.extend(["--fw-allow".into(), path.clone()]),
        FwCommand::Disallow { path } => v.extend(["--fw-disallow".into(), path.clone()]),
        FwCommand::List => v.push("--fw-list".into()),
        FwCommand::RemoveAll => v.push("--fw-remove-all".into()),
        FwCommand::Expire => v.push("--fw-expire".into()),
        FwCommand::LockdownOn { allow } => {
            v.extend(["--fw-lockdown".into(), "on".into()]);
            for a in allow {
                v.extend(["--allow".into(), a.clone()]);
            }
        }
        FwCommand::LockdownOff => v.extend(["--fw-lockdown".into(), "off".into()]),
        FwCommand::Undo { id } => v.extend(["--fw-undo".into(), id.to_string()]),
    }
    if let Some(d) = &inv.data_dir {
        v.extend(["--data-dir".into(), d.clone()]);
    }
    if let Some(r) = &inv.result_file {
        v.extend(["--result".into(), r.clone()]);
    }
    v
}

/// One command-line string for `ShellExecuteExW`.
pub fn command_line(inv: &Invocation) -> String {
    to_args(inv)
        .iter()
        .map(|a| quote_arg(a))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    const P: &str = "C:\\Program Files\\Example\\example.exe";

    #[test]
    fn not_a_firewall_command() {
        assert!(parse(&args(&["--demo", "--view", "apps"])).is_none());
    }

    #[test]
    fn block_variants() {
        let inv = parse(&args(&["--fw-block", P])).unwrap().unwrap();
        assert_eq!(
            inv.command,
            FwCommand::Block {
                path: P.into(),
                duration: Duration::Always,
                inbound: false,
                profiles: Profiles::ALL
            }
        );
        let inv = parse(&args(&[
            "--fw-block",
            P,
            "--for",
            "1h",
            "--inbound",
            "--profiles",
            "public",
            "--data-dir",
            "C:\\Users\\Alex\\AppData\\Local\\WireForge",
            "--result",
            "C:\\t\\r.txt",
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(
            inv.command,
            FwCommand::Block {
                path: P.into(),
                duration: Duration::Seconds(3600),
                inbound: true,
                profiles: Profiles(4)
            }
        );
        assert_eq!(inv.result_file.as_deref(), Some("C:\\t\\r.txt"));
        let inv = parse(&args(&["--fw-block", P, "--until-restart"]))
            .unwrap()
            .unwrap();
        assert!(matches!(
            inv.command,
            FwCommand::Block {
                duration: Duration::UntilRestart,
                ..
            }
        ));
    }

    #[test]
    fn narrow_and_strict() {
        let err = |a: &[&str]| parse(&args(a)).unwrap().unwrap_err();
        err(&["--fw-block"]);
        err(&["--fw-block", "--inbound"]);
        err(&["--fw-block", "example.exe"]);
        err(&["--fw-block", "C:\\x\\notes.txt"]);
        err(&["--fw-block", "C:\\x\\..\\y.exe"]);
        err(&["--fw-block", "C:\\x\\a\"b.exe"]);
        err(&["--fw-block", "C:\\x\\*.exe"]);
        err(&["--fw-block", P, "--fw-unblock", P]);
        err(&["--fw-block", P, "--delete-everything"]);
        err(&["--fw-block", P, "--for", "5s"]);
        err(&["--fw-block", P, "--for", "90d"]);
        err(&["--fw-block", P, "--profiles", "office"]);
        err(&["--fw-unblock", P, "--inbound"]);
        err(&["--fw-list", "--allow", P]);
        err(&["--fw-lockdown", "maybe"]);
        err(&["--fw-undo", "abc"]);
        assert!(check_program_path("\\\\server\\share\\tool.exe").is_ok());
        assert!(check_program_path("D:\\Tools\\TOOL.EXE").is_ok());
    }

    #[test]
    fn other_commands() {
        let c = |a: &[&str]| parse(&args(a)).unwrap().unwrap().command;
        assert_eq!(c(&["--fw-list"]), FwCommand::List);
        assert!(!FwCommand::List.changes());
        assert_eq!(
            c(&["--fw-unblock", P]),
            FwCommand::Unblock { path: P.into() }
        );
        assert_eq!(c(&["--fw-remove-all"]), FwCommand::RemoveAll);
        assert_eq!(c(&["--fw-expire"]), FwCommand::Expire);
        assert_eq!(c(&["--fw-lockdown", "OFF"]), FwCommand::LockdownOff);
        assert_eq!(
            c(&["--fw-lockdown", "on", "--allow", P, "--allow", "D:\\b.exe"]),
            FwCommand::LockdownOn {
                allow: vec![P.into(), "D:\\b.exe".into()]
            }
        );
        assert_eq!(
            c(&["--fw-undo", "1764000000123"]),
            FwCommand::Undo { id: 1764000000123 }
        );
        assert_eq!(c(&["--fw-allow", P]), FwCommand::Allow { path: P.into() });
        assert_eq!(
            c(&["--fw-disallow", P]),
            FwCommand::Disallow { path: P.into() }
        );
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("1h").unwrap(), 3600);
        assert_eq!(parse_duration("30m").unwrap(), 1800);
        assert_eq!(parse_duration("2d").unwrap(), 172_800);
        assert_eq!(parse_duration("600").unwrap(), 600);
        assert!(parse_duration("59s").is_err());
        assert!(parse_duration("soon").is_err());
    }

    #[test]
    fn arguments_round_trip() {
        for inv in [
            Invocation {
                command: FwCommand::Block {
                    path: P.into(),
                    duration: Duration::Seconds(3600),
                    inbound: true,
                    profiles: Profiles(6),
                },
                data_dir: Some("C:\\Users\\Alex\\AppData\\Local\\WireForge".into()),
                result_file: Some("C:\\Temp\\wf result.txt".into()),
            },
            Invocation {
                command: FwCommand::LockdownOn {
                    allow: vec![P.into()],
                },
                data_dir: None,
                result_file: None,
            },
            Invocation {
                command: FwCommand::Undo { id: 42 },
                data_dir: None,
                result_file: None,
            },
        ] {
            let back = parse(&to_args(&inv)).unwrap().unwrap();
            assert_eq!(back, inv);
        }
    }

    #[test]
    fn quoting() {
        assert_eq!(quote_arg("--fw-list"), "--fw-list");
        assert_eq!(quote_arg(P), format!("\"{P}\""));
        assert_eq!(quote_arg("C:\\a b\\"), "\"C:\\a b\\\\\"");
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("a\"b c"), "\"a\\\"b c\"");
        let inv = Invocation {
            command: FwCommand::Unblock { path: P.into() },
            data_dir: None,
            result_file: None,
        };
        assert_eq!(command_line(&inv), format!("--fw-unblock \"{P}\""));
    }
}
