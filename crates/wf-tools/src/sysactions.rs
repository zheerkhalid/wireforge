//! Actions that change system state. The UI confirms before `run`.

use crate::types::*;
use std::io::Read;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// No console window flashes up.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The most output kept from a command.
pub const MAX_OUTPUT: usize = 16 * 1024;

/// The longest a command may run (a lease renewal can be slow).
const TIMEOUT: Duration = Duration::from_secs(90);

/// The absolute path of a program in the Windows system folder.
pub fn system32(program: &str) -> String {
    let root = std::env::var("SystemRoot")
        .ok()
        .filter(|r| !r.trim().is_empty())
        .unwrap_or_else(|| "C:\\Windows".to_string());
    format!("{}\\System32\\{program}", root.trim_end_matches('\\'))
}

fn ipconfig(args: Vec<String>, description: String) -> SystemCommand {
    SystemCommand {
        program: system32("ipconfig.exe"),
        args,
        description,
        needs_admin: false,
    }
}

/// `ipconfig /flushdns`
pub fn flush_dns() -> SystemCommand {
    ipconfig(
        vec!["/flushdns".into()],
        "Clears the list of names Windows has looked up recently (ipconfig /flushdns).".into(),
    )
}

/// An adapter name that is safe to hand to ipconfig as one argument:
/// no quotes or control characters, and it cannot be taken for a switch.
fn clean_adapter(name: &str) -> Option<String> {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control() && *c != '"')
        .collect();
    let cleaned = cleaned.trim().trim_start_matches(['/', '-']).trim();
    (!cleaned.is_empty()).then(|| cleaned.to_string())
}

/// `ipconfig /release` then `/renew`, for one adapter name or all (`None`).
/// The name is its own argument; it is quoted when the command line is built,
/// never passed through a shell.
pub fn renew_lease(adapter: Option<&str>) -> Vec<SystemCommand> {
    let adapter = adapter.and_then(clean_adapter);
    let build = |switch: &str, what: &str| {
        let mut args = vec![switch.to_string()];
        let target = match &adapter {
            Some(name) => {
                args.push(name.clone());
                format!("for \"{name}\"")
            }
            None => "for every adapter".to_string(),
        };
        let shown = match &adapter {
            Some(name) => format!("ipconfig {switch} \"{name}\""),
            None => format!("ipconfig {switch}"),
        };
        ipconfig(args, format!("{what} {target} ({shown})."))
    };
    vec![
        build("/release", "Gives up the current address from the router"),
        build("/renew", "Asks the router for an address again"),
    ]
}

/// Decodes console output from the OEM code page.
fn decode_oem(bytes: &[u8]) -> String {
    use windows::Win32::Globalization::{
        GetOEMCP, MultiByteToWideChar, MULTI_BYTE_TO_WIDE_CHAR_FLAGS,
    };
    if bytes.is_empty() {
        return String::new();
    }
    if i32::try_from(bytes.len()).is_err() {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    // A character never needs more UTF-16 units than it has bytes.
    let mut wide = vec![0u16; bytes.len()];
    // SAFETY: both buffers are live slices; the API is told their lengths.
    let written = unsafe {
        MultiByteToWideChar(
            GetOEMCP(),
            MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0),
            bytes,
            Some(&mut wide),
        )
    };
    match usize::try_from(written) {
        Ok(n) if n > 0 => String::from_utf16_lossy(wide.get(..n).unwrap_or(&[])),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Reads a pipe to its end on a helper thread, keeping at most `MAX_OUTPUT`.
fn drain(pipe: Option<impl Read + Send + 'static>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        if let Some(mut pipe) = pipe {
            let mut chunk = [0u8; 4096];
            // Keep reading past the cap so the program is never blocked on a
            // full pipe; the extra is thrown away.
            while let Ok(n) = pipe.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let room = MAX_OUTPUT.saturating_sub(kept.len());
                kept.extend_from_slice(chunk.get(..n.min(room)).unwrap_or(&[]));
            }
        }
        kept
    })
}

/// Runs the command hidden and returns its output (trimmed, capped).
pub fn run(command: &SystemCommand) -> Result<String, String> {
    if command.program.trim().is_empty() {
        return Err("There is no command to run.".into());
    }
    let mut child = Command::new(&command.program)
        .args(&command.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("Could not start the command ({e})."))?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() > TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("The command took too long and was stopped.".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => return Err(format!("Could not wait for the command ({e}).")),
        }
    };
    let out = decode_oem(&stdout.join().unwrap_or_default());
    let err = decode_oem(&stderr.join().unwrap_or_default());
    let mut text = out.trim().replace("\r\n", "\n");
    let err = err.trim().replace("\r\n", "\n");
    if !err.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&err);
    }
    if status.success() {
        Ok(text)
    } else if text.is_empty() {
        Err(match status.code() {
            Some(code) => format!("The command failed (exit code {code})."),
            None => "The command failed.".to_string(),
        })
    } else {
        Err(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flush_command() {
        let c = flush_dns();
        assert!(c
            .program
            .to_ascii_lowercase()
            .ends_with("\\system32\\ipconfig.exe"));
        assert!(std::path::Path::new(&c.program).is_absolute());
        assert_eq!(c.args, vec!["/flushdns"]);
        assert!(!c.description.is_empty());
        assert!(!c.needs_admin);
    }

    #[test]
    fn renew_all() {
        let cs = renew_lease(None);
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0].args, vec!["/release"]);
        assert_eq!(cs[1].args, vec!["/renew"]);
        assert!(cs.iter().all(|c| c.program == flush_dns().program));
        assert!(cs[0].description.contains("every adapter"));
    }

    #[test]
    fn renew_one_adapter_is_a_separate_argument() {
        let cs = renew_lease(Some("Wi-Fi 2"));
        assert_eq!(cs[0].args, vec!["/release", "Wi-Fi 2"]);
        assert_eq!(cs[1].args, vec!["/renew", "Wi-Fi 2"]);
        assert!(cs[1].description.contains("\"Wi-Fi 2\""));
    }

    #[test]
    fn adapter_names_cannot_inject() {
        let cs = renew_lease(Some("  /all \"x\"\r\n & calc "));
        assert_eq!(cs[0].args.len(), 2);
        assert_eq!(cs[0].args[1], "all x & calc");
        // Nothing usable left: behaves like "all adapters".
        assert_eq!(renew_lease(Some(" \"/\" ")), renew_lease(None));
        assert_eq!(renew_lease(Some("")), renew_lease(None));
    }

    #[test]
    fn run_captures_output() {
        let echo = SystemCommand {
            program: system32("cmd.exe"),
            args: vec!["/c".into(), "echo".into(), "ok".into()],
            ..Default::default()
        };
        assert_eq!(run(&echo).unwrap(), "ok");
    }

    #[test]
    fn run_reports_failure() {
        let fail = SystemCommand {
            program: system32("cmd.exe"),
            args: vec!["/c".into(), "exit".into(), "3".into()],
            ..Default::default()
        };
        assert!(run(&fail).unwrap_err().contains('3'));
        let missing = SystemCommand {
            program: system32("wf-no-such-program.exe"),
            ..Default::default()
        };
        assert!(run(&missing).is_err());
        assert!(run(&SystemCommand::default()).is_err());
    }

    #[test]
    fn run_caps_output() {
        // 40 000 characters of output, far more than is kept.
        let noisy = SystemCommand {
            program: system32("cmd.exe"),
            args: vec![
                "/c".into(),
                "for /L %i in (1,1,4000) do @echo 123456789".into(),
            ],
            ..Default::default()
        };
        let out = run(&noisy).unwrap();
        assert!(out.len() <= MAX_OUTPUT);
        assert!(out.len() > MAX_OUTPUT / 2);
    }

    #[test]
    fn oem_decoding() {
        assert_eq!(decode_oem(b"plain"), "plain");
        assert_eq!(decode_oem(b""), "");
        // High bytes decode to something rather than failing.
        assert_eq!(decode_oem(&[0x80, 0x81]).chars().count(), 2);
    }
}
