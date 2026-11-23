//! The real Windows Defender Firewall through `INetFwPolicy2` / `INetFwRule`,
//! and the scheduled tasks that end temporary blocks (through `schtasks.exe`).
//! Reading works for every user; changes need administrator rights.

use crate::backend::FirewallApi;
use crate::model::*;
use crate::tasks::{task_xml, Expiry};
use std::collections::HashMap;
use std::ffi::c_void;
use std::os::windows::process::CommandExt;
use windows::core::{IUnknown, Interface, BSTR, PCWSTR, VARIANT};
use windows::Win32::Foundation::{VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NetFwPolicy2, NetFwRule, NET_FW_ACTION, NET_FW_ACTION_ALLOW,
    NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC,
    NET_FW_PROFILE_TYPE2, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::UI::Shell::SHLoadIndirectString;

const RPC_E_CHANGED_MODE: i32 = 0x8001_0106_u32 as i32;
const E_ACCESSDENIED: i32 = 0x8007_0005_u32 as i32;
const VT_DISPATCH: u16 = 9;
const VT_UNKNOWN: u16 = 13;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Balances `CoInitializeEx` when this object was the one to initialise COM.
struct ComGuard(bool);

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: paired with the successful CoInitializeEx in `open`.
            unsafe { CoUninitialize() };
        }
    }
}

pub struct ComFirewall {
    // Declared first, so it is dropped before COM is uninitialised.
    policy: INetFwPolicy2,
    _com: ComGuard,
}

fn api_profile(p: Profile) -> NET_FW_PROFILE_TYPE2 {
    match p {
        Profile::Domain => NET_FW_PROFILE2_DOMAIN,
        Profile::Private => NET_FW_PROFILE2_PRIVATE,
        Profile::Public => NET_FW_PROFILE2_PUBLIC,
    }
}

fn api_action(a: FwAction) -> NET_FW_ACTION {
    match a {
        FwAction::Allow => NET_FW_ACTION_ALLOW,
        FwAction::Block => NET_FW_ACTION_BLOCK,
    }
}

fn explain(e: &windows::core::Error, what: &str) -> String {
    if e.code().0 == E_ACCESSDENIED {
        format!("{what}: administrator rights are needed.")
    } else {
        format!("{what} ({}).", e.code())
    }
}

fn text(value: windows::core::Result<BSTR>) -> String {
    value.map(|b| b.to_string()).unwrap_or_default()
}

/// Expands `%ProgramFiles%` style variables.
pub fn expand_env(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let src = wide(s);
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: `src` is NUL-terminated; the buffer length is passed along.
        let n = unsafe { ExpandEnvironmentStringsW(PCWSTR(src.as_ptr()), Some(&mut buf)) } as usize;
        if n == 0 {
            return s.to_string();
        }
        if n <= buf.len() {
            return from_wide(&buf);
        }
        buf.resize(n + 1, 0);
    }
}

/// Resolves `@FirewallAPI.dll,-28502` style references (Windows' own rules).
fn resolve_indirect(text: &str, cache: &mut HashMap<String, String>) -> String {
    if !text.starts_with('@') {
        return text.to_string();
    }
    if let Some(hit) = cache.get(text) {
        return hit.clone();
    }
    let src = wide(text);
    let mut buf = vec![0u16; 1024];
    // SAFETY: NUL-terminated input, buffer passed as a slice.
    let resolved = match unsafe { SHLoadIndirectString(PCWSTR(src.as_ptr()), &mut buf, None) } {
        Ok(()) => from_wide(&buf),
        Err(_) => text.to_string(),
    };
    cache.insert(text.to_string(), resolved.clone());
    resolved
}

/// The COM object inside a VARIANT of type VT_DISPATCH / VT_UNKNOWN.
unsafe fn variant_object(v: &VARIANT) -> Option<IUnknown> {
    // VARIANT layout: the type tag in the first two bytes, the value at offset 8.
    let base = v as *const VARIANT as *const u8;
    let vt = *(base as *const u16);
    if vt != VT_DISPATCH && vt != VT_UNKNOWN {
        return None;
    }
    let ptr = *(base.add(8) as *const *mut c_void);
    IUnknown::from_raw_borrowed(&ptr).cloned()
}

unsafe fn read_rule(rule: &INetFwRule, cache: &mut HashMap<String, String>) -> FwRule {
    FwRule {
        name: resolve_indirect(&text(rule.Name()), cache),
        group: resolve_indirect(&text(rule.Grouping()), cache),
        description: resolve_indirect(&text(rule.Description()), cache),
        program: expand_env(text(rule.ApplicationName()).trim().trim_matches('"')),
        service: text(rule.ServiceName()),
        direction: if rule
            .Direction()
            .map(|d| d == NET_FW_RULE_DIR_IN)
            .unwrap_or(false)
        {
            Direction::In
        } else {
            Direction::Out
        },
        action: if rule
            .Action()
            .map(|a| a == NET_FW_ACTION_ALLOW)
            .unwrap_or(false)
        {
            FwAction::Allow
        } else {
            FwAction::Block
        },
        enabled: rule.Enabled().map(|b| b.as_bool()).unwrap_or(false),
        profiles: Profiles::from_mask(rule.Profiles().unwrap_or(0)),
        protocol: rule.Protocol().unwrap_or(256),
        local_ports: text(rule.LocalPorts()),
        remote_ports: text(rule.RemotePorts())
            .trim()
            .trim_start_matches('*')
            .to_string(),
        remote_addrs: text(rule.RemoteAddresses())
            .trim()
            .trim_start_matches('*')
            .to_string(),
    }
}

impl ComFirewall {
    pub fn open() -> Result<ComFirewall, String> {
        // SAFETY: COM is initialised for this thread and balanced by ComGuard.
        unsafe {
            let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
            if hr.is_err() && hr.0 != RPC_E_CHANGED_MODE {
                return Err(format!("COM could not be initialised ({hr})."));
            }
            let com = ComGuard(hr.is_ok());
            let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
                .map_err(|e| explain(&e, "Windows Firewall could not be opened"))?;
            Ok(ComFirewall { policy, _com: com })
        }
    }
}

impl FirewallApi for ComFirewall {
    fn status(&self) -> Result<FwStatus, String> {
        // SAFETY: plain COM property reads on a live object.
        unsafe {
            let active = Profiles::from_mask(self.policy.CurrentProfileTypes().unwrap_or(0));
            let mut profiles = Vec::new();
            for p in Profile::ALL {
                let api = api_profile(p);
                let enabled = self
                    .policy
                    .get_FirewallEnabled(api)
                    .map_err(|e| explain(&e, "The firewall state could not be read"))?;
                let din = self.policy.get_DefaultInboundAction(api).ok();
                let dout = self.policy.get_DefaultOutboundAction(api).ok();
                profiles.push(ProfileStatus {
                    profile: p,
                    enabled: enabled.as_bool(),
                    // Unknown reads as the Windows default.
                    default_in: if din == Some(NET_FW_ACTION_ALLOW) {
                        FwAction::Allow
                    } else {
                        FwAction::Block
                    },
                    default_out: if dout == Some(NET_FW_ACTION_BLOCK) {
                        FwAction::Block
                    } else {
                        FwAction::Allow
                    },
                    active: active.contains(p),
                });
            }
            Ok(FwStatus { profiles })
        }
    }

    fn rules(&self) -> Result<Vec<FwRule>, String> {
        // SAFETY: enumerates the rule collection; every VARIANT is checked
        // for an object type before use and dropped (released) afterwards.
        unsafe {
            let rules = self
                .policy
                .Rules()
                .map_err(|e| explain(&e, "The firewall rules could not be read"))?;
            let enumerator: IEnumVARIANT = rules
                ._NewEnum()
                .and_then(|u| u.cast())
                .map_err(|e| explain(&e, "The firewall rules could not be listed"))?;
            let mut out = Vec::new();
            let mut cache = HashMap::new();
            loop {
                let mut batch: [VARIANT; 64] = std::array::from_fn(|_| VARIANT::default());
                let mut fetched = 0u32;
                let hr = enumerator.Next(&mut batch, &mut fetched);
                for v in batch.iter().take(fetched as usize) {
                    if let Some(rule) = variant_object(v).and_then(|o| o.cast::<INetFwRule>().ok())
                    {
                        out.push(read_rule(&rule, &mut cache));
                    }
                }
                if hr.0 != 0 || fetched == 0 {
                    break;
                }
            }
            Ok(out)
        }
    }

    fn add_rule(&mut self, r: &FwRule) -> Result<(), String> {
        // SAFETY: a new rule object is filled in and added to the policy.
        unsafe {
            let rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)
                .map_err(|e| explain(&e, "A firewall rule could not be created"))?;
            let set = |res: windows::core::Result<()>| {
                res.map_err(|e| explain(&e, "A firewall rule could not be set up"))
            };
            set(rule.SetName(&BSTR::from(r.name.as_str())))?;
            set(rule.SetDescription(&BSTR::from(r.description.as_str())))?;
            set(rule.SetGrouping(&BSTR::from(r.group.as_str())))?;
            if !r.program.is_empty() {
                set(rule.SetApplicationName(&BSTR::from(r.program.as_str())))?;
            }
            set(rule.SetDirection(match r.direction {
                Direction::Out => NET_FW_RULE_DIR_OUT,
                Direction::In => NET_FW_RULE_DIR_IN,
            }))?;
            set(rule.SetAction(api_action(r.action)))?;
            set(rule.SetProfiles(r.profiles.to_mask()))?;
            set(rule.SetEnabled(if r.enabled {
                VARIANT_TRUE
            } else {
                VARIANT_FALSE
            }))?;
            let rules = self
                .policy
                .Rules()
                .map_err(|e| explain(&e, "The firewall rules could not be opened"))?;
            rules
                .Add(&rule)
                .map_err(|e| explain(&e, "The firewall rule could not be added"))
        }
    }

    fn remove_rule(&mut self, name: &str) -> Result<(), String> {
        // SAFETY: COM calls on live objects with an owned BSTR.
        unsafe {
            let rules = self
                .policy
                .Rules()
                .map_err(|e| explain(&e, "The firewall rules could not be opened"))?;
            let bstr = BSTR::from(name);
            // Remove deletes one rule per call; names can repeat.
            for _ in 0..64 {
                if rules.Item(&bstr).is_err() {
                    return Ok(());
                }
                rules
                    .Remove(&bstr)
                    .map_err(|e| explain(&e, "The firewall rule could not be removed"))?;
            }
            Err("The firewall rule could not be removed (too many with the same name).".into())
        }
    }

    fn set_default_outbound(&mut self, profile: Profile, action: FwAction) -> Result<(), String> {
        // SAFETY: a single COM property write.
        unsafe {
            self.policy
                .put_DefaultOutboundAction(api_profile(profile), api_action(action))
                .map_err(|e| explain(&e, "The default outgoing action could not be changed"))
        }
    }

    fn schedule(&mut self, e: &Expiry) -> Result<(), String> {
        let xml = task_xml(e);
        let file = std::env::temp_dir().join(format!(
            "wireforge-task-{}-{}.xml",
            std::process::id(),
            crate::naming::app_id(&e.task)
        ));
        // Task Scheduler reads UTF-16 with a byte-order mark.
        let mut bytes = vec![0xFF, 0xFE];
        for u in xml.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        std::fs::write(&file, bytes)
            .map_err(|err| format!("The end of the block could not be scheduled: {err}"))?;
        let result = schtasks(&[
            "/Create",
            "/TN",
            &e.task,
            "/XML",
            &file.to_string_lossy(),
            "/F",
        ]);
        let _ = std::fs::remove_file(&file);
        result.map_err(|err| format!("The end of the block could not be scheduled: {err}"))
    }

    fn cancel(&mut self, task: &str) -> Result<(), String> {
        if !task_exists(task) {
            return Ok(());
        }
        schtasks(&["/Delete", "/TN", task, "/F"])
            .map_err(|err| format!("The scheduled end of a block could not be removed: {err}"))
    }
}

fn schtasks_exe() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    format!("{root}\\System32\\schtasks.exe")
}

fn schtasks(args: &[&str]) -> Result<(), String> {
    let out = std::process::Command::new(schtasks_exe())
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if msg.is_empty() {
            format!("schtasks exit code {:?}", out.status.code())
        } else {
            msg
        })
    }
}

/// Whether a scheduled task exists (readable without administrator rights
/// only for tasks the user may see; SYSTEM tasks report as missing then).
pub fn task_exists(task: &str) -> bool {
    std::process::Command::new(schtasks_exe())
        .args(["/Query", "/TN", task])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// When Windows last started, as Unix time (to recognise a restart).
pub fn boot_time(now: i64) -> i64 {
    // SAFETY: no arguments, cannot fail.
    let up = unsafe { windows::Win32::System::SystemInformation::GetTickCount64() };
    now - (up / 1000) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_firewall_without_changing_it() {
        // Read-only: status and rules; nothing is added or removed here.
        let fw = ComFirewall::open().unwrap();
        let status = fw.status().unwrap();
        assert_eq!(status.profiles.len(), 3);
        let rules = fw.rules().unwrap();
        assert!(!rules.is_empty());
        // Opening twice on one thread keeps COM balanced.
        drop(fw);
        assert!(ComFirewall::open().is_ok());
    }

    #[test]
    fn environment_and_boot_time() {
        assert_eq!(expand_env("D:\\Tools\\app.exe"), "D:\\Tools\\app.exe");
        let root = std::env::var("SystemRoot").unwrap().to_lowercase();
        assert!(expand_env("%SystemRoot%\\x.exe")
            .to_lowercase()
            .starts_with(&root));
        let now = 2_000_000_000;
        let boot = boot_time(now);
        assert!(boot <= now && boot > 0);
        assert!((boot_time(now) - boot).abs() <= 1);
    }
}
