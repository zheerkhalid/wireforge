//! Rule names, the WireForge group, and the small metadata tag WireForge
//! keeps in each rule's description. Because everything WireForge needs is
//! stored in its own rules, the firewall itself is the source of truth: the
//! list survives a lost settings folder and other tools can see the rules.

use crate::model::*;
use std::collections::BTreeMap;

/// The rule group (shown as "Group" in Windows Defender Firewall).
pub const GROUP: &str = "WireForge";
/// Every WireForge rule name starts with this.
pub const PREFIX: &str = "WireForge: ";
/// The name of the disabled rule that remembers the settings before lockdown.
pub const LOCKDOWN_MARKER: &str = "WireForge: lockdown (saved settings)";
const TAG_OPEN: &str = "[wireforge v1 ";

/// What a WireForge rule is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Block,
    LockdownAllow,
    LockdownMarker,
}

/// A short, stable id for a program path (FNV-1a over the normalised path):
/// blocking the same program twice replaces the rules instead of adding more.
pub fn app_id(path: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in norm_path(path).bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:08x}", (h ^ (h >> 32)) as u32)
}

/// Rule names keep only printable characters (no quotes) so they are safe
/// in command lines and scheduled-task arguments.
fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && *c != '"')
        .collect::<String>()
}

pub fn block_rule_name(path: &str, dir: Direction) -> String {
    format!(
        "{PREFIX}block {} ({}) #{}",
        clean(&file_name(path)),
        match dir {
            Direction::Out => "outgoing",
            Direction::In => "incoming",
        },
        app_id(path)
    )
}

pub fn allow_rule_name(path: &str) -> String {
    format!(
        "{PREFIX}allow {} (lockdown) #{}",
        clean(&file_name(path)),
        app_id(path)
    )
}

/// The scheduled task that ends a temporary block.
pub fn task_name(path: &str) -> String {
    format!("\\WireForge\\Unblock {}", app_id(path))
}

pub fn is_ours(rule: &FwRule) -> bool {
    rule.group == GROUP && rule.name.starts_with(PREFIX)
}

/// `[wireforge v1 kind=block since=... until=...]`
pub fn tag(fields: &[(&str, String)]) -> String {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{TAG_OPEN}{body}]")
}

pub fn parse_tag(description: &str) -> Option<BTreeMap<String, String>> {
    let start = description.find(TAG_OPEN)? + TAG_OPEN.len();
    let rest = &description[start..];
    let end = rest.find(']')?;
    Some(
        rest[..end]
            .split_whitespace()
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )
}

pub fn kind_of(rule: &FwRule) -> Option<Kind> {
    if !is_ours(rule) {
        return None;
    }
    let tag = parse_tag(&rule.description)?;
    match tag.get("kind").map(String::as_str) {
        Some("block") => Some(Kind::Block),
        Some("allow") => Some(Kind::LockdownAllow),
        Some("lockdown") => Some(Kind::LockdownMarker),
        _ => None,
    }
}

fn lifetime_fields(l: Lifetime) -> (String, String) {
    match l {
        Lifetime::Always => ("always".into(), "0".into()),
        Lifetime::Until(t) => ("until".into(), t.to_string()),
        Lifetime::UntilRestart { boot } => ("restart".into(), boot.to_string()),
    }
}

fn lifetime_from(tag: &BTreeMap<String, String>) -> Lifetime {
    let n = tag
        .get("at")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
    match tag.get("until").map(String::as_str) {
        Some("until") => Lifetime::Until(n),
        Some("restart") => Lifetime::UntilRestart { boot: n },
        _ => Lifetime::Always,
    }
}

/// The rule that blocks `path` in one direction.
pub fn block_rule(
    path: &str,
    dir: Direction,
    profiles: Profiles,
    lifetime: Lifetime,
    now: i64,
) -> FwRule {
    let (until, at) = lifetime_fields(lifetime);
    FwRule {
        name: block_rule_name(path, dir),
        group: GROUP.into(),
        description: format!(
            "Added by WireForge: blocks this program from the network. {}",
            tag(&[
                ("kind", "block".into()),
                ("since", now.to_string()),
                ("until", until),
                ("at", at),
            ])
        ),
        program: path.to_string(),
        direction: dir,
        action: FwAction::Block,
        enabled: true,
        profiles,
        ..Default::default()
    }
}

/// The rule that lets `path` out while lockdown is on.
pub fn allow_rule(path: &str, now: i64) -> FwRule {
    FwRule {
        name: allow_rule_name(path),
        group: GROUP.into(),
        description: format!(
            "Added by WireForge: allowed while lockdown is on. {}",
            tag(&[("kind", "allow".into()), ("since", now.to_string())])
        ),
        program: path.to_string(),
        direction: Direction::Out,
        action: FwAction::Allow,
        enabled: true,
        profiles: Profiles::ALL,
        ..Default::default()
    }
}

/// The disabled marker rule that remembers each profile's default outbound
/// action from before lockdown. Disabled rules have no effect on traffic.
pub fn lockdown_marker(saved: &[(Profile, FwAction)], now: i64) -> FwRule {
    let mut fields = vec![("kind", "lockdown".to_string()), ("since", now.to_string())];
    for (p, a) in saved {
        fields.push((
            p.key(),
            match a {
                FwAction::Allow => "allow".into(),
                FwAction::Block => "block".into(),
            },
        ));
    }
    FwRule {
        name: LOCKDOWN_MARKER.into(),
        group: GROUP.into(),
        description: format!(
            "Added by WireForge: remembers the outgoing default of each network profile \
             from before lockdown. This rule is disabled and changes nothing. {}",
            tag(&fields)
        ),
        program: String::new(),
        direction: Direction::Out,
        action: FwAction::Allow,
        enabled: false,
        profiles: Profiles::ALL,
        ..Default::default()
    }
}

/// The programs WireForge blocks, one entry per program.
pub fn blocked_apps(rules: &[FwRule]) -> Vec<BlockedApp> {
    let mut out: Vec<BlockedApp> = Vec::new();
    for r in rules {
        if kind_of(r) != Some(Kind::Block) || r.program.is_empty() {
            continue;
        }
        let tag = parse_tag(&r.description).unwrap_or_default();
        let since = tag.get("since").and_then(|v| v.parse().ok()).unwrap_or(0);
        let lifetime = lifetime_from(&tag);
        let entry = match out.iter_mut().find(|a| same_path(&a.path, &r.program)) {
            Some(e) => e,
            None => {
                out.push(BlockedApp {
                    path: r.program.clone(),
                    name: file_name(&r.program),
                    since,
                    lifetime,
                    outbound: false,
                    inbound: false,
                    profiles: r.profiles,
                    rule_names: Vec::new(),
                });
                out.last_mut().expect("just pushed")
            }
        };
        match r.direction {
            Direction::Out => entry.outbound = true,
            Direction::In => entry.inbound = true,
        }
        entry.since = entry.since.min(since);
        entry.rule_names.push(r.name.clone());
    }
    out.sort_by_key(|a| a.name.to_lowercase());
    out
}

/// Lockdown state, if WireForge turned it on.
pub fn lockdown(rules: &[FwRule]) -> Option<Lockdown> {
    let marker = rules
        .iter()
        .find(|r| kind_of(r) == Some(Kind::LockdownMarker))?;
    let tag = parse_tag(&marker.description)?;
    let saved = Profile::ALL
        .iter()
        .filter_map(|p| {
            let a = match tag.get(p.key()).map(String::as_str) {
                Some("allow") => FwAction::Allow,
                Some("block") => FwAction::Block,
                _ => return None,
            };
            Some((*p, a))
        })
        .collect();
    let allowed = rules
        .iter()
        .filter(|r| kind_of(r) == Some(Kind::LockdownAllow))
        .map(|r| r.program.clone())
        .collect();
    Some(Lockdown {
        since: tag.get("since").and_then(|v| v.parse().ok()).unwrap_or(0),
        saved,
        allowed,
    })
}

/// Rules from other sources (Windows, installers, the user) that name this
/// program, or that apply to every program and block. Read-only, to explain
/// why something may be blocked or allowed.
pub fn other_rules_for<'a>(rules: &'a [FwRule], path: &str) -> Vec<&'a FwRule> {
    let mut list: Vec<&FwRule> = rules
        .iter()
        .filter(|r| !is_ours(r))
        .filter(|r| {
            (!r.program.is_empty() && same_path(&r.program, path))
                || (r.program.is_empty()
                    && r.service.is_empty()
                    && r.enabled
                    && r.action == FwAction::Block
                    && r.remote_addrs.is_empty()
                    && r.remote_ports.is_empty())
        })
        .collect();
    list.sort_by(|a, b| {
        (b.enabled, b.action == FwAction::Block, &a.name).cmp(&(
            a.enabled,
            a.action == FwAction::Block,
            &b.name,
        ))
    });
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "C:\\Program Files\\Example\\example.exe";

    #[test]
    fn names_are_clear_stable_and_grouped() {
        let out = block_rule_name(APP, Direction::Out);
        let id = app_id(APP);
        assert_eq!(id.len(), 8);
        assert_eq!(
            out,
            format!("WireForge: block example.exe (outgoing) #{id}")
        );
        assert_eq!(
            block_rule_name(APP, Direction::In),
            format!("WireForge: block example.exe (incoming) #{id}")
        );
        // Same program, other spelling: same id. Other program: other id.
        assert_eq!(app_id("c:/program files/example/EXAMPLE.EXE"), id);
        assert_ne!(app_id("C:\\Program Files\\Example\\other.exe"), id);
        assert_eq!(
            allow_rule_name(APP),
            format!("WireForge: allow example.exe (lockdown) #{id}")
        );
        assert_eq!(task_name(APP), format!("\\WireForge\\Unblock {id}"));
        // No quotes or control characters end up in a name.
        let odd = block_rule_name("C:\\x\\we\"ird\u{7}.exe", Direction::Out);
        assert!(!odd.contains('"') && !odd.contains('\u{7}'));
        let r = block_rule(APP, Direction::Out, Profiles::ALL, Lifetime::Always, 5);
        assert_eq!(r.group, GROUP);
        assert!(is_ours(&r));
        assert_eq!(kind_of(&r), Some(Kind::Block));
        assert_eq!(r.action, FwAction::Block);
    }

    #[test]
    fn tags_round_trip() {
        let t = tag(&[("kind", "block".into()), ("since", "12".into())]);
        let parsed = parse_tag(&format!("Some text. {t} trailing")).unwrap();
        assert_eq!(parsed["kind"], "block");
        assert_eq!(parsed["since"], "12");
        assert!(parse_tag("no tag here").is_none());
    }

    #[test]
    fn blocked_apps_are_assembled_from_rules() {
        let mut rules = vec![
            block_rule(APP, Direction::Out, Profiles(6), Lifetime::Until(9000), 100),
            block_rule(APP, Direction::In, Profiles(6), Lifetime::Until(9000), 100),
            block_rule(
                "D:\\Tools\\b.exe",
                Direction::Out,
                Profiles::ALL,
                Lifetime::UntilRestart { boot: 77 },
                200,
            ),
            // Somebody else's rule with a WireForge-like name but no group: ignored.
            FwRule {
                name: "WireForge: block fake.exe (outgoing) #00000000".into(),
                program: "C:\\fake.exe".into(),
                ..Default::default()
            },
        ];
        rules.push(lockdown_marker(&[], 1));
        let apps = blocked_apps(&rules);
        assert_eq!(apps.len(), 2);
        let b = &apps[0];
        assert_eq!(b.name, "b.exe");
        assert_eq!(b.lifetime, Lifetime::UntilRestart { boot: 77 });
        assert!(b.outbound && !b.inbound);
        let e = &apps[1];
        assert_eq!(e.name, "example.exe");
        assert_eq!(e.since, 100);
        assert_eq!(e.lifetime, Lifetime::Until(9000));
        assert!(e.outbound && e.inbound);
        assert_eq!(e.profiles, Profiles(6));
        assert_eq!(e.rule_names.len(), 2);
    }

    #[test]
    fn lockdown_marker_round_trips() {
        let saved = vec![
            (Profile::Domain, FwAction::Allow),
            (Profile::Private, FwAction::Allow),
            (Profile::Public, FwAction::Block),
        ];
        let marker = lockdown_marker(&saved, 42);
        assert!(!marker.enabled, "the marker must never filter anything");
        let rules = vec![marker, allow_rule(APP, 43)];
        let l = lockdown(&rules).unwrap();
        assert_eq!(l.saved, saved);
        assert_eq!(l.since, 42);
        assert_eq!(l.allowed, vec![APP.to_string()]);
        assert!(lockdown(&[allow_rule(APP, 1)]).is_none());
    }

    #[test]
    fn other_rules_explain_an_app() {
        let rules = vec![
            FwRule {
                name: "Example (in)".into(),
                program: "c:/program files/example/EXAMPLE.exe".into(),
                action: FwAction::Allow,
                direction: Direction::In,
                ..Default::default()
            },
            FwRule {
                name: "Block everything out".into(),
                action: FwAction::Block,
                ..Default::default()
            },
            FwRule {
                name: "Some service".into(),
                service: "Svc".into(),
                ..Default::default()
            },
            FwRule {
                name: "Unrelated".into(),
                program: "C:\\other.exe".into(),
                ..Default::default()
            },
            block_rule(APP, Direction::Out, Profiles::ALL, Lifetime::Always, 1),
        ];
        let names: Vec<&str> = other_rules_for(&rules, APP)
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(names, vec!["Block everything out", "Example (in)"]);
    }
}
