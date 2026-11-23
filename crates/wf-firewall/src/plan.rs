//! Every firewall action is first planned as a list of small reversible
//! steps, then applied in order. When a step fails the steps already done
//! are reversed, so an action either happens completely or not at all. The
//! applied steps go into the journal, which is how undo works.

use crate::backend::FirewallApi;
use crate::model::*;
use crate::naming::{self, Kind};
use crate::tasks::Expiry;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    AddRule(FwRule),
    /// Keeps the whole rule so that undo can put it back.
    RemoveRule(FwRule),
    SetOutbound {
        profile: Profile,
        from: FwAction,
        to: FwAction,
    },
    Schedule(Expiry),
    Cancel(Expiry),
}

impl Op {
    pub fn inverse(&self) -> Op {
        match self {
            Op::AddRule(r) => Op::RemoveRule(r.clone()),
            Op::RemoveRule(r) => Op::AddRule(r.clone()),
            Op::SetOutbound { profile, from, to } => Op::SetOutbound {
                profile: *profile,
                from: *to,
                to: *from,
            },
            Op::Schedule(e) => Op::Cancel(e.clone()),
            Op::Cancel(e) => Op::Schedule(e.clone()),
        }
    }

    pub fn run(&self, api: &mut dyn FirewallApi) -> Result<(), String> {
        match self {
            Op::AddRule(r) => api.add_rule(r),
            Op::RemoveRule(r) => api.remove_rule(&r.name),
            Op::SetOutbound { profile, to, .. } => api.set_default_outbound(*profile, *to),
            Op::Schedule(e) => api.schedule(e),
            Op::Cancel(e) => api.cancel(&e.task),
        }
    }

    /// One line for the journal view.
    pub fn describe(&self) -> String {
        match self {
            Op::AddRule(r) => format!("Added rule \"{}\"", r.name),
            Op::RemoveRule(r) => format!("Removed rule \"{}\"", r.name),
            Op::SetOutbound { profile, from, to } => format!(
                "{} profile: outgoing default {} -> {}",
                profile.label(),
                from.label().to_lowercase(),
                to.label().to_lowercase()
            ),
            Op::Schedule(e) => match e.at {
                Some(_) => format!("Scheduled the end of the block ({})", e.task),
                None => format!("Scheduled removal at the next restart ({})", e.task),
            },
            Op::Cancel(e) => format!("Cancelled the scheduled removal ({})", e.task),
        }
    }
}

/// How to block a program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockOptions {
    pub lifetime: Lifetime,
    pub inbound: bool,
    pub profiles: Profiles,
}

impl Default for BlockOptions {
    fn default() -> Self {
        BlockOptions {
            lifetime: Lifetime::Always,
            inbound: false,
            profiles: Profiles::ALL,
        }
    }
}

fn expiry_for(app: &BlockedApp) -> Option<Expiry> {
    let at = match app.lifetime {
        Lifetime::Always => return None,
        Lifetime::Until(t) => Some(t),
        Lifetime::UntilRestart { .. } => None,
    };
    Some(Expiry {
        task: naming::task_name(&app.path),
        rules: app.rule_names.clone(),
        at,
    })
}

fn ours_named<'a>(rules: &'a [FwRule], name: &str) -> Option<&'a FwRule> {
    rules.iter().find(|r| naming::is_ours(r) && r.name == name)
}

/// The steps that undo the current block of `path` (rules and task).
fn unblock_ops(rules: &[FwRule], app: &BlockedApp) -> Vec<Op> {
    let mut ops = Vec::new();
    if let Some(e) = expiry_for(app) {
        ops.push(Op::Cancel(e));
    }
    for name in &app.rule_names {
        if let Some(r) = ours_named(rules, name) {
            ops.push(Op::RemoveRule(r.clone()));
        }
    }
    ops
}

pub fn plan_block(
    rules: &[FwRule],
    path: &str,
    opts: BlockOptions,
    now: i64,
) -> Result<Vec<Op>, String> {
    crate::cli::check_program_path(path)?;
    if opts.profiles.is_empty() {
        return Err("Choose at least one network profile.".into());
    }
    if let Lifetime::Until(t) = opts.lifetime {
        if t <= now {
            return Err("The end of the block is already in the past.".into());
        }
    }
    let mut ops = Vec::new();
    // Blocking again replaces the old block (new duration or directions).
    if let Some(app) = naming::blocked_apps(rules)
        .into_iter()
        .find(|a| same_path(&a.path, path))
    {
        ops.extend(unblock_ops(rules, &app));
    }
    let mut names = Vec::new();
    let mut dirs = vec![Direction::Out];
    if opts.inbound {
        dirs.push(Direction::In);
    }
    for dir in dirs {
        let r = naming::block_rule(path, dir, opts.profiles, opts.lifetime, now);
        names.push(r.name.clone());
        ops.push(Op::AddRule(r));
    }
    match opts.lifetime {
        Lifetime::Always => {}
        Lifetime::Until(t) => ops.push(Op::Schedule(Expiry {
            task: naming::task_name(path),
            rules: names,
            at: Some(t),
        })),
        Lifetime::UntilRestart { .. } => ops.push(Op::Schedule(Expiry {
            task: naming::task_name(path),
            rules: names,
            at: None,
        })),
    }
    Ok(ops)
}

pub fn plan_unblock(rules: &[FwRule], path: &str) -> Result<Vec<Op>, String> {
    let app = naming::blocked_apps(rules)
        .into_iter()
        .find(|a| same_path(&a.path, path))
        .ok_or("WireForge does not block this program.")?;
    Ok(unblock_ops(rules, &app))
}

/// Blocks that should have ended (the scheduled task did not run, for
/// example because the program folder moved).
pub fn plan_expire(rules: &[FwRule], now: i64, boot: i64) -> Vec<Op> {
    naming::blocked_apps(rules)
        .iter()
        .filter(|a| a.lifetime.expired(now, boot))
        .flat_map(|a| unblock_ops(rules, a))
        .collect()
}

pub fn plan_lockdown_on(
    status: &FwStatus,
    rules: &[FwRule],
    allow: &[String],
    now: i64,
) -> Result<Vec<Op>, String> {
    if naming::lockdown(rules).is_some() {
        return Err("Lockdown is already on.".into());
    }
    let saved: Vec<(Profile, FwAction)> = Profile::ALL
        .iter()
        .filter_map(|p| status.get(*p).map(|s| (*p, s.default_out)))
        .collect();
    if saved.len() != 3 {
        return Err("The firewall settings could not be read, so lockdown was not started.".into());
    }
    // The marker goes first: whatever happens next, the old values are on record.
    let mut ops = vec![Op::AddRule(naming::lockdown_marker(&saved, now))];
    let mut seen: Vec<String> = Vec::new();
    for path in allow {
        crate::cli::check_program_path(path)?;
        if seen.iter().any(|s| same_path(s, path)) {
            continue;
        }
        seen.push(path.clone());
        ops.push(Op::AddRule(naming::allow_rule(path, now)));
    }
    for (p, from) in saved {
        if from != FwAction::Block {
            ops.push(Op::SetOutbound {
                profile: p,
                from,
                to: FwAction::Block,
            });
        }
    }
    Ok(ops)
}

pub fn plan_lockdown_off(status: &FwStatus, rules: &[FwRule]) -> Result<Vec<Op>, String> {
    let l = naming::lockdown(rules).ok_or("Lockdown is not on.")?;
    let mut ops = Vec::new();
    for (p, before) in &l.saved {
        let now = status
            .get(*p)
            .map(|s| s.default_out)
            .unwrap_or(FwAction::Block);
        if now != *before {
            ops.push(Op::SetOutbound {
                profile: *p,
                from: now,
                to: *before,
            });
        }
    }
    for r in rules {
        if naming::kind_of(r) == Some(Kind::LockdownAllow) {
            ops.push(Op::RemoveRule(r.clone()));
        }
    }
    if let Some(m) = rules
        .iter()
        .find(|r| naming::kind_of(r) == Some(Kind::LockdownMarker))
    {
        ops.push(Op::RemoveRule(m.clone()));
    }
    Ok(ops)
}

pub fn plan_allow(rules: &[FwRule], path: &str, now: i64) -> Result<Vec<Op>, String> {
    crate::cli::check_program_path(path)?;
    if naming::lockdown(rules).is_none() {
        return Err("The allow list is used only while lockdown is on.".into());
    }
    let name = naming::allow_rule_name(path);
    if ours_named(rules, &name).is_some() {
        return Err("This program is already on the allow list.".into());
    }
    Ok(vec![Op::AddRule(naming::allow_rule(path, now))])
}

pub fn plan_disallow(rules: &[FwRule], path: &str) -> Result<Vec<Op>, String> {
    let name = naming::allow_rule_name(path);
    let r = ours_named(rules, &name).ok_or("This program is not on the allow list.")?;
    Ok(vec![Op::RemoveRule(r.clone())])
}

/// Everything WireForge ever added, gone; lockdown ended with the old
/// defaults restored. Used by "Remove all WireForge rules" and the uninstaller.
pub fn plan_remove_all(status: &FwStatus, rules: &[FwRule]) -> Vec<Op> {
    let mut ops = Vec::new();
    if naming::lockdown(rules).is_some() {
        ops.extend(plan_lockdown_off(status, rules).unwrap_or_default());
    }
    for app in naming::blocked_apps(rules) {
        if let Some(e) = expiry_for(&app) {
            ops.push(Op::Cancel(e));
        }
    }
    for r in rules {
        if naming::is_ours(r)
            && !ops
                .iter()
                .any(|o| matches!(o, Op::RemoveRule(x) if x.name == r.name))
        {
            ops.push(Op::RemoveRule(r.clone()));
        }
    }
    ops
}

/// The steps that undo `ops`. Blocks whose time is already up are not
/// brought back.
pub fn undo_ops(ops: &[Op], now: i64, boot: i64) -> Vec<Op> {
    let expired_rule = |r: &FwRule| {
        naming::kind_of(r) == Some(Kind::Block)
            && naming::blocked_apps(std::slice::from_ref(r))
                .first()
                .map(|a| a.lifetime.expired(now, boot))
                .unwrap_or(false)
    };
    ops.iter()
        .rev()
        .map(Op::inverse)
        .filter(|op| match op {
            Op::AddRule(r) => !expired_rule(r),
            Op::Schedule(e) => e.at.map(|t| t > now).unwrap_or(true),
            _ => true,
        })
        .collect()
}

/// Applies the steps in order. On failure, reverses what was done and
/// reports the error; the firewall is then as it was before.
pub fn apply(api: &mut dyn FirewallApi, ops: &[Op]) -> Result<(), String> {
    for (i, op) in ops.iter().enumerate() {
        if let Err(e) = op.run(api) {
            let mut rollback_failed = false;
            for done in ops[..i].iter().rev() {
                if done.inverse().run(api).is_err() {
                    rollback_failed = true;
                }
            }
            return Err(if rollback_failed {
                format!(
                    "{e} Some of the steps already done could not be reversed; \
                     see the WireForge rules in Windows Defender Firewall."
                )
            } else {
                format!("{e} Nothing was changed.")
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockFirewall;

    const A: &str = "C:\\Program Files\\Example\\example.exe";
    const B: &str = "D:\\Tools\\b.exe";

    fn run(fw: &mut MockFirewall, ops: &[Op]) {
        apply(fw, ops).unwrap();
    }

    #[test]
    fn block_and_unblock() {
        let mut fw = MockFirewall::new();
        let ops = plan_block(&fw.rules, A, BlockOptions::default(), 100).unwrap();
        run(&mut fw, &ops);
        assert_eq!(fw.rules.len(), 1);
        let apps = naming::blocked_apps(&fw.rules);
        assert_eq!(apps.len(), 1);
        assert!(apps[0].outbound && !apps[0].inbound);
        assert!(fw.tasks.is_empty(), "a permanent block needs no task");

        // Blocking again with other options replaces, never duplicates.
        let opts = BlockOptions {
            inbound: true,
            profiles: Profiles(4),
            ..Default::default()
        };
        let ops = plan_block(&fw.rules, A, opts, 200).unwrap();
        run(&mut fw, &ops);
        assert_eq!(fw.rules.len(), 2);
        let app = &naming::blocked_apps(&fw.rules)[0];
        assert!(app.inbound && app.outbound);
        assert_eq!(app.profiles, Profiles(4));

        let ops = plan_unblock(&fw.rules, &A.to_uppercase()).unwrap();
        run(&mut fw, &ops);
        assert!(fw.rules.is_empty());
        assert!(plan_unblock(&fw.rules, A).is_err());
    }

    #[test]
    fn bad_input_is_refused() {
        let fw = MockFirewall::new();
        assert!(plan_block(&fw.rules, "notepad.exe", BlockOptions::default(), 1).is_err());
        let none = BlockOptions {
            profiles: Profiles::NONE,
            ..Default::default()
        };
        assert!(plan_block(&fw.rules, A, none, 1).is_err());
        let past = BlockOptions {
            lifetime: Lifetime::Until(5),
            ..Default::default()
        };
        assert!(plan_block(&fw.rules, A, past, 10).is_err());
    }

    #[test]
    fn temporary_blocks_schedule_and_expire() {
        let mut fw = MockFirewall::new();
        let hour = BlockOptions {
            lifetime: Lifetime::Until(1000 + 3600),
            inbound: true,
            ..Default::default()
        };
        {
            let ops = plan_block(&fw.rules, A, hour, 1000).unwrap();
            run(&mut fw, &ops);
        }
        let restart = BlockOptions {
            lifetime: Lifetime::UntilRestart { boot: 500 },
            ..Default::default()
        };
        {
            let ops = plan_block(&fw.rules, B, restart, 1000).unwrap();
            run(&mut fw, &ops);
        }
        assert_eq!(fw.tasks.len(), 2);
        let a_task = fw
            .tasks
            .iter()
            .find(|t| t.task == naming::task_name(A))
            .unwrap();
        assert_eq!(a_task.at, Some(4600));
        assert_eq!(a_task.rules.len(), 2, "both directions end together");
        let b_task = fw
            .tasks
            .iter()
            .find(|t| t.task == naming::task_name(B))
            .unwrap();
        assert_eq!(b_task.at, None, "until restart runs at boot");

        // Nothing has expired yet.
        assert!(plan_expire(&fw.rules, 2000, 500).is_empty());
        // After the hour, only A expires.
        let ops = plan_expire(&fw.rules, 5000, 500);
        run(&mut fw, &ops);
        let left = naming::blocked_apps(&fw.rules);
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].name, "b.exe");
        assert_eq!(fw.tasks.len(), 1);
        // After a restart, B expires as well.
        {
            let ops = plan_expire(&fw.rules, 9000, 8000);
            run(&mut fw, &ops);
        }
        assert!(fw.rules.is_empty() && fw.tasks.is_empty());
    }

    #[test]
    fn unblocking_a_temporary_block_cancels_its_task() {
        let mut fw = MockFirewall::new();
        let opts = BlockOptions {
            lifetime: Lifetime::Until(9999),
            ..Default::default()
        };
        {
            let ops = plan_block(&fw.rules, A, opts, 1).unwrap();
            run(&mut fw, &ops);
        }
        assert_eq!(fw.tasks.len(), 1);
        {
            let ops = plan_unblock(&fw.rules, A).unwrap();
            run(&mut fw, &ops);
        }
        assert!(fw.tasks.is_empty() && fw.rules.is_empty());
    }

    #[test]
    fn lockdown_saves_and_restores_defaults_exactly() {
        let mut fw = MockFirewall::new();
        // An unusual starting point: public already blocks outgoing.
        fw.status.profiles[2].default_out = FwAction::Block;
        let before = fw.status.clone();
        let ops =
            plan_lockdown_on(&fw.status, &fw.rules, &[A.into(), A.into(), B.into()], 7).unwrap();
        run(&mut fw, &ops);
        assert!(fw
            .status
            .profiles
            .iter()
            .all(|p| p.default_out == FwAction::Block));
        let l = naming::lockdown(&fw.rules).unwrap();
        assert_eq!(l.allowed.len(), 2, "duplicates are dropped");
        assert_eq!(
            l.saved,
            vec![
                (Profile::Domain, FwAction::Allow),
                (Profile::Private, FwAction::Allow),
                (Profile::Public, FwAction::Block)
            ]
        );
        assert!(plan_lockdown_on(&fw.status, &fw.rules, &[], 8).is_err());

        // Allow list changes while on.
        let c = "C:\\c.exe";
        {
            let ops = plan_allow(&fw.rules, c, 9).unwrap();
            run(&mut fw, &ops);
        }
        assert!(plan_allow(&fw.rules, c, 9).is_err());
        {
            let ops = plan_disallow(&fw.rules, c).unwrap();
            run(&mut fw, &ops);
        }

        let ops = plan_lockdown_off(&fw.status, &fw.rules).unwrap();
        run(&mut fw, &ops);
        assert_eq!(fw.status, before, "every profile is back exactly as it was");
        assert!(fw.rules.is_empty());
        assert!(plan_lockdown_off(&fw.status, &fw.rules).is_err());
        assert!(
            plan_allow(&fw.rules, c, 9).is_err(),
            "allow list needs lockdown"
        );
    }

    #[test]
    fn failures_roll_back() {
        let mut fw = MockFirewall::new();
        let before = fw.status.clone();
        let ops = plan_lockdown_on(&fw.status, &fw.rules, &[A.into()], 1).unwrap();
        // Fail at the second profile change: marker, allow rule, domain done.
        fw.fail_after = Some(4);
        let err = apply(&mut fw, &ops).unwrap_err();
        assert!(err.contains("Nothing was changed"));
        assert_eq!(fw.status, before);
        assert!(fw.rules.is_empty());
    }

    #[test]
    fn remove_all_ends_lockdown_and_cleans_everything() {
        let mut fw = MockFirewall::new();
        let before = fw.status.clone();
        let hour = BlockOptions {
            lifetime: Lifetime::Until(5000),
            ..Default::default()
        };
        {
            let ops = plan_block(&fw.rules, A, hour, 1).unwrap();
            run(&mut fw, &ops);
        }
        {
            let ops = plan_lockdown_on(&fw.status, &fw.rules, &[B.into()], 2).unwrap();
            run(&mut fw, &ops);
        }
        // A rule that is not ours stays.
        fw.rules.push(FwRule {
            name: "Someone else".into(),
            ..Default::default()
        });
        let ops = plan_remove_all(&fw.status, &fw.rules);
        run(&mut fw, &ops);
        assert_eq!(fw.status, before);
        assert_eq!(fw.rules.len(), 1);
        assert!(fw.tasks.is_empty());
        assert!(plan_remove_all(&fw.status, &fw.rules).is_empty());
    }

    #[test]
    fn undo_reverses_and_skips_expired_blocks() {
        let mut fw = MockFirewall::new();
        let ops = plan_block(&fw.rules, A, BlockOptions::default(), 1).unwrap();
        run(&mut fw, &ops);
        {
            let ops = undo_ops(&ops, 2, 0);
            run(&mut fw, &ops);
        }
        assert!(fw.rules.is_empty());

        // Undoing an unblock brings the block back...
        let opts = BlockOptions {
            lifetime: Lifetime::Until(100),
            ..Default::default()
        };
        {
            let ops = plan_block(&fw.rules, A, opts, 1).unwrap();
            run(&mut fw, &ops);
        }
        let unblock = plan_unblock(&fw.rules, A).unwrap();
        run(&mut fw, &unblock);
        {
            let ops = undo_ops(&unblock, 50, 0);
            run(&mut fw, &ops);
        }
        assert_eq!(fw.rules.len(), 1);
        assert_eq!(fw.tasks.len(), 1);
        // ...but not once its time is up.
        {
            let ops = plan_unblock(&fw.rules, A).unwrap();
            run(&mut fw, &ops);
        }
        assert!(undo_ops(&unblock, 150, 0).is_empty());

        // Undo of lockdown restores the old defaults.
        let before = fw.status.clone();
        let on = plan_lockdown_on(&fw.status, &fw.rules, &[], 3).unwrap();
        run(&mut fw, &on);
        {
            let ops = undo_ops(&on, 4, 0);
            run(&mut fw, &ops);
        }
        assert_eq!(fw.status, before);
        assert!(fw.rules.is_empty());
    }

    #[test]
    fn ops_are_described_and_serialisable() {
        let ops = plan_lockdown_on(&FwStatus::windows_default(), &[], &[A.into()], 1).unwrap();
        let json = serde_json::to_string(&ops).unwrap();
        let back: Vec<Op> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ops);
        assert!(ops[ops.len() - 1]
            .describe()
            .contains("outgoing default allow -> block"));
    }
}
