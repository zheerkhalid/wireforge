//! The firewall behind a trait, so every plan can be tested against an
//! in-memory mock and the demo mode never touches the real firewall.

use crate::model::*;
use crate::tasks::Expiry;

pub trait FirewallApi {
    fn status(&self) -> Result<FwStatus, String>;
    fn rules(&self) -> Result<Vec<FwRule>, String>;
    fn add_rule(&mut self, rule: &FwRule) -> Result<(), String>;
    /// Removes every rule with this name; no error when there is none.
    fn remove_rule(&mut self, name: &str) -> Result<(), String>;
    fn set_default_outbound(&mut self, profile: Profile, action: FwAction) -> Result<(), String>;
    fn schedule(&mut self, expiry: &Expiry) -> Result<(), String>;
    /// Deletes a scheduled removal; no error when it does not exist.
    fn cancel(&mut self, task: &str) -> Result<(), String>;
}

/// An in-memory firewall for tests and `--demo`.
#[derive(Clone, Debug, Default)]
pub struct MockFirewall {
    pub status: FwStatus,
    pub rules: Vec<FwRule>,
    pub tasks: Vec<Expiry>,
    /// Fail the n-th mutating call from now (1 = the next one), for rollback tests.
    pub fail_after: Option<usize>,
    pub calls: usize,
}

impl MockFirewall {
    pub fn new() -> MockFirewall {
        MockFirewall {
            status: FwStatus::windows_default(),
            ..Default::default()
        }
    }

    fn tick(&mut self) -> Result<(), String> {
        self.calls += 1;
        if let Some(n) = self.fail_after {
            if n <= 1 {
                self.fail_after = None;
                return Err("Access is denied (mock).".into());
            }
            self.fail_after = Some(n - 1);
        }
        Ok(())
    }
}

impl FirewallApi for MockFirewall {
    fn status(&self) -> Result<FwStatus, String> {
        Ok(self.status.clone())
    }

    fn rules(&self) -> Result<Vec<FwRule>, String> {
        Ok(self.rules.clone())
    }

    fn add_rule(&mut self, rule: &FwRule) -> Result<(), String> {
        self.tick()?;
        self.rules.push(rule.clone());
        Ok(())
    }

    fn remove_rule(&mut self, name: &str) -> Result<(), String> {
        self.tick()?;
        self.rules.retain(|r| r.name != name);
        Ok(())
    }

    fn set_default_outbound(&mut self, profile: Profile, action: FwAction) -> Result<(), String> {
        self.tick()?;
        if let Some(p) = self
            .status
            .profiles
            .iter_mut()
            .find(|p| p.profile == profile)
        {
            p.default_out = action;
        }
        Ok(())
    }

    fn schedule(&mut self, expiry: &Expiry) -> Result<(), String> {
        self.tick()?;
        self.tasks.retain(|t| t.task != expiry.task);
        self.tasks.push(expiry.clone());
        Ok(())
    }

    fn cancel(&mut self, task: &str) -> Result<(), String> {
        self.tick()?;
        self.tasks.retain(|t| t.task != task);
        Ok(())
    }
}
