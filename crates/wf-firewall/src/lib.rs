//! WireForge's app firewall: a thin layer over Windows Defender Firewall.
//!
//! WireForge never filters traffic itself. It adds ordinary Windows Firewall
//! rules (group "WireForge", one per program and direction) and, for
//! lockdown mode, changes the default outbound action of the profiles and
//! remembers the previous values so they can be put back exactly.
//!
//! * [`model`]: profiles, actions, rules and the firewall status.
//! * [`naming`]: rule names, the group and the metadata kept in descriptions.
//! * [`backend`]: the [`backend::FirewallApi`] trait and an in-memory mock.
//! * [`plan`]: what to change for each action, as a list of reversible steps.
//! * [`journal`]: the log of every change WireForge made, used for undo.
//! * [`watch`]: new-app detection from connection snapshots.
//! * [`cli`]: the narrow command line of the elevated helper.
//! * [`com`]: the real Windows Firewall through `INetFwPolicy2` (Windows only).
pub mod backend;
pub mod cli;
#[cfg(windows)]
pub mod com;
pub mod journal;
pub mod model;
pub mod naming;
pub mod plan;
pub mod tasks;
pub mod watch;

pub use backend::{FirewallApi, MockFirewall};
pub use model::*;
