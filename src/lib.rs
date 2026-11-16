//! WireForge: a network and Wi-Fi monitor and toolkit for Windows.
//!
//! The collectors live in three small crates (`wf-traffic`, `wf-wifi`,
//! `wf-tools`); this library holds settings, export, demo data and the user
//! interface. `main.rs` only parses the command line and opens the window.
pub mod demo;
pub mod export;
pub mod fmt;
pub mod report;
pub mod selftest;
pub mod settings;
pub mod sys;
pub mod ui;

pub use wf_tools as tools;
pub use wf_traffic as traffic;
pub use wf_wifi as wifi;
