//! WireForge diagnostic tools: ping, traceroute, DNS, port check,
//! Wake-on-LAN, whois, subnet maths, speed test, public IP, system actions.
//!
//! Every function here that touches the network is only ever called because
//! the user pressed a button.

pub mod types;
pub use types::*;

pub mod dns;
pub mod http;
pub mod ping;
pub mod ports;
pub mod publicip;
pub mod speedtest;
pub mod subnet;
pub mod sysactions;
pub mod trace;
pub mod whois;
pub mod wol;

mod checks;
pub use checks::selftest;
