//! The data model the user interface is written against.
//!
//! CONTRACT: the UI and the demo data use these names and fields. Fields and
//! types may be ADDED (every struct implements `Default`, and the UI builds
//! values with `..Default::default()`), but existing public names, field names
//! and field types must not be renamed, removed or changed.

use serde::{Deserialize, Serialize};

/// One echo reply (or the lack of one).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PingReply {
    pub seq: u32,
    /// Who answered (the target, or a router for TTL-expired replies).
    pub from: Option<String>,
    /// Round-trip time in milliseconds; `None` when nothing came back.
    pub rtt_ms: Option<f32>,
    pub ttl: Option<u8>,
    /// "Reply", "Timed out", "TTL expired", "Destination unreachable", ...
    pub status: String,
    /// The echo reached the target.
    pub ok: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PingStats {
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f32,
    pub min_ms: f32,
    pub avg_ms: f32,
    pub max_ms: f32,
    /// Mean absolute difference between consecutive replies.
    pub jitter_ms: f32,
    pub stddev_ms: f32,
}

/// One hop of a traceroute.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Hop {
    pub ttl: u8,
    pub addr: Option<String>,
    /// Reverse-DNS name when asked for and found.
    pub host: Option<String>,
    pub sent: u32,
    pub received: u32,
    /// One entry per probe; `None` = no answer.
    pub rtts_ms: Vec<Option<f32>>,
    pub loss_pct: f32,
    pub min_ms: Option<f32>,
    pub avg_ms: Option<f32>,
    pub max_ms: Option<f32>,
    /// This hop is the destination.
    pub reached: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    /// "A", "AAAA", "MX", ...
    pub rtype: String,
    pub ttl: u32,
    /// Human-readable data ("10 mail.example.org").
    pub data: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DnsAnswer {
    /// The server that answered.
    pub server: String,
    /// "NOERROR", "NXDOMAIN", "SERVFAIL", ...
    pub rcode: String,
    pub elapsed_ms: f32,
    pub authoritative: bool,
    pub truncated: bool,
    /// "UDP" or "TCP".
    pub transport: String,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    /// The host answered with a refusal.
    Closed,
    /// No answer within the timeout (filtered or host down).
    #[default]
    NoAnswer,
}

impl PortState {
    pub fn label(self) -> &'static str {
        match self {
            PortState::Open => "Open",
            PortState::Closed => "Closed",
            PortState::NoAnswer => "No answer",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    /// Usual service on this port ("HTTPS").
    pub service: String,
    pub state: PortState,
    pub connect_ms: Option<f32>,
}

/// Everything the subnet calculator shows.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubnetInfo {
    pub address: String,
    pub prefix: u8,
    pub mask: String,
    pub wildcard: String,
    pub network: String,
    pub broadcast: String,
    pub first_host: String,
    pub last_host: String,
    /// Usable hosts.
    pub hosts: u64,
    pub total: u64,
    /// "Private (RFC 1918)", "Loopback", "Link-local", "CGNAT (RFC 6598)", "Public", ...
    pub scope: String,
    /// "A", "B", "C", "D", "E"
    pub class: String,
    /// `11000000.10101000.00000001.00001010` with the network part first.
    pub address_bits: String,
    pub mask_bits: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpeedPhase {
    #[default]
    Locating,
    Latency,
    Download,
    Upload,
    Done,
}

/// Live progress of a speed test.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SpeedProgress {
    pub phase: SpeedPhase,
    /// 0.0 ..= 1.0 within the phase.
    pub fraction: f32,
    /// Current reading: Mbit/s for download / upload, ms for latency.
    pub current: f64,
    /// The server in use, once known ("Frankfurt, DE").
    pub server: String,
}

/// A finished speed test.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpeedResult {
    /// Unix seconds.
    pub when_unix: i64,
    /// The measurement service ("M-Lab NDT7" ...).
    pub provider: String,
    /// Server name / location as the service reports it.
    pub server: String,
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub bytes_down: u64,
    pub bytes_up: u64,
    /// Adapter name, filled in by the UI.
    pub adapter: String,
}

/// What the UI must tell the user about the measurement service before a test.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProviderInfo {
    pub name: &'static str,
    pub operator: &'static str,
    pub homepage: &'static str,
    pub terms_url: &'static str,
    pub privacy_url: &'static str,
    /// Plain sentences: what is sent, what the service keeps or publishes.
    pub notice: &'static str,
    /// Roughly how much data one run transfers.
    pub data_note: &'static str,
}

/// A system command, built separately from running it so it can be unit-tested.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SystemCommand {
    pub program: String,
    pub args: Vec<String>,
    /// What it does, for the confirmation dialog.
    pub description: String,
    pub needs_admin: bool,
}
