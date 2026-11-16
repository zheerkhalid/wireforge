//! Tools: ping, traceroute, DNS lookup, port check, Wake-on-LAN, whois, a
//! subnet calculator, the interface report and two system actions.
//!
//! Nothing here runs by itself: every tool starts on a click, works on its
//! own thread and can be stopped. In demo mode no tool is ever started.

use super::app::{App, Confirm};
use super::charts::{self, LineChart, Series};
use super::theme::{pal, regular, semibold, Icon};
use super::widgets::{self, Col};
use crate::export::Table;
use crate::fmt;
use eframe::egui::{
    self, text::LayoutJob, vec2, Align, CornerRadius, FontId, Frame, Layout, Margin, Response,
    RichText, Sense, Stroke, TextFormat, Ui,
};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};
use wf_tools::{dns, ping, ports, subnet, sysactions, trace, whois, wol};
use wf_tools::{
    DnsAnswer, DnsRecord, Hop, PingReply, PingStats, PortResult, PortState, SubnetInfo,
    SystemCommand,
};
use wf_traffic::AdapterInfo;

/// The most replies a ping run keeps (one hour at one per second).
const PING_KEEP: usize = 3600;
/// How many replies the chart shows.
const PING_CHART: usize = 300;
const PING_TIMEOUT_MS: u32 = 2000;
const PORT_TIMEOUT_MS: u32 = 1500;
const DEFAULT_PORTS: &str = "22, 80, 443, 445, 3389, 8080";
const DEMO_SENDS: &str = "Demo mode: nothing is sent";
const DEMO_CHANGES: &str = "Demo mode: nothing was changed";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tool {
    Ping,
    Trace,
    Dns,
    Ports,
    Wol,
    Whois,
    Subnet,
    Report,
    Actions,
}

/// The tools in picker order: `(tool, label, view name)`.
const TOOLS: [(Tool, &str, &str); 9] = [
    (Tool::Ping, "Ping", "tools-ping"),
    (Tool::Trace, "Traceroute", "tools-trace"),
    (Tool::Dns, "DNS", "tools-dns"),
    (Tool::Ports, "Ports", "tools-ports"),
    (Tool::Wol, "Wake-on-LAN", "tools-wol"),
    (Tool::Whois, "Whois", "tools-whois"),
    (Tool::Subnet, "Subnet", "tools-subnet"),
    (Tool::Report, "Interfaces", "tools-report"),
    (Tool::Actions, "Actions", "tools-actions"),
];

/// The tool a `--view` argument asks for (ping when it names none).
fn tool_from_view(view: &str) -> Tool {
    TOOLS
        .iter()
        .find(|t| t.2 == view)
        .map(|t| t.0)
        .unwrap_or(Tool::Ping)
}

// --------------------------------------------------------------------------------------
// Pure helpers (unit-tested)
// --------------------------------------------------------------------------------------

/// Checks a host field: one name or address, nothing that looks like a link.
fn validate_host(text: &str) -> Result<String, String> {
    let host = text.trim();
    if host.is_empty() {
        return Err("Enter a host name or an address first.".into());
    }
    if host.contains("://") || host.contains('/') || host.contains('\\') {
        return Err(
            "Enter only the host name or address, without http:// and without a path.".into(),
        );
    }
    if host
        .chars()
        .any(|c| c.is_whitespace() || c == ',' || c == ';')
    {
        return Err("Enter one host only, without spaces or commas.".into());
    }
    if host
        .chars()
        .any(|c| c.is_control() || c == '"' || c == '\'')
    {
        return Err("The host contains characters that cannot be part of a name.".into());
    }
    if host.chars().count() > 253 {
        return Err("That name is too long (253 characters at most).".into());
    }
    Ok(host.to_string())
}

/// Checks a ports field and says how many ports it names.
fn validate_ports(text: &str) -> Result<Vec<u16>, String> {
    if text.trim().is_empty() {
        return Err("Enter at least one port, for example 80, 443.".into());
    }
    let list = ports::parse_ports(text)?;
    if list.is_empty() {
        return Err("Enter at least one port, for example 80, 443.".into());
    }
    Ok(list)
}

/// The common ports as text for the ports field.
fn common_ports_text() -> String {
    ports::COMMON_PORTS
        .iter()
        .map(|(port, _)| port.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// One line of the ping log.
fn ping_log_line(r: &PingReply) -> String {
    let status = if r.status.trim().is_empty() {
        "Timed out"
    } else {
        r.status.trim()
    };
    match (r.ok, r.from.as_deref(), r.rtt_ms) {
        (true, Some(from), Some(rtt)) => {
            let mut line = format!("Reply from {from}: {}", fmt::millis(rtt as f64));
            if let Some(ttl) = r.ttl {
                line.push_str(&format!(", TTL {ttl}"));
            }
            line
        }
        (true, _, _) => "Reply".to_string(),
        (false, Some(from), _) => format!("{status} (reported by {from})"),
        (false, None, _) => status.to_string(),
    }
}

/// The round-trip times of the newest replies for the chart; lost replies are gaps.
fn ping_chart_values(replies: &[PingReply]) -> Vec<f64> {
    let skip = replies.len().saturating_sub(PING_CHART);
    replies[skip..]
        .iter()
        .map(|r| match (r.ok, r.rtt_ms) {
            (true, Some(rtt)) => rtt as f64,
            _ => f64::NAN,
        })
        .collect()
}

fn ms_or_dash(v: Option<f32>) -> String {
    match v {
        Some(v) if v >= 100.0 => format!("{v:.0}"),
        Some(v) => format!("{v:.1}"),
        None => "-".into(),
    }
}

fn ping_tables(host: &str, replies: &[PingReply], times: &[i64], offset: i64) -> Vec<Table> {
    let stats = ping::stats(replies);
    let mut summary = Table::new(&format!("Ping {host}: summary"), &["Property", "Value"]);
    for (label, value) in [
        ("Host", host.to_string()),
        ("Sent", stats.sent.to_string()),
        ("Received", stats.received.to_string()),
        ("Loss (%)", format!("{:.1}", stats.loss_pct)),
        ("Minimum (ms)", format!("{:.2}", stats.min_ms)),
        ("Average (ms)", format!("{:.2}", stats.avg_ms)),
        ("Maximum (ms)", format!("{:.2}", stats.max_ms)),
        ("Jitter (ms)", format!("{:.2}", stats.jitter_ms)),
    ] {
        summary.push(vec![label.to_string(), value]);
    }
    let mut rows = Table::new(
        &format!("Ping {host}: replies"),
        &["No.", "Time", "Result", "From", "Round trip (ms)", "TTL"],
    );
    for (i, r) in replies.iter().enumerate() {
        rows.push(vec![
            r.seq.to_string(),
            times
                .get(i)
                .map(|t| fmt::clock(*t, offset))
                .unwrap_or_default(),
            if r.status.is_empty() {
                if r.ok { "Reply" } else { "Timed out" }.to_string()
            } else {
                r.status.clone()
            },
            r.from.clone().unwrap_or_default(),
            r.rtt_ms.map(|v| format!("{v:.2}")).unwrap_or_default(),
            r.ttl.map(|v| v.to_string()).unwrap_or_default(),
        ]);
    }
    vec![summary, rows]
}

fn trace_table(host: &str, hops: &[Hop]) -> Table {
    let mut t = Table::new(
        &format!("Traceroute to {host}"),
        &[
            "Hop",
            "Address",
            "Host name",
            "Loss (%)",
            "Min (ms)",
            "Avg (ms)",
            "Max (ms)",
            "Destination",
        ],
    );
    for h in hops {
        t.push(vec![
            h.ttl.to_string(),
            h.addr.clone().unwrap_or_else(|| "*".into()),
            h.host.clone().unwrap_or_default(),
            format!("{:.0}", h.loss_pct),
            h.min_ms.map(|v| format!("{v:.2}")).unwrap_or_default(),
            h.avg_ms.map(|v| format!("{v:.2}")).unwrap_or_default(),
            h.max_ms.map(|v| format!("{v:.2}")).unwrap_or_default(),
            crate::export::yes_no(h.reached),
        ]);
    }
    t
}

/// What a finished (or stopped) trace amounts to, in one sentence.
fn trace_outcome(host: &str, hops: &[Hop], stopped: bool, max_hops: u8) -> String {
    if let Some(last) = hops.iter().find(|h| h.reached) {
        let hops_word = if last.ttl == 1 { "hop" } else { "hops" };
        return format!("Reached {host} in {} {hops_word}.", last.ttl);
    }
    if stopped {
        return format!("Stopped after {} hops, before reaching {host}.", hops.len());
    }
    format!(
        "{host} did not answer within {max_hops} hops. The route may still work: some \
         destinations do not answer this kind of request."
    )
}

/// A DNS response code in plain words.
fn rcode_words(rcode: &str, answers: usize) -> String {
    match rcode.trim().to_ascii_uppercase().as_str() {
        "NOERROR" if answers == 0 => {
            "The name exists, but it has no records of this type".to_string()
        }
        "NOERROR" => "Answered".to_string(),
        "NXDOMAIN" => "This name does not exist".to_string(),
        "SERVFAIL" => "The server could not find an answer (server failure)".to_string(),
        "REFUSED" => "The server refused to answer this question".to_string(),
        "FORMERR" => "The server did not understand the question".to_string(),
        "NOTIMP" => "The server does not support this kind of question".to_string(),
        other => format!("The server answered with an error ({other})"),
    }
}

/// The server argument for a lookup: `None` = system default.
/// `choice`: 0 = system, 1.. = the public servers, last = custom.
fn dns_server_arg(choice: usize, custom: &str) -> Result<Option<String>, String> {
    if choice == 0 {
        return Ok(None);
    }
    if let Some((_, addr)) = dns::PUBLIC_SERVERS.get(choice - 1) {
        return Ok(Some((*addr).to_string()));
    }
    let text = custom.trim();
    if text.is_empty() {
        return Err("Enter the address of the DNS server to ask.".into());
    }
    let bare = text.split('%').next().unwrap_or(text);
    if bare.parse::<IpAddr>().is_err() {
        return Err(
            "The DNS server must be an IP address, for example 192.168.1.1 (not a name).".into(),
        );
    }
    Ok(Some(text.to_string()))
}

fn dns_tables(question: &str, answer: &DnsAnswer) -> Vec<Table> {
    let mut out = Vec::new();
    for (title, records) in [
        ("answers", &answer.answers),
        ("authority", &answer.authority),
        ("additional", &answer.additional),
    ] {
        if records.is_empty() {
            continue;
        }
        let mut t = Table::new(
            &format!("DNS {question}: {title}"),
            &["Name", "Type", "TTL (s)", "Data"],
        );
        for r in records {
            t.push(vec![
                r.name.clone(),
                r.rtype.clone(),
                r.ttl.to_string(),
                r.data.clone(),
            ]);
        }
        out.push(t);
    }
    out
}

fn ports_table(host: &str, results: &[PortResult]) -> Table {
    let mut t = Table::new(
        &format!("Port check of {host}"),
        &["Port", "Service", "State", "Connect time (ms)"],
    );
    for r in results {
        t.push(vec![
            r.port.to_string(),
            r.service.clone(),
            r.state.label().to_string(),
            r.connect_ms.map(|v| format!("{v:.1}")).unwrap_or_default(),
        ]);
    }
    t
}

/// Puts a result into the list, keeping it sorted by port.
fn insert_port(results: &mut Vec<PortResult>, r: PortResult) {
    match results.binary_search_by_key(&r.port, |x| x.port) {
        Ok(i) => results[i] = r,
        Err(i) => results.insert(i, r),
    }
}

/// The broadcast address of the network an address belongs to.
fn broadcast_of(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let p = prefix.min(32) as u32;
    let mask: u32 = if p == 0 { 0 } else { u32::MAX << (32 - p) };
    let host_bits = !mask;
    Ipv4Addr::from(u32::from(addr) | host_bits)
}

/// Checks the Wake-on-LAN fields: the packet can be built and the target is
/// inside a local network.
fn wol_check(mac: &str, broadcast: &str) -> Result<Ipv4Addr, String> {
    if mac.trim().is_empty() {
        return Err("Enter the MAC address of the device to wake.".into());
    }
    wol::magic_packet(mac.trim())?;
    let target: Ipv4Addr = broadcast
        .trim()
        .parse()
        .map_err(|_| "The broadcast address must look like 192.168.1.255.".to_string())?;
    if !wol::allowed_target(target) {
        return Err(
            "The wake packet is only sent inside your own network: use the broadcast \
             address of a private network, for example 192.168.1.255."
                .into(),
        );
    }
    Ok(target)
}

/// Splits a dotted bit string after the first `prefix` bits.
fn split_bits(bits: &str, prefix: u8) -> (&str, &str) {
    let mut seen = 0u8;
    for (i, c) in bits.char_indices() {
        if seen == prefix {
            return bits.split_at(i);
        }
        if c == '0' || c == '1' {
            seen += 1;
        }
    }
    (bits, "")
}

/// A command as it would be typed, for the confirmation dialog.
fn command_line(c: &SystemCommand) -> String {
    let mut line = c.program.clone();
    for arg in &c.args {
        line.push(' ');
        if arg.contains(' ') {
            line.push_str(&format!("\"{arg}\""));
        } else {
            line.push_str(arg);
        }
    }
    line
}

/// The adapters of the interface report in display order: the default one
/// first, connected before disconnected. Without `all`, only real,
/// connected adapters.
fn report_adapters(adapters: &[AdapterInfo], all: bool) -> Vec<&AdapterInfo> {
    let mut list: Vec<&AdapterInfo> = adapters
        .iter()
        .filter(|a| all || a.is_default || (a.up && a.physical))
        .collect();
    list.sort_by_key(|a| (!a.is_default, !a.up, !a.physical, a.name.to_lowercase()));
    list
}

fn resolve_first(host: &str) -> Result<IpAddr, String> {
    ping::resolve(host)?
        .into_iter()
        .next()
        .ok_or_else(|| "No address was found for this name.".to_string())
}

// --------------------------------------------------------------------------------------
// State
// --------------------------------------------------------------------------------------

enum PingMsg {
    Target(String),
    Reply(PingReply),
    Failed(String),
}

#[derive(Default)]
struct PingState {
    host: String,
    running: bool,
    cancel: Arc<AtomicBool>,
    rx: Option<Receiver<PingMsg>>,
    /// The host of the current / last run and the address it resolved to.
    run_host: String,
    target: String,
    replies: Vec<PingReply>,
    /// Unix time of each reply.
    times: Vec<i64>,
    stats: PingStats,
    error: Option<String>,
}

impl PingState {
    fn stop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.rx = None;
        self.running = false;
    }

    fn start(&mut self, ctx: &egui::Context) {
        let host = match validate_host(&self.host) {
            Ok(h) => h,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        self.stop();
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = channel();
        self.cancel = cancel.clone();
        self.rx = Some(rx);
        self.running = true;
        self.error = None;
        self.replies.clear();
        self.times.clear();
        self.stats = PingStats::default();
        self.target.clear();
        self.run_host = host.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let addr = match resolve_first(&host) {
                Ok(a) => a,
                Err(e) => {
                    let _ = tx.send(PingMsg::Failed(e));
                    ctx.request_repaint();
                    return;
                }
            };
            let _ = tx.send(PingMsg::Target(addr.to_string()));
            let mut seq = 0u32;
            while !cancel.load(Ordering::Relaxed) {
                let began = Instant::now();
                seq = seq.wrapping_add(1);
                let reply = ping::ping_once(addr, seq, PING_TIMEOUT_MS, 128, 32);
                if cancel.load(Ordering::Relaxed) || tx.send(PingMsg::Reply(reply)).is_err() {
                    return;
                }
                ctx.request_repaint();
                while began.elapsed() < Duration::from_secs(1) && !cancel.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(40));
                }
            }
        });
    }

    fn push(&mut self, reply: PingReply, now: i64) {
        self.replies.push(reply);
        self.times.push(now);
        if self.replies.len() > PING_KEEP {
            let extra = self.replies.len() - PING_KEEP;
            self.replies.drain(..extra);
            self.times.drain(..extra.min(self.times.len()));
        }
        self.stats = ping::stats(&self.replies);
    }

    fn poll(&mut self, now: i64) {
        let mut got: Vec<PingMsg> = Vec::new();
        if let Some(rx) = &self.rx {
            while let Ok(m) = rx.try_recv() {
                got.push(m);
            }
        }
        for m in got {
            match m {
                PingMsg::Target(t) => self.target = t,
                PingMsg::Reply(r) => self.push(r, now),
                PingMsg::Failed(e) => {
                    self.error = Some(e);
                    self.stop();
                }
            }
        }
    }
}

enum TraceMsg {
    Target(String),
    Hop(Hop),
    Done(Option<String>),
}

struct TraceState {
    host: String,
    max_hops: u8,
    names: bool,
    running: bool,
    cancel: Arc<AtomicBool>,
    rx: Option<Receiver<TraceMsg>>,
    run_host: String,
    run_max: u8,
    target: String,
    hops: Vec<Hop>,
    outcome: Option<String>,
    error: Option<String>,
}

impl Default for TraceState {
    fn default() -> Self {
        TraceState {
            host: String::new(),
            max_hops: 30,
            names: true,
            running: false,
            cancel: Arc::default(),
            rx: None,
            run_host: String::new(),
            run_max: 30,
            target: String::new(),
            hops: Vec::new(),
            outcome: None,
            error: None,
        }
    }
}

impl TraceState {
    fn stop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.rx = None;
        if self.running {
            self.running = false;
            self.outcome = Some(trace_outcome(
                &self.run_host,
                &self.hops,
                true,
                self.run_max,
            ));
        }
    }

    fn start(&mut self, ctx: &egui::Context) {
        let host = match validate_host(&self.host) {
            Ok(h) => h,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        self.stop();
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = channel();
        self.cancel = cancel.clone();
        self.rx = Some(rx);
        self.running = true;
        self.error = None;
        self.outcome = None;
        self.hops.clear();
        self.target.clear();
        self.run_host = host.clone();
        self.run_max = self.max_hops;
        let options = trace::TraceOptions {
            max_hops: self.max_hops,
            resolve_names: self.names,
            ..Default::default()
        };
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let addr = match resolve_first(&host) {
                Ok(a) => a,
                Err(e) => {
                    let _ = tx.send(TraceMsg::Done(Some(e)));
                    ctx.request_repaint();
                    return;
                }
            };
            let _ = tx.send(TraceMsg::Target(addr.to_string()));
            let hop_tx = tx.clone();
            let hop_ctx = ctx.clone();
            let mut on_hop = move |h: &Hop| {
                let _ = hop_tx.send(TraceMsg::Hop(h.clone()));
                hop_ctx.request_repaint();
            };
            trace::trace(addr, options, &cancel, &mut on_hop);
            let _ = tx.send(TraceMsg::Done(None));
            ctx.request_repaint();
        });
    }

    fn poll(&mut self) {
        let mut got: Vec<TraceMsg> = Vec::new();
        if let Some(rx) = &self.rx {
            while let Ok(m) = rx.try_recv() {
                got.push(m);
            }
        }
        for m in got {
            match m {
                TraceMsg::Target(t) => self.target = t,
                TraceMsg::Hop(h) => self.hops.push(h),
                TraceMsg::Done(error) => {
                    self.running = false;
                    self.rx = None;
                    match error {
                        Some(e) => self.error = Some(e),
                        None => {
                            self.outcome = Some(trace_outcome(
                                &self.run_host,
                                &self.hops,
                                false,
                                self.run_max,
                            ))
                        }
                    }
                }
            }
        }
    }
}

#[derive(Default)]
struct DnsState {
    name: String,
    rtype: usize,
    /// 0 = system default, 1.. = `dns::PUBLIC_SERVERS`, last = custom.
    server: usize,
    custom: String,
    busy: bool,
    rx: Option<Receiver<Result<DnsAnswer, String>>>,
    /// "example.org (MX)" of the shown result.
    question: String,
    result: Option<Result<DnsAnswer, String>>,
    error: Option<String>,
}

impl DnsState {
    fn custom_index() -> usize {
        dns::PUBLIC_SERVERS.len() + 1
    }

    fn stop(&mut self) {
        self.rx = None;
        self.busy = false;
    }

    fn start(&mut self, ctx: &egui::Context) {
        let name = match validate_host(&self.name) {
            Ok(n) => n,
            Err(_) if self.name.trim().is_empty() => {
                self.error = Some("Enter a name to look up, for example example.org.".into());
                return;
            }
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        let server = match dns_server_arg(self.server, &self.custom) {
            Ok(s) => s,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        let rtype = dns::RECORD_TYPES
            .get(self.rtype)
            .copied()
            .unwrap_or("A")
            .to_string();
        let (tx, rx) = channel();
        self.rx = Some(rx);
        self.busy = true;
        self.error = None;
        self.result = None;
        self.question = format!("{name} ({rtype})");
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(dns::lookup(&name, &rtype, server.as_deref()));
            ctx.request_repaint();
        });
    }

    fn poll(&mut self) {
        let got = self.rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some(result) = got {
            self.result = Some(result);
            self.stop();
        }
    }
}

enum PortsMsg {
    Target(String),
    Result(PortResult),
    Done(Option<String>),
}

#[derive(Default)]
struct PortsState {
    host: String,
    ports: String,
    /// "This is my own equipment or I have permission". Never saved.
    permitted: bool,
    running: bool,
    cancel: Arc<AtomicBool>,
    rx: Option<Receiver<PortsMsg>>,
    run_host: String,
    target: String,
    total: usize,
    results: Vec<PortResult>,
    finished: bool,
    error: Option<String>,
}

impl PortsState {
    fn stop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.rx = None;
        self.running = false;
    }

    fn start(&mut self, ctx: &egui::Context) {
        if !self.permitted {
            return;
        }
        let checked = validate_host(&self.host).and_then(|h| Ok((h, validate_ports(&self.ports)?)));
        let (host, list) = match checked {
            Ok(v) => v,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        self.stop();
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = channel();
        self.cancel = cancel.clone();
        self.rx = Some(rx);
        self.running = true;
        self.finished = false;
        self.error = None;
        self.results.clear();
        self.target.clear();
        self.total = list.len().min(ports::MAX_PORTS);
        self.run_host = host.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let addr = match resolve_first(&host) {
                Ok(a) => a,
                Err(e) => {
                    let _ = tx.send(PortsMsg::Done(Some(e)));
                    ctx.request_repaint();
                    return;
                }
            };
            let _ = tx.send(PortsMsg::Target(addr.to_string()));
            let result_tx = tx.clone();
            let result_ctx = ctx.clone();
            let mut on_result = move |r: &PortResult| {
                let _ = result_tx.send(PortsMsg::Result(r.clone()));
                result_ctx.request_repaint();
            };
            ports::check_ports(addr, &list, PORT_TIMEOUT_MS, &cancel, &mut on_result);
            let _ = tx.send(PortsMsg::Done(None));
            ctx.request_repaint();
        });
    }

    fn poll(&mut self) {
        let mut got: Vec<PortsMsg> = Vec::new();
        if let Some(rx) = &self.rx {
            while let Ok(m) = rx.try_recv() {
                got.push(m);
            }
        }
        for m in got {
            match m {
                PortsMsg::Target(t) => self.target = t,
                PortsMsg::Result(r) => insert_port(&mut self.results, r),
                PortsMsg::Done(error) => {
                    self.running = false;
                    self.rx = None;
                    self.finished = error.is_none();
                    self.error = error;
                }
            }
        }
    }
}

#[derive(Default)]
struct WolState {
    mac: String,
    broadcast: String,
    /// The broadcast field was filled in from the adapter once.
    prefilled: bool,
    busy: bool,
    rx: Option<Receiver<Result<String, String>>>,
    result: Option<Result<String, String>>,
}

impl WolState {
    fn start(&mut self, ctx: &egui::Context) {
        let target = match wol_check(&self.mac, &self.broadcast) {
            Ok(t) => t,
            Err(e) => {
                self.result = Some(Err(e));
                return;
            }
        };
        let mac = self.mac.trim().to_string();
        let (tx, rx) = channel();
        self.rx = Some(rx);
        self.busy = true;
        self.result = None;
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let sent = wol::send(&mac, target).map(|()| {
                format!(
                    "Wake packet sent for {mac} to {target} (UDP port 9). Devices do not \
                     answer it: look whether the device switches on."
                )
            });
            let _ = tx.send(sent);
            ctx.request_repaint();
        });
    }

    fn poll(&mut self) {
        let got = self.rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some(result) = got {
            self.result = Some(result);
            self.rx = None;
            self.busy = false;
        }
    }
}

#[derive(Default)]
struct WhoisState {
    query: String,
    busy: bool,
    rx: Option<Receiver<Result<String, String>>>,
    asked: String,
    result: Option<Result<String, String>>,
}

impl WhoisState {
    fn stop(&mut self) {
        self.rx = None;
        self.busy = false;
    }

    fn start(&mut self, ctx: &egui::Context) {
        let query = match whois::clean_query(&self.query) {
            Ok(q) => q,
            Err(e) => {
                self.result = Some(Err(e));
                return;
            }
        };
        let (tx, rx) = channel();
        self.rx = Some(rx);
        self.busy = true;
        self.result = None;
        self.asked = query.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(whois::whois(&query));
            ctx.request_repaint();
        });
    }

    fn poll(&mut self) {
        let got = self.rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some(result) = got {
            self.result = Some(result);
            self.stop();
        }
    }
}

type ActionOutcome = (&'static str, Result<String, String>);

#[derive(Default)]
struct ActionsState {
    /// The tag of the action that is running.
    busy: Option<&'static str>,
    rx: Option<Receiver<ActionOutcome>>,
    flush: Option<Result<String, String>>,
    renew: Option<Result<String, String>>,
}

impl ActionsState {
    fn start(&mut self, tag: &'static str, commands: Vec<SystemCommand>, ctx: &egui::Context) {
        if self.busy.is_some() || commands.is_empty() {
            return;
        }
        let (tx, rx) = channel();
        self.rx = Some(rx);
        self.busy = Some(tag);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let mut output = String::new();
            let mut result = Ok(());
            for command in &commands {
                match sysactions::run(command) {
                    Ok(text) => {
                        if !output.is_empty() {
                            output.push_str("\n\n");
                        }
                        output.push_str(text.trim());
                    }
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                }
            }
            let outcome = match result {
                Ok(()) if output.trim().is_empty() => Ok("Done.".to_string()),
                Ok(()) => Ok(output),
                Err(e) if output.is_empty() => Err(e),
                Err(e) => Err(format!("{output}\n\n{e}")),
            };
            let _ = tx.send((tag, outcome));
            ctx.request_repaint();
        });
    }

    fn poll(&mut self) {
        let got = self.rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some((tag, result)) = got {
            if tag == "flush" {
                self.flush = Some(result);
            } else {
                self.renew = Some(result);
            }
            self.rx = None;
            self.busy = None;
        }
    }
}

/// State of this page.
pub struct ToolsPage {
    tool: Tool,
    ping: PingState,
    trace: TraceState,
    dns: DnsState,
    ports: PortsState,
    wol: WolState,
    whois: WhoisState,
    subnet: String,
    report_all: bool,
    actions: ActionsState,
}

impl ToolsPage {
    pub fn new(demo: bool, view: &str) -> Self {
        let mut page = ToolsPage {
            tool: tool_from_view(view),
            ping: PingState::default(),
            trace: TraceState::default(),
            dns: DnsState::default(),
            ports: PortsState {
                ports: DEFAULT_PORTS.into(),
                ..Default::default()
            },
            wol: WolState::default(),
            whois: WhoisState::default(),
            subnet: String::new(),
            report_all: false,
            actions: ActionsState::default(),
        };
        if demo {
            page.fill_demo(crate::sys::now_unix());
        }
        page
    }

    /// Finished, invented results for every tool.
    fn fill_demo(&mut self, now: i64) {
        use crate::demo::tools as demo;
        self.ping.host = demo::GATEWAY.into();
        self.ping.run_host = demo::GATEWAY.into();
        self.ping.target = demo::GATEWAY.into();
        self.ping.replies = demo::ping_replies();
        let n = self.ping.replies.len() as i64;
        self.ping.times = (0..n).map(|i| now - n + i).collect();
        self.ping.stats = ping::stats(&self.ping.replies);

        self.trace.host = demo::HOST.into();
        self.trace.run_host = demo::HOST.into();
        self.trace.hops = demo::trace_hops();
        self.trace.target = self
            .trace
            .hops
            .last()
            .and_then(|h| h.addr.clone())
            .unwrap_or_default();
        self.trace.outcome = Some(trace_outcome(demo::HOST, &self.trace.hops, false, 30));

        self.dns.name = demo::HOST.into();
        self.dns.question = format!("{} (A, AAAA and MX)", demo::HOST);
        self.dns.result = Some(Ok(demo::dns_answer()));

        self.ports.host = demo::GATEWAY.into();
        self.ports.run_host = demo::GATEWAY.into();
        self.ports.target = demo::GATEWAY.into();
        self.ports.ports = demo::PORTS.into();
        self.ports.permitted = true;
        self.ports.results = demo::port_results();
        self.ports.total = self.ports.results.len();
        self.ports.finished = true;

        self.wol.mac = demo::WAKE_MAC.into();
        self.wol.broadcast = demo::WAKE_BROADCAST.into();
        self.wol.prefilled = true;

        self.whois.query = demo::HOST.into();
        self.whois.asked = demo::HOST.into();
        self.whois.result = Some(Ok(demo::whois_text()));

        self.subnet = demo::SUBNET.into();
    }

    fn stop_all(&mut self) {
        self.ping.stop();
        self.trace.stop();
        self.dns.stop();
        self.ports.stop();
        self.whois.stop();
    }
}

// --------------------------------------------------------------------------------------
// Small UI pieces
// --------------------------------------------------------------------------------------

/// A row of fields and buttons, bottom-aligned so buttons sit next to the
/// text boxes rather than next to their captions.
fn form_row(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    ui.allocate_ui_with_layout(
        vec2(ui.available_width(), 54.0),
        Layout::left_to_right(Align::Max),
        add,
    );
}

fn submitted(ui: &Ui, field: &Response) -> bool {
    field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
}

/// Start or Stop. `Some(true)` = start clicked, `Some(false)` = stop clicked.
fn run_button(ui: &mut Ui, running: bool, start: &str, enabled: bool) -> Option<bool> {
    if running {
        widgets::ghost_button(ui, &Icon::STOP.with("Stop"))
            .clicked()
            .then_some(false)
    } else {
        widgets::primary_button(ui, start, enabled)
            .clicked()
            .then_some(true)
    }
}

/// The one muted line that says what a tool sends and to whom.
fn sends_line(ui: &mut Ui, text: &str) {
    let p = pal(ui);
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        ui.label(RichText::new(Icon::GLOBE.glyph()).size(12.5).color(p.faint));
        ui.add(egui::Label::new(RichText::new(text).size(12.5).color(p.muted)).wrap());
    });
}

fn caption(ui: &mut Ui, text: &str) {
    let p = pal(ui);
    ui.add(egui::Label::new(RichText::new(text).size(12.5).color(p.muted)).wrap());
}

fn busy_line(ui: &mut Ui, text: &str) {
    let p = pal(ui);
    ui.horizontal(|ui| {
        ui.add(egui::Spinner::new().size(14.0).color(p.accent));
        ui.label(RichText::new(text).size(13.0).color(p.muted));
    });
}

/// A stat tile whose value never wraps.
fn tile(ui: &mut Ui, caption: &str, value: &str, note: &str) {
    let p = pal(ui);
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 1.0;
        ui.label(RichText::new(caption).size(12.5).color(p.muted));
        ui.add(egui::Label::new(RichText::new(value).font(semibold(20.0))).truncate());
        ui.add(egui::Label::new(RichText::new(note).size(12.0).color(p.faint)).truncate());
    });
}

/// A block of monospace text on the page background, scrolling when long.
fn mono_block(ui: &mut Ui, id: &str, text: &str, max_height: f32) {
    let p = pal(ui);
    Frame::new()
        .fill(p.bg)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::ScrollArea::vertical()
                .id_salt(id)
                .max_height(max_height)
                .min_scrolled_height(max_height)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(text)
                                .font(FontId::monospace(12.5))
                                .color(p.text),
                        )
                        .wrap()
                        .selectable(true),
                    );
                });
        });
}

/// "Label    value" with a wider label column than `widgets::kv`.
fn kv_wide(ui: &mut Ui, label: &str, value: &str, label_width: f32) {
    let p = pal(ui);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        let (rect, _) = ui.allocate_exact_size(vec2(label_width, 20.0), Sense::hover());
        widgets::text_in(ui, rect, label, regular(13.0), p.faint);
        ui.add(
            egui::Label::new(RichText::new(value).size(13.5).color(p.text))
                .truncate()
                .selectable(true),
        );
    });
}

fn error_notice(ui: &mut Ui, text: &str) {
    let p = pal(ui);
    ui.add_space(4.0);
    widgets::notice(ui, Icon::ERROR, p.danger, text);
}

const TRACE_COLS: [Col; 8] = [
    Col::fixed("Hop", 30.0),
    Col::flex("Address", 1.0),
    Col::flex("Host name", 1.6),
    Col::right("Loss", 48.0),
    Col::right("Min ms", 54.0),
    Col::right("Avg ms", 54.0),
    Col::right("Max ms", 54.0),
    Col::fixed("Latency", 100.0),
];

const DNS_COLS: [Col; 4] = [
    Col::flex("Name", 1.2),
    Col::fixed("Type", 56.0),
    Col::right("TTL", 76.0),
    Col::flex("Data", 2.2),
];

const PORT_COLS: [Col; 4] = [
    Col::fixed("Port", 70.0),
    Col::flex("Service", 1.0),
    Col::fixed("State", 150.0),
    Col::right("Connect time", 110.0),
];

fn dns_section(ui: &mut Ui, title: &str, note: &str, records: &[DnsRecord]) {
    let p = pal(ui);
    widgets::titled_card(
        ui,
        title,
        |ui| {
            ui.label(RichText::new(note).size(12.5).color(p.muted));
        },
        |ui| {
            // Three of these tables share a page: keep their header ids apart.
            ui.push_id(title, |ui| {
                widgets::table_header(ui, &DNS_COLS, None);
                ui.spacing_mut().item_spacing.y = 0.0;
                for r in records {
                    let (cells, resp) = widgets::table_row(ui, &DNS_COLS, 40.0, false);
                    widgets::text_in(ui, cells[0], &r.name, regular(13.5), p.text);
                    widgets::text_in(ui, cells[1], &r.rtype, semibold(13.0), p.muted);
                    widgets::text_in_right(
                        ui,
                        cells[2],
                        &format!("{} s", fmt::thousands(r.ttl as u64)),
                        regular(13.5),
                        p.muted,
                    );
                    if widgets::text_in(ui, cells[3], &r.data, regular(13.5), p.text) {
                        resp.on_hover_text(&r.data);
                    }
                }
            });
        },
    );
}

fn subnet_bits(ui: &mut Ui, label: &str, bits: &str, prefix: u8) {
    let p = pal(ui);
    let (network, host) = split_bits(bits, prefix);
    let font = FontId::monospace(14.0);
    let mut job = LayoutJob::default();
    job.append(
        network,
        0.0,
        TextFormat {
            font_id: font.clone(),
            color: p.text,
            background: p.accent.gamma_multiply(0.22),
            ..Default::default()
        },
    );
    job.append(
        host,
        0.0,
        TextFormat {
            font_id: font,
            color: p.muted,
            ..Default::default()
        },
    );
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(vec2(124.0, 22.0), Sense::hover());
        widgets::text_in(ui, rect, label, regular(13.0), p.faint);
        ui.add(egui::Label::new(job).selectable(true));
    });
}

fn subnet_result(ui: &mut Ui, info: &SubnetInfo) {
    let p = pal(ui);
    widgets::titled_card(
        ui,
        &format!("{}/{}", info.network, info.prefix),
        |ui| {
            ui.label(RichText::new(&info.scope).size(12.5).color(p.muted));
        },
        |ui| {
            widgets::columns_n(ui, 2, |i, ui| {
                if i == 0 {
                    widgets::kv(ui, "Address", &info.address);
                    widgets::kv(ui, "Prefix length", &format!("/{}", info.prefix));
                    widgets::kv(ui, "Subnet mask", &info.mask);
                    widgets::kv(ui, "Wildcard mask", &info.wildcard);
                    widgets::kv(ui, "Network", &info.network);
                    widgets::kv(ui, "Broadcast", &info.broadcast);
                } else {
                    widgets::kv(ui, "First host", &info.first_host);
                    widgets::kv(ui, "Last host", &info.last_host);
                    widgets::kv(ui, "Usable hosts", &fmt::thousands(info.hosts));
                    widgets::kv(ui, "Total addresses", &fmt::thousands(info.total));
                    widgets::kv(ui, "Kind of address", &info.scope);
                    widgets::kv(ui, "Class", &info.class);
                }
            });
        },
    );
    ui.add_space(12.0);
    widgets::titled_card(
        ui,
        "In bits",
        |_| {},
        |ui| {
            subnet_bits(ui, "Address", &info.address_bits, info.prefix);
            subnet_bits(ui, "Subnet mask", &info.mask_bits, info.prefix);
            ui.add_space(2.0);
            caption(
                ui,
                &format!(
                    "The highlighted first {} bits are the network part: every device on this \
                     network shares them. The remaining {} bits tell the devices apart.",
                    info.prefix,
                    32 - info.prefix.min(32)
                ),
            );
        },
    );
}

// --------------------------------------------------------------------------------------
// The page
// --------------------------------------------------------------------------------------

impl App {
    /// Called every frame, also while another page is shown: pick up results
    /// of background work here.
    pub(super) fn tools_poll(&mut self, ctx: &egui::Context) {
        let now = self.now;
        let t = &mut self.tools;
        t.ping.poll(now);
        t.trace.poll();
        t.dns.poll();
        t.ports.poll();
        t.wol.poll();
        t.whois.poll();
        t.actions.poll();

        // The two system actions run only after the confirmation dialog.
        if self.confirmed("tools.flush") {
            if self.demo {
                self.toast(DEMO_CHANGES, false);
            } else {
                self.tools
                    .actions
                    .start("flush", vec![sysactions::flush_dns()], ctx);
            }
        }
        if self.confirmed("tools.renew") {
            if self.demo {
                self.toast(DEMO_CHANGES, false);
            } else if let Some(name) = self.primary_adapter().map(|a| a.name.clone()) {
                self.tools
                    .actions
                    .start("renew", sysactions::renew_lease(Some(&name)), ctx);
            } else {
                self.toast("No connected adapter was found.", true);
            }
        }
    }

    /// Called when the program closes: stop background work.
    pub(super) fn tools_exit(&mut self) {
        self.tools.stop_all();
    }

    pub(super) fn tools_ui(&mut self, ui: &mut Ui) {
        widgets::page_header(
            ui,
            "Tools",
            "Check a connection, look things up, fix common problems. Nothing is sent until you press a button.",
            |_| {},
        );
        let labels: Vec<&str> = TOOLS.iter().map(|t| t.1).collect();
        let current = TOOLS
            .iter()
            .position(|t| t.0 == self.tools.tool)
            .unwrap_or(0);
        if let Some(i) = widgets::segmented(ui, &labels, current) {
            self.tools.tool = TOOLS[i].0;
        }
        ui.add_space(6.0);
        let tool = self.tools.tool;
        let scroll_id = TOOLS.iter().find(|t| t.0 == tool).map_or("tools", |t| t.2);
        App::scroll(ui, scroll_id, |ui| match tool {
            Tool::Ping => self.tools_ping(ui),
            Tool::Trace => self.tools_trace(ui),
            Tool::Dns => self.tools_dns(ui),
            Tool::Ports => self.tools_ports(ui),
            Tool::Wol => self.tools_wol(ui),
            Tool::Whois => self.tools_whois(ui),
            Tool::Subnet => self.tools_subnet(ui),
            Tool::Report => self.tools_report(ui),
            Tool::Actions => self.tools_actions(ui),
        });
    }

    // ---------------------------------------------------------------------------- ping

    fn tools_ping(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let (gateway, dns_server) = match self.primary_adapter() {
            Some(a) => (
                a.gateways.first().map(|g| g.to_string()),
                a.dns_servers.first().map(|d| d.to_string()),
            ),
            None => (None, None),
        };
        let offset = self.offset;
        let mut start = false;
        let mut stop = false;
        let mut export = false;
        let s = &mut self.tools.ping;

        widgets::card(ui, |ui| {
            form_row(ui, |ui| {
                let field = widgets::text_field(
                    ui,
                    "Host name or address",
                    &mut s.host,
                    "example.org or 192.168.1.1",
                    300.0,
                );
                if submitted(ui, &field) && !s.running {
                    start = true;
                }
                match run_button(ui, s.running, "Start", true) {
                    Some(true) => start = true,
                    Some(false) => stop = true,
                    None => {}
                }
                ui.add_space(8.0);
                if let Some(g) = &gateway {
                    if widgets::chip(ui, "Gateway", None, s.host.trim() == g.as_str())
                        .on_hover_text(format!("Your router, {g}"))
                        .clicked()
                    {
                        s.host = g.clone();
                    }
                }
                if let Some(d) = dns_server.as_ref().filter(|d| Some(*d) != gateway.as_ref()) {
                    if widgets::chip(ui, "DNS server", None, s.host.trim() == d.as_str())
                        .on_hover_text(format!("The DNS server of your connection, {d}"))
                        .clicked()
                    {
                        s.host = d.clone();
                    }
                }
            });
            sends_line(
                ui,
                "Sends one small echo request (ICMP, 32 bytes) per second to the host you \
                 enter and waits for the reply, until you press Stop. A name is first looked \
                 up through your DNS server.",
            );
            if let Some(e) = &s.error {
                error_notice(ui, e);
            }
        });

        if s.run_host.is_empty() && !s.running {
            ui.add_space(12.0);
            widgets::card(ui, |ui| {
                ui.set_min_height(260.0);
                widgets::empty_state(
                    ui,
                    Icon::CONNECTIONS,
                    p.accent,
                    "Is it reachable, and how fast?",
                    "Enter a host and press Start. Ping shows whether the host answers, how \
                     long each answer takes and how many get lost.",
                );
            });
        } else {
            ui.add_space(12.0);
            let title = if s.target.is_empty() || s.target == s.run_host {
                format!("Ping {}", s.run_host)
            } else {
                format!("Ping {} ({})", s.run_host, s.target)
            };
            let stats = s.stats;
            let (running, has_replies) = (s.running, !s.replies.is_empty());
            widgets::titled_card(
                ui,
                &title,
                |ui| {
                    if widgets::ghost_button_enabled(ui, &Icon::EXPORT.with("Export"), has_replies)
                        .clicked()
                    {
                        export = true;
                    }
                    if running {
                        busy_line(ui, "Running");
                    } else {
                        ui.label(RichText::new("Stopped").size(12.5).color(p.muted));
                    }
                },
                |ui| {
                    ui.add_space(4.0);
                    let none = stats.received == 0;
                    widgets::columns_weighted(ui, &[1.0, 1.0, 1.0, 2.3, 1.2], |i, ui| match i {
                        0 => tile(ui, "Sent", &fmt::thousands(stats.sent as u64), "requests"),
                        1 => tile(
                            ui,
                            "Received",
                            &fmt::thousands(stats.received as u64),
                            "replies",
                        ),
                        2 => tile(
                            ui,
                            "Loss",
                            &format!("{:.1} %", stats.loss_pct),
                            &format!("{} lost", stats.sent.saturating_sub(stats.received)),
                        ),
                        3 => tile(
                            ui,
                            "Min / avg / max",
                            &if none {
                                "No replies yet".to_string()
                            } else {
                                format!(
                                    "{} / {} / {} ms",
                                    ms_or_dash(Some(stats.min_ms)),
                                    ms_or_dash(Some(stats.avg_ms)),
                                    ms_or_dash(Some(stats.max_ms))
                                )
                            },
                            "round-trip time",
                        ),
                        _ => tile(
                            ui,
                            "Jitter",
                            &if none {
                                "-".to_string()
                            } else {
                                format!("{} ms", ms_or_dash(Some(stats.jitter_ms)))
                            },
                            "change between replies",
                        ),
                    });
                },
            );

            ui.add_space(12.0);
            let values = ping_chart_values(&s.replies);
            let first_shown = s.replies.len() - values.len();
            widgets::titled_card(
                ui,
                "Round-trip time",
                |ui| {
                    ui.label(
                        RichText::new("Gaps are lost replies")
                            .size(12.5)
                            .color(p.muted),
                    );
                },
                |ui| {
                    let series = [Series {
                        name: "Round-trip time",
                        values: &values,
                        color: p.down,
                        fill: true,
                    }];
                    let y_fmt = fmt::millis;
                    let slots = values.len().max(60);
                    let times = &s.times;
                    let replies = &s.replies;
                    let shown = values.len();
                    let x_fmt = move |slot: usize, slots: usize| {
                        let i = first_shown + (slot + shown).saturating_sub(slots);
                        match (times.get(i), replies.get(i)) {
                            (Some(t), Some(r)) => {
                                format!("{}, request {}", fmt::clock(*t, offset), r.seq)
                            }
                            _ => String::new(),
                        }
                    };
                    let left = format!("{} ago", fmt::duration(slots as i64));
                    let mut chart = LineChart::new(&series, &y_fmt);
                    chart.height = 150.0;
                    chart.slots = slots;
                    chart.x_left = &left;
                    chart.x_right = if running { "now" } else { "last reply" };
                    chart.x_fmt = Some(&x_fmt);
                    charts::line_chart(ui, &chart);
                },
            );

            ui.add_space(12.0);
            widgets::titled_card(
                ui,
                "Log",
                |ui| {
                    ui.label(
                        RichText::new(format!("{} lines", fmt::thousands(s.replies.len() as u64)))
                            .size(12.5)
                            .color(p.muted),
                    );
                },
                |ui| {
                    let row_h = 22.0;
                    // Set before the scroll area: it sizes its rows with this spacing.
                    ui.add_space(4.0);
                    ui.spacing_mut().item_spacing.y = 0.0;
                    egui::ScrollArea::vertical()
                        .id_salt("ping-log")
                        .max_height(row_h * 8.0)
                        .min_scrolled_height(row_h * 8.0)
                        .auto_shrink([false, true])
                        .stick_to_bottom(true)
                        .show_rows(ui, row_h, s.replies.len(), |ui, range| {
                            ui.spacing_mut().item_spacing.y = 0.0;
                            for i in range {
                                let Some(r) = s.replies.get(i) else { continue };
                                let (rect, _) = ui.allocate_exact_size(
                                    vec2(ui.available_width(), row_h),
                                    Sense::hover(),
                                );
                                let (clock, line) = rect.split_left_right_at_x(rect.left() + 74.0);
                                let when = s.times.get(i).map(|t| fmt::clock(*t, offset));
                                widgets::text_in(
                                    ui,
                                    clock,
                                    when.as_deref().unwrap_or(""),
                                    FontId::monospace(12.5),
                                    p.faint,
                                );
                                widgets::text_in(
                                    ui,
                                    line,
                                    &ping_log_line(r),
                                    FontId::monospace(12.5),
                                    if r.ok { p.text } else { p.warn },
                                );
                            }
                        });
                },
            );
        }

        if stop {
            self.tools.ping.stop();
        }
        if start {
            if self.demo {
                self.toast(DEMO_SENDS, false);
            } else if !self.still() {
                self.tools.ping.start(&ctx);
            }
        }
        if export {
            let s = &self.tools.ping;
            let tables = ping_tables(&s.run_host, &s.replies, &s.times, self.offset);
            self.export(&tables, "Ping results", "wireforge-ping");
        }
    }

    // ---------------------------------------------------------------------- traceroute

    fn tools_trace(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let mut start = false;
        let mut stop = false;
        let mut export = false;
        let s = &mut self.tools.trace;

        widgets::card(ui, |ui| {
            form_row(ui, |ui| {
                let field = widgets::text_field(
                    ui,
                    "Host name or address",
                    &mut s.host,
                    "example.org",
                    300.0,
                );
                if submitted(ui, &field) && !s.running {
                    start = true;
                }
                match run_button(ui, s.running, "Start", true) {
                    Some(true) => start = true,
                    Some(false) => stop = true,
                    None => {}
                }
            });
            ui.horizontal(|ui| {
                ui.label(RichText::new("Give up after").size(13.0).color(p.muted));
                for hops in [15u8, 30, 64] {
                    if widgets::chip(ui, &format!("{hops} hops"), None, s.max_hops == hops)
                        .clicked()
                    {
                        s.max_hops = hops;
                    }
                }
                ui.add_space(12.0);
                widgets::checkbox(ui, &mut s.names, "Look up the names of the routers")
                    .on_hover_text(
                        "Asks your DNS server for the name of each router on the way. \
                         Turn it off for a faster trace that asks nothing extra.",
                    );
            });
            sends_line(
                ui,
                "Sends small echo requests (ICMP) towards the host you enter, three per hop, \
                 each allowed to travel one router further. The routers on the way and the \
                 host see them. Names are asked from your DNS server.",
            );
            if let Some(e) = &s.error {
                error_notice(ui, e);
            }
        });
        ui.add_space(12.0);

        if s.hops.is_empty() && !s.running {
            widgets::card(ui, |ui| {
                ui.set_min_height(260.0);
                widgets::empty_state(
                    ui,
                    Icon::ROUTER,
                    p.accent,
                    "Which way does the traffic go?",
                    "Enter a host and press Start. Traceroute lists every router between \
                     this PC and the host and how long each one takes to answer.",
                );
            });
        } else {
            let title = if s.target.is_empty() || s.target == s.run_host {
                format!("Route to {}", s.run_host)
            } else {
                format!("Route to {} ({})", s.run_host, s.target)
            };
            let running = s.running;
            let has_hops = !s.hops.is_empty();
            let slowest = s
                .hops
                .iter()
                .filter_map(|h| h.avg_ms)
                .fold(0.0_f32, f32::max);
            let any_silent = s.hops.iter().any(|h| h.addr.is_none());
            widgets::titled_card(
                ui,
                &title,
                |ui| {
                    if widgets::ghost_button_enabled(ui, &Icon::EXPORT.with("Export"), has_hops)
                        .clicked()
                    {
                        export = true;
                    }
                    if running {
                        busy_line(ui, "Tracing");
                    }
                },
                |ui| {
                    if let Some(outcome) = &s.outcome {
                        let reached = s.hops.iter().any(|h| h.reached);
                        ui.horizontal(|ui| {
                            let (icon, color) = if reached {
                                (Icon::CHECK, p.good)
                            } else {
                                (Icon::INFO, p.info)
                            };
                            ui.label(RichText::new(icon.glyph()).size(13.0).color(color));
                            ui.add(egui::Label::new(RichText::new(outcome).size(13.5)).wrap());
                        });
                    }
                    widgets::table_header(ui, &TRACE_COLS, None);
                    ui.scope(|ui| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        for h in &s.hops {
                            let (cells, resp) = widgets::table_row(ui, &TRACE_COLS, 40.0, false);
                            let font = regular(13.5);
                            widgets::text_in(
                                ui,
                                cells[0],
                                &h.ttl.to_string(),
                                semibold(13.5),
                                p.muted,
                            );
                            match &h.addr {
                                Some(addr) => {
                                    widgets::text_in(ui, cells[1], addr, font.clone(), p.text);
                                }
                                None => {
                                    widgets::text_in(ui, cells[1], "*", font.clone(), p.faint);
                                }
                            }
                            let mut name_cell = cells[2];
                            if h.reached {
                                let w = 86.0_f32.min(name_cell.width());
                                let badge = egui::Rect::from_min_max(
                                    egui::pos2(name_cell.right() - w, name_cell.top()),
                                    name_cell.max,
                                );
                                widgets::paint_badge(ui, badge, "Destination", p.good);
                                name_cell.set_right(badge.left() - 8.0);
                            }
                            let (name, color) = match (&h.addr, &h.host) {
                                (None, _) => ("No answer", p.faint),
                                (Some(_), Some(host)) => (host.as_str(), p.text),
                                (Some(_), None) => ("", p.faint),
                            };
                            if name_cell.width() > 20.0
                                && widgets::text_in(ui, name_cell, name, font.clone(), color)
                            {
                                resp.on_hover_text(name);
                            }
                            let loss_color = if h.loss_pct > 0.0 && h.addr.is_some() {
                                p.warn
                            } else {
                                p.muted
                            };
                            widgets::text_in_right(
                                ui,
                                cells[3],
                                &format!("{:.0} %", h.loss_pct),
                                font.clone(),
                                loss_color,
                            );
                            for (cell, v) in [
                                (cells[4], h.min_ms),
                                (cells[5], h.avg_ms),
                                (cells[6], h.max_ms),
                            ] {
                                widgets::text_in_right(
                                    ui,
                                    cell,
                                    &ms_or_dash(v),
                                    font.clone(),
                                    if v.is_some() { p.text } else { p.faint },
                                );
                            }
                            if let Some(avg) = h.avg_ms {
                                let bar = egui::Rect::from_center_size(
                                    cells[7].center(),
                                    vec2(cells[7].width(), 6.0),
                                );
                                let fraction = if slowest > 0.0 { avg / slowest } else { 0.0 };
                                charts::paint_meter_bar(ui, bar, fraction, p.down, p.hover);
                            }
                        }
                    });
                    if any_silent {
                        ui.add_space(6.0);
                        caption(
                            ui,
                            "A * means that router did not answer. Many routers are set up not \
                             to answer these requests; that is normal as long as later hops reply.",
                        );
                    }
                    if has_hops {
                        caption(
                            ui,
                            "The bar compares the average answer time of each hop with the slowest hop.",
                        );
                    }
                },
            );
        }

        if stop {
            self.tools.trace.stop();
        }
        if start {
            if self.demo {
                self.toast(DEMO_SENDS, false);
            } else if !self.still() {
                self.tools.trace.start(&ctx);
            }
        }
        if export {
            let s = &self.tools.trace;
            let table = trace_table(&s.run_host, &s.hops);
            self.export(&[table], "Traceroute", "wireforge-traceroute");
        }
    }

    // ----------------------------------------------------------------------------- dns

    fn tools_dns(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let mut start = false;
        let mut stop = false;
        let mut export = false;
        let s = &mut self.tools.dns;
        let custom = DnsState::custom_index();

        widgets::card(ui, |ui| {
            form_row(ui, |ui| {
                let field = widgets::text_field(
                    ui,
                    "Name to look up (or an address for PTR)",
                    &mut s.name,
                    "example.org",
                    300.0,
                );
                if submitted(ui, &field) && !s.busy {
                    start = true;
                }
                if s.busy {
                    if widgets::ghost_button(ui, &Icon::STOP.with("Stop")).clicked() {
                        stop = true;
                    }
                } else if widgets::primary_button(ui, "Look up", true).clicked() {
                    start = true;
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Record type").size(13.0).color(p.muted));
                for (i, rtype) in dns::RECORD_TYPES.iter().enumerate() {
                    if widgets::chip(ui, rtype, None, s.rtype == i).clicked() {
                        s.rtype = i;
                    }
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Ask this server").size(13.0).color(p.muted));
                if widgets::chip(ui, "System default", None, s.server == 0)
                    .on_hover_text("The DNS server your connection already uses.")
                    .clicked()
                {
                    s.server = 0;
                }
                for (i, (label, addr)) in dns::PUBLIC_SERVERS.iter().enumerate() {
                    if widgets::chip(ui, &format!("{label} ({addr})"), None, s.server == i + 1)
                        .on_hover_text(format!(
                            "A public DNS server run by {label}. {label} sees the name you ask for."
                        ))
                        .clicked()
                    {
                        s.server = i + 1;
                    }
                }
                if widgets::chip(ui, "Other", None, s.server == custom).clicked() {
                    s.server = custom;
                }
                if s.server == custom {
                    ui.add(
                        egui::TextEdit::singleline(&mut s.custom)
                            .hint_text(RichText::new("Server address").color(p.faint))
                            .desired_width(170.0)
                            .margin(Margin::symmetric(10, 6)),
                    );
                }
            });
            sends_line(
                ui,
                "Sends one question to the DNS server you choose. With the system default \
                 that is the server your connection already uses. A public server is run by \
                 the named company, which then sees the name you ask for and your IP address.",
            );
            if let Some(e) = &s.error {
                error_notice(ui, e);
            }
        });
        ui.add_space(12.0);

        if s.busy {
            widgets::card(ui, |ui| {
                ui.set_min_height(200.0);
                widgets::busy_state(ui, "Asking the DNS server", &s.question);
            });
        } else {
            match &s.result {
                None => {
                    widgets::card(ui, |ui| {
                        ui.set_min_height(240.0);
                        widgets::empty_state(
                            ui,
                            Icon::SEARCH,
                            p.accent,
                            "What does a name point to?",
                            "DNS turns names into addresses. Enter a name, pick the kind of \
                             record and press Look up.",
                        );
                    });
                }
                Some(Err(e)) => {
                    widgets::notice(ui, Icon::ERROR, p.danger, e);
                }
                Some(Ok(answer)) => {
                    let ok = answer.rcode.eq_ignore_ascii_case("NOERROR");
                    widgets::titled_card(
                        ui,
                        &s.question,
                        |ui| {
                            if widgets::ghost_button(ui, &Icon::EXPORT.with("Export")).clicked() {
                                export = true;
                            }
                        },
                        |ui| {
                            widgets::columns_n(ui, 2, |i, ui| {
                                if i == 0 {
                                    widgets::kv_colored(
                                        ui,
                                        "Result",
                                        &rcode_words(&answer.rcode, answer.answers.len()),
                                        Some(if ok && !answer.answers.is_empty() {
                                            p.good
                                        } else if ok {
                                            p.text
                                        } else {
                                            p.warn
                                        }),
                                    );
                                    widgets::kv(ui, "Status code", &answer.rcode);
                                    widgets::kv(ui, "Server asked", &answer.server);
                                } else {
                                    widgets::kv(ui, "Time", &fmt::millis(answer.elapsed_ms as f64));
                                    widgets::kv(
                                        ui,
                                        "Sent over",
                                        &if answer.truncated && answer.transport == "UDP" {
                                            "UDP (answer cut short)".to_string()
                                        } else {
                                            answer.transport.clone()
                                        },
                                    );
                                    widgets::kv(
                                        ui,
                                        "Authoritative",
                                        if answer.authoritative {
                                            "Yes, from the server in charge of the name"
                                        } else {
                                            "No, a remembered or passed-on answer"
                                        },
                                    );
                                }
                            });
                        },
                    );
                    let sections = [
                        (
                            "Answers",
                            "The records that were asked for",
                            &answer.answers,
                        ),
                        (
                            "Authority",
                            "The servers in charge of this name",
                            &answer.authority,
                        ),
                        (
                            "Additional",
                            "Extra records the server added",
                            &answer.additional,
                        ),
                    ];
                    for (title, note, records) in sections {
                        if records.is_empty() {
                            continue;
                        }
                        ui.add_space(12.0);
                        dns_section(ui, title, note, records);
                    }
                    ui.add_space(6.0);
                    caption(
                        ui,
                        "TTL: for how many seconds other computers may remember a record \
                         before asking again.",
                    );
                }
            }
        }

        if stop {
            self.tools.dns.stop();
        }
        if start {
            if self.demo {
                self.toast(DEMO_SENDS, false);
            } else if !self.still() {
                self.tools.dns.start(&ctx);
            }
        }
        if export {
            let s = &self.tools.dns;
            if let Some(Ok(answer)) = &s.result {
                let tables = dns_tables(&s.question, answer);
                if tables.is_empty() {
                    self.toast("There are no records to export.", false);
                } else {
                    self.export(&tables, "DNS lookup", "wireforge-dns");
                }
            }
        }
    }

    // --------------------------------------------------------------------------- ports

    fn tools_ports(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let mut start = false;
        let mut stop = false;
        let mut export = false;
        let s = &mut self.tools.ports;
        let parsed = validate_ports(&s.ports);

        widgets::notice_with(
            ui,
            Icon::SHIELD,
            p.warn,
            "Only test equipment you own or are allowed to test. Checking ports on other \
             people's devices can break rules or the law, and it is not what this tool is for.",
            |ui| {
                widgets::checkbox(
                    ui,
                    &mut s.permitted,
                    "This is my own equipment or I have permission",
                );
            },
        );
        ui.add_space(12.0);
        widgets::card(ui, |ui| {
            form_row(ui, |ui| {
                let field = widgets::text_field(
                    ui,
                    "Host name or address (one device)",
                    &mut s.host,
                    "192.168.1.1",
                    220.0,
                );
                let ports_field = widgets::text_field(
                    ui,
                    "Ports (numbers and ranges)",
                    &mut s.ports,
                    "80, 443, 8000-8010",
                    260.0,
                );
                let ready = s.permitted && parsed.is_ok();
                if (submitted(ui, &field) || submitted(ui, &ports_field)) && !s.running && ready {
                    start = true;
                }
                let button = run_button(ui, s.running, "Start", ready);
                match button {
                    Some(true) => start = true,
                    Some(false) => stop = true,
                    None => {}
                }
                if widgets::ghost_button(ui, "Common ports")
                    .on_hover_text(format!(
                        "Fills in {} ports that home devices often use.",
                        ports::COMMON_PORTS.len()
                    ))
                    .clicked()
                {
                    s.ports = common_ports_text();
                }
            });
            match &parsed {
                Ok(list) if !s.permitted => caption(
                    ui,
                    &format!("{} ports. Tick the box above to enable Start.", list.len()),
                ),
                Ok(list) => caption(
                    ui,
                    &format!(
                        "{} ports, at most {} per run.",
                        list.len(),
                        ports::MAX_PORTS
                    ),
                ),
                Err(e) => {
                    ui.label(RichText::new(e).size(12.5).color(p.danger));
                }
            }
            sends_line(
                ui,
                "Tries to open a connection (TCP) to each listed port on the one host you \
                 enter and closes it again at once. No data is sent over the connection. \
                 The device may note the attempts in its log.",
            );
            if let Some(e) = &s.error {
                error_notice(ui, e);
            }
        });
        ui.add_space(12.0);

        if s.results.is_empty() && !s.running {
            widgets::card(ui, |ui| {
                ui.set_min_height(220.0);
                widgets::empty_state(
                    ui,
                    Icon::LOCK,
                    p.accent,
                    "Which services does a device offer?",
                    "An open port means a program on the device is listening there, for \
                     example a web page on 80 or 443. Enter your device and press Start.",
                );
            });
        } else {
            let title = if s.target.is_empty() || s.target == s.run_host {
                format!("Ports on {}", s.run_host)
            } else {
                format!("Ports on {} ({})", s.run_host, s.target)
            };
            let open = s
                .results
                .iter()
                .filter(|r| r.state == PortState::Open)
                .count();
            let (running, done, total) = (s.running, s.results.len(), s.total);
            widgets::titled_card(
                ui,
                &title,
                |ui| {
                    if widgets::ghost_button_enabled(ui, &Icon::EXPORT.with("Export"), done > 0)
                        .clicked()
                    {
                        export = true;
                    }
                    if running {
                        busy_line(ui, &format!("{done} of {total} checked"));
                    } else {
                        ui.label(
                            RichText::new(format!("{open} open of {done} checked"))
                                .size(12.5)
                                .color(p.muted),
                        );
                    }
                },
                |ui| {
                    widgets::table_header(ui, &PORT_COLS, None);
                    ui.scope(|ui| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        for r in &s.results {
                            let (cells, _) = widgets::table_row(ui, &PORT_COLS, 40.0, false);
                            widgets::text_in(
                                ui,
                                cells[0],
                                &r.port.to_string(),
                                semibold(13.5),
                                p.text,
                            );
                            let service = if r.service.is_empty() {
                                "Not a well-known port"
                            } else {
                                r.service.as_str()
                            };
                            widgets::text_in(
                                ui,
                                cells[1],
                                service,
                                regular(13.5),
                                if r.service.is_empty() {
                                    p.faint
                                } else {
                                    p.text
                                },
                            );
                            let (text, color) = match r.state {
                                PortState::Open => (Icon::CHECK.with("Open"), p.good),
                                PortState::Closed => ("Closed".to_string(), p.muted),
                                PortState::NoAnswer => ("No answer".to_string(), p.faint),
                            };
                            let font = if r.state == PortState::Open {
                                semibold(13.5)
                            } else {
                                regular(13.5)
                            };
                            widgets::text_in(ui, cells[2], &text, font, color);
                            widgets::text_in_right(
                                ui,
                                cells[3],
                                &r.connect_ms
                                    .map(|v| fmt::millis(v as f64))
                                    .unwrap_or_else(|| "-".into()),
                                regular(13.5),
                                p.muted,
                            );
                        }
                    });
                    ui.add_space(6.0);
                    caption(
                        ui,
                        "Open: a program is listening there. Closed: the device answered that \
                         nothing is listening. No answer: a firewall dropped the attempt, or \
                         the device is off.",
                    );
                },
            );
        }

        if stop {
            self.tools.ports.stop();
        }
        if start {
            if self.demo {
                self.toast(DEMO_SENDS, false);
            } else if !self.still() {
                self.tools.ports.start(&ctx);
            }
        }
        if export {
            let s = &self.tools.ports;
            let table = ports_table(&s.run_host, &s.results);
            self.export(&[table], "Port check", "wireforge-ports");
        }
    }

    // --------------------------------------------------------------------- wake-on-lan

    fn tools_wol(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        if !self.tools.wol.prefilled {
            let broadcast = self
                .primary_adapter()
                .and_then(|a| a.ipv4.first())
                .map(|n| broadcast_of(n.addr, n.prefix).to_string());
            if let Some(b) = broadcast {
                self.tools.wol.broadcast = b;
                self.tools.wol.prefilled = true;
            }
        }
        let mut send = false;
        let s = &mut self.tools.wol;
        let check = wol_check(&s.mac, &s.broadcast);

        widgets::card(ui, |ui| {
            form_row(ui, |ui| {
                let mac = widgets::text_field(
                    ui,
                    "MAC address of the device to wake",
                    &mut s.mac,
                    "AA:BB:CC:DD:EE:FF",
                    240.0,
                );
                let target = widgets::text_field(
                    ui,
                    "Broadcast address of your network",
                    &mut s.broadcast,
                    "192.168.1.255",
                    220.0,
                );
                let ready = check.is_ok() && !s.busy;
                if (submitted(ui, &mac) || submitted(ui, &target)) && ready {
                    send = true;
                }
                if widgets::primary_button(ui, "Send wake packet", ready).clicked() {
                    send = true;
                }
            });
            match &check {
                Ok(target) => caption(
                    ui,
                    &format!("Ready: the packet goes to every device on {target}."),
                ),
                Err(e) if s.mac.trim().is_empty() => caption(ui, e),
                Err(e) => {
                    ui.label(RichText::new(e).size(12.5).color(p.danger));
                }
            }
            sends_line(
                ui,
                "Sends one small \"magic packet\" (UDP port 9) to the broadcast address of \
                 your own network. It never leaves your network and nothing is sent to the \
                 internet.",
            );
            match &s.result {
                Some(Ok(text)) => {
                    ui.add_space(4.0);
                    widgets::notice(ui, Icon::CHECK, p.good, text);
                }
                Some(Err(e)) => error_notice(ui, e),
                None => {}
            }
        });
        ui.add_space(12.0);
        widgets::titled_card(
            ui,
            "What the device needs",
            |_| {},
            |ui| {
                for line in [
                    "The device must support Wake-on-LAN and have it switched on, usually in \
                     its BIOS / UEFI setup and in the settings of its network adapter.",
                    "It normally has to be connected by cable. Few devices wake over Wi-Fi.",
                    "It must be asleep or shut down but still plugged in, on the same network \
                     as this PC.",
                    "You find the MAC address of a device on the Devices page or on a label \
                     on the device. The broadcast address is filled in from your connection.",
                ] {
                    ui.horizontal_top(|ui| {
                        ui.label(RichText::new("\u{2022}").color(p.accent));
                        ui.add(egui::Label::new(RichText::new(line).size(13.5)).wrap());
                    });
                }
            },
        );

        if send {
            if self.demo {
                self.toast(DEMO_SENDS, false);
            } else if !self.still() {
                self.tools.wol.start(&ctx);
            }
        }
    }

    // --------------------------------------------------------------------------- whois

    fn tools_whois(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let mut start = false;
        let mut stop = false;
        let mut copy = false;
        let s = &mut self.tools.whois;

        widgets::card(ui, |ui| {
            form_row(ui, |ui| {
                let field = widgets::text_field(
                    ui,
                    "Domain name or IP address",
                    &mut s.query,
                    "example.org or 192.0.2.1",
                    300.0,
                );
                if submitted(ui, &field) && !s.busy {
                    start = true;
                }
                if s.busy {
                    if widgets::ghost_button(ui, &Icon::STOP.with("Stop")).clicked() {
                        stop = true;
                    }
                } else if widgets::primary_button(ui, "Look up", true).clicked() {
                    start = true;
                }
            });
            sends_line(
                ui,
                &format!(
                    "Asks the central registry IANA ({}) who is in charge of the name or \
                     address, then asks the registry it points to. Both see what you look up \
                     and your IP address.",
                    whois::IANA
                ),
            );
        });
        ui.add_space(12.0);

        if s.busy {
            widgets::card(ui, |ui| {
                ui.set_min_height(200.0);
                widgets::busy_state(ui, "Asking the registries", &s.asked);
            });
        } else {
            match &s.result {
                None => {
                    widgets::card(ui, |ui| {
                        ui.set_min_height(240.0);
                        widgets::empty_state(
                            ui,
                            Icon::DOCUMENT,
                            p.accent,
                            "Who is behind a name or an address?",
                            "Whois shows the public registration record: the registrar, the \
                             dates and the name servers of a domain, or the owner of an \
                             address range.",
                        );
                    });
                }
                Some(Err(e)) => widgets::notice(ui, Icon::ERROR, p.danger, e),
                Some(Ok(text)) => {
                    widgets::titled_card(
                        ui,
                        &format!("Whois record for {}", s.asked),
                        |ui| {
                            if widgets::ghost_button(ui, &Icon::COPY.with("Copy")).clicked() {
                                copy = true;
                            }
                            ui.label(
                                RichText::new(format!("{} lines", text.lines().count()))
                                    .size(12.5)
                                    .color(p.muted),
                            );
                        },
                        |ui| {
                            ui.add_space(4.0);
                            let room = (ui.ctx().screen_rect().height() - 400.0).max(260.0);
                            mono_block(ui, "whois-text", text, room);
                        },
                    );
                }
            }
        }

        if stop {
            self.tools.whois.stop();
        }
        if start {
            if self.demo {
                self.toast(DEMO_SENDS, false);
            } else if !self.still() {
                self.tools.whois.start(&ctx);
            }
        }
        if copy {
            if let Some(Ok(text)) = self.tools.whois.result.clone() {
                self.copy(&ctx, &text, "Whois record");
            }
        }
    }

    // -------------------------------------------------------------------------- subnet

    fn tools_subnet(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let own = self
            .primary_adapter()
            .and_then(|a| a.ipv4.first())
            .map(|n| format!("{}/{}", n.addr, n.prefix));
        let s = &mut self.tools.subnet;
        widgets::card(ui, |ui| {
            form_row(ui, |ui| {
                widgets::text_field(
                    ui,
                    "Address and prefix, or address and mask",
                    s,
                    "192.168.1.10/24 or 192.168.1.10 255.255.255.0",
                    360.0,
                );
                if let Some(own) = &own {
                    if widgets::chip(ui, "My network", None, s.trim() == own.as_str())
                        .on_hover_text("Fills in the address of this PC on its current connection.")
                        .clicked()
                    {
                        *s = own.clone();
                    }
                }
            });
            sends_line(
                ui,
                "Pure arithmetic on this PC, worked out as you type. Nothing is sent anywhere.",
            );
        });
        ui.add_space(12.0);
        if s.trim().is_empty() {
            widgets::card(ui, |ui| {
                ui.set_min_height(240.0);
                widgets::empty_state(
                    ui,
                    Icon::CHART,
                    p.accent,
                    "How big is a network?",
                    "Type an address with its prefix, for example 192.168.1.10/24, to see \
                     the network it belongs to, the first and last usable address and how \
                     many devices fit.",
                );
            });
            return;
        }
        match subnet::calculate(s) {
            Ok(info) => subnet_result(ui, &info),
            Err(e) => widgets::notice(ui, Icon::INFO, p.warn, &e),
        }
    }

    // -------------------------------------------------------------------------- report

    fn tools_report(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let (now, offset) = (self.now, self.offset);
        let all = self.tools.report_all;
        let shown: Vec<AdapterInfo> = report_adapters(&self.adapters, all)
            .into_iter()
            .cloned()
            .collect();
        let hidden = self.adapters.len() - shown.len();
        let mut toggle = false;
        let mut copy = false;
        let mut export = false;
        const PRIVATE: &str = "The report contains the addresses of this PC (IP and MAC). \
                               Share it only with people you trust.";

        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                if widgets::toggle(ui, all, true).clicked() {
                    toggle = true;
                }
                ui.label("Show virtual and disconnected adapters");
                if hidden > 0 {
                    ui.label(
                        RichText::new(format!("{hidden} hidden"))
                            .size(12.5)
                            .color(p.faint),
                    );
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if widgets::ghost_button_enabled(
                        ui,
                        &Icon::EXPORT.with("Export"),
                        !shown.is_empty(),
                    )
                    .on_hover_text(PRIVATE)
                    .clicked()
                    {
                        export = true;
                    }
                    if widgets::ghost_button_enabled(
                        ui,
                        &Icon::COPY.with("Copy report"),
                        !shown.is_empty(),
                    )
                    .on_hover_text(PRIVATE)
                    .clicked()
                    {
                        copy = true;
                    }
                });
            });
            sends_line(
                ui,
                "Everything Windows knows about each network adapter, read on this PC. \
                 Nothing is sent anywhere.",
            );
        });

        if shown.is_empty() {
            ui.add_space(12.0);
            widgets::card(ui, |ui| {
                ui.set_min_height(220.0);
                widgets::empty_state(
                    ui,
                    Icon::ETHERNET,
                    p.muted,
                    "No connected adapter",
                    "This PC is not connected to a network right now. Turn the switch on \
                     to see every adapter, including the disconnected ones.",
                );
            });
        }
        for a in &shown {
            ui.add_space(12.0);
            let fields = crate::report::adapter_fields(a, now, offset);
            widgets::titled_card(
                ui,
                &a.name,
                |ui| {
                    if a.up {
                        widgets::badge(ui, "Connected", p.good);
                    } else {
                        widgets::badge(ui, "Not connected", p.muted);
                    }
                    if a.is_default {
                        widgets::badge(ui, "Used for the internet", p.accent).on_hover_text(
                            "The adapter that carries your internet traffic right now.",
                        );
                    }
                    if !a.physical {
                        widgets::badge(ui, "Virtual", p.info);
                    }
                },
                |ui| {
                    ui.spacing_mut().item_spacing.y = 4.0;
                    if ui.available_width() >= 820.0 && fields.len() > 8 {
                        let half = fields.len().div_ceil(2);
                        widgets::columns_n(ui, 2, |i, ui| {
                            ui.spacing_mut().item_spacing.y = 4.0;
                            let part = if i == 0 {
                                &fields[..half]
                            } else {
                                &fields[half..]
                            };
                            for (label, value) in part {
                                kv_wide(ui, label, value, 168.0);
                            }
                        });
                    } else {
                        for (label, value) in &fields {
                            kv_wide(ui, label, value, 190.0);
                        }
                    }
                },
            );
        }

        if toggle {
            self.tools.report_all = !all;
        }
        if copy {
            let text = crate::report::text(&shown, "", now, offset);
            self.copy(&ctx, &text, "Interface report");
        }
        if export {
            let tables = crate::report::tables(&shown, now, offset);
            self.export(&tables, "Interface report", "wireforge-interfaces");
        }
    }

    // ------------------------------------------------------------------------- actions

    fn tools_actions(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let adapter = self
            .primary_adapter()
            .map(|a| (a.name.clone(), a.dhcp_enabled));
        let flush = vec![sysactions::flush_dns()];
        let renew = adapter
            .as_ref()
            .map(|(name, _)| sysactions::renew_lease(Some(name)))
            .unwrap_or_default();
        let needs_admin = !self.elevated && flush.iter().chain(renew.iter()).any(|c| c.needs_admin);
        let busy = self.tools.actions.busy;
        let mut ask_flush = false;
        let mut ask_renew = false;
        let mut elevate = false;

        widgets::notice(
            ui,
            Icon::WARNING,
            p.warn,
            "These two actions change the state of this PC, unlike everything else in \
             WireForge. Each one shows the exact command and asks you to confirm first.",
        );
        if needs_admin {
            ui.add_space(12.0);
            widgets::notice_with(
                ui,
                Icon::SHIELD,
                p.info,
                "These commands need administrator rights.",
                |ui| {
                    if widgets::ghost_button(ui, "Restart as administrator").clicked() {
                        elevate = true;
                    }
                },
            );
        }
        ui.add_space(12.0);

        let state = &self.tools.actions;
        let renew_note = match &adapter {
            None => Some("No connected adapter was found, so there is nothing to renew."),
            Some((_, false)) => Some(
                "This connection uses a fixed address instead of one handed out by the \
                 router, so there is no lease to renew.",
            ),
            Some(_) => None,
        };
        widgets::columns_n(ui, 2, |i, ui| {
            let (title, what, when, commands, button, output, tag, blocked) = if i == 0 {
                (
                    "Flush DNS cache",
                    "Makes Windows forget the addresses of the names it looked up recently. \
                     The next visit to each site asks the DNS server again.",
                    "Helps when a site moved to a new address and this PC still goes to the \
                     old one, or after changing the DNS server. It is harmless: the list \
                     fills up again by itself.",
                    &flush,
                    "Flush DNS cache...",
                    &state.flush,
                    "flush",
                    None,
                )
            } else {
                (
                    "Renew DHCP lease",
                    "Gives the address of this PC back to the router and asks for one \
                     again, for the adapter that carries your internet traffic.",
                    "Helps when the PC shows \"No internet\" or a 169.254 address although \
                     the router works. The connection drops for a few seconds, and running \
                     downloads or calls are interrupted.",
                    &renew,
                    "Renew DHCP lease...",
                    &state.renew,
                    "renew",
                    renew_note,
                )
            };
            widgets::titled_card(
                ui,
                title,
                |ui| {
                    widgets::badge(ui, "Changes system state", p.warn);
                },
                |ui| {
                    ui.add(egui::Label::new(RichText::new(what).size(13.5)).wrap());
                    ui.add(egui::Label::new(RichText::new(when).size(13.0).color(p.muted)).wrap());
                    if !commands.is_empty() {
                        ui.label(RichText::new("Runs").size(12.0).color(p.faint));
                        let lines: Vec<String> = commands.iter().map(command_line).collect();
                        mono_block(ui, &format!("cmd-{tag}"), &lines.join("\n"), 80.0);
                    }
                    if let Some(note) = blocked {
                        caption(ui, note);
                    }
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        let enabled = busy.is_none()
                            && blocked.is_none()
                            && !commands.is_empty()
                            && !needs_admin;
                        if widgets::danger_button(ui, button, enabled).clicked() {
                            if i == 0 {
                                ask_flush = true;
                            } else {
                                ask_renew = true;
                            }
                        }
                        if busy == Some(tag) {
                            busy_line(ui, "Running the command");
                        }
                    });
                    match output {
                        Some(Ok(text)) => {
                            ui.label(RichText::new("Output").size(12.0).color(p.faint));
                            mono_block(ui, &format!("out-{tag}"), text, 180.0);
                        }
                        Some(Err(e)) => error_notice(ui, e),
                        None => {}
                    }
                },
            );
        });
        ui.add_space(10.0);
        caption(
            ui,
            "Resetting the whole network stack of Windows is deliberately not offered here: \
             it wipes saved network settings and needs a restart, so it should not be one \
             click away.",
        );

        if elevate {
            self.restart_elevated(&ctx);
        }
        if ask_flush {
            if self.demo {
                self.toast(DEMO_CHANGES, false);
            } else {
                self.ask(Confirm {
                    title: "Flush the DNS cache?".into(),
                    intro: "Windows forgets the names it has looked up recently. This \
                            command will run:"
                        .into(),
                    lines: flush.iter().map(command_line).collect(),
                    button: "Flush DNS cache".into(),
                    danger: true,
                    tag: "tools.flush".into(),
                });
            }
        }
        if ask_renew {
            if self.demo {
                self.toast(DEMO_CHANGES, false);
            } else {
                self.ask(Confirm {
                    title: "Renew the DHCP lease?".into(),
                    intro: "The connection drops for a few seconds while this PC asks the \
                            router for an address again. These commands will run:"
                        .into(),
                    lines: renew.iter().map(command_line).collect(),
                    button: "Renew lease".into(),
                    danger: true,
                    tag: "tools.renew".into(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_argument_picks_the_tool() {
        assert_eq!(tool_from_view("tools"), Tool::Ping);
        assert_eq!(tool_from_view("tools-ping"), Tool::Ping);
        assert_eq!(tool_from_view("tools-trace"), Tool::Trace);
        assert_eq!(tool_from_view("tools-dns"), Tool::Dns);
        assert_eq!(tool_from_view("tools-ports"), Tool::Ports);
        assert_eq!(tool_from_view("tools-wol"), Tool::Wol);
        assert_eq!(tool_from_view("tools-whois"), Tool::Whois);
        assert_eq!(tool_from_view("tools-subnet"), Tool::Subnet);
        assert_eq!(tool_from_view("tools-report"), Tool::Report);
        assert_eq!(tool_from_view("tools-actions"), Tool::Actions);
        assert_eq!(tool_from_view("speed"), Tool::Ping);
        assert_eq!(tool_from_view(""), Tool::Ping);
        // Every tool is in the picker exactly once.
        for (i, a) in TOOLS.iter().enumerate() {
            assert!(TOOLS.iter().skip(i + 1).all(|b| b.0 != a.0 && b.2 != a.2));
        }
    }

    #[test]
    fn host_field() {
        assert_eq!(validate_host("  example.org "), Ok("example.org".into()));
        assert_eq!(validate_host("192.0.2.1"), Ok("192.0.2.1".into()));
        assert_eq!(validate_host("2001:db8::1"), Ok("2001:db8::1".into()));
        assert_eq!(
            validate_host("_dmarc.example.org"),
            Ok("_dmarc.example.org".into())
        );
        assert!(validate_host("").is_err());
        assert!(validate_host("   ").is_err());
        assert!(validate_host("https://example.org")
            .unwrap_err()
            .contains("http://"));
        assert!(validate_host("example.org/path").is_err());
        assert!(validate_host("a.example b.example")
            .unwrap_err()
            .contains("one host"));
        assert!(validate_host("a.example,b.example").is_err());
        assert!(validate_host("exa\"mple").is_err());
        assert!(validate_host(&"a".repeat(254)).is_err());
        assert!(validate_host(&"a".repeat(253)).is_ok());
    }

    #[test]
    fn ports_field() {
        assert_eq!(validate_ports("80, 443"), Ok(vec![80, 443]));
        assert_eq!(validate_ports("8000-8002").map(|p| p.len()), Ok(3));
        assert!(validate_ports("").is_err());
        assert!(validate_ports("  ").is_err());
        assert!(validate_ports("0").is_err());
        assert!(validate_ports("http").is_err());
        assert!(validate_ports("1-5000").is_err());
        assert!(validate_ports(DEFAULT_PORTS).is_ok());
        let common = validate_ports(&common_ports_text()).unwrap();
        assert_eq!(common.len(), ports::COMMON_PORTS.len());
        assert!(common.len() <= ports::MAX_PORTS);
    }

    #[test]
    fn ping_log_lines() {
        let reply = PingReply {
            seq: 1,
            from: Some("192.0.2.1".into()),
            rtt_ms: Some(12.3),
            ttl: Some(57),
            status: "Reply".into(),
            ok: true,
        };
        assert_eq!(
            ping_log_line(&reply),
            "Reply from 192.0.2.1: 12.3 ms, TTL 57"
        );
        let v6 = PingReply {
            from: Some("2001:db8::1".into()),
            ttl: None,
            rtt_ms: Some(4.5),
            ..reply.clone()
        };
        assert_eq!(ping_log_line(&v6), "Reply from 2001:db8::1: 4.50 ms");
        let lost = PingReply {
            seq: 2,
            status: "Timed out".into(),
            ..Default::default()
        };
        assert_eq!(ping_log_line(&lost), "Timed out");
        assert_eq!(ping_log_line(&PingReply::default()), "Timed out");
        let expired = PingReply {
            seq: 3,
            from: Some("198.51.100.1".into()),
            status: "TTL expired".into(),
            ..Default::default()
        };
        assert_eq!(
            ping_log_line(&expired),
            "TTL expired (reported by 198.51.100.1)"
        );
    }

    #[test]
    fn ping_chart_has_gaps_and_a_limit() {
        let replies = crate::demo::tools::ping_replies();
        let values = ping_chart_values(&replies);
        assert_eq!(values.len(), 60);
        assert_eq!(values.iter().filter(|v| v.is_nan()).count(), 2);
        let many: Vec<PingReply> = replies.iter().cycle().take(1000).cloned().collect();
        assert_eq!(ping_chart_values(&many).len(), PING_CHART);
        assert!(ping_chart_values(&[]).is_empty());
    }

    #[test]
    fn ping_keeps_a_bounded_history() {
        let mut s = PingState::default();
        let reply = crate::demo::tools::ping_replies().remove(0);
        for i in 0..(PING_KEEP as i64 + 25) {
            s.push(reply.clone(), i);
        }
        assert_eq!(s.replies.len(), PING_KEEP);
        assert_eq!(s.times.len(), PING_KEEP);
        assert_eq!(s.times[0], 25);
        assert_eq!(s.stats.sent as usize, PING_KEEP);
    }

    #[test]
    fn ping_export() {
        let replies = crate::demo::tools::ping_replies();
        let times: Vec<i64> = (0..replies.len() as i64).collect();
        let tables = ping_tables("192.168.50.1", &replies, &times, 0);
        assert_eq!(tables.len(), 2);
        assert!(tables[0]
            .rows
            .iter()
            .any(|r| r[0] == "Sent" && r[1] == "60"));
        assert!(tables[0]
            .rows
            .iter()
            .any(|r| r[0] == "Received" && r[1] == "58"));
        assert_eq!(tables[1].rows.len(), 60);
        assert!(tables[1]
            .rows
            .iter()
            .all(|r| r.len() == tables[1].columns.len()));
        assert_eq!(tables[1].rows[22][2], "Timed out");
        assert_eq!(tables[1].rows[22][4], "");
        assert_eq!(tables[1].rows[0][1], "00:00:00");
    }

    #[test]
    fn trace_outcomes_and_export() {
        let hops = crate::demo::tools::trace_hops();
        assert_eq!(
            trace_outcome("example.org", &hops, false, 30),
            "Reached example.org in 9 hops."
        );
        assert!(trace_outcome("example.org", &hops[..4], true, 30).starts_with("Stopped after 4"));
        assert!(trace_outcome("example.org", &hops[..4], false, 15).contains("within 15 hops"));
        assert_eq!(
            trace_outcome(
                "router",
                &[Hop {
                    ttl: 1,
                    reached: true,
                    ..Default::default()
                }],
                false,
                30
            ),
            "Reached router in 1 hop."
        );
        let t = trace_table("example.org", &hops);
        assert_eq!(t.rows.len(), 9);
        assert!(t.rows.iter().all(|r| r.len() == t.columns.len()));
        assert_eq!(t.rows[4][1], "*");
        assert_eq!(t.rows[4][5], "");
        assert_eq!(t.rows[8][7], crate::export::yes_no(true));
    }

    #[test]
    fn rcodes_in_words() {
        assert_eq!(rcode_words("NXDOMAIN", 0), "This name does not exist");
        assert_eq!(rcode_words("nxdomain", 0), "This name does not exist");
        assert_eq!(rcode_words("NOERROR", 3), "Answered");
        assert!(rcode_words("NOERROR", 0).contains("no records of this type"));
        assert!(rcode_words("SERVFAIL", 0).contains("server failure"));
        assert!(rcode_words("REFUSED", 0).contains("refused"));
        assert!(rcode_words("YXDOMAIN", 0).contains("YXDOMAIN"));
        // Every code the collector can name gets a sentence.
        for code in 0..=10u8 {
            assert!(!rcode_words(&dns::rcode_name(code), 0).is_empty());
        }
    }

    #[test]
    fn dns_server_choice() {
        assert_eq!(dns_server_arg(0, "ignored"), Ok(None));
        for (i, (_, addr)) in dns::PUBLIC_SERVERS.iter().enumerate() {
            assert_eq!(dns_server_arg(i + 1, ""), Ok(Some((*addr).to_string())));
        }
        let custom = DnsState::custom_index();
        assert_eq!(
            dns_server_arg(custom, " 192.168.1.1 "),
            Ok(Some("192.168.1.1".into()))
        );
        assert_eq!(
            dns_server_arg(custom, "fe80::1%12"),
            Ok(Some("fe80::1%12".into()))
        );
        assert!(dns_server_arg(custom, "").is_err());
        assert!(dns_server_arg(custom, "dns.example").is_err());
    }

    #[test]
    fn dns_export_skips_empty_sections() {
        let mut answer = crate::demo::tools::dns_answer();
        assert_eq!(dns_tables("example.org (A)", &answer).len(), 3);
        answer.additional.clear();
        let tables = dns_tables("example.org (A)", &answer);
        assert_eq!(tables.len(), 2);
        assert_eq!(tables[0].rows.len(), answer.answers.len());
        assert_eq!(
            tables[0].rows[3],
            vec!["example.org", "MX", "7200", "10 mail.example.org"]
        );
    }

    #[test]
    fn port_results_stay_sorted() {
        let mut list = Vec::new();
        for port in [443u16, 22, 8080, 80, 22] {
            insert_port(
                &mut list,
                PortResult {
                    port,
                    ..Default::default()
                },
            );
        }
        let ports: Vec<u16> = list.iter().map(|r| r.port).collect();
        assert_eq!(ports, vec![22, 80, 443, 8080]);
        let t = ports_table("192.168.50.1", &crate::demo::tools::port_results());
        assert_eq!(t.rows.len(), 5);
        assert_eq!(t.rows[1], vec!["53", "DNS", "Open", "1.9"]);
        assert_eq!(t.rows[4][2], "No answer");
        assert_eq!(t.rows[4][3], "");
    }

    #[test]
    fn broadcast_addresses() {
        let a = Ipv4Addr::new(192, 168, 50, 23);
        assert_eq!(broadcast_of(a, 24), Ipv4Addr::new(192, 168, 50, 255));
        assert_eq!(broadcast_of(a, 16), Ipv4Addr::new(192, 168, 255, 255));
        assert_eq!(
            broadcast_of(Ipv4Addr::new(10, 1, 2, 3), 20),
            Ipv4Addr::new(10, 1, 15, 255)
        );
        assert_eq!(broadcast_of(a, 32), a);
        assert_eq!(broadcast_of(a, 0), Ipv4Addr::BROADCAST);
        assert_eq!(broadcast_of(a, 99), a);
    }

    #[test]
    fn wake_fields() {
        use crate::demo::tools::{WAKE_BROADCAST, WAKE_MAC};
        assert_eq!(
            wol_check(WAKE_MAC, WAKE_BROADCAST),
            Ok(Ipv4Addr::new(192, 168, 50, 255))
        );
        assert!(wol_check("", WAKE_BROADCAST).is_err());
        assert!(wol_check("02:00:5E:10:20", WAKE_BROADCAST).is_err());
        assert!(wol_check(WAKE_MAC, "not an address").is_err());
        // Never to an address on the internet.
        assert!(wol_check(WAKE_MAC, "203.0.113.255")
            .unwrap_err()
            .contains("own network"));
        assert!(wol_check("02-00-5e-10-20-30", "255.255.255.255").is_ok());
    }

    #[test]
    fn bit_strings_split_at_the_prefix() {
        let bits = "11000000.10101000.00110010.00010111";
        assert_eq!(
            split_bits(bits, 24),
            ("11000000.10101000.00110010", ".00010111")
        );
        assert_eq!(
            split_bits(bits, 20),
            ("11000000.10101000.0011", "0010.00010111")
        );
        assert_eq!(split_bits(bits, 0), ("", bits));
        assert_eq!(split_bits(bits, 32), (bits, ""));
        assert_eq!(split_bits(bits, 40), (bits, ""));
        let info = subnet::calculate(crate::demo::tools::SUBNET).unwrap();
        let (network, host) = split_bits(&info.address_bits, info.prefix);
        assert_eq!(network.matches(['0', '1']).count(), 24);
        assert_eq!(host.matches(['0', '1']).count(), 8);
    }

    #[test]
    fn commands_are_shown_as_typed() {
        let c = SystemCommand {
            program: "ipconfig".into(),
            args: vec!["/renew".into(), "Ethernet 2".into()],
            ..Default::default()
        };
        assert_eq!(command_line(&c), "ipconfig /renew \"Ethernet 2\"");
        let flush = command_line(&sysactions::flush_dns());
        assert!(flush.ends_with("/flushdns"));
        let renew = sysactions::renew_lease(Some("Wi-Fi"));
        assert_eq!(renew.len(), 2);
        assert!(command_line(&renew[0]).ends_with("/release Wi-Fi"));
        assert!(command_line(&renew[1]).ends_with("/renew Wi-Fi"));
    }

    #[test]
    fn report_order_and_filter() {
        let adapters = crate::demo::adapters(1_800_000_000);
        let all = report_adapters(&adapters, true);
        assert_eq!(all.len(), adapters.len());
        assert!(all[0].is_default);
        // Connected adapters come before disconnected ones.
        let first_down = all.iter().position(|a| !a.up).unwrap_or(all.len());
        assert!(all[first_down..].iter().all(|a| !a.up));
        let some = report_adapters(&adapters, false);
        assert!(!some.is_empty() && some.len() < all.len());
        assert!(some.iter().all(|a| a.is_default || (a.up && a.physical)));
        assert!(report_adapters(&[], false).is_empty());
    }

    #[test]
    fn demo_page_shows_finished_results_and_runs_nothing() {
        let page = ToolsPage::new(true, "tools-dns");
        assert_eq!(page.tool, Tool::Dns);
        assert_eq!(page.ping.replies.len(), 60);
        assert_eq!(page.ping.times.len(), 60);
        assert!((page.ping.stats.loss_pct - 3.33).abs() < 0.1);
        assert!(!page.ping.running && page.ping.rx.is_none());
        assert_eq!(page.trace.hops.len(), 9);
        assert!(!page.trace.running && page.trace.rx.is_none());
        assert!(matches!(page.dns.result, Some(Ok(_))));
        assert!(page.ports.finished && !page.ports.running);
        assert!(matches!(page.whois.result, Some(Ok(_))));
        assert!(page.actions.busy.is_none() && page.actions.flush.is_none());
        assert!(wol_check(&page.wol.mac, &page.wol.broadcast).is_ok());
        assert!(subnet::calculate(&page.subnet).is_ok());

        let real = ToolsPage::new(false, "tools");
        assert_eq!(real.tool, Tool::Ping);
        assert!(real.ping.replies.is_empty() && real.trace.hops.is_empty());
        assert!(real.dns.result.is_none() && real.whois.result.is_none());
        assert!(!real.ports.permitted);
    }
}
