//! Wi-Fi: the networks nearby, how crowded the channels are, and the signal
//! and details of the current connection.
//!
//! Nothing here changes the PC's Wi-Fi configuration. The only request sent
//! is "please scan" to the Wi-Fi adapter.

use super::app::{App, Tab};
use super::charts;
use super::theme::{pal, regular, semibold, Icon, Palette};
use super::widgets::{self, Col};
use crate::{export, fmt};
use eframe::egui::{
    self, epaint::Mesh, pos2, vec2, Align2, Color32, CornerRadius, Pos2, Rect, Response, RichText,
    Sense, Shape, Stroke, Ui,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};
use wf_wifi::{channels, wlan, Band, Bss, ChannelLoad, WlanError};

// --------------------------------------------------------------------------------------
// Pure helpers (shared with the other Wi-Fi pages)
// --------------------------------------------------------------------------------------

/// "Wi-Fi 6 (802.11ax)", "802.11g", "Unknown".
pub fn standard_label(generation: Option<u8>, phy: &str) -> String {
    match (generation, phy.trim()) {
        (Some(g), "") => format!("Wi-Fi {g}"),
        (Some(g), phy) => format!("Wi-Fi {g} ({phy})"),
        (None, "") => "Unknown".to_string(),
        (None, phy) => phy.to_string(),
    }
}

/// "Wi-Fi 6" for narrow cells.
pub fn standard_short(generation: Option<u8>, phy: &str) -> String {
    match generation {
        Some(g) => format!("Wi-Fi {g}"),
        None => standard_label(None, phy),
    }
}

/// How well a security mode protects a network.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecLevel {
    /// WPA2 or WPA3.
    Good,
    /// The outdated first WPA, or a mode that still accepts it.
    Warn,
    /// No encryption, or WEP (broken).
    Danger,
    Unknown,
}

pub fn security_level(security: &str) -> SecLevel {
    let s = security.trim().to_ascii_lowercase();
    if s.is_empty() {
        return SecLevel::Unknown;
    }
    if s.contains("wep") || s.contains("open") || s == "none" {
        return SecLevel::Danger;
    }
    let modes: Vec<&str> = s
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.starts_with("wpa"))
        .collect();
    if modes.is_empty() {
        return if s.contains("owe") {
            SecLevel::Warn
        } else {
            SecLevel::Unknown
        };
    }
    if modes.iter().any(|m| *m == "wpa" || *m == "wpa1") {
        SecLevel::Warn
    } else {
        SecLevel::Good
    }
}

pub fn security_color(p: &Palette, security: &str) -> Color32 {
    match security_level(security) {
        SecLevel::Good => p.good,
        SecLevel::Warn => p.warn,
        SecLevel::Danger => p.danger,
        SecLevel::Unknown => p.muted,
    }
}

/// One plain sentence about a security mode, for hover texts.
pub fn security_note(security: &str) -> &'static str {
    match security_level(security) {
        SecLevel::Good => "Current protection: traffic is encrypted.",
        SecLevel::Warn => {
            "Weak protection: this network still accepts an outdated mode. \
             If it is yours, switch the router to WPA2 or WPA3 only."
        }
        SecLevel::Danger => {
            "No real protection: others nearby can read what is sent over this network \
             unless the website or app encrypts it."
        }
        SecLevel::Unknown => "The protection of this network is not known.",
    }
}

/// The security shown when Windows gave none.
fn security_text(security: &str) -> &str {
    if security.trim().is_empty() {
        "Unknown"
    } else {
        security
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum NetSort {
    #[default]
    Signal,
    Name,
    Channel,
    Band,
    Width,
    Standard,
    Security,
    Vendor,
}

/// Band filter and search over name, address, vendor and security.
pub fn net_matches(b: &Bss, band: Option<Band>, needle: &str) -> bool {
    if band.is_some_and(|x| x != b.band) {
        return false;
    }
    let needle = needle.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    let name = if b.ssid.is_empty() {
        "hidden network"
    } else {
        &b.ssid
    };
    [
        name,
        &b.bssid,
        b.vendor.as_deref().unwrap_or(""),
        &b.security,
        b.band.label(),
        &b.phy,
    ]
    .iter()
    .any(|f| f.to_lowercase().contains(&needle))
        || needle
            .strip_prefix("ch")
            .map(str::trim)
            .and_then(|n| n.parse::<u16>().ok())
            .is_some_and(|n| n == b.channel)
}

/// Sorts by one column; ties go strongest signal first, then by address.
pub fn sort_networks(list: &mut [Bss], sort: (NetSort, bool)) {
    use std::cmp::Ordering as O;
    let lower = |s: &str| s.to_lowercase();
    list.sort_by(|a, b| {
        let main: O = match sort.0 {
            NetSort::Signal => a.rssi_dbm.cmp(&b.rssi_dbm),
            // Hidden networks go last when ascending.
            NetSort::Name => {
                (a.ssid.is_empty(), lower(&a.ssid)).cmp(&(b.ssid.is_empty(), lower(&b.ssid)))
            }
            NetSort::Channel => (a.band, a.channel).cmp(&(b.band, b.channel)),
            NetSort::Band => a.band.cmp(&b.band),
            NetSort::Width => a.width_mhz.cmp(&b.width_mhz),
            NetSort::Standard => (a.generation, &a.phy).cmp(&(b.generation, &b.phy)),
            NetSort::Security => lower(&a.security).cmp(&lower(&b.security)),
            NetSort::Vendor => {
                let (va, vb) = (a.vendor.as_deref(), b.vendor.as_deref());
                (va.is_none(), va.map(lower)).cmp(&(vb.is_none(), vb.map(lower)))
            }
        };
        let main = if sort.1 { main } else { main.reverse() };
        main.then(b.rssi_dbm.cmp(&a.rssi_dbm))
            .then(a.bssid.cmp(&b.bssid))
    });
}

/// Networks in total and per band: `[all, 2.4 GHz, 5 GHz, 6 GHz]`.
pub fn band_counts(list: &[Bss]) -> [usize; 4] {
    let n = |band: Band| list.iter().filter(|b| b.band == band).count();
    [list.len(), n(Band::B24), n(Band::B5), n(Band::B6)]
}

/// A row of the table when access points are grouped by network name.
#[derive(Clone, Debug, PartialEq)]
pub enum NetRow {
    Group {
        ssid: String,
        count: usize,
        best_dbm: i32,
        connected: bool,
    },
    /// Index into the list the rows were built from.
    Ap(usize),
}

/// Groups access points by network name, keeping the order of `list` inside
/// each group and ordering the groups by first appearance.
pub fn grouped_rows(list: &[Bss]) -> Vec<NetRow> {
    let mut order: Vec<&str> = Vec::new();
    for b in list {
        if !order.contains(&b.ssid.as_str()) {
            order.push(&b.ssid);
        }
    }
    let mut rows = Vec::new();
    for ssid in order {
        let members: Vec<usize> = (0..list.len()).filter(|i| list[*i].ssid == ssid).collect();
        rows.push(NetRow::Group {
            ssid: ssid.to_string(),
            count: members.len(),
            best_dbm: members
                .iter()
                .map(|i| list[*i].rssi_dbm)
                .max()
                .unwrap_or(-100),
            connected: members.iter().any(|i| list[*i].connected),
        });
        rows.extend(members.into_iter().map(NetRow::Ap));
    }
    rows
}

fn opt<T: std::fmt::Display>(v: Option<T>, unit: &str) -> String {
    v.map(|v| format!("{v}{unit}")).unwrap_or_default()
}

/// The scan as an export table.
pub fn networks_table(list: &[Bss]) -> export::Table {
    let mut t = export::Table::new(
        "Wi-Fi networks nearby",
        &[
            "Network (SSID)",
            "Access point (BSSID)",
            "Signal (dBm)",
            "Signal (%)",
            "Channel",
            "Band",
            "Frequency (MHz)",
            "Width (MHz)",
            "Standard",
            "Security",
            "Vendor",
            "Connected",
            "Stations",
            "Channel in use (%)",
            "Country",
        ],
    );
    for b in list {
        t.push(vec![
            if b.ssid.is_empty() {
                "(hidden network)".to_string()
            } else {
                b.ssid.clone()
            },
            b.bssid.clone(),
            b.rssi_dbm.to_string(),
            b.quality.to_string(),
            b.channel.to_string(),
            b.band.label().to_string(),
            b.freq_mhz.to_string(),
            opt(b.width_mhz, ""),
            standard_label(b.generation, &b.phy),
            security_text(&b.security).to_string(),
            b.vendor.clone().unwrap_or_default(),
            export::yes_no(b.connected),
            opt(b.stations, ""),
            opt(b.utilization, ""),
            b.country.clone().unwrap_or_default(),
        ]);
    }
    t
}

/// The line under the page title.
pub fn wifi_subtitle(networks: Option<&[Bss]>) -> String {
    let Some(list) = networks else {
        return "Networks nearby, channel use and the quality of your connection.".to_string();
    };
    let mut names: Vec<&str> = list
        .iter()
        .filter(|b| !b.ssid.is_empty())
        .map(|b| b.ssid.as_str())
        .collect();
    names.sort_unstable();
    names.dedup();
    let hidden = list.iter().filter(|b| b.ssid.is_empty()).count();
    let mut s = format!(
        "{} access {} nearby, {} network {}",
        list.len(),
        if list.len() == 1 { "point" } else { "points" },
        names.len(),
        if names.len() == 1 { "name" } else { "names" },
    );
    if hidden > 0 {
        s.push_str(&format!(", {hidden} hidden"));
    }
    s.push('.');
    s
}

/// One move between two access points of the same network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoamEntry {
    pub at: i64,
    pub ssid: String,
    pub from: String,
    pub to: String,
}

pub const ROAM_KEEP: usize = 20;

/// Feeds the current association (network name, access point) into the
/// roaming detector. Returns an entry when the PC moved to another access
/// point of the same network. A different network is not a move, and a
/// short disconnect does not hide one.
pub fn roam_step(
    last: &mut Option<(String, String)>,
    current: Option<(&str, &str)>,
    now: i64,
) -> Option<RoamEntry> {
    let (ssid, bssid) = current?;
    if bssid.is_empty() {
        return None;
    }
    let entry = match last {
        Some((s, b)) if s == ssid && !b.eq_ignore_ascii_case(bssid) => Some(RoamEntry {
            at: now,
            ssid: ssid.to_string(),
            from: b.clone(),
            to: bssid.to_string(),
        }),
        _ => None,
    };
    *last = Some((ssid.to_string(), bssid.to_string()));
    entry
}

/// Appends to the log, keeping the newest [`ROAM_KEEP`] entries.
pub fn push_roam(log: &mut Vec<RoamEntry>, entry: RoamEntry) {
    log.push(entry);
    if log.len() > ROAM_KEEP {
        let extra = log.len() - ROAM_KEEP;
        log.drain(..extra);
    }
}

/// Lowest, average and highest of the samples that are numbers.
pub fn signal_stats(samples: &[f64]) -> Option<(f64, f64, f64)> {
    let real: Vec<f64> = samples.iter().copied().filter(|v| v.is_finite()).collect();
    if real.is_empty() {
        return None;
    }
    let min = real.iter().copied().fold(f64::INFINITY, f64::min);
    let max = real.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let avg = real.iter().sum::<f64>() / real.len() as f64;
    Some((min, avg, max))
}

/// What a signal strength means in everyday use.
pub fn signal_meaning(dbm: i32) -> &'static str {
    match channels::signal_word(dbm) {
        "Excellent" => "as strong as it gets. Everything works at full speed.",
        "Good" => "fine for video calls, streaming and games.",
        "Fair" => "fine for browsing and video, but speeds drop and calls may stutter.",
        _ => "expect slow pages and drop-outs. Move closer to the router or add an access point.",
    }
}

// ---- Channel picture geometry --------------------------------------------------------

/// Maps frequencies to a horizontal position, skipping the unused gaps
/// between groups of channels (5 GHz has a wide one).
#[derive(Clone, Debug, PartialEq)]
pub struct Axis {
    /// Frequency ranges shown, in MHz, left to right.
    pub segments: Vec<(f32, f32)>,
}

/// Share of the width left empty between two segments.
const AXIS_GAP: f32 = 0.025;

impl Axis {
    /// The axis of a band: all its usual channels plus whatever the
    /// networks seen occupy.
    pub fn for_band(band: Band, networks: &[&Bss]) -> Axis {
        let mut ranges: Vec<(f32, f32)> = match band {
            Band::B24 => vec![(2401.0, 2483.0)],
            Band::B6 => vec![(5945.0, 7125.0)],
            Band::B5 => channels::standard_channels(band)
                .into_iter()
                .filter_map(|c| channels::freq_from_channel(band, c))
                .map(|f| (f as f32 - 10.0, f as f32 + 10.0))
                .collect(),
        };
        ranges.extend(
            networks
                .iter()
                .filter(|b| b.band == band && b.freq_mhz > 0)
                .map(|b| channels::span_mhz(b)),
        );
        ranges.sort_by(|a, b| a.0.total_cmp(&b.0));
        let mut segments: Vec<(f32, f32)> = Vec::new();
        for (lo, hi) in ranges {
            match segments.last_mut() {
                // Channel groups five megahertz apart read as one block.
                Some(last) if lo <= last.1 + 5.0 => last.1 = last.1.max(hi),
                _ => segments.push((lo, hi)),
            }
        }
        Axis { segments }
    }

    /// Position of a frequency as a fraction 0..=1 of the plot width.
    /// Frequencies in a gap land on the edge of the next segment.
    pub fn frac(&self, mhz: f32) -> f32 {
        let total: f32 = self.segments.iter().map(|s| s.1 - s.0).sum();
        if total <= 0.0 {
            return 0.0;
        }
        let gaps = self.segments.len().saturating_sub(1) as f32;
        let scale = (1.0 - AXIS_GAP * gaps) / total;
        let mut x = 0.0;
        for (i, (lo, hi)) in self.segments.iter().enumerate() {
            if i > 0 {
                x += AXIS_GAP;
            }
            if mhz <= *lo {
                return x;
            }
            if mhz <= *hi {
                return x + (mhz - lo) * scale;
            }
            x += (hi - lo) * scale;
        }
        1.0
    }
}

/// Height of a signal in the picture: -100 dBm is the floor, -30 dBm the top.
pub fn signal_frac(dbm: i32) -> f32 {
    ((dbm as f32 + 100.0) / 70.0).clamp(0.02, 1.0)
}

/// The outline of one network: a flat top with rounded shoulders, from
/// (`x0`, `base`) up to `top` and down to (`x1`, `base`), left to right.
pub fn hump(x0: f32, x1: f32, base: f32, top: f32) -> Vec<Pos2> {
    const STEPS: usize = 8;
    let (x0, x1) = (x0.min(x1), x0.max(x1));
    let shoulder = ((x1 - x0) * 0.22).min(16.0);
    let mut points = Vec::with_capacity(2 * STEPS + 2);
    for i in 0..=STEPS {
        let t = i as f32 / STEPS as f32;
        let rise = 0.5 - 0.5 * (std::f32::consts::PI * t).cos();
        points.push(pos2(x0 + shoulder * t, base + (top - base) * rise));
    }
    for i in 0..=STEPS {
        let t = i as f32 / STEPS as f32;
        let fall = 0.5 + 0.5 * (std::f32::consts::PI * t).cos();
        points.push(pos2(x1 - shoulder * (1.0 - t), base + (top - base) * fall));
    }
    points
}

/// Places name labels above their humps, most important first. `wanted` is
/// (centre x, top of the hump, label width). A label that would cover one
/// placed earlier is left out (`None`).
pub fn place_labels(wanted: &[(f32, f32, f32)], height: f32, bounds: Rect) -> Vec<Option<Rect>> {
    let mut placed: Vec<Rect> = Vec::new();
    wanted
        .iter()
        .map(|&(cx, top, width)| {
            let width = width.min(bounds.width());
            let left = (cx - width / 2.0).clamp(bounds.left(), bounds.right() - width);
            let mut y = top - height - 3.0;
            if y < bounds.top() {
                // No room above: write inside the hump.
                y = top + 3.0;
            }
            let rect = Rect::from_min_size(pos2(left, y), vec2(width, height));
            if placed.iter().any(|r| r.expand(3.0).intersects(rect)) {
                None
            } else {
                placed.push(rect);
                Some(rect)
            }
        })
        .collect()
}

// --------------------------------------------------------------------------------------
// Small painting helpers shared with the Saved networks and Devices pages
// --------------------------------------------------------------------------------------

/// A clickable icon painted into `rect` (for buttons inside table rows).
pub(super) fn icon_at(
    ui: &mut Ui,
    rect: Rect,
    id: impl std::hash::Hash,
    icon: Icon,
    color: Color32,
    enabled: bool,
    tip: &str,
) -> Response {
    let p = pal(ui);
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let resp = ui.interact(rect, ui.id().with(id), sense);
    if enabled && resp.hovered() {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(7), p.border);
    }
    let glyph = if icon.glyph().is_empty() {
        tip.chars().take(1).collect::<String>()
    } else {
        icon.glyph().to_string()
    };
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        glyph,
        regular(15.0),
        if enabled {
            color
        } else {
            p.faint.gamma_multiply(0.6)
        },
    );
    resp.on_hover_text(tip)
}

/// A badge at the left of `rect`, its text cut off when the cell is narrow.
/// Returns the width used.
pub(super) fn badge_in(ui: &Ui, rect: Rect, text: &str, color: Color32) -> f32 {
    let galley = widgets::elided(ui, text, semibold(11.5), color, rect.width() - 14.0);
    let w = galley.size().x + 14.0;
    let r = Rect::from_min_size(pos2(rect.left(), rect.center().y - 10.0), vec2(w, 20.0));
    ui.painter()
        .rect_filled(r, CornerRadius::same(10), color.gamma_multiply(0.16));
    ui.painter().galley(
        pos2(r.left() + 7.0, r.center().y - galley.size().y / 2.0),
        galley,
        color,
    );
    w
}

/// The upper and lower half of a two-line table cell.
pub(super) fn two_lines(cell: Rect) -> (Rect, Rect) {
    let mid = cell.center().y;
    (
        Rect::from_min_max(
            pos2(cell.left(), cell.top() + 5.0),
            pos2(cell.right(), mid + 2.0),
        ),
        Rect::from_min_max(
            pos2(cell.left(), mid + 1.0),
            pos2(cell.right(), cell.bottom() - 5.0),
        ),
    )
}

// --------------------------------------------------------------------------------------
// Page state and background work
// --------------------------------------------------------------------------------------

enum WifiMsg {
    Adapter(String),
    Networks(Vec<Bss>),
    Error(WlanError),
    ScanFailed(String),
}

struct Flags {
    stop: AtomicBool,
    /// The page is on screen: only then is anything read.
    open: AtomicBool,
    scan_now: AtomicBool,
    auto: AtomicBool,
}

struct Worker {
    rx: Receiver<WifiMsg>,
    flags: Arc<Flags>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.flags.stop.store(true, Ordering::SeqCst);
    }
}

fn spawn_worker(ctx: egui::Context, auto: bool) -> Worker {
    let (tx, rx) = channel();
    let flags = Arc::new(Flags {
        stop: AtomicBool::new(false),
        open: AtomicBool::new(true),
        scan_now: AtomicBool::new(false),
        auto: AtomicBool::new(auto),
    });
    let f = flags.clone();
    std::thread::spawn(move || {
        let mut guid: Option<String> = None;
        let mut next_lookup = Instant::now();
        let mut last_request: Option<Instant> = None;
        let mut last_results: Option<Instant> = None;
        let mut fetch_at: Option<Instant> = None;
        while !f.stop.load(Ordering::Relaxed) {
            if !f.open.load(Ordering::Relaxed) {
                // Refresh at once when the page is opened again.
                last_results = None;
                std::thread::sleep(Duration::from_millis(300));
                continue;
            }
            let mut sent = false;
            if guid.is_none() && Instant::now() >= next_lookup {
                next_lookup = Instant::now() + Duration::from_secs(10);
                let found = wlan::interfaces().and_then(|list| {
                    list.into_iter()
                        .max_by_key(|i| (i.connected, i.radio_on))
                        .ok_or_else(|| WlanError::NoWifi("no adapter".into()))
                });
                let msg = match found {
                    Ok(i) => {
                        guid = Some(i.guid);
                        WifiMsg::Adapter(i.description)
                    }
                    Err(e) => WifiMsg::Error(e),
                };
                if tx.send(msg).is_err() {
                    return;
                }
                sent = true;
            }
            if let Some(g) = guid.clone() {
                let manual = f.scan_now.swap(false, Ordering::Relaxed);
                let auto_due = f.auto.load(Ordering::Relaxed)
                    && last_request.is_none_or(|t| t.elapsed() >= Duration::from_secs(60));
                if manual || auto_due {
                    last_request = Some(Instant::now());
                    match wlan::request_scan(&g) {
                        // The adapter needs about four seconds to finish.
                        Ok(()) => fetch_at = Some(Instant::now() + Duration::from_secs(4)),
                        Err(e) => {
                            if manual {
                                let _ = tx.send(WifiMsg::ScanFailed(e.to_string()));
                                sent = true;
                            }
                        }
                    }
                }
                let after_scan = fetch_at.is_some_and(|t| Instant::now() >= t);
                if after_scan || last_results.is_none_or(|t| t.elapsed() >= Duration::from_secs(5))
                {
                    if after_scan {
                        fetch_at = None;
                    }
                    last_results = Some(Instant::now());
                    let msg = match wlan::scan_results(&g) {
                        Ok(list) => WifiMsg::Networks(list),
                        Err(e) => {
                            if matches!(e, WlanError::NoWifi(_)) {
                                // The adapter went away: look for one again.
                                guid = None;
                            }
                            WifiMsg::Error(e)
                        }
                    };
                    if tx.send(msg).is_err() {
                        return;
                    }
                    sent = true;
                }
            }
            if sent {
                ctx.request_repaint();
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    });
    Worker { rx, flags }
}

/// State of this page.
#[derive(Default)]
pub struct WifiPage {
    demo: bool,
    /// 0 = networks, 1 = channels, 2 = signal and link.
    sub: usize,
    networks: Option<Vec<Bss>>,
    error: Option<WlanError>,
    /// Unix time of the last successful read of the scan list.
    refreshed: Option<i64>,
    adapter: String,
    search: String,
    band: Option<Band>,
    group: bool,
    sort: (NetSort, bool),
    /// BSSID of the row whose details are shown.
    selected: Option<String>,
    worker: Option<Worker>,
    roam: Vec<RoamEntry>,
    last_ap: Option<(String, String)>,
    demo_seeded: bool,
    /// Which band the Channels view starts with (0 = 2.4 GHz).
    first_band: usize,
}

impl WifiPage {
    pub fn new(demo: bool, view: &str) -> Self {
        let mut page = WifiPage {
            demo,
            sub: match view {
                "wifi-channels" | "wifi-channels-5" | "wifi-channels-6" => 1,
                "wifi-signal" => 2,
                _ => 0,
            },
            ..Default::default()
        };
        if demo {
            let list = crate::demo::wifi::networks();
            if view == "wifi-details" {
                page.selected = list.iter().find(|b| b.connected).map(|b| b.bssid.clone());
            }
            page.group = view == "wifi-grouped";
            page.first_band = match view {
                "wifi-channels-5" => 1,
                "wifi-channels-6" => 2,
                _ => 0,
            };
            page.networks = Some(list);
        }
        page
    }

    /// The number shown next to the page in the navigation rail.
    pub fn count(&self) -> Option<usize> {
        self.networks.as_ref().map(Vec::len)
    }

    fn poll(&mut self, app: &mut App, ctx: &egui::Context) {
        let open = app.tab == Tab::Wifi;
        if self.demo {
            if !self.demo_seeded {
                self.demo_seeded = true;
                self.refreshed = Some(app.now - 3);
                for (ago, from, to) in crate::demo::wifi::roaming() {
                    self.roam.push(RoamEntry {
                        at: app.now - ago,
                        ssid: "Maple-Home".into(),
                        from: from.into(),
                        to: to.into(),
                    });
                }
            }
            return;
        }
        // The roaming log runs whichever page is shown.
        let current = app
            .link
            .as_ref()
            .map(|l| (l.ssid.as_str(), l.bssid.as_str()));
        if let Some(entry) = roam_step(&mut self.last_ap, current, app.now) {
            push_roam(&mut self.roam, entry);
        }
        if open && self.worker.is_none() && !app.still() {
            self.worker = Some(spawn_worker(ctx.clone(), app.settings.wifi_auto_scan));
        }
        let Some(worker) = &self.worker else { return };
        worker.flags.open.store(open, Ordering::Relaxed);
        worker
            .flags
            .auto
            .store(app.settings.wifi_auto_scan, Ordering::Relaxed);
        while let Ok(msg) = worker.rx.try_recv() {
            match msg {
                WifiMsg::Adapter(name) => self.adapter = name,
                WifiMsg::Networks(list) => {
                    self.networks = Some(list);
                    self.error = None;
                    self.refreshed = Some(app.now);
                }
                WifiMsg::Error(e) => {
                    if !matches!(e, WlanError::Other(_)) {
                        // The old list would only mislead.
                        self.networks = None;
                    }
                    self.error = Some(e);
                }
                WifiMsg::ScanFailed(e) => {
                    app.toast(format!("The scan could not be started. {e}"), true)
                }
            }
        }
    }
}

impl App {
    /// Called every frame, also while another page is shown: pick up results
    /// of background work here.
    pub(super) fn wifi_poll(&mut self, ctx: &egui::Context) {
        let mut page = std::mem::take(&mut self.wifi);
        page.poll(self, ctx);
        self.wifi = page;
    }

    pub(super) fn wifi_ui(&mut self, ui: &mut Ui) {
        let mut page = std::mem::take(&mut self.wifi);
        page.ui(self, ui);
        self.wifi = page;
    }
}

// --------------------------------------------------------------------------------------
// The page
// --------------------------------------------------------------------------------------

const ROW_H: f32 = 44.0;

impl WifiPage {
    fn ui(&mut self, app: &mut App, ui: &mut Ui) {
        let p = pal(ui);
        let nets: Vec<Bss> = self.networks.clone().unwrap_or_default();
        let no_wifi = matches!(self.error, Some(WlanError::NoWifi(_)));
        let subtitle = wifi_subtitle(self.networks.as_deref());
        let (mut scan, mut do_export) = (false, false);
        widgets::page_header(ui, "Wi-Fi", &subtitle, |ui| {
            ui.add_enabled_ui(!nets.is_empty(), |ui| {
                if widgets::ghost_button(ui, &Icon::EXPORT.with("Export"))
                    .on_hover_text(
                        "Save the list as CSV, HTML or JSON. The export contains network names \
                         and access-point addresses.",
                    )
                    .clicked()
                {
                    do_export = true;
                }
            });
            if widgets::primary_button(ui, &Icon::REFRESH.with("Scan now"), !no_wifi)
                .on_hover_text(
                    "Asks the Wi-Fi adapter to look for networks again. Results arrive within \
                     about four seconds.",
                )
                .clicked()
            {
                scan = true;
            }
        });
        if scan {
            if self.demo {
                self.refreshed = Some(app.now);
                app.toast("Demo mode: nothing is scanned.", false);
            } else if let Some(w) = &self.worker {
                w.flags.scan_now.store(true, Ordering::Relaxed);
                app.toast("Scanning for networks", false);
            }
        }
        if do_export {
            let mut list = nets.clone();
            sort_networks(&mut list, self.sort);
            app.export(
                &[networks_table(&list)],
                "Wi-Fi networks nearby",
                "wireforge-wifi-scan",
            );
        }

        ui.horizontal(|ui| {
            if let Some(i) =
                widgets::segmented(ui, &["Networks", "Channels", "Signal and link"], self.sub)
            {
                self.sub = i;
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let on = app.settings.wifi_auto_scan;
                let tip = "While this page is open, ask the Wi-Fi adapter for a fresh scan once \
                           a minute. Off: the list still follows what Windows already knows.";
                if widgets::toggle(ui, on, true).on_hover_text(tip).clicked() {
                    app.settings.wifi_auto_scan = !on;
                    app.save_settings();
                }
                ui.label(RichText::new("Scan every minute").size(13.0).color(p.muted))
                    .on_hover_text(tip);
                ui.add_space(10.0);
                let when = match self.refreshed {
                    Some(t) => format!("List refreshed {}", fmt::ago(app.now, t)),
                    None if no_wifi => String::new(),
                    None => "Waiting for the first list".to_string(),
                };
                ui.label(RichText::new(when).size(12.5).color(p.faint))
                    .on_hover_text(match self.refreshed {
                        Some(t) => format!("At {}", fmt::clock(t, app.offset)),
                        None => String::new(),
                    });
            });
        });
        ui.add_space(8.0);

        if self.sub == 2 {
            self.signal_ui(app, ui, &nets);
            return;
        }
        match self.error.clone() {
            Some(WlanError::NoWifi(_)) => {
                widgets::empty_state(
                    ui,
                    Icon::WIFI,
                    p.muted,
                    "No Wi-Fi here",
                    "This PC has no Wi-Fi adapter, or the Windows Wi-Fi service (WLAN AutoConfig) \
                     is turned off. Plug in or enable an adapter and this page fills by itself.",
                );
                return;
            }
            Some(WlanError::LocationDenied) => {
                let mut open_settings = false;
                widgets::notice_with(
                    ui,
                    Icon::LOCK,
                    p.warn,
                    "Windows only lists nearby networks for apps when location access is on, \
                     because network names can reveal where you are. Turn on \"Location services\" \
                     and \"Let desktop apps access your location\", then come back. WireForge \
                     does not use or store your location. Your current connection is still shown \
                     under \"Signal and link\".",
                    |ui| {
                        ui.add_space(2.0);
                        if widgets::ghost_button(ui, "Open location settings").clicked() {
                            open_settings = true;
                        }
                    },
                );
                if open_settings && !self.demo {
                    let _ = std::process::Command::new("explorer.exe")
                        .arg("ms-settings:privacy-location")
                        .spawn();
                }
                ui.add_space(12.0);
            }
            Some(e) => {
                widgets::notice(
                    ui,
                    Icon::WARNING,
                    p.warn,
                    &format!("The list of networks could not be read. {e}"),
                );
                ui.add_space(12.0);
            }
            None => {}
        }
        if self.networks.is_none() {
            if self.error.is_none() {
                widgets::busy_state(
                    ui,
                    "Reading the networks nearby",
                    "This takes a moment the first time.",
                );
            }
            return;
        }
        if self.sub == 0 {
            self.networks_ui(ui, &nets);
        } else {
            channels_ui(ui, &nets, self.first_band);
        }
    }

    // ---- Networks ------------------------------------------------------------------

    fn networks_ui(&mut self, ui: &mut Ui, nets: &[Bss]) {
        let p = pal(ui);
        let counts = band_counts(nets);
        ui.horizontal(|ui| {
            let chips: [(&str, Option<Band>); 4] = [
                ("All", None),
                ("2.4 GHz", Some(Band::B24)),
                ("5 GHz", Some(Band::B5)),
                ("6 GHz", Some(Band::B6)),
            ];
            for (i, (label, band)) in chips.into_iter().enumerate() {
                if widgets::chip(ui, label, Some(counts[i]), self.band == band).clicked() {
                    self.band = band;
                }
            }
            ui.add_space(6.0);
            widgets::checkbox(ui, &mut self.group, "Group by name").on_hover_text(
                "Put access points that belong to the same network name together \
                 (a mesh or several routers).",
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let w = (ui.available_width() - 24.0).clamp(120.0, 240.0);
                widgets::search_box(ui, &mut self.search, "Search name, address, vendor", w);
            });
        });
        ui.add_space(8.0);

        let mut list: Vec<Bss> = nets
            .iter()
            .filter(|b| net_matches(b, self.band, &self.search))
            .cloned()
            .collect();
        sort_networks(&mut list, self.sort);
        if self.group {
            // Keep each network's access points together, in the sorted order.
            let rows = grouped_rows(&list);
            let order: Vec<usize> = rows
                .iter()
                .filter_map(|r| match r {
                    NetRow::Ap(i) => Some(*i),
                    NetRow::Group { .. } => None,
                })
                .collect();
            list = order.into_iter().map(|i| list[i].clone()).collect();
        }
        let rows: Vec<NetRow> = if self.group {
            grouped_rows(&list)
        } else {
            (0..list.len()).map(NetRow::Ap).collect()
        };
        let selected: Option<Bss> = self
            .selected
            .as_ref()
            .and_then(|s| nets.iter().find(|b| &b.bssid == s))
            .cloned();
        if selected.is_none() {
            self.selected = None;
        }

        let wide = ui.available_width() >= 900.0;
        let mut cols = vec![
            Col::fixed("Signal", 86.0),
            Col::flex("Network", 1.5),
            Col::fixed("Channel", 56.0),
            Col::fixed("Band", 58.0),
            Col::fixed("Width", 60.0),
            Col::flex("Standard", 1.0),
            Col::flex("Security", 1.15),
        ];
        let mut sorts = vec![
            NetSort::Signal,
            NetSort::Name,
            NetSort::Channel,
            NetSort::Band,
            NetSort::Width,
            NetSort::Standard,
            NetSort::Security,
        ];
        if wide {
            cols.push(Col::flex("Vendor", 0.85));
            sorts.push(NetSort::Vendor);
        }
        let details_h = if selected.is_some() { 228.0 } else { 0.0 };
        let table_h = (ui.available_height() - details_h - 32.0 - 30.0 - 14.0).max(132.0);
        let group = self.group;
        widgets::card(ui, |ui| {
            let sorted = sorts
                .iter()
                .position(|s| *s == self.sort.0)
                .map(|i| (i, self.sort.1));
            if let Some(i) = widgets::table_header(ui, &cols, sorted) {
                let s = sorts[i];
                self.sort = if self.sort.0 == s {
                    (s, !self.sort.1)
                } else {
                    // Signal starts strongest first, text columns A to Z.
                    (s, s != NetSort::Signal)
                };
            }
            if rows.is_empty() {
                ui.allocate_ui(vec2(ui.available_width(), table_h), |ui| {
                    widgets::empty_state(
                        ui,
                        Icon::WIFI,
                        p.muted,
                        if nets.is_empty() { "No networks in range" } else { "Nothing matches" },
                        if nets.is_empty() {
                            "The Wi-Fi adapter sees no network right now. Press \"Scan now\" to look again."
                        } else {
                            "Change the band or clear the search to see more networks."
                        },
                    );
                });
                return;
            }
            egui::ScrollArea::vertical()
                .id_salt("wifi-networks")
                .auto_shrink([false, false])
                .max_height(table_h)
                .show_rows(ui, ROW_H, rows.len(), |ui, range| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for row in &rows[range] {
                        match row {
                            NetRow::Group {
                                ssid,
                                count,
                                best_dbm,
                                connected,
                            } => group_row(ui, &cols, ssid, *count, *best_dbm, *connected),
                            NetRow::Ap(i) => {
                                let b = &list[*i];
                                let is_sel = self.selected.as_deref() == Some(b.bssid.as_str());
                                if network_row(ui, &cols, b, is_sel, group, wide).clicked() {
                                    self.selected =
                                        if is_sel { None } else { Some(b.bssid.clone()) };
                                }
                            }
                        }
                    }
                });
        });
        if let Some(b) = selected {
            ui.add_space(12.0);
            if details_card(ui, &b) {
                self.selected = None;
            }
        }
    }

    // ---- Signal and link -----------------------------------------------------------

    fn signal_ui(&mut self, app: &mut App, ui: &mut Ui, nets: &[Bss]) {
        let p = pal(ui);
        let Some(link) = app.link.clone() else {
            let no_wifi = matches!(self.error, Some(WlanError::NoWifi(_)));
            widgets::empty_state(
                ui,
                Icon::WIFI,
                p.muted,
                "Not connected to Wi-Fi",
                if no_wifi {
                    "This PC has no Wi-Fi adapter, or the Windows Wi-Fi service is turned off."
                } else {
                    "Connect to a wireless network in Windows and the signal chart and the \
                     details of the connection appear here."
                },
            );
            return;
        };
        let history = app.signal_history.clone();
        let (now, offset) = (app.now, app.offset);
        let roam = self.roam.clone();
        // What the scan knows about the access point in use.
        let ap = nets
            .iter()
            .find(|b| b.bssid.eq_ignore_ascii_case(&link.bssid));
        App::scroll(ui, "wifi-signal", |ui| {
            widgets::columns_weighted(ui, &[1.45, 1.0], |col, ui| {
                if col == 0 {
                    widgets::titled_card(
                        ui,
                        "Signal strength",
                        |ui| {
                            ui.label(RichText::new("Last 10 minutes").size(12.5).color(p.faint));
                        },
                        |ui| {
                            let color = charts::signal_color(ui, link.rssi_dbm);
                            ui.horizontal(|ui| {
                                let (r, _) =
                                    ui.allocate_exact_size(vec2(22.0, 20.0), Sense::hover());
                                charts::signal_bars(
                                    ui,
                                    r.shrink2(vec2(1.0, 2.0)),
                                    link.quality,
                                    color,
                                );
                                ui.label(
                                    RichText::new(channels::signal_word(link.rssi_dbm))
                                        .font(semibold(15.0))
                                        .color(color),
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(format!(
                                            "{} dBm: {}",
                                            link.rssi_dbm,
                                            signal_meaning(link.rssi_dbm)
                                        ))
                                        .color(p.muted),
                                    )
                                    .truncate(),
                                );
                            });
                            ui.add_space(6.0);
                            let stats = signal_stats(&history);
                            let show = |v: Option<f64>| {
                                v.map(|v| format!("{v:.0} dBm"))
                                    .unwrap_or_else(|| "No data".into())
                            };
                            widgets::columns_n(ui, 4, |i, ui| match i {
                                0 => charts::stat(
                                    ui,
                                    "Now",
                                    &format!("{} dBm", link.rssi_dbm),
                                    &format!("{} %", link.quality),
                                ),
                                1 => charts::stat(ui, "Weakest", &show(stats.map(|s| s.0)), ""),
                                2 => charts::stat(ui, "Average", &show(stats.map(|s| s.1)), ""),
                                _ => charts::stat(ui, "Strongest", &show(stats.map(|s| s.2)), ""),
                            });
                            ui.add_space(8.0);
                            let series = [charts::Series {
                                name: "Signal",
                                values: &history,
                                color: p.down,
                                fill: true,
                            }];
                            let y_fmt = |v: f64| format!("{v:.0} dBm");
                            let x_fmt = |slot: usize, slots: usize| {
                                let secs = (slots - 1 - slot) as i64 * 2;
                                if secs == 0 {
                                    "Now".to_string()
                                } else {
                                    format!("{} ago", fmt::duration(secs))
                                }
                            };
                            let mut chart = charts::LineChart::new(&series, &y_fmt);
                            chart.height = 190.0;
                            chart.y_min = -90.0;
                            chart.y_max = Some(-30.0);
                            chart.x_left = "10 min ago";
                            chart.x_right = "now";
                            chart.x_fmt = Some(&x_fmt);
                            chart.slots = 300;
                            charts::line_chart(ui, &chart);
                            ui.add_space(2.0);
                            ui.label(
                                RichText::new(
                                    "Closer to 0 is stronger: -50 dBm is excellent, below -75 dBm is weak.",
                                )
                                .size(12.0)
                                .color(p.faint),
                            );
                        },
                    );
                    ui.add_space(12.0);
                    widgets::titled_card(
                        ui,
                        "Moves between access points",
                        |_| {},
                        |ui| {
                            if roam.is_empty() {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(
                                            "No moves since WireForge started. When a network has several \
                                             access points under one name (a mesh), each move of this PC \
                                             from one to another is listed here.",
                                        )
                                        .color(p.muted),
                                    )
                                    .wrap(),
                                );
                            }
                            for e in roam.iter().rev() {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 8.0;
                                    let (r, _) =
                                        ui.allocate_exact_size(vec2(124.0, 20.0), Sense::hover());
                                    widgets::text_in(
                                        ui,
                                        r,
                                        &fmt::date_time(e.at, offset),
                                        regular(13.0),
                                        p.faint,
                                    );
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(format!(
                                                "Moved from {} to {}",
                                                e.from, e.to
                                            ))
                                            .size(13.5),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(format!(
                                        "{}, {} ({})",
                                        e.ssid,
                                        fmt::ago(now, e.at),
                                        fmt::clock(e.at, offset)
                                    ));
                                });
                            }
                        },
                    );
                } else {
                    widgets::titled_card(
                        ui,
                        "Current connection",
                        |ui| {
                            widgets::badge(ui, "Connected", p.good);
                        },
                        |ui| {
                            let not_reported = "Not reported by Windows";
                            widgets::kv(ui, "Network", &link.ssid);
                            widgets::kv(ui, "Access point", &link.bssid);
                            widgets::kv(
                                ui,
                                "Made by",
                                link.vendor.as_deref().unwrap_or("Unknown vendor"),
                            );
                            widgets::kv(
                                ui,
                                "Standard",
                                &standard_label(link.generation, &link.phy),
                            );
                            widgets::kv(ui, "Band", link.band.label());
                            widgets::kv(
                                ui,
                                "Channel",
                                &if link.freq_mhz > 0 {
                                    format!("{} ({} MHz)", link.channel, link.freq_mhz)
                                } else {
                                    link.channel.to_string()
                                },
                            );
                            widgets::kv(
                                ui,
                                "Channel width",
                                &link
                                    .width_mhz
                                    .or(ap.and_then(|b| b.width_mhz))
                                    .map(|w| format!("{w} MHz"))
                                    .unwrap_or_else(|| not_reported.into()),
                            );
                            let speed = |mbps: f32| {
                                if mbps > 0.0 {
                                    fmt::link_speed((f64::from(mbps) * 1_000_000.0) as u64)
                                } else {
                                    not_reported.to_string()
                                }
                            };
                            widgets::kv(ui, "Receive rate", &speed(link.rx_rate_mbps));
                            widgets::kv(ui, "Transmit rate", &speed(link.tx_rate_mbps));
                            widgets::kv(
                                ui,
                                "MCS index",
                                &link
                                    .mcs
                                    .map(|m| m.to_string())
                                    .unwrap_or_else(|| not_reported.into()),
                            );
                            widgets::kv(
                                ui,
                                "Streams",
                                &link
                                    .streams
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| not_reported.into()),
                            );
                            widgets::kv_colored(
                                ui,
                                "Security",
                                security_text(&link.security),
                                Some(security_color(&p, &link.security)),
                            );
                            widgets::kv(ui, "Encryption", &link.cipher);
                            widgets::kv(ui, "Adapter", &link.interface);
                            ui.add_space(4.0);
                            ui.add(
                                egui::Label::new(
                                    RichText::new(
                                        "The rates are what the adapter and the access point agreed on \
                                         for the radio link, not your internet speed.",
                                    )
                                    .size(12.0)
                                    .color(p.faint),
                                )
                                .wrap(),
                            );
                        },
                    );
                }
            });
        });
    }
}

fn group_row(ui: &mut Ui, cols: &[Col], ssid: &str, count: usize, best_dbm: i32, connected: bool) {
    let p = pal(ui);
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), ROW_H), Sense::hover());
    let band = Rect::from_min_max(
        pos2(rect.left(), rect.top() + 6.0),
        pos2(rect.right(), rect.bottom() - 4.0),
    );
    ui.painter()
        .rect_filled(band, CornerRadius::same(8), p.hover);
    let cells = widgets::col_rects(cols, rect);
    let bars = Rect::from_center_size(cells[0].left_center() + vec2(9.0, 1.0), vec2(18.0, 14.0));
    charts::signal_bars(
        ui,
        bars,
        channels::quality_from_rssi(best_dbm),
        charts::signal_color(ui, best_dbm),
    );
    let title = Rect::from_min_max(
        pos2(cells[0].left() + 28.0, band.top()),
        pos2(rect.right() - 12.0, band.bottom()),
    );
    let (name, color) = if ssid.is_empty() {
        ("Hidden networks", p.muted)
    } else {
        (ssid, p.text)
    };
    let galley = widgets::elided(ui, name, semibold(13.5), color, title.width() - 220.0);
    let w = galley.size().x;
    ui.painter().galley(
        pos2(title.left(), title.center().y - galley.size().y / 2.0),
        galley,
        color,
    );
    let mut x = title.left() + w + 10.0;
    let note = format!(
        "{count} access {}, best {best_dbm} dBm",
        if count == 1 { "point" } else { "points" }
    );
    let galley = ui.painter().layout_no_wrap(note, regular(12.5), p.muted);
    let nw = galley.size().x;
    ui.painter().galley(
        pos2(x, title.center().y - galley.size().y / 2.0),
        galley,
        p.muted,
    );
    x += nw + 10.0;
    if connected {
        let r = Rect::from_min_max(pos2(x, title.top()), title.right_bottom());
        badge_in(ui, r, "Connected", p.accent);
    }
}

fn network_row(
    ui: &mut Ui,
    cols: &[Col],
    b: &Bss,
    selected: bool,
    indent: bool,
    wide: bool,
) -> Response {
    let p = pal(ui);
    let (cells, resp) = widgets::table_row(ui, cols, ROW_H, selected);
    // Signal
    let cell = cells[0];
    let color = charts::signal_color(ui, b.rssi_dbm);
    let bars = Rect::from_center_size(cell.left_center() + vec2(9.0, 0.0), vec2(18.0, 16.0));
    charts::signal_bars(ui, bars, b.quality, color);
    let text = Rect::from_min_max(pos2(cell.left() + 28.0, cell.top()), cell.right_bottom());
    let (top, bottom) = two_lines(text);
    widgets::text_in(
        ui,
        top,
        &format!("{} dBm", b.rssi_dbm),
        semibold(13.0),
        p.text,
    );
    widgets::text_in(
        ui,
        bottom,
        &format!("{} %", b.quality),
        regular(11.5),
        p.faint,
    );
    // Network
    let pad = if indent { 16.0 } else { 0.0 };
    let cell = Rect::from_min_max(
        pos2(cells[1].left() + pad, cells[1].top()),
        cells[1].right_bottom(),
    );
    let (top, bottom) = two_lines(cell);
    let badge_w = if b.connected { 82.0 } else { 0.0 };
    let name_rect = Rect::from_min_max(
        top.min,
        pos2((top.right() - badge_w).max(top.left() + 30.0), top.bottom()),
    );
    let (name, font, color) = if b.ssid.is_empty() {
        ("Hidden network", regular(13.5), p.muted)
    } else {
        (b.ssid.as_str(), semibold(13.5), p.text)
    };
    let galley = widgets::elided(ui, name, font, color, name_rect.width());
    let w = galley.size().x;
    ui.painter().galley(
        pos2(
            name_rect.left(),
            name_rect.center().y - galley.size().y / 2.0,
        ),
        galley,
        color,
    );
    if b.connected {
        let r = Rect::from_min_max(
            pos2(name_rect.left() + w + 8.0, top.top()),
            pos2(cell.right(), top.bottom()),
        );
        badge_in(ui, r, "Connected", p.accent);
    }
    widgets::text_in(ui, bottom, &b.bssid, regular(11.5), p.faint);
    // Channel, band, width
    widgets::text_in(ui, cells[2], &b.channel.to_string(), regular(13.5), p.text);
    widgets::text_in(ui, cells[3], b.band.label(), regular(13.0), p.muted);
    match b.width_mhz {
        Some(w) => widgets::text_in(ui, cells[4], &format!("{w} MHz"), regular(13.0), p.muted),
        None => widgets::text_in(ui, cells[4], "Unknown", regular(13.0), p.faint),
    };
    // Standard
    let standard = if cells[5].width() >= 128.0 {
        standard_label(b.generation, &b.phy)
    } else {
        standard_short(b.generation, &b.phy)
    };
    widgets::text_in(ui, cells[5], &standard, regular(13.0), p.muted);
    // Security
    badge_in(
        ui,
        cells[6],
        security_text(&b.security),
        security_color(&p, &b.security),
    );
    // Vendor
    if wide {
        match &b.vendor {
            Some(v) => widgets::text_in(ui, cells[7], v, regular(13.0), p.muted),
            None => widgets::text_in(ui, cells[7], "Unknown", regular(13.0), p.faint),
        };
    }
    resp
}

/// Everything known about one access point. Returns true when closed.
fn details_card(ui: &mut Ui, b: &Bss) -> bool {
    let p = pal(ui);
    let mut close = false;
    let title = if b.ssid.is_empty() {
        "Details of the hidden network".to_string()
    } else {
        format!("Details of {}", b.ssid)
    };
    widgets::titled_card(
        ui,
        &title,
        |ui| {
            if widgets::icon_button(ui, Icon::CLOSE, "Close the details").clicked() {
                close = true;
            }
            if b.connected {
                widgets::badge(ui, "Connected", p.accent);
            }
        },
        |ui| {
            let unknown = "Not announced";
            let or = |v: Option<String>| v.unwrap_or_else(|| unknown.to_string());
            widgets::columns_n(ui, 3, |col, ui| {
                ui.spacing_mut().item_spacing.y = 5.0;
                match col {
                    0 => {
                        widgets::kv(
                            ui,
                            "Network name",
                            if b.ssid.is_empty() {
                                "Hidden (not broadcast)"
                            } else {
                                &b.ssid
                            },
                        );
                        widgets::kv(ui, "Access point", &b.bssid);
                        widgets::kv(
                            ui,
                            "Made by",
                            b.vendor.as_deref().unwrap_or("Unknown vendor"),
                        );
                        widgets::kv_colored(
                            ui,
                            "Security",
                            security_text(&b.security),
                            Some(security_color(&p, &b.security)),
                        );
                        widgets::kv(ui, "Standard", &standard_label(b.generation, &b.phy));
                    }
                    1 => {
                        widgets::kv(
                            ui,
                            "Signal",
                            &format!(
                                "{} dBm, {} % ({})",
                                b.rssi_dbm,
                                b.quality,
                                channels::signal_word(b.rssi_dbm)
                            ),
                        );
                        widgets::kv(ui, "Band", b.band.label());
                        widgets::kv(
                            ui,
                            "Channel",
                            &format!(
                                "{} ({} MHz){}",
                                b.channel,
                                b.freq_mhz,
                                if channels::is_dfs(b.band, b.channel) {
                                    ", shared with radar"
                                } else {
                                    ""
                                }
                            ),
                        );
                        widgets::kv(
                            ui,
                            "Channel width",
                            &or(b.width_mhz.map(|w| format!("{w} MHz"))),
                        );
                        let (lo, hi) = channels::span_mhz(b);
                        widgets::kv(
                            ui,
                            "Centre frequency",
                            &match b.center_mhz {
                                Some(c) => format!("{c} MHz"),
                                None => format!("{:.0} MHz", (lo + hi) / 2.0),
                            },
                        );
                    }
                    _ => {
                        widgets::kv(
                            ui,
                            "Highest basic rate",
                            &or(b.max_rate_mbps.map(|r| format!("{r:.0} Mbit/s"))),
                        );
                        widgets::kv(
                            ui,
                            "Beacon interval",
                            &or(b.beacon_interval_ms.map(|m| format!("{m} ms"))),
                        );
                        widgets::kv(
                            ui,
                            "Devices connected",
                            &or(b.stations.map(|s| s.to_string())),
                        );
                        widgets::kv(
                            ui,
                            "Air time in use",
                            &or(b.utilization.map(|u| format!("{u} %"))),
                        );
                        widgets::kv(ui, "Country", &or(b.country.clone()));
                    }
                }
            });
        },
    );
    close
}

// ---- Channels ----------------------------------------------------------------------

fn channels_ui(ui: &mut Ui, nets: &[Bss], first_band: usize) {
    let p = pal(ui);
    App::scroll(ui, "wifi-channels", |ui| {
        let own_ssid = nets
            .iter()
            .find(|b| b.connected)
            .map(|b| b.ssid.clone())
            .unwrap_or_default();
        let mut bands = [Band::B24, Band::B5, Band::B6];
        bands.rotate_left(first_band.min(2));
        for band in bands {
            let in_band: Vec<&Bss> = nets.iter().filter(|b| b.band == band).collect();
            if in_band.is_empty() && band != Band::B24 {
                continue;
            }
            let loads = channels::occupancy(nets, band);
            let best = channels::best_channel(nets, band);
            let own = in_band.iter().find(|b| b.connected).map(|b| b.channel);
            let count = in_band.len();
            widgets::titled_card(
                ui,
                &format!("{} band", band.label()),
                |ui| {
                    ui.label(
                        RichText::new(format!(
                            "{count} access {}",
                            if count == 1 { "point" } else { "points" }
                        ))
                        .size(12.5)
                        .color(p.faint),
                    );
                },
                |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 14.0;
                        charts::legend_item(ui, "Your network", p.accent);
                        charts::legend_item(ui, "Other networks", p.faint);
                        charts::legend_item(ui, "Crowding per channel", p.muted);
                        if best.is_some() {
                            charts::legend_item(ui, "Suggested channel", p.good);
                        }
                    });
                    channel_picture(
                        ui,
                        band,
                        &in_band,
                        &loads,
                        best.as_ref().map(|b| b.channel),
                        &own_ssid,
                    );
                    if let Some(s) = &best {
                        ui.add_space(8.0);
                        let already = if own == Some(s.channel) {
                            " Your network already uses it."
                        } else {
                            ""
                        };
                        widgets::notice(
                            ui,
                            Icon::INFO,
                            p.info,
                            &format!(
                                "{}{already} You would change this in your router's settings.",
                                s.reason
                            ),
                        );
                    }
                },
            );
            ui.add_space(12.0);
        }
        ui.label(
            RichText::new(
                "Each shape is one access point: as wide as the channels it uses, as tall as its \
                 signal here. Shapes that overlap share air time and slow each other down.",
            )
            .size(12.0)
            .color(p.faint),
        );
    });
}

fn fill_under(points: &[Pos2], base: f32, color: Color32) -> Mesh {
    let mut mesh = Mesh::default();
    for (i, pt) in points.iter().enumerate() {
        mesh.colored_vertex(*pt, color);
        mesh.colored_vertex(pos2(pt.x, base), color);
        if i > 0 {
            let n = (i * 2) as u32;
            mesh.add_triangle(n - 2, n - 1, n);
            mesh.add_triangle(n - 1, n + 1, n);
        }
    }
    mesh
}

/// The channel-occupancy picture of one band with the per-channel load
/// under it.
fn channel_picture(
    ui: &mut Ui,
    band: Band,
    nets: &[&Bss],
    loads: &[ChannelLoad],
    best: Option<u16>,
    own_ssid: &str,
) {
    // Every access point of the network this PC is on counts as "yours".
    let mine = |b: &Bss| b.connected || (!own_ssid.is_empty() && b.ssid == own_ssid);
    const PLOT_H: f32 = 196.0;
    const LABEL_H: f32 = 20.0;
    const LOAD_H: f32 = 30.0;
    const GUTTER: f32 = 56.0;
    let p = pal(ui);
    let (outer, resp) = ui.allocate_exact_size(
        vec2(ui.available_width(), PLOT_H + LABEL_H + LOAD_H),
        Sense::hover(),
    );
    if !ui.is_rect_visible(outer) {
        return;
    }
    let painter = ui.painter_at(outer);
    let plot = Rect::from_min_max(
        pos2(outer.left() + GUTTER, outer.top() + 18.0),
        pos2(outer.right() - 8.0, outer.top() + PLOT_H),
    );
    let strip = Rect::from_min_max(
        pos2(plot.left(), plot.bottom() + LABEL_H),
        pos2(plot.right(), outer.bottom()),
    );
    let axis = Axis::for_band(band, nets);
    let to_x = |mhz: f32| plot.left() + plot.width() * axis.frac(mhz);
    let to_y = |dbm: i32| plot.bottom() - signal_frac(dbm) * plot.height();

    // Quiet grid with the signal scale in the gutter.
    for dbm in [-90, -70, -50, -30] {
        let y = to_y(dbm);
        painter.hline(
            plot.x_range(),
            y,
            Stroke::new(1.0_f32, p.border.gamma_multiply(0.55)),
        );
        painter.text(
            pos2(plot.left() - 8.0, y),
            Align2::RIGHT_CENTER,
            format!("{dbm} dBm"),
            regular(11.0),
            p.faint,
        );
    }
    painter.hline(
        plot.x_range(),
        plot.bottom(),
        Stroke::new(1.0_f32, p.border),
    );

    // Channel numbers and the load bars under them.
    let ticks: Vec<(f32, &ChannelLoad)> = loads
        .iter()
        .filter_map(|l| channels::freq_from_channel(band, l.channel).map(|f| (to_x(f as f32), l)))
        .collect();
    let spacing = ticks
        .windows(2)
        .map(|w| w[1].0 - w[0].0)
        .filter(|d| *d > 0.5)
        .fold(f32::INFINITY, f32::min);
    let bar_w = if spacing.is_finite() {
        (spacing - 3.0).clamp(3.0, 14.0)
    } else {
        14.0
    };
    let max_score = loads
        .iter()
        .map(|l| l.score)
        .fold(0.0_f32, f32::max)
        .max(0.001);
    painter.text(
        pos2(plot.left() - 8.0, plot.bottom() + LABEL_H / 2.0),
        Align2::RIGHT_CENTER,
        "Channel",
        regular(11.0),
        p.faint,
    );
    painter.text(
        pos2(plot.left() - 8.0, strip.center().y),
        Align2::RIGHT_CENTER,
        "Crowding",
        regular(11.0),
        p.faint,
    );
    painter.hline(
        strip.x_range(),
        strip.bottom() - 0.5,
        Stroke::new(1.0_f32, p.border.gamma_multiply(0.55)),
    );
    let mut last_right = f32::NEG_INFINITY;
    for (x, l) in &ticks {
        let is_best = best == Some(l.channel);
        painter.vline(
            *x,
            plot.bottom()..=plot.bottom() + 3.0,
            Stroke::new(1.0_f32, p.border),
        );
        let galley = painter.layout_no_wrap(
            l.channel.to_string(),
            if is_best {
                semibold(11.0)
            } else {
                regular(11.0)
            },
            if is_best { p.text } else { p.faint },
        );
        let w = galley.size().x;
        if x - w / 2.0 > last_right + 4.0 || is_best {
            painter.galley(pos2(x - w / 2.0, plot.bottom() + 4.0), galley, p.faint);
            last_right = x + w / 2.0;
        }
        let h = (l.score / max_score * (strip.height() - 4.0)).max(if l.score > 0.0 {
            2.0
        } else {
            0.0
        });
        if h > 0.0 || is_best {
            let h = h.max(2.0);
            painter.rect_filled(
                Rect::from_min_max(
                    pos2(x - bar_w / 2.0, strip.bottom() - 1.0 - h),
                    pos2(x + bar_w / 2.0, strip.bottom() - 1.0),
                ),
                CornerRadius {
                    nw: 2,
                    ne: 2,
                    sw: 0,
                    se: 0,
                },
                if is_best {
                    p.good
                } else {
                    p.muted.gamma_multiply(0.75)
                },
            );
        }
    }

    // The networks: weakest first so the strong ones stay on top, own last.
    let mut order: Vec<&Bss> = nets.to_vec();
    order.sort_by_key(|b| (mine(b), b.connected, b.rssi_dbm));
    let hover = resp
        .hover_pos()
        .filter(|pos| pos.x >= plot.left() && pos.x <= plot.right());
    let spans: Vec<(f32, f32)> = order
        .iter()
        .map(|b| {
            let (lo, hi) = channels::span_mhz(b);
            (to_x(lo), to_x(hi))
        })
        .collect();
    for (b, (x0, x1)) in order.iter().zip(&spans) {
        let under = hover.is_some_and(|pos| pos.x >= *x0 && pos.x <= *x1);
        let outline = hump(*x0, *x1, plot.bottom(), to_y(b.rssi_dbm));
        let (line, fill, width) = if mine(b) {
            (
                p.accent,
                p.accent
                    .gamma_multiply(if b.connected { 0.24 } else { 0.12 }),
                2.0_f32,
            )
        } else if under {
            (p.muted, p.muted.gamma_multiply(0.16), 2.0)
        } else {
            (p.faint, p.faint.gamma_multiply(0.12), 1.5_f32)
        };
        painter.add(Shape::mesh(fill_under(&outline, plot.bottom(), fill)));
        painter.add(Shape::line(outline, Stroke::new(width, line)));
    }

    // Names of the strongest few, your own first.
    let mut named: Vec<usize> = (0..order.len()).collect();
    named.sort_by_key(|i| (!order[*i].connected, !mine(order[*i]), -order[*i].rssi_dbm));
    named.truncate(9);
    let galleys: Vec<_> = named
        .iter()
        .map(|i| {
            let b = order[*i];
            let (text, color, font) = if mine(b) {
                (b.ssid.as_str(), p.text, semibold(11.5))
            } else if b.ssid.is_empty() {
                ("Hidden network", p.faint, regular(11.5))
            } else {
                (b.ssid.as_str(), p.muted, regular(11.5))
            };
            (widgets::elided(ui, text, font, color, 150.0), color)
        })
        .collect();
    let wanted: Vec<(f32, f32, f32)> = named
        .iter()
        .zip(&galleys)
        .map(|(i, (g, _))| {
            (
                (spans[*i].0 + spans[*i].1) / 2.0,
                to_y(order[*i].rssi_dbm),
                g.size().x,
            )
        })
        .collect();
    let label_bounds = Rect::from_min_max(pos2(plot.left(), outer.top()), plot.right_bottom());
    for (slot, (galley, color)) in place_labels(&wanted, 14.0, label_bounds)
        .into_iter()
        .zip(galleys)
    {
        if let Some(rect) = slot {
            painter.galley(rect.min, galley, color);
        }
    }

    // Hover: the channel under the pointer and the networks that use it.
    if let Some(pos) = hover {
        painter.vline(pos.x, plot.y_range(), Stroke::new(1.0_f32, p.faint));
        let nearest = ticks
            .iter()
            .min_by(|a, b| (a.0 - pos.x).abs().total_cmp(&(b.0 - pos.x).abs()))
            .filter(|t| {
                (t.0 - pos.x).abs()
                    <= if spacing.is_finite() {
                        spacing.max(8.0)
                    } else {
                        40.0
                    }
            })
            .map(|t| t.1);
        let mut under: Vec<&Bss> = order
            .iter()
            .zip(&spans)
            .filter(|(_, (x0, x1))| pos.x >= *x0 && pos.x <= *x1)
            .map(|(b, _)| *b)
            .collect();
        under.sort_by_key(|b| -b.rssi_dbm);
        if nearest.is_some() || !under.is_empty() {
            resp.on_hover_ui_at_pointer(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                if let Some(l) = nearest {
                    ui.label(RichText::new(format!("Channel {}", l.channel)).font(semibold(13.0)));
                    ui.label(
                        RichText::new(format!(
                            "{} on this channel, crowding {:.1}{}",
                            match l.networks {
                                0 => "No access point".to_string(),
                                1 => "1 access point".to_string(),
                                n => format!("{n} access points"),
                            },
                            l.score,
                            if channels::is_dfs(band, l.channel) {
                                ", shared with radar (DFS)"
                            } else {
                                ""
                            }
                        ))
                        .size(12.0)
                        .color(p.muted),
                    );
                }
                for b in under.iter().take(8) {
                    ui.horizontal(|ui| {
                        let (r, _) = ui.allocate_exact_size(vec2(10.0, 14.0), Sense::hover());
                        ui.painter().circle_filled(
                            r.center(),
                            4.0,
                            if mine(b) { p.accent } else { p.faint },
                        );
                        ui.label(RichText::new(format!("{} dBm", b.rssi_dbm)).font(semibold(13.0)));
                        ui.label(
                            RichText::new(format!(
                                "{}, channel {}{}",
                                if b.ssid.is_empty() {
                                    "Hidden network"
                                } else {
                                    &b.ssid
                                },
                                b.channel,
                                b.width_mhz
                                    .map(|w| format!(", {w} MHz wide"))
                                    .unwrap_or_default()
                            ))
                            .size(12.5)
                            .color(p.muted),
                        );
                    });
                }
                if under.len() > 8 {
                    ui.label(
                        RichText::new(format!("and {} more", under.len() - 8))
                            .size(12.0)
                            .color(p.muted),
                    );
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bss(ssid: &str, bssid: &str, rssi: i32, band: Band, channel: u16, width: u16) -> Bss {
        Bss {
            ssid: ssid.into(),
            bssid: bssid.into(),
            rssi_dbm: rssi,
            quality: channels::quality_from_rssi(rssi),
            freq_mhz: channels::freq_from_channel(band, channel).unwrap_or(0),
            channel,
            band,
            width_mhz: Some(width),
            security: "WPA2-Personal".into(),
            ..Default::default()
        }
    }

    #[test]
    fn standards_and_security() {
        assert_eq!(standard_label(Some(6), "802.11ax"), "Wi-Fi 6 (802.11ax)");
        assert_eq!(standard_label(None, "802.11g"), "802.11g");
        assert_eq!(standard_label(None, ""), "Unknown");
        assert_eq!(standard_short(Some(5), "802.11ac"), "Wi-Fi 5");
        assert_eq!(security_level("WPA2-Personal"), SecLevel::Good);
        assert_eq!(security_level("WPA3-Personal"), SecLevel::Good);
        assert_eq!(security_level("WPA2/WPA3-Personal"), SecLevel::Good);
        assert_eq!(security_level("WPA2-Enterprise"), SecLevel::Good);
        assert_eq!(security_level("WPA-Personal"), SecLevel::Warn);
        assert_eq!(security_level("WPA/WPA2-Personal"), SecLevel::Warn);
        assert_eq!(security_level("OWE"), SecLevel::Warn);
        assert_eq!(security_level("Open"), SecLevel::Danger);
        assert_eq!(security_level("WEP"), SecLevel::Danger);
        assert_eq!(security_level(""), SecLevel::Unknown);
    }

    #[test]
    fn filter_sort_and_counts() {
        let mut list = vec![
            bss("Maple-Home", "AA:00:00:00:00:01", -50, Band::B5, 36, 80),
            bss("", "AA:00:00:00:00:02", -70, Band::B24, 6, 20),
            bss("birch", "AA:00:00:00:00:03", -60, Band::B24, 1, 20),
            bss("Maple-Home", "AA:00:00:00:00:04", -65, Band::B6, 37, 160),
        ];
        assert_eq!(band_counts(&list), [4, 2, 1, 1]);
        assert!(net_matches(&list[0], None, "maple"));
        assert!(!net_matches(&list[0], Some(Band::B24), ""));
        assert!(net_matches(&list[1], None, "hidden"));
        assert!(net_matches(&list[2], None, "00:03"));
        assert!(net_matches(&list[0], None, "ch 36"));
        assert!(!net_matches(&list[0], None, "ch 6"));
        sort_networks(&mut list, (NetSort::Signal, false));
        assert_eq!(list[0].rssi_dbm, -50);
        assert_eq!(list[3].rssi_dbm, -70);
        sort_networks(&mut list, (NetSort::Name, true));
        assert_eq!(list[0].ssid, "birch");
        assert_eq!(list[3].ssid, "", "hidden networks go last");
        // Same name: strongest first.
        assert_eq!(list[1].rssi_dbm, -50);
        sort_networks(&mut list, (NetSort::Channel, true));
        assert_eq!(
            list.iter().map(|b| b.channel).collect::<Vec<_>>(),
            vec![1, 6, 36, 37]
        );
    }

    #[test]
    fn grouping_keeps_members_together() {
        let list = vec![
            bss("A", "1", -50, Band::B5, 36, 80),
            bss("B", "2", -55, Band::B5, 44, 80),
            bss("A", "3", -70, Band::B24, 6, 20),
        ];
        let rows = grouped_rows(&list);
        assert_eq!(rows.len(), 5);
        assert_eq!(
            rows[0],
            NetRow::Group {
                ssid: "A".into(),
                count: 2,
                best_dbm: -50,
                connected: false
            }
        );
        assert_eq!(rows[1], NetRow::Ap(0));
        assert_eq!(rows[2], NetRow::Ap(2));
        assert_eq!(rows[4], NetRow::Ap(1));
    }

    #[test]
    fn export_and_subtitle() {
        let list = vec![
            bss("Maple-Home", "AA:00:00:00:00:01", -50, Band::B5, 36, 80),
            bss("", "AA:00:00:00:00:02", -70, Band::B24, 6, 20),
        ];
        let t = networks_table(&list);
        assert_eq!(t.rows.len(), 2);
        assert!(t.rows.iter().all(|r| r.len() == t.columns.len()));
        assert_eq!(t.rows[1][0], "(hidden network)");
        assert_eq!(t.rows[0][2], "-50");
        assert_eq!(
            wifi_subtitle(Some(&list)),
            "2 access points nearby, 1 network name, 1 hidden."
        );
        assert!(wifi_subtitle(None).starts_with("Networks nearby"));
    }

    #[test]
    fn roaming_log() {
        let mut last = None;
        assert_eq!(roam_step(&mut last, None, 1), None);
        assert_eq!(roam_step(&mut last, Some(("Home", "AA")), 2), None);
        assert_eq!(
            roam_step(&mut last, Some(("Home", "aa")), 3),
            None,
            "same access point"
        );
        let e = roam_step(&mut last, Some(("Home", "BB")), 4).expect("a move");
        assert_eq!((e.from.as_str(), e.to.as_str(), e.at), ("aa", "BB", 4));
        // A short disconnect does not hide a move.
        assert_eq!(roam_step(&mut last, None, 5), None);
        assert!(roam_step(&mut last, Some(("Home", "CC")), 6).is_some());
        // Another network is not a move.
        assert_eq!(roam_step(&mut last, Some(("Cafe", "DD")), 7), None);
        assert_eq!(roam_step(&mut last, Some(("Cafe", "")), 8), None);
        let mut log = Vec::new();
        for i in 0..30 {
            push_roam(
                &mut log,
                RoamEntry {
                    at: i,
                    ssid: "Home".into(),
                    from: "A".into(),
                    to: "B".into(),
                },
            );
        }
        assert_eq!(log.len(), ROAM_KEEP);
        assert_eq!(log[0].at, 10);
    }

    #[test]
    fn signal_statistics() {
        assert_eq!(signal_stats(&[]), None);
        assert_eq!(signal_stats(&[f64::NAN]), None);
        assert_eq!(
            signal_stats(&[-60.0, f64::NAN, -50.0, -70.0]),
            Some((-70.0, -60.0, -50.0))
        );
        assert!(signal_meaning(-40).contains("full speed"));
        assert!(signal_meaning(-90).contains("closer"));
    }

    #[test]
    fn axis_geometry() {
        let a = Axis::for_band(Band::B24, &[]);
        assert_eq!(a.segments, vec![(2401.0, 2483.0)]);
        assert_eq!(a.frac(2401.0), 0.0);
        assert!((a.frac(2483.0) - 1.0).abs() < 1e-5);
        assert!((a.frac(2442.0) - 0.5).abs() < 1e-5);
        assert_eq!(a.frac(1000.0), 0.0);
        assert_eq!(a.frac(9000.0), 1.0);

        // 5 GHz: channels 36..64, then 100..165 (144 and 149 are 5 MHz apart).
        let a = Axis::for_band(Band::B5, &[]);
        assert_eq!(a.segments, vec![(5170.0, 5330.0), (5490.0, 5835.0)]);
        let end_first = a.frac(5330.0);
        let start_second = a.frac(5490.0);
        assert!((start_second - end_first - AXIS_GAP).abs() < 1e-5);
        // A frequency in the gap lands on the next segment's edge.
        assert_eq!(a.frac(5400.0), start_second);
        assert!((a.frac(5835.0) - 1.0).abs() < 1e-5);
        // Positions never go backwards.
        let mut prev = -1.0;
        for mhz in (5100..5900).step_by(5) {
            let x = a.frac(mhz as f32);
            assert!(x >= prev);
            prev = x;
        }
        // A network outside the usual channels widens the axis.
        let far = bss("x", "1", -60, Band::B5, 173, 20);
        let a = Axis::for_band(Band::B5, &[&far]);
        assert_eq!(a.segments.last().unwrap().1, 5875.0);
    }

    #[test]
    fn hump_and_signal_height() {
        assert_eq!(signal_frac(-30), 1.0);
        assert!(signal_frac(-100) > 0.0);
        assert!(signal_frac(-50) > signal_frac(-80));
        let pts = hump(100.0, 200.0, 300.0, 100.0);
        assert_eq!(pts.first().copied(), Some(pos2(100.0, 300.0)));
        assert_eq!(pts.last().copied(), Some(pos2(200.0, 300.0)));
        assert!(pts.windows(2).all(|w| w[1].x >= w[0].x), "left to right");
        assert!(pts
            .iter()
            .all(|p| p.y >= 100.0 - 1e-3 && p.y <= 300.0 + 1e-3));
        let top = pts.iter().map(|p| p.y).fold(f32::INFINITY, f32::min);
        assert!((top - 100.0).abs() < 1e-3);
        // Reversed ends give the same shape.
        assert_eq!(hump(200.0, 100.0, 300.0, 100.0), pts);
    }

    #[test]
    fn labels_do_not_collide() {
        let bounds = Rect::from_min_max(pos2(0.0, 0.0), pos2(400.0, 200.0));
        let placed = place_labels(
            &[
                (100.0, 80.0, 60.0),
                (110.0, 82.0, 60.0),
                (300.0, 80.0, 60.0),
                (5.0, 150.0, 60.0),
                (200.0, 4.0, 40.0),
            ],
            14.0,
            bounds,
        );
        assert!(placed[0].is_some());
        assert!(placed[1].is_none(), "would cover the first label");
        assert!(placed[2].is_some());
        // Clamped into the plot.
        assert_eq!(placed[3].unwrap().left(), 0.0);
        // No room above the hump: written inside it.
        assert!(placed[4].unwrap().top() > 4.0);
        let rects: Vec<Rect> = placed.into_iter().flatten().collect();
        for (i, a) in rects.iter().enumerate() {
            for b in &rects[i + 1..] {
                assert!(!a.intersects(*b));
            }
        }
    }

    #[test]
    fn demo_networks_cover_the_cases() {
        let list = crate::demo::wifi::networks();
        let counts = band_counts(&list);
        assert_eq!(counts[3], 2);
        assert!(counts[0] >= 16);
        assert_eq!(list.iter().filter(|b| b.connected).count(), 1);
        assert!(list.iter().any(|b| b.ssid.is_empty()));
        assert!(list.iter().any(|b| b.security == "Open"));
        let link = crate::demo::link();
        let own = list.iter().find(|b| b.connected).unwrap();
        assert_eq!(
            (own.bssid.as_str(), own.channel),
            (link.bssid.as_str(), link.channel)
        );
        assert!(
            list.iter()
                .filter(|b| b.ssid == link.ssid && b.band == Band::B5)
                .count()
                >= 2
        );
    }
}
