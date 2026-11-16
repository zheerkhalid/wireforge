//! Devices on my network: who answers on the directly attached private
//! network, remembered between scans, with the user's own names for them.
//!
//! A scan only ever asks addresses of the local network; nothing is sent to
//! the internet.

use super::app::{App, Confirm, Tab};
use super::charts;
use super::theme::{pal, regular, semibold, Icon};
use super::widgets::{self, Col};
use super::wifi_view::{badge_in, icon_at, two_lines};
use crate::{export, fmt};
use eframe::egui::{self, pos2, vec2, Align2, Rect, RichText, Sense, Stroke, Ui};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};
use wf_wifi::devices::{self, DeviceBook};
use wf_wifi::{FoundDevice, KnownDevice, Subnet};

// --------------------------------------------------------------------------------------
// Pure helpers
// --------------------------------------------------------------------------------------

/// What a cancelled scan returns; not an error worth showing in red.
const CANCELLED: &str = "The scan was cancelled.";
/// Time between automatic scans.
const AUTO_EVERY: Duration = Duration::from_secs(600);

/// The key the device book knows a device by: its MAC address, or its IP
/// address when no MAC is known.
pub fn device_key(d: &KnownDevice) -> &str {
    if d.mac.is_empty() {
        &d.last_ip
    } else {
        &d.mac
    }
}

/// The user's label, else the discovered name, else the vendor, else "Unknown device".
pub fn display_name(d: &KnownDevice) -> String {
    let clean = |s: &str| s.trim().to_string();
    if !d.label.trim().is_empty() {
        return clean(&d.label);
    }
    if let Some(name) = d.name.as_deref().filter(|n| !n.trim().is_empty()) {
        return clean(name);
    }
    if let Some(vendor) = d.vendor.as_deref().filter(|v| !v.trim().is_empty()) {
        return format!("{} device", vendor.trim());
    }
    "Unknown device".to_string()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeviceKind {
    Router,
    ThisPc,
    Computer,
    Phone,
    Printer,
    Tv,
    Generic,
}

impl DeviceKind {
    pub fn icon(self) -> Icon {
        match self {
            DeviceKind::Router => Icon::ROUTER,
            DeviceKind::ThisPc | DeviceKind::Computer => Icon::PC,
            DeviceKind::Phone => Icon::PHONE,
            DeviceKind::Printer => Icon::PRINTER,
            DeviceKind::Tv => Icon::TV,
            DeviceKind::Generic => Icon::DEVICES,
        }
    }

    pub fn word(self) -> &'static str {
        match self {
            DeviceKind::Router => "Router",
            DeviceKind::ThisPc => "This PC",
            DeviceKind::Computer => "Computer",
            DeviceKind::Phone => "Phone or tablet",
            DeviceKind::Printer => "Printer",
            DeviceKind::Tv => "TV or media player",
            DeviceKind::Generic => "Device",
        }
    }
}

/// A guess at what a device is, from its role, the hints the name lookups
/// gave, its names and its vendor.
pub fn device_kind(d: &KnownDevice) -> DeviceKind {
    if d.is_self {
        return DeviceKind::ThisPc;
    }
    if d.is_gateway {
        return DeviceKind::Router;
    }
    let text = format!(
        "{} {} {} {}",
        d.kind_hint.as_deref().unwrap_or(""),
        d.label,
        d.name.as_deref().unwrap_or(""),
        d.vendor.as_deref().unwrap_or("")
    )
    .to_lowercase();
    let words: Vec<&str> = text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let has = |list: &[&str]| list.iter().any(|k| text.contains(k));
    let word = |list: &[&str]| words.iter().any(|w| list.contains(w));
    if has(&["printer", "_ipp", "_pdl", "laserjet", "inkjet", "scanner"]) || word(&["print", "mfp"])
    {
        DeviceKind::Printer
    } else if has(&[
        "television",
        "mediarenderer",
        "cast",
        "airplay",
        "_dial",
        "chromecast",
        "roku",
        "bravia",
        "smarttv",
    ]) || word(&["tv"])
    {
        DeviceKind::Tv
    } else if has(&[
        "phone", "android", "tablet", "ipad", "galaxy", "pixel", "mobile",
    ]) {
        DeviceKind::Phone
    } else if has(&["router", "gateway", "accesspoint", "access point"]) || word(&["ap", "mesh"]) {
        DeviceKind::Router
    } else if has(&[
        "laptop",
        "desktop",
        "notebook",
        "workstation",
        "macbook",
        "imac",
    ]) || word(&["pc"])
        || d.name_source.as_deref() == Some("NetBIOS")
    {
        DeviceKind::Computer
    } else if d.random_mac && d.kind_hint.is_none() {
        // Private addresses are what phones and tablets use on Wi-Fi.
        DeviceKind::Phone
    } else {
        DeviceKind::Generic
    }
}

/// An IPv4 address as a number, for sorting. Anything else sorts last.
pub fn ip_number(ip: &str) -> u32 {
    ip.trim()
        .parse::<std::net::Ipv4Addr>()
        .map(u32::from)
        .unwrap_or(u32::MAX)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DevFilter {
    #[default]
    All,
    Online,
    /// First seen in the latest scan and not marked as known.
    New,
    /// Not marked as known.
    Unknown,
}

/// First seen in the latest scan and not marked as known.
pub fn is_new(d: &KnownDevice, fresh: &HashSet<String>) -> bool {
    !d.known && !d.is_self && !d.mac.is_empty() && fresh.contains(&d.mac.to_ascii_uppercase())
}

pub fn device_matches(
    d: &KnownDevice,
    filter: DevFilter,
    needle: &str,
    fresh: &HashSet<String>,
) -> bool {
    let pass = match filter {
        DevFilter::All => true,
        DevFilter::Online => d.online,
        DevFilter::New => is_new(d, fresh),
        DevFilter::Unknown => !d.known && !d.is_self,
    };
    if !pass {
        return false;
    }
    let needle = needle.trim().to_lowercase();
    needle.is_empty()
        || [
            display_name(d).as_str(),
            d.name.as_deref().unwrap_or(""),
            d.last_ip.as_str(),
            d.mac.as_str(),
            d.vendor.as_deref().unwrap_or(""),
            device_kind(d).word(),
        ]
        .iter()
        .any(|f| f.to_lowercase().contains(&needle))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DevSort {
    Name,
    #[default]
    Ip,
    Mac,
    Vendor,
    First,
    Last,
}

/// Sorts by one column; ties go by IP address (numerically), then by key.
pub fn sort_devices(list: &mut [KnownDevice], sort: (DevSort, bool)) {
    let lower = |s: &str| s.to_lowercase();
    list.sort_by(|a, b| {
        let main = match sort.0 {
            DevSort::Name => lower(&display_name(a)).cmp(&lower(&display_name(b))),
            DevSort::Ip => ip_number(&a.last_ip).cmp(&ip_number(&b.last_ip)),
            DevSort::Mac => (a.mac.is_empty(), &a.mac).cmp(&(b.mac.is_empty(), &b.mac)),
            DevSort::Vendor => {
                let (va, vb) = (a.vendor.as_deref(), b.vendor.as_deref());
                (va.is_none(), va.map(lower)).cmp(&(vb.is_none(), vb.map(lower)))
            }
            DevSort::First => a.first_seen.cmp(&b.first_seen),
            DevSort::Last => a.last_seen.cmp(&b.last_seen),
        };
        let main = if sort.1 { main } else { main.reverse() };
        main.then(ip_number(&a.last_ip).cmp(&ip_number(&b.last_ip)))
            .then(device_key(a).cmp(device_key(b)))
    });
}

/// `[all, online, new, unknown]`
pub fn filter_counts(list: &[KnownDevice], fresh: &HashSet<String>) -> [usize; 4] {
    let n = |f: DevFilter| {
        list.iter()
            .filter(|d| device_matches(d, f, "", fresh))
            .count()
    };
    [
        n(DevFilter::All),
        n(DevFilter::Online),
        n(DevFilter::New),
        n(DevFilter::Unknown),
    ]
}

/// The line under the page title. `network` is (range, adapter name).
pub fn devices_subtitle(
    network: Option<(&str, &str)>,
    total: usize,
    online: usize,
    scanned: bool,
) -> String {
    let place = match network {
        Some((cidr, adapter)) if !adapter.is_empty() => format!("Network {cidr} on {adapter}"),
        Some((cidr, _)) => format!("Network {cidr}"),
        None => "Not connected to a network".to_string(),
    };
    let devices = |n: usize| {
        if n == 1 {
            "1 device".to_string()
        } else {
            format!("{n} devices")
        }
    };
    if scanned {
        format!(
            "{place}. {online} of {} online in the last scan.",
            devices(total)
        )
    } else if total > 0 {
        format!("{place}. {} remembered from earlier scans.", devices(total))
    } else {
        format!("{place}. Not scanned yet.")
    }
}

/// The alert for devices never seen before: one line however many there are.
pub fn new_device_alert(book: &DeviceBook, new_macs: &[String]) -> Option<String> {
    let found: Vec<&KnownDevice> = new_macs
        .iter()
        .filter_map(|m| book.devices.iter().find(|d| d.mac.eq_ignore_ascii_case(m)))
        .collect();
    let describe = |d: &KnownDevice| {
        if d.label.trim().is_empty() && d.name.is_none() && d.vendor.is_none() {
            d.mac.clone()
        } else {
            display_name(d)
        }
    };
    match found.as_slice() {
        [] => None,
        [d] => Some(format!("{} joined at {}", describe(d), d.last_ip)),
        [a, b] => Some(format!(
            "2 new devices joined: {} at {} and {} at {}",
            describe(a),
            a.last_ip,
            describe(b),
            b.last_ip
        )),
        many => Some(format!(
            "{} new devices joined: {}, {} and {} more",
            many.len(),
            describe(many[0]),
            describe(many[1]),
            many.len() - 2
        )),
    }
}

/// The device list as an export table.
pub fn devices_table(list: &[KnownDevice], fresh: &HashSet<String>, offset: i64) -> export::Table {
    let mut t = export::Table::new(
        "Devices on my network",
        &[
            "Name",
            "Type",
            "Status",
            "IP address",
            "MAC address",
            "Private address",
            "Vendor",
            "Discovered name",
            "Name source",
            "Known",
            "New",
            "First seen",
            "Last seen",
            "Reply time (ms)",
        ],
    );
    for d in list {
        t.push(vec![
            display_name(d),
            device_kind(d).word().to_string(),
            if d.online { "Online" } else { "Offline" }.to_string(),
            d.last_ip.clone(),
            d.mac.clone(),
            export::yes_no(d.random_mac),
            d.vendor.clone().unwrap_or_default(),
            d.name.clone().unwrap_or_default(),
            d.name_source.clone().unwrap_or_default(),
            export::yes_no(d.known),
            export::yes_no(is_new(d, fresh)),
            fmt::date_time(d.first_seen, offset),
            fmt::date_time(d.last_seen, offset),
            d.rtt_ms.map(|r| r.to_string()).unwrap_or_default(),
        ]);
    }
    t
}

/// Progress of a sweep as a fraction and a sentence.
pub fn progress_text(done: u32, total: u32) -> (f32, String) {
    if total == 0 {
        return (0.0, "Starting the scan".to_string());
    }
    let done = done.min(total);
    let text = if done == total {
        format!(
            "All {} addresses checked, looking up device names",
            fmt::thousands(u64::from(total))
        )
    } else {
        format!(
            "{} of {} addresses checked",
            fmt::thousands(u64::from(done)),
            fmt::thousands(u64::from(total))
        )
    };
    (done as f32 / total as f32, text)
}

// --------------------------------------------------------------------------------------
// Page state and background work
// --------------------------------------------------------------------------------------

struct Scan {
    rx: Receiver<Result<Vec<FoundDevice>, String>>,
    cancel: Arc<AtomicBool>,
    done: Arc<AtomicU32>,
    total: Arc<AtomicU32>,
    /// Started by the ten-minute timer, not by the user.
    auto: bool,
}

impl Drop for Scan {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
    }
}

struct Rename {
    key: String,
    text: String,
    focused: bool,
}

/// State of this page.
#[derive(Default)]
pub struct DevicesPage {
    demo: bool,
    book: DeviceBook,
    path: PathBuf,
    /// Unix time of the last finished scan in this session.
    scanned_at: Option<i64>,
    /// MAC addresses first seen in the latest scan.
    fresh: HashSet<String>,
    scan: Option<Scan>,
    /// A frozen progress display for the demo: (done, total).
    demo_progress: Option<(u32, u32)>,
    error: Option<String>,
    resolve_names: bool,
    /// When the timer for the automatic scan was last reset.
    timer: Option<Instant>,
    filter: DevFilter,
    search: String,
    sort: (DevSort, bool),
    rename: Option<Rename>,
}

impl DevicesPage {
    pub fn new(demo: bool, view: &str, data_dir: &std::path::Path) -> Self {
        let mut page = DevicesPage {
            demo,
            path: data_dir.join("devices.json"),
            resolve_names: true,
            sort: (DevSort::Ip, true),
            timer: Some(Instant::now()),
            ..Default::default()
        };
        if demo {
            let now = crate::sys::now_unix();
            page.book = DeviceBook {
                devices: crate::demo::wifi::devices(now),
            };
            page.scanned_at = Some(now - crate::demo::wifi::SCAN_AGO);
            page.fresh.insert(crate::demo::wifi::NEW_DEVICE.to_string());
            if view == "devices-scan" {
                page.demo_progress = Some((152, 254));
            }
        } else {
            page.book = DeviceBook::load(&page.path);
        }
        page
    }

    /// The number shown next to the page in the navigation rail.
    pub fn count(&self) -> Option<usize> {
        self.scanned_at
            .map(|_| self.book.devices.iter().filter(|d| d.online).count())
    }

    fn scanning(&self) -> bool {
        self.scan.is_some() || self.demo_progress.is_some()
    }

    fn save(&self, app: &mut App) {
        if self.demo {
            return;
        }
        if let Err(e) = self.book.save(&self.path) {
            app.toast(e, true);
        }
    }

    fn start_scan(&mut self, ctx: &egui::Context, auto: bool) {
        if self.demo || self.scan.is_some() {
            return;
        }
        self.error = None;
        let (tx, rx) = channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicU32::new(0));
        let total = Arc::new(AtomicU32::new(0));
        let (c, d, t, ctx) = (cancel.clone(), done.clone(), total.clone(), ctx.clone());
        let resolve = self.resolve_names;
        std::thread::spawn(move || {
            let result = match devices::default_network() {
                None => Err(
                    "No home or office network to scan was found. Connect to Wi-Fi or a \
                             network cable first."
                        .to_string(),
                ),
                Some(network) => {
                    let options = devices::ScanOptions::for_network(&network, resolve);
                    let repaint = ctx.clone();
                    devices::scan(&options, &c, &move |n, of| {
                        d.store(n, Ordering::Relaxed);
                        t.store(of, Ordering::Relaxed);
                        repaint.request_repaint();
                    })
                }
            };
            let _ = tx.send(result);
            ctx.request_repaint();
        });
        self.scan = Some(Scan {
            rx,
            cancel,
            done,
            total,
            auto,
        });
    }

    fn stop_scan(&mut self) {
        if let Some(s) = &self.scan {
            s.cancel.store(true, Ordering::SeqCst);
        }
        self.demo_progress = None;
    }

    fn poll(&mut self, app: &mut App, ctx: &egui::Context) {
        if self.demo {
            return;
        }
        let finished = match &self.scan {
            Some(s) => match s.rx.try_recv() {
                Ok(result) => Some((result, s.auto)),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    Some((Err("The scan stopped unexpectedly.".to_string()), s.auto))
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => None,
            },
            None => None,
        };
        if let Some((result, auto)) = finished {
            self.scan = None;
            self.timer = Some(Instant::now());
            match result {
                Ok(found) => {
                    let new = self.book.merge(&found, app.now);
                    self.fresh = new.iter().map(|m| m.to_ascii_uppercase()).collect();
                    self.scanned_at = Some(app.now);
                    self.save(app);
                    let online = self.book.devices.iter().filter(|d| d.online).count();
                    let alert = new_device_alert(&self.book, &new)
                        .filter(|_| app.settings.alert_new_device);
                    match alert {
                        Some(text) => app.alert("New device on your network", &text),
                        None if !auto => app.toast(
                            format!(
                                "Scan finished: {online} {} online",
                                if online == 1 { "device" } else { "devices" }
                            ),
                            false,
                        ),
                        None => {}
                    }
                }
                Err(e) if e == CANCELLED => {
                    if !auto {
                        app.toast("Scan stopped. The list was left as it was.", false);
                    }
                }
                Err(e) => {
                    if !auto {
                        self.error = Some(e);
                    }
                }
            }
        }
        // The ten-minute timer runs whichever page is shown.
        if app.settings.devices_auto_scan
            && self.scan.is_none()
            && !app.still()
            && self.timer.is_none_or(|t| t.elapsed() >= AUTO_EVERY)
        {
            self.timer = Some(Instant::now());
            // Not in the middle of typing a name. The worker itself refuses networks
            // that must not be scanned.
            if app.tab != Tab::Devices || self.rename.is_none() {
                self.start_scan(ctx, true);
            }
        }
    }
}

impl App {
    /// Called every frame, also while another page is shown: pick up results
    /// of background work here.
    pub(super) fn devices_poll(&mut self, ctx: &egui::Context) {
        let mut page = std::mem::take(&mut self.devices);
        page.poll(self, ctx);
        self.devices = page;
    }

    /// Called when the program closes: stop background work.
    pub(super) fn devices_exit(&mut self) {
        if let Some(s) = &self.devices.scan {
            s.cancel.store(true, Ordering::SeqCst);
        }
        if !self.demo && !self.devices.book.devices.is_empty() {
            let _ = self.devices.book.save(&self.devices.path);
        }
    }

    pub(super) fn devices_ui(&mut self, ui: &mut Ui) {
        let mut page = std::mem::take(&mut self.devices);
        page.ui(self, ui);
        self.devices = page;
    }
}

// --------------------------------------------------------------------------------------
// The page
// --------------------------------------------------------------------------------------

const ROW_H: f32 = 46.0;

enum RowAction {
    Star(String, bool),
    Rename(String, String),
    Commit,
    CancelRename,
    Forget(String),
}

impl DevicesPage {
    fn ui(&mut self, app: &mut App, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        if let Some(key) = app.confirmed_prefix("devices.forget:") {
            self.book.forget(&key);
            self.fresh.remove(&key.to_ascii_uppercase());
            self.save(app);
            app.toast("The device was removed from the list.", false);
        }

        // The network shown is the one with the default route.
        let network: Option<(Subnet, String)> = if self.demo {
            None
        } else {
            app.primary_adapter().and_then(|a| {
                a.ipv4.first().map(|n| {
                    (
                        Subnet {
                            addr: n.addr,
                            prefix: n.prefix,
                        },
                        a.name.clone(),
                    )
                })
            })
        };
        let (cidr, adapter, refusal) = if self.demo {
            (
                Some(crate::demo::wifi::SUBNET.to_string()),
                crate::demo::wifi::ADAPTER.to_string(),
                None,
            )
        } else {
            match &network {
                Some((s, name)) => (Some(s.cidr()), name.clone(), s.scan_refusal()),
                None => (None, String::new(), None),
            }
        };
        let online = self.book.devices.iter().filter(|d| d.online).count();
        let subtitle = devices_subtitle(
            cidr.as_deref().map(|c| (c, adapter.as_str())),
            self.book.devices.len(),
            online,
            self.scanned_at.is_some(),
        );
        let scanning = self.scanning();
        let can_scan = cidr.is_some() && refusal.is_none();
        let (mut start, mut stop, mut do_export) = (false, false, false);
        widgets::page_header(ui, "Devices", &subtitle, |ui| {
            ui.add_enabled_ui(!self.book.devices.is_empty(), |ui| {
                if widgets::ghost_button(ui, &Icon::EXPORT.with("Export"))
                    .on_hover_text(
                        "Save the list as CSV, HTML or JSON. The export contains device names \
                         and addresses.",
                    )
                    .clicked()
                {
                    do_export = true;
                }
            });
            if scanning {
                if widgets::ghost_button(ui, &Icon::STOP.with("Stop"))
                    .on_hover_text("Stop the scan. The list stays as it was.")
                    .clicked()
                {
                    stop = true;
                }
            } else if widgets::primary_button(ui, &Icon::SEARCH.with("Scan"), can_scan)
                .on_hover_text(if can_scan {
                    "Ask every address on your own network who is there. Takes about a quarter \
                     of a minute."
                } else {
                    "There is no network that may be scanned."
                })
                .clicked()
            {
                start = true;
            }
        });
        if start {
            if self.demo {
                app.toast("Demo mode: nothing is scanned.", false);
            } else {
                self.start_scan(&ctx, false);
            }
        }
        if stop {
            self.stop_scan();
        }
        if do_export {
            let mut list = self.book.devices.clone();
            sort_devices(&mut list, self.sort);
            app.export(
                &[devices_table(&list, &self.fresh, app.offset)],
                "Devices on my network",
                "wireforge-devices",
            );
        }

        if let Some(reason) = &refusal {
            widgets::notice(
                ui,
                Icon::SHIELD,
                p.warn,
                &format!(
                    "{reason} WireForge only scans the private network this PC is directly \
                     attached to, so the Scan button is off."
                ),
            );
            ui.add_space(10.0);
        }
        if let Some(e) = self.error.clone() {
            let mut dismiss = false;
            widgets::notice_with(
                ui,
                Icon::WARNING,
                p.warn,
                &format!("The scan did not finish. {e}"),
                |ui| {
                    if widgets::ghost_button(ui, "Dismiss").clicked() {
                        dismiss = true;
                    }
                },
            );
            if dismiss {
                self.error = None;
            }
            ui.add_space(10.0);
        }

        self.scan_card(app, ui);
        ui.add_space(10.0);

        let counts = filter_counts(&self.book.devices, &self.fresh);
        ui.horizontal(|ui| {
            let chips = [
                ("All", DevFilter::All, "Every device ever seen"),
                (
                    "Online",
                    DevFilter::Online,
                    "Devices that answered in the last scan",
                ),
                (
                    "New",
                    DevFilter::New,
                    "Seen for the first time in the last scan",
                ),
                (
                    "Unknown",
                    DevFilter::Unknown,
                    "Devices you have not starred as known",
                ),
            ];
            for (i, (label, filter, tip)) in chips.into_iter().enumerate() {
                if widgets::chip(ui, label, Some(counts[i]), self.filter == filter)
                    .on_hover_text(tip)
                    .clicked()
                {
                    self.filter = filter;
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let w = (ui.available_width() - 24.0).clamp(120.0, 260.0);
                widgets::search_box(ui, &mut self.search, "Search name, address, vendor", w);
            });
        });
        ui.add_space(8.0);

        let mut list: Vec<KnownDevice> = self
            .book
            .devices
            .iter()
            .filter(|d| device_matches(d, self.filter, &self.search, &self.fresh))
            .cloned()
            .collect();
        sort_devices(&mut list, self.sort);

        let wide = ui.available_width() >= 900.0;
        let (cols, sorts): (Vec<Col>, Vec<Option<DevSort>>) = if wide {
            (
                vec![
                    Col::fixed("", 14.0),
                    Col::flex("Device", 1.55),
                    Col::fixed("IP address", 104.0),
                    Col::flex("MAC address", 1.05),
                    Col::flex("Vendor", 0.9),
                    Col::fixed("First seen", 82.0),
                    Col::fixed("Last seen", 82.0),
                    Col::fixed("", 92.0),
                ],
                vec![
                    None,
                    Some(DevSort::Name),
                    Some(DevSort::Ip),
                    Some(DevSort::Mac),
                    Some(DevSort::Vendor),
                    Some(DevSort::First),
                    Some(DevSort::Last),
                    None,
                ],
            )
        } else {
            (
                vec![
                    Col::fixed("", 14.0),
                    Col::flex("Device", 1.5),
                    Col::fixed("IP address", 104.0),
                    Col::flex("MAC address", 1.0),
                    Col::fixed("Last seen", 82.0),
                    Col::fixed("", 92.0),
                ],
                vec![
                    None,
                    Some(DevSort::Name),
                    Some(DevSort::Ip),
                    Some(DevSort::Mac),
                    Some(DevSort::Last),
                    None,
                ],
            )
        };
        let table_h = (ui.available_height() - 32.0 - 30.0 - 10.0).max(120.0);
        let (now, offset) = (app.now, app.offset);
        let mut actions: Vec<RowAction> = Vec::new();
        widgets::card(ui, |ui| {
            let sorted = sorts
                .iter()
                .position(|s| *s == Some(self.sort.0))
                .map(|i| (i, self.sort.1));
            if let Some(s) = widgets::table_header(ui, &cols, sorted).and_then(|i| sorts[i]) {
                self.sort = if self.sort.0 == s {
                    (s, !self.sort.1)
                } else {
                    // Dates start with the most recent.
                    (s, !matches!(s, DevSort::First | DevSort::Last))
                };
            }
            if list.is_empty() {
                ui.allocate_ui(vec2(ui.available_width(), table_h), |ui| {
                    if self.book.devices.is_empty() {
                        widgets::empty_state(
                            ui,
                            Icon::DEVICES,
                            p.muted,
                            "No devices yet",
                            if scanning {
                                "The scan is running. Devices appear here when it has finished."
                            } else {
                                "Press Scan to see which phones, computers, TVs and other devices \
                                 are on your network right now."
                            },
                        );
                    } else {
                        widgets::empty_state(
                            ui,
                            Icon::DEVICES,
                            p.muted,
                            "Nothing matches",
                            "Pick another filter or clear the search to see more devices.",
                        );
                    }
                });
                return;
            }
            let last = cols.len() - 1;
            egui::ScrollArea::vertical()
                .id_salt("devices")
                .auto_shrink([false, false])
                .max_height(table_h)
                .show_rows(ui, ROW_H, list.len(), |ui, range| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for d in &list[range] {
                        let key = device_key(d).to_string();
                        let (cells, _) = widgets::table_row(ui, &cols, ROW_H, false);
                        // Status
                        let c = cells[0].center();
                        if d.online {
                            ui.painter().circle_filled(c, 4.5, p.good);
                        } else {
                            ui.painter().circle_stroke(c, 4.0, Stroke::new(1.5_f32, p.faint));
                        }
                        ui.interact(cells[0].expand2(vec2(6.0, 0.0)), ui.id().with((&key, "dot")), Sense::hover())
                            .on_hover_text(if d.online {
                                match d.rtt_ms {
                                    Some(ms) => format!("Online in the last scan (answered in {ms} ms)"),
                                    None => "Online in the last scan".to_string(),
                                }
                            } else {
                                format!("Offline: last seen {}", fmt::ago(now, d.last_seen))
                            });
                        // Device
                        let cell = cells[1];
                        let kind = device_kind(d);
                        let icon = Rect::from_center_size(cell.left_center() + vec2(13.0, 0.0), vec2(26.0, 26.0));
                        ui.painter().text(
                            icon.center(),
                            Align2::CENTER_CENTER,
                            kind.icon().glyph(),
                            regular(17.0),
                            if d.online { p.muted } else { p.faint },
                        );
                        ui.interact(icon, ui.id().with((&key, "kind")), Sense::hover())
                            .on_hover_text(format!("{} (a guess from its name and maker)", kind.word()));
                        let text = Rect::from_min_max(pos2(cell.left() + 34.0, cell.top()), cell.right_bottom());
                        let editing = self.rename.as_ref().is_some_and(|r| r.key == key);
                        if editing {
                            if let Some(r) = &mut self.rename {
                                let field = Rect::from_center_size(text.center(), vec2(text.width(), 28.0));
                                let resp = ui.put(
                                    field,
                                    egui::TextEdit::singleline(&mut r.text)
                                        .hint_text("Name for this device")
                                        .char_limit(60),
                                );
                                if !r.focused {
                                    r.focused = true;
                                    resp.request_focus();
                                } else if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                                    actions.push(RowAction::CancelRename);
                                } else if resp.lost_focus() {
                                    actions.push(RowAction::Commit);
                                }
                            }
                        } else {
                            let badges: Vec<(&str, egui::Color32)> = [
                                (d.is_self, "This PC", p.accent),
                                (d.is_gateway, "Router", p.info),
                                (is_new(d, &self.fresh), "New", p.warn),
                            ]
                            .into_iter()
                            .filter(|b| b.0)
                            .map(|b| (b.1, b.2))
                            .collect();
                            let name = display_name(d);
                            let named = !d.label.trim().is_empty() || d.name.is_some() || d.vendor.is_some();
                            let sub = match (&d.name, d.label.trim().is_empty()) {
                                // The user's label is shown: keep the discovered name visible.
                                (Some(n), false) => Some(match &d.name_source {
                                    Some(src) => format!("{n} (from {src})"),
                                    None => n.clone(),
                                }),
                                (Some(_), true) => d.name_source.as_ref().map(|s| format!("{}, name from {s}", kind.word())),
                                _ => (kind != DeviceKind::Generic).then(|| kind.word().to_string()),
                            };
                            let (top, bottom) = if sub.is_some() { two_lines(text) } else { (text, text) };
                            let font = if named { semibold(13.5) } else { regular(13.5) };
                            let color = if !named {
                                p.muted
                            } else if d.online {
                                p.text
                            } else {
                                p.muted
                            };
                            let reserve: f32 = badges.iter().map(|b| b.0.len() as f32 * 6.5 + 22.0).sum();
                            let galley = widgets::elided(ui, &name, font, color, (top.width() - reserve).max(40.0));
                            let w = galley.size().x;
                            ui.painter()
                                .galley(pos2(top.left(), top.center().y - galley.size().y / 2.0), galley, color);
                            let mut x = top.left() + w + 8.0;
                            for (label, color) in badges {
                                let r = Rect::from_min_max(pos2(x, top.top()), pos2(cell.right(), top.bottom()));
                                if r.width() > 30.0 {
                                    x += badge_in(ui, r, label, color) + 5.0;
                                }
                            }
                            if let Some(sub) = sub {
                                widgets::text_in(ui, bottom, &sub, regular(11.5), p.faint);
                            }
                        }
                        // IP address
                        widgets::text_in(ui, cells[2], &d.last_ip, regular(13.5), p.text);
                        // MAC address
                        if d.mac.is_empty() {
                            widgets::text_in(ui, cells[3], "Not known", regular(13.0), p.faint);
                        } else if d.random_mac {
                            let (top, bottom) = two_lines(cells[3]);
                            widgets::text_in(ui, top, &d.mac, regular(13.0), p.muted);
                            widgets::text_in(ui, bottom, "private address", regular(11.5), p.faint);
                            ui.interact(cells[3], ui.id().with((&key, "mac")), Sense::hover()).on_hover_text(
                                "A private (randomised) address: phones and tablets invent one per \
                                 network to be harder to track, so it does not reveal the maker.",
                            );
                        } else {
                            widgets::text_in(ui, cells[3], &d.mac, regular(13.0), p.muted);
                        }
                        let mut next = 4;
                        if wide {
                            match &d.vendor {
                                Some(v) => widgets::text_in(ui, cells[4], v, regular(13.0), p.muted),
                                None => widgets::text_in(ui, cells[4], "Unknown", regular(13.0), p.faint),
                            };
                            widgets::text_in(ui, cells[5], &fmt::ago(now, d.first_seen), regular(13.0), p.muted);
                            ui.interact(cells[5], ui.id().with((&key, "first")), Sense::hover())
                                .on_hover_text(fmt::date_time(d.first_seen, offset));
                            next = 6;
                        }
                        widgets::text_in(ui, cells[next], &fmt::ago(now, d.last_seen), regular(13.0), p.muted);
                        ui.interact(cells[next], ui.id().with((&key, "last")), Sense::hover())
                            .on_hover_text(format!(
                                "Last seen {}, first seen {}",
                                fmt::date_time(d.last_seen, offset),
                                fmt::date_time(d.first_seen, offset)
                            ));
                        // Actions
                        let cell = cells[last];
                        let slot = |i: f32| {
                            Rect::from_center_size(
                                pos2(cell.left() + 15.0 + 31.0 * i, cell.center().y),
                                vec2(29.0, 29.0),
                            )
                        };
                        if icon_at(
                            ui,
                            slot(0.0),
                            (&key, "star"),
                            if d.known { Icon::STAR_FILLED } else { Icon::STAR },
                            if d.known { p.warn } else { p.faint },
                            true,
                            if d.known {
                                "Known device. Click to remove the mark."
                            } else {
                                "Mark as known: a device you recognise and trust"
                            },
                        )
                        .clicked()
                        {
                            actions.push(RowAction::Star(key.clone(), !d.known));
                        }
                        if icon_at(ui, slot(1.0), (&key, "edit"), Icon::EDIT, p.muted, true, "Give this device a name")
                            .clicked()
                        {
                            let current = if d.label.trim().is_empty() {
                                d.name.clone().unwrap_or_default()
                            } else {
                                d.label.clone()
                            };
                            actions.push(RowAction::Rename(key.clone(), current));
                        }
                        if icon_at(
                            ui,
                            slot(2.0),
                            (&key, "forget"),
                            Icon::DELETE,
                            p.muted,
                            true,
                            "Forget this device (it comes back when a scan sees it again)",
                        )
                        .clicked()
                        {
                            actions.push(RowAction::Forget(key.clone()));
                        }
                    }
                });
        });

        for action in actions {
            match action {
                RowAction::Star(key, known) => {
                    self.book.set_known(&key, known);
                    self.save(app);
                }
                RowAction::Rename(key, text) => {
                    self.rename = Some(Rename {
                        key,
                        text,
                        focused: false,
                    });
                }
                RowAction::Commit => {
                    if let Some(r) = self.rename.take() {
                        self.book.set_label(&r.key, r.text.trim());
                        self.save(app);
                    }
                }
                RowAction::CancelRename => self.rename = None,
                RowAction::Forget(key) => {
                    let Some(d) = self.book.devices.iter().find(|d| device_key(d) == key) else {
                        continue;
                    };
                    let mut lines = vec![format!("{} at {}", display_name(d), d.last_ip)];
                    if !d.mac.is_empty() {
                        lines.push(format!("MAC address {}", d.mac));
                    }
                    app.ask(Confirm {
                        title: "Forget this device?".into(),
                        intro: "The device, its name and its history are removed from WireForge's \
                                list. Nothing changes on the network: if the device is still there, \
                                the next scan lists it again as new."
                            .into(),
                        lines,
                        button: "Forget".into(),
                        danger: true,
                        tag: format!("devices.forget:{key}"),
                    });
                }
            }
        }
    }

    /// What a scan does, its switches and its progress.
    fn scan_card(&mut self, app: &mut App, ui: &mut Ui) {
        let p = pal(ui);
        let progress = match (&self.scan, self.demo_progress) {
            (Some(s), _) => Some((
                s.done.load(Ordering::Relaxed),
                s.total.load(Ordering::Relaxed),
            )),
            (None, demo) => demo,
        };
        let online = self.book.devices.iter().filter(|d| d.online).count();
        widgets::card(ui, |ui| {
            widgets::columns_weighted(ui, &[2.1, 1.0], |col, ui| {
                if col == 0 {
                    ui.add(
                        egui::Label::new(
                            RichText::new(
                                "A scan asks each address on your own network who is there, like the \
                                 device list in a router. It never looks outside your local network \
                                 and sends nothing to the internet.",
                            )
                            .size(13.0)
                            .color(p.muted),
                        )
                        .wrap(),
                    );
                    ui.add_space(2.0);
                    match progress {
                        Some((done, total)) => {
                            let (fraction, text) = progress_text(done, total);
                            charts::meter_bar(ui, fraction, p.accent, 8.0);
                            ui.label(RichText::new(text).font(semibold(13.0)));
                        }
                        None => {
                            let line = match self.scanned_at {
                                Some(t) => format!(
                                    "Last scan {}: {online} {} online.",
                                    fmt::ago(app.now, t),
                                    if online == 1 { "device" } else { "devices" }
                                ),
                                None => "No scan yet since WireForge started.".to_string(),
                            };
                            ui.label(RichText::new(line).font(semibold(13.0)));
                        }
                    }
                } else {
                    let row = |ui: &mut Ui, on: bool, label: &str, tip: &str| -> bool {
                        let mut clicked = false;
                        ui.horizontal(|ui| {
                            clicked = widgets::toggle(ui, on, true).on_hover_text(tip).clicked();
                            ui.add(egui::Label::new(RichText::new(label).size(13.5)).truncate())
                                .on_hover_text(tip);
                        });
                        clicked
                    };
                    ui.add_space(2.0);
                    if row(
                        ui,
                        self.resolve_names,
                        "Look up device names",
                        "Asks the devices found for their names (mDNS, NetBIOS and SSDP). This sends \
                         small queries on the local network only.",
                    ) {
                        self.resolve_names = !self.resolve_names;
                    }
                    ui.add_space(2.0);
                    if row(
                        ui,
                        app.settings.devices_auto_scan,
                        "Scan every 10 minutes",
                        "Repeats the scan every ten minutes while WireForge runs, so a new device \
                         is noticed soon after it joins.",
                    ) {
                        app.settings.devices_auto_scan = !app.settings.devices_auto_scan;
                        app.save_settings();
                        self.timer = Some(Instant::now());
                    }
                }
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(ip: &str, mac: &str) -> KnownDevice {
        KnownDevice {
            mac: mac.into(),
            last_ip: ip.into(),
            online: true,
            ..Default::default()
        }
    }

    #[test]
    fn ip_addresses_sort_numerically() {
        assert!(ip_number("192.168.1.9") < ip_number("192.168.1.10"));
        assert!(ip_number("192.168.1.200") < ip_number("192.168.2.1"));
        assert_eq!(ip_number("not an address"), u32::MAX);
        assert_eq!(ip_number(""), u32::MAX);
        let mut list = vec![
            dev("192.168.1.100", "A"),
            dev("192.168.1.9", "B"),
            dev("", "C"),
            dev("192.168.1.23", "D"),
        ];
        sort_devices(&mut list, (DevSort::Ip, true));
        let ips: Vec<&str> = list.iter().map(|d| d.last_ip.as_str()).collect();
        assert_eq!(
            ips,
            vec!["192.168.1.9", "192.168.1.23", "192.168.1.100", ""]
        );
        sort_devices(&mut list, (DevSort::Ip, false));
        assert_eq!(list[1].last_ip, "192.168.1.100");
    }

    #[test]
    fn names_fall_back_in_order() {
        let mut d = dev("192.168.1.5", "AA:BB:CC:00:00:01");
        assert_eq!(display_name(&d), "Unknown device");
        d.vendor = Some("Northwind Devices".into());
        assert_eq!(display_name(&d), "Northwind Devices device");
        d.name = Some("attic-storage".into());
        assert_eq!(display_name(&d), "attic-storage");
        d.label = "  Attic box ".into();
        assert_eq!(display_name(&d), "Attic box");
        d.label = "   ".into();
        assert_eq!(display_name(&d), "attic-storage");
        assert_eq!(device_key(&d), "AA:BB:CC:00:00:01");
        d.mac.clear();
        assert_eq!(device_key(&d), "192.168.1.5");
    }

    #[test]
    fn kinds_are_guessed() {
        let base = dev("192.168.1.5", "AA:BB:CC:00:00:01");
        let with = |f: &dyn Fn(&mut KnownDevice)| {
            let mut d = base.clone();
            f(&mut d);
            device_kind(&d)
        };
        assert_eq!(device_kind(&base), DeviceKind::Generic);
        assert_eq!(with(&|d| d.is_self = true), DeviceKind::ThisPc);
        assert_eq!(with(&|d| d.is_gateway = true), DeviceKind::Router);
        // This PC wins over being the gateway (internet sharing).
        assert_eq!(
            with(&|d| {
                d.is_self = true;
                d.is_gateway = true
            }),
            DeviceKind::ThisPc
        );
        assert_eq!(
            with(&|d| d.kind_hint = Some("printer".into())),
            DeviceKind::Printer
        );
        assert_eq!(
            with(&|d| d.kind_hint = Some("_ipp._tcp".into())),
            DeviceKind::Printer
        );
        assert_eq!(with(&|d| d.label = "Living-room TV".into()), DeviceKind::Tv);
        assert_eq!(
            with(&|d| d.kind_hint = Some("MediaRenderer".into())),
            DeviceKind::Tv
        );
        assert_eq!(
            with(&|d| d.name = Some("sams-phone".into())),
            DeviceKind::Phone
        );
        assert_eq!(with(&|d| d.random_mac = true), DeviceKind::Phone);
        assert_eq!(
            with(&|d| d.name_source = Some("NetBIOS".into())),
            DeviceKind::Computer
        );
        assert_eq!(
            with(&|d| d.name = Some("ALEX-LAPTOP".into())),
            DeviceKind::Computer
        );
        // "tv" must be a word of its own, not part of another word.
        assert_eq!(
            with(&|d| d.name = Some("outvoice".into())),
            DeviceKind::Generic
        );
        assert_eq!(DeviceKind::Printer.word(), "Printer");
        assert!(DeviceKind::Tv.icon() == Icon::TV);
    }

    #[test]
    fn filters_and_counts() {
        let mut a = dev("192.168.1.2", "AA:00:00:00:00:01");
        a.known = true;
        let mut b = dev("192.168.1.3", "AA:00:00:00:00:02");
        b.online = false;
        let c = dev("192.168.1.4", "aa:00:00:00:00:03");
        let mut me = dev("192.168.1.9", "AA:00:00:00:00:09");
        me.is_self = true;
        let fresh: HashSet<String> = [
            "AA:00:00:00:00:03".to_string(),
            "AA:00:00:00:00:01".to_string(),
        ]
        .into_iter()
        .collect();
        let list = vec![a.clone(), b.clone(), c.clone(), me.clone()];
        assert_eq!(filter_counts(&list, &fresh), [4, 3, 1, 2]);
        assert!(is_new(&c, &fresh));
        assert!(!is_new(&a, &fresh), "marked as known");
        assert!(!is_new(&b, &fresh));
        assert!(
            !device_matches(&me, DevFilter::Unknown, "", &fresh),
            "this PC is never unknown"
        );
        assert!(device_matches(&b, DevFilter::All, "00:02", &fresh));
        assert!(device_matches(&b, DevFilter::All, "1.3", &fresh));
        assert!(!device_matches(&b, DevFilter::Online, "", &fresh));
        assert!(device_matches(&c, DevFilter::New, "unknown", &fresh));
        assert!(!device_matches(&c, DevFilter::New, "printer", &fresh));
    }

    #[test]
    fn sorting_by_name_and_dates() {
        let mut a = dev("192.168.1.9", "A");
        a.label = "zebra".into();
        a.first_seen = 10;
        let mut b = dev("192.168.1.3", "B");
        b.name = Some("Apple-tree".into());
        b.first_seen = 30;
        let mut c = dev("192.168.1.5", "C");
        c.first_seen = 20;
        let mut list = vec![a, b, c];
        sort_devices(&mut list, (DevSort::Name, true));
        assert_eq!(
            list.iter().map(display_name).collect::<Vec<_>>(),
            vec!["Apple-tree", "Unknown device", "zebra"]
        );
        sort_devices(&mut list, (DevSort::First, false));
        assert_eq!(
            list.iter().map(|d| d.first_seen).collect::<Vec<_>>(),
            vec![30, 20, 10]
        );
        sort_devices(&mut list, (DevSort::Vendor, true));
        // No vendors: falls back to the IP address.
        assert_eq!(list[0].last_ip, "192.168.1.3");
    }

    #[test]
    fn subtitles() {
        assert_eq!(
            devices_subtitle(Some(("192.168.50.0/24", "Wi-Fi")), 12, 10, true),
            "Network 192.168.50.0/24 on Wi-Fi. 10 of 12 devices online in the last scan."
        );
        assert_eq!(
            devices_subtitle(Some(("10.0.0.0/24", "")), 1, 1, true),
            "Network 10.0.0.0/24. 1 of 1 device online in the last scan."
        );
        assert_eq!(
            devices_subtitle(Some(("10.0.0.0/24", "Ethernet")), 3, 0, false),
            "Network 10.0.0.0/24 on Ethernet. 3 devices remembered from earlier scans."
        );
        assert_eq!(
            devices_subtitle(None, 0, 0, false),
            "Not connected to a network. Not scanned yet."
        );
    }

    #[test]
    fn alerts_summarise() {
        let mut named = dev("192.168.1.7", "AA:00:00:00:00:07");
        named.name = Some("Hallway printer".into());
        let bare = dev("192.168.1.8", "AA:00:00:00:00:08");
        let mut third = dev("192.168.1.9", "AA:00:00:00:00:09");
        third.vendor = Some("Bluepine Labs".into());
        let book = DeviceBook {
            devices: vec![named, bare, third],
        };
        assert_eq!(new_device_alert(&book, &[]), None);
        assert_eq!(new_device_alert(&book, &["FF:FF:FF:FF:FF:FF".into()]), None);
        assert_eq!(
            new_device_alert(&book, &["aa:00:00:00:00:07".into()]).unwrap(),
            "Hallway printer joined at 192.168.1.7"
        );
        // Nothing known about it: the address identifies it.
        assert_eq!(
            new_device_alert(&book, &["AA:00:00:00:00:08".into()]).unwrap(),
            "AA:00:00:00:00:08 joined at 192.168.1.8"
        );
        let all: Vec<String> = book.devices.iter().map(|d| d.mac.clone()).collect();
        assert!(new_device_alert(&book, &all[..2])
            .unwrap()
            .starts_with("2 new devices joined: "));
        assert_eq!(
            new_device_alert(&book, &all).unwrap(),
            "3 new devices joined: Hallway printer, AA:00:00:00:00:08 and 1 more"
        );
    }

    #[test]
    fn export_table_shape() {
        let mut d = dev("192.168.1.7", "AA:00:00:00:00:07");
        d.first_seen = 0;
        d.last_seen = 86_400;
        d.rtt_ms = Some(3);
        let fresh: HashSet<String> = [d.mac.clone()].into_iter().collect();
        let t = devices_table(&[d], &fresh, 0);
        assert_eq!(t.rows.len(), 1);
        assert_eq!(t.rows[0].len(), t.columns.len());
        assert_eq!(t.rows[0][0], "Unknown device");
        assert_eq!(t.rows[0][2], "Online");
        assert_eq!(t.rows[0][10], "Yes");
        assert_eq!(t.rows[0][11], "1970-01-01 00:00");
        assert_eq!(t.rows[0][13], "3");
    }

    #[test]
    fn progress_sentences() {
        assert_eq!(progress_text(0, 0), (0.0, "Starting the scan".to_string()));
        let (f, text) = progress_text(152, 254);
        assert!((f - 0.598).abs() < 0.01);
        assert_eq!(text, "152 of 254 addresses checked");
        let (f, text) = progress_text(300, 254);
        assert_eq!(f, 1.0);
        assert!(text.starts_with("All 254 addresses checked"));
    }

    #[test]
    fn demo_page() {
        let dir = std::path::Path::new("Z:\\nowhere");
        let page = DevicesPage::new(true, "devices", dir);
        assert_eq!(page.book.devices.len(), 12);
        assert_eq!(page.count(), Some(10));
        assert!(!page.scanning());
        let counts = filter_counts(&page.book.devices, &page.fresh);
        assert_eq!(counts[2], 1, "one new device");
        let me = page.book.devices.iter().find(|d| d.is_self).unwrap();
        assert_eq!(
            (me.last_ip.as_str(), me.mac.as_str()),
            ("192.168.50.23", "3C:9A:77:2B:19:5C")
        );
        assert_eq!(device_kind(me), DeviceKind::ThisPc);
        assert!(page.book.devices.iter().any(|d| d.random_mac));
        let scan = DevicesPage::new(true, "devices-scan", dir);
        assert!(scan.scanning());
        assert_eq!(scan.demo_progress, Some((152, 254)));
    }
}
