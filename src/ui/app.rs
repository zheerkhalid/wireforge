//! Application state, background work plumbing and the window frame
//! (header, navigation rail, dialogs, toasts).
//!
//! Each page lives in its own file as `impl App { fn <page>_ui(..) }` with its
//! own state struct stored in a field here.

use super::theme::{self, pal_ctx, regular, semibold, Icon};
use super::widgets;
use super::{
    apps_view::AppsPage, connections_view::ConnectionsPage, devices_view::DevicesPage,
    firewall_view::FirewallPage, overview::OverviewPage, saved_view::SavedPage,
    speed_view::SpeedPage, tools_view::ToolsPage, wifi_view::WifiPage,
};
use crate::fmt::{self, Units};
use crate::settings::{self, Settings};
use crate::sys::{self, MeterFeed, SysEvent, SysWindow};
use crate::{demo, export};
use eframe::egui::{
    self, vec2, Align, Align2, Color32, CornerRadius, Frame, Key, Layout, Margin, Rect, RichText,
    Sense, Stroke, TextureHandle, Ui,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};
use wf_traffic::monitor::{Monitor, MonitorConfig};
use wf_traffic::usage::UsageDb;
use wf_traffic::{AdapterInfo, AdapterKind, Connection, IconImage, Snapshot};
use wf_wifi::Link;

/// How the app was started.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Show invented data and never touch the network or the disk.
    pub demo: bool,
    /// Render one frame of the chosen view to this PNG, then exit.
    pub screenshot: Option<PathBuf>,
    /// Which page / panel to open first (see `--help`).
    pub view: Option<String>,
    /// Force the light theme (for screenshots).
    pub light: bool,
    /// Start hidden in the tray (used by the startup entry).
    pub minimized: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Overview,
    Apps,
    Connections,
    Firewall,
    Wifi,
    Saved,
    Devices,
    Tools,
    Speed,
    Settings,
}

/// Messages from the background poller to the UI.
pub enum Msg {
    Adapters(Vec<AdapterInfo>),
    Connections(Result<Vec<Connection>, String>),
    Link(Option<Link>),
    Icon(String, Option<IconImage>),
    PublicIp(Result<String, String>),
}

/// A yes / no question. When the user agrees, `tag` becomes available through
/// [`App::confirmed`] so the page that asked can act on it.
pub struct Confirm {
    pub title: String,
    pub intro: String,
    pub lines: Vec<String>,
    pub button: String,
    /// Red button (destructive or state-changing) instead of the accent colour.
    pub danger: bool,
    pub tag: String,
}

pub struct Toast {
    pub text: String,
    pub error: bool,
    pub born: Instant,
}

struct Shot {
    path: PathBuf,
    frames: u32,
    requested: bool,
}

/// What the poller thread should be fetching, set by the UI each frame.
pub struct PollFlags {
    pub stop: AtomicBool,
    /// 1 = the Connections page is open.
    pub want_connections: AtomicU8,
    pub connections_now: AtomicBool,
}

pub struct App {
    pub(super) demo: bool,
    pub(super) elevated: bool,
    pub(super) settings: Settings,
    /// `%LOCALAPPDATA%\WireForge`; never written to in demo mode.
    pub(super) data_dir: PathBuf,
    pub(super) tab: Tab,
    /// Unix time and local UTC offset, refreshed every frame.
    pub(super) now: i64,
    pub(super) offset: i64,

    pub(super) monitor: Option<Arc<Monitor>>,
    pub(super) snap: Snapshot,
    snap_at: Option<Instant>,
    pub(super) usage: UsageDb,
    usage_at: Option<Instant>,
    pub(super) adapters: Vec<AdapterInfo>,
    /// The current Wi-Fi association (refreshed every two seconds).
    pub(super) link: Option<Link>,
    /// Signal of the current association in dBm, one sample per two seconds,
    /// oldest first, at most 300; `NaN` while not connected.
    pub(super) signal_history: Vec<f64>,
    pub(super) connections: Vec<Connection>,
    pub(super) connections_error: Option<String>,
    pub(super) connections_at: Option<Instant>,
    pub(super) public_ip: Option<Result<String, String>>,
    pub(super) public_ip_busy: bool,

    pub(super) overview: OverviewPage,
    pub(super) apps: AppsPage,
    pub(super) conns: ConnectionsPage,
    pub(super) wifi: WifiPage,
    pub(super) saved: SavedPage,
    pub(super) devices: DevicesPage,
    pub(super) tools: ToolsPage,
    pub(super) speed: SpeedPage,
    pub(super) fw: FirewallPage,

    icons: HashMap<String, Option<TextureHandle>>,
    icon_tx: Option<Sender<(String, String)>>,
    pub(super) poll: Arc<PollFlags>,

    confirm: Option<Confirm>,
    confirmed: Option<String>,
    pub(super) about_open: bool,
    toasts: Vec<Toast>,

    pub(super) tx: Sender<Msg>,
    rx: Receiver<Msg>,
    sys_rx: Receiver<SysEvent>,
    sys: Option<SysWindow>,
    main_window: isize,
    pub(super) logo: Option<TextureHandle>,
    shot: Option<Shot>,
    exiting: bool,
    /// Frames left during which the window is hidden again (start minimized).
    hide_frames: u8,
}

/// Starts the window.
pub fn run(options: Options, icon: egui::IconData) -> eframe::Result<()> {
    let viewport = egui::ViewportBuilder::default()
        .with_title(if options.demo {
            "WireForge (demo)"
        } else {
            "WireForge"
        })
        .with_inner_size([1280.0, 800.0])
        .with_min_inner_size([1040.0, 660.0])
        // Started by the startup entry: stay out of sight until the tray icon is used.
        .with_visible(!starts_hidden(&options))
        .with_icon(icon.clone());
    let native = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "WireForge",
        native,
        Box::new(move |cc| Ok(Box::new(App::new(cc, options, icon)))),
    )
}

/// `--minimized` only hides the window when there is a tray icon to bring it back.
fn starts_hidden(options: &Options) -> bool {
    options.minimized
        && !options.demo
        && options.screenshot.is_none()
        && Settings::load(&settings::data_dir()).tray_icon
}

fn window_handle(cc: &eframe::CreationContext<'_>) -> isize {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match cc.window_handle().map(|h| h.as_raw()) {
        Ok(RawWindowHandle::Win32(h)) => h.hwnd.get(),
        _ => 0,
    }
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, options: Options, icon: egui::IconData) -> Self {
        let ctx = &cc.egui_ctx;
        theme::install(ctx);
        let demo = options.demo;
        // Nothing is read from or written to this folder in demo mode; an
        // invented path keeps the real user name out of screenshots.
        let data_dir = if demo {
            PathBuf::from("C:\\Users\\Alex\\AppData\\Local\\WireForge")
        } else {
            settings::data_dir()
        };
        let mut settings = if demo {
            Settings::default()
        } else {
            Settings::load(&data_dir)
        };
        if options.light {
            settings.theme = settings::ThemeChoice::Light;
        }
        theme::apply_choice(ctx, settings.theme);

        let logo = (icon.width > 0).then(|| {
            let image = egui::ColorImage::from_rgba_unmultiplied(
                [icon.width as usize, icon.height as usize],
                &icon.rgba,
            );
            ctx.load_texture("logo", image, egui::TextureOptions::LINEAR)
        });
        let (tx, rx) = channel();
        let (sys_tx, sys_rx) = channel();
        let elevated = if demo { true } else { sys::is_elevated() };
        let now = sys::now_unix();
        let offset = sys::utc_offset();
        let view = options.view.clone().unwrap_or_default();
        let poll = Arc::new(PollFlags {
            stop: AtomicBool::new(false),
            want_connections: AtomicU8::new(0),
            connections_now: AtomicBool::new(false),
        });

        let monitor = (!demo).then(|| {
            Arc::new(Monitor::start(MonitorConfig {
                data_dir: Some(data_dir.clone()),
                per_app: settings.per_app,
                resolve_hosts: settings.resolve_hosts,
                keep_days: settings.keep_days,
            }))
        });

        let main_window = window_handle(cc);
        let mut sys_window = None;
        let mut icon_tx = None;
        if !demo && options.screenshot.is_none() {
            let wake = ctx.clone();
            let monitor_for_sys = monitor.clone();
            let units = Arc::new(AtomicU8::new(units_code(settings.units)));
            UNITS.get_or_init(|| units.clone());
            sys_window = SysWindow::start(
                main_window,
                sys_tx,
                Box::new(move || wake.request_repaint()),
                Box::new(move || {
                    // Runs on the tray thread once per second, also while the
                    // main window is hidden.
                    let units = if units.load(Ordering::Relaxed) == 1 {
                        Units::Bits
                    } else {
                        Units::Bytes
                    };
                    match &monitor_for_sys {
                        Some(m) => {
                            let s = m.snapshot();
                            MeterFeed {
                                down: fmt::rate(s.rate.down, units),
                                up: fmt::rate(s.rate.up, units),
                            }
                        }
                        None => MeterFeed::default(),
                    }
                }),
            );
            if let Some(s) = &sys_window {
                s.set_tray(settings.tray_icon);
                if settings.mini_meter {
                    s.set_meter(true, settings.meter_pos);
                }
            }
            icon_tx = Some(spawn_icon_worker(tx.clone(), ctx.clone()));
            spawn_poller(tx.clone(), ctx.clone(), poll.clone());
        }

        let mut app = App {
            demo,
            elevated,
            data_dir: data_dir.clone(),
            tab: Tab::Overview,
            now,
            offset,
            monitor,
            snap: if demo {
                demo::snapshot(now)
            } else {
                Snapshot::default()
            },
            snap_at: None,
            usage: if demo {
                demo::usage()
            } else {
                UsageDb::default()
            },
            usage_at: None,
            adapters: if demo {
                demo::adapters(now)
            } else {
                Vec::new()
            },
            link: demo.then(demo::link),
            signal_history: if demo {
                demo::signal_history()
            } else {
                Vec::new()
            },
            connections: if demo {
                demo::connections(now)
            } else {
                Vec::new()
            },
            connections_error: None,
            connections_at: None,
            public_ip: None,
            public_ip_busy: false,
            overview: OverviewPage::default(),
            apps: AppsPage::default(),
            conns: ConnectionsPage::default(),
            wifi: WifiPage::new(demo, &view),
            saved: SavedPage::new(demo, &view),
            devices: DevicesPage::new(demo, &view, &data_dir),
            tools: ToolsPage::new(demo, &view),
            speed: SpeedPage::new(demo, &view, &data_dir),
            fw: FirewallPage::new(demo, &view, &data_dir, now),
            icons: HashMap::new(),
            icon_tx,
            poll,
            confirm: None,
            confirmed: None,
            about_open: false,
            toasts: Vec::new(),
            tx,
            rx,
            sys_rx,
            sys: sys_window,
            main_window,
            logo,
            shot: options.screenshot.clone().map(|path| Shot {
                path,
                frames: 0,
                requested: false,
            }),
            exiting: false,
            hide_frames: if starts_hidden(&options) { 3 } else { 0 },
            settings,
        };
        app.apply_view(&view);
        app
    }

    /// Opens the page / panel named on the command line.
    fn apply_view(&mut self, view: &str) {
        let page = view.split('-').next().unwrap_or("");
        self.tab = match page {
            "apps" | "usage" => Tab::Apps,
            "connections" => Tab::Connections,
            "firewall" => Tab::Firewall,
            "wifi" => Tab::Wifi,
            "saved" => Tab::Saved,
            "devices" => Tab::Devices,
            "tools" => Tab::Tools,
            "speed" => Tab::Speed,
            "settings" => Tab::Settings,
            _ => Tab::Overview,
        };
        match view {
            "about" => self.about_open = true,
            "usage" | "apps-usage" => self.apps.show_usage(),
            "apps-details" => self.apps.select_first(&self.snap),
            "overview-ip" if self.demo => {
                self.public_ip = Some(Ok(demo::PUBLIC_IP.to_string()));
            }
            _ => {}
        }
    }

    // ----------------------------------------------------------------------------------
    // Services for the pages
    // ----------------------------------------------------------------------------------

    pub(super) fn toast(&mut self, text: impl Into<String>, error: bool) {
        self.toasts.push(Toast {
            text: text.into(),
            error,
            born: Instant::now(),
        });
    }

    /// A toast, plus a balloon from the tray icon when the window is hidden.
    pub(super) fn alert(&mut self, title: &str, text: &str) {
        self.toast(format!("{title}: {text}"), false);
        if let Some(s) = &self.sys {
            s.notify(title, text);
        }
    }

    /// A balloon from the tray icon (no toast).
    pub(super) fn notify(&mut self, title: &str, text: &str) {
        if let Some(s) = &self.sys {
            s.notify(title, text);
        }
    }

    /// Asks a yes / no question; see [`Confirm`].
    pub(super) fn ask(&mut self, confirm: Confirm) {
        self.confirm = Some(confirm);
    }

    /// True once, right after the user agreed to the question with this tag.
    pub(super) fn confirmed(&mut self, tag: &str) -> bool {
        if self.confirmed.as_deref() == Some(tag) {
            self.confirmed = None;
            true
        } else {
            false
        }
    }

    /// Like [`App::confirmed`] for a family of tags (`"devices.forget:"` + id):
    /// returns the part after the prefix.
    pub(super) fn confirmed_prefix(&mut self, prefix: &str) -> Option<String> {
        let rest = self
            .confirmed
            .as_deref()
            .and_then(|t| t.strip_prefix(prefix))
            .map(str::to_string)?;
        self.confirmed = None;
        Some(rest)
    }

    /// True while a screenshot is being taken: pages should not animate.
    pub(super) fn still(&self) -> bool {
        self.shot.is_some()
    }

    pub(super) fn units(&self) -> Units {
        self.settings.units
    }

    pub(super) fn save_settings(&mut self) {
        if let Some(u) = UNITS.get() {
            u.store(units_code(self.settings.units), Ordering::Relaxed);
        }
        if self.demo {
            return;
        }
        if let Err(e) = self.settings.save(&self.data_dir) {
            self.toast(e, true);
        }
    }

    /// Copies text to the clipboard and says so.
    pub(super) fn copy(&mut self, ctx: &egui::Context, text: &str, what: &str) {
        ctx.copy_text(text.to_string());
        self.toast(format!("{what} copied"), false);
    }

    /// Saves tables through the system "Save as" dialog (CSV, HTML or JSON).
    pub(super) fn export(&mut self, tables: &[export::Table], heading: &str, file_name: &str) {
        if self.still() {
            return;
        }
        match export::save_with_dialog(tables, heading, file_name) {
            Ok(Some(path)) => self.toast(format!("Saved {}", path.display()), false),
            Ok(None) => {}
            Err(e) => self.toast(e, true),
        }
    }

    /// The adapter that carries the default route (or the first one that is up).
    pub(super) fn primary_adapter(&self) -> Option<&AdapterInfo> {
        self.adapters
            .iter()
            .find(|a| a.is_default && a.up)
            .or_else(|| {
                self.adapters.iter().find(|a| {
                    a.up && a.physical
                        && !a.ipv4.is_empty()
                        && !matches!(a.kind, AdapterKind::Loopback | AdapterKind::Virtual)
                })
            })
    }

    /// The icon of a program, loaded in the background the first time it is asked for.
    pub(super) fn icon(&mut self, name: &str, path: &str) -> Option<TextureHandle> {
        if let Some(found) = self.icons.get(name) {
            return found.clone();
        }
        self.icons.insert(name.to_string(), None);
        if !path.is_empty() {
            if let Some(tx) = &self.icon_tx {
                let _ = tx.send((name.to_string(), path.to_string()));
            }
        }
        None
    }

    pub(super) fn restart_elevated(&mut self, ctx: &egui::Context) {
        if self.demo {
            self.toast("Demo mode: nothing is restarted.", false);
            return;
        }
        if let Some(m) = &self.monitor {
            m.flush();
        }
        match sys::restart_as_admin() {
            Ok(()) => {
                self.exiting = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Err(e) => self.toast(e, true),
        }
    }

    pub(super) fn fetch_public_ip(&mut self, ctx: &egui::Context) {
        if self.demo {
            self.public_ip = Some(Ok(demo::PUBLIC_IP.to_string()));
            return;
        }
        if self.public_ip_busy {
            return;
        }
        self.public_ip_busy = true;
        let (tx, c) = (self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let _ = tx.send(Msg::PublicIp(wf_tools::publicip::fetch()));
            c.request_repaint();
        });
    }

    pub(super) fn apply_tray_settings(&mut self) {
        if let Some(s) = &self.sys {
            s.set_tray(self.settings.tray_icon);
            s.set_meter(self.settings.mini_meter, self.settings.meter_pos);
        }
    }

    // ----------------------------------------------------------------------------------
    // Per-frame housekeeping
    // ----------------------------------------------------------------------------------

    fn refresh(&mut self, ctx: &egui::Context) {
        self.now = sys::now_unix();
        self.poll.want_connections.store(
            u8::from(
                (self.tab == Tab::Connections && !self.conns.paused)
                    || (self.settings.fw_alerts && !self.demo),
            ),
            Ordering::Relaxed,
        );
        let Some(monitor) = self.monitor.clone() else {
            return;
        };
        if self
            .snap_at
            .map(|t| t.elapsed() >= Duration::from_millis(500))
            .unwrap_or(true)
        {
            self.snap = monitor.snapshot();
            self.snap_at = Some(Instant::now());
        }
        if self
            .usage_at
            .map(|t| t.elapsed() >= Duration::from_secs(15))
            .unwrap_or(true)
        {
            self.usage = monitor.usage();
            self.usage_at = Some(Instant::now());
            self.offset = sys::utc_offset();
            self.check_cap();
        }
        // Keep the numbers moving without burning CPU.
        ctx.request_repaint_after(Duration::from_millis(500));
    }

    /// The data-allowance alerts: once per billing period each.
    fn check_cap(&mut self) {
        if !self.settings.cap_enabled || !self.settings.alert_cap {
            return;
        }
        let today = wf_traffic::Day::today();
        let (from, to) = wf_traffic::usage::cycle_range(today, self.settings.cap_start_day);
        let used = self.usage.range_total(from, to).sum();
        let status = wf_traffic::usage::cap_status(
            used,
            self.settings.cap_bytes(),
            self.settings.cap_warn_pct as f64 / 100.0,
        );
        let period = from.iso();
        if status.exceeded && self.settings.cap_exceeded_period != period {
            self.settings.cap_exceeded_period = period;
            self.save_settings();
            self.alert(
                "Data allowance used up",
                &format!(
                    "{} of {} used in this period.",
                    fmt::bytes(status.used),
                    fmt::bytes(status.cap)
                ),
            );
        } else if status.warn && !status.exceeded && self.settings.cap_warned_period != period {
            self.settings.cap_warned_period = period;
            self.save_settings();
            self.alert(
                "Data allowance",
                &format!(
                    "{:.0} % used: {} of {}.",
                    status.fraction * 100.0,
                    fmt::bytes(status.used),
                    fmt::bytes(status.cap)
                ),
            );
        }
    }

    fn drain_messages(&mut self, ctx: &egui::Context) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Adapters(list) => self.adapters = list,
                Msg::Connections(Ok(list)) => {
                    self.connections = list;
                    self.connections_error = None;
                    self.connections_at = Some(Instant::now());
                    self.fw_observe();
                }
                Msg::Connections(Err(e)) => self.connections_error = Some(e),
                Msg::Link(link) => {
                    self.signal_history
                        .push(link.as_ref().map(|l| l.rssi_dbm as f64).unwrap_or(f64::NAN));
                    if self.signal_history.len() > 300 {
                        let extra = self.signal_history.len() - 300;
                        self.signal_history.drain(..extra);
                    }
                    self.link = link;
                }
                Msg::Icon(name, image) => {
                    let tex = image.filter(|i| i.width > 0 && i.height > 0).map(|img| {
                        let image = egui::ColorImage::from_rgba_unmultiplied(
                            [img.width as usize, img.height as usize],
                            &img.rgba,
                        );
                        ctx.load_texture(
                            format!("icon:{name}"),
                            image,
                            egui::TextureOptions::LINEAR,
                        )
                    });
                    self.icons.insert(name, tex);
                }
                Msg::PublicIp(result) => {
                    self.public_ip_busy = false;
                    self.public_ip = Some(result);
                }
            }
        }
        while let Ok(event) = self.sys_rx.try_recv() {
            match event {
                SysEvent::Shown => {}
                SysEvent::Exit => {
                    self.exiting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                SysEvent::MeterToggled(on) => {
                    self.settings.mini_meter = on;
                    self.save_settings();
                }
                SysEvent::MeterMoved(x, y) => {
                    self.settings.meter_pos = Some((x, y));
                    self.save_settings();
                }
            }
        }
    }

    fn handle_keys(&mut self, ctx: &egui::Context) {
        let escape = ctx.input(|i| i.key_pressed(Key::Escape));
        if escape {
            if self.confirm.is_some() {
                self.confirm = None;
            } else if self.fw.dialog.is_some() {
                self.fw.dialog = None;
            } else if self.about_open {
                self.about_open = false;
            }
        }
    }

    fn handle_close(&mut self, ctx: &egui::Context) {
        if self.hide_frames > 0 {
            self.hide_frames -= 1;
            sys::hide_window(self.main_window);
        }
        if ctx.input(|i| i.viewport().close_requested())
            && !self.exiting
            && self.settings.close_to_tray
            && self.settings.tray_icon
            && self.sys.is_some()
            && self.shot.is_none()
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            sys::hide_window(self.main_window);
        }
    }

    fn handle_screenshot(&mut self, ctx: &egui::Context) {
        let Some(shot) = &mut self.shot else { return };
        ctx.request_repaint();
        shot.frames += 1;
        if shot.frames == 1 {
            ctx.set_pixels_per_point(1.0);
        }
        if shot.frames == 3 {
            // Now that one point is one pixel, this gives an exact 1280 x 800 image.
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(vec2(1280.0, 800.0)));
        }
        let image = ctx.input(|i| {
            i.events.iter().find_map(|e| match e {
                egui::Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        if let Some(image) = image {
            let [w, h] = image.size;
            if let Some(parent) = shot.path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let result = image::save_buffer(
                &shot.path,
                image.as_raw(),
                w as u32,
                h as u32,
                image::ColorType::Rgba8,
            );
            if let Err(e) = result {
                eprintln!("screenshot failed: {e}");
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            self.shot = None;
            return;
        }
        if !shot.requested && shot.frames > 40 {
            shot.requested = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
        }
    }

    // ----------------------------------------------------------------------------------
    // Frame: header and navigation
    // ----------------------------------------------------------------------------------

    fn header(&mut self, ctx: &egui::Context) {
        let p = pal_ctx(ctx);
        egui::TopBottomPanel::top("header")
            .exact_height(64.0)
            .frame(
                Frame::new()
                    .fill(p.rail)
                    .inner_margin(Margin::symmetric(18, 0)),
            )
            .show(ctx, |ui| {
                let full = ui.max_rect();
                ui.painter().hline(
                    full.x_range().expand(18.0),
                    full.bottom(),
                    Stroke::new(1.0_f32, p.border),
                );
                ui.horizontal_centered(|ui| {
                    // Brand
                    let (rect, _) = ui.allocate_exact_size(vec2(32.0, 32.0), Sense::hover());
                    if let Some(logo) = &self.logo {
                        ui.painter().image(
                            logo.id(),
                            rect,
                            Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                            Color32::WHITE,
                        );
                    }
                    ui.add_space(2.0);
                    ui.label(RichText::new("WireForge").font(semibold(19.0)));
                    if self.demo {
                        widgets::badge(ui, "DEMO", p.info).on_hover_text(
                            "Invented data. Nothing on this PC or network is read or changed.",
                        );
                    }
                    ui.add_space(196.0 - ui.min_rect().width().min(196.0));

                    // Live rates
                    let units = self.units();
                    let rate = self.snap.rate;
                    let (pill, pill_resp) =
                        ui.allocate_exact_size(vec2(248.0, 36.0), Sense::hover());
                    ui.painter().rect(
                        pill,
                        CornerRadius::same(10),
                        if p.dark { p.card } else { p.bg },
                        Stroke::new(1.0_f32, p.border),
                        egui::StrokeKind::Inside,
                    );
                    for (i, (icon, color, value)) in [
                        (Icon::DOWNLOAD, p.down, rate.down),
                        (Icon::UPLOAD, p.up, rate.up),
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        let x = pill.left() + 14.0 + 118.0 * i as f32;
                        ui.painter().text(
                            egui::pos2(x, pill.center().y),
                            Align2::LEFT_CENTER,
                            icon.glyph(),
                            regular(13.0),
                            color,
                        );
                        let r = Rect::from_min_max(
                            egui::pos2(x + 20.0, pill.top()),
                            egui::pos2(x + 112.0, pill.bottom()),
                        );
                        widgets::text_in(ui, r, &fmt::rate(value, units), semibold(14.0), p.text);
                    }
                    pill_resp.on_hover_text(
                        "Download and upload rate right now, over all physical adapters.",
                    );

                    // Right side: privacy, elevation, About
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::icon_button(ui, Icon::INFO, "About WireForge").clicked() {
                            self.about_open = true;
                        }
                        ui.add_space(6.0);
                        if self.fw.lockdown_on() {
                            // Always visible while lockdown is on, on every page.
                            if widgets::danger_button(ui, "End lockdown", self.fw.busy.is_none())
                                .on_hover_text(
                                    "Lockdown blocks every outgoing connection except allowed programs. Ending it restores the previous settings exactly.",
                                )
                                .clicked()
                            {
                                self.fw_request(
                                    ctx,
                                    wf_firewall::cli::FwCommand::LockdownOff,
                                    "Ending lockdown".into(),
                                );
                            }
                            widgets::badge(ui, &Icon::LOCK.with("Lockdown on"), p.danger);
                            ui.add_space(6.0);
                        }
                        if self.elevated {
                            widgets::badge(ui, &Icon::SHIELD.with("Administrator"), p.accent)
                                .on_hover_text(
                                    "WireForge runs with administrator rights: bytes are counted \
                                     per app and Wi-Fi passwords saved for all users can be shown.",
                                );
                        } else {
                            if widgets::ghost_button(ui, "Restart as administrator")
                                .on_hover_text(
                                    "Needed to count bytes per app and to show Wi-Fi passwords \
                                     that were saved for all users. Everything else works without.",
                                )
                                .clicked()
                            {
                                self.restart_elevated(ctx);
                            }
                            widgets::badge(ui, "Standard rights", p.muted);
                        }
                        widgets::badge(ui, &Icon::LOCK.with("Stays on this PC"), p.good)
                            .on_hover_text(
                                "WireForge keeps everything on this PC. It only contacts the \
                                 internet when you start a speed test, ask for your public IP \
                                 address or run one of the tools.",
                            );
                    });
                });
            });
    }

    fn rail(&mut self, ctx: &egui::Context) {
        let p = pal_ctx(ctx);
        egui::SidePanel::left("rail")
            .exact_width(208.0)
            .resizable(false)
            .frame(
                Frame::new()
                    .fill(p.rail)
                    .inner_margin(Margin::symmetric(10, 14)),
            )
            .show(ctx, |ui| {
                let full = ui.max_rect();
                ui.painter().vline(
                    full.right() + 10.0,
                    full.y_range().expand(14.0),
                    Stroke::new(1.0_f32, p.border),
                );
                ui.spacing_mut().item_spacing.y = 4.0;
                let items: [(Tab, Icon, &str, Option<usize>); 10] = [
                    (Tab::Overview, Icon::HOME, "Overview", None),
                    (Tab::Apps, Icon::APPS, "Apps", Some(self.snap.apps.len())),
                    (
                        Tab::Connections,
                        Icon::CONNECTIONS,
                        "Connections",
                        (!self.connections.is_empty()).then_some(self.connections.len()),
                    ),
                    (Tab::Firewall, Icon::SHIELD, "Firewall", self.fw.count()),
                    (Tab::Wifi, Icon::WIFI, "Wi-Fi", self.wifi.count()),
                    (Tab::Saved, Icon::KEY, "Saved networks", self.saved.count()),
                    (Tab::Devices, Icon::DEVICES, "Devices", self.devices.count()),
                    (Tab::Tools, Icon::TOOLS, "Tools", None),
                    (Tab::Speed, Icon::SPEED, "Speed test", None),
                    (Tab::Settings, Icon::SETTINGS, "Settings", None),
                ];
                for (tab, icon, label, count) in items {
                    if matches!(tab, Tab::Settings | Tab::Wifi | Tab::Tools) {
                        ui.add_space(6.0);
                        widgets::divider(ui);
                        ui.add_space(6.0);
                    }
                    let active = self.tab == tab;
                    let (rect, resp) =
                        ui.allocate_exact_size(vec2(ui.available_width(), 40.0), Sense::click());
                    if active {
                        ui.painter()
                            .rect_filled(rect, CornerRadius::same(9), p.selected);
                        let bar = Rect::from_min_size(
                            rect.left_center() - vec2(0.0, 9.0),
                            vec2(3.0, 18.0),
                        );
                        ui.painter()
                            .rect_filled(bar, CornerRadius::same(2), p.accent);
                    } else if resp.hovered() {
                        ui.painter()
                            .rect_filled(rect, CornerRadius::same(9), p.hover);
                    }
                    let fg = if active { p.text } else { p.muted };
                    ui.painter().text(
                        rect.left_center() + vec2(24.0, 0.0),
                        Align2::CENTER_CENTER,
                        icon.glyph(),
                        regular(16.0),
                        if active { p.accent } else { fg },
                    );
                    ui.painter().text(
                        rect.left_center() + vec2(46.0, -1.0),
                        Align2::LEFT_CENTER,
                        label,
                        if active {
                            semibold(14.5)
                        } else {
                            regular(14.5)
                        },
                        fg,
                    );
                    if let Some(n) = count {
                        ui.painter().text(
                            rect.right_center() - vec2(12.0, 1.0),
                            Align2::RIGHT_CENTER,
                            n.to_string(),
                            regular(12.5),
                            p.faint,
                        );
                    }
                    if resp.clicked() {
                        self.tab = tab;
                    }
                }
                ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.add_space(12.0);
                        ui.label(
                            RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION")))
                                .size(12.0)
                                .color(p.faint),
                        );
                    });
                });
            });
    }

    // ----------------------------------------------------------------------------------
    // Dialogs and toasts
    // ----------------------------------------------------------------------------------

    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(confirm) = &self.confirm else { return };
        let p = pal_ctx(ctx);
        let mut decision: Option<bool> = None;
        let modal = egui::Modal::new(egui::Id::new("confirm"))
            .frame(widgets::modal_frame(&p))
            .show(ctx, |ui| {
                ui.set_width(500.0);
                ui.label(RichText::new(&confirm.title).font(semibold(19.0)));
                ui.add_space(2.0);
                ui.add(egui::Label::new(RichText::new(&confirm.intro).color(p.muted)).wrap());
                if !confirm.lines.is_empty() {
                    ui.add_space(6.0);
                    Frame::new()
                        .fill(p.bg)
                        .corner_radius(CornerRadius::same(10))
                        .inner_margin(Margin::same(12))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            egui::ScrollArea::vertical()
                                .max_height(220.0)
                                .show(ui, |ui| {
                                    for line in &confirm.lines {
                                        ui.horizontal_top(|ui| {
                                            ui.label(RichText::new("\u{2022}").color(
                                                if confirm.danger { p.danger } else { p.accent },
                                            ));
                                            ui.add(egui::Label::new(line.as_str()).wrap());
                                        });
                                    }
                                });
                        });
                }
                ui.add_space(12.0);
                widgets::button_row(ui, |ui| {
                    let yes = if confirm.danger {
                        widgets::danger_button(ui, &confirm.button, true)
                    } else {
                        widgets::primary_button(ui, &confirm.button, true)
                    };
                    if yes.clicked() {
                        decision = Some(true);
                    }
                    if widgets::ghost_button(ui, "Cancel").clicked() {
                        decision = Some(false);
                    }
                });
            });
        if modal.should_close() && decision.is_none() {
            decision = Some(false);
        }
        match decision {
            Some(true) => {
                if let Some(c) = self.confirm.take() {
                    self.confirmed = Some(c.tag);
                }
            }
            Some(false) => self.confirm = None,
            None => {}
        }
    }

    fn toasts_ui(&mut self, ctx: &egui::Context) {
        self.toasts
            .retain(|t| t.born.elapsed().as_secs_f32() < if t.error { 8.0 } else { 3.5 });
        if self.toasts.is_empty() {
            return;
        }
        ctx.request_repaint_after(Duration::from_millis(250));
        let p = pal_ctx(ctx);
        egui::Area::new(egui::Id::new("toasts"))
            .anchor(Align2::RIGHT_BOTTOM, vec2(-18.0, -18.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                ui.with_layout(Layout::bottom_up(Align::Max), |ui| {
                    for t in self.toasts.iter().rev().take(4) {
                        let color = if t.error { p.danger } else { p.accent };
                        Frame::new()
                            .fill(p.card)
                            .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.7)))
                            .corner_radius(CornerRadius::same(10))
                            .inner_margin(Margin::symmetric(14, 10))
                            .show(ui, |ui| {
                                ui.set_max_width(420.0);
                                ui.horizontal(|ui| {
                                    let icon = if t.error { Icon::ERROR } else { Icon::DONE };
                                    ui.label(RichText::new(icon.glyph()).color(color));
                                    ui.add(egui::Label::new(t.text.as_str()).wrap());
                                });
                            });
                    }
                });
            });
    }

    /// A page body that scrolls vertically.
    pub(super) fn scroll(ui: &mut Ui, id: &str, add: impl FnOnce(&mut Ui)) {
        egui::ScrollArea::vertical()
            .id_salt(id)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // Room for the floating scroll bar.
                ui.set_width(ui.available_width() - 6.0);
                add(ui);
                ui.add_space(8.0);
            });
    }
}

static UNITS: std::sync::OnceLock<Arc<AtomicU8>> = std::sync::OnceLock::new();

fn units_code(units: Units) -> u8 {
    match units {
        Units::Bytes => 0,
        Units::Bits => 1,
    }
}

/// Loads program icons off the UI thread.
fn spawn_icon_worker(tx: Sender<Msg>, ctx: egui::Context) -> Sender<(String, String)> {
    let (req_tx, req_rx) = channel::<(String, String)>();
    std::thread::spawn(move || {
        while let Ok((name, path)) = req_rx.recv() {
            let image = wf_traffic::procs::exe_icon(&path, 32);
            if tx.send(Msg::Icon(name, image)).is_err() {
                break;
            }
            ctx.request_repaint();
        }
    });
    req_tx
}

/// Fetches the slower inventory data in the background: adapters every five
/// seconds, the Wi-Fi link every two, connections every two while that page
/// is open. None of this sends anything on the network.
fn spawn_poller(tx: Sender<Msg>, ctx: egui::Context, flags: Arc<PollFlags>) {
    std::thread::spawn(move || {
        let mut tick: u64 = 0;
        let mut wifi_guid: Option<String> = None;
        while !flags.stop.load(Ordering::Relaxed) {
            let mut changed = false;
            if tick.is_multiple_of(10) {
                if let Ok(list) = wf_traffic::adapters::list_adapters() {
                    wifi_guid = list
                        .iter()
                        .filter(|a| a.kind == AdapterKind::WiFi)
                        .max_by_key(|a| (a.up, a.is_default))
                        .map(|a| a.guid.clone());
                    if tx.send(Msg::Adapters(list)).is_err() {
                        return;
                    }
                    changed = true;
                }
            }
            if tick.is_multiple_of(4) {
                if let Some(guid) = &wifi_guid {
                    let link = wf_wifi::wlan::current_link(guid).ok().flatten();
                    if tx.send(Msg::Link(link)).is_err() {
                        return;
                    }
                    changed = true;
                }
            }
            let now = flags.connections_now.swap(false, Ordering::Relaxed);
            if now || (tick % 4 == 1 && flags.want_connections.load(Ordering::Relaxed) == 1) {
                let result = wf_traffic::connections::list_connections();
                if tx.send(Msg::Connections(result)).is_err() {
                    return;
                }
                changed = true;
            }
            if changed {
                ctx.request_repaint();
            }
            tick += 1;
            std::thread::sleep(Duration::from_millis(500));
        }
    });
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_messages(ctx);
        self.refresh(ctx);
        self.handle_keys(ctx);
        self.handle_close(ctx);
        self.handle_screenshot(ctx);
        // Pages may have background results to pick up even when not shown.
        self.wifi_poll(ctx);
        self.saved_poll(ctx);
        self.devices_poll(ctx);
        self.tools_poll(ctx);
        self.speed_poll(ctx);
        self.firewall_poll(ctx);

        self.header(ctx);
        self.rail(ctx);

        let p = pal_ctx(ctx);
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(p.bg)
                    .inner_margin(Margin::symmetric(24, 18)),
            )
            .show(ctx, |ui| match self.tab {
                Tab::Overview => self.overview_ui(ui),
                Tab::Apps => self.apps_ui(ui),
                Tab::Connections => self.connections_ui(ui),
                Tab::Firewall => self.firewall_ui(ui),
                Tab::Wifi => self.wifi_ui(ui),
                Tab::Saved => self.saved_ui(ui),
                Tab::Devices => self.devices_ui(ui),
                Tab::Tools => self.tools_ui(ui),
                Tab::Speed => self.speed_ui(ui),
                Tab::Settings => self.settings_ui(ui),
            });

        self.fw_dialogs(ctx);
        self.confirm_dialog(ctx);
        self.about_dialog(ctx);
        self.fw_alerts_ui(ctx);
        self.toasts_ui(ctx);
    }

    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        // Screenshots must not depend on where the mouse happens to be:
        // no hover highlights, no tooltips.
        if self.shot.is_some() {
            raw_input.events.retain(|e| {
                !matches!(
                    e,
                    egui::Event::PointerMoved(_)
                        | egui::Event::MouseMoved(_)
                        | egui::Event::PointerButton { .. }
                        | egui::Event::MouseWheel { .. }
                )
            });
            raw_input.events.push(egui::Event::PointerGone);
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.poll.stop.store(true, Ordering::SeqCst);
        self.devices_exit();
        self.tools_exit();
        self.speed_exit();
        if let Some(m) = &self.monitor {
            m.flush();
        }
        // Dropping the tray window removes the icon and the meter.
        self.sys = None;
    }
}
