//! Speed test: an opt-in measurement against an outside service, with the
//! service named on the page, a consent step before the first run, a polite
//! pause between runs and a history kept on this PC.

use super::app::{App, Confirm};
use super::charts::{self, LineChart, Series};
use super::theme::{pal, pal_ctx, regular, semibold, Icon};
use super::widgets::{self, Col};
use crate::export::Table;
use crate::fmt;
use eframe::egui::{self, vec2, RichText, Sense, Ui};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Instant;
use wf_tools::speedtest;
use wf_tools::{ProviderInfo, SpeedPhase, SpeedProgress, SpeedResult};

/// After a test the Start button rests for this long.
const COOLDOWN_SECS: f64 = 30.0;

const HISTORY_FILE: &str = "speedtest.json";

enum SpeedMsg {
    Progress(SpeedProgress),
    Done(Result<SpeedResult, String>),
}

/// State of this page.
pub struct SpeedPage {
    /// Oldest first.
    history: Vec<SpeedResult>,
    path: PathBuf,
    /// The demo history is written on the first frame, when the clock is known.
    seeded: bool,
    running: bool,
    /// A frozen "running" picture for the demo screenshot.
    staged: bool,
    progress: SpeedProgress,
    /// The last reading of latency, download and upload in this run.
    seen: [Option<f64>; 3],
    cancel: Arc<AtomicBool>,
    rx: Option<Receiver<SpeedMsg>>,
    adapter_at_start: String,
    error: Option<String>,
    finished_at: Option<Instant>,
    consent_open: bool,
}

impl SpeedPage {
    pub fn new(demo: bool, view: &str, data_dir: &Path) -> Self {
        let path = data_dir.join(HISTORY_FILE);
        let history = if demo {
            Vec::new()
        } else {
            speedtest::load_history(&path)
        };
        let staged = demo && view == "speed-running";
        let progress = if staged {
            crate::demo::tools::speed_progress()
        } else {
            SpeedProgress::default()
        };
        SpeedPage {
            history,
            path,
            seeded: false,
            running: staged,
            staged,
            seen: if staged {
                [Some(12.4), Some(progress.current), None]
            } else {
                [None; 3]
            },
            progress,
            cancel: Arc::new(AtomicBool::new(false)),
            rx: None,
            adapter_at_start: String::new(),
            error: None,
            finished_at: None,
            consent_open: view == "speed-consent",
        }
    }

    fn cooldown(&self) -> u64 {
        cooldown_left(self.finished_at.map(|t| t.elapsed().as_secs_f64()))
    }
}

// --------------------------------------------------------------------------------------
// Pure helpers (unit-tested)
// --------------------------------------------------------------------------------------

/// Whole seconds until the Start button works again; `elapsed` is the time
/// since the last test ended (`None` = no test yet).
fn cooldown_left(elapsed: Option<f64>) -> u64 {
    match elapsed {
        Some(e) if (0.0..COOLDOWN_SECS).contains(&e) => (COOLDOWN_SECS - e).ceil() as u64,
        _ => 0,
    }
}

/// Whether a click on Start may begin a test.
fn can_start(running: bool, cooldown: u64) -> bool {
    !running && cooldown == 0
}

/// `8.42`, `48.3`, `248`: a rate in Mbit/s without its unit.
fn mbps_number(v: f64) -> String {
    let v = v.max(0.0);
    if v >= 100.0 {
        format!("{v:.0}")
    } else if v >= 10.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.2}")
    }
}

fn mbps_text(v: f64) -> String {
    format!("{} Mbit/s", mbps_number(v))
}

fn ms_number(v: f64) -> String {
    let v = v.max(0.0);
    if v >= 100.0 {
        format!("{v:.0}")
    } else {
        format!("{v:.1}")
    }
}

/// Where a rate sits on the gauge: a logarithmic scale from 0 to 10 Gbit/s,
/// so a slow line and a very fast one both move the needle visibly.
fn gauge_fraction(mbps: f64) -> f32 {
    if !mbps.is_finite() || mbps <= 0.0 {
        return 0.0;
    }
    (((1.0 + mbps).log10()) / 4.0).clamp(0.0, 1.0) as f32
}

/// What a result means in everyday terms.
fn plain_reading(download_mbps: f64, upload_mbps: f64, latency_ms: f64) -> String {
    let what = if download_mbps < 1.0 {
        "Very slow: only email and plain web pages will work well."
    } else if download_mbps < 5.0 {
        "Enough for web pages, email and music. Video will often pause to load."
    } else if download_mbps < 25.0 {
        "Good for HD streaming on one or two screens."
    } else if download_mbps < 100.0 {
        "Good for 4K streaming and several people online at once."
    } else if download_mbps < 500.0 {
        "Fast: good for 4K streaming on many screens and for large downloads."
    } else {
        "Very fast: more than almost any household needs."
    };
    let calls = if upload_mbps < 1.0 {
        "Video calls will struggle because the upload is slow."
    } else if latency_ms > 150.0 {
        "Video calls and games may lag because the response time is long."
    } else if upload_mbps < 3.0 {
        "Video calls work, but your own picture may look soft."
    } else {
        "Video calls will work well."
    };
    format!("{what} {calls}")
}

fn phase_title(phase: SpeedPhase) -> &'static str {
    match phase {
        SpeedPhase::Locating => "Finding a server",
        SpeedPhase::Latency => "Latency",
        SpeedPhase::Download => "Download",
        SpeedPhase::Upload => "Upload",
        SpeedPhase::Done => "Done",
    }
}

fn phase_index(phase: SpeedPhase) -> usize {
    match phase {
        SpeedPhase::Locating => 0,
        SpeedPhase::Latency => 1,
        SpeedPhase::Download => 2,
        SpeedPhase::Upload => 3,
        SpeedPhase::Done => 4,
    }
}

/// The history as an export table, newest first.
fn history_table(history: &[SpeedResult], offset: i64) -> Table {
    let mut t = Table::new(
        "Speed test history",
        &[
            "Time",
            "Download (Mbit/s)",
            "Upload (Mbit/s)",
            "Latency (ms)",
            "Jitter (ms)",
            "Server",
            "Adapter",
            "Service",
        ],
    );
    for r in history.iter().rev() {
        t.push(vec![
            fmt::date_time(r.when_unix, offset),
            format!("{:.2}", r.download_mbps),
            format!("{:.2}", r.upload_mbps),
            format!("{:.1}", r.latency_ms),
            format!("{:.1}", r.jitter_ms),
            r.server.clone(),
            r.adapter.clone(),
            r.provider.clone(),
        ]);
    }
    t
}

/// The cells of one row of the on-screen history table.
fn history_cells(r: &SpeedResult, offset: i64) -> [String; 7] {
    [
        fmt::date_time(r.when_unix, offset),
        mbps_text(r.download_mbps),
        mbps_text(r.upload_mbps),
        format!("{} ms", ms_number(r.latency_ms)),
        format!("{} ms", ms_number(r.jitter_ms)),
        r.server.clone(),
        r.adapter.clone(),
    ]
}

// --------------------------------------------------------------------------------------
// The page
// --------------------------------------------------------------------------------------

enum Act {
    Start,
    Stop,
    Withdraw,
    Open(&'static str),
    Clear,
    Export,
}

const HISTORY_COLS: [Col; 7] = [
    Col::fixed("Time", 124.0),
    Col::right("Download", 96.0),
    Col::right("Upload", 92.0),
    Col::right("Latency", 66.0),
    Col::right("Jitter", 60.0),
    Col::flex("Server", 1.2),
    Col::flex("Adapter", 1.0),
];

fn link(ui: &mut Ui, text: &str, hover: &str) -> bool {
    let p = pal(ui);
    let r = ui.add(egui::Link::new(
        RichText::new(text).size(13.0).color(p.accent).underline(),
    ));
    if hover.is_empty() {
        r.clicked()
    } else {
        r.on_hover_text(hover).clicked()
    }
}

fn provider_card(
    ui: &mut Ui,
    info: &ProviderInfo,
    consent: bool,
    runs_today: usize,
) -> Option<Act> {
    let p = pal(ui);
    let mut act = None;
    widgets::titled_card(
        ui,
        &format!("Measured by {}", info.name),
        |ui| {
            widgets::badge(ui, "Outside service", p.info).on_hover_text(
                "The test is run by this service, not by WireForge. Nothing is sent until \
                 you press Start test.",
            );
        },
        |ui| {
            ui.label(
                RichText::new(format!("Run by {}", info.operator))
                    .size(13.0)
                    .color(p.muted),
            );
            ui.add_space(2.0);
            ui.add(egui::Label::new(RichText::new(info.notice).size(13.0).color(p.text)).wrap());
            ui.add(
                egui::Label::new(RichText::new(info.data_note).size(13.0).color(p.muted)).wrap(),
            );
            ui.add_space(2.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 16.0;
                if link(ui, "About the service", info.homepage) {
                    act = Some(Act::Open(info.homepage));
                }
                if link(ui, "Terms of use", info.terms_url) {
                    act = Some(Act::Open(info.terms_url));
                }
                if link(ui, "Privacy policy", info.privacy_url) {
                    act = Some(Act::Open(info.privacy_url));
                }
                if consent
                    && link(
                        ui,
                        "Withdraw agreement",
                        "You will be asked again before the next test. Results already \
                         published by the service are not removed by this.",
                    )
                {
                    act = Some(Act::Withdraw);
                }
                ui.label(
                    RichText::new(format!(
                        "Tests in the last 24 hours: {runs_today} of {}",
                        speedtest::DAILY_LIMIT
                    ))
                    .size(12.5)
                    .color(p.faint),
                );
            });
        },
    );
    act
}

fn running_card(ui: &mut Ui, progress: &SpeedProgress, seen: &[Option<f64>; 3]) {
    let p = pal(ui);
    widgets::titled_card(
        ui,
        "Test in progress",
        |ui| {
            let server = if progress.server.is_empty() {
                "Server not chosen yet".to_string()
            } else {
                format!("Server: {}", progress.server)
            };
            ui.label(RichText::new(server).size(12.5).color(p.muted));
        },
        |ui| {
            ui.horizontal(|ui| {
                let (fraction, color, value, caption) = match progress.phase {
                    SpeedPhase::Locating => (0.0, p.faint, "...".to_string(), "Finding a server"),
                    SpeedPhase::Latency => (
                        progress.fraction,
                        p.third,
                        ms_number(progress.current),
                        "ms latency",
                    ),
                    SpeedPhase::Download => (
                        gauge_fraction(progress.current),
                        p.down,
                        mbps_number(progress.current),
                        "Mbit/s download",
                    ),
                    SpeedPhase::Upload => (
                        gauge_fraction(progress.current),
                        p.up,
                        mbps_number(progress.current),
                        "Mbit/s upload",
                    ),
                    SpeedPhase::Done => (1.0, p.good, "Done".to_string(), "Saving the result"),
                };
                ui.add_space(8.0);
                charts::gauge(ui, 210.0, fraction, color, &value, caption);
                ui.add_space(24.0);
                ui.vertical(|ui| {
                    ui.add_space(14.0);
                    let current = phase_index(progress.phase);
                    let steps = [
                        (SpeedPhase::Locating, String::new()),
                        (
                            SpeedPhase::Latency,
                            seen[0]
                                .map(|v| format!("{} ms", ms_number(v)))
                                .unwrap_or_default(),
                        ),
                        (
                            SpeedPhase::Download,
                            seen[1].map(mbps_text).unwrap_or_default(),
                        ),
                        (
                            SpeedPhase::Upload,
                            seen[2].map(mbps_text).unwrap_or_default(),
                        ),
                    ];
                    for (i, (phase, value)) in steps.iter().enumerate() {
                        let (rect, _) = ui
                            .allocate_exact_size(vec2(ui.available_width(), 28.0), Sense::hover());
                        let (icon, icon_color, text_color) = if i < current {
                            (Icon::CHECK, p.good, p.muted)
                        } else if i == current {
                            (Icon::PLAY, p.accent, p.text)
                        } else {
                            (Icon::CLOCK, p.faint, p.faint)
                        };
                        ui.painter().text(
                            egui::pos2(rect.left() + 8.0, rect.center().y),
                            egui::Align2::CENTER_CENTER,
                            icon.glyph(),
                            regular(13.0),
                            icon_color,
                        );
                        let state = if i < current {
                            "done"
                        } else if i == current {
                            "now"
                        } else {
                            "waiting"
                        };
                        let label = egui::Rect::from_min_max(
                            egui::pos2(rect.left() + 26.0, rect.top()),
                            egui::pos2(rect.left() + 190.0, rect.bottom()),
                        );
                        let font = if i == current {
                            semibold(14.0)
                        } else {
                            regular(14.0)
                        };
                        widgets::text_in(ui, label, phase_title(*phase), font, text_color);
                        let right = egui::Rect::from_min_max(
                            egui::pos2(rect.left() + 196.0, rect.top()),
                            rect.max,
                        );
                        let shown = if value.is_empty() || i > current {
                            state.to_string()
                        } else {
                            value.clone()
                        };
                        widgets::text_in(
                            ui,
                            right,
                            &shown,
                            regular(13.0),
                            if i == current { p.text } else { p.faint },
                        );
                    }
                    ui.add_space(8.0);
                    charts::meter_bar(ui, progress.fraction, p.accent, 6.0);
                    ui.label(
                        RichText::new(format!(
                            "{}: {:.0} % of this step",
                            phase_title(progress.phase),
                            (progress.fraction.clamp(0.0, 1.0) * 100.0)
                        ))
                        .size(12.5)
                        .color(p.muted),
                    );
                });
            });
        },
    );
}

fn result_card(ui: &mut Ui, r: &SpeedResult, now: i64, offset: i64) {
    let p = pal(ui);
    widgets::titled_card(
        ui,
        "Last result",
        |ui| {
            ui.label(
                RichText::new(format!(
                    "{} ({})",
                    fmt::date_time(r.when_unix, offset),
                    fmt::ago(now, r.when_unix)
                ))
                .size(12.5)
                .color(p.muted),
            );
        },
        |ui| {
            ui.add_space(4.0);
            widgets::columns_n(ui, 4, |i, ui| match i {
                0 => charts::stat(ui, "Download", &mbps_number(r.download_mbps), "Mbit/s"),
                1 => charts::stat(ui, "Upload", &mbps_number(r.upload_mbps), "Mbit/s"),
                2 => charts::stat(
                    ui,
                    "Latency",
                    &ms_number(r.latency_ms),
                    "ms, the response time",
                ),
                _ => charts::stat(
                    ui,
                    "Jitter",
                    &ms_number(r.jitter_ms),
                    "ms, how much it varies",
                ),
            });
            ui.add_space(6.0);
            widgets::divider(ui);
            ui.add_space(2.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(Icon::INFO.glyph()).size(13.0).color(p.info));
                ui.label(
                    RichText::new(plain_reading(r.download_mbps, r.upload_mbps, r.latency_ms))
                        .size(13.5),
                );
            });
            let mut where_from = format!("Server: {}", r.server);
            if !r.adapter.is_empty() {
                where_from.push_str(&format!("   Measured over: {}", r.adapter));
            }
            if !r.provider.is_empty() {
                where_from.push_str(&format!("   Service: {}", r.provider));
            }
            ui.label(RichText::new(where_from).size(12.5).color(p.faint));
        },
    );
}

fn history_chart(ui: &mut Ui, history: &[SpeedResult], offset: i64) {
    let p = pal(ui);
    let down: Vec<f64> = history.iter().map(|r| r.download_mbps).collect();
    let up: Vec<f64> = history.iter().map(|r| r.upload_mbps).collect();
    let series = [
        Series {
            name: "Download",
            values: &down,
            color: p.down,
            fill: false,
        },
        Series {
            name: "Upload",
            values: &up,
            color: p.up,
            fill: false,
        },
    ];
    let y_fmt = |v: f64| format!("{} Mbit/s", mbps_number(v));
    let x_fmt = |slot: usize, slots: usize| {
        let index = (slot + history.len()).saturating_sub(slots);
        history
            .get(index)
            .map(|r| fmt::date_time(r.when_unix, offset))
            .unwrap_or_default()
    };
    let left = history
        .first()
        .map(|r| fmt::date_time(r.when_unix, offset))
        .unwrap_or_default();
    let right = history
        .last()
        .map(|r| fmt::date_time(r.when_unix, offset))
        .unwrap_or_default();
    let mut chart = LineChart::new(&series, &y_fmt);
    chart.height = 170.0;
    chart.x_left = &left;
    chart.x_right = &right;
    chart.x_fmt = Some(&x_fmt);
    charts::line_chart(ui, &chart);
}

fn history_rows(ui: &mut Ui, history: &[SpeedResult], offset: i64) {
    let p = pal(ui);
    widgets::table_header(ui, &HISTORY_COLS, None);
    let row_h = 40.0;
    // Set before the scroll area: it sizes its rows with this spacing.
    ui.spacing_mut().item_spacing.y = 0.0;
    egui::ScrollArea::vertical()
        .id_salt("speed-history")
        .max_height(row_h * 7.0)
        .min_scrolled_height(row_h * 7.0)
        .auto_shrink([false, true])
        .show_rows(ui, row_h, history.len(), |ui, range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for i in range {
                let Some(r) = history.get(history.len() - 1 - i) else {
                    continue;
                };
                let (cells, _) = widgets::table_row(ui, &HISTORY_COLS, row_h, false);
                let text = history_cells(r, offset);
                for (c, (cell, value)) in cells.iter().zip(text.iter()).enumerate() {
                    let font = regular(13.5);
                    match c {
                        0 => {
                            widgets::text_in(ui, *cell, value, font, p.text);
                        }
                        1..=4 => widgets::text_in_right(
                            ui,
                            *cell,
                            value,
                            font,
                            if c <= 2 { p.text } else { p.muted },
                        ),
                        _ => {
                            widgets::text_in(ui, *cell, value, font, p.muted);
                        }
                    }
                }
            }
        });
}

impl App {
    /// Called every frame, also while another page is shown: pick up results
    /// of background work here.
    pub(super) fn speed_poll(&mut self, ctx: &egui::Context) {
        let _ = ctx;
        if self.demo && !self.speed.seeded {
            self.speed.seeded = true;
            self.speed.history = crate::demo::tools::speed_history(self.now);
        }
        let mut finished: Option<Result<SpeedResult, String>> = None;
        if let Some(rx) = &self.speed.rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    SpeedMsg::Progress(progress) => {
                        let slot = match progress.phase {
                            SpeedPhase::Latency => Some(0),
                            SpeedPhase::Download => Some(1),
                            SpeedPhase::Upload => Some(2),
                            _ => None,
                        };
                        if let Some(slot) = slot {
                            if progress.current > 0.0 {
                                self.speed.seen[slot] = Some(progress.current);
                            }
                        }
                        self.speed.progress = progress;
                    }
                    SpeedMsg::Done(result) => finished = Some(result),
                }
            }
        }
        let Some(result) = finished else { return };
        self.speed.rx = None;
        self.speed.running = false;
        self.speed.finished_at = Some(Instant::now());
        match result {
            Ok(mut r) => {
                if r.when_unix <= 0 {
                    r.when_unix = self.now;
                }
                r.adapter = std::mem::take(&mut self.speed.adapter_at_start);
                let summary = format!(
                    "{} down, {} up",
                    mbps_text(r.download_mbps),
                    mbps_text(r.upload_mbps)
                );
                self.speed.history.push(r);
                self.speed_save_history();
                self.toast(format!("Speed test finished: {summary}"), false);
            }
            Err(e) if e == "Cancelled" => self.toast("Speed test stopped", false),
            Err(e) => self.speed.error = Some(e),
        }
    }

    /// Writes the history on a helper thread (never in demo mode).
    fn speed_save_history(&mut self) {
        if self.demo {
            return;
        }
        let path = self.speed.path.clone();
        let history = self.speed.history.clone();
        std::thread::spawn(move || {
            let _ = speedtest::save_history(&path, &history);
        });
    }

    /// Called when the program closes: stop background work.
    pub(super) fn speed_exit(&mut self) {
        self.speed.cancel.store(true, Ordering::Relaxed);
    }

    /// Starts the measurement. Only reached from a click, after consent.
    fn speed_begin(&mut self, ctx: &egui::Context) {
        if self.demo {
            self.toast("Demo mode: nothing is sent", false);
            return;
        }
        if self.still() || !self.settings.speed_consent {
            return;
        }
        if !can_start(self.speed.running, self.speed.cooldown()) {
            return;
        }
        if let Err(message) = speedtest::check_daily_limit(&self.speed.history, self.now) {
            self.speed.error = Some(message);
            return;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = channel();
        self.speed.cancel = cancel.clone();
        self.speed.rx = Some(rx);
        self.speed.running = true;
        self.speed.error = None;
        self.speed.progress = SpeedProgress::default();
        self.speed.seen = [None; 3];
        self.speed.adapter_at_start = self
            .primary_adapter()
            .map(|a| a.name.clone())
            .unwrap_or_default();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let progress_tx = tx.clone();
            let progress_ctx = ctx.clone();
            let mut on_progress = move |p: &SpeedProgress| {
                let _ = progress_tx.send(SpeedMsg::Progress(p.clone()));
                progress_ctx.request_repaint();
            };
            let result = speedtest::run(&cancel, &mut on_progress);
            let _ = tx.send(SpeedMsg::Done(result));
            ctx.request_repaint();
        });
    }

    pub(super) fn speed_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let cooldown = self.speed.cooldown();
        let running = self.speed.running;
        let consent = self.settings.speed_consent;
        let info = speedtest::provider();
        let mut act: Option<Act> = None;

        widgets::page_header(
            ui,
            "Speed test",
            "Measures download, upload and response time. Nothing is sent until you press Start test.",
            |ui| {
                if running {
                    if widgets::ghost_button(ui, &Icon::STOP.with("Stop")).clicked() {
                        act = Some(Act::Stop);
                    }
                } else {
                    let r = widgets::primary_button(ui, "Start test", can_start(running, cooldown));
                    if r.clicked() {
                        act = Some(Act::Start);
                    }
                    if cooldown > 0 {
                        ui.label(
                            RichText::new(format!("Ready again in {cooldown} s"))
                                .size(12.5)
                                .color(p.muted),
                        )
                        .on_hover_text(
                            "A short pause between tests keeps the load on the free \
                             measurement servers low.",
                        );
                    }
                }
            },
        );
        if cooldown > 0 && !self.still() {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }

        {
            let page = &self.speed;
            let (now, offset) = (self.now, self.offset);
            let runs_today = if self.demo {
                1
            } else {
                speedtest::runs_last_day(&page.history, now)
            };
            App::scroll(ui, "speed", |ui| {
                if let Some(a) = provider_card(ui, &info, consent, runs_today) {
                    act = Some(a);
                }
                ui.add_space(12.0);
                if let Some(error) = &page.error {
                    widgets::notice(ui, Icon::ERROR, p.danger, error);
                    ui.add_space(12.0);
                }
                if page.running {
                    running_card(ui, &page.progress, &page.seen);
                    ui.add_space(12.0);
                } else if let Some(last) = page.history.last() {
                    result_card(ui, last, now, offset);
                    ui.add_space(12.0);
                }
                if page.history.is_empty() {
                    if !page.running {
                        widgets::card(ui, |ui| {
                            ui.set_min_height(220.0);
                            widgets::empty_state(
                                ui,
                                Icon::SPEED,
                                p.accent,
                                "No test yet",
                                "Press Start test to measure your connection. Results are \
                                 kept on this PC so you can see how the speed changes over time.",
                            );
                        });
                    }
                    return;
                }
                widgets::titled_card(
                    ui,
                    "Speed over time",
                    |ui| {
                        ui.label(
                            RichText::new(format!("{} tests", page.history.len()))
                                .size(12.5)
                                .color(p.muted),
                        );
                    },
                    |ui| history_chart(ui, &page.history, offset),
                );
                ui.add_space(12.0);
                widgets::titled_card(
                    ui,
                    "Past results",
                    |ui| {
                        if widgets::ghost_button(ui, &Icon::EXPORT.with("Export")).clicked() {
                            act = Some(Act::Export);
                        }
                        if widgets::ghost_button(ui, "Clear history").clicked() {
                            act = Some(Act::Clear);
                        }
                    },
                    |ui| {
                        ui.add_space(4.0);
                        history_rows(ui, &page.history, offset);
                    },
                );
            });
        }

        match act {
            Some(Act::Start) => {
                if self.demo {
                    self.toast("Demo mode: nothing is sent", false);
                } else if !self.settings.speed_consent {
                    self.speed.consent_open = true;
                } else {
                    self.speed_begin(&ctx);
                }
            }
            Some(Act::Stop) => {
                if self.speed.staged {
                    self.toast("Demo mode: nothing is sent", false);
                } else {
                    self.speed.cancel.store(true, Ordering::Relaxed);
                }
            }
            Some(Act::Withdraw) => {
                if self.demo {
                    self.toast("Demo mode: nothing was changed", false);
                } else {
                    self.settings.speed_consent = false;
                    self.save_settings();
                    self.toast(
                        "Agreement withdrawn. You will be asked again before the next test.",
                        false,
                    );
                }
            }
            Some(Act::Open(url)) => {
                if self.demo {
                    self.toast("Demo mode: links are not opened", false);
                } else if let Err(e) = crate::sys::open_url(url) {
                    self.toast(e, true);
                }
            }
            Some(Act::Clear) => self.ask(Confirm {
                title: "Clear the speed test history?".into(),
                intro: "This removes the results kept on this PC. Results the measurement \
                        service has published are not affected."
                    .into(),
                lines: vec![format!("{} saved results", self.speed.history.len())],
                button: "Clear history".into(),
                danger: true,
                tag: "speed.clear".into(),
            }),
            Some(Act::Export) => {
                let table = history_table(&self.speed.history, self.offset);
                self.export(&[table], "Speed test history", "wireforge-speed-tests");
            }
            None => {}
        }
        if self.confirmed("speed.clear") {
            if self.demo {
                self.toast("Demo mode: nothing was changed", false);
            } else {
                self.speed.history.clear();
                self.speed_save_history();
                self.toast("Speed test history cleared", false);
            }
        }
        self.speed_consent_modal(&ctx, &info);
    }

    fn speed_consent_modal(&mut self, ctx: &egui::Context, info: &ProviderInfo) {
        if !self.speed.consent_open {
            return;
        }
        let p = pal_ctx(ctx);
        let mut agree = false;
        let mut cancel = false;
        let mut open: Option<&'static str> = None;
        let modal = egui::Modal::new(egui::Id::new("speed-consent"))
            .frame(widgets::modal_frame(&p))
            .show(ctx, |ui| {
                ui.set_width(540.0);
                ui.label(RichText::new("Before your first speed test").font(semibold(19.0)));
                ui.add_space(2.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "The test uses {}, run by {}. Please read what that means.",
                            info.name, info.operator
                        ))
                        .color(p.muted),
                    )
                    .wrap(),
                );
                ui.add_space(6.0);
                egui::Frame::new()
                    .fill(p.bg)
                    .corner_radius(egui::CornerRadius::same(10))
                    .inner_margin(egui::Margin::same(12))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(
                            RichText::new("What is sent and what is published")
                                .font(semibold(13.5)),
                        );
                        ui.add(egui::Label::new(RichText::new(info.notice).size(13.5)).wrap());
                        ui.add_space(4.0);
                        ui.label(RichText::new("How much data it uses").font(semibold(13.5)));
                        ui.add(egui::Label::new(RichText::new(info.data_note).size(13.5)).wrap());
                    });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 16.0;
                    if link(ui, "Privacy policy", info.privacy_url) {
                        open = Some(info.privacy_url);
                    }
                    if link(ui, "Terms of use", info.terms_url) {
                        open = Some(info.terms_url);
                    }
                    if link(ui, "About the service", info.homepage) {
                        open = Some(info.homepage);
                    }
                });
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "You are asked once. You can withdraw the agreement on this page \
                             at any time; every test still starts only when you press the button.",
                        )
                        .size(12.5)
                        .color(p.faint),
                    )
                    .wrap(),
                );
                ui.add_space(8.0);
                widgets::button_row(ui, |ui| {
                    if widgets::primary_button(ui, "Agree and start", true).clicked() {
                        agree = true;
                    }
                    if widgets::ghost_button(ui, "Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        if let Some(url) = open {
            if self.demo {
                self.toast("Demo mode: links are not opened", false);
            } else if let Err(e) = crate::sys::open_url(url) {
                self.toast(e, true);
            }
        }
        if agree {
            self.speed.consent_open = false;
            if self.demo {
                self.toast("Demo mode: nothing is sent", false);
            } else {
                self.settings.speed_consent = true;
                self.save_settings();
                self.speed_begin(ctx);
            }
        } else if cancel || modal.should_close() {
            self.speed.consent_open = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(when: i64, down: f64, up: f64) -> SpeedResult {
        SpeedResult {
            when_unix: when,
            provider: "M-Lab NDT7".into(),
            server: "Frankfurt, DE".into(),
            download_mbps: down,
            upload_mbps: up,
            latency_ms: 12.34,
            jitter_ms: 1.26,
            adapter: "Wi-Fi".into(),
            ..Default::default()
        }
    }

    #[test]
    fn cooldown_counts_down_and_ends() {
        assert_eq!(cooldown_left(None), 0);
        assert_eq!(cooldown_left(Some(0.0)), 30);
        assert_eq!(cooldown_left(Some(0.2)), 30);
        assert_eq!(cooldown_left(Some(29.1)), 1);
        assert_eq!(cooldown_left(Some(30.0)), 0);
        assert_eq!(cooldown_left(Some(4000.0)), 0);
        assert_eq!(cooldown_left(Some(-5.0)), 0);
    }

    #[test]
    fn start_needs_idle_and_no_cooldown() {
        assert!(can_start(false, 0));
        assert!(!can_start(true, 0));
        assert!(!can_start(false, 12));
        assert!(!can_start(true, 12));
    }

    #[test]
    fn reading_thresholds() {
        assert!(plain_reading(0.5, 0.2, 40.0).starts_with("Very slow"));
        assert!(plain_reading(3.0, 1.0, 40.0).starts_with("Enough for web pages"));
        assert!(plain_reading(5.0, 5.0, 40.0).starts_with("Good for HD streaming"));
        assert!(plain_reading(24.9, 5.0, 40.0).starts_with("Good for HD streaming"));
        assert!(plain_reading(25.0, 5.0, 40.0).starts_with("Good for 4K streaming"));
        assert!(plain_reading(250.0, 40.0, 12.0).starts_with("Fast:"));
        assert!(plain_reading(940.0, 500.0, 3.0).starts_with("Very fast"));
    }

    #[test]
    fn reading_mentions_calls() {
        assert!(plain_reading(250.0, 40.0, 12.0).ends_with("Video calls will work well."));
        assert!(plain_reading(250.0, 0.5, 12.0).contains("upload is slow"));
        assert!(plain_reading(250.0, 40.0, 400.0).contains("response time is long"));
        assert!(plain_reading(50.0, 2.0, 30.0).contains("may look soft"));
        // No em dashes in user-facing text.
        assert!(!plain_reading(50.0, 2.0, 30.0).contains('\u{2014}'));
    }

    #[test]
    fn numbers() {
        assert_eq!(mbps_number(8.416), "8.42");
        assert_eq!(mbps_number(48.26), "48.3");
        assert_eq!(mbps_number(248.4), "248");
        assert_eq!(mbps_number(-3.0), "0.00");
        assert_eq!(mbps_text(40.0), "40.0 Mbit/s");
        assert_eq!(ms_number(12.34), "12.3");
        assert_eq!(ms_number(212.7), "213");
    }

    #[test]
    fn gauge_scale() {
        assert_eq!(gauge_fraction(0.0), 0.0);
        assert_eq!(gauge_fraction(f64::NAN), 0.0);
        assert!((gauge_fraction(99.0) - 0.5).abs() < 0.001);
        assert!(gauge_fraction(250.0) > 0.55 && gauge_fraction(250.0) < 0.65);
        assert_eq!(gauge_fraction(1e9), 1.0);
        assert!(gauge_fraction(10.0) < gauge_fraction(20.0));
    }

    #[test]
    fn phases_are_ordered() {
        let order = [
            SpeedPhase::Locating,
            SpeedPhase::Latency,
            SpeedPhase::Download,
            SpeedPhase::Upload,
            SpeedPhase::Done,
        ];
        for (i, phase) in order.iter().enumerate() {
            assert_eq!(phase_index(*phase), i);
            assert!(!phase_title(*phase).is_empty());
        }
    }

    #[test]
    fn export_table_is_newest_first() {
        let history = vec![
            result(1_800_000_000, 250.04, 40.0),
            result(1_800_003_600, 121.5, 28.25),
        ];
        let t = history_table(&history, 0);
        assert_eq!(t.columns.len(), 8);
        assert_eq!(t.rows.len(), 2);
        assert!(t.rows.iter().all(|r| r.len() == t.columns.len()));
        assert_eq!(t.rows[0][1], "121.50");
        assert_eq!(t.rows[1][1], "250.04");
        assert_eq!(t.rows[1][3], "12.3");
        assert_eq!(t.rows[0][5], "Frankfurt, DE");
        assert_eq!(t.rows[0][7], "M-Lab NDT7");
        assert!(history_table(&[], 0).rows.is_empty());
    }

    #[test]
    fn screen_cells() {
        let cells = history_cells(&result(1_800_000_000, 250.04, 40.0), 0);
        assert_eq!(cells[1], "250 Mbit/s");
        assert_eq!(cells[2], "40.0 Mbit/s");
        assert_eq!(cells[3], "12.3 ms");
        assert_eq!(cells[6], "Wi-Fi");
        assert_eq!(HISTORY_COLS.len(), cells.len());
    }

    #[test]
    fn demo_page_never_loads_files() {
        let dir = Path::new("Z:\\does-not-exist");
        let page = SpeedPage::new(true, "speed-running", dir);
        assert!(page.running && page.staged && page.history.is_empty());
        assert_eq!(page.progress.phase, SpeedPhase::Download);
        let page = SpeedPage::new(true, "speed-consent", dir);
        assert!(page.consent_open && !page.running);
        let page = SpeedPage::new(true, "speed", dir);
        assert!(!page.consent_open && !page.running);
    }
}
