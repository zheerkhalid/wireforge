//! Firewall page: apps blocked by WireForge (on top of Windows Defender
//! Firewall), the state of each firewall profile, new-app alerts, lockdown
//! mode and the journal of changes. Also the block dialog, the alert
//! pop-ups and the "Block internet access" buttons used on other pages.
//!
//! WireForge itself never runs as administrator for this: every change
//! starts one elevated `WireForge.exe --fw-...` command (one UAC prompt).

use super::app::{App, Confirm, Tab};
use super::theme::{pal, pal_ctx, regular, semibold, Icon};
use super::widgets::{self, Col};
use crate::firewall::{self, FwView};
use crate::fmt;
use eframe::egui::{self, vec2, Align2, RichText, Sense, Ui};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};
use wf_firewall::cli::{Duration as FwDuration, FwCommand};
use wf_firewall::journal::{self, Entry};
use wf_firewall::watch::{Decision, KnownApp, KnownApps, Seen};
use wf_firewall::{
    file_name, naming, same_path, FwAction, Lifetime, MockFirewall, Profile, Profiles,
};

/// The block dialog's duration choices.
const DURATIONS: [&str; 3] = ["For 1 hour", "Until restart", "Always"];

pub enum FwDialog {
    Block {
        path: String,
        duration: usize,
        inbound: bool,
        profiles: Profiles,
    },
    Lockdown {
        /// Candidate programs and whether each is allowed.
        allow: Vec<(String, bool)>,
        agree: bool,
    },
}

enum FwMsg {
    View(Result<FwView, String>),
    Done(Result<String, String>),
}

/// What a menu or button on another page asked for.
pub enum FwAsk {
    Block(String),
    Unblock(String),
    Show(String),
}

pub struct FirewallPage {
    pub view: Option<FwView>,
    pub error: Option<String>,
    read_at: Option<Instant>,
    reading: bool,
    /// The change being made right now (waiting for the UAC prompt / helper).
    pub busy: Option<String>,
    pub search: String,
    pub selected: Option<String>,
    pub dialog: Option<FwDialog>,
    pub known: KnownApps,
    pub journal: Vec<Entry>,
    /// New-app alerts waiting for an answer, oldest first.
    pub alerts: Vec<KnownApp>,
    /// Show the whole known-programs list instead of the first few.
    known_all: bool,
    /// The in-memory firewall of demo mode.
    demo_fw: Option<MockFirewall>,
    tx: Sender<FwMsg>,
    rx: Receiver<FwMsg>,
}

impl FirewallPage {
    pub fn new(demo: bool, view: &str, data_dir: &std::path::Path, now: i64) -> FirewallPage {
        let (tx, rx) = channel();
        let mut page = FirewallPage {
            view: None,
            error: None,
            read_at: None,
            reading: false,
            busy: None,
            search: String::new(),
            selected: None,
            dialog: None,
            known: KnownApps::default(),
            journal: Vec::new(),
            alerts: Vec::new(),
            known_all: false,
            demo_fw: None,
            tx,
            rx,
        };
        if demo {
            let (fw, known, journal) = crate::demo::firewall(now);
            page.view = Some(FwView::from(
                fw.status.clone(),
                fw.rules.clone(),
                now - 7200,
            ));
            page.read_at = Some(Instant::now());
            page.known = known;
            page.journal = journal;
            page.demo_fw = Some(fw);
            match view {
                "firewall" => {
                    page.selected = page
                        .view
                        .as_ref()
                        .and_then(|v| v.blocked.iter().find(|a| a.name == "tunebox.exe"))
                        .map(|a| a.path.clone());
                }
                "firewall-alert" => {
                    page.alerts = page.known.pending().into_iter().cloned().collect();
                }
                "firewall-block" => {
                    page.dialog = Some(FwDialog::Block {
                        path: "C:\\Program Files\\GameHub\\gamehub.exe".into(),
                        duration: 0,
                        inbound: false,
                        profiles: Profiles::ALL,
                    })
                }
                "firewall-lockdown" => {
                    page.dialog = Some(FwDialog::Lockdown {
                        allow: crate::demo::lockdown_candidates(),
                        agree: true,
                    })
                }
                _ => {}
            }
        } else {
            page.known = KnownApps::load(data_dir);
            page.journal = journal::load(data_dir);
        }
        page
    }

    pub fn count(&self) -> Option<usize> {
        self.view
            .as_ref()
            .map(|v| v.blocked.len())
            .filter(|n| *n > 0)
    }

    pub fn lockdown_on(&self) -> bool {
        self.view
            .as_ref()
            .map(|v| v.lockdown.is_some())
            .unwrap_or(false)
    }

    pub fn is_blocked(&self, path: &str) -> bool {
        self.view.as_ref().and_then(|v| v.blocked(path)).is_some()
    }
}

fn duration_cmd(i: usize) -> FwDuration {
    match i {
        0 => FwDuration::Seconds(3600),
        1 => FwDuration::UntilRestart,
        _ => FwDuration::Always,
    }
}

const BLOCK_COLS: [Col; 5] = [
    Col::flex("App", 1.0),
    Col::fixed("Blocks", 104.0),
    Col::fixed("Since", 78.0),
    Col::fixed("Ends", 112.0),
    Col::fixed("", 80.0),
];

impl App {
    // ----------------------------------------------------------------------------------
    // Background work
    // ----------------------------------------------------------------------------------

    fn fw_read(&mut self, ctx: &egui::Context) {
        if self.demo {
            if let Some(fw) = &self.fw.demo_fw {
                let boot = self.fw.view.as_ref().map(|v| v.boot).unwrap_or(self.now);
                self.fw.view = Some(FwView::from(fw.status.clone(), fw.rules.clone(), boot));
            }
            self.fw.read_at = Some(Instant::now());
            return;
        }
        if self.fw.reading {
            return;
        }
        self.fw.reading = true;
        let (tx, c) = (self.fw.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let _ = tx.send(FwMsg::View(firewall::read_view()));
            c.request_repaint();
        });
    }

    /// Picks up results and keeps the view fresh (every 10 s on the page,
    /// every minute elsewhere, so the buttons on other pages stay right).
    pub(super) fn firewall_poll(&mut self, ctx: &egui::Context) {
        while let Ok(msg) = self.fw.rx.try_recv() {
            match msg {
                FwMsg::View(Ok(v)) => {
                    self.fw.view = Some(v);
                    self.fw.error = None;
                    self.fw.reading = false;
                    self.fw.read_at = Some(Instant::now());
                }
                FwMsg::View(Err(e)) => {
                    self.fw.error = Some(e);
                    self.fw.reading = false;
                    self.fw.read_at = Some(Instant::now());
                }
                FwMsg::Done(result) => {
                    self.fw.busy = None;
                    match result {
                        Ok(m) => self.toast(m, false),
                        Err(e) => self.toast(e, true),
                    }
                    self.fw.journal = journal::load(&self.data_dir);
                    self.fw_read(ctx);
                }
            }
        }
        let every = if self.tab == Tab::Firewall { 10 } else { 60 };
        if self.still() {
            return;
        }
        if self
            .fw
            .read_at
            .map(|t| t.elapsed() >= Duration::from_secs(every))
            .unwrap_or(true)
        {
            self.fw_read(ctx);
        }
    }

    /// Runs one firewall change (in demo mode on the invented firewall).
    pub(super) fn fw_request(&mut self, ctx: &egui::Context, command: FwCommand, busy: String) {
        if self.fw.busy.is_some() {
            self.toast("Another firewall change is still in progress.", true);
            return;
        }
        if let Some(fw) = &mut self.fw.demo_fw {
            let boot = self.fw.view.as_ref().map(|v| v.boot).unwrap_or(0);
            match firewall::execute(fw, &command, &self.fw.journal, self.now, boot) {
                Ok((msg, entry)) => {
                    if let Some(e) = entry {
                        let undoes = e.undoes;
                        self.fw.journal.push(e);
                        if let Some(id) = undoes {
                            for j in &mut self.fw.journal {
                                if j.id == id {
                                    j.undone = true;
                                }
                            }
                        }
                    }
                    self.toast(
                        format!("{msg} (Demo: the real firewall was not touched.)"),
                        false,
                    );
                }
                Err(e) => self.toast(e, true),
            }
            self.fw_read(ctx);
            return;
        }
        self.fw.busy = Some(busy);
        let (tx, c, dir) = (self.fw.tx.clone(), ctx.clone(), self.data_dir.clone());
        std::thread::spawn(move || {
            let _ = tx.send(FwMsg::Done(firewall::change(command, &dir)));
            c.request_repaint();
        });
    }

    fn fw_save_known(&mut self) {
        if self.demo {
            return;
        }
        if let Err(e) = self.fw.known.save(&self.data_dir) {
            self.toast(e, true);
        }
    }

    /// New-app alerts: called with every fresh connection snapshot.
    pub(super) fn fw_observe(&mut self) {
        if !self.settings.fw_alerts || self.demo {
            return;
        }
        let seen: Vec<Seen> = self
            .connections
            .iter()
            .map(|c| Seen {
                path: c.path.clone(),
                internet: c
                    .remote
                    .map(|r| super::connections_view::scope(&r) == "Internet")
                    .unwrap_or(false),
            })
            .collect();
        let before = self.fw.known.apps.len();
        let fresh = self.fw.known.observe(&seen, self.now);
        if self.fw.known.apps.len() != before {
            self.fw_save_known();
        }
        for app in fresh {
            self.notify(
                "New app on the internet",
                &format!(
                    "{} just connected. Open WireForge to allow or block it.",
                    app.name
                ),
            );
            self.fw.alerts.push(app);
        }
    }

    pub(super) fn fw_handle(&mut self, ctx: &egui::Context, ask: FwAsk) {
        match ask {
            FwAsk::Block(path) => self.fw_open_block(&path),
            FwAsk::Unblock(path) => {
                let name = file_name(&path);
                self.fw_request(
                    ctx,
                    FwCommand::Unblock { path },
                    format!("Unblocking {name}"),
                );
            }
            FwAsk::Show(path) => {
                self.fw.selected = Some(path);
                self.tab = Tab::Firewall;
            }
        }
    }

    fn fw_open_block(&mut self, path: &str) {
        let current = self.fw.view.as_ref().and_then(|v| v.blocked(path)).cloned();
        self.fw.dialog = Some(FwDialog::Block {
            path: path.to_string(),
            duration: match current.as_ref().map(|a| a.lifetime) {
                Some(Lifetime::Until(_)) => 0,
                Some(Lifetime::UntilRestart { .. }) => 1,
                _ => 2,
            },
            inbound: current.as_ref().map(|a| a.inbound).unwrap_or(false),
            profiles: current.map(|a| a.profiles).unwrap_or(Profiles::ALL),
        });
    }

    /// "Block internet access" / "Unblock" for a program, used in the detail
    /// panels of the Apps and Connections pages.
    pub(super) fn fw_button(&self, ui: &mut Ui, path: &str) -> Option<FwAsk> {
        if path.is_empty() {
            widgets::ghost_button_enabled(ui, &Icon::BLOCKED.with("Block internet access"), false)
                .on_hover_text(
                    "This program's path is not available (protected system process), \
                     so it cannot be blocked by program.",
                );
            return None;
        }
        if self.fw.is_blocked(path) {
            if widgets::ghost_button(ui, &Icon::CHECK.with("Unblock"))
                .on_hover_text("Remove WireForge's block (asks for administrator permission)")
                .clicked()
            {
                return Some(FwAsk::Unblock(path.to_string()));
            }
        } else if widgets::ghost_button(ui, &Icon::BLOCKED.with("Block internet access\u{2026}"))
            .on_hover_text("Stop this program from using the network")
            .clicked()
        {
            return Some(FwAsk::Block(path.to_string()));
        }
        None
    }

    /// The right-click menu entries for a program row.
    pub(super) fn fw_menu(&self, ui: &mut Ui, path: &str) -> Option<FwAsk> {
        let mut ask = None;
        if path.is_empty() {
            ui.add_enabled(
                false,
                egui::Button::new("Block internet access (no program path)"),
            );
            return None;
        }
        if self.fw.is_blocked(path) {
            if ui.button(Icon::CHECK.with("Allow (unblock)")).clicked() {
                ask = Some(FwAsk::Unblock(path.to_string()));
                ui.close_menu();
            }
            if ui
                .button(Icon::CLOCK.with("Change the block\u{2026}"))
                .clicked()
            {
                ask = Some(FwAsk::Block(path.to_string()));
                ui.close_menu();
            }
        } else if ui
            .button(Icon::BLOCKED.with("Block internet access\u{2026}"))
            .clicked()
        {
            ask = Some(FwAsk::Block(path.to_string()));
            ui.close_menu();
        }
        if ui.button(Icon::SHIELD.with("Show in Firewall")).clicked() {
            ask = Some(FwAsk::Show(path.to_string()));
            ui.close_menu();
        }
        ask
    }

    // ----------------------------------------------------------------------------------
    // The page
    // ----------------------------------------------------------------------------------

    pub(super) fn firewall_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        if self.confirmed("fw.remove-all") {
            self.fw_request(
                &ctx,
                FwCommand::RemoveAll,
                "Removing all WireForge rules".into(),
            );
        }
        if let Some(id) = self.confirmed_prefix("fw.undo:") {
            if let Ok(id) = id.parse::<u64>() {
                self.fw_request(&ctx, FwCommand::Undo { id }, "Undoing the change".into());
            }
        }
        let blocked_n = self.fw.view.as_ref().map(|v| v.blocked.len()).unwrap_or(0);
        let subtitle = format!(
            "{} blocked by WireForge. Built on Windows Defender Firewall; each change asks \
             for administrator permission once.",
            match blocked_n {
                1 => "1 app".to_string(),
                n => format!("{n} apps"),
            }
        );
        let mut add = false;
        let mut refresh = false;
        widgets::page_header(ui, "Firewall", &subtitle, |ui| {
            if widgets::primary_button(ui, &Icon::ADD.with("Block an app\u{2026}"), true)
                .on_hover_text("Choose a program (.exe) to block")
                .clicked()
            {
                add = true;
            }
            if widgets::icon_button(ui, Icon::REFRESH, "Read the firewall again").clicked() {
                refresh = true;
            }
        });
        if refresh {
            self.fw_read(&ctx);
        }
        if add && !self.still() {
            if let Some(file) = rfd::FileDialog::new()
                .set_title("Choose a program to block")
                .add_filter("Programs", &["exe"])
                .pick_file()
            {
                self.fw_open_block(&file.to_string_lossy());
            }
        }

        if let Some(busy) = self.fw.busy.clone() {
            widgets::notice(
                ui,
                Icon::SHIELD,
                p.info,
                &format!(
                    "{busy}\u{2026} Windows asks for administrator permission; WireForge \
                     itself keeps running with standard rights."
                ),
            );
            ui.add_space(8.0);
        }
        if let Some(e) = self.fw.error.clone() {
            widgets::notice(
                ui,
                Icon::WARNING,
                p.warn,
                &format!("Windows Defender Firewall could not be read: {e}"),
            );
            ui.add_space(8.0);
        }
        if let Some(l) = self.fw.view.as_ref().and_then(|v| v.lockdown.clone()) {
            let mut end = false;
            widgets::notice_with(
                ui,
                Icon::LOCK,
                p.danger,
                &format!(
                    "Lockdown is on since {}: programs can connect out only when they are on the \
                     allow list ({} programs). Ending it puts back the previous settings exactly.",
                    fmt::date_time(l.since, self.offset),
                    l.allowed.len()
                ),
                |ui| {
                    if widgets::danger_button(ui, "End lockdown", self.fw.busy.is_none()).clicked()
                    {
                        end = true;
                    }
                },
            );
            if end {
                self.fw_request(&ctx, FwCommand::LockdownOff, "Ending lockdown".into());
            }
            ui.add_space(8.0);
        }

        let expired: usize = self
            .fw
            .view
            .as_ref()
            .map(|v| {
                v.blocked
                    .iter()
                    .filter(|a| a.lifetime.expired(self.now, v.boot))
                    .count()
            })
            .unwrap_or(0);
        if expired > 0 {
            let mut clean = false;
            widgets::notice_with(
                ui,
                Icon::CLOCK,
                p.warn,
                &format!(
                    "{expired} temporary block(s) should have ended but are still in place \
                     (the scheduled removal has not run yet)."
                ),
                |ui| {
                    if widgets::ghost_button(ui, "Remove them now").clicked() {
                        clean = true;
                    }
                },
            );
            if clean {
                self.fw_request(&ctx, FwCommand::Expire, "Removing ended blocks".into());
            }
            ui.add_space(8.0);
        }

        App::scroll(ui, "firewall", |ui| {
            widgets::columns_weighted(ui, &[1.85, 1.0], |col, ui| {
                if col == 0 {
                    self.fw_blocked_card(ui);
                    if self.fw.selected.is_some() {
                        ui.add_space(12.0);
                        self.fw_rules_card(ui);
                    }
                } else {
                    self.fw_status_card(ui);
                    ui.add_space(12.0);
                    self.fw_alerts_card(ui);
                    ui.add_space(12.0);
                    self.fw_lockdown_card(ui);
                    ui.add_space(12.0);
                    self.fw_journal_card(ui);
                }
            });
        });
    }

    fn fw_blocked_card(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let now = self.now;
        let offset = self.offset;
        let list: Vec<wf_firewall::BlockedApp> = self
            .fw
            .view
            .as_ref()
            .map(|v| v.blocked.clone())
            .unwrap_or_default()
            .into_iter()
            .filter(|a| {
                let n = self.fw.search.trim().to_lowercase();
                n.is_empty() || a.path.to_lowercase().contains(&n)
            })
            .collect();
        let boot = self.fw.view.as_ref().map(|v| v.boot).unwrap_or(0);
        let mut ask: Option<FwAsk> = None;
        let mut select: Option<String> = None;
        let mut search = std::mem::take(&mut self.fw.search);
        let searching = !search.trim().is_empty();
        widgets::titled_card(
            ui,
            "Blocked apps",
            |ui| {
                widgets::search_box(ui, &mut search, "Search blocked apps", 210.0);
            },
            |ui| {
                ui.label(
                    RichText::new(
                        "These programs cannot use the network. Windows Defender Firewall \
                         enforces it, also while WireForge is closed.",
                    )
                    .size(12.5)
                    .color(p.muted),
                );
                ui.add_space(4.0);
                widgets::table_header(ui, &BLOCK_COLS, None);
                if list.is_empty() {
                    let loading = self.fw.view.is_none() && self.fw.error.is_none();
                    if loading {
                        widgets::busy_state(ui, "Reading Windows Defender Firewall", "");
                    } else {
                        widgets::empty_state(
                            ui,
                            Icon::SHIELD,
                            p.good,
                            if !searching {
                                "No app is blocked"
                            } else {
                                "No blocked app matches"
                            },
                            "Use \"Block an app\", or right-click an app on the Apps or \
                             Connections page.",
                        );
                    }
                    return;
                }
                ui.spacing_mut().item_spacing.y = 0.0;
                for a in &list {
                    let is_sel = self
                        .fw
                        .selected
                        .as_deref()
                        .map(|s| same_path(s, &a.path))
                        .unwrap_or(false);
                    let tex = self.icon(&a.name, &a.path);
                    let (cells, resp) = widgets::table_row(ui, &BLOCK_COLS, 48.0, is_sel);
                    let cell = cells[0];
                    let icon_rect = egui::Rect::from_center_size(
                        cell.left_center() + vec2(12.0, 0.0),
                        vec2(24.0, 24.0),
                    );
                    widgets::program_icon(ui, icon_rect, &a.name, tex.as_ref());
                    let top = egui::Rect::from_min_max(
                        cell.left_top() + vec2(34.0, 5.0),
                        egui::pos2(cell.right(), cell.center().y + 2.0),
                    );
                    widgets::text_in(ui, top, &a.name, semibold(13.5), p.text);
                    let bottom = egui::Rect::from_min_max(
                        egui::pos2(top.left(), cell.center().y + 1.0),
                        egui::pos2(cell.right(), cell.bottom() - 4.0),
                    );
                    if widgets::text_in(ui, bottom, &a.path, regular(11.5), p.faint) {
                        resp.clone().on_hover_text(&a.path);
                    }
                    let dirs = match (a.outbound, a.inbound) {
                        (true, true) => "Out and in",
                        (false, true) => "Incoming",
                        _ => "Outgoing",
                    };
                    let top1 = egui::Rect::from_min_max(
                        cells[1].left_top() + vec2(0.0, 5.0),
                        egui::pos2(cells[1].right(), cells[1].center().y + 2.0),
                    );
                    widgets::text_in(ui, top1, dirs, regular(13.0), p.text);
                    let bottom1 = egui::Rect::from_min_max(
                        egui::pos2(cells[1].left(), cells[1].center().y + 1.0),
                        egui::pos2(cells[1].right(), cells[1].bottom() - 4.0),
                    );
                    widgets::text_in(ui, bottom1, &a.profiles.label(), regular(11.5), p.faint);
                    widgets::text_in(
                        ui,
                        cells[2],
                        &if a.since > 0 {
                            fmt::ago(now, a.since)
                        } else {
                            "\u{2013}".into()
                        },
                        regular(12.5),
                        p.muted,
                    );
                    let (text, color) = match a.lifetime {
                        Lifetime::Always => ("Always".to_string(), p.danger),
                        l if l.expired(now, boot) => ("Time is up".to_string(), p.warn),
                        l => (firewall::lifetime_text(l, now), p.warn),
                    };
                    widgets::paint_badge(ui, cells[3], &text, color);
                    // Painted by hand: a placed widget would move the row cursor.
                    let b = egui::Rect::from_center_size(
                        egui::pos2(cells[4].right() - 38.0, cells[4].center().y),
                        vec2(76.0, 28.0),
                    );
                    let unblock = ui
                        .interact(b, ui.id().with(("fw-unblock", &a.path)), Sense::click())
                        .on_hover_text("Remove the block (asks for administrator permission)");
                    ui.painter().rect(
                        b,
                        egui::CornerRadius::same(7),
                        if unblock.hovered() {
                            p.hover
                        } else {
                            egui::Color32::TRANSPARENT
                        },
                        egui::Stroke::new(1.0_f32, p.border),
                        egui::StrokeKind::Inside,
                    );
                    ui.painter().text(
                        b.center(),
                        Align2::CENTER_CENTER,
                        "Unblock",
                        regular(13.0),
                        p.text,
                    );
                    if unblock.clicked() {
                        ask = Some(FwAsk::Unblock(a.path.clone()));
                    } else if resp.clicked() {
                        select = Some(a.path.clone());
                    }
                    resp.context_menu(|ui| {
                        if ui.button(Icon::CHECK.with("Allow (unblock)")).clicked() {
                            ask = Some(FwAsk::Unblock(a.path.clone()));
                            ui.close_menu();
                        }
                        if ui
                            .button(Icon::CLOCK.with("Change the block\u{2026}"))
                            .clicked()
                        {
                            ask = Some(FwAsk::Block(a.path.clone()));
                            ui.close_menu();
                        }
                        if ui.button(Icon::COPY.with("Copy path")).clicked() {
                            ui.ctx().copy_text(a.path.clone());
                            ui.close_menu();
                        }
                    });
                }
                let _ = offset;
            },
        );
        self.fw.search = search;
        if let Some(path) = select {
            let same = self
                .fw
                .selected
                .as_deref()
                .map(|s| same_path(s, &path))
                .unwrap_or(false);
            self.fw.selected = if same { None } else { Some(path) };
        }
        if let Some(a) = ask {
            self.fw_handle(&ctx, a);
        }
    }

    /// Read-only: every rule that applies to the selected program.
    fn fw_rules_card(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let Some(path) = self.fw.selected.clone() else {
            return;
        };
        let Some(view) = self.fw.view.clone() else {
            return;
        };
        let ours: Vec<&wf_firewall::FwRule> = view
            .rules
            .iter()
            .filter(|r| naming::is_ours(r) && !r.program.is_empty() && same_path(&r.program, &path))
            .collect();
        let others = naming::other_rules_for(&view.rules, &path);
        let mut close = false;
        widgets::titled_card(
            ui,
            &format!("Rules for {}", file_name(&path)),
            |ui| {
                if widgets::icon_button(ui, Icon::CLOSE, "Close").clicked() {
                    close = true;
                }
            },
            |ui| {
                ui.add(egui::Label::new(RichText::new(&path).size(12.0).color(p.faint)).truncate());
                ui.label(
                    RichText::new(
                        "Every Windows Defender Firewall rule that names this program, and \
                         rules that block all programs. A block rule wins over an allow rule. \
                         Only WireForge's own rules are changed here; the others are shown \
                         to explain what happens.",
                    )
                    .size(12.5)
                    .color(p.muted),
                );
                ui.add_space(4.0);
                let row = |ui: &mut Ui, r: &wf_firewall::FwRule, mine: bool| {
                    let (rect, _) =
                        ui.allocate_exact_size(vec2(ui.available_width(), 40.0), Sense::hover());
                    let left = egui::Rect::from_min_max(
                        rect.left_top() + vec2(0.0, 3.0),
                        egui::pos2(rect.right() - 150.0, rect.center().y + 1.0),
                    );
                    widgets::text_in(
                        ui,
                        left,
                        &r.name,
                        regular(13.0),
                        if r.enabled { p.text } else { p.faint },
                    );
                    let sub = egui::Rect::from_min_max(
                        egui::pos2(rect.left(), rect.center().y),
                        egui::pos2(rect.right() - 150.0, rect.bottom() - 3.0),
                    );
                    let mut detail = format!(
                        "{}, {}, {}",
                        r.direction.label(),
                        r.protocol_label(),
                        r.profiles.label().to_lowercase()
                    );
                    if !r.remote_ports.is_empty() {
                        detail.push_str(&format!(", remote ports {}", r.remote_ports));
                    }
                    if r.program.is_empty() {
                        detail.push_str(", all programs");
                    }
                    if mine {
                        detail.push_str(", added by WireForge");
                    } else if !r.group.is_empty() {
                        detail.push_str(&format!(", group {}", r.group));
                    }
                    widgets::text_in(ui, sub, &detail, regular(11.5), p.faint);
                    let badge_rect = egui::Rect::from_min_max(
                        egui::pos2(rect.right() - 74.0, rect.top()),
                        rect.right_bottom(),
                    );
                    let (text, color) = match (r.enabled, r.action) {
                        (false, _) => ("Disabled", p.faint),
                        (true, FwAction::Block) => ("Blocks", p.danger),
                        (true, FwAction::Allow) => ("Allows", p.good),
                    };
                    widgets::paint_badge(ui, badge_rect, text, color);
                    ui.painter().hline(
                        rect.x_range(),
                        rect.bottom(),
                        egui::Stroke::new(1.0_f32, p.border.gamma_multiply(0.5)),
                    );
                };
                ui.spacing_mut().item_spacing.y = 0.0;
                for r in &ours {
                    row(ui, r, true);
                }
                for r in &others {
                    row(ui, r, false);
                }
                if ours.is_empty() && others.is_empty() {
                    ui.label(
                        RichText::new("No rule names this program.")
                            .size(12.5)
                            .color(p.faint),
                    );
                }
            },
        );
        if close {
            self.fw.selected = None;
        }
    }

    fn fw_status_card(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let view = self.fw.view.clone();
        widgets::titled_card(
            ui,
            "Windows Defender Firewall",
            |_| {},
            |ui| {
                let Some(v) = view else {
                    ui.label(RichText::new("Reading\u{2026}").color(p.faint));
                    return;
                };
                ui.spacing_mut().item_spacing.y = 0.0;
                for s in &v.status.profiles {
                    let (rect, resp) =
                        ui.allocate_exact_size(vec2(ui.available_width(), 46.0), Sense::hover());
                    let name = egui::Rect::from_min_max(
                        rect.left_top() + vec2(0.0, 5.0),
                        egui::pos2(rect.right() - 70.0, rect.center().y + 1.0),
                    );
                    let mut title = format!("{} network", s.profile.label());
                    if s.active {
                        title.push_str("  \u{2022}  connected");
                    }
                    widgets::text_in(
                        ui,
                        name,
                        &title,
                        semibold(13.5),
                        if s.active { p.text } else { p.muted },
                    );
                    let sub = egui::Rect::from_min_max(
                        egui::pos2(rect.left(), rect.center().y + 1.0),
                        egui::pos2(rect.right() - 70.0, rect.bottom() - 4.0),
                    );
                    widgets::text_in(
                        ui,
                        sub,
                        &format!(
                            "Incoming: {}   Outgoing: {}",
                            s.default_in.label().to_lowercase(),
                            s.default_out.label().to_lowercase()
                        ),
                        regular(12.0),
                        if s.default_out == FwAction::Block {
                            p.danger
                        } else {
                            p.faint
                        },
                    );
                    let badge = egui::Rect::from_min_max(
                        egui::pos2(rect.right() - 44.0, rect.top()),
                        rect.right_bottom(),
                    );
                    widgets::paint_badge(
                        ui,
                        badge,
                        if s.enabled { "On" } else { "Off" },
                        if s.enabled { p.good } else { p.danger },
                    );
                    resp.on_hover_text(match s.profile {
                        Profile::Domain => "Used on a network with a company domain controller.",
                        Profile::Private => "Used on networks you marked as private (home).",
                        Profile::Public => {
                            "Used on public networks (cafes, airports) and by default."
                        }
                    });
                }
                if v.status.profiles.iter().any(|s| !s.enabled) {
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(
                            "A profile with the firewall off ignores every rule, including \
                             WireForge's blocks. Turn it on in Windows Security.",
                        )
                        .size(12.0)
                        .color(p.warn),
                    );
                }
            },
        );
    }

    fn fw_alerts_card(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let mut toggle = false;
        let mut act: Option<(String, Option<Decision>)> = None;
        let on = self.settings.fw_alerts;
        let known = self.fw.known.apps.clone();
        let show_all = self.fw.known_all;
        let mut flip_all = false;
        widgets::titled_card(
            ui,
            "New-app alerts",
            |ui| {
                if widgets::toggle(ui, on, true)
                    .on_hover_text("Off by default")
                    .clicked()
                {
                    toggle = true;
                }
            },
            |ui| {
                ui.label(
                    RichText::new(
                        "The first time a program connects to the internet, ask whether to \
                         allow or block it. Programs already connecting when this is turned on \
                         are recorded without asking.",
                    )
                    .size(12.5)
                    .color(p.muted),
                );
                if known.is_empty() {
                    return;
                }
                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!("Known programs ({})", known.len())).font(semibold(13.0)),
                );
                ui.label(
                    RichText::new("Right-click a program to allow, block or forget it.")
                        .size(12.0)
                        .color(p.faint),
                );
                // Inside the page's scroll area: a plain list, shortened.
                ui.scope(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    let mut list = known.clone();
                    list.sort_by_key(|a| (a.decision != Decision::Pending, a.name.to_lowercase()));
                    let limit = if show_all { list.len() } else { 6 };
                    for a in list.iter().take(limit) {
                        let (rect, resp) = ui
                            .allocate_exact_size(vec2(ui.available_width(), 38.0), Sense::click());
                        if resp.hovered() {
                            ui.painter()
                                .rect_filled(rect, egui::CornerRadius::same(6), p.hover);
                        }
                        let tex = self.icon(&a.name, &a.path);
                        let icon = egui::Rect::from_center_size(
                            rect.left_center() + vec2(14.0, 0.0),
                            vec2(20.0, 20.0),
                        );
                        widgets::program_icon(ui, icon, &a.name, tex.as_ref());
                        let name = egui::Rect::from_min_max(
                            rect.left_top() + vec2(32.0, 0.0),
                            egui::pos2(rect.right() - 120.0, rect.bottom()),
                        );
                        widgets::text_in(ui, name, &a.name, regular(13.0), p.text);
                        let color = match a.decision {
                            Decision::Allowed => p.good,
                            Decision::Blocked => p.danger,
                            Decision::Pending => p.warn,
                            Decision::Seen => p.muted,
                        };
                        let badge = egui::Rect::from_min_max(
                            egui::pos2(rect.right() - 112.0, rect.top()),
                            rect.right_bottom(),
                        );
                        widgets::paint_badge(ui, badge, a.decision.label(), color);
                        let resp = resp.on_hover_text(format!(
                            "{}\nFirst seen {}. Right-click to change.",
                            a.path,
                            fmt::date_time(a.first_seen, self.offset)
                        ));
                        resp.context_menu(|ui| {
                            if ui.button(Icon::CHECK.with("Allow")).clicked() {
                                act = Some((a.path.clone(), Some(Decision::Allowed)));
                                ui.close_menu();
                            }
                            if ui.button(Icon::BLOCKED.with("Block")).clicked() {
                                act = Some((a.path.clone(), Some(Decision::Blocked)));
                                ui.close_menu();
                            }
                            if ui
                                .button(Icon::DELETE.with("Forget (ask again next time)"))
                                .clicked()
                            {
                                act = Some((a.path.clone(), None));
                                ui.close_menu();
                            }
                        });
                    }
                    if list.len() > 6 {
                        ui.add_space(4.0);
                        let label = if show_all {
                            "Show fewer".to_string()
                        } else {
                            format!("Show all {}", list.len())
                        };
                        if ui
                            .add(
                                egui::Button::new(RichText::new(label).size(12.5).color(p.accent))
                                    .frame(false),
                            )
                            .clicked()
                        {
                            flip_all = true;
                        }
                    }
                });
            },
        );
        if flip_all {
            self.fw.known_all = !self.fw.known_all;
        }
        if toggle {
            self.settings.fw_alerts = !self.settings.fw_alerts;
            self.save_settings();
            if self.settings.fw_alerts {
                self.toast(
                    "New-app alerts are on. Programs connecting right now are recorded as known.",
                    false,
                );
            }
        }
        if let Some((path, decision)) = act {
            self.fw_decide(&ctx, &path, decision);
        }
    }

    /// Records an answer for a program; blocking or allowing it when needed.
    pub(super) fn fw_decide(
        &mut self,
        ctx: &egui::Context,
        path: &str,
        decision: Option<Decision>,
    ) {
        self.fw.alerts.retain(|a| !same_path(&a.path, path));
        match decision {
            None => self.fw.known.forget(path),
            Some(d) => self.fw.known.set(path, d, self.now),
        }
        self.fw_save_known();
        let name = file_name(path);
        match decision {
            Some(Decision::Blocked) if !self.fw.is_blocked(path) => self.fw_request(
                ctx,
                FwCommand::Block {
                    path: path.to_string(),
                    duration: FwDuration::Always,
                    inbound: false,
                    profiles: Profiles::ALL,
                },
                format!("Blocking {name}"),
            ),
            Some(Decision::Allowed) if self.fw.is_blocked(path) => self.fw_request(
                ctx,
                FwCommand::Unblock {
                    path: path.to_string(),
                },
                format!("Unblocking {name}"),
            ),
            Some(Decision::Allowed) if self.fw.lockdown_on() => {
                let listed = self
                    .fw
                    .view
                    .as_ref()
                    .and_then(|v| v.lockdown.as_ref())
                    .map(|l| l.allowed.iter().any(|a| same_path(a, path)))
                    .unwrap_or(false);
                if !listed {
                    self.fw_request(
                        ctx,
                        FwCommand::Allow {
                            path: path.to_string(),
                        },
                        format!("Allowing {name} during lockdown"),
                    );
                }
            }
            _ => {}
        }
    }

    fn fw_lockdown_card(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let lockdown = self.fw.view.as_ref().and_then(|v| v.lockdown.clone());
        let mut start = false;
        let mut end = false;
        let mut add = false;
        let mut remove: Option<String> = None;
        let idle = self.fw.busy.is_none();
        widgets::titled_card(
            ui,
            "Lockdown",
            |ui| {
                if lockdown.is_some() {
                    widgets::badge(ui, "On", p.danger);
                } else {
                    widgets::badge(ui, "Off", p.muted);
                }
            },
            |ui| match &lockdown {
                None => {
                    ui.label(
                        RichText::new(
                            "Block every outgoing connection except for the programs you allow. \
                             For when you want to be sure nothing else talks to the internet. \
                             The previous settings are saved and put back exactly when it ends.",
                        )
                        .size(12.5)
                        .color(p.muted),
                    );
                    ui.add_space(4.0);
                    if widgets::ghost_button_enabled(
                        ui,
                        &Icon::LOCK.with("Start lockdown\u{2026}"),
                        idle,
                    )
                    .clicked()
                    {
                        start = true;
                    }
                }
                Some(l) => {
                    ui.label(
                        RichText::new(format!(
                            "On since {}. Allowed programs:",
                            fmt::date_time(l.since, self.offset)
                        ))
                        .size(12.5)
                        .color(p.muted),
                    );
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for a in &l.allowed {
                        ui.allocate_ui_with_layout(
                            vec2(ui.available_width(), 32.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.label(RichText::new(file_name(a)).size(13.0))
                                    .on_hover_text(a);
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if widgets::icon_button(
                                            ui,
                                            Icon::CLOSE,
                                            "Remove from the allow list",
                                        )
                                        .clicked()
                                        {
                                            remove = Some(a.clone());
                                        }
                                    },
                                );
                            },
                        );
                    }
                    ui.add_space(6.0);
                    ui.spacing_mut().item_spacing.y = 8.0;
                    ui.horizontal(|ui| {
                        if widgets::ghost_button_enabled(
                            ui,
                            &Icon::ADD.with("Allow a program\u{2026}"),
                            idle,
                        )
                        .clicked()
                        {
                            add = true;
                        }
                        if widgets::danger_button(ui, "End lockdown", idle).clicked() {
                            end = true;
                        }
                    });
                }
            },
        );
        if start {
            let mut allow: Vec<(String, bool)> = Vec::new();
            for a in &self.snap.apps {
                if !a.path.is_empty() && !allow.iter().any(|(x, _)| same_path(x, &a.path)) {
                    allow.push((a.path.clone(), false));
                }
            }
            for k in &self.fw.known.apps {
                if k.decision == Decision::Allowed
                    && !allow.iter().any(|(x, _)| same_path(x, &k.path))
                {
                    allow.push((k.path.clone(), true));
                }
            }
            allow.sort_by_key(|(x, _)| file_name(x).to_lowercase());
            self.fw.dialog = Some(FwDialog::Lockdown {
                allow,
                agree: false,
            });
        }
        if end {
            self.fw_request(&ctx, FwCommand::LockdownOff, "Ending lockdown".into());
        }
        if let Some(path) = remove {
            let name = file_name(&path);
            self.fw_request(
                &ctx,
                FwCommand::Disallow { path },
                format!("Removing {name} from the allow list"),
            );
        }
        if add && !self.still() {
            if let Some(file) = rfd::FileDialog::new()
                .set_title("Choose a program to allow during lockdown")
                .add_filter("Programs", &["exe"])
                .pick_file()
            {
                let path = file.to_string_lossy().into_owned();
                let name = file_name(&path);
                self.fw_request(
                    &ctx,
                    FwCommand::Allow { path },
                    format!("Allowing {name} during lockdown"),
                );
            }
        }
    }

    fn fw_journal_card(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let entries: Vec<Entry> = self.fw.journal.iter().rev().take(8).cloned().collect();
        let last = journal::last_undoable(&self.fw.journal).cloned();
        let any_rules = self
            .fw
            .view
            .as_ref()
            .map(|v| v.rules.iter().any(naming::is_ours))
            .unwrap_or(false);
        let idle = self.fw.busy.is_none();
        let mut undo: Option<Entry> = None;
        let mut remove_all = false;
        widgets::titled_card(
            ui,
            "Changes by WireForge",
            |_| {},
            |ui| {
                if entries.is_empty() {
                    ui.label(
                        RichText::new("No changes yet. Every change WireForge makes is listed here and can be undone.")
                            .size(12.5)
                            .color(p.faint),
                    );
                }
                ui.spacing_mut().item_spacing.y = 0.0;
                for e in &entries {
                    let (rect, resp) =
                        ui.allocate_exact_size(vec2(ui.available_width(), 38.0), Sense::hover());
                    let top = egui::Rect::from_min_max(
                        rect.left_top() + vec2(0.0, 3.0),
                        egui::pos2(rect.right(), rect.center().y + 1.0),
                    );
                    widgets::text_in(
                        ui,
                        top,
                        &e.summary,
                        regular(13.0),
                        if e.undone { p.faint } else { p.text },
                    );
                    let bottom = egui::Rect::from_min_max(
                        egui::pos2(rect.left(), rect.center().y),
                        egui::pos2(rect.right(), rect.bottom() - 3.0),
                    );
                    let when = format!(
                        "{}{}",
                        fmt::date_time(e.time, self.offset),
                        if e.undone { ", undone" } else { "" }
                    );
                    widgets::text_in(ui, bottom, &when, regular(11.5), p.faint);
                    resp.on_hover_text(
                        e.ops
                            .iter()
                            .map(|o| o.describe())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
                }
                ui.add_space(8.0);
                ui.spacing_mut().item_spacing.y = 8.0;
                ui.horizontal(|ui| {
                    if let Some(l) = &last {
                        if widgets::ghost_button_enabled(
                            ui,
                            &Icon::UNDO.with("Undo last change"),
                            idle,
                        )
                        .on_hover_text(format!("Undo: {}", l.summary))
                        .clicked()
                        {
                            undo = Some(l.clone());
                        }
                    }
                    if widgets::ghost_button_enabled(
                        ui,
                        &Icon::DELETE.with("Remove all WireForge rules\u{2026}"),
                        idle && any_rules,
                    )
                    .clicked()
                    {
                        remove_all = true;
                    }
                });
            },
        );
        if let Some(e) = undo {
            self.ask(Confirm {
                title: "Undo this change?".into(),
                intro: "WireForge reverses the steps below. Blocks whose time is already up \
                        are not brought back."
                    .into(),
                lines: std::iter::once(e.summary.clone())
                    .chain(e.ops.iter().map(|o| o.describe()))
                    .collect(),
                button: "Undo".into(),
                danger: false,
                tag: format!("fw.undo:{}", e.id),
            });
        }
        if remove_all {
            let n = self
                .fw
                .view
                .as_ref()
                .map(|v| v.rules.iter().filter(|r| naming::is_ours(r)).count())
                .unwrap_or(0);
            let mut lines = vec![format!("{n} rules in the WireForge group are deleted")];
            if self.fw.lockdown_on() {
                lines.push("Lockdown ends and the previous outgoing defaults are restored".into());
            }
            lines.push("Rules made by Windows or other programs are not touched".into());
            self.ask(Confirm {
                title: "Remove all WireForge rules?".into(),
                intro: "Every app WireForge blocked can use the network again.".into(),
                lines,
                button: "Remove all".into(),
                danger: true,
                tag: "fw.remove-all".into(),
            });
        }
    }

    // ----------------------------------------------------------------------------------
    // Dialogs, alerts and the header banner
    // ----------------------------------------------------------------------------------

    pub(super) fn fw_dialogs(&mut self, ctx: &egui::Context) {
        let Some(dialog) = &mut self.fw.dialog else {
            return;
        };
        let p = pal_ctx(ctx);
        let mut close = false;
        let mut run: Option<(FwCommand, String)> = None;
        let active: Vec<Profile> = self
            .fw
            .view
            .as_ref()
            .map(|v| {
                v.status
                    .profiles
                    .iter()
                    .filter(|s| s.active)
                    .map(|s| s.profile)
                    .collect()
            })
            .unwrap_or_default();
        let mut browse = false;
        match dialog {
            FwDialog::Block {
                path,
                duration,
                inbound,
                profiles,
            } => {
                let name = file_name(path);
                let modal = egui::Modal::new(egui::Id::new("fw-block"))
                    .frame(widgets::modal_frame(&p))
                    .show(ctx, |ui| {
                        ui.set_width(500.0);
                        ui.label(
                            RichText::new(format!("Block internet access for {name}?"))
                                .font(semibold(19.0)),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(path.as_str()).size(12.0).color(p.faint),
                            )
                            .truncate(),
                        );
                        ui.add_space(4.0);
                        ui.add(
                            egui::Label::new(
                                RichText::new(
                                    "Windows Defender Firewall stops this program from making \
                                     connections, also while WireForge is closed. Other programs \
                                     are not affected.",
                                )
                                .color(p.muted),
                            )
                            .wrap(),
                        );
                        ui.add_space(8.0);
                        ui.label(RichText::new("How long").font(semibold(13.5)));
                        if let Some(i) = widgets::segmented(ui, &DURATIONS, *duration) {
                            *duration = i;
                        }
                        ui.add_space(6.0);
                        ui.label(RichText::new("On these networks").font(semibold(13.5)));
                        ui.horizontal(|ui| {
                            for pr in Profile::ALL {
                                let mut on = profiles.contains(pr);
                                let label = if active.contains(&pr) {
                                    format!("{} (connected)", pr.label())
                                } else {
                                    pr.label().to_string()
                                };
                                if widgets::checkbox(ui, &mut on, &label).changed() {
                                    *profiles = profiles.with(pr, on);
                                }
                                ui.add_space(8.0);
                            }
                        });
                        ui.add_space(2.0);
                        widgets::checkbox(ui, inbound, "Also block incoming connections");
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(
                                "Windows asks for administrator permission for this one change. \
                                 It is recorded under \"Changes by WireForge\" and can be undone.",
                            )
                            .size(12.0)
                            .color(p.faint),
                        );
                        ui.add_space(10.0);
                        widgets::button_row(ui, |ui| {
                            if widgets::danger_button(ui, "Block", !profiles.is_empty()).clicked() {
                                run = Some((
                                    FwCommand::Block {
                                        path: path.clone(),
                                        duration: duration_cmd(*duration),
                                        inbound: *inbound,
                                        profiles: *profiles,
                                    },
                                    format!("Blocking {name}"),
                                ));
                            }
                            if widgets::ghost_button(ui, "Cancel").clicked() {
                                close = true;
                            }
                        });
                    });
                if modal.should_close() {
                    close = true;
                }
            }
            FwDialog::Lockdown { allow, agree } => {
                let modal = egui::Modal::new(egui::Id::new("fw-lockdown"))
                    .frame(widgets::modal_frame(&p))
                    .show(ctx, |ui| {
                        ui.set_width(540.0);
                        ui.label(RichText::new("Start lockdown?").font(semibold(19.0)));
                        ui.add_space(2.0);
                        widgets::notice(
                            ui,
                            Icon::WARNING,
                            p.danger,
                            "Every program loses internet access except the ones ticked below. \
                             Browsers, updates, cloud sync and chat stop working unless allowed. \
                             Windows' own core networking (DNS, DHCP) keeps working.",
                        );
                        ui.add_space(6.0);
                        ui.label(RichText::new("Allowed programs").font(semibold(13.5)));
                        egui::ScrollArea::vertical()
                            .id_salt("fw-lockdown-list")
                            .max_height(200.0)
                            .auto_shrink([false, true])
                            .show(ui, |ui| {
                                if allow.is_empty() {
                                    ui.label(
                                        RichText::new(
                                            "No program has a connection open right now.",
                                        )
                                        .size(12.5)
                                        .color(p.faint),
                                    );
                                }
                                for (path, on) in allow.iter_mut() {
                                    widgets::checkbox(ui, on, &file_name(path))
                                        .on_hover_text(path.as_str());
                                }
                            });
                        if widgets::ghost_button(ui, &Icon::ADD.with("Add a program\u{2026}"))
                            .clicked()
                        {
                            browse = true;
                        }
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(
                                "The current outgoing default of each network profile is saved \
                                 in a disabled WireForge rule and put back exactly when lockdown \
                                 ends. End it with the button at the top of the window, or from \
                                 a terminal: WireForge.exe --fw-lockdown off",
                            )
                            .size(12.0)
                            .color(p.faint),
                        );
                        ui.add_space(4.0);
                        widgets::checkbox(
                            ui,
                            agree,
                            "I understand that other programs lose internet access",
                        );
                        ui.add_space(10.0);
                        widgets::button_row(ui, |ui| {
                            if widgets::danger_button(ui, "Start lockdown", *agree).clicked() {
                                let list: Vec<String> = allow
                                    .iter()
                                    .filter(|(_, on)| *on)
                                    .map(|(p, _)| p.clone())
                                    .collect();
                                run = Some((
                                    FwCommand::LockdownOn { allow: list },
                                    "Starting lockdown".into(),
                                ));
                            }
                            if widgets::ghost_button(ui, "Cancel").clicked() {
                                close = true;
                            }
                        });
                    });
                if modal.should_close() {
                    close = true;
                }
            }
        }
        if browse && !self.still() {
            if let Some(file) = rfd::FileDialog::new()
                .set_title("Choose a program to allow")
                .add_filter("Programs", &["exe"])
                .pick_file()
            {
                if let Some(FwDialog::Lockdown { allow, .. }) = &mut self.fw.dialog {
                    let path = file.to_string_lossy().into_owned();
                    if !allow.iter().any(|(x, _)| same_path(x, &path)) {
                        allow.push((path, true));
                    }
                }
            }
        }
        if let Some((cmd, busy)) = run {
            self.fw.dialog = None;
            self.fw_request(ctx, cmd, busy);
        } else if close {
            self.fw.dialog = None;
        }
    }

    /// The new-app question, at the top right of the window.
    pub(super) fn fw_alerts_ui(&mut self, ctx: &egui::Context) {
        let Some(a) = self.fw.alerts.first().cloned() else {
            return;
        };
        let p = pal_ctx(ctx);
        let tex = self.icon(&a.name, &a.path);
        let more = self.fw.alerts.len() - 1;
        let mut answer: Option<Option<Decision>> = None;
        let mut later = false;
        egui::Area::new(egui::Id::new("fw-alert"))
            .anchor(Align2::RIGHT_TOP, vec2(-18.0, 78.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(p.card)
                    .stroke(egui::Stroke::new(1.0_f32, p.warn.gamma_multiply(0.8)))
                    .corner_radius(egui::CornerRadius::same(12))
                    .inner_margin(egui::Margin::same(16))
                    .shadow(egui::Shadow {
                        offset: [0, 6],
                        blur: 18,
                        spread: 0,
                        color: egui::Color32::from_black_alpha(70),
                    })
                    .show(ui, |ui| {
                        ui.set_width(380.0);
                        ui.allocate_ui_with_layout(
                            vec2(380.0, 22.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.label(RichText::new(Icon::GLOBE.glyph()).color(p.warn));
                                ui.label(
                                    RichText::new("New app on the internet")
                                        .font(semibold(13.0))
                                        .color(p.warn),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if more > 0 {
                                            ui.label(
                                                RichText::new(format!("+{more} more"))
                                                    .size(12.0)
                                                    .color(p.faint),
                                            );
                                        }
                                    },
                                );
                            },
                        );
                        ui.add_space(4.0);
                        ui.allocate_ui_with_layout(
                            vec2(380.0, 40.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                let (r, _) =
                                    ui.allocate_exact_size(vec2(34.0, 34.0), Sense::hover());
                                widgets::program_icon(ui, r, &a.name, tex.as_ref());
                                ui.vertical(|ui| {
                                    ui.spacing_mut().item_spacing.y = 0.0;
                                    ui.label(RichText::new(&a.name).font(semibold(16.0)));
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&a.path).size(11.5).color(p.faint),
                                        )
                                        .truncate(),
                                    );
                                });
                            },
                        );
                        ui.add_space(2.0);
                        ui.label(
                            RichText::new(format!(
                                "First connected at {}. Allow it, or block its internet access? \
                                 WireForge remembers the answer.",
                                &fmt::clock(a.first_seen, self.offset)[..5]
                            ))
                            .size(12.5)
                            .color(p.muted),
                        );
                        ui.add_space(8.0);
                        widgets::button_row(ui, |ui| {
                            if widgets::danger_button(ui, &Icon::BLOCKED.with("Block"), true)
                                .clicked()
                            {
                                answer = Some(Some(Decision::Blocked));
                            }
                            if widgets::primary_button(ui, &Icon::CHECK.with("Allow"), true)
                                .clicked()
                            {
                                answer = Some(Some(Decision::Allowed));
                            }
                            if widgets::ghost_button(ui, "Decide later").clicked() {
                                later = true;
                            }
                        });
                    });
            });
        if let Some(d) = answer {
            self.fw_decide(ctx, &a.path, d);
        } else if later {
            self.fw.alerts.remove(0);
        }
    }
}
