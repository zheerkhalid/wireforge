//! Saved networks: the Wi-Fi networks Windows remembers on this PC, with
//! their passwords (hidden until asked for), QR codes and an export.
//!
//! Read-only: profiles are never changed or deleted.

use super::app::{App, Tab};
use super::theme::{pal, regular, semibold, Icon};
use super::widgets::{self, Col};
use super::wifi_view::{badge_in, icon_at, security_color, security_note, two_lines};
use crate::export;
use eframe::egui::{
    self, epaint::Mesh, pos2, vec2, Color32, CornerRadius, Rect, RichText, Sense, Shape, Ui,
};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use wf_wifi::{profiles, qr, KeyState, SavedProfile, WlanError};

// --------------------------------------------------------------------------------------
// Pure helpers
// --------------------------------------------------------------------------------------

/// Identifies a profile in the list (the same name can be saved twice: per
/// adapter, or for this user and for all users).
pub fn profile_key(p: &SavedProfile) -> String {
    format!("{}|{}|{}", p.name, p.interface_guid, p.all_users)
}

/// The name to show: the network name, or the profile name when they differ.
pub fn display_name(p: &SavedProfile) -> &str {
    if p.ssid.is_empty() {
        &p.name
    } else {
        &p.ssid
    }
}

/// Which passwords are shown in clear text. Everything else stays dots.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reveal {
    shown: HashSet<String>,
}

impl Reveal {
    pub fn is_shown(&self, key: &str) -> bool {
        self.shown.contains(key)
    }

    /// Shows a hidden password, hides a shown one.
    pub fn toggle(&mut self, key: &str) {
        if !self.shown.remove(key) {
            self.shown.insert(key.to_string());
        }
    }

    /// True when there is something to show and all of it is shown.
    pub fn all_shown(&self, keys: &[String]) -> bool {
        !keys.is_empty() && keys.iter().all(|k| self.shown.contains(k))
    }

    /// "Reveal all" when anything is hidden, otherwise "Hide all".
    pub fn toggle_all(&mut self, keys: &[String]) {
        if self.all_shown(keys) {
            self.shown.clear();
        } else {
            self.shown.extend(keys.iter().cloned());
        }
    }

    /// Forgets everything (leaving the page, reloading the list).
    pub fn hide_all(&mut self) {
        self.shown.clear();
    }

    #[cfg(test)]
    pub fn any(&self) -> bool {
        !self.shown.is_empty()
    }
}

/// The keys of the profiles that have a password to reveal.
pub fn revealable(list: &[SavedProfile]) -> Vec<String> {
    list.iter()
        .filter(|p| matches!(p.key, KeyState::Key(_)))
        .map(profile_key)
        .collect()
}

/// Why there is no password to show, in plain words (`None` for a readable key).
pub fn key_reason(key: &KeyState) -> Option<&'static str> {
    match key {
        KeyState::Key(_) => None,
        KeyState::Open => Some("No password: open network"),
        KeyState::Enterprise => {
            Some("Signs in with a user account (802.1X): there is no shared password to show")
        }
        KeyState::NeedsAdmin => Some("Saved for all users: restart as administrator to show it"),
        KeyState::Unknown | KeyState::Unavailable(_) => {
            Some("Windows did not provide a password for this network")
        }
    }
}

/// A saved "networkKey" is the 64-digit key derived from the password, not
/// the password itself.
pub fn is_raw_key(p: &SavedProfile) -> bool {
    match &p.key {
        KeyState::Key(k) => {
            p.key_type.eq_ignore_ascii_case("networkKey")
                && k.len() == 64
                && k.bytes().all(|b| b.is_ascii_hexdigit())
        }
        _ => false,
    }
}

/// "12 saved networks, 9 with a password".
pub fn saved_subtitle(list: &[SavedProfile]) -> String {
    let with_key = list
        .iter()
        .filter(|p| matches!(p.key, KeyState::Key(_)))
        .count();
    match list.len() {
        0 => "No saved networks".to_string(),
        1 => format!("1 saved network, {with_key} with a password"),
        n => format!("{n} saved networks, {with_key} with a password"),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum SavedSort {
    #[default]
    Name,
    Security,
}

/// Search over the network name and the security mode.
pub fn profile_matches(p: &SavedProfile, needle: &str) -> bool {
    let needle = needle.trim().to_lowercase();
    needle.is_empty()
        || p.name.to_lowercase().contains(&needle)
        || p.ssid.to_lowercase().contains(&needle)
        || p.security.to_lowercase().contains(&needle)
}

/// The indices of the profiles to list, filtered and sorted.
pub fn visible_profiles(
    list: &[SavedProfile],
    needle: &str,
    sort: (SavedSort, bool),
) -> Vec<usize> {
    let mut out: Vec<usize> = (0..list.len())
        .filter(|i| profile_matches(&list[*i], needle))
        .collect();
    let name = |i: usize| display_name(&list[i]).to_lowercase();
    out.sort_by(|a, b| {
        let main = match sort.0 {
            SavedSort::Name => name(*a).cmp(&name(*b)),
            SavedSort::Security => list[*a]
                .security
                .to_lowercase()
                .cmp(&list[*b].security.to_lowercase()),
        };
        let main = if sort.1 { main } else { main.reverse() };
        main.then(name(*a).cmp(&name(*b))).then(a.cmp(b))
    });
    out
}

/// The text of the QR code that lets a phone join, or why there is none.
pub fn qr_text(p: &SavedProfile) -> Result<String, &'static str> {
    let name = display_name(p);
    match &p.key {
        KeyState::Key(k) => Ok(qr::wifi_payload(name, k, &p.security, p.hidden)),
        KeyState::Open => Ok(qr::wifi_payload(name, "", "Open", p.hidden)),
        KeyState::Enterprise => Err(
            "No QR code: this network signs each person in with their own account, \
             which a QR code cannot carry.",
        ),
        KeyState::NeedsAdmin => Err(
            "No QR code yet: the password was saved for all users. Restart as administrator \
             to read it.",
        ),
        KeyState::Unknown | KeyState::Unavailable(_) => {
            Err("No QR code: Windows did not provide a password for this network.")
        }
    }
}

/// The side of one QR module in points: a whole number of screen pixels, as
/// large as fits `target` points for `modules` modules (quiet zone included).
pub fn qr_module_points(target: f32, modules: usize, pixels_per_point: f32) -> f32 {
    let ppp = pixels_per_point.max(0.1);
    let pixels = ((target * ppp) / modules.max(1) as f32).floor().max(1.0);
    pixels / ppp
}

/// Quiet zone around the code, in modules (the standard asks for four).
pub const QUIET: usize = 4;

// --------------------------------------------------------------------------------------
// Page state
// --------------------------------------------------------------------------------------

struct QrView {
    name: String,
    security: String,
    open_network: bool,
    matrix: Option<qr::Matrix>,
}

struct Loading {
    rx: Receiver<Result<Vec<SavedProfile>, WlanError>>,
    cancel: Arc<AtomicBool>,
}

impl Drop for Loading {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
    }
}

/// State of this page.
#[derive(Default)]
pub struct SavedPage {
    demo: bool,
    list: Option<Vec<SavedProfile>>,
    error: Option<WlanError>,
    loading: Option<Loading>,
    reveal: Reveal,
    search: String,
    sort: (SavedSort, bool),
    qr: Option<QrView>,
    export_open: bool,
    include_passwords: bool,
    /// The page was on screen in the previous frame.
    was_open: bool,
}

fn qr_view(p: &SavedProfile) -> Option<QrView> {
    let text = qr_text(p).ok()?;
    Some(QrView {
        name: display_name(p).to_string(),
        security: p.security.clone(),
        open_network: p.key == KeyState::Open,
        matrix: qr::matrix(text.as_bytes()),
    })
}

impl SavedPage {
    pub fn new(demo: bool, view: &str) -> Self {
        let mut page = SavedPage {
            demo,
            sort: (SavedSort::Name, true),
            ..Default::default()
        };
        if demo {
            let list = crate::demo::wifi::profiles();
            let first = list.iter().find(|p| matches!(p.key, KeyState::Key(_)));
            match view {
                "saved-qr" => page.qr = first.and_then(qr_view),
                "saved-export" => {
                    // The demo view exists to show the warning; in real use the
                    // box always starts unticked.
                    page.export_open = true;
                    page.include_passwords = true;
                }
                _ => {
                    // Show the feature in the plain demo view.
                    if let Some(p) = first {
                        page.reveal.toggle(&profile_key(p));
                    }
                }
            }
            page.list = Some(list);
        }
        page
    }

    /// The number shown next to the page in the navigation rail.
    pub fn count(&self) -> Option<usize> {
        self.list.as_ref().map(Vec::len)
    }

    fn load(&mut self, ctx: &egui::Context) {
        self.reveal.hide_all();
        self.qr = None;
        if self.demo {
            self.list = Some(crate::demo::wifi::profiles());
            return;
        }
        let (tx, rx) = channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let (flag, ctx) = (cancel.clone(), ctx.clone());
        std::thread::spawn(move || {
            let result = profiles::saved_profiles();
            if !flag.load(Ordering::SeqCst) {
                let _ = tx.send(result);
                ctx.request_repaint();
            }
        });
        self.loading = Some(Loading { rx, cancel });
    }

    fn poll(&mut self, app: &mut App, ctx: &egui::Context) {
        let open = app.tab == Tab::Saved;
        if self.was_open && !open && !app.still() {
            // Leaving the page hides every password again.
            self.reveal.hide_all();
            self.qr = None;
            self.export_open = false;
            self.include_passwords = false;
        }
        self.was_open = open;
        if let Some(l) = &self.loading {
            match l.rx.try_recv() {
                Ok(Ok(list)) => {
                    self.list = Some(list);
                    self.error = None;
                    self.loading = None;
                }
                Ok(Err(e)) => {
                    self.list = None;
                    self.error = Some(e);
                    self.loading = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.error = Some(WlanError::Other(
                        "The saved networks could not be read.".into(),
                    ));
                    self.loading = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if open
            && !self.demo
            && !app.still()
            && self.list.is_none()
            && self.error.is_none()
            && self.loading.is_none()
        {
            self.load(ctx);
        }
    }
}

impl App {
    /// Called every frame, also while another page is shown: pick up results
    /// of background work here.
    pub(super) fn saved_poll(&mut self, ctx: &egui::Context) {
        let mut page = std::mem::take(&mut self.saved);
        page.poll(self, ctx);
        self.saved = page;
    }

    pub(super) fn saved_ui(&mut self, ui: &mut Ui) {
        let mut page = std::mem::take(&mut self.saved);
        page.ui(self, ui);
        self.saved = page;
    }
}

// --------------------------------------------------------------------------------------
// The page
// --------------------------------------------------------------------------------------

const ROW_H: f32 = 46.0;
const FOOTER: &str = "Passwords are read from Windows on this PC and never leave it. \
                      WireForge never changes or deletes saved networks.";

enum RowAction {
    Toggle(String),
    Copy(usize),
    Qr(usize),
}

impl SavedPage {
    fn ui(&mut self, app: &mut App, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let list: Vec<SavedProfile> = self.list.clone().unwrap_or_default();
        let subtitle = match &self.list {
            Some(l) => saved_subtitle(l),
            None => {
                "The Wi-Fi networks Windows remembers on this PC, with their passwords.".to_string()
            }
        };
        let keys = revealable(&list);
        let (mut refresh, mut open_export) = (false, false);
        widgets::page_header(ui, "Saved networks", &subtitle, |ui| {
            ui.add_enabled_ui(!list.is_empty(), |ui| {
                if widgets::ghost_button(ui, &Icon::EXPORT.with("Export"))
                    .on_hover_text(
                        "Save the list as CSV, HTML or JSON. You choose whether the file \
                         contains the passwords.",
                    )
                    .clicked()
                {
                    open_export = true;
                }
            });
            if widgets::ghost_button_enabled(
                ui,
                &Icon::REFRESH.with("Refresh"),
                self.loading.is_none(),
            )
            .on_hover_text(
                "Read the saved networks from Windows again. Shown passwords are hidden again.",
            )
            .clicked()
            {
                refresh = true;
            }
        });
        if refresh {
            self.error = None;
            self.load(&ctx);
        }
        if open_export {
            self.include_passwords = false;
            self.export_open = true;
        }

        if self.list.is_none() {
            match &self.error {
                Some(WlanError::NoWifi(_)) => widgets::empty_state(
                    ui,
                    Icon::KEY,
                    p.muted,
                    "No Wi-Fi here",
                    "This PC has no Wi-Fi adapter, or the Windows Wi-Fi service (WLAN AutoConfig) \
                     is turned off, so there are no saved networks to read.",
                ),
                Some(e) => widgets::empty_state(
                    ui,
                    Icon::WARNING,
                    p.warn,
                    "The saved networks could not be read",
                    &format!("{e} Press Refresh to try again."),
                ),
                None => widgets::busy_state(
                    ui,
                    "Reading the saved networks",
                    "Nothing is sent anywhere.",
                ),
            }
            return;
        }

        if !app.elevated && list.iter().any(|x| x.key == KeyState::NeedsAdmin) {
            let n = list
                .iter()
                .filter(|x| x.key == KeyState::NeedsAdmin)
                .count();
            let mut restart = false;
            widgets::notice_with(
                ui,
                Icon::SHIELD,
                p.info,
                &format!(
                    "{} saved for all users of this PC. Windows only hands out those passwords \
                     to an administrator.",
                    if n == 1 {
                        "1 network was".to_string()
                    } else {
                        format!("{n} networks were")
                    }
                ),
                |ui| {
                    ui.add_space(2.0);
                    if widgets::ghost_button(ui, "Restart as administrator").clicked() {
                        restart = true;
                    }
                },
            );
            if restart {
                app.restart_elevated(&ctx);
            }
            ui.add_space(10.0);
        }

        ui.horizontal(|ui| {
            let w = (ui.available_width() - 200.0).clamp(160.0, 300.0);
            widgets::search_box(ui, &mut self.search, "Search name or security", w);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let all = self.reveal.all_shown(&keys);
                let label = if all {
                    Icon::EYE_OFF.with("Hide all")
                } else {
                    Icon::EYE.with("Reveal all")
                };
                if widgets::ghost_button_enabled(ui, &label, !keys.is_empty())
                    .on_hover_text(if all {
                        "Hide every password again."
                    } else {
                        "Show every password in clear text. Check that nobody is looking over your shoulder."
                    })
                    .clicked()
                {
                    self.reveal.toggle_all(&keys);
                }
            });
        });
        ui.add_space(8.0);

        let visible = visible_profiles(&list, &self.search, self.sort);
        let wide = ui.available_width() >= 900.0;
        let cols: Vec<Col> = if wide {
            vec![
                Col::flex("Network", 1.25),
                Col::fixed("Security", 150.0),
                Col::flex("Password", 1.75),
                Col::fixed("Connects", 96.0),
                Col::fixed("Saved for", 84.0),
                Col::fixed("", 32.0),
            ]
        } else {
            vec![
                Col::flex("Network", 1.2),
                Col::fixed("Security", 142.0),
                Col::flex("Password", 1.6),
                Col::fixed("Connects", 84.0),
                Col::fixed("", 32.0),
            ]
        };
        let qr_col = cols.len() - 1;
        let footer_h = 30.0;
        let table_h = (ui.available_height() - footer_h - 32.0 - 30.0 - 12.0).max(120.0);
        let mut actions: Vec<RowAction> = Vec::new();
        widgets::card(ui, |ui| {
            let sorted = match self.sort {
                (SavedSort::Name, asc) => Some((0, asc)),
                (SavedSort::Security, asc) => Some((1, asc)),
            };
            match widgets::table_header(ui, &cols, sorted) {
                Some(0) => {
                    self.sort = (
                        SavedSort::Name,
                        !(self.sort.0 == SavedSort::Name && self.sort.1),
                    )
                }
                Some(1) => {
                    self.sort = (
                        SavedSort::Security,
                        !(self.sort.0 == SavedSort::Security && self.sort.1),
                    )
                }
                _ => {}
            }
            if visible.is_empty() {
                ui.allocate_ui(vec2(ui.available_width(), table_h.min(300.0)), |ui| {
                    widgets::empty_state(
                        ui,
                        Icon::KEY,
                        p.muted,
                        if list.is_empty() {
                            "No saved networks"
                        } else {
                            "Nothing matches"
                        },
                        if list.is_empty() {
                            "Windows has no Wi-Fi network saved on this PC. Networks appear here \
                             after you connect to them."
                        } else {
                            "Clear the search to see all saved networks."
                        },
                    );
                });
                return;
            }
            egui::ScrollArea::vertical()
                .id_salt("saved-networks")
                .auto_shrink([false, true])
                .max_height(table_h)
                .show_rows(ui, ROW_H, visible.len(), |ui, range| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for &i in &visible[range] {
                        let x = &list[i];
                        let key = profile_key(x);
                        let (cells, _) = widgets::table_row(ui, &cols, ROW_H, false);
                        // Network
                        if x.hidden {
                            let (top, bottom) = two_lines(cells[0]);
                            widgets::text_in(ui, top, display_name(x), semibold(13.5), p.text);
                            widgets::text_in(
                                ui,
                                bottom,
                                "Hidden network (name not broadcast)",
                                regular(11.5),
                                p.faint,
                            );
                        } else {
                            widgets::text_in(ui, cells[0], display_name(x), semibold(13.5), p.text);
                        }
                        // Security
                        let sec = if x.security.is_empty() {
                            "Unknown"
                        } else {
                            &x.security
                        };
                        badge_in(ui, cells[1], sec, security_color(&p, &x.security));
                        ui.interact(cells[1], ui.id().with((&key, "sec")), Sense::hover())
                            .on_hover_text(security_note(&x.security));
                        // Password
                        let cell = cells[2];
                        match &x.key {
                            KeyState::Key(k) => {
                                let shown = self.reveal.is_shown(&key);
                                let text = Rect::from_min_max(
                                    cell.min,
                                    pos2(cell.right() - 66.0, cell.bottom()),
                                );
                                if shown {
                                    if is_raw_key(x) {
                                        let (top, bottom) = two_lines(text);
                                        widgets::text_in(ui, top, k, regular(13.0), p.text);
                                        widgets::text_in(
                                            ui,
                                            bottom,
                                            "raw key (64 hex digits)",
                                            regular(11.5),
                                            p.faint,
                                        );
                                    } else {
                                        widgets::text_in(ui, text, k, regular(14.0), p.text);
                                    }
                                } else {
                                    widgets::text_in(
                                        ui,
                                        text,
                                        export::MASK,
                                        regular(14.0),
                                        p.muted,
                                    );
                                }
                                let eye = Rect::from_center_size(
                                    pos2(cell.right() - 47.0, cell.center().y),
                                    vec2(30.0, 30.0),
                                );
                                let copy = Rect::from_center_size(
                                    pos2(cell.right() - 15.0, cell.center().y),
                                    vec2(30.0, 30.0),
                                );
                                if icon_at(
                                    ui,
                                    eye,
                                    (&key, "eye"),
                                    if shown { Icon::EYE_OFF } else { Icon::EYE },
                                    if shown { p.accent } else { p.muted },
                                    true,
                                    if shown {
                                        "Hide the password"
                                    } else {
                                        "Show the password"
                                    },
                                )
                                .clicked()
                                {
                                    actions.push(RowAction::Toggle(key.clone()));
                                }
                                if icon_at(
                                    ui,
                                    copy,
                                    (&key, "copy"),
                                    Icon::COPY,
                                    p.muted,
                                    true,
                                    "Copy the password",
                                )
                                .clicked()
                                {
                                    actions.push(RowAction::Copy(i));
                                }
                            }
                            other => {
                                let reason = key_reason(other).unwrap_or_default();
                                widgets::text_in(ui, cell, reason, regular(12.5), p.muted);
                                ui.interact(cell, ui.id().with((&key, "why")), Sense::hover())
                                    .on_hover_text(profiles::key_explanation(other));
                            }
                        }
                        // Connects
                        let (text, color) = if x.auto_connect {
                            ("Automatically", p.text)
                        } else {
                            ("When asked", p.muted)
                        };
                        widgets::text_in(ui, cells[3], text, regular(13.0), color);
                        ui.interact(cells[3], ui.id().with((&key, "auto")), Sense::hover())
                            .on_hover_text(if x.auto_connect {
                                "Windows joins this network by itself when it is in range."
                            } else {
                                "Windows only joins this network when you pick it."
                            });
                        // Saved for
                        if wide {
                            let who = if x.all_users {
                                "All users"
                            } else {
                                "This user"
                            };
                            widgets::text_in(ui, cells[4], who, regular(13.0), p.muted);
                        }
                        // QR code
                        let offer = qr_text(x);
                        let r = Rect::from_center_size(cells[qr_col].center(), vec2(30.0, 30.0));
                        let tip = match &offer {
                            Ok(_) => "Show a QR code a phone can scan to join this network",
                            Err(why) => why,
                        };
                        if icon_at(ui, r, (&key, "qr"), Icon::QR, p.muted, offer.is_ok(), tip)
                            .clicked()
                        {
                            actions.push(RowAction::Qr(i));
                        }
                    }
                });
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(Icon::LOCK.glyph()).size(12.0).color(p.faint));
            ui.add(egui::Label::new(RichText::new(FOOTER).size(12.5).color(p.faint)).truncate());
        });

        for action in actions {
            match action {
                RowAction::Toggle(key) => self.reveal.toggle(&key),
                RowAction::Copy(i) => {
                    if let Some(KeyState::Key(k)) = list.get(i).map(|x| &x.key) {
                        app.copy(&ctx, k, "Password");
                    }
                }
                RowAction::Qr(i) => self.qr = list.get(i).and_then(qr_view),
            }
        }
        self.qr_modal(&ctx);
        self.export_modal(app, &ctx, &list);
    }

    fn qr_modal(&mut self, ctx: &egui::Context) {
        let Some(view) = &self.qr else { return };
        let p = super::theme::pal_ctx(ctx);
        let mut close = false;
        let modal = egui::Modal::new(egui::Id::new("saved-qr"))
            .frame(widgets::modal_frame(&p))
            .show(ctx, |ui| {
                ui.set_width(340.0);
                ui.label(RichText::new("Join with a phone").font(semibold(19.0)));
                ui.add_space(8.0);
                ui.vertical_centered(|ui| {
                    match &view.matrix {
                        Some(m) => paint_qr(ui, m, 280.0),
                        None => {
                            ui.add_space(40.0);
                            ui.label(
                                RichText::new("The name and password are too long for a QR code.")
                                    .color(p.muted),
                            );
                            ui.add_space(40.0);
                        }
                    }
                    ui.add_space(8.0);
                    ui.add(
                        egui::Label::new(RichText::new(&view.name).font(semibold(16.0))).truncate(),
                    );
                    ui.label(
                        RichText::new(if view.open_network {
                            "Open network: the code contains no password".to_string()
                        } else {
                            view.security.clone()
                        })
                        .size(12.5)
                        .color(p.muted),
                    );
                });
                ui.add_space(6.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(if view.open_network {
                            "Point a phone camera at the code to join this network."
                        } else {
                            "Point a phone camera at the code to join this network. The code \
                             contains the password, so only show it to people you would tell it to."
                        })
                        .color(p.muted),
                    )
                    .wrap(),
                );
                ui.add_space(10.0);
                widgets::button_row(ui, |ui| {
                    if widgets::primary_button(ui, "Close", true).clicked() {
                        close = true;
                    }
                });
            });
        if close || modal.should_close() {
            self.qr = None;
        }
    }

    fn export_modal(&mut self, app: &mut App, ctx: &egui::Context, list: &[SavedProfile]) {
        if !self.export_open {
            return;
        }
        let p = super::theme::pal_ctx(ctx);
        let (mut go, mut close) = (false, false);
        let modal = egui::Modal::new(egui::Id::new("saved-export"))
            .frame(widgets::modal_frame(&p))
            .show(ctx, |ui| {
                ui.set_width(480.0);
                ui.label(RichText::new("Export saved networks").font(semibold(19.0)));
                ui.add_space(2.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "Saves the list of {} as a CSV, HTML or JSON file in a place you choose.",
                            match list.len() {
                                1 => "1 network".to_string(),
                                n => format!("{n} networks"),
                            }
                        ))
                        .color(p.muted),
                    )
                    .wrap(),
                );
                ui.add_space(10.0);
                widgets::checkbox(ui, &mut self.include_passwords, "Include passwords");
                ui.add_space(6.0);
                if self.include_passwords {
                    widgets::notice(
                        ui,
                        Icon::WARNING,
                        p.warn,
                        "This file will contain your Wi-Fi passwords in clear text. Anyone who can \
                         open the file can join these networks. Keep it somewhere safe and delete \
                         it when you no longer need it.",
                    );
                } else {
                    widgets::notice(
                        ui,
                        Icon::LOCK,
                        p.good,
                        "Passwords are left out: the file shows dots in their place.",
                    );
                }
                ui.add_space(14.0);
                widgets::button_row(ui, |ui| {
                    let label = if self.include_passwords {
                        "Export with passwords"
                    } else {
                        "Export"
                    };
                    if widgets::primary_button(ui, label, true).clicked() {
                        go = true;
                    }
                    if widgets::ghost_button(ui, "Cancel").clicked() {
                        close = true;
                    }
                });
            });
        if go {
            let include = self.include_passwords;
            self.export_open = false;
            self.include_passwords = false;
            app.export(
                &[export::saved_networks_table(list, include)],
                "Saved Wi-Fi networks",
                "wireforge-wifi-networks",
            );
        } else if close || modal.should_close() {
            self.export_open = false;
            self.include_passwords = false;
        }
    }
}

/// Draws a QR code black on white whatever the theme, every module a whole
/// number of screen pixels, with the quiet zone the standard asks for.
fn paint_qr(ui: &mut Ui, m: &qr::Matrix, target: f32) {
    let ppp = ui.ctx().pixels_per_point();
    let modules = m.width + 2 * QUIET;
    let module = qr_module_points(target, modules, ppp);
    let side = module * modules as f32;
    let (rect, _) = ui.allocate_exact_size(vec2(side, side), Sense::hover());
    // Start on a pixel boundary so the edges stay sharp.
    let snap = |v: f32| (v * ppp).round() / ppp;
    let origin = pos2(snap(rect.left()), snap(rect.top()));
    let painter = ui.painter();
    painter.rect_filled(
        Rect::from_min_size(origin, vec2(side, side)),
        CornerRadius::same(8),
        Color32::WHITE,
    );
    // A mesh has no soft edges: neighbouring modules join without seams.
    let mut mesh = Mesh::default();
    for y in 0..m.width {
        let mut x = 0;
        while x < m.width {
            if !m.is_dark(x, y) {
                x += 1;
                continue;
            }
            let start = x;
            while x < m.width && m.is_dark(x, y) {
                x += 1;
            }
            let min = origin + vec2((start + QUIET) as f32 * module, (y + QUIET) as f32 * module);
            let max = origin + vec2((x + QUIET) as f32 * module, (y + QUIET + 1) as f32 * module);
            mesh.add_colored_rect(Rect::from_min_max(min, max), Color32::BLACK);
        }
    }
    painter.add(Shape::mesh(mesh));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, security: &str, key: KeyState) -> SavedProfile {
        SavedProfile {
            name: name.into(),
            ssid: name.into(),
            security: security.into(),
            key,
            ..Default::default()
        }
    }

    fn sample() -> Vec<SavedProfile> {
        vec![
            profile(
                "maple",
                "WPA3-Personal",
                KeyState::Key("invented-pass-1".into()),
            ),
            profile("Cafe", "Open", KeyState::Open),
            profile(
                "Birch",
                "WPA2-Personal",
                KeyState::Key("invented-pass-2".into()),
            ),
            profile("Office", "WPA2-Enterprise", KeyState::Enterprise),
            profile("Flat", "WPA2-Personal", KeyState::NeedsAdmin),
        ]
    }

    #[test]
    fn reveal_state() {
        let list = sample();
        let keys = revealable(&list);
        assert_eq!(keys.len(), 2);
        let mut r = Reveal::default();
        assert!(!r.any());
        assert!(!r.is_shown(&keys[0]), "hidden by default");
        assert!(!r.all_shown(&keys));
        r.toggle(&keys[0]);
        assert!(r.is_shown(&keys[0]) && !r.is_shown(&keys[1]));
        assert!(!r.all_shown(&keys));
        // One shown, one hidden: the header button reveals the rest.
        r.toggle_all(&keys);
        assert!(r.all_shown(&keys));
        r.toggle(&keys[1]);
        assert!(!r.is_shown(&keys[1]) && r.is_shown(&keys[0]));
        r.toggle_all(&keys);
        assert!(r.all_shown(&keys));
        r.toggle_all(&keys);
        assert!(!r.any(), "hide all");
        r.toggle(&keys[0]);
        r.hide_all();
        assert!(!r.is_shown(&keys[0]));
        // Nothing to reveal is never "all shown".
        assert!(!Reveal::default().all_shown(&[]));
    }

    #[test]
    fn leaving_the_page_hides_passwords() {
        let mut page = SavedPage::new(true, "saved");
        assert!(page.reveal.any(), "the demo view shows one password");
        assert_eq!(page.count(), Some(crate::demo::wifi::profiles().len()));
        // What `poll` does when the tab changes away.
        page.was_open = true;
        let open = false;
        if page.was_open && !open {
            page.reveal.hide_all();
        }
        assert!(!page.reveal.any());
        let page = SavedPage::new(true, "saved-qr");
        assert!(page.qr.as_ref().is_some_and(|q| q.matrix.is_some()));
        assert!(!page.reveal.any());
        assert!(SavedPage::new(true, "saved-export").export_open);
        assert_eq!(SavedPage::new(false, "saved").count(), None);
    }

    #[test]
    fn subtitles_and_reasons() {
        assert_eq!(
            saved_subtitle(&sample()),
            "5 saved networks, 2 with a password"
        );
        assert_eq!(
            saved_subtitle(&sample()[..1]),
            "1 saved network, 1 with a password"
        );
        assert_eq!(saved_subtitle(&[]), "No saved networks");
        assert_eq!(key_reason(&KeyState::Key("x".into())), None);
        assert_eq!(
            key_reason(&KeyState::Open),
            Some("No password: open network")
        );
        assert!(key_reason(&KeyState::Enterprise)
            .unwrap()
            .contains("802.1X"));
        assert!(key_reason(&KeyState::NeedsAdmin)
            .unwrap()
            .contains("administrator"));
        assert!(key_reason(&KeyState::Unknown).is_some());
    }

    #[test]
    fn raw_keys() {
        let mut p = profile("x", "WPA2-Personal", KeyState::Key("ab".repeat(32)));
        assert!(
            !is_raw_key(&p),
            "a passphrase of 64 hex digits is still a passphrase"
        );
        p.key_type = "networkKey".into();
        assert!(is_raw_key(&p));
        p.key = KeyState::Key("short".into());
        assert!(!is_raw_key(&p));
    }

    #[test]
    fn search_and_sort() {
        let list = sample();
        let names = |v: Vec<usize>| {
            v.into_iter()
                .map(|i| list[i].name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(visible_profiles(&list, "", (SavedSort::Name, true))),
            vec!["Birch", "Cafe", "Flat", "maple", "Office"]
        );
        assert_eq!(
            names(visible_profiles(&list, "", (SavedSort::Name, false)))[0],
            "Office"
        );
        assert_eq!(
            names(visible_profiles(&list, "wpa2", (SavedSort::Name, true))),
            vec!["Birch", "Flat", "Office"]
        );
        assert_eq!(
            names(visible_profiles(&list, "", (SavedSort::Security, true))),
            vec!["Cafe", "Office", "Birch", "Flat", "maple"]
        );
        assert!(visible_profiles(&list, "zzz", (SavedSort::Name, true)).is_empty());
        assert!(profile_matches(&list[0], "  MAPLE "));
    }

    #[test]
    fn qr_offers() {
        let list = sample();
        let with_key = qr_text(&list[0]).unwrap();
        assert!(with_key.starts_with("WIFI:T:WPA;S:maple;P:"));
        let open = qr_text(&list[1]).unwrap();
        assert!(open.contains("nopass") && !open.contains("P:"));
        assert!(qr_text(&list[3]).is_err());
        assert!(qr_text(&list[4]).unwrap_err().contains("administrator"));
        assert!(qr_view(&list[0]).is_some_and(|v| v.matrix.is_some() && !v.open_network));
        assert!(qr_view(&list[1]).is_some_and(|v| v.open_network));
        assert!(qr_view(&list[3]).is_none());
    }

    #[test]
    fn qr_modules_are_whole_pixels() {
        for ppp in [1.0_f32, 1.25, 1.5, 2.0] {
            for modules in [29_usize, 37, 41, 65] {
                let m = qr_module_points(280.0, modules, ppp);
                let pixels = m * ppp;
                assert!((pixels - pixels.round()).abs() < 1e-3, "{ppp} {modules}");
                assert!(pixels >= 1.0);
                assert!(m * modules as f32 <= 280.0 + 1e-3);
            }
        }
        assert_eq!(qr_module_points(280.0, 37, 1.0), 7.0);
        // Never zero, even when the code cannot fit.
        assert!(qr_module_points(10.0, 100, 1.0) >= 1.0);
    }

    #[test]
    fn export_masks_unless_asked() {
        let list = sample();
        let masked = export::saved_networks_table(&list, false);
        assert_eq!(masked.rows.len(), 5);
        assert!(masked
            .rows
            .iter()
            .all(|r| !r.iter().any(|c| c.contains("invented-pass"))));
        assert_eq!(masked.rows[0][2], export::MASK);
        let clear = export::saved_networks_table(&list, true);
        assert_eq!(clear.rows[0][2], "invented-pass-1");
        assert_eq!(clear.rows[1][2], "(none: open network)");
    }

    #[test]
    fn demo_profiles_cover_every_key_state() {
        let list = crate::demo::wifi::profiles();
        assert!(list.len() >= 10);
        assert!(list.iter().any(|p| matches!(p.key, KeyState::Key(_))));
        assert!(list.iter().any(|p| p.key == KeyState::Open));
        assert!(list.iter().any(|p| p.key == KeyState::Enterprise));
        assert!(list.iter().any(|p| p.key == KeyState::NeedsAdmin));
        assert!(list
            .iter()
            .any(|p| matches!(p.key, KeyState::Unavailable(_))));
        assert!(list.iter().any(is_raw_key));
        assert!(list.iter().any(|p| p.hidden));
        let keys: HashSet<String> = list.iter().map(profile_key).collect();
        assert_eq!(keys.len(), list.len(), "row keys are unique");
    }
}
