//! Apps page: live per-app rates and totals, the endpoints each app talks
//! to, and the usage history by day, app and adapter.

use super::app::App;
use super::charts::{self, LineChart, Series};
use super::overview::{last_days, usage_bars};
use super::theme::{pal, regular, semibold, Icon};
use super::widgets::{self, Col};
use crate::export::Table;
use crate::fmt;
use eframe::egui::{self, vec2, Align2, RichText, Sense, Ui};
use wf_traffic::{AppLive, Day, PerAppMode, Snapshot, Totals, UsageRow};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum AppsMode {
    #[default]
    Live,
    Usage,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Range {
    Week,
    #[default]
    Month30,
    ThisMonth,
    Quarter,
}

impl Range {
    pub fn label(self) -> &'static str {
        match self {
            Range::Week => "7 days",
            Range::Month30 => "30 days",
            Range::ThisMonth => "This month",
            Range::Quarter => "90 days",
        }
    }

    /// The inclusive days the range covers.
    pub fn days(self, today: Day) -> (Day, Day) {
        match self {
            Range::Week => last_days(today, 7),
            Range::Month30 => last_days(today, 30),
            Range::ThisMonth => (
                Day {
                    y: today.y,
                    m: today.m,
                    d: 1,
                },
                today,
            ),
            Range::Quarter => last_days(today, 90),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppSort {
    Name,
    Down,
    Up,
    Session,
    Today,
    Connections,
}

pub struct AppsPage {
    pub mode: AppsMode,
    pub search: String,
    pub sort: (AppSort, bool),
    pub selected: Option<String>,
    pub range: Range,
}

impl Default for AppsPage {
    fn default() -> Self {
        AppsPage {
            mode: AppsMode::Live,
            search: String::new(),
            sort: (AppSort::Down, false),
            selected: None,
            range: Range::Month30,
        }
    }
}

impl AppsPage {
    pub fn show_usage(&mut self) {
        self.mode = AppsMode::Usage;
    }

    pub fn select_first(&mut self, snap: &Snapshot) {
        self.selected = sorted_apps(&snap.apps, "", (AppSort::Down, false))
            .first()
            .map(|a| a.name.clone());
    }
}

/// Filters by the search text and sorts; ties fall back to the name.
pub fn sorted_apps(apps: &[AppLive], search: &str, sort: (AppSort, bool)) -> Vec<AppLive> {
    let needle = search.trim().to_lowercase();
    let mut list: Vec<AppLive> = apps
        .iter()
        .filter(|a| {
            needle.is_empty()
                || a.name.to_lowercase().contains(&needle)
                || a.path.to_lowercase().contains(&needle)
        })
        .cloned()
        .collect();
    list.sort_by(|a, b| {
        let ord = match sort.0 {
            AppSort::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            AppSort::Down => a.rate.down.total_cmp(&b.rate.down),
            AppSort::Up => a.rate.up.total_cmp(&b.rate.up),
            AppSort::Session => a.session.sum().cmp(&b.session.sum()),
            AppSort::Today => a.today.sum().cmp(&b.today.sum()),
            AppSort::Connections => a.connections.cmp(&b.connections),
        };
        let ord = if sort.1 { ord } else { ord.reverse() };
        ord.then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    list
}

/// Each row's share of the largest row, for the bars in the usage table.
pub fn shares(rows: &[UsageRow]) -> Vec<f32> {
    let max = rows.iter().map(|r| r.totals.sum()).max().unwrap_or(0);
    rows.iter()
        .map(|r| {
            if max == 0 {
                0.0
            } else {
                r.totals.sum() as f32 / max as f32
            }
        })
        .collect()
}

pub fn live_table(apps: &[AppLive], units: fmt::Units) -> Table {
    let mut t = Table::new(
        "Apps using the network",
        &[
            "App",
            "Path",
            "Processes",
            "Download rate",
            "Upload rate",
            "Received this session",
            "Sent this session",
            "Received today",
            "Sent today",
            "Connections",
        ],
    );
    for a in apps {
        t.push(vec![
            a.name.clone(),
            a.path.clone(),
            a.pids.len().to_string(),
            fmt::rate(a.rate.down, units),
            fmt::rate(a.rate.up, units),
            fmt::bytes(a.session.rx),
            fmt::bytes(a.session.tx),
            fmt::bytes(a.today.rx),
            fmt::bytes(a.today.tx),
            a.connections.to_string(),
        ]);
    }
    t
}

pub fn usage_tables(
    days: &[(Day, Totals)],
    apps: &[UsageRow],
    adapters: &[UsageRow],
) -> Vec<Table> {
    let mut by_day = Table::new(
        "Usage by day",
        &[
            "Day",
            "Received",
            "Sent",
            "Received (bytes)",
            "Sent (bytes)",
        ],
    );
    for (d, t) in days {
        by_day.push(vec![
            d.iso(),
            fmt::bytes(t.rx),
            fmt::bytes(t.tx),
            t.rx.to_string(),
            t.tx.to_string(),
        ]);
    }
    let rows = |title: &str, first: &str, rows: &[UsageRow]| {
        let mut t = Table::new(
            title,
            &[
                first,
                "Received",
                "Sent",
                "Received (bytes)",
                "Sent (bytes)",
            ],
        );
        for r in rows {
            t.push(vec![
                r.key.clone(),
                fmt::bytes(r.totals.rx),
                fmt::bytes(r.totals.tx),
                r.totals.rx.to_string(),
                r.totals.tx.to_string(),
            ]);
        }
        t
    };
    vec![
        by_day,
        rows("Usage by app", "App", apps),
        rows("Usage by adapter", "Adapter", adapters),
    ]
}

const LIVE_COLS: [Col; 7] = [
    Col::flex("App", 1.0),
    Col::fixed("Last minute", 110.0),
    Col::right("Download", 96.0),
    Col::right("Upload", 96.0),
    Col::right("Session", 84.0),
    Col::right("Today", 84.0),
    Col::right("Connections", 86.0),
];

impl App {
    pub(super) fn apps_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let etw = matches!(self.snap.per_app_mode, PerAppMode::Etw);
        let subtitle = match self.apps.mode {
            AppsMode::Live if etw => format!(
                "{} apps are using the network. Bytes are counted per app.",
                self.snap.apps.len()
            ),
            AppsMode::Live => format!(
                "{} apps have network connections open.",
                self.snap.apps.len()
            ),
            AppsMode::Usage => {
                "How much data was used, by day, app and adapter. Stored only on this PC."
                    .to_string()
            }
        };
        let mut export = false;
        let mut mode = self.apps.mode;
        widgets::page_header(ui, "Apps", &subtitle, |ui| {
            if widgets::ghost_button(ui, &Icon::EXPORT.with("Export")).clicked() {
                export = true;
            }
            ui.add_space(4.0);
            let current = usize::from(mode == AppsMode::Usage);
            if let Some(i) = widgets::segmented(ui, &["Live", "Usage history"], current) {
                mode = if i == 0 {
                    AppsMode::Live
                } else {
                    AppsMode::Usage
                };
            }
        });
        self.apps.mode = mode;

        if !etw && self.apps.mode == AppsMode::Live {
            let ctx = ui.ctx().clone();
            let (text, offer) = match &self.snap.per_app_mode {
                PerAppMode::ConnectionsOnly(reason) if !self.elevated => (
                    format!(
                        "Windows only lets administrators count bytes per app. Until then this \
                         list shows which apps have connections open, without speeds or totals. \
                         ({reason})"
                    ),
                    true,
                ),
                PerAppMode::ConnectionsOnly(reason) => (
                    format!(
                        "Per-app byte counts could not be started: {reason} This list shows \
                         which apps have connections open."
                    ),
                    false,
                ),
                _ => ("Starting to measure…".to_string(), false),
            };
            let mut restart = false;
            widgets::notice_with(ui, Icon::INFO, p.info, &text, |ui| {
                if offer
                    && widgets::ghost_button(ui, &Icon::SHIELD.with("Restart as administrator"))
                        .clicked()
                {
                    restart = true;
                }
            });
            if restart {
                self.restart_elevated(&ctx);
            }
            ui.add_space(10.0);
        }

        match self.apps.mode {
            AppsMode::Live => self.apps_live(ui, export),
            AppsMode::Usage => self.apps_usage(ui, export),
        }
    }

    fn apps_live(&mut self, ui: &mut Ui, export: bool) {
        let p = pal(ui);
        let units = self.units();
        let etw = matches!(self.snap.per_app_mode, PerAppMode::Etw);
        let list = sorted_apps(&self.snap.apps, &self.apps.search, self.apps.sort);
        if export {
            let table = live_table(&list, units);
            self.export(&[table], "Apps using the network", "wireforge-apps");
        }
        if let Some(sel) = &self.apps.selected {
            if !self.snap.apps.iter().any(|a| &a.name == sel) {
                self.apps.selected = None;
            }
        }
        let selected = self
            .apps
            .selected
            .as_ref()
            .and_then(|s| self.snap.apps.iter().find(|a| &a.name == s))
            .cloned();

        let weights: &[f32] = if selected.is_some() {
            &[1.7, 1.0]
        } else {
            &[1.0]
        };
        let full_height = ui.available_height();
        widgets::columns_weighted(ui, weights, |col, ui| {
            if col == 0 {
                widgets::card(ui, |ui| {
                    ui.set_min_height(full_height - 34.0);
                    ui.horizontal(|ui| {
                        widgets::search_box(ui, &mut self.apps.search, "Search apps", 240.0);
                        ui.label(
                            RichText::new(format!("{} shown", list.len()))
                                .size(12.5)
                                .color(p.faint),
                        );
                    });
                    ui.add_space(4.0);
                    // With the details panel open there is less room: drop two columns.
                    let narrow = selected.is_some();
                    let cols: Vec<Col> = LIVE_COLS
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| !(narrow && matches!(i, 1 | 4)))
                        .map(|(_, c)| *c)
                        .collect();
                    let sort_cols: Vec<Option<AppSort>> = [
                        Some(AppSort::Name),
                        None,
                        Some(AppSort::Down),
                        Some(AppSort::Up),
                        Some(AppSort::Session),
                        Some(AppSort::Today),
                        Some(AppSort::Connections),
                    ]
                    .into_iter()
                    .enumerate()
                    .filter(|(i, _)| !(narrow && matches!(i, 1 | 4)))
                    .map(|(_, c)| c)
                    .collect();
                    let sorted_index = sort_cols
                        .iter()
                        .position(|c| *c == Some(self.apps.sort.0))
                        .map(|i| (i, self.apps.sort.1));
                    if let Some(i) = widgets::table_header(ui, &cols, sorted_index) {
                        if let Some(Some(s)) = sort_cols.get(i) {
                            self.apps.sort = if self.apps.sort.0 == *s {
                                (*s, !self.apps.sort.1)
                            } else {
                                (*s, *s == AppSort::Name)
                            };
                        }
                    }
                    if list.is_empty() {
                        widgets::empty_state(
                            ui,
                            Icon::APPS,
                            p.muted,
                            if self.apps.search.is_empty() {
                                "No app is using the network"
                            } else {
                                "No app matches the search"
                            },
                            "Apps appear here as soon as they open a connection.",
                        );
                        return;
                    }
                    let mut clicked: Option<String> = None;
                    let mut fw_ask = None;
                    egui::ScrollArea::vertical()
                        .id_salt("apps-live")
                        .auto_shrink([false, false])
                        .show_rows(ui, 44.0, list.len(), |ui, range| {
                            ui.spacing_mut().item_spacing.y = 0.0;
                            for a in &list[range] {
                                let tex = self.icon(&a.name, &a.path);
                                let is_sel = self.apps.selected.as_deref() == Some(&a.name);
                                let (cells, resp) = widgets::table_row(ui, &cols, 44.0, is_sel);
                                let cells_name = cells.first().copied();
                                let mut c = cells.into_iter();
                                // App
                                if let Some(cell) = c.next() {
                                    let icon_rect = egui::Rect::from_center_size(
                                        cell.left_center() + vec2(12.0, 0.0),
                                        vec2(24.0, 24.0),
                                    );
                                    widgets::program_icon(ui, icon_rect, &a.name, tex.as_ref());
                                    let name = egui::Rect::from_min_max(
                                        cell.left_top() + vec2(34.0, 5.0),
                                        egui::pos2(cell.right(), cell.center().y + 2.0),
                                    );
                                    widgets::text_in(ui, name, &a.name, semibold(13.5), p.text);
                                    let sub = egui::Rect::from_min_max(
                                        egui::pos2(name.left(), cell.center().y + 1.0),
                                        egui::pos2(cell.right(), cell.bottom() - 4.0),
                                    );
                                    let procs = if a.pids.len() == 1 {
                                        "1 process".to_string()
                                    } else {
                                        format!("{} processes", a.pids.len())
                                    };
                                    widgets::text_in(ui, sub, &procs, regular(11.5), p.faint);
                                }
                                if !narrow {
                                    if let Some(cell) = c.next() {
                                        let values: Vec<f64> =
                                            a.history.iter().map(|r| r.down + r.up).collect();
                                        charts::sparkline(
                                            ui,
                                            cell.shrink2(vec2(0.0, 9.0)),
                                            &values,
                                            p.down,
                                        );
                                    }
                                }
                                let dash = "\u{2013}".to_string();
                                let mut number = |text: String, strong: bool| {
                                    if let Some(cell) = c.next() {
                                        widgets::text_in_right(
                                            ui,
                                            cell,
                                            &text,
                                            regular(13.0),
                                            if strong { p.text } else { p.muted },
                                        );
                                    }
                                };
                                if etw {
                                    number(fmt::rate(a.rate.down, units), a.rate.down >= 1024.0);
                                    number(fmt::rate(a.rate.up, units), a.rate.up >= 1024.0);
                                    if !narrow {
                                        number(fmt::bytes(a.session.sum()), false);
                                    }
                                    number(fmt::bytes(a.today.sum()), false);
                                } else {
                                    number(dash.clone(), false);
                                    number(dash.clone(), false);
                                    if !narrow {
                                        number(dash.clone(), false);
                                    }
                                    number(dash.clone(), false);
                                }
                                number(a.connections.to_string(), false);
                                if self.fw.is_blocked(&a.path) {
                                    if let Some(cell) = cells_name {
                                        ui.painter().text(
                                            cell.right_center(),
                                            Align2::RIGHT_CENTER,
                                            Icon::BLOCKED.glyph(),
                                            regular(13.0),
                                            p.danger,
                                        );
                                    }
                                }
                                if resp.clicked() {
                                    clicked = Some(a.name.clone());
                                }
                                resp.context_menu(|ui| {
                                    if let Some(ask) = self.fw_menu(ui, &a.path) {
                                        fw_ask = Some(ask);
                                    }
                                });
                            }
                        });
                    if let Some(ask) = fw_ask {
                        let ctx = ui.ctx().clone();
                        self.fw_handle(&ctx, ask);
                    }
                    if let Some(name) = clicked {
                        self.apps.selected = if self.apps.selected.as_deref() == Some(&name) {
                            None
                        } else {
                            Some(name)
                        };
                    }
                });
            } else if let Some(a) = &selected {
                self.app_details(ui, a, etw, full_height - 34.0);
            }
        });
    }

    fn app_details(&mut self, ui: &mut Ui, a: &AppLive, etw: bool, height: f32) {
        let p = pal(ui);
        let units = self.units();
        let tex = self.icon(&a.name, &a.path);
        widgets::card(ui, |ui| {
            ui.set_min_height(height);
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(vec2(36.0, 36.0), Sense::hover());
                widgets::program_icon(ui, r, &a.name, tex.as_ref());
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.add(
                        egui::Label::new(RichText::new(&a.name).font(semibold(17.0))).truncate(),
                    );
                    ui.add(
                        egui::Label::new(
                            RichText::new(if a.path.is_empty() {
                                "Windows component"
                            } else {
                                &a.path
                            })
                            .size(11.5)
                            .color(p.faint),
                        )
                        .truncate(),
                    )
                    .on_hover_text(&a.path);
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                    if widgets::icon_button(ui, Icon::CLOSE, "Close details").clicked() {
                        self.apps.selected = None;
                    }
                });
            });
            ui.add_space(2.0);
            let blocked = self.fw.is_blocked(&a.path);
            let mut ask = None;
            ui.allocate_ui_with_layout(
                vec2(ui.available_width(), 36.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ask = self.fw_button(ui, &a.path);
                    if blocked {
                        widgets::badge(ui, &Icon::BLOCKED.with("Blocked by WireForge"), p.danger);
                    }
                },
            );
            if let Some(ask) = ask {
                let ctx = ui.ctx().clone();
                self.fw_handle(&ctx, ask);
            }
            ui.add_space(4.0);
            egui::ScrollArea::vertical()
                .id_salt("app-details")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.set_width(ui.available_width() - 6.0);
                    if etw {
                        let down: Vec<f64> = a.history.iter().map(|r| r.down).collect();
                        let up: Vec<f64> = a.history.iter().map(|r| r.up).collect();
                        let top = down.iter().chain(up.iter()).copied().fold(0.0, f64::max);
                        let y_fmt = |v: f64| fmt::rate(v, units);
                        let series = [
                            Series {
                                name: "Download",
                                values: &down,
                                color: p.down,
                                fill: true,
                            },
                            Series {
                                name: "Upload",
                                values: &up,
                                color: p.up,
                                fill: true,
                            },
                        ];
                        let mut chart = LineChart::new(&series, &y_fmt);
                        chart.height = 96.0;
                        chart.slots = 60;
                        chart.y_max = Some(fmt::rate_ceiling(top, units));
                        chart.x_left = "1 minute ago";
                        chart.x_right = "Now";
                        charts::line_chart(ui, &chart);
                        ui.add_space(4.0);
                        ui.spacing_mut().item_spacing.y = 3.0;
                        widgets::kv(
                            ui,
                            "Right now",
                            &format!(
                                "{} down, {} up",
                                fmt::rate(a.rate.down, units),
                                fmt::rate(a.rate.up, units)
                            ),
                        );
                        widgets::kv(
                            ui,
                            "This session",
                            &format!(
                                "{} received, {} sent",
                                fmt::bytes(a.session.rx),
                                fmt::bytes(a.session.tx)
                            ),
                        );
                        widgets::kv(
                            ui,
                            "Today",
                            &format!(
                                "{} received, {} sent",
                                fmt::bytes(a.today.rx),
                                fmt::bytes(a.today.tx)
                            ),
                        );
                    }
                    ui.spacing_mut().item_spacing.y = 3.0;
                    widgets::kv(ui, "Connections", &a.connections.to_string());
                    widgets::kv(
                        ui,
                        "Process IDs",
                        &a.pids
                            .iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                    ui.add_space(8.0);
                    ui.spacing_mut().item_spacing.y = 6.0;

                    // Last 30 days of this app.
                    let (from, to) = last_days(Day::today(), 30);
                    let days = self.usage.app_by_day(&a.name, from, to);
                    if days.iter().any(|(_, t)| t.sum() > 0) {
                        widgets::section(ui, "Last 30 days");
                        let bars = usage_bars(&days);
                        charts::bar_chart_with(
                            ui,
                            &bars,
                            &[("Download", p.down), ("Upload", p.up)],
                            90.0,
                            &|v| fmt::bytes(v as u64),
                            false,
                            &fmt::bytes_ceiling,
                        );
                        ui.add_space(4.0);
                    }

                    widgets::section(ui, "Talking to");
                    if a.endpoints.is_empty() {
                        ui.label(
                            RichText::new("No remote endpoints at the moment.")
                                .size(12.5)
                                .color(p.faint),
                        );
                    }
                    if !self.settings.resolve_hosts && !self.demo {
                        ui.label(
                            RichText::new(
                                "Host names are off. They can be turned on in Settings \
                                 (it asks your DNS server for the name of each address).",
                            )
                            .size(11.5)
                            .color(p.faint),
                        );
                    }
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for e in a.endpoints.iter().take(40) {
                        let (rect, _) = ui
                            .allocate_exact_size(vec2(ui.available_width(), 38.0), Sense::hover());
                        let title = match &e.host {
                            Some(h) => h.clone(),
                            None => e.addr.to_string(),
                        };
                        let top = egui::Rect::from_min_max(
                            rect.left_top() + vec2(0.0, 3.0),
                            egui::pos2(rect.right() - 92.0, rect.center().y + 1.0),
                        );
                        widgets::text_in(ui, top, &title, regular(13.0), p.text);
                        let bottom = egui::Rect::from_min_max(
                            egui::pos2(rect.left(), rect.center().y),
                            egui::pos2(rect.right() - 92.0, rect.bottom() - 3.0),
                        );
                        let sub = if e.host.is_some() {
                            format!("{} {} port {}", e.addr, e.proto.label(), e.port)
                        } else {
                            format!("{} port {}", e.proto.label(), e.port)
                        };
                        widgets::text_in(ui, bottom, &sub, regular(11.5), p.faint);
                        if etw {
                            ui.painter().text(
                                rect.right_center(),
                                Align2::RIGHT_CENTER,
                                fmt::bytes(e.rx + e.tx),
                                regular(12.5),
                                p.muted,
                            );
                        }
                        ui.painter().hline(
                            rect.x_range(),
                            rect.bottom(),
                            egui::Stroke::new(1.0_f32, p.border.gamma_multiply(0.5)),
                        );
                    }
                });
        });
    }

    fn apps_usage(&mut self, ui: &mut Ui, export: bool) {
        let p = pal(ui);
        let today = Day::today();
        let (from, to) = self.apps.range.days(today);
        let days = self.usage.by_day(from, to);
        let apps = self.usage.by_app(from, to);
        let adapters = self.usage.by_adapter(from, to);
        let total = self.usage.range_total(from, to);
        if export {
            let tables = usage_tables(&days, &apps, &adapters);
            self.export(&tables, "Data usage", "wireforge-usage");
        }

        ui.horizontal(|ui| {
            for r in [
                Range::Week,
                Range::Month30,
                Range::ThisMonth,
                Range::Quarter,
            ] {
                if widgets::chip(ui, r.label(), None, self.apps.range == r).clicked() {
                    self.apps.range = r;
                }
            }
            ui.add_space(8.0);
            ui.label(
                RichText::new(format!(
                    "{} to {}",
                    fmt::day_label(from.m, from.d),
                    fmt::day_label(to.m, to.d)
                ))
                .size(12.5)
                .color(p.faint),
            );
        });
        ui.add_space(8.0);

        App::scroll(ui, "apps-usage", |ui| {
            widgets::card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 36.0;
                    charts::stat(ui, "Total", &fmt::bytes(total.sum()), "");
                    charts::stat(ui, "Received", &fmt::bytes(total.rx), "");
                    charts::stat(ui, "Sent", &fmt::bytes(total.tx), "");
                    let n = days.len().max(1) as u64;
                    charts::stat(ui, "Average per day", &fmt::bytes(total.sum() / n), "");
                    if self.settings.cap_enabled {
                        let (cf, ct) =
                            wf_traffic::usage::cycle_range(today, self.settings.cap_start_day);
                        let used = self.usage.range_total(cf, ct).sum();
                        let status = wf_traffic::usage::cap_status(
                            used,
                            self.settings.cap_bytes(),
                            self.settings.cap_warn_pct as f64 / 100.0,
                        );
                        charts::stat(
                            ui,
                            "Data allowance",
                            &format!("{:.0} % used", status.fraction * 100.0),
                            &format!("{} of {}", fmt::bytes(status.used), fmt::bytes(status.cap)),
                        );
                    }
                });
                ui.add_space(6.0);
                if total.sum() == 0 {
                    ui.add_space(30.0);
                    ui.label(
                        RichText::new(
                            "Nothing recorded for this period yet. Usage is counted while \
                             WireForge is running.",
                        )
                        .color(p.muted),
                    );
                    ui.add_space(30.0);
                } else {
                    let bars = usage_bars(&days);
                    charts::bar_chart_with(
                        ui,
                        &bars,
                        &[("Download", p.down), ("Upload", p.up)],
                        170.0,
                        &|v| fmt::bytes(v as u64),
                        false,
                        &fmt::bytes_ceiling,
                    );
                }
            });
            ui.add_space(12.0);
            widgets::columns_weighted(ui, &[1.6, 1.0], |col, ui| {
                let (title, rows, empty) = if col == 0 {
                    (
                        "By app",
                        &apps,
                        "Per-app history is recorded while WireForge runs as administrator.",
                    )
                } else {
                    ("By adapter", &adapters, "Nothing recorded yet.")
                };
                widgets::titled_card(
                    ui,
                    title,
                    |ui| {
                        ui.label(
                            RichText::new(format!("{} entries", rows.len()))
                                .size(12.5)
                                .color(p.faint),
                        );
                    },
                    |ui| {
                        ui.set_min_height(120.0);
                        if rows.is_empty() {
                            ui.add_space(20.0);
                            ui.label(RichText::new(empty).color(p.muted));
                            return;
                        }
                        let share = shares(rows);
                        ui.spacing_mut().item_spacing.y = 0.0;
                        for (r, s) in rows.iter().zip(share).take(if col == 0 { 25 } else { 12 }) {
                            let (rect, _) = ui.allocate_exact_size(
                                vec2(ui.available_width(), 36.0),
                                Sense::hover(),
                            );
                            let name = egui::Rect::from_min_max(
                                rect.left_top() + vec2(0.0, 2.0),
                                egui::pos2(rect.right() - 200.0, rect.top() + 22.0),
                            );
                            widgets::text_in(ui, name, &r.key, regular(13.5), p.text);
                            ui.painter().text(
                                egui::pos2(rect.right(), rect.top() + 12.0),
                                Align2::RIGHT_CENTER,
                                fmt::bytes(r.totals.sum()),
                                semibold(13.0),
                                p.text,
                            );
                            ui.painter().text(
                                egui::pos2(rect.right() - 84.0, rect.top() + 12.0),
                                Align2::RIGHT_CENTER,
                                format!(
                                    "{} in, {} out",
                                    fmt::bytes(r.totals.rx),
                                    fmt::bytes(r.totals.tx)
                                ),
                                regular(11.5),
                                p.faint,
                            );
                            let bar = egui::Rect::from_min_max(
                                egui::pos2(rect.left(), rect.bottom() - 9.0),
                                egui::pos2(rect.right(), rect.bottom() - 5.0),
                            );
                            charts::paint_meter_bar(ui, bar, s, p.down, p.hover);
                        }
                    },
                );
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wf_traffic::Rate;

    fn app(name: &str, down: f64, up: f64, conns: u32, today: u64) -> AppLive {
        AppLive {
            name: name.into(),
            path: format!("C:\\Apps\\{name}"),
            rate: Rate { down, up },
            connections: conns,
            today: Totals { rx: today, tx: 0 },
            ..Default::default()
        }
    }

    #[test]
    fn sorting_and_search() {
        let apps = vec![
            app("beta.exe", 10.0, 5.0, 3, 100),
            app("Alpha.exe", 10.0, 9.0, 1, 900),
            app("gamma.exe", 99.0, 0.0, 7, 5),
        ];
        let names = |sort| -> Vec<String> {
            sorted_apps(&apps, "", sort)
                .into_iter()
                .map(|a| a.name)
                .collect()
        };
        assert_eq!(
            names((AppSort::Down, false)),
            ["gamma.exe", "Alpha.exe", "beta.exe"]
        );
        assert_eq!(
            names((AppSort::Name, true)),
            ["Alpha.exe", "beta.exe", "gamma.exe"]
        );
        assert_eq!(
            names((AppSort::Connections, true)),
            ["Alpha.exe", "beta.exe", "gamma.exe"]
        );
        assert_eq!(
            names((AppSort::Today, false)),
            ["Alpha.exe", "beta.exe", "gamma.exe"]
        );
        assert_eq!(names((AppSort::Up, false))[0], "Alpha.exe");
        let found = sorted_apps(&apps, "  GAM ", (AppSort::Name, true));
        assert_eq!(found.len(), 1);
        assert_eq!(
            sorted_apps(&apps, "apps\\be", (AppSort::Name, true)).len(),
            1
        );
        assert!(sorted_apps(&apps, "zzz", (AppSort::Name, true)).is_empty());
    }

    #[test]
    fn share_bars() {
        let rows = vec![
            UsageRow {
                key: "a".into(),
                totals: Totals { rx: 300, tx: 100 },
            },
            UsageRow {
                key: "b".into(),
                totals: Totals { rx: 100, tx: 0 },
            },
        ];
        assert_eq!(shares(&rows), vec![1.0, 0.25]);
        assert_eq!(shares(&[UsageRow::default()]), vec![0.0]);
        assert!(shares(&[]).is_empty());
    }

    #[test]
    fn ranges() {
        let today = Day {
            y: 2026,
            m: 3,
            d: 10,
        };
        assert_eq!(Range::ThisMonth.days(today).0.d, 1);
        assert_eq!(Range::ThisMonth.days(today).1, today);
        assert_eq!(Range::Week.days(today).1, today);
    }

    #[test]
    fn export_tables() {
        let apps = vec![app("a.exe", 2048.0, 0.0, 2, 1024)];
        let t = live_table(&apps, fmt::Units::Bytes);
        assert_eq!(t.columns.len(), t.rows[0].len());
        assert_eq!(t.rows[0][3], "2.00 KB/s");
        let tables = usage_tables(
            &[(
                Day {
                    y: 2026,
                    m: 1,
                    d: 2,
                },
                Totals { rx: 5, tx: 6 },
            )],
            &[UsageRow {
                key: "a.exe".into(),
                totals: Totals { rx: 1, tx: 2 },
            }],
            &[],
        );
        assert_eq!(tables.len(), 3);
        assert_eq!(tables[0].rows[0][0], "2026-01-02");
        assert_eq!(tables[1].rows[0][4], "2");
        assert!(tables[2].rows.is_empty());
    }
}
