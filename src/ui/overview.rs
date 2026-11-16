//! Overview page: live rates, totals, the current connection, Wi-Fi signal,
//! adapters, the busiest apps and recent daily usage.

use super::app::{App, Tab};
use super::charts::{self, Bar, LineChart, Series};
use super::theme::{pal, regular, semibold, Icon};
use super::widgets;
use crate::fmt;
use eframe::egui::{self, vec2, Align2, RichText, Sense, Ui};
use wf_traffic::{AdapterKind, Day, PerAppMode, Totals};

#[derive(Default)]
pub struct OverviewPage {
    /// Show adapters that are virtual or not connected.
    pub show_all_adapters: bool,
}

/// `(from, to)` of the last `days` days ending today.
pub fn last_days(today: Day, days: u32) -> (Day, Day) {
    (today.minus_days(days.saturating_sub(1)), today)
}

/// "Mon", "Tue", ...
pub fn weekday_name(weekday: u32) -> &'static str {
    ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][(weekday % 7) as usize]
}

/// Daily usage as chart bars (download below, upload on top).
pub fn usage_bars(days: &[(Day, Totals)]) -> Vec<Bar> {
    days.iter()
        .map(|(day, t)| Bar {
            label: fmt::day_label(day.m, day.d),
            title: format!(
                "{} {}",
                weekday_name(day.weekday()),
                fmt::day_label(day.m, day.d)
            ),
            parts: vec![t.rx as f64, t.tx as f64],
        })
        .collect()
}

impl App {
    pub(super) fn overview_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let adapter = self.primary_adapter().cloned();
        let subtitle = match &adapter {
            Some(a) if a.kind == AdapterKind::WiFi && self.link.is_some() => format!(
                "Connected through {} to {}",
                a.name,
                self.link.as_ref().map(|l| l.ssid.as_str()).unwrap_or("")
            ),
            Some(a) => format!("Connected through {} ({})", a.name, a.kind.label()),
            None if self.adapters.is_empty() && !self.demo => "Reading the adapters…".to_string(),
            None => "Not connected to a network".to_string(),
        };
        widgets::page_header(ui, "Overview", &subtitle, |_| {});

        App::scroll(ui, "overview", |ui| {
            self.overview_traffic_row(ui);
            ui.add_space(12.0);
            self.overview_connection_row(ui, adapter.as_ref());
            ui.add_space(12.0);
            self.overview_usage_row(ui);
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(Icon::LOCK.glyph()).size(12.0).color(p.faint));
                ui.label(
                    RichText::new(
                        "Everything shown here is measured on this PC and stays on this PC. \
                         WireForge contacts the internet only when you start a speed test, \
                         ask for your public IP address or run a tool.",
                    )
                    .size(12.0)
                    .color(p.faint),
                );
            });
        });
    }

    fn overview_traffic_row(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let units = self.units();
        let snap = self.snap.clone();
        widgets::columns_weighted(ui, &[2.25, 1.0], |col, ui| {
            if col == 0 {
                widgets::card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 12.0;
                        for (icon, color, label, value, peak) in [
                            (
                                Icon::DOWNLOAD,
                                p.down,
                                "Download",
                                snap.rate.down,
                                snap.peak.down,
                            ),
                            (Icon::UPLOAD, p.up, "Upload", snap.rate.up, snap.peak.up),
                        ] {
                            ui.allocate_ui_with_layout(
                                vec2(236.0, 66.0),
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    ui.spacing_mut().item_spacing.x = 10.0;
                                    let (r, _) =
                                        ui.allocate_exact_size(vec2(38.0, 38.0), Sense::hover());
                                    ui.painter().circle_filled(
                                        r.center(),
                                        19.0,
                                        color.gamma_multiply(0.16),
                                    );
                                    ui.painter().text(
                                        r.center(),
                                        Align2::CENTER_CENTER,
                                        icon.glyph(),
                                        regular(17.0),
                                        color,
                                    );
                                    ui.vertical(|ui| {
                                        ui.spacing_mut().item_spacing.y = 0.0;
                                        ui.label(RichText::new(label).size(12.5).color(p.muted));
                                        // A fixed width keeps the row from jumping as digits change.
                                        let (r, _) = ui
                                            .allocate_exact_size(vec2(170.0, 30.0), Sense::hover());
                                        widgets::text_in(
                                            ui,
                                            r,
                                            &fmt::rate(value, units),
                                            semibold(24.0),
                                            p.text,
                                        );
                                        ui.label(
                                            RichText::new(format!(
                                                "Peak {}",
                                                fmt::rate(peak, units)
                                            ))
                                            .size(12.0)
                                            .color(p.faint),
                                        );
                                    });
                                },
                            );
                        }
                    });
                    ui.add_space(4.0);
                    let down: Vec<f64> = snap.history.iter().map(|r| r.down).collect();
                    let up: Vec<f64> = snap.history.iter().map(|r| r.up).collect();
                    let top = down.iter().chain(up.iter()).copied().fold(0.0, f64::max);
                    let y_fmt = |v: f64| fmt::rate(v, units);
                    let x_fmt = |slot: usize, slots: usize| {
                        let secs = (slots - 1 - slot) as i64;
                        if secs == 0 {
                            "Now".to_string()
                        } else {
                            format!("{} ago", fmt::duration(secs))
                        }
                    };
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
                    chart.height = 172.0;
                    chart.y_max = Some(fmt::rate_ceiling(top, units));
                    chart.slots = 300;
                    chart.x_left = "5 minutes ago";
                    chart.x_right = "Now";
                    chart.x_fmt = Some(&x_fmt);
                    chart.legend = false;
                    charts::line_chart(ui, &chart);
                });
            } else {
                widgets::card(ui, |ui| {
                    ui.set_min_height(268.0);
                    widgets::section(ui, "Data used");
                    ui.add_space(2.0);
                    for (label, t, hint) in [
                        ("Today", snap.today, "Since midnight, all adapters"),
                        ("This month", snap.month, "Since the first of the month"),
                        ("This session", snap.session, "Since WireForge was started"),
                    ] {
                        let (rect, resp) = ui
                            .allocate_exact_size(vec2(ui.available_width(), 46.0), Sense::hover());
                        ui.painter().text(
                            rect.left_top() + vec2(0.0, 1.0),
                            Align2::LEFT_TOP,
                            label,
                            regular(12.5),
                            p.muted,
                        );
                        ui.painter().text(
                            rect.left_bottom() - vec2(0.0, 1.0),
                            Align2::LEFT_BOTTOM,
                            fmt::bytes(t.sum()),
                            semibold(20.0),
                            p.text,
                        );
                        for (i, (icon, color, v)) in
                            [(Icon::DOWNLOAD, p.down, t.rx), (Icon::UPLOAD, p.up, t.tx)]
                                .into_iter()
                                .enumerate()
                        {
                            let y = rect.top() + 14.0 + 19.0 * i as f32;
                            ui.painter().text(
                                egui::pos2(rect.right() - 78.0, y),
                                Align2::LEFT_CENTER,
                                icon.glyph(),
                                regular(10.5),
                                color,
                            );
                            ui.painter().text(
                                egui::pos2(rect.right(), y),
                                Align2::RIGHT_CENTER,
                                fmt::bytes(v),
                                regular(12.5),
                                p.muted,
                            );
                        }
                        resp.on_hover_text(hint);
                        ui.add_space(3.0);
                    }
                    if self.settings.cap_enabled {
                        widgets::divider(ui);
                        ui.add_space(2.0);
                        let today = Day::today();
                        let (from, to) =
                            wf_traffic::usage::cycle_range(today, self.settings.cap_start_day);
                        let used = self.usage.range_total(from, to).sum();
                        let status = wf_traffic::usage::cap_status(
                            used,
                            self.settings.cap_bytes(),
                            self.settings.cap_warn_pct as f64 / 100.0,
                        );
                        let (color, word) = if status.exceeded {
                            (p.danger, "Allowance used up")
                        } else if status.warn {
                            (p.warn, "Getting close")
                        } else {
                            (p.good, "Within allowance")
                        };
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Data allowance").size(12.5).color(p.muted));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    widgets::badge(ui, word, color);
                                },
                            );
                        });
                        charts::meter_bar(ui, status.fraction as f32, color, 8.0);
                        ui.label(
                            RichText::new(format!(
                                "{} of {} since {}",
                                fmt::bytes(status.used),
                                fmt::bytes(status.cap),
                                fmt::day_label(from.m, from.d)
                            ))
                            .size(12.0)
                            .color(p.faint),
                        );
                    } else {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("No data allowance set.")
                                    .size(12.0)
                                    .color(p.faint),
                            );
                            if ui
                                .link(RichText::new("Set one").size(12.0))
                                .on_hover_text("Get a warning before a monthly limit is reached")
                                .clicked()
                            {
                                self.tab = Tab::Settings;
                            }
                        });
                    }
                });
            }
        });
    }

    fn overview_connection_row(&mut self, ui: &mut Ui, adapter: Option<&wf_traffic::AdapterInfo>) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let units = self.units();
        widgets::columns_weighted(ui, &[1.25, 1.0, 1.0], |col, ui| match col {
            0 => widgets::titled_card(
                ui,
                "Connection",
                |ui| {
                    if let Some(a) = adapter {
                        widgets::badge(ui, a.kind.label(), p.accent);
                    }
                },
                |ui| {
                    ui.set_min_height(246.0);
                    ui.spacing_mut().item_spacing.y = 3.0;
                    let Some(a) = adapter else {
                        ui.add_space(30.0);
                        ui.label(
                            RichText::new("No adapter is connected to a network right now.")
                                .color(p.muted),
                        );
                        return;
                    };
                    widgets::kv(ui, "Adapter", &format!("{} ({})", a.name, a.description));
                    widgets::kv(
                        ui,
                        "Link speed",
                        &if a.rx_link_bps == a.tx_link_bps {
                            fmt::link_speed(a.rx_link_bps)
                        } else {
                            format!(
                                "{} down, {} up",
                                fmt::link_speed(a.rx_link_bps),
                                fmt::link_speed(a.tx_link_bps)
                            )
                        },
                    );
                    widgets::kv(
                        ui,
                        "IPv4 address",
                        &a.ipv4
                            .iter()
                            .map(|n| format!("{}/{}", n.addr, n.prefix))
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                    // Global addresses first; link-local ones say little.
                    let mut v6: Vec<String> = a
                        .ipv6
                        .iter()
                        .filter(|n| (n.addr.segments()[0] & 0xffc0) != 0xfe80)
                        .map(|n| n.addr.to_string())
                        .collect();
                    if v6.is_empty() {
                        v6 = a.ipv6.iter().map(|n| n.addr.to_string()).collect();
                    }
                    widgets::kv(ui, "IPv6 address", &v6.join(", "));
                    widgets::kv(
                        ui,
                        "Gateway",
                        &a.gateways
                            .iter()
                            .map(|g| g.to_string())
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                    widgets::kv(
                        ui,
                        "DNS servers",
                        &a.dns_servers
                            .iter()
                            .map(|g| g.to_string())
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                    let lease = match (a.dhcp_enabled, a.lease_expires) {
                        (true, Some(t)) if t > self.now => {
                            format!(
                                "Automatic (DHCP), renews in {}",
                                fmt::duration(t - self.now)
                            )
                        }
                        (true, _) => "Automatic (DHCP)".to_string(),
                        (false, _) => "Set by hand (static)".to_string(),
                    };
                    widgets::kv(ui, "Address setup", &lease);
                    widgets::kv(ui, "MAC address", &a.mac);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        let (rect, _) = ui.allocate_exact_size(vec2(124.0, 24.0), Sense::hover());
                        widgets::text_in(ui, rect, "Public IP address", regular(13.0), p.faint);
                        match &self.public_ip {
                            Some(Ok(ip)) => {
                                ui.add(
                                    egui::Label::new(RichText::new(ip).size(13.5)).selectable(true),
                                );
                                if ui.link(RichText::new("Hide").size(12.5)).clicked() {
                                    self.public_ip = None;
                                }
                            }
                            Some(Err(e)) => {
                                ui.add(
                                    egui::Label::new(RichText::new(e).size(12.5).color(p.danger))
                                        .truncate(),
                                );
                            }
                            None if self.public_ip_busy => {
                                ui.add(egui::Spinner::new().size(14.0).color(p.accent));
                            }
                            None => {
                                let (name, url) = wf_tools::publicip::service();
                                let tip = if name.is_empty() {
                                    "Asks a public service which address your connection uses. \
                                     Nothing is asked until you click."
                                        .to_string()
                                } else {
                                    format!(
                                        "Asks {name} ({url}) which address your connection uses. \
                                         Nothing is asked until you click."
                                    )
                                };
                                if ui
                                    .link(RichText::new("Show (asks the internet)").size(13.0))
                                    .on_hover_text(tip)
                                    .clicked()
                                {
                                    self.fetch_public_ip(&ctx);
                                }
                            }
                        }
                    });
                },
            ),
            1 => {
                let link = self.link.clone();
                widgets::titled_card(
                    ui,
                    "Wi-Fi signal",
                    |ui| {
                        if let Some(l) = &link {
                            let color = charts::signal_color(ui, l.rssi_dbm);
                            widgets::badge(ui, wf_wifi::channels::signal_word(l.rssi_dbm), color);
                        }
                    },
                    |ui| {
                        ui.set_min_height(246.0);
                        let Some(l) = &link else {
                            ui.add_space(30.0);
                            ui.label(
                                RichText::new(
                                    if adapter
                                        .map(|a| a.kind == AdapterKind::Ethernet)
                                        .unwrap_or(false)
                                    {
                                        "This PC is connected by cable. Wi-Fi is not in use."
                                    } else {
                                        "Not connected to a Wi-Fi network."
                                    },
                                )
                                .color(p.muted),
                            );
                            return;
                        };
                        let color = charts::signal_color(ui, l.rssi_dbm);
                        ui.horizontal(|ui| {
                            let (r, _) = ui.allocate_exact_size(vec2(34.0, 30.0), Sense::hover());
                            charts::signal_bars(ui, r.shrink2(vec2(2.0, 3.0)), l.quality, color);
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 0.0;
                                ui.add(
                                    egui::Label::new(RichText::new(&l.ssid).font(semibold(17.0)))
                                        .truncate(),
                                );
                                ui.label(
                                    RichText::new(format!("{} dBm, {} %", l.rssi_dbm, l.quality))
                                        .size(12.5)
                                        .color(p.muted),
                                );
                            });
                        });
                        ui.add_space(2.0);
                        let (rect, _) = ui
                            .allocate_exact_size(vec2(ui.available_width(), 46.0), Sense::hover());
                        // Signal over time, drawn against a fixed -95..-30 dBm scale.
                        let scaled: Vec<f64> = self
                            .signal_history
                            .iter()
                            .map(|v| {
                                if v.is_finite() {
                                    (v + 95.0).max(0.0)
                                } else {
                                    0.0
                                }
                            })
                            .collect();
                        charts::sparkline(ui, rect, &scaled, p.third);
                        ui.label(
                            RichText::new("Signal over the last minutes")
                                .size(11.5)
                                .color(p.faint),
                        );
                        ui.add_space(2.0);
                        ui.spacing_mut().item_spacing.y = 3.0;
                        widgets::kv(
                            ui,
                            "Band and channel",
                            &format!(
                                "{}, channel {}{}",
                                l.band.label(),
                                l.channel,
                                l.width_mhz
                                    .map(|w| format!(" ({w} MHz)"))
                                    .unwrap_or_default()
                            ),
                        );
                        widgets::kv(
                            ui,
                            "Standard",
                            &match l.generation {
                                Some(g) => format!("Wi-Fi {g} ({})", l.phy),
                                None => l.phy.clone(),
                            },
                        );
                        widgets::kv(
                            ui,
                            "Link rate",
                            &format!("{:.0} / {:.0} Mbit/s", l.rx_rate_mbps, l.tx_rate_mbps),
                        );
                        widgets::kv(ui, "Security", &l.security);
                    },
                );
            }
            _ => {
                let show_all = self.overview.show_all_adapters;
                let mut flip = false;
                let hidden = self
                    .snap
                    .adapters
                    .iter()
                    .filter(|a| !adapter_is_main(a))
                    .count();
                widgets::titled_card(
                    ui,
                    "Adapters",
                    |ui| {
                        if hidden > 0 {
                            let label = if show_all {
                                "Show fewer".to_string()
                            } else {
                                format!("Show all ({})", self.snap.adapters.len())
                            };
                            if ui.link(RichText::new(label).size(12.5)).clicked() {
                                flip = true;
                            }
                        }
                    },
                    |ui| {
                        ui.set_min_height(246.0);
                        let list: Vec<&wf_traffic::AdapterLive> = self
                            .snap
                            .adapters
                            .iter()
                            .filter(|a| show_all || adapter_is_main(a))
                            .collect();
                        if list.is_empty() {
                            ui.add_space(30.0);
                            ui.label(RichText::new("No adapters found yet.").color(p.muted));
                        }
                        egui::ScrollArea::vertical()
                            .id_salt("overview-adapters")
                            .max_height(238.0)
                            .show(ui, |ui| {
                                for a in list {
                                    let (rect, _) = ui.allocate_exact_size(
                                        vec2(ui.available_width(), 46.0),
                                        Sense::hover(),
                                    );
                                    let icon = match a.kind {
                                        AdapterKind::WiFi => Icon::WIFI,
                                        AdapterKind::Ethernet => Icon::ETHERNET,
                                        _ => Icon::CONNECTIONS,
                                    };
                                    ui.painter().text(
                                        rect.left_center() + vec2(12.0, 0.0),
                                        Align2::CENTER_CENTER,
                                        icon.glyph(),
                                        regular(16.0),
                                        if a.up { p.accent } else { p.faint },
                                    );
                                    let name_rect = egui::Rect::from_min_max(
                                        rect.left_top() + vec2(30.0, 3.0),
                                        egui::pos2(rect.right() - 96.0, rect.center().y + 1.0),
                                    );
                                    widgets::text_in(
                                        ui,
                                        name_rect,
                                        &a.name,
                                        semibold(13.5),
                                        if a.up { p.text } else { p.muted },
                                    );
                                    let sub_rect = egui::Rect::from_min_max(
                                        egui::pos2(name_rect.left(), rect.center().y),
                                        egui::pos2(rect.right() - 96.0, rect.bottom() - 3.0),
                                    );
                                    let sub = if a.up {
                                        format!(
                                            "{}, {} this session",
                                            a.kind.label(),
                                            fmt::bytes(a.session.sum())
                                        )
                                    } else {
                                        format!("{}, not connected", a.kind.label())
                                    };
                                    widgets::text_in(ui, sub_rect, &sub, regular(12.0), p.faint);
                                    if a.up {
                                        for (i, (icon, color, v)) in [
                                            (Icon::DOWNLOAD, p.down, a.rate.down),
                                            (Icon::UPLOAD, p.up, a.rate.up),
                                        ]
                                        .into_iter()
                                        .enumerate()
                                        {
                                            let y = rect.top() + 13.0 + 19.0 * i as f32;
                                            ui.painter().text(
                                                egui::pos2(rect.right() - 86.0, y),
                                                Align2::LEFT_CENTER,
                                                icon.glyph(),
                                                regular(10.5),
                                                color,
                                            );
                                            ui.painter().text(
                                                egui::pos2(rect.right() - 2.0, y),
                                                Align2::RIGHT_CENTER,
                                                fmt::rate(v, units),
                                                regular(12.5),
                                                p.muted,
                                            );
                                        }
                                    }
                                }
                            });
                    },
                );
                if flip {
                    self.overview.show_all_adapters = !show_all;
                }
            }
        });
    }

    fn overview_usage_row(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let units = self.units();
        let mut go_apps = false;
        widgets::columns_weighted(ui, &[1.0, 1.25], |col, ui| {
            if col == 0 {
                widgets::titled_card(
                    ui,
                    "Busiest apps right now",
                    |ui| {
                        if ui.link(RichText::new("All apps").size(12.5)).clicked() {
                            go_apps = true;
                        }
                    },
                    |ui| {
                        ui.set_min_height(196.0);
                        let mut apps: Vec<wf_traffic::AppLive> = self.snap.apps.clone();
                        let by_rate = matches!(self.snap.per_app_mode, PerAppMode::Etw);
                        if by_rate {
                            apps.sort_by(|a, b| {
                                (b.rate.down + b.rate.up).total_cmp(&(a.rate.down + a.rate.up))
                            });
                        } else {
                            apps.sort_by_key(|a| std::cmp::Reverse(a.connections));
                        }
                        if !by_rate {
                            let why = match &self.snap.per_app_mode {
                                PerAppMode::ConnectionsOnly(_) if !self.elevated => {
                                    "Per-app speeds need administrator rights. Showing the apps \
                                     with the most connections instead."
                                }
                                PerAppMode::ConnectionsOnly(_) => {
                                    "Per-app speeds are not available. Showing the apps with the \
                                     most connections instead."
                                }
                                _ => "Starting to measure…",
                            };
                            ui.label(RichText::new(why).size(12.0).color(p.faint));
                        }
                        if apps.is_empty() {
                            ui.add_space(20.0);
                            ui.label(RichText::new("No app is using the network.").color(p.muted));
                        }
                        for a in apps.iter().take(5) {
                            let tex = self.icon(&a.name, &a.path);
                            let (rect, _) = ui.allocate_exact_size(
                                vec2(ui.available_width(), 32.0),
                                Sense::hover(),
                            );
                            let icon_rect = egui::Rect::from_center_size(
                                rect.left_center() + vec2(12.0, 0.0),
                                vec2(22.0, 22.0),
                            );
                            widgets::program_icon(ui, icon_rect, &a.name, tex.as_ref());
                            let name_rect = egui::Rect::from_min_max(
                                rect.left_top() + vec2(34.0, 0.0),
                                egui::pos2(rect.right() - 190.0, rect.bottom()),
                            );
                            widgets::text_in(ui, name_rect, &a.name, regular(13.5), p.text);
                            if by_rate {
                                for (i, (icon, color, v)) in [
                                    (Icon::DOWNLOAD, p.down, a.rate.down),
                                    (Icon::UPLOAD, p.up, a.rate.up),
                                ]
                                .into_iter()
                                .enumerate()
                                {
                                    let right = rect.right() - 94.0 * (1 - i) as f32;
                                    ui.painter().text(
                                        egui::pos2(right - 88.0, rect.center().y),
                                        Align2::LEFT_CENTER,
                                        icon.glyph(),
                                        regular(10.5),
                                        color,
                                    );
                                    ui.painter().text(
                                        egui::pos2(right, rect.center().y),
                                        Align2::RIGHT_CENTER,
                                        fmt::rate(v, units),
                                        regular(12.5),
                                        p.muted,
                                    );
                                }
                            } else {
                                ui.painter().text(
                                    rect.right_center(),
                                    Align2::RIGHT_CENTER,
                                    format!("{} connections", a.connections),
                                    regular(12.5),
                                    p.muted,
                                );
                            }
                        }
                    },
                );
            } else {
                widgets::titled_card(
                    ui,
                    "Last 14 days",
                    |ui| {
                        let (from, to) = last_days(Day::today(), 14);
                        let total = self.usage.range_total(from, to);
                        ui.label(
                            RichText::new(format!("{} in total", fmt::bytes(total.sum())))
                                .size(12.5)
                                .color(p.muted),
                        );
                    },
                    |ui| {
                        ui.set_min_height(196.0);
                        let (from, to) = last_days(Day::today(), 14);
                        let days = self.usage.by_day(from, to);
                        if days.iter().all(|(_, t)| t.sum() == 0) {
                            ui.add_space(40.0);
                            ui.label(
                                RichText::new(
                                    "Usage history builds up while WireForge is running. \
                                     Come back later today.",
                                )
                                .color(p.muted),
                            );
                            return;
                        }
                        let bars = usage_bars(&days);
                        charts::bar_chart_with(
                            ui,
                            &bars,
                            &[("Download", p.down), ("Upload", p.up)],
                            150.0,
                            &|v| fmt::bytes(v as u64),
                            false,
                            &fmt::bytes_ceiling,
                        );
                    },
                );
            }
        });
        if go_apps {
            self.tab = Tab::Apps;
        }
    }
}

/// Adapters worth showing by default: real hardware, or anything that is up
/// and not a loopback.
fn adapter_is_main(a: &wf_traffic::AdapterLive) -> bool {
    match a.kind {
        AdapterKind::WiFi | AdapterKind::Ethernet | AdapterKind::Cellular => true,
        AdapterKind::Loopback => false,
        _ => a.up && a.session.sum() > 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bars_from_days() {
        let days = vec![
            (
                Day {
                    y: 2026,
                    m: 11,
                    d: 15,
                },
                Totals { rx: 10, tx: 2 },
            ),
            (
                Day {
                    y: 2026,
                    m: 11,
                    d: 16,
                },
                Totals { rx: 0, tx: 0 },
            ),
        ];
        let bars = usage_bars(&days);
        assert_eq!(bars.len(), 2);
        assert_eq!(bars[0].label, "15 Nov");
        assert_eq!(bars[0].parts, vec![10.0, 2.0]);
        assert_eq!(weekday_name(0), "Mon");
        assert_eq!(weekday_name(6), "Sun");
        assert_eq!(weekday_name(9), "Wed");
    }

    #[test]
    fn main_adapters() {
        let mk = |kind, up, bytes| wf_traffic::AdapterLive {
            kind,
            up,
            session: Totals { rx: bytes, tx: 0 },
            ..Default::default()
        };
        assert!(adapter_is_main(&mk(AdapterKind::WiFi, false, 0)));
        assert!(adapter_is_main(&mk(AdapterKind::Ethernet, false, 0)));
        assert!(!adapter_is_main(&mk(AdapterKind::Loopback, true, 99)));
        assert!(!adapter_is_main(&mk(AdapterKind::Virtual, true, 0)));
        assert!(adapter_is_main(&mk(AdapterKind::Virtual, true, 5)));
        assert!(!adapter_is_main(&mk(AdapterKind::Tunnel, false, 5)));
    }
}
