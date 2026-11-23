//! Settings page and the About dialog.

use super::app::{App, Confirm};
use super::theme::{self, pal, pal_ctx, semibold, Icon};
use super::widgets;
use crate::fmt::Units;
use crate::settings::ThemeChoice;
use crate::sys;
use eframe::egui::{self, vec2, Color32, Rect, RichText, Sense, Ui};

/// One setting: title and explanation on the left, the control on the right.
fn row(ui: &mut Ui, title: &str, text: &str, control: impl FnOnce(&mut Ui)) {
    let p = pal(ui);
    ui.allocate_ui_with_layout(
        vec2(ui.available_width(), 46.0),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                ui.set_max_width((ui.available_width() - 270.0).max(200.0));
                ui.label(RichText::new(title).size(14.0));
                ui.add(egui::Label::new(RichText::new(text).size(12.0).color(p.faint)).wrap());
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), control);
        },
    );
}

/// The choices offered for how long usage history is kept: `(days, label)`.
pub const KEEP_CHOICES: [(u32, &str); 5] = [
    (90, "3 months"),
    (180, "6 months"),
    (400, "13 months"),
    (1100, "3 years"),
    (0, "Forever"),
];

pub fn keep_label(days: u32) -> String {
    KEEP_CHOICES
        .iter()
        .find(|(d, _)| *d == days)
        .map(|(_, l)| l.to_string())
        .unwrap_or_else(|| format!("{days} days"))
}

impl App {
    pub(super) fn settings_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        if self.confirmed("settings.clear-usage") {
            if let Some(m) = &self.monitor {
                m.clear_usage();
                self.usage = m.usage();
            }
            if self.demo {
                self.toast("Demo mode: nothing was deleted.", false);
            } else {
                self.toast("The usage history was deleted.", false);
            }
        }
        widgets::page_header(
            ui,
            "Settings",
            "Saved automatically. Everything WireForge stores is in one folder on this PC.",
            |ui| {
                if widgets::ghost_button(ui, &Icon::INFO.with("About")).clicked() {
                    self.about_open = true;
                }
            },
        );
        let mut changed = false;
        let mut tray_changed = false;
        App::scroll(ui, "settings", |ui| {
            ui.set_max_width(860.0);

            widgets::titled_card(
                ui,
                "Appearance",
                |_| {},
                |ui| {
                    row(
                        ui,
                        "Theme",
                        "Dark, light, or whatever Windows uses.",
                        |ui| {
                            let current = match self.settings.theme {
                                ThemeChoice::Dark => 0,
                                ThemeChoice::Light => 1,
                                ThemeChoice::System => 2,
                            };
                            if let Some(i) =
                                widgets::segmented(ui, &["Dark", "Light", "System"], current)
                            {
                                self.settings.theme =
                                    [ThemeChoice::Dark, ThemeChoice::Light, ThemeChoice::System][i];
                                theme::apply_choice(&ctx, self.settings.theme);
                                changed = true;
                            }
                        },
                    );
                    row(
                        ui,
                        "Speed units",
                        "Bytes (MB/s) are what download windows show. Bits (Mbit/s) are what \
                     internet providers advertise: 8 Mbit/s is 1 MB/s.",
                        |ui| {
                            let current = usize::from(self.settings.units == Units::Bits);
                            if let Some(i) =
                                widgets::segmented(ui, &["MB/s (bytes)", "Mbit/s (bits)"], current)
                            {
                                self.settings.units =
                                    if i == 0 { Units::Bytes } else { Units::Bits };
                                changed = true;
                            }
                        },
                    );
                },
            );
            ui.add_space(12.0);

            widgets::titled_card(
                ui,
                "Running in the background",
                |_| {},
                |ui| {
                    row(
                    ui,
                    "Icon in the notification area",
                    "Hover it for the current download and upload speed. Right-click for a menu.",
                    |ui| {
                        if widgets::toggle(ui, self.settings.tray_icon, true).clicked() {
                            self.settings.tray_icon = !self.settings.tray_icon;
                            changed = true;
                            tray_changed = true;
                        }
                    },
                );
                    row(
                        ui,
                        "Keep running when the window is closed",
                        "Closing the window hides WireForge in the notification area, so usage \
                     keeps being counted. Use Exit in the icon's menu to quit.",
                        |ui| {
                            if widgets::toggle(
                                ui,
                                self.settings.close_to_tray && self.settings.tray_icon,
                                self.settings.tray_icon,
                            )
                            .clicked()
                            {
                                self.settings.close_to_tray = !self.settings.close_to_tray;
                                changed = true;
                            }
                        },
                    );
                    row(
                        ui,
                        "Floating meter",
                        "A small always-on-top window with the live speeds. Drag it anywhere; \
                     double-click it to open WireForge.",
                        |ui| {
                            if widgets::toggle(ui, self.settings.mini_meter, true).clicked() {
                                self.settings.mini_meter = !self.settings.mini_meter;
                                changed = true;
                                tray_changed = true;
                            }
                        },
                    );
                    let id = egui::Id::new("startup-entry");
                    let cached: Option<bool> = ui.data(|d| d.get_temp(id));
                    let on = match cached {
                        Some(v) => v,
                        None => {
                            let v = !self.demo && sys::startup_enabled();
                            ui.data_mut(|d| d.insert_temp(id, v));
                            v
                        }
                    };
                    row(
                        ui,
                        "Start with Windows",
                        "Starts WireForge hidden in the notification area when you sign in \
                     (an entry in your own startup list, no administrator rights needed).",
                        |ui| {
                            if widgets::toggle(ui, on, true).clicked() {
                                if self.demo {
                                    self.toast(
                                        "Demo mode: the startup list is not changed.",
                                        false,
                                    );
                                } else {
                                    match sys::set_startup(!on) {
                                        Ok(()) => {
                                            ui.data_mut(|d| d.insert_temp(id, !on));
                                            if !on && !self.settings.tray_icon {
                                                self.settings.tray_icon = true;
                                                changed = true;
                                                tray_changed = true;
                                            }
                                        }
                                        Err(e) => self.toast(e, true),
                                    }
                                }
                            }
                        },
                    );
                },
            );
            ui.add_space(12.0);

            widgets::titled_card(
                ui,
                "Monitoring",
                |_| {},
                |ui| {
                    row(
                        ui,
                        "Count bytes per app",
                        if self.elevated {
                            "Uses the Windows network trace. Takes effect the next time WireForge starts."
                        } else {
                            "Windows only allows this for administrators: use \"Restart as \
                         administrator\" at the top. Takes effect the next time WireForge starts."
                        },
                        |ui| {
                            if widgets::toggle(ui, self.settings.per_app, true).clicked() {
                                self.settings.per_app = !self.settings.per_app;
                                changed = true;
                            }
                        },
                    );
                    row(
                        ui,
                        "Look up host names",
                        "Shows names instead of bare addresses on the Apps and Connections pages. \
                     This asks your DNS server about each address, so it is off by default.",
                        |ui| {
                            if widgets::toggle(ui, self.settings.resolve_hosts, true).clicked() {
                                self.settings.resolve_hosts = !self.settings.resolve_hosts;
                                if let Some(m) = &self.monitor {
                                    m.set_resolve_hosts(self.settings.resolve_hosts);
                                }
                                changed = true;
                            }
                        },
                    );
                    row(
                        ui,
                        "Keep usage history for",
                        "Older days are removed from the history file.",
                        |ui| {
                            egui::ComboBox::from_id_salt("keep-days")
                                .selected_text(keep_label(self.settings.keep_days))
                                .width(130.0)
                                .show_ui(ui, |ui| {
                                    for (days, label) in KEEP_CHOICES {
                                        if ui
                                            .selectable_label(
                                                self.settings.keep_days == days,
                                                label,
                                            )
                                            .clicked()
                                        {
                                            self.settings.keep_days = days;
                                            changed = true;
                                        }
                                    }
                                });
                        },
                    );
                    row(
                        ui,
                        "Usage history",
                        "Deletes every recorded day, for all apps and adapters.",
                        |ui| {
                            if widgets::ghost_button(ui, "Delete history\u{2026}").clicked() {
                                self.ask(Confirm {
                                    title: "Delete the usage history?".into(),
                                    intro:
                                        "All recorded data usage is removed. This cannot be undone."
                                            .into(),
                                    lines: vec![
                                        "Usage by day, app and adapter".into(),
                                        "Totals for today and this month start again from zero"
                                            .into(),
                                    ],
                                    button: "Delete history".into(),
                                    danger: true,
                                    tag: "settings.clear-usage".into(),
                                });
                            }
                        },
                    );
                },
            );
            ui.add_space(12.0);

            widgets::titled_card(
                ui,
                "Data allowance",
                |_| {},
                |ui| {
                    row(
                        ui,
                        "Monthly data allowance",
                        "For connections with a monthly limit. WireForge only counts what this PC \
                     uses, not other devices on the same connection.",
                        |ui| {
                            if widgets::toggle(ui, self.settings.cap_enabled, true).clicked() {
                                self.settings.cap_enabled = !self.settings.cap_enabled;
                                changed = true;
                            }
                        },
                    );
                    if self.settings.cap_enabled {
                        row(
                            ui,
                            "Allowance",
                            "How much data one period includes.",
                            |ui| {
                                ui.label(RichText::new("GB").color(p.muted));
                                let r = ui.add(
                                    egui::DragValue::new(&mut self.settings.cap_gb)
                                        .range(0.1..=100_000.0)
                                        .speed(1.0)
                                        .max_decimals(1),
                                );
                                changed |= r.changed();
                            },
                        );
                        row(
                            ui,
                            "Period starts on day",
                            "The day of the month your allowance starts again (1 to 28).",
                            |ui| {
                                let r = ui.add(
                                    egui::DragValue::new(&mut self.settings.cap_start_day)
                                        .range(1..=28)
                                        .speed(0.1),
                                );
                                changed |= r.changed();
                            },
                        );
                        row(
                            ui,
                            "Warn me at",
                            "A notice appears once when this share is used, and once when the \
                         allowance is used up.",
                            |ui| {
                                ui.label(RichText::new("%").color(p.muted));
                                let r = ui.add(
                                    egui::DragValue::new(&mut self.settings.cap_warn_pct)
                                        .range(10..=100)
                                        .speed(0.5),
                                );
                                changed |= r.changed();
                                if widgets::toggle(ui, self.settings.alert_cap, true)
                                    .on_hover_text("Turn the allowance notices on or off")
                                    .clicked()
                                {
                                    self.settings.alert_cap = !self.settings.alert_cap;
                                    changed = true;
                                }
                            },
                        );
                    }
                },
            );
            ui.add_space(12.0);

            widgets::titled_card(
                ui,
                "Alerts",
                |_| {},
                |ui| {
                    row(
                        ui,
                        "New device on my network",
                        "After a device scan, tell me when a device shows up that was never seen \
                     before.",
                        |ui| {
                            if widgets::toggle(ui, self.settings.alert_new_device, true).clicked() {
                                self.settings.alert_new_device = !self.settings.alert_new_device;
                                changed = true;
                            }
                        },
                    );
                    row(
                        ui,
                        "New app on the internet",
                        "Ask whether to allow or block a program the first time it connects to the internet (Firewall page).",
                        |ui| {
                            if widgets::toggle(ui, self.settings.fw_alerts, true).clicked() {
                                self.settings.fw_alerts = !self.settings.fw_alerts;
                                changed = true;
                            }
                        },
                    );
                    row(
                        ui,
                        "Scan for devices every 10 minutes",
                        "Checks your own local network in the background while WireForge runs.",
                        |ui| {
                            if widgets::toggle(ui, self.settings.devices_auto_scan, true).clicked()
                            {
                                self.settings.devices_auto_scan = !self.settings.devices_auto_scan;
                                changed = true;
                            }
                        },
                    );
                },
            );
            ui.add_space(12.0);

            widgets::titled_card(
                ui,
                "Privacy",
                |ui| {
                    widgets::badge(ui, &Icon::LOCK.with("Stays on this PC"), p.good);
                },
                |ui| {
                    ui.spacing_mut().item_spacing.y = 5.0;
                    for line in [
                        "WireForge has no account, no telemetry and no update check. What it \
                         measures is stored only in the folder below.",
                        "It contacts the internet only when you click: the speed test \
                         (Measurement Lab, which publishes test results including your IP \
                         address; you are asked first), \"Show public IP address\" (ipify), and \
                         the tools you run yourself (ping, traceroute, DNS lookup, whois, port check).",
                        "Looking for devices only ever touches your own local network. Host-name \
                         lookups are off unless you turn them on.",
                        "Saved Wi-Fi passwords are read from Windows when you open that page and \
                         are never stored or sent anywhere by WireForge.",
                    ] {
                        ui.horizontal_top(|ui| {
                            ui.label(RichText::new("\u{2022}").color(p.good));
                            ui.add(
                                egui::Label::new(RichText::new(line).size(13.0).color(p.muted))
                                    .wrap(),
                            );
                        });
                    }
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if widgets::ghost_button(ui, &Icon::FOLDER.with("Open data folder"))
                            .clicked()
                        {
                            if self.demo {
                                self.toast("Demo mode: there is no data folder.", false);
                            } else {
                                let _ = std::fs::create_dir_all(&self.data_dir);
                                if let Err(e) = sys::open_folder(&self.data_dir) {
                                    self.toast(e, true);
                                }
                            }
                        }
                        ui.add(
                            egui::Label::new(
                                RichText::new(self.data_dir.display().to_string())
                                    .size(12.5)
                                    .color(p.faint),
                            )
                            .truncate()
                            .selectable(true),
                        );
                    });
                },
            );
        });
        if changed {
            self.settings = self.settings.clone().sanitized();
            self.save_settings();
        }
        if tray_changed {
            self.apply_tray_settings();
        }
    }

    pub(super) fn about_dialog(&mut self, ctx: &egui::Context) {
        if !self.about_open {
            return;
        }
        let p = pal_ctx(ctx);
        let mut close = false;
        let modal = egui::Modal::new(egui::Id::new("about"))
            .frame(widgets::modal_frame(&p).inner_margin(egui::Margin::same(28)))
            .show(ctx, |ui| {
                ui.set_width(400.0);
                ui.vertical_centered(|ui| {
                    let (rect, _) = ui.allocate_exact_size(vec2(84.0, 84.0), Sense::hover());
                    if let Some(logo) = &self.logo {
                        ui.painter().image(
                            logo.id(),
                            rect,
                            Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                            Color32::WHITE,
                        );
                    }
                    ui.add_space(6.0);
                    ui.label(RichText::new("WireForge").font(semibold(26.0)));
                    ui.label(
                        RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION")))
                            .color(p.muted),
                    );
                    ui.add_space(10.0);
                    ui.label(
                        "See what your network is doing: traffic, apps, Wi-Fi, devices and tools.",
                    );
                    ui.add_space(10.0);
                    ui.label(RichText::new("Developed by Zheer Khalid").font(semibold(15.0)));
                    ui.add_space(2.0);
                    ui.hyperlink_to(
                        RichText::new("zheer.dev").color(p.accent),
                        "https://zheer.dev",
                    );
                    ui.hyperlink_to(
                        RichText::new("github.com/zheerkhalid/wireforge").color(p.accent),
                        "https://github.com/zheerkhalid/wireforge",
                    );
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(
                            "Free and open source under the MIT License.\n\
                             Speed test by Measurement Lab (NDT7). MAC vendor names from the \
                             IEEE public registry. Everything else stays on this PC.",
                        )
                        .size(12.0)
                        .color(p.faint),
                    );
                    ui.add_space(14.0);
                    if widgets::primary_button(ui, "Close", true).clicked() {
                        close = true;
                    }
                });
            });
        if close || modal.should_close() {
            self.about_open = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_labels() {
        assert_eq!(keep_label(0), "Forever");
        assert_eq!(keep_label(400), "13 months");
        assert_eq!(keep_label(123), "123 days");
        // The default setting is one of the offered choices.
        let default = crate::settings::Settings::default().keep_days;
        assert!(KEEP_CHOICES.iter().any(|(d, _)| *d == default));
    }
}
