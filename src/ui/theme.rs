//! Colours, fonts and icon glyphs.

use crate::settings::ThemeChoice;
use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Stroke, TextStyle,
    Theme, ThemePreference, Visuals,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub const AZURE: Color32 = Color32::from_rgb(0x2c, 0xb4, 0xff);
pub const BLUE: Color32 = Color32::from_rgb(0x0b, 0x6f, 0xd6);
pub const CORAL: Color32 = Color32::from_rgb(0xff, 0x5a, 0x4e);
pub const AMBER: Color32 = Color32::from_rgb(0xf2, 0xa9, 0x3b);

#[derive(Clone, Copy)]
pub struct Palette {
    pub dark: bool,
    pub bg: Color32,
    pub rail: Color32,
    pub card: Color32,
    pub hover: Color32,
    pub selected: Color32,
    pub border: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub faint: Color32,
    /// Azure, tuned for contrast on this background.
    pub accent: Color32,
    pub on_accent: Color32,
    pub danger: Color32,
    pub warn: Color32,
    pub info: Color32,
    pub good: Color32,
    /// Chart series: download, upload, a third series.
    pub down: Color32,
    pub up: Color32,
    pub third: Color32,
}

pub fn palette(dark: bool) -> Palette {
    if dark {
        Palette {
            dark,
            bg: Color32::from_rgb(0x0e, 0x13, 0x19),
            rail: Color32::from_rgb(0x0a, 0x0e, 0x14),
            card: Color32::from_rgb(0x15, 0x1c, 0x25),
            hover: Color32::from_rgb(0x1b, 0x24, 0x30),
            selected: Color32::from_rgb(0x12, 0x2b, 0x44),
            border: Color32::from_rgb(0x25, 0x30, 0x3d),
            text: Color32::from_rgb(0xe8, 0xee, 0xf2),
            muted: Color32::from_rgb(0x9a, 0xa8, 0xb3),
            faint: Color32::from_rgb(0x64, 0x72, 0x7d),
            accent: AZURE,
            on_accent: Color32::from_rgb(0x03, 0x16, 0x2b),
            danger: CORAL,
            warn: AMBER,
            info: Color32::from_rgb(0x8f, 0x9c, 0xf5),
            good: Color32::from_rgb(0x34, 0xc7, 0x8a),
            down: Color32::from_rgb(0x2b, 0x8f, 0xf0),
            up: Color32::from_rgb(0xd6, 0x74, 0x28),
            third: Color32::from_rgb(0x2f, 0xa8, 0x7e),
        }
    } else {
        Palette {
            dark,
            bg: Color32::from_rgb(0xf3, 0xf6, 0xf8),
            rail: Color32::from_rgb(0xff, 0xff, 0xff),
            card: Color32::from_rgb(0xff, 0xff, 0xff),
            hover: Color32::from_rgb(0xec, 0xf1, 0xf4),
            selected: Color32::from_rgb(0xdd, 0xec, 0xfc),
            border: Color32::from_rgb(0xd9, 0xe1, 0xe7),
            text: Color32::from_rgb(0x14, 0x1f, 0x29),
            muted: Color32::from_rgb(0x56, 0x65, 0x72),
            faint: Color32::from_rgb(0x8c, 0x99, 0xa4),
            accent: BLUE,
            on_accent: Color32::WHITE,
            danger: Color32::from_rgb(0xe0, 0x3d, 0x31),
            warn: Color32::from_rgb(0xb8, 0x73, 0x0a),
            info: Color32::from_rgb(0x4b, 0x55, 0xc4),
            good: Color32::from_rgb(0x12, 0x8a, 0x5c),
            down: Color32::from_rgb(0x0b, 0x74, 0xd6),
            up: Color32::from_rgb(0xc8, 0x5a, 0x0a),
            third: Color32::from_rgb(0x1d, 0x8f, 0x6a),
        }
    }
}

pub fn pal(ui: &egui::Ui) -> Palette {
    palette(ui.visuals().dark_mode)
}

pub fn pal_ctx(ctx: &egui::Context) -> Palette {
    palette(ctx.style().visuals.dark_mode)
}

fn visuals(dark: bool) -> Visuals {
    let p = palette(dark);
    let mut v = if dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    v.panel_fill = p.bg;
    v.window_fill = p.card;
    v.extreme_bg_color = if dark {
        Color32::from_rgb(0x0b, 0x10, 0x14)
    } else {
        Color32::WHITE
    };
    v.faint_bg_color = p.hover;
    v.window_stroke = Stroke::new(1.0_f32, p.border);
    v.window_corner_radius = CornerRadius::same(14);
    v.menu_corner_radius = CornerRadius::same(10);
    v.override_text_color = Some(p.text);
    v.hyperlink_color = p.accent;
    v.selection.bg_fill = if dark {
        Color32::from_rgb(0x14, 0x4a, 0x7a)
    } else {
        Color32::from_rgb(0xb9, 0xd9, 0xf8)
    };
    v.selection.stroke = Stroke::new(1.0_f32, p.accent);
    v.warn_fg_color = p.warn;
    v.error_fg_color = p.danger;
    let r = CornerRadius::same(8);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.corner_radius = r;
    }
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, p.border);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, p.muted);
    v.widgets.inactive.bg_fill = p.hover;
    v.widgets.inactive.weak_bg_fill = p.hover;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, p.border);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, p.text);
    v.widgets.hovered.bg_fill = p.border;
    v.widgets.hovered.weak_bg_fill = p.border;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, p.faint);
    v.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, p.text);
    v.widgets.active.bg_fill = p.border;
    v.widgets.active.weak_bg_fill = p.border;
    v.widgets.active.bg_stroke = Stroke::new(1.0_f32, p.accent);
    v.widgets.active.fg_stroke = Stroke::new(1.0_f32, p.text);
    v.widgets.open.bg_fill = p.hover;
    v.widgets.open.weak_bg_fill = p.hover;
    v.widgets.open.bg_stroke = Stroke::new(1.0_f32, p.faint);
    v
}

static ICON_FONT: AtomicBool = AtomicBool::new(false);

fn load_fonts(ctx: &egui::Context) {
    let dir = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "C:\\Windows".into())
        .join("Fonts");
    let mut fonts = FontDefinitions::default();
    let mut add = |name: &str, file: &str| -> bool {
        match std::fs::read(dir.join(file)) {
            Ok(bytes) => {
                fonts
                    .font_data
                    .insert(name.to_string(), Arc::new(FontData::from_owned(bytes)));
                true
            }
            Err(_) => false,
        }
    };
    // System fonts are loaded at run time so the program stays small.
    let regular = add("ui", "segoeui.ttf");
    let semibold = add("ui-semibold", "seguisb.ttf");
    let icons = add("ui-icons", "segmdl2.ttf") || add("ui-icons", "SegoeIcons.ttf");
    ICON_FONT.store(icons, Ordering::Relaxed);

    let defaults = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    let mut body = Vec::new();
    if regular {
        body.push("ui".to_string());
    }
    if icons {
        body.push("ui-icons".to_string());
    }
    body.extend(defaults.iter().cloned());
    let mut strong = Vec::new();
    if semibold {
        strong.push("ui-semibold".to_string());
    }
    strong.extend(body.iter().cloned());
    fonts.families.insert(FontFamily::Proportional, body);
    fonts
        .families
        .insert(FontFamily::Name("semibold".into()), strong);
    ctx.set_fonts(fonts);
}

pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("semibold".into()))
}

pub fn regular(size: f32) -> FontId {
    FontId::new(size, FontFamily::Proportional)
}

/// One-time setup: fonts, spacing and both colour schemes.
pub fn install(ctx: &egui::Context) {
    load_fonts(ctx);
    ctx.set_visuals_of(Theme::Dark, visuals(true));
    ctx.set_visuals_of(Theme::Light, visuals(false));
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (TextStyle::Heading, semibold(22.0)),
            (TextStyle::Body, regular(14.0)),
            (TextStyle::Button, regular(14.0)),
            (TextStyle::Small, regular(12.0)),
            (
                TextStyle::Monospace,
                FontId::new(13.0, FontFamily::Monospace),
            ),
        ]
        .into();
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 6.0);
        style.spacing.interact_size.y = 30.0;
        style.spacing.scroll.bar_width = 10.0;
        style.spacing.scroll.floating = true;
        style.interaction.selectable_labels = false;
        style.visuals.indent_has_left_vline = false;
    });
}

pub fn apply_choice(ctx: &egui::Context, choice: ThemeChoice) {
    ctx.set_theme(match choice {
        ThemeChoice::Dark => ThemePreference::Dark,
        ThemeChoice::Light => ThemePreference::Light,
        ThemeChoice::System => ThemePreference::System,
    });
}

/// Icon glyphs from the system icon font (Segoe MDL2 Assets). If the font is
/// missing the icons are simply left out.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Icon(pub &'static str);

impl Icon {
    pub const SEARCH: Icon = Icon("\u{E721}");
    pub const SETTINGS: Icon = Icon("\u{E713}");
    pub const DELETE: Icon = Icon("\u{E74D}");
    pub const REFRESH: Icon = Icon("\u{E72C}");
    pub const APPS: Icon = Icon("\u{E71D}");
    pub const FOLDER: Icon = Icon("\u{E8B7}");
    pub const WARNING: Icon = Icon("\u{E7BA}");
    pub const INFO: Icon = Icon("\u{E946}");
    pub const SHIELD: Icon = Icon("\u{EA18}");
    pub const CHECK: Icon = Icon("\u{E73E}");
    pub const CLOSE: Icon = Icon("\u{E711}");
    pub const EXPORT: Icon = Icon("\u{EDE1}");
    pub const DOCUMENT: Icon = Icon("\u{E8A5}");
    pub const GLOBE: Icon = Icon("\u{E774}");
    pub const SORT_UP: Icon = Icon("\u{E70E}");
    pub const SORT_DOWN: Icon = Icon("\u{E70D}");
    pub const CLOCK: Icon = Icon("\u{E823}");
    pub const DONE: Icon = Icon("\u{E930}");
    pub const ERROR: Icon = Icon("\u{EA39}");
    pub const HOME: Icon = Icon("\u{E80F}");
    pub const WIFI: Icon = Icon("\u{E701}");
    pub const ETHERNET: Icon = Icon("\u{E839}");
    pub const KEY: Icon = Icon("\u{E8D7}");
    pub const DEVICES: Icon = Icon("\u{E772}");
    pub const TOOLS: Icon = Icon("\u{E90F}");
    pub const SPEED: Icon = Icon("\u{EC4A}");
    pub const CONNECTIONS: Icon = Icon("\u{E8AB}");
    pub const DOWNLOAD: Icon = Icon("\u{E896}");
    pub const UPLOAD: Icon = Icon("\u{E898}");
    pub const COPY: Icon = Icon("\u{E8C8}");
    pub const EYE: Icon = Icon("\u{E7B3}");
    pub const EYE_OFF: Icon = Icon("\u{ED1A}");
    pub const QR: Icon = Icon("\u{ED14}");
    pub const PLAY: Icon = Icon("\u{E768}");
    pub const STOP: Icon = Icon("\u{E71A}");
    pub const STAR: Icon = Icon("\u{E734}");
    pub const STAR_FILLED: Icon = Icon("\u{E735}");
    pub const EDIT: Icon = Icon("\u{E70F}");
    pub const LOCK: Icon = Icon("\u{E72E}");
    pub const CHART: Icon = Icon("\u{E9D2}");
    pub const ROUTER: Icon = Icon("\u{E968}");
    pub const PC: Icon = Icon("\u{E7F8}");
    pub const PHONE: Icon = Icon("\u{E8EA}");
    pub const PRINTER: Icon = Icon("\u{E749}");
    pub const TV: Icon = Icon("\u{E7F4}");

    /// The glyph, or an empty string when the icon font is unavailable.
    pub fn glyph(self) -> &'static str {
        if ICON_FONT.load(Ordering::Relaxed) {
            self.0
        } else {
            ""
        }
    }

    /// `"<glyph>  text"` for buttons.
    pub fn with(self, text: &str) -> String {
        if ICON_FONT.load(Ordering::Relaxed) {
            format!("{}  {text}", self.0)
        } else {
            text.to_string()
        }
    }
}
