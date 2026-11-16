//! Small reusable pieces of UI.

use super::theme::{pal, regular, semibold, Icon, Palette};
use eframe::egui::{
    self, pos2, text::LayoutJob, text::TextWrapping, vec2, Align2, Color32, CornerRadius, FontId,
    Frame, Margin, Rect, Response, RichText, Sense, Stroke, StrokeKind, TextureHandle, Ui, Vec2,
};

/// A rounded card.
pub fn card(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    let p = pal(ui);
    Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        });
}

fn filled_button(ui: &mut Ui, text: &str, fill: Color32, fg: Color32, enabled: bool) -> Response {
    let p = pal(ui);
    let (fill, fg) = if enabled {
        (fill, fg)
    } else {
        (p.hover, p.faint)
    };
    let button = egui::Button::new(RichText::new(text).font(semibold(14.0)).color(fg))
        .fill(fill)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(8))
        .min_size(vec2(0.0, 34.0));
    let prev = ui.spacing().button_padding;
    ui.spacing_mut().button_padding = vec2(16.0, 7.0);
    let r = ui.add_enabled(enabled, button);
    ui.spacing_mut().button_padding = prev;
    if r.hovered() && enabled {
        ui.painter()
            .rect_filled(r.rect, CornerRadius::same(8), Color32::from_white_alpha(22));
    }
    r
}

/// The main action on a screen (azure).
pub fn primary_button(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    let p = pal(ui);
    filled_button(ui, text, p.accent, p.on_accent, enabled)
}

/// A destructive action (coral).
pub fn danger_button(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    let p = pal(ui);
    filled_button(ui, text, p.danger, Color32::WHITE, enabled)
}

/// A secondary action.
pub fn ghost_button(ui: &mut Ui, text: &str) -> Response {
    ghost_button_enabled(ui, text, true)
}

pub fn ghost_button_enabled(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    let p = pal(ui);
    let button =
        egui::Button::new(RichText::new(text).color(if enabled { p.text } else { p.faint }))
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::new(1.0_f32, p.border))
            .corner_radius(CornerRadius::same(8))
            .min_size(vec2(0.0, 34.0));
    ui.add_enabled(enabled, button)
}

/// A square icon-only button with a tooltip.
pub fn icon_button(ui: &mut Ui, icon: Icon, tooltip: &str) -> Response {
    let p = pal(ui);
    let label = if icon.glyph().is_empty() {
        tooltip.chars().take(1).collect::<String>()
    } else {
        icon.glyph().to_string()
    };
    let button = egui::Button::new(RichText::new(label).size(15.0).color(p.muted))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(8))
        .min_size(vec2(32.0, 32.0));
    ui.add(button).on_hover_text(tooltip)
}

/// A small pill label.
pub fn badge(ui: &mut Ui, text: &str, color: Color32) -> Response {
    let font = semibold(11.5);
    let galley = ui.painter().layout_no_wrap(text.to_string(), font, color);
    let size = vec2(galley.size().x + 14.0, 20.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    paint_badge_at(ui, rect, galley, color);
    resp
}

fn paint_badge_at(ui: &Ui, rect: Rect, galley: std::sync::Arc<egui::Galley>, color: Color32) {
    ui.painter()
        .rect_filled(rect, CornerRadius::same(10), color.gamma_multiply(0.16));
    let pos = pos2(
        rect.center().x - galley.size().x / 2.0,
        rect.center().y - galley.size().y / 2.0,
    );
    ui.painter().galley(pos, galley, color);
}

/// Paints a badge right-aligned inside `rect` and returns the width it used.
pub fn paint_badge(ui: &Ui, rect: Rect, text: &str, color: Color32) -> f32 {
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_string(), semibold(11.5), color);
    let w = galley.size().x + 14.0;
    let r = Rect::from_min_size(pos2(rect.left(), rect.center().y - 10.0), vec2(w, 20.0));
    paint_badge_at(ui, r, galley, color);
    w
}

/// Paints a custom checkbox in `rect`. `state`: Some(true) checked,
/// Some(false) unchecked, None = mixed.
pub fn paint_checkbox(ui: &Ui, rect: Rect, state: Option<bool>, hovered: bool) {
    let p = pal(ui);
    let r = Rect::from_center_size(rect.center(), Vec2::splat(18.0));
    match state {
        Some(false) => {
            ui.painter().rect_stroke(
                r,
                CornerRadius::same(5),
                Stroke::new(1.5_f32, if hovered { p.accent } else { p.faint }),
                StrokeKind::Inside,
            );
        }
        Some(true) => {
            ui.painter().rect_filled(r, CornerRadius::same(5), p.accent);
            let c = r.center();
            let pts = [
                c + vec2(-4.5, 0.0),
                c + vec2(-1.5, 3.2),
                c + vec2(4.8, -3.6),
            ];
            ui.painter()
                .line_segment([pts[0], pts[1]], Stroke::new(2.0_f32, p.on_accent));
            ui.painter()
                .line_segment([pts[1], pts[2]], Stroke::new(2.0_f32, p.on_accent));
        }
        None => {
            ui.painter().rect_filled(r, CornerRadius::same(5), p.accent);
            let c = r.center();
            ui.painter().line_segment(
                [c + vec2(-4.5, 0.0), c + vec2(4.5, 0.0)],
                Stroke::new(2.0_f32, p.on_accent),
            );
        }
    }
}

/// A checkbox with a label, in the brand style.
pub fn checkbox(ui: &mut Ui, value: &mut bool, label: &str) -> Response {
    checkbox_enabled(ui, value, label, true)
}

pub fn checkbox_enabled(ui: &mut Ui, value: &mut bool, label: &str, enabled: bool) -> Response {
    let p = pal(ui);
    let galley = ui.painter().layout_no_wrap(
        label.to_string(),
        regular(14.0),
        if enabled { p.text } else { p.faint },
    );
    let size = vec2(26.0 + galley.size().x, 24.0);
    let (rect, mut resp) = ui.allocate_exact_size(
        size,
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    if resp.clicked() {
        *value = !*value;
        resp.mark_changed();
    }
    let box_rect = Rect::from_min_size(rect.min, vec2(20.0, rect.height()));
    if enabled {
        paint_checkbox(ui, box_rect, Some(*value), resp.hovered());
    } else {
        ui.painter().rect_stroke(
            Rect::from_center_size(box_rect.center(), Vec2::splat(18.0)),
            CornerRadius::same(5),
            Stroke::new(1.5_f32, p.border),
            StrokeKind::Inside,
        );
    }
    ui.painter().galley(
        pos2(rect.left() + 26.0, rect.center().y - galley.size().y / 2.0),
        galley,
        p.text,
    );
    resp
}

/// An on/off switch. Returns true when clicked.
pub fn toggle(ui: &mut Ui, on: bool, enabled: bool) -> Response {
    let p = pal(ui);
    let (rect, resp) = ui.allocate_exact_size(
        vec2(38.0, 22.0),
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    let t = ui.ctx().animate_bool_with_time(resp.id, on, 0.12);
    let track = if !enabled {
        p.border
    } else if on {
        p.accent
    } else {
        p.faint.gamma_multiply(0.6)
    };
    ui.painter()
        .rect_filled(rect, CornerRadius::same(11), track);
    let x = egui::lerp((rect.left() + 11.0)..=(rect.right() - 11.0), t);
    ui.painter().circle_filled(
        pos2(x, rect.center().y),
        8.0,
        if enabled { Color32::WHITE } else { p.faint },
    );
    resp
}

/// A row of mutually exclusive choices. Returns the newly picked index.
pub fn segmented(ui: &mut Ui, options: &[&str], current: usize) -> Option<usize> {
    let p = pal(ui);
    let mut picked = None;
    Frame::new()
        .fill(p.hover)
        .corner_radius(CornerRadius::same(9))
        .inner_margin(Margin::same(3))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                // In a right-to-left row the first widget lands on the right:
                // add the options backwards so they still read left to right.
                let mut order: Vec<usize> = (0..options.len()).collect();
                if ui.layout().prefer_right_to_left() {
                    order.reverse();
                }
                for i in order {
                    let label = &options[i];
                    let active = i == current;
                    let text = RichText::new(*label).color(if active { p.text } else { p.muted });
                    let text = if active {
                        text.font(semibold(13.5))
                    } else {
                        text.size(13.5)
                    };
                    let b = egui::Button::new(text)
                        .fill(if active { p.card } else { Color32::TRANSPARENT })
                        .stroke(if active {
                            Stroke::new(1.0_f32, p.border)
                        } else {
                            Stroke::NONE
                        })
                        .corner_radius(CornerRadius::same(7))
                        .min_size(vec2(0.0, 28.0));
                    if ui.add(b).clicked() && !active {
                        picked = Some(i);
                    }
                }
            });
        });
    picked
}

/// A filter chip.
pub fn chip(ui: &mut Ui, label: &str, count: Option<usize>, active: bool) -> Response {
    let p = pal(ui);
    let text = match count {
        Some(n) => format!("{label}  {n}"),
        None => label.to_string(),
    };
    let (fill, fg, stroke) = if active {
        (
            p.accent.gamma_multiply(0.16),
            p.accent,
            Stroke::new(1.0_f32, p.accent.gamma_multiply(0.6)),
        )
    } else {
        (
            Color32::TRANSPARENT,
            p.muted,
            Stroke::new(1.0_f32, p.border),
        )
    };
    let b = egui::Button::new(RichText::new(text).size(13.0).color(fg))
        .fill(fill)
        .stroke(stroke)
        .corner_radius(CornerRadius::same(15))
        .min_size(vec2(0.0, 30.0));
    ui.add(b)
}

/// Lays out one line of text, cut off with an ellipsis at `max_width`.
pub fn elided(
    ui: &Ui,
    text: &str,
    font: FontId,
    color: Color32,
    max_width: f32,
) -> std::sync::Arc<egui::Galley> {
    let mut job = LayoutJob::simple_singleline(text.to_string(), font, color);
    job.wrap = TextWrapping {
        max_width: max_width.max(8.0),
        max_rows: 1,
        break_anywhere: true,
        overflow_character: Some('…'),
    };
    ui.fonts(|f| f.layout_job(job))
}

/// Paints one elided line, vertically centred in `rect`. Returns whether it was cut.
pub fn text_in(ui: &Ui, rect: Rect, text: &str, font: FontId, color: Color32) -> bool {
    let galley = elided(ui, text, font, color, rect.width());
    let cut = galley.elided;
    ui.painter().galley(
        pos2(rect.left(), rect.center().y - galley.size().y / 2.0),
        galley,
        color,
    );
    cut
}

/// Like [`text_in`], right-aligned.
pub fn text_in_right(ui: &Ui, rect: Rect, text: &str, font: FontId, color: Color32) {
    let galley = elided(ui, text, font, color, rect.width());
    ui.painter().galley(
        pos2(
            rect.right() - galley.size().x,
            rect.center().y - galley.size().y / 2.0,
        ),
        galley,
        color,
    );
}

fn tile_color(name: &str) -> Color32 {
    const COLORS: [Color32; 8] = [
        Color32::from_rgb(0x10, 0xa3, 0x7f),
        Color32::from_rgb(0x08, 0x6f, 0xa8),
        Color32::from_rgb(0x7c, 0x5c, 0xd6),
        Color32::from_rgb(0xd9, 0x6a, 0x2b),
        Color32::from_rgb(0xc2, 0x48, 0x7a),
        Color32::from_rgb(0x2f, 0x86, 0xc9),
        Color32::from_rgb(0x4e, 0x9a, 0x3c),
        Color32::from_rgb(0xb8, 0x8a, 0x1f),
    ];
    let h = name
        .bytes()
        .fold(7u32, |a, b| a.wrapping_mul(31).wrapping_add(b as u32));
    COLORS[(h % COLORS.len() as u32) as usize]
}

/// Paints a program icon, or a coloured tile with the program's initial.
pub fn program_icon(ui: &Ui, rect: Rect, name: &str, texture: Option<&TextureHandle>) {
    match texture {
        Some(tex) => {
            ui.painter().image(
                tex.id(),
                rect,
                Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)),
                Color32::WHITE,
            );
        }
        None => {
            let radius = (rect.width() * 0.26) as u8;
            ui.painter()
                .rect_filled(rect, CornerRadius::same(radius), tile_color(name));
            let initial: String = name
                .chars()
                .find(|c| c.is_alphanumeric())
                .map(|c| c.to_uppercase().collect())
                .unwrap_or_default();
            ui.painter().text(
                rect.center(),
                Align2::CENTER_CENTER,
                initial,
                semibold(rect.height() * 0.5),
                Color32::WHITE,
            );
        }
    }
}

/// A designed empty / error state: icon, title, explanation.
pub fn empty_state(ui: &mut Ui, icon: Icon, color: Color32, title: &str, text: &str) {
    let p = pal(ui);
    ui.vertical_centered(|ui| {
        ui.add_space((ui.available_height() * 0.22).clamp(24.0, 140.0));
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(72.0), Sense::hover());
        ui.painter()
            .circle_filled(rect.center(), 36.0, color.gamma_multiply(0.14));
        ui.painter().text(
            rect.center(),
            Align2::CENTER_CENTER,
            icon.glyph(),
            regular(30.0),
            color,
        );
        ui.add_space(10.0);
        ui.label(RichText::new(title).font(semibold(18.0)).color(p.text));
        ui.add_space(2.0);
        ui.scope(|ui| {
            ui.set_max_width(460.0);
            ui.label(RichText::new(text).color(p.muted));
        });
        ui.add_space(8.0);
    });
}

/// A spinner with a line of text, centred.
pub fn busy_state(ui: &mut Ui, title: &str, text: &str) {
    let p = pal(ui);
    ui.vertical_centered(|ui| {
        ui.add_space((ui.available_height() * 0.25).clamp(24.0, 160.0));
        ui.add(egui::Spinner::new().size(34.0).color(p.accent));
        ui.add_space(12.0);
        ui.label(RichText::new(title).font(semibold(18.0)));
        ui.add_space(2.0);
        ui.scope(|ui| {
            ui.set_max_width(560.0);
            ui.add(egui::Label::new(RichText::new(text).color(p.muted)).truncate());
        });
    });
}

/// Section title inside a page.
pub fn section(ui: &mut Ui, title: &str) {
    ui.label(RichText::new(title).font(semibold(15.0)));
}

/// A thin horizontal line.
pub fn divider(ui: &mut Ui) {
    let p = pal(ui);
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(rect, 0, p.border);
}

// --------------------------------------------------------------------------------------
// Tables
// --------------------------------------------------------------------------------------

/// A table column: a fixed width in points, or a share of what is left.
#[derive(Clone, Copy)]
pub struct Col {
    pub title: &'static str,
    /// Positive: fixed width. Negative: flexible, the magnitude is the weight.
    pub width: f32,
    /// Right-align the header (numbers).
    pub right: bool,
}

impl Col {
    pub const fn fixed(title: &'static str, width: f32) -> Col {
        Col {
            title,
            width,
            right: false,
        }
    }
    pub const fn flex(title: &'static str, weight: f32) -> Col {
        Col {
            title,
            width: -weight,
            right: false,
        }
    }
    pub const fn right(title: &'static str, width: f32) -> Col {
        Col {
            title,
            width,
            right: true,
        }
    }
}

const COL_GAP: f32 = 14.0;
const ROW_PAD: f32 = 12.0;

/// The cell rectangles of a row laid out inside `rect`.
pub fn col_rects(cols: &[Col], rect: Rect) -> Vec<Rect> {
    let inner = rect.width() - 2.0 * ROW_PAD - COL_GAP * cols.len().saturating_sub(1) as f32;
    let fixed: f32 = cols.iter().filter(|c| c.width > 0.0).map(|c| c.width).sum();
    let weight: f32 = cols
        .iter()
        .filter(|c| c.width < 0.0)
        .map(|c| -c.width)
        .sum();
    let flex = (inner - fixed).max(0.0);
    let mut x = rect.left() + ROW_PAD;
    cols.iter()
        .map(|c| {
            let w = if c.width > 0.0 {
                c.width
            } else if weight > 0.0 {
                flex * (-c.width) / weight
            } else {
                0.0
            };
            let r = Rect::from_min_size(pos2(x, rect.top()), vec2(w.max(0.0), rect.height()));
            x += w + COL_GAP;
            r
        })
        .collect()
}

/// The header row. `sort` is the sorted column and whether it ascends.
/// Returns the column that was clicked.
pub fn table_header(ui: &mut Ui, cols: &[Col], sort: Option<(usize, bool)>) -> Option<usize> {
    let p = pal(ui);
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 30.0), Sense::hover());
    let mut clicked = None;
    for (i, (col, cell)) in cols.iter().zip(col_rects(cols, rect)).enumerate() {
        if col.title.is_empty() {
            continue;
        }
        let resp = ui.interact(cell, ui.id().with(("th", i)), Sense::click());
        let active = sort.map(|s| s.0 == i).unwrap_or(false);
        let color = if active || resp.hovered() {
            p.text
        } else {
            p.faint
        };
        let arrow = match sort {
            Some((c, asc)) if c == i => {
                if asc {
                    Icon::SORT_UP.glyph()
                } else {
                    Icon::SORT_DOWN.glyph()
                }
            }
            _ => "",
        };
        let galley = ui
            .painter()
            .layout_no_wrap(col.title.to_string(), semibold(12.0), color);
        let w = galley.size().x;
        let x = if col.right {
            cell.right() - w - if arrow.is_empty() { 0.0 } else { 14.0 }
        } else {
            cell.left()
        };
        ui.painter().galley(
            pos2(x, cell.center().y - galley.size().y / 2.0),
            galley,
            color,
        );
        if !arrow.is_empty() {
            ui.painter().text(
                pos2(x + w + 5.0, cell.center().y),
                Align2::LEFT_CENTER,
                arrow,
                regular(9.0),
                p.accent,
            );
        }
        if resp.clicked() {
            clicked = Some(i);
        }
    }
    ui.painter().hline(
        rect.x_range(),
        rect.bottom(),
        Stroke::new(1.0_f32, p.border),
    );
    clicked
}

/// Allocates one row, paints its hover / selected background and a divider,
/// and returns the cell rectangles to paint into.
pub fn table_row(ui: &mut Ui, cols: &[Col], height: f32, selected: bool) -> (Vec<Rect>, Response) {
    let p = pal(ui);
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::click());
    if selected {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(8), p.selected);
    } else if resp.hovered() {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(8), p.hover);
    } else {
        ui.painter().hline(
            rect.x_range().shrink(ROW_PAD),
            rect.bottom(),
            Stroke::new(1.0_f32, p.border.gamma_multiply(0.5)),
        );
    }
    (col_rects(cols, rect), resp)
}

// --------------------------------------------------------------------------------------
// Bits and pieces
// --------------------------------------------------------------------------------------

/// A card with a title line (and optional right-aligned extras on that line,
/// added rightmost first).
pub fn titled_card(
    ui: &mut Ui,
    title: &str,
    extras: impl FnOnce(&mut Ui),
    add: impl FnOnce(&mut Ui),
) {
    card(ui, |ui| {
        ui.allocate_ui_with_layout(
            vec2(ui.available_width(), 24.0),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.label(RichText::new(title).font(semibold(15.0)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), extras);
            },
        );
        ui.add_space(2.0);
        add(ui)
    });
}

/// "Label    value" on one line, the value selectable; used in detail cards.
pub fn kv(ui: &mut Ui, label: &str, value: &str) {
    kv_colored(ui, label, value, None);
}

pub fn kv_colored(ui: &mut Ui, label: &str, value: &str, color: Option<Color32>) {
    let p = pal(ui);
    // A fixed height: a plain horizontal row would be as tall as a button.
    ui.allocate_ui_with_layout(
        vec2(ui.available_width(), 22.0),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            let (rect, _) = ui.allocate_exact_size(vec2(124.0, 20.0), Sense::hover());
            text_in(ui, rect, label, regular(13.0), p.faint);
            let shown = if value.trim().is_empty() {
                "Not available"
            } else {
                value
            };
            let color = if value.trim().is_empty() {
                p.faint
            } else {
                color.unwrap_or(p.text)
            };
            ui.add(
                egui::Label::new(RichText::new(shown).size(13.5).color(color))
                    .truncate()
                    .selectable(true),
            );
        },
    );
}

/// A full-width notice with an icon: information, warning or error.
pub fn notice(ui: &mut Ui, icon: Icon, color: Color32, text: &str) {
    notice_with(ui, icon, color, text, |_| {});
}

/// A notice with extra widgets (buttons) under the text.
pub fn notice_with(
    ui: &mut Ui,
    icon: Icon,
    color: Color32,
    text: &str,
    extras: impl FnOnce(&mut Ui),
) {
    let p = pal(ui);
    Frame::new()
        .fill(color.gamma_multiply(0.10))
        .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.45)))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                ui.label(RichText::new(icon.glyph()).size(15.0).color(color));
                ui.vertical(|ui| {
                    ui.add(egui::Label::new(RichText::new(text).color(p.text)).wrap());
                    extras(ui);
                });
            });
        });
}

/// A search field with a magnifier and a clear button. Returns true when the text changed.
pub fn search_box(ui: &mut Ui, text: &mut String, hint: &str, width: f32) -> bool {
    let p = pal(ui);
    let mut changed = false;
    Frame::new()
        .fill(if p.dark { p.card } else { p.bg })
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(9))
        .inner_margin(Margin::symmetric(10, 3))
        .show(ui, |ui| {
            ui.allocate_ui_with_layout(
                vec2(width, 26.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.label(
                        RichText::new(Icon::SEARCH.glyph())
                            .size(13.0)
                            .color(p.faint),
                    );
                    let edit = egui::TextEdit::singleline(text)
                        .hint_text(RichText::new(hint).color(p.faint))
                        .frame(false)
                        .desired_width(width - 52.0);
                    changed = ui.add(edit).changed();
                    if !text.is_empty()
                        && ui
                            .add(
                                egui::Button::new(
                                    RichText::new(Icon::CLOSE.glyph()).size(11.0).color(p.muted),
                                )
                                .frame(false),
                            )
                            .on_hover_text("Clear")
                            .clicked()
                    {
                        text.clear();
                        changed = true;
                    }
                },
            );
        });
    changed
}

/// A framed single-line text field with a caption above it.
pub fn text_field(
    ui: &mut Ui,
    caption: &str,
    text: &mut String,
    hint: &str,
    width: f32,
) -> Response {
    let p = pal(ui);
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 3.0;
        if !caption.is_empty() {
            ui.label(RichText::new(caption).size(12.0).color(p.faint));
        }
        ui.add(
            egui::TextEdit::singleline(text)
                .hint_text(RichText::new(hint).color(p.faint))
                .desired_width(width)
                .margin(Margin::symmetric(10, 7)),
        )
    })
    .inner
}

/// The frame every modal dialog uses.
pub fn modal_frame(p: &Palette) -> Frame {
    Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(14))
        .inner_margin(Margin::same(22))
}

/// A right-aligned row of buttons with a fixed height. Use this in modals:
/// a plain right-to-left layout there stretches to the full height.
/// Add the buttons in reverse order (rightmost first).
pub fn button_row(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    ui.allocate_ui_with_layout(
        vec2(ui.available_width(), 36.0),
        egui::Layout::right_to_left(egui::Align::Center),
        add,
    );
}

/// The standard page header: title, subtitle and right-aligned actions
/// (added rightmost first).
pub fn page_header(ui: &mut Ui, title: &str, subtitle: &str, actions: impl FnOnce(&mut Ui)) {
    let p = pal(ui);
    ui.allocate_ui_with_layout(
        vec2(ui.available_width(), 52.0),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.label(RichText::new(title).font(semibold(24.0)));
                ui.add(egui::Label::new(RichText::new(subtitle).color(p.muted)).truncate());
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), actions);
        },
    );
    ui.add_space(6.0);
}

/// Lays children out in `n` equal columns with the standard gap; the closure
/// is called once per column with its index.
pub fn columns_n(ui: &mut Ui, n: usize, mut add: impl FnMut(usize, &mut Ui)) {
    let gap = 14.0;
    let w = (ui.available_width() - gap * (n as f32 - 1.0)) / n as f32;
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = gap;
        for i in 0..n {
            ui.allocate_ui_with_layout(
                vec2(w, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.set_width(w);
                    add(i, ui)
                },
            );
        }
    });
}

/// Columns with explicit relative weights.
pub fn columns_weighted(ui: &mut Ui, weights: &[f32], mut add: impl FnMut(usize, &mut Ui)) {
    let gap = 14.0;
    let total: f32 = weights.iter().sum();
    let avail = ui.available_width() - gap * (weights.len() as f32 - 1.0);
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = gap;
        for (i, weight) in weights.iter().enumerate() {
            let w = avail * weight / total.max(0.001);
            ui.allocate_ui_with_layout(
                vec2(w, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.set_width(w);
                    add(i, ui)
                },
            );
        }
    });
}
