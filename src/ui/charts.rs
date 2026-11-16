//! Charts drawn directly with the painter: line / area charts, stacked bars,
//! sparklines, progress bars, signal bars and an arc gauge.
//!
//! House rules: thin marks (2 px lines), recessive grid and axis text in the
//! muted ink colours, a legend whenever there are two or more series, a hover
//! read-out on every plot, one y-axis per chart, text never in a series colour.

use super::theme::{pal, regular, semibold};
use eframe::egui::{
    epaint::Mesh, pos2, vec2, Align2, Color32, CornerRadius, Pos2, Rect, Response, RichText, Sense,
    Shape, Stroke, Ui,
};

/// One line of a [`line_chart`]. `NaN` values are gaps.
pub struct Series<'a> {
    pub name: &'a str,
    pub values: &'a [f64],
    pub color: Color32,
    /// Shade the area under the line.
    pub fill: bool,
}

pub struct LineChart<'a> {
    pub series: &'a [Series<'a>],
    pub height: f32,
    /// Bottom of the y-axis (usually 0).
    pub y_min: f64,
    /// Top of the y-axis; `None` = the largest value, rounded up.
    pub y_max: Option<f64>,
    /// Formats axis labels and hover values.
    pub y_fmt: &'a dyn Fn(f64) -> String,
    /// Labels under the left and right ends of the x-axis ("5 min ago", "now").
    pub x_left: &'a str,
    pub x_right: &'a str,
    /// Describes a sample index for the hover read-out; `None` = no line for it.
    pub x_fmt: Option<&'a dyn Fn(usize, usize) -> String>,
    /// Number of sample slots across the full width (so a short history
    /// starts at the right edge); 0 = the longest series.
    pub slots: usize,
    pub legend: bool,
}

impl<'a> LineChart<'a> {
    pub fn new(series: &'a [Series<'a>], y_fmt: &'a dyn Fn(f64) -> String) -> Self {
        LineChart {
            series,
            height: 180.0,
            y_min: 0.0,
            y_max: None,
            y_fmt,
            x_left: "",
            x_right: "",
            x_fmt: None,
            slots: 0,
            legend: true,
        }
    }
}

/// A coloured dot followed by a name, for legends.
pub fn legend_item(ui: &mut Ui, name: &str, color: Color32) {
    let p = pal(ui);
    let galley = ui
        .painter()
        .layout_no_wrap(name.to_string(), regular(12.5), p.muted);
    let (rect, _) = ui.allocate_exact_size(vec2(galley.size().x + 16.0, 18.0), Sense::hover());
    ui.painter()
        .circle_filled(pos2(rect.left() + 5.0, rect.center().y), 4.0, color);
    ui.painter().galley(
        pos2(rect.left() + 14.0, rect.center().y - galley.size().y / 2.0),
        galley,
        p.muted,
    );
}

fn area_mesh(points: &[Pos2], base_y: f32, color: Color32) -> Mesh {
    let mut mesh = Mesh::default();
    let top = color.gamma_multiply(0.20);
    let bottom = color.gamma_multiply(0.02);
    for (i, pt) in points.iter().enumerate() {
        mesh.colored_vertex(*pt, top);
        mesh.colored_vertex(pos2(pt.x, base_y), bottom);
        if i > 0 {
            let n = (i * 2) as u32;
            mesh.add_triangle(n - 2, n - 1, n);
            mesh.add_triangle(n - 1, n + 1, n);
        }
    }
    mesh
}

/// A line / area chart over evenly spaced samples (oldest first).
pub fn line_chart(ui: &mut Ui, chart: &LineChart<'_>) -> Response {
    let p = pal(ui);
    if chart.legend && chart.series.len() >= 2 {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 14.0;
            for s in chart.series {
                legend_item(ui, s.name, s.color);
            }
        });
    }
    let has_x = !chart.x_left.is_empty() || !chart.x_right.is_empty();
    let total_h = chart.height + if has_x { 18.0 } else { 0.0 };
    let (outer, resp) = ui.allocate_exact_size(vec2(ui.available_width(), total_h), Sense::hover());
    let plot = Rect::from_min_max(outer.min, pos2(outer.right(), outer.top() + chart.height));
    if !ui.is_rect_visible(outer) {
        return resp;
    }
    let painter = ui.painter_at(outer);

    let longest = chart
        .series
        .iter()
        .map(|s| s.values.len())
        .max()
        .unwrap_or(0);
    let slots = chart.slots.max(longest).max(2);
    let data_max = chart
        .series
        .iter()
        .flat_map(|s| s.values.iter().copied())
        .filter(|v| v.is_finite())
        .fold(f64::MIN, f64::max);
    let y_max = match chart.y_max {
        Some(m) => m,
        None if data_max > chart.y_min => crate::fmt::nice_ceiling(data_max),
        None => chart.y_min + 1.0,
    };
    let span = (y_max - chart.y_min).max(f64::EPSILON);
    let to_y = |v: f64| {
        let t = ((v - chart.y_min) / span).clamp(0.0, 1.0) as f32;
        plot.bottom() - 1.0 - t * (plot.height() - 10.0)
    };
    let to_x = |slot: usize| plot.left() + plot.width() * slot as f32 / (slots - 1) as f32;

    // Grid: a few quiet horizontal lines with their values.
    let divisions = if chart.height < 120.0 { 2 } else { 4 };
    for i in 0..=divisions {
        let v = chart.y_min + span * i as f64 / divisions as f64;
        let y = to_y(v);
        painter.hline(
            plot.x_range(),
            y,
            Stroke::new(
                1.0_f32,
                p.border.gamma_multiply(if i == 0 { 1.0 } else { 0.55 }),
            ),
        );
        if i > 0 {
            painter.text(
                pos2(plot.left() + 2.0, y + 2.0),
                Align2::LEFT_TOP,
                (chart.y_fmt)(v),
                regular(11.0),
                p.faint,
            );
        }
    }

    for s in chart.series {
        let offset = slots - s.values.len().min(slots);
        let skip = s.values.len().saturating_sub(slots);
        let mut run: Vec<Pos2> = Vec::new();
        let flush = |run: &mut Vec<Pos2>| {
            if run.len() >= 2 {
                if s.fill {
                    painter.add(Shape::mesh(area_mesh(run, plot.bottom() - 1.0, s.color)));
                }
                painter.add(Shape::line(run.clone(), Stroke::new(2.0_f32, s.color)));
            } else if run.len() == 1 {
                painter.circle_filled(run[0], 2.5, s.color);
            }
            run.clear();
        };
        for (i, v) in s.values.iter().skip(skip).enumerate() {
            if v.is_finite() {
                run.push(pos2(to_x(offset + i), to_y(*v)));
            } else {
                flush(&mut run);
            }
        }
        flush(&mut run);
    }

    if has_x {
        painter.text(
            pos2(plot.left(), plot.bottom() + 4.0),
            Align2::LEFT_TOP,
            chart.x_left,
            regular(11.0),
            p.faint,
        );
        painter.text(
            pos2(plot.right(), plot.bottom() + 4.0),
            Align2::RIGHT_TOP,
            chart.x_right,
            regular(11.0),
            p.faint,
        );
    }

    // Hover: a crosshair and the values at that sample.
    if let Some(pos) = resp.hover_pos().filter(|pos| plot.contains(*pos)) {
        let slot = (((pos.x - plot.left()) / plot.width()) * (slots - 1) as f32).round() as usize;
        let slot = slot.min(slots - 1);
        let x = to_x(slot);
        painter.vline(x, plot.y_range(), Stroke::new(1.0_f32, p.faint));
        let mut lines: Vec<(Color32, String, String)> = Vec::new();
        for s in chart.series {
            let offset = slots - s.values.len().min(slots);
            let skip = s.values.len().saturating_sub(slots);
            if slot >= offset {
                if let Some(v) = s.values.get(skip + slot - offset).filter(|v| v.is_finite()) {
                    painter.circle_filled(pos2(x, to_y(*v)), 5.0, p.card);
                    painter.circle_filled(pos2(x, to_y(*v)), 3.5, s.color);
                    lines.push((s.color, s.name.to_string(), (chart.y_fmt)(*v)));
                }
            }
        }
        let when = chart.x_fmt.map(|f| f(slot, slots));
        if !lines.is_empty() {
            resp.clone().on_hover_ui_at_pointer(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                if let Some(when) = &when {
                    ui.label(RichText::new(when).size(12.0).color(p.muted));
                }
                for (color, name, value) in &lines {
                    ui.horizontal(|ui| {
                        let (r, _) = ui.allocate_exact_size(vec2(10.0, 14.0), Sense::hover());
                        ui.painter().circle_filled(r.center(), 4.0, *color);
                        ui.label(RichText::new(value).font(semibold(13.0)));
                        ui.label(RichText::new(name).size(12.5).color(p.muted));
                    });
                }
            });
        }
    }
    resp
}

/// A tiny line with no axes, for table rows and stat tiles.
pub fn sparkline(ui: &Ui, rect: Rect, values: &[f64], color: Color32) {
    if values.len() < 2 {
        return;
    }
    let max = values
        .iter()
        .copied()
        .filter(|v| v.is_finite())
        .fold(0.0, f64::max)
        .max(1.0);
    let points: Vec<Pos2> = values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let v = if v.is_finite() { *v } else { 0.0 };
            pos2(
                rect.left() + rect.width() * i as f32 / (values.len() - 1) as f32,
                rect.bottom() - 1.0 - (v / max) as f32 * (rect.height() - 3.0),
            )
        })
        .collect();
    let painter = ui.painter_at(rect);
    painter.add(Shape::mesh(area_mesh(&points, rect.bottom(), color)));
    painter.add(Shape::line(points, Stroke::new(1.5_f32, color)));
}

/// One bar of a [`bar_chart`]: stacked parts, bottom first.
pub struct Bar {
    /// Axis label (shown for some bars only when space is tight).
    pub label: String,
    /// Shown in the hover read-out ("Mon 16 Nov").
    pub title: String,
    pub parts: Vec<f64>,
}

/// Stacked vertical bars. `series` gives the name and colour of each part;
/// `ceiling` rounds the largest bar up to the top of the axis (for example
/// [`crate::fmt::bytes_ceiling`]).
pub fn bar_chart_with(
    ui: &mut Ui,
    bars: &[Bar],
    series: &[(&str, Color32)],
    height: f32,
    y_fmt: &dyn Fn(f64) -> String,
    highlight_last: bool,
    ceiling: &dyn Fn(f64) -> f64,
) -> Response {
    let p = pal(ui);
    if series.len() >= 2 {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 14.0;
            for (name, color) in series {
                legend_item(ui, name, *color);
            }
        });
    }
    let (outer, resp) =
        ui.allocate_exact_size(vec2(ui.available_width(), height + 20.0), Sense::hover());
    if !ui.is_rect_visible(outer) || bars.is_empty() {
        return resp;
    }
    let plot = Rect::from_min_max(outer.min, pos2(outer.right(), outer.top() + height));
    let painter = ui.painter_at(outer);
    let max = bars
        .iter()
        .map(|b| b.parts.iter().sum::<f64>())
        .fold(0.0, f64::max);
    let y_max = ceiling(max.max(f64::MIN_POSITIVE)).max(f64::MIN_POSITIVE);
    let to_h = |v: f64| ((v / y_max).clamp(0.0, 1.0) as f32) * (plot.height() - 12.0);
    for i in 0..=2 {
        let v = y_max * i as f64 / 2.0;
        let y = plot.bottom() - 1.0 - to_h(v);
        painter.hline(
            plot.x_range(),
            y,
            Stroke::new(
                1.0_f32,
                p.border.gamma_multiply(if i == 0 { 1.0 } else { 0.55 }),
            ),
        );
    }
    let n = bars.len();
    let slot = plot.width() / n as f32;
    let bar_w = (slot - 2.0).clamp(2.0, 28.0);
    // Label every k-th bar so the texts do not collide.
    let widest = bars
        .iter()
        .map(|b| {
            painter
                .layout_no_wrap(b.label.clone(), regular(11.0), p.faint)
                .size()
                .x
        })
        .fold(0.0, f32::max);
    let every = ((widest + 10.0) / slot).ceil().max(1.0) as usize;
    let hover_x = resp
        .hover_pos()
        .filter(|pos| outer.contains(*pos))
        .map(|p| p.x);
    let mut hovered: Option<usize> = None;
    for (i, bar) in bars.iter().enumerate() {
        let cx = plot.left() + slot * (i as f32 + 0.5);
        let is_hover = hover_x
            .map(|x| x >= cx - slot / 2.0 && x < cx + slot / 2.0)
            .unwrap_or(false);
        if is_hover {
            hovered = Some(i);
            painter.rect_filled(
                Rect::from_min_max(
                    pos2(cx - slot / 2.0, plot.top()),
                    pos2(cx + slot / 2.0, plot.bottom()),
                ),
                CornerRadius::same(4),
                p.hover,
            );
        }
        let mut y = plot.bottom() - 1.0;
        let last_part = bar.parts.iter().rposition(|v| *v > 0.0);
        for (k, v) in bar.parts.iter().enumerate() {
            let h = to_h(*v);
            if h <= 0.0 {
                continue;
            }
            // A 2 px surface gap between stacked parts.
            let gap = if k > 0 && h > 3.0 { 2.0 } else { 0.0 };
            let rect = Rect::from_min_max(
                pos2(cx - bar_w / 2.0, y - h),
                pos2(cx + bar_w / 2.0, y - gap),
            );
            let color = series.get(k).map(|s| s.1).unwrap_or(p.accent);
            let dim = highlight_last && i + 1 != n && !is_hover;
            let r = if Some(k) == last_part {
                let rr = (bar_w / 2.0).min(4.0) as u8;
                CornerRadius {
                    nw: rr,
                    ne: rr,
                    sw: 0,
                    se: 0,
                }
            } else {
                CornerRadius::ZERO
            };
            painter.rect_filled(
                rect,
                r,
                if dim {
                    color.gamma_multiply(0.62)
                } else {
                    color
                },
            );
            y -= h;
        }
        if i % every == (n - 1) % every {
            let galley = painter.layout_no_wrap(bar.label.clone(), regular(11.0), p.faint);
            let x = (cx - galley.size().x / 2.0)
                .min(plot.right() - galley.size().x)
                .max(plot.left());
            painter.galley(pos2(x, plot.bottom() + 5.0), galley, p.faint);
        }
    }
    // Axis values go on top of the bars, on a patch of the surface colour.
    if max > 0.0 {
        for i in 1..=2 {
            let v = y_max * i as f64 / 2.0;
            let y = plot.bottom() - 1.0 - to_h(v);
            let galley = painter.layout_no_wrap(y_fmt(v), regular(11.0), p.faint);
            let at = pos2(plot.left() + 2.0, y + 2.0);
            painter.rect_filled(
                Rect::from_min_size(at, galley.size()).expand2(vec2(3.0, 1.0)),
                CornerRadius::same(3),
                p.card.gamma_multiply(0.85),
            );
            painter.galley(at, galley, p.faint);
        }
    }
    if let Some(i) = hovered {
        let bar = &bars[i];
        resp.clone().on_hover_ui_at_pointer(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.label(RichText::new(&bar.title).size(12.0).color(p.muted));
            for (k, v) in bar.parts.iter().enumerate() {
                let (name, color) = series.get(k).copied().unwrap_or(("", p.accent));
                ui.horizontal(|ui| {
                    let (r, _) = ui.allocate_exact_size(vec2(10.0, 14.0), Sense::hover());
                    ui.painter().circle_filled(r.center(), 4.0, color);
                    ui.label(RichText::new(y_fmt(*v)).font(semibold(13.0)));
                    ui.label(RichText::new(name).size(12.5).color(p.muted));
                });
            }
            if bar.parts.len() > 1 {
                ui.label(
                    RichText::new(format!("{} in total", y_fmt(bar.parts.iter().sum())))
                        .size(12.0)
                        .color(p.muted),
                );
            }
        });
    }
    resp
}

/// A horizontal progress / share bar.
pub fn meter_bar(ui: &mut Ui, fraction: f32, color: Color32, height: f32) -> Response {
    let p = pal(ui);
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::hover());
    paint_meter_bar(ui, rect, fraction, color, p.hover);
    resp
}

pub fn paint_meter_bar(ui: &Ui, rect: Rect, fraction: f32, color: Color32, track: Color32) {
    let r = CornerRadius::same((rect.height() / 2.0) as u8);
    ui.painter().rect_filled(rect, r, track);
    let f = fraction.clamp(0.0, 1.0);
    if f > 0.0 {
        let w = (rect.width() * f).max(rect.height());
        ui.painter().rect_filled(
            Rect::from_min_size(rect.min, vec2(w, rect.height())),
            r,
            color,
        );
    }
}

/// Four rising bars showing a signal quality of 0..=100.
pub fn signal_bars(ui: &Ui, rect: Rect, quality: u8, color: Color32) {
    let p = pal(ui);
    let lit = match quality {
        0 => 0,
        1..=29 => 1,
        30..=54 => 2,
        55..=79 => 3,
        _ => 4,
    };
    let w = (rect.width() - 6.0) / 4.0;
    for i in 0..4 {
        let h = rect.height() * (0.4 + 0.2 * i as f32);
        let x = rect.left() + i as f32 * (w + 2.0);
        let bar = Rect::from_min_max(pos2(x, rect.bottom() - h), pos2(x + w, rect.bottom()));
        ui.painter().rect_filled(
            bar,
            CornerRadius::same(1),
            if i < lit { color } else { p.border },
        );
    }
}

/// The status colour for a signal strength in dBm.
pub fn signal_color(ui: &Ui, dbm: i32) -> Color32 {
    let p = pal(ui);
    if dbm >= -67 {
        p.good
    } else if dbm >= -75 {
        p.warn
    } else {
        p.danger
    }
}

/// A 240-degree arc gauge with a big value in the middle.
pub fn gauge(ui: &mut Ui, size: f32, fraction: f32, color: Color32, value: &str, caption: &str) {
    let p = pal(ui);
    let (rect, _) = ui.allocate_exact_size(vec2(size, size * 0.86), Sense::hover());
    let center = pos2(rect.center().x, rect.top() + size * 0.5);
    let radius = size * 0.5 - 10.0;
    let arc = |from: f32, to: f32| -> Vec<Pos2> {
        let steps = 64;
        (0..=steps)
            .map(|i| {
                let t = from + (to - from) * i as f32 / steps as f32;
                // 150 degrees (lower left) clockwise to 390 degrees (lower right).
                let a = (150.0 + 240.0 * t).to_radians();
                pos2(center.x + radius * a.cos(), center.y + radius * a.sin())
            })
            .collect()
    };
    let painter = ui.painter_at(rect.expand(4.0));
    painter.add(Shape::line(arc(0.0, 1.0), Stroke::new(10.0_f32, p.hover)));
    let f = fraction.clamp(0.0, 1.0);
    if f > 0.005 {
        painter.add(Shape::line(arc(0.0, f), Stroke::new(10.0_f32, color)));
    }
    painter.text(
        center - vec2(0.0, 4.0),
        Align2::CENTER_CENTER,
        value,
        semibold(size * 0.2),
        p.text,
    );
    painter.text(
        center + vec2(0.0, size * 0.17),
        Align2::CENTER_CENTER,
        caption,
        regular(13.0),
        p.muted,
    );
}

/// A big number with a caption above it and an optional note below.
pub fn stat(ui: &mut Ui, caption: &str, value: &str, note: &str) {
    let p = pal(ui);
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 1.0;
        ui.label(RichText::new(caption).size(12.5).color(p.muted));
        ui.label(RichText::new(value).font(semibold(22.0)));
        if !note.is_empty() {
            ui.label(RichText::new(note).size(12.0).color(p.faint));
        }
    });
}
