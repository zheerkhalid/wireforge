//! Build script: renders the WireForge icon (vector, via tiny-skia) into a
//! multi-size .ico and a PNG for the window, then embeds the icon, manifest and version info.

#![allow(clippy::field_reassign_with_default)]

use std::{env, fs, path::PathBuf};
use tiny_skia::*;

fn rounded_rect(x0: f32, y0: f32, x1: f32, y1: f32, r: f32) -> Path {
    let mut pb = PathBuilder::new();
    pb.move_to(x0 + r, y0);
    pb.line_to(x1 - r, y0);
    pb.quad_to(x1, y0, x1, y0 + r);
    pb.line_to(x1, y1 - r);
    pb.quad_to(x1, y1, x1 - r, y1);
    pb.line_to(x0 + r, y1);
    pb.quad_to(x0, y1, x0, y1 - r);
    pb.line_to(x0, y0 + r);
    pb.quad_to(x0, y0, x0 + r, y0);
    pb.close();
    pb.finish().expect("rounded rect")
}

fn render_icon(size: u32) -> Vec<u8> {
    let mut pm = Pixmap::new(size, size).expect("pixmap");
    let s = size as f32 / 256.0;
    let id = Transform::identity();

    // Background: rounded square, deep blue -> electric cyan gradient.
    let (x0, y0, x1, y1) = (8.0 * s, 8.0 * s, 248.0 * s, 248.0 * s);
    let bg = rounded_rect(x0, y0, x1, y1, 56.0 * s);
    let mut paint = Paint::default();
    paint.anti_alias = true;
    paint.shader = LinearGradient::new(
        Point::from_xy(x0, y0),
        Point::from_xy(x1, y1),
        vec![
            GradientStop::new(0.0, Color::from_rgba8(0x1b, 0x3f, 0xd8, 255)),
            GradientStop::new(1.0, Color::from_rgba8(0x12, 0xd6, 0xff, 255)),
        ],
        SpreadMode::Pad,
        id,
    )
    .expect("gradient");
    pm.fill_path(&bg, &paint, FillRule::Winding, id, None);

    let fill = |pm: &mut Pixmap, path: &Path, r: u8, g: u8, b: u8, a: u8| {
        let mut p = Paint::default();
        p.anti_alias = true;
        p.set_color_rgba8(r, g, b, a);
        pm.fill_path(path, &p, FillRule::Winding, id, None);
    };
    // A soft highlight in the upper left corner.
    let mut pb = PathBuilder::new();
    pb.push_circle(70.0 * s, 54.0 * s, 120.0 * s);
    if let Some(glow) = pb.finish() {
        let mut p = Paint::default();
        p.anti_alias = true;
        p.set_color_rgba8(255, 255, 255, 20);
        let mask = Mask::from_pixmap(pm.as_ref(), MaskType::Alpha);
        pm.fill_path(&glow, &p, FillRule::Winding, id, Some(&mask));
    }

    // Signal arcs fanning upwards from a node on a wire.
    let (cx, cy) = (128.0_f32, 182.0_f32);
    let small = size < 32;
    let arcs: &[(f32, f32, u8)] = if small {
        &[(58.0, 26.0, 255), (108.0, 26.0, 255)]
    } else {
        &[(46.0, 19.0, 255), (80.0, 19.0, 255), (114.0, 19.0, 255)]
    };
    for &(radius, width, alpha) in arcs {
        let mut pb = PathBuilder::new();
        let steps = 48;
        for i in 0..=steps {
            // 225 to 315 degrees: a quarter circle opening upwards.
            let a = (225.0 + 90.0 * i as f32 / steps as f32).to_radians();
            let (x, y) = ((cx + radius * a.cos()) * s, (cy + radius * a.sin()) * s);
            if i == 0 {
                pb.move_to(x, y)
            } else {
                pb.line_to(x, y)
            }
        }
        let path = pb.finish().expect("arc");
        let mut p = Paint::default();
        p.anti_alias = true;
        p.set_color_rgba8(255, 255, 255, alpha);
        let mut stroke = Stroke::default();
        stroke.width = width * s;
        stroke.line_cap = LineCap::Round;
        pm.stroke_path(&path, &p, &stroke, id, None);
    }
    // The wire with its end points, and the node in the middle.
    if !small {
        let wire = rounded_rect(54.0 * s, 176.0 * s, 202.0 * s, 188.0 * s, 6.0 * s);
        fill(&mut pm, &wire, 0xff, 0xff, 0xff, 150);
        for x in [54.0_f32, 202.0] {
            let mut pb = PathBuilder::new();
            pb.push_circle(x * s, cy * s, 11.0 * s);
            fill(&mut pm, &pb.finish().expect("end"), 0xd8, 0xf4, 0xff, 255);
        }
    }
    let mut pb = PathBuilder::new();
    pb.push_circle(cx * s, cy * s, if small { 26.0 } else { 21.0 } * s);
    fill(&mut pm, &pb.finish().expect("node"), 0xff, 0xff, 0xff, 255);

    pm.encode_png().expect("png")
}

fn write_ico(path: &PathBuf, sizes: &[u32]) {
    let pngs: Vec<Vec<u8>> = sizes.iter().map(|&s| render_icon(s)).collect();
    let mut out = Vec::new();
    out.extend_from_slice(&[0, 0, 1, 0]);
    out.extend_from_slice(&(sizes.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * sizes.len() as u32;
    for (i, &s) in sizes.iter().enumerate() {
        let b = if s >= 256 { 0 } else { s as u8 };
        out.extend_from_slice(&[b, b, 0, 0, 1, 0, 32, 0]);
        out.extend_from_slice(&(pngs[i].len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += pngs[i].len() as u32;
    }
    for p in &pngs {
        out.extend_from_slice(p);
    }
    fs::write(path, out).expect("write ico");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let ico = out.join("wireforge.ico");
    write_ico(&ico, &[16, 20, 24, 32, 40, 48, 64, 256]);
    let png = render_icon(256);
    fs::write(out.join("icon-256.png"), &png).expect("write png");
    let docs_png = PathBuf::from("docs/assets/wireforge-icon.png");
    if fs::read(&docs_png).ok().as_deref() != Some(&png[..]) {
        let _ = fs::create_dir_all("docs/assets");
        let _ = fs::write(&docs_png, &png);
    }

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let ver = env::var("CARGO_PKG_VERSION").expect("version");
    let parts: Vec<u16> = ver
        .split(['.', '-'])
        .take(3)
        .map(|p| p.parse().unwrap_or(0))
        .collect();
    let (ma, mi, pa) = (
        parts[0],
        parts.get(1).copied().unwrap_or(0),
        parts.get(2).copied().unwrap_or(0),
    );
    let ver4 = format!("{ma}.{mi}.{pa}.0");
    println!("cargo:rerun-if-changed=res/wireforge.manifest.in");
    let manifest = fs::read_to_string("res/wireforge.manifest.in")
        .expect("manifest")
        .replace("@VERSION4@", &ver4);
    let manifest_path = out.join("wireforge.manifest");
    fs::write(&manifest_path, manifest).expect("write manifest");
    let esc = |p: &PathBuf| p.display().to_string().replace('\\', "\\\\");
    let rc = format!(
        r#"#pragma code_page(65001)
1 ICON "{ico}"
1 24 "{manifest}"
1 VERSIONINFO
FILEVERSION {ma},{mi},{pa},0
PRODUCTVERSION {ma},{mi},{pa},0
FILEOS 0x40004
FILETYPE 0x1
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "Zheer Khalid (zheer.dev)"
      VALUE "FileDescription", "WireForge network monitor"
      VALUE "FileVersion", "{ver}"
      VALUE "InternalName", "WireForge"
      VALUE "LegalCopyright", "Copyright (c) 2026 Zheer Khalid. MIT License."
      VALUE "OriginalFilename", "WireForge.exe"
      VALUE "ProductName", "WireForge"
      VALUE "ProductVersion", "{ver}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#,
        ico = esc(&ico),
        manifest = esc(&manifest_path),
    );
    let rc_path = out.join("wireforge.rc");
    fs::write(&rc_path, rc).expect("write rc");
    embed_resource::compile(&rc_path, embed_resource::NONE);
    println!("cargo:rustc-link-arg-bins=/MANIFEST:NO");
}
