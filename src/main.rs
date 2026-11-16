#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::path::PathBuf;
use wireforge::ui::{self, Options};

const USAGE: &str = "WireForge

  WireForge.exe                    open the program
  WireForge.exe --minimized        start hidden in the notification area
  WireForge.exe --demo             show invented data; this PC and its network are not read
  WireForge.exe --screenshot <png> render the window to a PNG and exit (use with --demo)
        [--view <name>] [--light]
        views: overview, overview-ip, apps, apps-details, usage, connections,
               wifi, wifi-channels, wifi-signal, saved, saved-qr, saved-export, devices,
               devices-scan, tools-ping, tools-trace, tools-dns, tools-ports, tools-wol,
               tools-whois, tools-subnet, tools-report, tools-actions, speed, speed-running,
               speed-consent, settings, about
        (the view can also be set with the WIREFORGE_VIEW environment variable)
  WireForge.exe --selftest         run every collector once and print success or failure
                                   with counts only (no addresses, names or passwords)";

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |flag: &str| args.iter().any(|a| a == flag);
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };

    if has("--help") || has("-h") || has("/?") {
        wireforge::sys::attach_console();
        println!("{USAGE}");
        return Ok(());
    }
    if has("--selftest") {
        wireforge::sys::attach_console();
        let mut failed = 0;
        for (name, result) in wireforge::selftest::run() {
            match result {
                Ok(summary) => println!("ok    {name}: {summary}"),
                Err(reason) if wireforge::selftest::needs_admin(&name, &reason) => {
                    println!("skip  {name}: {reason}")
                }
                Err(reason) => {
                    failed += 1;
                    println!("FAIL  {name}: {reason}");
                }
            }
        }
        if failed == 0 {
            println!("SELFTEST PASSED");
            std::process::exit(0);
        }
        println!("SELFTEST FAILED ({failed})");
        std::process::exit(1);
    }

    let options = Options {
        demo: has("--demo"),
        screenshot: value("--screenshot").map(PathBuf::from),
        view: value("--view").or_else(|| std::env::var("WIREFORGE_VIEW").ok()),
        light: has("--light"),
        minimized: has("--minimized"),
    };
    ui::run(options, window_icon())
}

fn window_icon() -> egui::IconData {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/icon-256.png"));
    match image::load_from_memory(bytes) {
        Ok(img) => {
            let rgba = img.into_rgba8();
            let (width, height) = rgba.dimensions();
            egui::IconData {
                rgba: rgba.into_raw(),
                width,
                height,
            }
        }
        Err(_) => egui::IconData::default(),
    }
}
