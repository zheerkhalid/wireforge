//! Runs ONE speed test and prints only the numbers and the provider name
//! (never the public IP address or the server). Running this sends a test
//! to M-Lab, which publishes results including the IP address: see
//! `wf_tools::speedtest::provider().notice`.
//! `cargo run -p wf-tools --example speed`

use std::sync::atomic::AtomicBool;
use wf_tools::SpeedPhase;

fn main() {
    let provider = wf_tools::speedtest::provider();
    println!("provider: {} ({})", provider.name, provider.operator);
    let cancel = AtomicBool::new(false);
    let mut last_phase = None;
    let mut updates = 0u32;
    let result = wf_tools::speedtest::run(&cancel, &mut |p| {
        updates += 1;
        if last_phase != Some(p.phase) {
            last_phase = Some(p.phase);
            let name = match p.phase {
                SpeedPhase::Locating => "locating",
                SpeedPhase::Latency => "latency",
                SpeedPhase::Download => "download",
                SpeedPhase::Upload => "upload",
                SpeedPhase::Done => "done",
            };
            println!("phase: {name}");
        }
    });
    match result {
        Ok(r) => {
            println!("download: {:.2} Mbit/s", r.download_mbps);
            println!("upload:   {:.2} Mbit/s", r.upload_mbps);
            println!("latency:  {:.2} ms", r.latency_ms);
            println!("jitter:   {:.2} ms", r.jitter_ms);
            println!(
                "data:     {:.1} MB down, {:.1} MB up, {} progress updates",
                r.bytes_down as f64 / 1e6,
                r.bytes_up as f64 / 1e6,
                updates
            );
        }
        Err(e) => {
            // Errors may quote system messages but never addresses.
            println!("failed: {e}");
            std::process::exit(1);
        }
    }
}
