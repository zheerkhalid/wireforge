//! Runs one device scan of the directly attached private subnet and prints
//! counts only: `cargo run -p wf-wifi --example devscan`.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use wf_wifi::devices;

fn main() {
    let Some(network) = devices::default_network() else {
        println!("no attached private network of at most 1,024 addresses: nothing to scan");
        return;
    };
    let options = devices::ScanOptions::for_network(&network, true);
    println!(
        "scanning a /{} network ({} addresses){}",
        options.subnet.prefix,
        options.subnet.hosts().len(),
        if network.wifi { " on Wi-Fi" } else { "" }
    );
    let cancel = AtomicBool::new(false);
    let calls = AtomicU32::new(0);
    let started = std::time::Instant::now();
    let result = devices::scan(&options, &cancel, &|_, _| {
        calls.fetch_add(1, Ordering::Relaxed);
    });
    let seconds = started.elapsed().as_secs_f32();
    match result {
        Ok(found) => {
            let n = |test: &dyn Fn(&wf_wifi::FoundDevice) -> bool| {
                found.iter().filter(|d| test(d)).count()
            };
            let by = |source: &str| n(&|d| d.name_source.as_deref() == Some(source));
            println!(
                "{} devices in {seconds:.1} s ({} progress calls): {} with a MAC, {} with a vendor, {} with a random MAC, {} answering ping",
                found.len(),
                calls.load(Ordering::Relaxed),
                n(&|d| !d.mac.is_empty()),
                n(&|d| d.vendor.is_some()),
                n(&|d| d.random_mac),
                n(&|d| d.rtt_ms.is_some() && !d.is_self),
            );
            println!(
                "{} named: {} mDNS, {} NetBIOS, {} SSDP, {} DNS; {} with a kind hint; gateway found: {}; this PC listed: {}",
                n(&|d| d.name.is_some()),
                by("mDNS"),
                by("NetBIOS"),
                by("SSDP"),
                by("DNS"),
                n(&|d| d.kind_hint.is_some()),
                n(&|d| d.is_gateway),
                n(&|d| d.is_self),
            );
        }
        Err(reason) => println!("scan refused or failed after {seconds:.1} s: {reason}"),
    }
}
