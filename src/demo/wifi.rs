//! Invented Wi-Fi networks, saved profiles and devices for `--demo`.
//!
//! Everything here is made up: network names, addresses, vendors, passwords.

use wf_wifi::{channels, Band, Bss, KeyState, KnownDevice, SavedProfile};

/// The network the demo PC is attached to.
pub const SUBNET: &str = "192.168.50.0/24";
pub const ADAPTER: &str = "Wi-Fi";

#[allow(clippy::too_many_arguments)]
fn ap(
    ssid: &str,
    bssid: &str,
    rssi: i32,
    band: Band,
    channel: u16,
    width: u16,
    generation: Option<u8>,
    security: &str,
    vendor: Option<&str>,
) -> Bss {
    let phy = match generation {
        Some(7) => "802.11be",
        Some(6) => "802.11ax",
        Some(5) => "802.11ac",
        Some(4) => "802.11n",
        _ => "802.11g",
    };
    let freq = channels::freq_from_channel(band, channel).unwrap_or(0);
    Bss {
        ssid: ssid.into(),
        bssid: bssid.into(),
        rssi_dbm: rssi,
        quality: channels::quality_from_rssi(rssi),
        freq_mhz: freq,
        channel,
        band,
        width_mhz: Some(width),
        phy: phy.into(),
        generation,
        security: security.into(),
        vendor: vendor.map(str::to_string),
        connected: false,
        beacon_interval_ms: Some(102),
        max_rate_mbps: Some(if generation.is_some() { 54.0 } else { 11.0 }),
        stations: None,
        utilization: None,
        country: Some("GB".into()),
        center_mhz: (width == 20).then_some(freq),
    }
}

/// About eighteen access points over three bands, strongest first.
pub fn networks() -> Vec<Bss> {
    use Band::{B24, B5, B6};
    let orbit = Some("Orbitlink Networks");
    let north = Some("Northwind Devices");
    let fern = Some("Fernleaf Electronics");
    let kestrel = Some("Kestrel Systems");
    let tall = Some("Tallgrass Peripherals");
    let mut list = vec![
        // 2.4 GHz
        ap(
            "Maple-Home",
            "D4:6E:0E:5A:21:91",
            -47,
            B24,
            6,
            20,
            Some(6),
            "WPA3-Personal",
            orbit,
        ),
        ap(
            "Birchwood-Guest",
            "58:2F:40:1B:7C:A2",
            -63,
            B24,
            1,
            20,
            Some(4),
            "WPA2-Personal",
            north,
        ),
        ap(
            "Harbour-Cafe-Free",
            "0C:8D:DB:44:19:E0",
            -71,
            B24,
            11,
            20,
            Some(4),
            "Open",
            fern,
        ),
        ap(
            "",
            "9C:53:22:6F:0D:14",
            -68,
            B24,
            6,
            20,
            Some(4),
            "WPA2-Personal",
            None,
        ),
        ap(
            "Willow-Flat-3",
            "B0:4E:26:91:5A:38",
            -58,
            B24,
            11,
            40,
            Some(4),
            "WPA/WPA2-Personal",
            kestrel,
        ),
        ap(
            "Old-Printer-Setup",
            "00:1E:8F:3A:60:C5",
            -80,
            B24,
            3,
            20,
            None,
            "WEP",
            tall,
        ),
        ap(
            "Cedar-Office",
            "74:AC:B9:20:D7:01",
            -76,
            B24,
            1,
            20,
            Some(6),
            "WPA2-Enterprise",
            north,
        ),
        ap(
            "Juniper-IoT",
            "E8:9F:80:C4:2B:7D",
            -84,
            B24,
            13,
            20,
            Some(4),
            "WPA2-Personal",
            fern,
        ),
        // 5 GHz
        ap(
            "Maple-Home",
            "D4:6E:0E:5A:21:90",
            -52,
            B5,
            36,
            80,
            Some(6),
            "WPA3-Personal",
            orbit,
        ),
        ap(
            "Maple-Home",
            "D4:6E:0E:5A:3C:10",
            -66,
            B5,
            149,
            80,
            Some(6),
            "WPA3-Personal",
            orbit,
        ),
        ap(
            "Birchwood-5G",
            "58:2F:40:1B:7C:A6",
            -69,
            B5,
            44,
            80,
            Some(5),
            "WPA2-Personal",
            north,
        ),
        ap(
            "Willow-Flat-3",
            "B0:4E:26:91:5A:3C",
            -61,
            B5,
            100,
            80,
            Some(6),
            "WPA2/WPA3-Personal",
            kestrel,
        ),
        ap(
            "Cedar-Office",
            "74:AC:B9:20:D7:05",
            -74,
            B5,
            52,
            40,
            Some(6),
            "WPA2-Enterprise",
            north,
        ),
        ap(
            "Aspen-Studio",
            "A4:91:B1:7E:02:5F",
            -78,
            B5,
            157,
            80,
            Some(5),
            "WPA2-Personal",
            fern,
        ),
        ap(
            "Rowan-Loft",
            "3C:84:6A:D0:55:B9",
            -82,
            B5,
            116,
            160,
            Some(6),
            "WPA3-Personal",
            kestrel,
        ),
        ap(
            "Harbour-Cafe-Free",
            "0C:8D:DB:44:19:E4",
            -75,
            B5,
            165,
            20,
            Some(5),
            "Open",
            fern,
        ),
        // 6 GHz
        ap(
            "Maple-Home",
            "D4:6E:0E:5A:21:92",
            -58,
            B6,
            37,
            160,
            Some(7),
            "WPA3-Personal",
            orbit,
        ),
        ap(
            "Willow-Flat-3",
            "B0:4E:26:91:5A:40",
            -72,
            B6,
            117,
            80,
            Some(6),
            "WPA3-Personal",
            kestrel,
        ),
    ];
    for b in &mut list {
        if b.bssid == "D4:6E:0E:5A:21:90" {
            b.connected = true;
            b.stations = Some(7);
            b.utilization = Some(18);
            b.max_rate_mbps = Some(54.0);
        }
        if b.ssid == "Cedar-Office" {
            b.stations = Some(23);
            b.utilization = Some(41);
        }
    }
    list.sort_by_key(|b| -b.rssi_dbm);
    list
}

/// Two invented moves between the mesh access points: (seconds ago, from, to).
pub fn roaming() -> Vec<(i64, &'static str, &'static str)> {
    vec![
        (47 * 60, "D4:6E:0E:5A:21:90", "D4:6E:0E:5A:3C:10"),
        (41 * 60, "D4:6E:0E:5A:3C:10", "D4:6E:0E:5A:21:90"),
    ]
}

fn profile(name: &str, security: &str, key: KeyState) -> SavedProfile {
    let (auth, cipher) = match security {
        "WPA3-Personal" => ("WPA3SAE", "AES"),
        "WPA2/WPA3-Personal" => ("WPA2PSK", "AES"),
        "WPA2-Enterprise" => ("WPA2", "AES"),
        "Open" => ("open", "none"),
        "WEP" => ("open", "WEP"),
        _ => ("WPA2PSK", "AES"),
    };
    SavedProfile {
        name: name.into(),
        ssid: name.into(),
        security: security.into(),
        auth: auth.into(),
        cipher: cipher.into(),
        auto_connect: true,
        hidden: false,
        key_type: match &key {
            KeyState::Key(_) => "passPhrase".into(),
            _ => String::new(),
        },
        key,
        all_users: false,
        interface_guid: "{5D1F0A52-7C1B-4E0E-9B7A-2F6C1D3E4A10}".into(),
        random_mac: Some(false),
        priority: 0,
    }
}

/// Saved networks covering every key state. The passwords are invented.
pub fn profiles() -> Vec<SavedProfile> {
    let key = |k: &str| KeyState::Key(k.to_string());
    let mut list = vec![
        SavedProfile {
            all_users: true,
            ..profile("Maple-Home", "WPA3-Personal", key("maple-kettle-2041"))
        },
        SavedProfile {
            auto_connect: false,
            ..profile("Maple-Home-Guest", "WPA2-Personal", key("welcome-to-maple"))
        },
        profile("Birchwood-Guest", "WPA2-Personal", key("birch-lantern-77")),
        SavedProfile {
            auto_connect: false,
            ..profile("Harbour-Cafe-Free", "Open", KeyState::Open)
        },
        SavedProfile {
            all_users: true,
            ..profile("Cedar-Office", "WPA2-Enterprise", KeyState::Enterprise)
        },
        SavedProfile {
            all_users: true,
            ..profile("Willow-Flat-3", "WPA2/WPA3-Personal", KeyState::NeedsAdmin)
        },
        SavedProfile {
            auto_connect: false,
            ..profile("Pinecone-Hotspot", "WPA2-Personal", key("pocket-signal-9"))
        },
        SavedProfile {
            hidden: true,
            ..profile("Hidden-Attic", "WPA2-Personal", key("attic-window-318"))
        },
        SavedProfile {
            auto_connect: false,
            ..profile("Old-Workshop", "WEP", key("A1B2C3D4E5"))
        },
        SavedProfile {
            auto_connect: false,
            ..profile(
                "Lakeside-Library",
                "WPA2-Personal",
                KeyState::Unavailable("The profile does not contain a saved key.".into()),
            )
        },
        SavedProfile {
            key_type: "networkKey".into(),
            ..profile(
                "Garden-Shed-Bridge",
                "WPA2-Personal",
                key("3f9a1c0b7e52d4486a1b9c0d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5"),
            )
        },
    ];
    for (i, p) in list.iter_mut().enumerate() {
        p.priority = i as u32;
    }
    list
}

#[allow(clippy::too_many_arguments)]
fn device(
    ip: u8,
    mac: &str,
    label: &str,
    name: Option<&str>,
    source: Option<&str>,
    vendor: Option<&str>,
    hint: Option<&str>,
    known: bool,
    first_ago: i64,
    last_ago: i64,
    now: i64,
) -> KnownDevice {
    let second = mac.as_bytes().get(1).copied().unwrap_or(b'0');
    KnownDevice {
        mac: mac.into(),
        label: label.into(),
        known,
        first_seen: now - first_ago,
        last_seen: now - last_ago,
        last_ip: format!("192.168.50.{ip}"),
        vendor: vendor.map(str::to_string),
        name: name.map(str::to_string),
        name_source: source.map(str::to_string),
        kind_hint: hint.map(str::to_string),
        is_gateway: false,
        is_self: false,
        random_mac: matches!(second, b'2' | b'6' | b'A' | b'E'),
        online: last_ago == SCAN_AGO,
        rtt_ms: (last_ago == SCAN_AGO).then_some(2 + u32::from(ip) % 9),
    }
}

/// How long ago the demo's last device scan finished, in seconds.
pub const SCAN_AGO: i64 = 180;
/// The MAC address of the device that is new in the demo's last scan.
pub const NEW_DEVICE: &str = "70:B3:D5:1C:44:09";

/// A dozen devices on the invented home network.
pub fn devices(now: i64) -> Vec<KnownDevice> {
    const DAY: i64 = 86_400;
    let s = SCAN_AGO;
    let mut list = vec![
        device(
            1,
            "D4:6E:0E:5A:21:8F",
            "",
            Some("maple-router"),
            Some("mDNS"),
            Some("Orbitlink Networks"),
            Some("InternetGatewayDevice"),
            true,
            94 * DAY,
            s,
            now,
        ),
        device(
            23,
            "3C:9A:77:2B:19:5C",
            "",
            Some("STUDY-PC"),
            Some("NetBIOS"),
            Some("Kestrel Systems"),
            None,
            true,
            94 * DAY,
            s,
            now,
        ),
        device(
            31,
            "A6:3B:19:70:C2:4E",
            "Sam's phone",
            Some("sams-phone"),
            Some("mDNS"),
            None,
            Some("phone"),
            true,
            61 * DAY,
            s,
            now,
        ),
        device(
            32,
            "5E:91:0C:D2:77:18",
            "",
            None,
            None,
            None,
            None,
            false,
            3 * DAY,
            s,
            now,
        ),
        device(
            40,
            "0C:8D:DB:7A:33:10",
            "Living-room TV",
            Some("living-room-tv"),
            Some("SSDP"),
            Some("Fernleaf Electronics"),
            Some("MediaRenderer tv"),
            true,
            80 * DAY,
            s,
            now,
        ),
        device(
            41,
            "00:1E:8F:3A:61:07",
            "",
            Some("Hallway printer"),
            Some("mDNS"),
            Some("Tallgrass Peripherals"),
            Some("printer"),
            true,
            90 * DAY,
            s,
            now,
        ),
        device(
            45,
            "E8:9F:80:C4:90:2A",
            "Kitchen speaker",
            Some("kitchen-speaker"),
            Some("mDNS"),
            Some("Bluepine Labs"),
            Some("speaker"),
            true,
            40 * DAY,
            s,
            now,
        ),
        device(
            52,
            "3C:9A:77:80:4D:E1",
            "",
            Some("ALEX-LAPTOP"),
            Some("NetBIOS"),
            Some("Kestrel Systems"),
            None,
            true,
            75 * DAY,
            2 * DAY + 3 * 3600,
            now,
        ),
        device(
            60,
            "58:2F:40:66:0A:9C",
            "",
            None,
            None,
            Some("Northwind Devices"),
            None,
            false,
            12 * DAY,
            s,
            now,
        ),
        device(
            61,
            "74:AC:B9:13:5F:C8",
            "",
            Some("attic-storage"),
            Some("mDNS"),
            Some("Northwind Devices"),
            Some("storage"),
            true,
            88 * DAY,
            s,
            now,
        ),
        device(77, NEW_DEVICE, "", None, None, None, None, false, s, s, now),
        device(
            88,
            "B2:47:E0:19:6C:D3",
            "Kids' tablet",
            None,
            None,
            None,
            Some("tablet"),
            true,
            30 * DAY,
            5 * 3600,
            now,
        ),
    ];
    list[0].is_gateway = true;
    list[1].is_self = true;
    list
}
