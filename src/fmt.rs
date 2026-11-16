//! Formatting of sizes, rates, times and signal values.

use serde::{Deserialize, Serialize};

/// How transfer rates are shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Units {
    /// kB/s, MB/s (bytes; what download dialogs show).
    Bytes,
    /// kbit/s, Mbit/s (bits; what internet providers advertise).
    Bits,
}

fn scaled(value: f64, step: f64, units: &[&str]) -> String {
    let mut v = value.max(0.0);
    let mut i = 0;
    while v >= step && i + 1 < units.len() {
        v /= step;
        i += 1;
    }
    // Rounding may push 999.96 to "1000.0": move to the next unit instead.
    if i > 0 && v >= 999.5 && i + 1 < units.len() {
        v /= step;
        i += 1;
    }
    if i == 0 {
        format!("{:.0} {}", v, units[0])
    } else if v >= 100.0 {
        format!("{:.0} {}", v, units[i])
    } else if v >= 10.0 {
        format!("{:.1} {}", v, units[i])
    } else {
        format!("{:.2} {}", v, units[i])
    }
}

/// `1.50 GB` (binary steps, the way Windows counts).
pub fn bytes(n: u64) -> String {
    scaled(n as f64, 1024.0, &["B", "KB", "MB", "GB", "TB", "PB"])
}

/// A rate given in bytes per second, shown in the chosen unit.
pub fn rate(bytes_per_sec: f64, units: Units) -> String {
    match units {
        Units::Bytes => scaled(
            bytes_per_sec,
            1024.0,
            &["B/s", "KB/s", "MB/s", "GB/s", "TB/s"],
        ),
        Units::Bits => scaled(
            bytes_per_sec * 8.0,
            1000.0,
            &["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"],
        ),
    }
}

/// A very short rate for the tray and the mini meter: `1.2M`, `340K`, `0`.
pub fn rate_compact(bytes_per_sec: f64, units: Units) -> String {
    let (v, step) = match units {
        Units::Bytes => (bytes_per_sec.max(0.0), 1024.0),
        Units::Bits => (bytes_per_sec.max(0.0) * 8.0, 1000.0),
    };
    let names = ["", "K", "M", "G", "T"];
    let mut v = v;
    let mut i = 0;
    while v >= 999.5 && i + 1 < names.len() {
        v /= step;
        i += 1;
    }
    if i == 0 {
        format!("{v:.0}")
    } else if v >= 10.0 {
        format!("{:.0}{}", v, names[i])
    } else {
        format!("{:.1}{}", v, names[i])
    }
}

/// A link speed given in bits per second: `866 Mbit/s`, `1 Gbit/s`.
pub fn link_speed(bps: u64) -> String {
    if bps == 0 || bps == u64::MAX {
        return "Unknown".into();
    }
    let v = bps as f64;
    if v >= 1e9 {
        let g = v / 1e9;
        if (g - g.round()).abs() < 0.05 {
            format!("{:.0} Gbit/s", g)
        } else {
            format!("{:.1} Gbit/s", g)
        }
    } else if v >= 1e6 {
        let m = v / 1e6;
        if (m - m.round()).abs() < 0.05 {
            format!("{:.0} Mbit/s", m)
        } else {
            format!("{:.1} Mbit/s", m)
        }
    } else {
        format!("{:.0} kbit/s", v / 1e3)
    }
}

/// `1,234,567`
pub fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `2 d 3 h`, `4 h 12 min`, `35 min`, `12 s`.
pub fn duration(secs: i64) -> String {
    let s = secs.max(0);
    if s >= 86_400 {
        format!("{} d {} h", s / 86_400, (s % 86_400) / 3600)
    } else if s >= 3600 {
        format!("{} h {} min", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{} min", s / 60)
    } else {
        format!("{s} s")
    }
}

/// `just now`, `5 min ago`, `3 h ago`, `2 days ago`.
pub fn ago(now_unix: i64, then_unix: i64) -> String {
    let s = now_unix - then_unix;
    if s < 60 {
        "just now".into()
    } else if s < 3600 {
        format!("{} min ago", s / 60)
    } else if s < 86_400 {
        format!("{} h ago", s / 3600)
    } else if s < 2 * 86_400 {
        "yesterday".into()
    } else {
        format!("{} days ago", s / 86_400)
    }
}

/// `12.3 ms`, `0.4 ms`, `1,204 ms`.
pub fn millis(ms: f64) -> String {
    if ms >= 100.0 {
        format!("{} ms", thousands(ms.round() as u64))
    } else if ms >= 10.0 {
        format!("{ms:.1} ms")
    } else {
        format!("{ms:.2} ms")
    }
}

/// The next "round" number at or above `v`, for chart axes: 1, 1.2, 1.6, 2, 2.4, 3.2, 4, 5, 6, 8, 10...
pub fn nice_ceiling(v: f64) -> f64 {
    if !v.is_finite() || v <= 0.0 {
        return 1.0;
    }
    let exp = v.log10().floor();
    let base = 10f64.powf(exp);
    let f = v / base;
    // Every step divides by four into tidy axis labels.
    const STEPS: [f64; 11] = [1.0, 1.2, 1.6, 2.0, 2.4, 3.2, 4.0, 5.0, 6.0, 8.0, 10.0];
    let nice = STEPS
        .iter()
        .copied()
        .find(|s| f <= *s * (1.0 + 1e-9))
        .unwrap_or(10.0);
    nice * base
}

/// A chart ceiling for a rate in bytes per second that lands on a round
/// number in the chosen unit (never below 10 KB/s so idle noise stays small).
pub fn rate_ceiling(max_bytes_per_sec: f64, units: Units) -> f64 {
    match units {
        Units::Bytes => {
            let v = max_bytes_per_sec.max(10.0 * 1024.0);
            let mut unit = 1024.0;
            while v / unit >= 1024.0 {
                unit *= 1024.0;
            }
            nice_ceiling(v / unit) * unit
        }
        Units::Bits => {
            let v = (max_bytes_per_sec * 8.0).max(100_000.0);
            nice_ceiling(v) / 8.0
        }
    }
}

/// A chart ceiling for a byte count that lands on a round number of KB / MB / GB.
pub fn bytes_ceiling(max_bytes: f64) -> f64 {
    let v = max_bytes.max(1.0);
    let mut unit = 1.0;
    while v / unit >= 1024.0 {
        unit *= 1024.0;
    }
    nice_ceiling(v / unit) * unit
}

/// Civil date from days since 1970-01-01 (proleptic Gregorian).
pub fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    ((if m <= 2 { y + 1 } else { y }) as i32, m, d)
}

/// Days since 1970-01-01 of a civil date.
pub fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y as i64 - 1 } else { y as i64 };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m as i64 - 3 } else { m as i64 + 9 };
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `2026-11-16 14:05` for a Unix time shifted by `offset_secs` (local offset).
pub fn date_time(unix: i64, offset_secs: i64) -> String {
    let t = unix + offset_secs;
    let (y, m, d) = civil_from_days(t.div_euclid(86_400));
    let s = t.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        s / 3600,
        (s % 3600) / 60
    )
}

/// `14:05:09`
pub fn clock(unix: i64, offset_secs: i64) -> String {
    let s = (unix + offset_secs).rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

pub const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `16 Nov`
pub fn day_label(m: u32, d: u32) -> String {
    format!("{d} {}", MONTHS[(m.clamp(1, 12) - 1) as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_rates() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1536), "1.50 KB");
        assert_eq!(bytes(5 * 1024 * 1024 * 1024), "5.00 GB");
        assert_eq!(bytes(1024 * 1024 - 1), "1.00 MB");
        assert_eq!(rate(1024.0 * 1024.0 * 12.34, Units::Bytes), "12.3 MB/s");
        assert_eq!(rate(125_000.0, Units::Bits), "1.00 Mbit/s");
        assert_eq!(rate(-5.0, Units::Bits), "0 bit/s");
        assert_eq!(rate_compact(0.0, Units::Bytes), "0");
        assert_eq!(rate_compact(1_300_000.0, Units::Bytes), "1.2M");
        assert_eq!(rate_compact(350.0 * 1024.0, Units::Bytes), "350K");
        assert_eq!(rate_compact(125_000.0, Units::Bits), "1.0M");
    }

    #[test]
    fn link_speeds_and_counts() {
        assert_eq!(link_speed(0), "Unknown");
        assert_eq!(link_speed(1_000_000_000), "1 Gbit/s");
        assert_eq!(link_speed(866_700_000), "866.7 Mbit/s");
        assert_eq!(link_speed(2_402_000_000), "2.4 Gbit/s");
        assert_eq!(link_speed(54_000_000), "54 Mbit/s");
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn times() {
        assert_eq!(duration(12), "12 s");
        assert_eq!(duration(35 * 60 + 5), "35 min");
        assert_eq!(duration(4 * 3600 + 12 * 60), "4 h 12 min");
        assert_eq!(duration(2 * 86_400 + 3 * 3600), "2 d 3 h");
        assert_eq!(ago(1000, 990), "just now");
        assert_eq!(ago(10_000, 10_000 - 300), "5 min ago");
        assert_eq!(ago(200_000, 200_000 - 90_000), "yesterday");
        assert_eq!(ago(900_000, 900_000 - 3 * 86_400), "3 days ago");
        assert_eq!(millis(0.42), "0.42 ms");
        assert_eq!(millis(12.34), "12.3 ms");
        assert_eq!(millis(1204.0), "1,204 ms");
    }

    #[test]
    fn calendar() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(days_from_civil(2024, 2, 29)), (2024, 2, 29));
        assert_eq!(days_from_civil(2026, 11, 16), 20_773);
        for z in [-800_000, -1, 0, 59, 365, 11_016, 20_773, 100_000] {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
        // 2026-11-16 12:34:56 UTC
        let t = 20_773 * 86_400 + 12 * 3600 + 34 * 60 + 56;
        assert_eq!(date_time(t, 0), "2026-11-16 12:34");
        assert_eq!(date_time(t, 3 * 3600), "2026-11-16 15:34");
        assert_eq!(date_time(t, 12 * 3600), "2026-11-17 00:34");
        assert_eq!(clock(t, -3600), "11:34:56");
        assert_eq!(day_label(11, 16), "16 Nov");
    }

    #[test]
    fn axis_ceilings() {
        assert_eq!(nice_ceiling(0.0), 1.0);
        assert_eq!(nice_ceiling(1.0), 1.0);
        assert_eq!(nice_ceiling(1.2), 1.2);
        assert_eq!(nice_ceiling(1.3), 1.6);
        assert_eq!(nice_ceiling(37.0), 40.0);
        assert_eq!(nice_ceiling(51.0), 60.0);
        assert_eq!(nice_ceiling(950.0), 1000.0);
        assert_eq!(bytes_ceiling(0.0), 1.0);
        assert_eq!(
            bytes_ceiling(41.0 * 1024.0 * 1024.0 * 1024.0),
            50.0 * 1024.0 * 1024.0 * 1024.0
        );
        assert_eq!(bytes_ceiling(900.0 * 1024.0), 1000.0 * 1024.0);
        assert_eq!(rate_ceiling(0.0, Units::Bytes), 10.0 * 1024.0);
        assert_eq!(
            rate_ceiling(3.3 * 1024.0 * 1024.0, Units::Bytes),
            4.0 * 1024.0 * 1024.0
        );
        assert_eq!(rate_ceiling(700_000.0, Units::Bits), 6_000_000.0 / 8.0);
    }
}
