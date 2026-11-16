//! The local usage database: bytes by day, adapter and app.

use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

/// Version written into `usage.json`.
pub const USAGE_FILE_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Day
// ---------------------------------------------------------------------------

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`). Out-of-range months / days are clamped first.
fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let m = m.clamp(1, 12) as i64;
    let d = d.clamp(1, 31) as i64;
    let y = y as i64 - if m <= 2 { 1 } else { 0 };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> Day {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    Day {
        y: y.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
        m: m as u32,
        d: d as u32,
    }
}

impl Day {
    pub fn new(y: i32, m: u32, d: u32) -> Day {
        Day { y, m, d }
    }

    /// Today in local time.
    pub fn today() -> Day {
        // SAFETY: GetLocalTime has no preconditions and returns by value.
        let st = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
        Day {
            y: st.wYear as i32,
            m: st.wMonth as u32,
            d: st.wDay as u32,
        }
    }

    /// The local calendar day of a Unix time stamp (UTC when the time zone
    /// conversion is not available).
    pub fn from_unix_local(unix: i64) -> Day {
        crate::util::unix_to_local_day(unix).unwrap_or_else(|| Day::from_unix_utc(unix))
    }

    /// The UTC calendar day of a Unix time stamp.
    pub fn from_unix_utc(unix: i64) -> Day {
        civil_from_days(unix.div_euclid(86_400))
    }

    /// Days since 1970-01-01.
    pub fn days_since_epoch(self) -> i64 {
        days_from_civil(self.y, self.m, self.d)
    }

    pub fn from_days_since_epoch(days: i64) -> Day {
        civil_from_days(days)
    }

    /// The day `n` days before this one.
    pub fn minus_days(self, n: u32) -> Day {
        civil_from_days(self.days_since_epoch() - n as i64)
    }

    pub fn plus_days(self, n: u32) -> Day {
        civil_from_days(self.days_since_epoch() + n as i64)
    }

    /// `2026-11-16`
    pub fn iso(self) -> String {
        format!("{:04}-{:02}-{:02}", self.y, self.m, self.d)
    }

    /// Parses `2026-11-16`; `None` for anything that is not a real date.
    pub fn parse_iso(s: &str) -> Option<Day> {
        let mut parts = s.splitn(3, '-');
        let y: i32 = parts.next()?.parse().ok()?;
        let m: u32 = parts.next()?.parse().ok()?;
        let d: u32 = parts.next()?.parse().ok()?;
        let day = Day { y, m, d };
        day.is_valid().then_some(day)
    }

    /// A real calendar date (month 1..=12, day within the month).
    pub fn is_valid(self) -> bool {
        (1..=12).contains(&self.m) && self.d >= 1 && self.d <= days_in_month(self.y, self.m)
    }

    /// 0 = Monday.
    pub fn weekday(self) -> u32 {
        // 1970-01-01 was a Thursday.
        (self.days_since_epoch() + 3).rem_euclid(7) as u32
    }
}

pub fn is_leap_year(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// 28..=31; 0 for a month outside 1..=12.
pub fn days_in_month(y: i32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(y) => 29,
        2 => 28,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// UsageDb
// ---------------------------------------------------------------------------

/// One stored row. `app` is empty for the adapter-level total (always
/// recorded); rows with an app name exist only while per-app counting ran.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageRecord {
    pub day: Day,
    pub adapter: String,
    pub app: String,
    pub rx: u64,
    pub tx: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Row {
    adapter: String,
    app: String,
    rx: u64,
    tx: u64,
}

/// Rows are grouped by day and kept sorted by (adapter, app) inside a day, so
/// adding to today's rows is a short binary search and two equal databases
/// compare equal whatever the order of the additions was.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsageDb {
    days: BTreeMap<Day, Vec<Row>>,
}

/// On-disk form: `{"version":1,"days":[{"day":"2026-11-16","rows":[["Wi-Fi","",1,2]]}]}`.
#[derive(Serialize, Deserialize)]
struct FileRoot {
    version: u32,
    #[serde(default)]
    days: Vec<FileDay>,
}

#[derive(Serialize, Deserialize)]
struct FileDay {
    day: String,
    #[serde(default)]
    rows: Vec<(String, String, u64, u64)>,
}

fn add_to(t: &mut Totals, rx: u64, tx: u64) {
    t.rx = t.rx.saturating_add(rx);
    t.tx = t.tx.saturating_add(tx);
}

fn sorted_rows(map: HashMap<&str, Totals>) -> Vec<UsageRow> {
    let mut rows: Vec<UsageRow> = map
        .into_iter()
        .map(|(key, totals)| UsageRow {
            key: key.to_string(),
            totals,
        })
        .collect();
    rows.sort_by(|a, b| {
        b.totals
            .sum()
            .cmp(&a.totals.sum())
            .then_with(|| a.key.cmp(&b.key))
    });
    rows
}

impl UsageDb {
    fn add(&mut self, day: Day, adapter: &str, app: &str, rx: u64, tx: u64) {
        if rx == 0 && tx == 0 {
            return;
        }
        let rows = self.days.entry(day).or_default();
        match rows.binary_search_by(|r| (r.adapter.as_str(), r.app.as_str()).cmp(&(adapter, app))) {
            Ok(i) => {
                rows[i].rx = rows[i].rx.saturating_add(rx);
                rows[i].tx = rows[i].tx.saturating_add(tx);
            }
            Err(i) => rows.insert(
                i,
                Row {
                    adapter: adapter.to_string(),
                    app: app.to_string(),
                    rx,
                    tx,
                },
            ),
        }
    }

    fn range(&self, from: Day, to: Day) -> impl Iterator<Item = (&Day, &Vec<Row>)> {
        // BTreeMap::range panics on an inverted range; an inverted range is empty.
        let (lo, hi, empty) = if from <= to {
            (from, to, false)
        } else {
            (to, to, true)
        };
        self.days.range(lo..=hi).filter(move |_| !empty)
    }

    /// Adds to the adapter-level total of `adapter` on `day`.
    pub fn add_adapter(&mut self, day: Day, adapter: &str, rx: u64, tx: u64) {
        self.add(day, adapter, "", rx, tx);
    }

    /// Adds to the bytes of `app` on `day` (an empty app name is ignored: that
    /// key is the adapter-level total).
    pub fn add_app(&mut self, day: Day, app: &str, adapter: &str, rx: u64, tx: u64) {
        if app.is_empty() {
            return;
        }
        self.add(day, adapter, app, rx, tx);
    }

    /// Adapter-level total of one day.
    pub fn day_total(&self, day: Day) -> Totals {
        self.range_total(day, day)
    }

    pub fn month_total(&self, year: i32, month: u32) -> Totals {
        let last = days_in_month(year, month);
        if last == 0 {
            return Totals::default();
        }
        self.range_total(Day::new(year, month, 1), Day::new(year, month, last))
    }

    /// Adapter-level total of an inclusive range.
    pub fn range_total(&self, from: Day, to: Day) -> Totals {
        let mut t = Totals::default();
        for (_, rows) in self.range(from, to) {
            for r in rows.iter().filter(|r| r.app.is_empty()) {
                add_to(&mut t, r.rx, r.tx);
            }
        }
        t
    }

    fn fill_days(
        &self,
        from: Day,
        to: Day,
        mut pick: impl FnMut(&Row) -> bool,
    ) -> Vec<(Day, Totals)> {
        let first = from.days_since_epoch();
        let last = to.days_since_epoch();
        if last < first {
            return Vec::new();
        }
        let mut out: Vec<(Day, Totals)> = (first..=last)
            .map(|n| (Day::from_days_since_epoch(n), Totals::default()))
            .collect();
        for (day, rows) in self.range(from, to) {
            let idx = day.days_since_epoch() - first;
            let Some(slot) = usize::try_from(idx).ok().and_then(|i| out.get_mut(i)) else {
                continue; // an invalid stored date that sorts into the range
            };
            for r in rows.iter().filter(|r| pick(r)) {
                add_to(&mut slot.1, r.rx, r.tx);
            }
        }
        out
    }

    /// One entry per day of the inclusive range, zeros included, oldest first.
    pub fn by_day(&self, from: Day, to: Day) -> Vec<(Day, Totals)> {
        self.fill_days(from, to, |r| r.app.is_empty())
    }

    /// Per-app totals of the range, largest first.
    pub fn by_app(&self, from: Day, to: Day) -> Vec<UsageRow> {
        let mut map: HashMap<&str, Totals> = HashMap::new();
        for (_, rows) in self.range(from, to) {
            for r in rows.iter().filter(|r| !r.app.is_empty()) {
                add_to(map.entry(r.app.as_str()).or_default(), r.rx, r.tx);
            }
        }
        sorted_rows(map)
    }

    /// Per-adapter totals of the range, largest first.
    pub fn by_adapter(&self, from: Day, to: Day) -> Vec<UsageRow> {
        let mut map: HashMap<&str, Totals> = HashMap::new();
        for (_, rows) in self.range(from, to) {
            for r in rows.iter().filter(|r| r.app.is_empty()) {
                add_to(map.entry(r.adapter.as_str()).or_default(), r.rx, r.tx);
            }
        }
        sorted_rows(map)
    }

    /// One app, per day, zeros included, oldest first.
    pub fn app_by_day(&self, app: &str, from: Day, to: Day) -> Vec<(Day, Totals)> {
        if app.is_empty() {
            return self.fill_days(from, to, |_| false);
        }
        self.fill_days(from, to, |r| r.app == app)
    }

    /// Bytes of one app on one day, over all adapters.
    pub fn app_day_total(&self, app: &str, day: Day) -> Totals {
        let mut t = Totals::default();
        if app.is_empty() {
            return t;
        }
        if let Some(rows) = self.days.get(&day) {
            for r in rows.iter().filter(|r| r.app == app) {
                add_to(&mut t, r.rx, r.tx);
            }
        }
        t
    }

    /// Bytes of every app on one day, over all adapters (one pass).
    pub fn apps_on_day(&self, day: Day) -> HashMap<&str, Totals> {
        let mut map: HashMap<&str, Totals> = HashMap::new();
        if let Some(rows) = self.days.get(&day) {
            for r in rows.iter().filter(|r| !r.app.is_empty()) {
                add_to(map.entry(r.app.as_str()).or_default(), r.rx, r.tx);
            }
        }
        map
    }

    /// Every stored row, oldest day first.
    pub fn records(&self) -> Vec<UsageRecord> {
        let mut out = Vec::with_capacity(self.len());
        for (day, rows) in &self.days {
            for r in rows {
                out.push(UsageRecord {
                    day: *day,
                    adapter: r.adapter.clone(),
                    app: r.app.clone(),
                    rx: r.rx,
                    tx: r.tx,
                });
            }
        }
        out
    }

    /// Builds a database from rows (duplicates are merged).
    pub fn from_records(records: &[UsageRecord]) -> UsageDb {
        let mut db = UsageDb::default();
        for r in records {
            db.add(r.day, &r.adapter, &r.app, r.rx, r.tx);
        }
        db
    }

    /// Number of stored rows.
    pub fn len(&self) -> usize {
        self.days.values().map(Vec::len).sum()
    }

    /// The oldest and newest day with data.
    pub fn span(&self) -> Option<(Day, Day)> {
        let first = self.days.keys().next()?;
        let last = self.days.keys().next_back()?;
        Some((*first, *last))
    }

    /// Drops everything older than `keep_days` before `today`.
    /// `keep_days == 0` keeps everything.
    pub fn prune(&mut self, keep_days: u32, today: Day) {
        if keep_days == 0 {
            return;
        }
        let cutoff = today.minus_days(keep_days);
        self.days = self.days.split_off(&cutoff);
    }

    pub fn clear(&mut self) {
        self.days.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.days.values().all(Vec::is_empty)
    }

    /// The JSON text that `save` writes.
    pub fn to_json(&self) -> String {
        let root = FileRoot {
            version: USAGE_FILE_VERSION,
            days: self
                .days
                .iter()
                .filter(|(_, rows)| !rows.is_empty())
                .map(|(day, rows)| FileDay {
                    day: day.iso(),
                    rows: rows
                        .iter()
                        .map(|r| (r.adapter.clone(), r.app.clone(), r.rx, r.tx))
                        .collect(),
                })
                .collect(),
        };
        serde_json::to_string(&root).unwrap_or_else(|_| String::from("{\"version\":1,\"days\":[]}"))
    }

    /// Parses the text written by `to_json`. Rows with an invalid date are skipped.
    pub fn from_json(text: &str) -> Result<UsageDb, String> {
        let root: FileRoot =
            serde_json::from_str(text).map_err(|e| format!("usage file is damaged: {e}"))?;
        if root.version == 0 || root.version > USAGE_FILE_VERSION {
            return Err(format!(
                "usage file has unsupported version {}",
                root.version
            ));
        }
        let mut db = UsageDb::default();
        for d in &root.days {
            let Some(day) = Day::parse_iso(&d.day) else {
                continue;
            };
            for (adapter, app, rx, tx) in &d.rows {
                db.add(day, adapter, app, *rx, *tx);
            }
        }
        Ok(db)
    }

    /// Like `load`, but tells a missing file (`Ok(empty)`) from a damaged one (`Err`).
    pub fn try_load(path: &Path) -> Result<UsageDb, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => UsageDb::from_json(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UsageDb::default()),
            Err(e) => Err(format!("usage file could not be read: {e}")),
        }
    }

    /// A missing or damaged file gives an empty database.
    pub fn load(path: &Path) -> UsageDb {
        UsageDb::try_load(path).unwrap_or_default()
    }

    /// Written atomically (temporary file, then rename).
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)
                    .map_err(|e| format!("could not create the data folder: {e}"))?;
            }
        }
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp);
        let write = || -> std::io::Result<()> {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(self.to_json().as_bytes())?;
            f.sync_all()?;
            Ok(())
        };
        if let Err(e) = write() {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("could not write the usage file: {e}"));
        }
        // std::fs::rename replaces an existing file on Windows (MoveFileExW
        // with MOVEFILE_REPLACE_EXISTING), so readers see the old or the new
        // file, never half of one.
        std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("could not replace the usage file: {e}")
        })
    }
}

/// The inclusive billing period containing `today` when the allowance
/// resets on day `start_day` (1..=28) of each month.
pub fn cycle_range(today: Day, start_day: u32) -> (Day, Day) {
    let start_day = start_day.clamp(1, 28);
    let (sy, sm) = if today.d >= start_day {
        (today.y, today.m)
    } else if today.m <= 1 {
        (today.y - 1, 12)
    } else {
        (today.y, today.m - 1)
    };
    let (ny, nm) = if sm >= 12 { (sy + 1, 1) } else { (sy, sm + 1) };
    let from = Day::new(sy, sm, start_day);
    let to = Day::new(ny, nm, start_day).minus_days(1);
    (from, to)
}

/// `warn_fraction` is for example 0.8. A cap of zero means "no cap".
pub fn cap_status(used: u64, cap: u64, warn_fraction: f64) -> CapStatus {
    if cap == 0 {
        return CapStatus {
            used,
            ..CapStatus::default()
        };
    }
    let fraction = used as f64 / cap as f64;
    let warn_at = if warn_fraction.is_finite() {
        warn_fraction.clamp(0.0, 1.0)
    } else {
        1.0
    };
    CapStatus {
        used,
        cap,
        fraction,
        warn: fraction >= warn_at,
        exceeded: used > cap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, dd: u32) -> Day {
        Day::new(y, m, dd)
    }
    fn t(rx: u64, tx: u64) -> Totals {
        Totals { rx, tx }
    }

    // ---- Day ----

    #[test]
    fn epoch_and_known_dates() {
        assert_eq!(d(1970, 1, 1).days_since_epoch(), 0);
        assert_eq!(d(1970, 1, 2).days_since_epoch(), 1);
        assert_eq!(d(1969, 12, 31).days_since_epoch(), -1);
        assert_eq!(d(2000, 3, 1).days_since_epoch(), 11_017);
        assert_eq!(d(2026, 11, 16).days_since_epoch(), 20_773);
        assert_eq!(Day::from_days_since_epoch(20_773), d(2026, 11, 16));
    }

    #[test]
    fn round_trip_every_day_for_centuries() {
        let start = d(1899, 12, 25).days_since_epoch();
        let mut prev = Day::from_days_since_epoch(start - 1);
        for n in start..start + 366 * 250 {
            let day = Day::from_days_since_epoch(n);
            assert!(day.is_valid(), "{day:?}");
            assert_eq!(day.days_since_epoch(), n);
            assert!(day > prev);
            prev = day;
        }
    }

    #[test]
    fn plus_minus_cross_month_year_and_leap_day() {
        assert_eq!(d(2026, 1, 1).minus_days(1), d(2025, 12, 31));
        assert_eq!(d(2025, 12, 31).plus_days(1), d(2026, 1, 1));
        assert_eq!(d(2024, 2, 28).plus_days(1), d(2024, 2, 29));
        assert_eq!(d(2024, 2, 29).plus_days(1), d(2024, 3, 1));
        assert_eq!(d(2023, 2, 28).plus_days(1), d(2023, 3, 1));
        assert_eq!(d(2100, 2, 28).plus_days(1), d(2100, 3, 1)); // not a leap year
        assert_eq!(d(2000, 2, 28).plus_days(1), d(2000, 2, 29)); // leap year
        assert_eq!(d(2026, 3, 1).minus_days(365), d(2025, 3, 1));
        assert_eq!(d(2026, 11, 16).minus_days(0), d(2026, 11, 16));
        assert_eq!(
            d(2026, 11, 16).plus_days(30).minus_days(30),
            d(2026, 11, 16)
        );
    }

    #[test]
    fn weekday_monday_is_zero() {
        assert_eq!(d(1970, 1, 1).weekday(), 3); // Thursday
        assert_eq!(d(2026, 11, 16).weekday(), 0); // Monday
        assert_eq!(d(2026, 11, 22).weekday(), 6); // Sunday
        assert_eq!(d(2024, 2, 29).weekday(), 3); // Thursday
        assert_eq!(d(1969, 12, 28).weekday(), 6); // Sunday, before the epoch
    }

    #[test]
    fn iso_and_parse() {
        assert_eq!(d(2026, 1, 5).iso(), "2026-01-05");
        assert_eq!(Day::parse_iso("2026-01-05"), Some(d(2026, 1, 5)));
        assert_eq!(Day::parse_iso("2024-02-29"), Some(d(2024, 2, 29)));
        assert_eq!(Day::parse_iso("2023-02-29"), None);
        assert_eq!(Day::parse_iso("2023-13-01"), None);
        assert_eq!(Day::parse_iso("2023-00-10"), None);
        assert_eq!(Day::parse_iso("hello"), None);
        assert_eq!(Day::parse_iso(""), None);
    }

    #[test]
    fn unix_utc_days() {
        assert_eq!(Day::from_unix_utc(0), d(1970, 1, 1));
        assert_eq!(Day::from_unix_utc(86_399), d(1970, 1, 1));
        assert_eq!(Day::from_unix_utc(86_400), d(1970, 1, 2));
        assert_eq!(Day::from_unix_utc(-1), d(1969, 12, 31));
        assert_eq!(Day::from_unix_utc(1_794_787_200), d(2026, 11, 16));
    }

    #[test]
    fn local_day_is_within_a_day_of_utc_and_today_is_valid() {
        let unix = 1_794_787_200 + 12 * 3600;
        let local = Day::from_unix_local(unix).days_since_epoch();
        let utc = Day::from_unix_utc(unix).days_since_epoch();
        assert!((local - utc).abs() <= 1);
        assert!(Day::today().is_valid());
        assert!(Day::today().y >= 2024);
    }

    #[test]
    fn default_day_does_not_panic_in_maths() {
        let z = Day::default();
        let _ = z.days_since_epoch();
        let _ = z.minus_days(10);
        let _ = z.plus_days(10);
        let _ = z.weekday();
        assert!(!z.is_valid());
    }

    #[test]
    fn month_lengths() {
        assert_eq!(days_in_month(2024, 2), 29);
        assert_eq!(days_in_month(2025, 2), 28);
        assert_eq!(days_in_month(1900, 2), 28);
        assert_eq!(days_in_month(2000, 2), 29);
        assert_eq!(days_in_month(2025, 4), 30);
        assert_eq!(days_in_month(2025, 12), 31);
        assert_eq!(days_in_month(2025, 13), 0);
    }

    // ---- accounting ----

    fn sample() -> UsageDb {
        let mut db = UsageDb::default();
        // Adapter-level totals.
        db.add_adapter(d(2026, 10, 30), "Wi-Fi", 1000, 100);
        db.add_adapter(d(2026, 10, 31), "Wi-Fi", 2000, 200);
        db.add_adapter(d(2026, 11, 1), "Wi-Fi", 4000, 400);
        db.add_adapter(d(2026, 11, 1), "Ethernet", 10_000, 1000);
        db.add_adapter(d(2026, 11, 3), "Ethernet", 500, 50);
        // Per-app rows.
        db.add_app(d(2026, 10, 31), "browser.exe", "Wi-Fi", 1500, 150);
        db.add_app(d(2026, 11, 1), "browser.exe", "Wi-Fi", 3000, 300);
        db.add_app(d(2026, 11, 1), "browser.exe", "Ethernet", 6000, 600);
        db.add_app(d(2026, 11, 1), "sync.exe", "Ethernet", 4000, 400);
        db.add_app(d(2026, 11, 3), "sync.exe", "Ethernet", 100, 10);
        db
    }

    #[test]
    fn additions_merge_by_day_adapter_app() {
        let mut db = UsageDb::default();
        let day = d(2026, 11, 16);
        db.add_adapter(day, "Wi-Fi", 10, 1);
        db.add_adapter(day, "Wi-Fi", 20, 2);
        db.add_app(day, "a.exe", "Wi-Fi", 5, 5);
        db.add_app(day, "a.exe", "Wi-Fi", 5, 5);
        db.add_app(day, "a.exe", "Ethernet", 1, 1);
        assert_eq!(db.len(), 3);
        let recs = db.records();
        assert!(recs.contains(&UsageRecord {
            day,
            adapter: "Wi-Fi".into(),
            app: String::new(),
            rx: 30,
            tx: 3
        }));
        assert!(recs.contains(&UsageRecord {
            day,
            adapter: "Wi-Fi".into(),
            app: "a.exe".into(),
            rx: 10,
            tx: 10
        }));
    }

    #[test]
    fn zero_additions_and_empty_app_names_create_no_rows() {
        let mut db = UsageDb::default();
        db.add_adapter(d(2026, 1, 1), "Wi-Fi", 0, 0);
        db.add_app(d(2026, 1, 1), "a.exe", "Wi-Fi", 0, 0);
        db.add_app(d(2026, 1, 1), "", "Wi-Fi", 50, 50);
        assert!(db.is_empty());
        assert_eq!(db.len(), 0);
        assert!(db.records().is_empty());
    }

    #[test]
    fn app_rows_do_not_count_towards_adapter_totals() {
        let db = sample();
        assert_eq!(db.day_total(d(2026, 11, 1)), t(14_000, 1400));
        assert_eq!(db.day_total(d(2026, 10, 31)), t(2000, 200));
        assert_eq!(db.day_total(d(2026, 11, 2)), t(0, 0));
    }

    #[test]
    fn month_totals() {
        let db = sample();
        assert_eq!(db.month_total(2026, 10), t(3000, 300));
        assert_eq!(db.month_total(2026, 11), t(14_500, 1450));
        assert_eq!(db.month_total(2026, 12), t(0, 0));
        assert_eq!(db.month_total(2025, 11), t(0, 0));
        assert_eq!(db.month_total(2026, 0), t(0, 0));
        assert_eq!(db.month_total(2026, 13), t(0, 0));
    }

    #[test]
    fn range_totals_are_inclusive() {
        let db = sample();
        assert_eq!(
            db.range_total(d(2026, 10, 31), d(2026, 11, 1)),
            t(16_000, 1600)
        );
        assert_eq!(
            db.range_total(d(2026, 10, 1), d(2026, 12, 31)),
            t(17_500, 1750)
        );
        assert_eq!(
            db.range_total(d(2026, 11, 2), d(2026, 11, 2)),
            Totals::default()
        );
        // Inverted range: empty, no panic.
        assert_eq!(
            db.range_total(d(2026, 11, 3), d(2026, 10, 1)),
            Totals::default()
        );
    }

    #[test]
    fn by_day_fills_zeros_oldest_first() {
        let db = sample();
        let days = db.by_day(d(2026, 10, 29), d(2026, 11, 4));
        assert_eq!(days.len(), 7);
        assert_eq!(days[0], (d(2026, 10, 29), t(0, 0)));
        assert_eq!(days[1], (d(2026, 10, 30), t(1000, 100)));
        assert_eq!(days[2], (d(2026, 10, 31), t(2000, 200)));
        assert_eq!(days[3], (d(2026, 11, 1), t(14_000, 1400)));
        assert_eq!(days[4], (d(2026, 11, 2), t(0, 0)));
        assert_eq!(days[5], (d(2026, 11, 3), t(500, 50)));
        assert_eq!(days[6], (d(2026, 11, 4), t(0, 0)));
        assert!(db.by_day(d(2026, 11, 4), d(2026, 10, 29)).is_empty());
        assert_eq!(db.by_day(d(2026, 11, 1), d(2026, 11, 1)).len(), 1);
        // The sum of the days equals the range total.
        let sum: u64 = days.iter().map(|(_, x)| x.sum()).sum();
        assert_eq!(sum, db.range_total(d(2026, 10, 29), d(2026, 11, 4)).sum());
    }

    #[test]
    fn by_app_sums_over_adapters_largest_first() {
        let db = sample();
        let rows = db.by_app(d(2026, 10, 1), d(2026, 11, 30));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].key, "browser.exe");
        assert_eq!(rows[0].totals, t(10_500, 1050));
        assert_eq!(rows[1].key, "sync.exe");
        assert_eq!(rows[1].totals, t(4100, 410));
        let rows = db.by_app(d(2026, 11, 3), d(2026, 11, 3));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key, "sync.exe");
        assert!(db.by_app(d(2027, 1, 1), d(2027, 1, 31)).is_empty());
    }

    #[test]
    fn by_app_ties_are_ordered_by_name() {
        let mut db = UsageDb::default();
        db.add_app(d(2026, 1, 1), "b.exe", "Wi-Fi", 10, 0);
        db.add_app(d(2026, 1, 1), "a.exe", "Wi-Fi", 0, 10);
        let rows = db.by_app(d(2026, 1, 1), d(2026, 1, 1));
        assert_eq!(rows[0].key, "a.exe");
        assert_eq!(rows[1].key, "b.exe");
    }

    #[test]
    fn by_adapter_uses_adapter_level_rows_only() {
        let db = sample();
        let rows = db.by_adapter(d(2026, 10, 1), d(2026, 11, 30));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].key, "Ethernet");
        assert_eq!(rows[0].totals, t(10_500, 1050));
        assert_eq!(rows[1].key, "Wi-Fi");
        assert_eq!(rows[1].totals, t(7000, 700));
        let rows = db.by_adapter(d(2026, 10, 30), d(2026, 10, 31));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].totals, t(3000, 300));
    }

    #[test]
    fn app_by_day_fills_zeros() {
        let db = sample();
        let days = db.app_by_day("browser.exe", d(2026, 10, 30), d(2026, 11, 2));
        assert_eq!(
            days,
            vec![
                (d(2026, 10, 30), t(0, 0)),
                (d(2026, 10, 31), t(1500, 150)),
                (d(2026, 11, 1), t(9000, 900)),
                (d(2026, 11, 2), t(0, 0)),
            ]
        );
        let none = db.app_by_day("missing.exe", d(2026, 10, 30), d(2026, 11, 2));
        assert_eq!(none.len(), 4);
        assert!(none.iter().all(|(_, x)| x.sum() == 0));
        // The empty name is the adapter total key, not an app.
        let empty = db.app_by_day("", d(2026, 11, 1), d(2026, 11, 1));
        assert_eq!(empty, vec![(d(2026, 11, 1), t(0, 0))]);
    }

    #[test]
    fn app_day_helpers() {
        let db = sample();
        assert_eq!(
            db.app_day_total("browser.exe", d(2026, 11, 1)),
            t(9000, 900)
        );
        assert_eq!(db.app_day_total("browser.exe", d(2026, 11, 2)), t(0, 0));
        assert_eq!(db.app_day_total("", d(2026, 11, 1)), t(0, 0));
        let map = db.apps_on_day(d(2026, 11, 1));
        assert_eq!(map.len(), 2);
        assert_eq!(map["sync.exe"], t(4000, 400));
    }

    #[test]
    fn counters_saturate_instead_of_overflowing() {
        let mut db = UsageDb::default();
        let day = d(2026, 5, 5);
        db.add_adapter(day, "Wi-Fi", u64::MAX - 5, 1);
        db.add_adapter(day, "Wi-Fi", 100, 1);
        db.add_adapter(day, "Ethernet", 100, 1);
        assert_eq!(db.day_total(day), t(u64::MAX, 3));
    }

    #[test]
    fn records_round_trip_and_order_independence() {
        let db = sample();
        let mut recs = db.records();
        assert_eq!(recs.len(), db.len());
        assert!(recs.windows(2).all(|w| w[0].day <= w[1].day));
        recs.reverse();
        assert_eq!(UsageDb::from_records(&recs), db);
    }

    #[test]
    fn prune_drops_old_days_only() {
        let mut db = sample();
        db.prune(0, d(2026, 11, 16));
        assert_eq!(db, sample());
        // Keep 3 days before 3 Nov: 31 Oct and later stay.
        db.prune(3, d(2026, 11, 3));
        assert_eq!(db.span(), Some((d(2026, 10, 31), d(2026, 11, 3))));
        assert_eq!(db.day_total(d(2026, 10, 30)), t(0, 0));
        assert_eq!(db.day_total(d(2026, 10, 31)), t(2000, 200));
        db.prune(1, d(2026, 11, 3));
        assert_eq!(db.span(), Some((d(2026, 11, 3), d(2026, 11, 3))));
        db.prune(1, d(2027, 1, 1));
        assert!(db.is_empty());
        assert_eq!(db.span(), None);
    }

    #[test]
    fn clear_empties() {
        let mut db = sample();
        assert!(!db.is_empty());
        db.clear();
        assert!(db.is_empty());
        assert_eq!(db, UsageDb::default());
    }

    // ---- file ----

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wf-traffic-test-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|x| x.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn json_has_a_version_field() {
        let json = sample().to_json();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["version"], 1);
        assert!(v["days"].is_array());
        assert_eq!(UsageDb::from_json(&json), Ok(sample()));
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("nested").join("usage.json");
        let db = sample();
        db.save(&path).expect("save");
        assert_eq!(UsageDb::load(&path), db);
        // Saving again replaces the file and leaves no temporary file behind.
        let mut db2 = db.clone();
        db2.add_adapter(d(2026, 11, 4), "Wi-Fi", 7, 7);
        db2.save(&path).expect("second save");
        assert_eq!(UsageDb::load(&path), db2);
        let names: Vec<String> = std::fs::read_dir(path.parent().expect("parent"))
            .expect("read dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["usage.json".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_database_round_trips() {
        let dir = temp_dir("empty");
        let path = dir.join("usage.json");
        UsageDb::default().save(&path).expect("save");
        assert!(UsageDb::load(&path).is_empty());
        assert_eq!(UsageDb::try_load(&path), Ok(UsageDb::default()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_is_empty_and_not_an_error() {
        let dir = temp_dir("missing");
        let path = dir.join("nope.json");
        assert!(UsageDb::load(&path).is_empty());
        assert_eq!(UsageDb::try_load(&path), Ok(UsageDb::default()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn damaged_files_load_as_empty() {
        let dir = temp_dir("damaged");
        let path = dir.join("usage.json");
        for bad in [
            "",
            "{",
            "not json at all",
            "[1,2,3]",
            "{\"version\":1,\"days\":[{\"day\":\"2026-11-01\",\"rows\":[[\"Wi-Fi\",\"\",-5,2]]}]}",
            "{\"version\":99,\"days\":[]}",
            "{\"version\":0,\"days\":[]}",
            "{\"days\":[]}",
        ] {
            std::fs::write(&path, bad).expect("write");
            assert!(UsageDb::load(&path).is_empty(), "input: {bad}");
            assert!(UsageDb::try_load(&path).is_err(), "input: {bad}");
        }
        // Truncated copy of a real file.
        let json = sample().to_json();
        std::fs::write(&path, &json[..json.len() / 2]).expect("write");
        assert!(UsageDb::load(&path).is_empty());
        // Binary rubbish.
        std::fs::write(&path, [0xFFu8, 0xFE, 0x00, 0x80]).expect("write");
        assert!(UsageDb::load(&path).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rows_with_invalid_dates_are_skipped_and_duplicates_merged() {
        let text = "{\"version\":1,\"days\":[\
            {\"day\":\"2026-02-30\",\"rows\":[[\"Wi-Fi\",\"\",1,1]]},\
            {\"day\":\"2026-02-03\",\"rows\":[[\"Wi-Fi\",\"\",1,1],[\"Wi-Fi\",\"\",2,2]]},\
            {\"day\":\"2026-02-03\",\"rows\":[[\"Wi-Fi\",\"\",4,4]]}]}";
        let db = UsageDb::from_json(text).expect("parses");
        assert_eq!(db.len(), 1);
        assert_eq!(db.day_total(d(2026, 2, 3)), t(7, 7));
    }

    // ---- cycles and caps ----

    #[test]
    fn cycle_starting_on_the_first_is_the_calendar_month() {
        assert_eq!(
            cycle_range(d(2026, 11, 16), 1),
            (d(2026, 11, 1), d(2026, 11, 30))
        );
        assert_eq!(
            cycle_range(d(2026, 12, 31), 1),
            (d(2026, 12, 1), d(2026, 12, 31))
        );
        assert_eq!(
            cycle_range(d(2024, 2, 29), 1),
            (d(2024, 2, 1), d(2024, 2, 29))
        );
        assert_eq!(
            cycle_range(d(2025, 2, 1), 1),
            (d(2025, 2, 1), d(2025, 2, 28))
        );
    }

    #[test]
    fn cycle_mid_month() {
        assert_eq!(
            cycle_range(d(2026, 11, 16), 15),
            (d(2026, 11, 15), d(2026, 12, 14))
        );
        assert_eq!(
            cycle_range(d(2026, 11, 14), 15),
            (d(2026, 10, 15), d(2026, 11, 14))
        );
        assert_eq!(
            cycle_range(d(2026, 11, 15), 15),
            (d(2026, 11, 15), d(2026, 12, 14))
        );
    }

    #[test]
    fn cycle_across_year_end() {
        assert_eq!(
            cycle_range(d(2026, 12, 20), 10),
            (d(2026, 12, 10), d(2027, 1, 9))
        );
        assert_eq!(
            cycle_range(d(2027, 1, 5), 10),
            (d(2026, 12, 10), d(2027, 1, 9))
        );
        assert_eq!(
            cycle_range(d(2027, 1, 10), 10),
            (d(2027, 1, 10), d(2027, 2, 9))
        );
    }

    #[test]
    fn cycle_around_february() {
        // Leap year.
        assert_eq!(
            cycle_range(d(2024, 2, 10), 28),
            (d(2024, 1, 28), d(2024, 2, 27))
        );
        assert_eq!(
            cycle_range(d(2024, 2, 28), 28),
            (d(2024, 2, 28), d(2024, 3, 27))
        );
        assert_eq!(
            cycle_range(d(2024, 2, 29), 28),
            (d(2024, 2, 28), d(2024, 3, 27))
        );
        // Ordinary year.
        assert_eq!(
            cycle_range(d(2025, 2, 28), 28),
            (d(2025, 2, 28), d(2025, 3, 27))
        );
        assert_eq!(
            cycle_range(d(2025, 3, 1), 28),
            (d(2025, 2, 28), d(2025, 3, 27))
        );
        assert_eq!(
            cycle_range(d(2025, 3, 1), 2),
            (d(2025, 2, 2), d(2025, 3, 1))
        );
    }

    #[test]
    fn cycle_start_day_is_clamped_and_always_contains_today() {
        assert_eq!(
            cycle_range(d(2026, 5, 10), 0),
            cycle_range(d(2026, 5, 10), 1)
        );
        assert_eq!(
            cycle_range(d(2026, 5, 30), 31),
            cycle_range(d(2026, 5, 30), 28)
        );
        let mut day = d(2023, 12, 1);
        for _ in 0..800 {
            for start in [1, 2, 14, 15, 27, 28] {
                let (from, to) = cycle_range(day, start);
                assert!(from <= day && day <= to, "{day:?} start {start}");
                assert_eq!(from.d, start);
                let len = to.days_since_epoch() - from.days_since_epoch() + 1;
                assert!((28..=31).contains(&len));
                // The next cycle starts the day after this one ends.
                assert_eq!(cycle_range(to.plus_days(1), start).0, to.plus_days(1));
            }
            day = day.plus_days(1);
        }
    }

    #[test]
    fn cap_statuses() {
        let s = cap_status(50, 100, 0.8);
        assert_eq!((s.used, s.cap), (50, 100));
        assert_eq!(s.fraction, 0.5);
        assert!(!s.warn && !s.exceeded);

        let s = cap_status(80, 100, 0.8);
        assert!(s.warn && !s.exceeded);

        let s = cap_status(100, 100, 0.8);
        assert_eq!(s.fraction, 1.0);
        assert!(s.warn && !s.exceeded);

        let s = cap_status(150, 100, 0.8);
        assert_eq!(s.fraction, 1.5);
        assert!(s.warn && s.exceeded);

        // No cap set.
        let s = cap_status(150, 0, 0.8);
        assert_eq!(s.used, 150);
        assert_eq!(s.fraction, 0.0);
        assert!(!s.warn && !s.exceeded);

        // A broken warning fraction only warns at the cap.
        let s = cap_status(99, 100, f64::NAN);
        assert!(!s.warn);
        let s = cap_status(100, 100, f64::NAN);
        assert!(s.warn);
    }
}
