//! The background sampler that feeds the Overview and Apps pages.

pub mod accounting;

use crate::adapters;
use crate::connections;
use crate::etw::EtwSession;
use crate::procs;
use crate::types::*;
use crate::usage::UsageDb;
use crate::util::{self, lock};
use accounting::{AdapterMeta, AppAccounting, AppConn, AppFlow, NetAccounting};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// File name of the usage database inside `MonitorConfig::data_dir`.
pub const USAGE_FILE_NAME: &str = "usage.json";

const TICK: Duration = Duration::from_secs(1);
/// Ticks between two refreshes of the adapter list.
const ADAPTER_REFRESH_TICKS: u64 = 10;
/// Ticks between two refreshes of the connection table.
const CONNECTION_REFRESH_TICKS: u64 = 3;
/// Ticks between two saves of the usage database.
const SAVE_TICKS: u64 = 60;
/// Ticks after which a cached process name is checked again (PID reuse).
const PID_RECHECK_TICKS: u64 = 30;
/// Ticks an unknown PID waits before the next lookup.
const PID_RETRY_TICKS: u64 = 5;
/// Ticks the name of a PID is remembered after its last use (covers
/// processes that exited while their last bytes were still being counted).
const PID_FORGET_TICKS: u64 = 300;
/// New reverse-DNS lookups queued per tick.
const HOST_LOOKUPS_PER_TICK: usize = 8;
/// Reverse-DNS answers remembered.
const MAX_HOSTS: usize = 4096;
/// The app name bytes are counted under when the process is already gone.
pub const UNKNOWN_APP: &str = "Unknown";

#[derive(Clone, Debug, Default)]
pub struct MonitorConfig {
    /// Where `usage.json` lives; `None` keeps everything in memory.
    pub data_dir: Option<PathBuf>,
    /// Try to start the kernel trace for per-app byte counts.
    pub per_app: bool,
    /// Look up host names of remote endpoints (reverse DNS).
    pub resolve_hosts: bool,
    /// Days of usage history to keep (0 = forever).
    pub keep_days: u32,
}

struct Shared {
    snapshot: Mutex<Snapshot>,
    db: Mutex<UsageDb>,
    adapters: Mutex<Vec<AdapterInfo>>,
    db_path: Option<PathBuf>,
    /// Serialises writers of the usage file (they share one temporary file).
    save_lock: Mutex<()>,
    dirty: AtomicBool,
    resolve_hosts: Arc<AtomicBool>,
    stop: Mutex<bool>,
    wake: Condvar,
}

impl Shared {
    /// Writes the usage database when a data folder is configured.
    fn save(&self) -> Result<(), String> {
        let Some(path) = &self.db_path else {
            return Ok(());
        };
        let _writer = lock(&self.save_lock);
        self.dirty.store(false, Ordering::Relaxed);
        // Copy under the lock, write outside it: the sampler never waits for the disk.
        let copy = lock(&self.db).clone();
        let result = copy.save(path);
        if result.is_err() {
            self.dirty.store(true, Ordering::Relaxed);
        }
        result
    }

    /// Sleeps up to `timeout`; true when the monitor was asked to stop.
    fn wait_stop(&self, timeout: Duration) -> bool {
        let guard = lock(&self.stop);
        if *guard {
            return true;
        }
        match self
            .wake
            .wait_timeout_while(guard, timeout, |stopped| !*stopped)
        {
            Ok((guard, _)) => *guard,
            Err(poisoned) => *poisoned.into_inner().0,
        }
    }
}

/// Samples once per second on its own thread; stops when dropped.
pub struct Monitor {
    shared: Arc<Shared>,
    thread: Option<std::thread::JoinHandle<()>>,
    done: Mutex<mpsc::Receiver<()>>,
}

impl Monitor {
    pub fn start(config: MonitorConfig) -> Monitor {
        let db_path = config.data_dir.as_ref().map(|d| d.join(USAGE_FILE_NAME));
        let mut db = UsageDb::default();
        if let Some(path) = &db_path {
            match UsageDb::try_load(path) {
                Ok(loaded) => db = loaded,
                Err(_) => {
                    // Keep the damaged file for inspection instead of
                    // silently overwriting it at the next save.
                    let mut bad = path.as_os_str().to_owned();
                    bad.push(".bad");
                    let _ = std::fs::copy(path, PathBuf::from(bad));
                }
            }
        }
        db.prune(config.keep_days, Day::today());

        let shared = Arc::new(Shared {
            snapshot: Mutex::new(Snapshot::default()),
            db: Mutex::new(db),
            adapters: Mutex::new(Vec::new()),
            db_path,
            save_lock: Mutex::new(()),
            dirty: AtomicBool::new(false),
            resolve_hosts: Arc::new(AtomicBool::new(config.resolve_hosts)),
            stop: Mutex::new(false),
            wake: Condvar::new(),
        });

        let (done_tx, done_rx) = mpsc::channel::<()>();
        let worker_shared = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("wf-monitor".into())
            .spawn(move || {
                Worker::new(worker_shared, config).run();
                let _ = done_tx.send(());
            });
        let thread = match thread {
            Ok(handle) => Some(handle),
            Err(_) => {
                lock(&shared.snapshot).per_app_mode =
                    PerAppMode::ConnectionsOnly("The monitor thread could not be started.".into());
                None
            }
        };
        Monitor {
            shared,
            thread,
            done: Mutex::new(done_rx),
        }
    }

    /// The last published snapshot (a clone; never waits for I/O).
    pub fn snapshot(&self) -> Snapshot {
        lock(&self.shared.snapshot).clone()
    }

    /// A copy of the usage database including what was counted so far today.
    pub fn usage(&self) -> UsageDb {
        lock(&self.shared.db).clone()
    }

    /// The adapter list as of the last refresh (about every 10 seconds).
    pub fn adapters(&self) -> Vec<AdapterInfo> {
        lock(&self.shared.adapters).clone()
    }

    /// Forgets all recorded usage (and empties the file).
    pub fn clear_usage(&self) {
        lock(&self.shared.db).clear();
        let _ = self.shared.save();
    }

    pub fn set_resolve_hosts(&self, on: bool) {
        self.shared.resolve_hosts.store(on, Ordering::Relaxed);
    }

    /// Writes the usage database now (also done every minute and on drop).
    pub fn flush(&self) {
        let _ = self.shared.save();
    }

    /// Like `flush`, but reports why the file could not be written.
    pub fn try_flush(&self) -> Result<(), String> {
        self.shared.save()
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        *lock(&self.shared.stop) = true;
        self.shared.wake.notify_all();
        if let Some(handle) = self.thread.take() {
            // The worker saves the database and stops the trace before it
            // reports back. Never hang the caller: when Windows takes
            // unusually long, the thread is left to finish on its own.
            if lock(&self.done)
                .recv_timeout(Duration::from_secs(6))
                .is_ok()
            {
                let _ = handle.join();
            }
        } else {
            let _ = self.shared.save();
        }
    }
}

// ---------------------------------------------------------------------------
// PID -> executable cache
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PidEntry {
    name: String,
    path: String,
    /// Tick at which the name is looked up again.
    next_check: u64,
    used: u64,
}

/// Remembers which executable a PID belongs to. Entries are re-checked now
/// and then (PID reuse) and survive the exit of the process for a while.
#[derive(Debug, Default)]
struct PidNames {
    map: HashMap<u32, PidEntry>,
}

impl PidNames {
    /// Makes sure `pid` has an entry that is fresh enough at `tick`.
    fn ensure(
        &mut self,
        pid: u32,
        tick: u64,
        lookup: &mut dyn FnMut(u32) -> Option<(String, String)>,
    ) {
        if let Some(e) = self.map.get_mut(&pid) {
            e.used = tick;
            if tick < e.next_check {
                return;
            }
        }
        // The kernel's own traffic is reported under PID 0 or 4.
        let found = if pid == 0 || pid == 4 {
            Some(("System".to_string(), String::new()))
        } else {
            lookup(pid).filter(|(name, _)| !name.is_empty())
        };
        match (found, self.map.get_mut(&pid)) {
            (Some((name, path)), Some(e)) => {
                e.name = name;
                e.path = path;
                e.next_check = tick + PID_RECHECK_TICKS;
            }
            (Some((name, path)), None) => {
                self.map.insert(
                    pid,
                    PidEntry {
                        name,
                        path,
                        next_check: tick + PID_RECHECK_TICKS,
                        used: tick,
                    },
                );
            }
            // The process is gone: keep the name it had.
            (None, Some(e)) => e.next_check = tick + PID_RECHECK_TICKS,
            (None, None) => {
                self.map.insert(
                    pid,
                    PidEntry {
                        name: String::new(),
                        path: String::new(),
                        // Look again soon: it may just have been too early.
                        next_check: tick + PID_RETRY_TICKS,
                        used: tick,
                    },
                );
            }
        }
    }

    /// `(file name, path)`; both empty when unknown.
    fn get(&self, pid: u32) -> (&str, &str) {
        match self.map.get(&pid) {
            Some(e) => (e.name.as_str(), e.path.as_str()),
            None => ("", ""),
        }
    }

    fn prune(&mut self, tick: u64) {
        self.map
            .retain(|_, e| tick.saturating_sub(e.used) <= PID_FORGET_TICKS);
    }
}

// ---------------------------------------------------------------------------
// Reverse DNS worker
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum HostState {
    Pending,
    Done(Option<String>),
}

type Hosts = Arc<Mutex<HashMap<IpAddr, HostState>>>;

/// One worker thread resolving addresses one at a time. It only ever runs a
/// lookup while the "resolve host names" switch is on.
struct Resolver {
    tx: mpsc::Sender<IpAddr>,
    hosts: Hosts,
}

impl Resolver {
    fn start(enabled: Arc<AtomicBool>) -> Option<Resolver> {
        let (tx, rx) = mpsc::channel::<IpAddr>();
        let hosts: Hosts = Arc::new(Mutex::new(HashMap::new()));
        let worker_hosts = Arc::clone(&hosts);
        std::thread::Builder::new()
            .name("wf-rdns".into())
            .spawn(move || {
                // Ends when the sender (the monitor worker) is dropped.
                for ip in rx {
                    if !enabled.load(Ordering::Relaxed) {
                        lock(&worker_hosts).remove(&ip);
                        continue;
                    }
                    let name = crate::rdns::reverse_dns(ip);
                    lock(&worker_hosts).insert(ip, HostState::Done(name));
                }
            })
            .ok()?;
        Some(Resolver { tx, hosts })
    }
}

/// Addresses a reverse lookup makes sense for.
fn worth_resolving(ip: &IpAddr) -> bool {
    if util::is_loopback_or_unspecified(ip) || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_broadcast(),
        IpAddr::V6(_) => true,
    }
}

// ---------------------------------------------------------------------------
// The worker thread
// ---------------------------------------------------------------------------

struct Worker {
    shared: Arc<Shared>,
    config: MonitorConfig,
    started: Instant,
    tick: u64,
    last_secs: Option<f64>,
    last_day: Day,
    metas: Vec<AdapterMeta>,
    usage_adapter: String,
    adapters_due: bool,
    net: NetAccounting,
    apps: AppAccounting,
    etw: Option<EtwSession>,
    etw_tried: bool,
    mode: PerAppMode,
    pids: PidNames,
    resolver: Option<Resolver>,
    resolver_failed: bool,
    luids: Vec<u64>,
}

impl Worker {
    fn new(shared: Arc<Shared>, config: MonitorConfig) -> Worker {
        Worker {
            shared,
            config,
            started: Instant::now(),
            tick: 0,
            last_secs: None,
            last_day: Day::today(),
            metas: Vec::new(),
            usage_adapter: String::new(),
            adapters_due: true,
            net: NetAccounting::default(),
            apps: AppAccounting::default(),
            etw: None,
            etw_tried: false,
            mode: PerAppMode::Starting,
            pids: PidNames::default(),
            resolver: None,
            resolver_failed: false,
            luids: Vec::new(),
        }
    }

    fn run(mut self) {
        let mut deadline = Instant::now() + TICK;
        loop {
            self.sample();
            self.tick += 1;
            let now = Instant::now();
            if deadline <= now {
                // Behind schedule (slow tick, or the PC slept): do not fire a
                // burst of catch-up ticks.
                deadline = now + TICK;
            }
            if self
                .shared
                .wait_stop(deadline.saturating_duration_since(now))
            {
                break;
            }
            deadline += TICK;
        }
        if self.shared.dirty.load(Ordering::Relaxed) {
            let _ = self.shared.save();
        }
        // Dropping `self` stops the trace session and the resolver.
    }

    fn refresh_adapters(&mut self) {
        self.adapters_due = false;
        let Ok(list) = adapters::list_adapters() else {
            return; // keep the previous list
        };
        let counted = accounting::counted_adapters(&list);
        self.usage_adapter = accounting::usage_adapter_name(&list, &counted);
        self.metas = list
            .iter()
            .zip(&counted)
            .map(|(a, &counted)| AdapterMeta {
                luid: a.luid,
                name: a.name.clone(),
                kind: a.kind,
                up: a.up,
                counted,
            })
            .collect();
        if let Some(etw) = &self.etw {
            etw.set_local_addrs(&local_addrs(&list));
        }
        *lock(&self.shared.adapters) = list;
    }

    fn start_etw(&mut self) {
        self.etw_tried = true;
        if !self.config.per_app {
            self.mode = PerAppMode::ConnectionsOnly("Per-app byte counting is turned off.".into());
            return;
        }
        match EtwSession::start() {
            Ok(session) => {
                session.set_local_addrs(&local_addrs(&lock(&self.shared.adapters)));
                self.etw = Some(session);
                self.mode = PerAppMode::Etw;
            }
            // One attempt only: the reason does not go away by itself.
            Err(e) => self.mode = PerAppMode::ConnectionsOnly(e.to_string()),
        }
    }

    /// One tick.
    fn sample(&mut self) {
        let secs = self.started.elapsed().as_secs_f64();
        let dt = self.last_secs.map(|last| secs - last).unwrap_or(1.0);
        self.last_secs = Some(secs);
        let today = Day::today();
        let tick = self.tick;

        if self.adapters_due || tick.is_multiple_of(ADAPTER_REFRESH_TICKS) {
            self.refresh_adapters();
        }
        if !self.etw_tried {
            self.start_etw();
        }

        // Adapter counters (one cheap query per known adapter).
        self.luids.clear();
        self.luids.extend(self.metas.iter().map(|m| m.luid));
        let live = adapters::read_counters_for(&self.luids);
        let mut counters = Vec::with_capacity(live.len());
        for (c, up) in &live {
            counters.push(*c);
            if self.metas.iter().any(|m| m.luid == c.luid && m.up != *up) {
                // Link went up or down: names, routes and the set of counted
                // adapters may have changed.
                self.adapters_due = true;
            }
        }
        if live.len() != self.metas.len() {
            self.adapters_due = true; // an adapter was removed
        }
        let net = self.net.tick(secs, &self.metas, &counters);

        // Per-process flows from the trace.
        let trace_alive = self.etw.as_ref().map(EtwSession::is_running);
        let flows = match (trace_alive, &self.etw) {
            (Some(true), Some(etw)) => etw.drain(),
            (Some(false), _) => {
                self.etw = None;
                self.mode = PerAppMode::ConnectionsOnly(
                    "The network trace was stopped by another program.".into(),
                );
                Vec::new()
            }
            _ => Vec::new(),
        };
        for f in &flows {
            self.pids
                .ensure(f.pid, tick, &mut procs::process_name_cached);
        }
        let app_flows: Vec<AppFlow<'_>> = flows
            .iter()
            .map(|f| {
                let (name, path) = self.pids.get(f.pid);
                AppFlow {
                    app: if name.is_empty() { UNKNOWN_APP } else { name },
                    path,
                    pid: f.pid,
                    proto: f.proto,
                    remote: f.remote,
                    remote_port: f.remote_port,
                    rx: f.rx,
                    tx: f.tx,
                }
            })
            .collect();
        let app_deltas = self.apps.tick(&app_flows, dt);
        drop(app_flows);

        // Connection table: counts, PIDs and (zero-byte) endpoints.
        if tick.is_multiple_of(CONNECTION_REFRESH_TICKS) {
            if let Ok(rows) = connections::list_raw() {
                for r in &rows {
                    self.pids
                        .ensure(r.pid, tick, &mut procs::process_name_cached);
                }
                let conns: Vec<AppConn<'_>> = rows
                    .iter()
                    .map(|r| {
                        let (app, path) = self.pids.get(r.pid);
                        AppConn {
                            app,
                            path,
                            pid: r.pid,
                            proto: r.proto,
                            remote: r.remote,
                            remote_port: r.remote_port,
                            state: r.state,
                        }
                    })
                    .collect();
                self.apps.set_connections(&conns);
            }
        }

        // Host names (only while the switch is on).
        let resolve = self.shared.resolve_hosts.load(Ordering::Relaxed);
        if resolve && self.resolver.is_none() && !self.resolver_failed {
            self.resolver = Resolver::start(Arc::clone(&self.shared.resolve_hosts));
            self.resolver_failed = self.resolver.is_none();
        }

        // Usage database and the rows for the snapshot.
        let (apps, today_total, month_total) = {
            let mut db = lock(&self.shared.db);
            let mut changed = false;
            for (i, bytes) in &net.deltas {
                if let Some(meta) = self.metas.get(*i) {
                    db.add_adapter(today, &meta.name, bytes.rx, bytes.tx);
                    changed = true;
                }
            }
            for (app, bytes) in &app_deltas {
                db.add_app(today, app, &self.usage_adapter, bytes.rx, bytes.tx);
                changed = true;
            }
            if today != self.last_day {
                self.last_day = today;
                db.prune(self.config.keep_days, today);
                changed = true;
            }
            if changed {
                self.shared.dirty.store(true, Ordering::Relaxed);
            }

            let today_by_app = db.apps_on_day(today);
            let today_of = |app: &str| today_by_app.get(app).copied().unwrap_or_default();
            let apps = match (&self.resolver, resolve) {
                (Some(resolver), true) => {
                    let mut hosts = lock(&resolver.hosts);
                    let apps = self.apps.build(&today_of, &|ip| match hosts.get(ip) {
                        Some(HostState::Done(name)) => name.clone(),
                        _ => None,
                    });
                    queue_lookups(&apps, &mut hosts, &resolver.tx);
                    apps
                }
                _ => self.apps.build(&today_of, &|_| None),
            };
            (apps, db.day_total(today), db.month_total(today.y, today.m))
        };

        let snapshot = Snapshot {
            taken_unix: util::unix_now(),
            rate: net.rate,
            peak: self.net.peak(),
            history: self.net.history(),
            adapters: net.adapters,
            apps,
            per_app_mode: self.mode.clone(),
            session: self.net.session(),
            today: today_total,
            month: month_total,
        };
        *lock(&self.shared.snapshot) = snapshot;

        if tick % SAVE_TICKS == SAVE_TICKS - 1 {
            self.pids.prune(tick);
            if self.shared.dirty.load(Ordering::Relaxed) {
                let _ = self.shared.save();
            }
        }
    }
}

/// Queues reverse lookups for listed endpoints that have no answer yet.
fn queue_lookups(
    apps: &[AppLive],
    hosts: &mut HashMap<IpAddr, HostState>,
    tx: &mpsc::Sender<IpAddr>,
) {
    if hosts.len() > MAX_HOSTS {
        hosts.retain(|_, state| *state == HostState::Pending);
    }
    let mut queued = 0;
    for ep in apps.iter().flat_map(|a| a.endpoints.iter()) {
        if queued >= HOST_LOOKUPS_PER_TICK {
            break;
        }
        if hosts.contains_key(&ep.addr) || !worth_resolving(&ep.addr) {
            continue;
        }
        if tx.send(ep.addr).is_ok() {
            hosts.insert(ep.addr, HostState::Pending);
            queued += 1;
        }
    }
}

/// Every unicast address of this PC.
fn local_addrs(adapters: &[AdapterInfo]) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for a in adapters {
        out.extend(a.ipv4.iter().map(|n| IpAddr::V4(n.addr)));
        out.extend(a.ipv6.iter().map(|n| IpAddr::V6(n.addr)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("literal")
    }

    fn fixed(name: &'static str) -> impl FnMut(u32) -> Option<(String, String)> {
        move |_| Some((name.to_string(), format!("C:\\Apps\\{name}")))
    }

    #[test]
    fn pid_names_are_cached_and_rechecked() {
        let mut pids = PidNames::default();
        let mut calls = 0;
        let mut lookup = |_: u32| {
            calls += 1;
            Some(("a.exe".to_string(), "C:\\Apps\\a.exe".to_string()))
        };
        pids.ensure(100, 0, &mut lookup);
        pids.ensure(100, 1, &mut lookup);
        pids.ensure(100, PID_RECHECK_TICKS - 1, &mut lookup);
        assert_eq!(pids.get(100), ("a.exe", "C:\\Apps\\a.exe"));
        pids.ensure(100, PID_RECHECK_TICKS, &mut lookup);
        assert_eq!(calls, 2);
        // The PID was reused by another program.
        pids.ensure(100, PID_RECHECK_TICKS * 2, &mut fixed("b.exe"));
        assert_eq!(pids.get(100).0, "b.exe");
    }

    #[test]
    fn exited_processes_keep_their_name_for_a_while() {
        let mut pids = PidNames::default();
        pids.ensure(100, 0, &mut fixed("a.exe"));
        let mut gone = |_: u32| None;
        pids.ensure(100, PID_RECHECK_TICKS + 1, &mut gone);
        assert_eq!(pids.get(100).0, "a.exe");
        pids.prune(PID_RECHECK_TICKS + 1 + PID_FORGET_TICKS);
        assert_eq!(pids.get(100).0, "a.exe");
        pids.prune(PID_RECHECK_TICKS + 2 + PID_FORGET_TICKS);
        assert_eq!(pids.get(100), ("", ""));
    }

    #[test]
    fn unknown_pids_are_retried_soon_and_kernel_pids_are_system() {
        let mut pids = PidNames::default();
        let mut calls = 0;
        let mut gone = |_: u32| {
            calls += 1;
            None
        };
        pids.ensure(200, 10, &mut gone);
        assert_eq!(pids.get(200), ("", ""));
        pids.ensure(200, 11, &mut gone);
        assert_eq!(calls, 1);
        pids.ensure(200, 10 + PID_RETRY_TICKS, &mut fixed("late.exe"));
        assert_eq!(pids.get(200).0, "late.exe");
        // Very early ticks must not underflow.
        pids.ensure(300, 0, &mut |_| None);
        assert_eq!(pids.get(300), ("", ""));

        let mut never =
            |_: u32| -> Option<(String, String)> { panic!("no lookup for kernel PIDs") };
        pids.ensure(0, 0, &mut never);
        pids.ensure(4, 0, &mut never);
        assert_eq!(pids.get(0).0, "System");
        assert_eq!(pids.get(4).0, "System");
        assert_eq!(pids.get(999), ("", ""));
    }

    #[test]
    fn lookups_are_rate_limited_deduplicated_and_filtered() {
        let (tx, rx) = mpsc::channel();
        let mut hosts = HashMap::new();
        hosts.insert(ip("198.51.100.1"), HostState::Done(None));
        let endpoint = |addr: &str| Endpoint {
            proto: Proto::Tcp,
            addr: ip(addr),
            port: 443,
            host: None,
            rx: 0,
            tx: 0,
        };
        let mut endpoints = vec![
            endpoint("198.51.100.1"), // already answered
            endpoint("127.0.0.1"),
            endpoint("224.0.0.251"),
            endpoint("255.255.255.255"),
            endpoint("ff02::fb"),
            endpoint("203.0.113.5"),
            endpoint("203.0.113.5"), // duplicate
        ];
        for i in 0..20 {
            endpoints.push(endpoint(&format!("198.51.100.{}", 10 + i)));
        }
        let apps = vec![AppLive {
            name: "a.exe".into(),
            endpoints,
            ..AppLive::default()
        }];
        queue_lookups(&apps, &mut hosts, &tx);
        let queued: Vec<IpAddr> = rx.try_iter().collect();
        assert_eq!(queued.len(), HOST_LOOKUPS_PER_TICK);
        assert_eq!(queued[0], ip("203.0.113.5"));
        assert_eq!(
            queued.iter().filter(|a| **a == ip("203.0.113.5")).count(),
            1
        );
        assert!(queued.iter().all(worth_resolving));
        assert_eq!(hosts.get(&ip("203.0.113.5")), Some(&HostState::Pending));
        // The next tick continues with the rest, not with the same ones.
        queue_lookups(&apps, &mut hosts, &tx);
        let second: Vec<IpAddr> = rx.try_iter().collect();
        assert_eq!(second.len(), HOST_LOOKUPS_PER_TICK);
        assert!(second.iter().all(|a| !queued.contains(a)));
    }

    #[test]
    fn host_cache_is_bounded() {
        let (tx, _rx) = mpsc::channel();
        let mut hosts = HashMap::new();
        for i in 0..(MAX_HOSTS as u32 + 10) {
            let addr = IpAddr::V4(std::net::Ipv4Addr::from(0xC633_0000u32 + i));
            hosts.insert(addr, HostState::Done(None));
        }
        hosts.insert(ip("203.0.113.9"), HostState::Pending);
        queue_lookups(&[], &mut hosts, &tx);
        assert_eq!(hosts.len(), 1);
        assert!(hosts.contains_key(&ip("203.0.113.9")));
    }

    #[test]
    fn monitor_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Monitor>();
    }

    #[test]
    fn local_addresses_are_collected() {
        let a = AdapterInfo {
            ipv4: vec![V4Net {
                addr: "192.0.2.10".parse().expect("literal"),
                prefix: 24,
            }],
            ipv6: vec![V6Net {
                addr: "2001:db8::10".parse().expect("literal"),
                prefix: 64,
            }],
            ..AdapterInfo::default()
        };
        assert_eq!(
            local_addrs(&[a.clone(), a]),
            vec![
                ip("192.0.2.10"),
                ip("2001:db8::10"),
                ip("192.0.2.10"),
                ip("2001:db8::10")
            ]
        );
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wf-traffic-monitor-{}-{}-{}",
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

    fn wait_for(monitor: &Monitor, what: impl Fn(&Snapshot) -> bool) -> Snapshot {
        let end = Instant::now() + Duration::from_secs(20);
        loop {
            let snap = monitor.snapshot();
            if what(&snap) || Instant::now() > end {
                return snap;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn live_monitor_in_memory() {
        let monitor = Monitor::start(MonitorConfig::default());
        let snap = wait_for(&monitor, |s| s.history.len() >= 3);
        assert!(snap.history.len() >= 3);
        assert!(snap.taken_unix > 1_700_000_000);
        assert_eq!(
            snap.per_app_mode,
            PerAppMode::ConnectionsOnly("Per-app byte counting is turned off.".into())
        );
        assert_eq!(snap.adapters.len(), monitor.adapters().len());
        assert!(snap.rate.down >= 0.0 && snap.rate.up >= 0.0);
        assert!(snap.peak.down >= snap.rate.down);
        assert!(snap.today.rx >= snap.session.rx);
        assert!(snap.month.rx >= snap.today.rx);
        // Nothing but adapter-level rows without the trace.
        assert!(monitor.usage().records().iter().all(|r| r.app.is_empty()));
        for app in &snap.apps {
            assert!(!app.name.is_empty());
            assert_eq!(app.session, Totals::default());
            assert!(app.endpoints.iter().all(|e| e.host.is_none()));
            assert!(app.endpoints.len() <= accounting::TOP_ENDPOINTS);
        }
        monitor.set_resolve_hosts(false);
        monitor.flush(); // no data folder: nothing to write, no error
        assert_eq!(monitor.try_flush(), Ok(()));
        monitor.clear_usage();
        let started = Instant::now();
        drop(monitor);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn live_monitor_with_a_data_folder_and_per_app_requested() {
        let dir = temp_dir("data");
        let path = dir.join(USAGE_FILE_NAME);
        // A damaged file from an earlier run is set aside, not trusted.
        std::fs::write(&path, "{ this is not json").expect("write");
        let monitor = Monitor::start(MonitorConfig {
            data_dir: Some(dir.clone()),
            per_app: true,
            resolve_hosts: false,
            keep_days: 30,
        });
        assert!(dir.join("usage.json.bad").exists());
        let snap = wait_for(&monitor, |s| s.per_app_mode != PerAppMode::Starting);
        match &snap.per_app_mode {
            PerAppMode::Etw => {}
            PerAppMode::ConnectionsOnly(reason) => {
                assert!(reason.contains("administrator"), "{reason}")
            }
            PerAppMode::Starting => panic!("still starting"),
        }
        assert_eq!(monitor.try_flush(), Ok(()));
        let on_disk = UsageDb::try_load(&path).expect("a valid usage file");
        assert_eq!(on_disk.is_empty(), on_disk.records().is_empty());
        drop(monitor);
        // Still valid after the final save; no temporary file left behind.
        assert!(UsageDb::try_load(&path).is_ok());
        assert!(!dir.join("usage.json.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
