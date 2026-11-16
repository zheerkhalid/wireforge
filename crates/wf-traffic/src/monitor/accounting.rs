//! The per-tick accounting of the monitor, free of Windows calls.
//!
//! `NetAccounting` turns adapter counters into rates, history, peak and
//! session totals. `AppAccounting` turns per-process flows and the connection
//! table into `AppLive` rows and per-app usage deltas.

use crate::rates::RateTracker;
use crate::types::*;
use crate::util;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// Samples kept in `Snapshot::history`.
pub const NET_HISTORY: usize = 300;
/// Samples kept in `AppLive::history`.
pub const APP_HISTORY: usize = 60;
/// Endpoints listed per app.
pub const TOP_ENDPOINTS: usize = 8;
/// Endpoints remembered per app before the smallest are forgotten.
pub const MAX_ENDPOINTS_PER_APP: usize = 256;
/// Apps remembered before idle ones with the least traffic are forgotten.
pub const MAX_APPS: usize = 512;
/// Ticks a PID stays listed for an app after its last traffic.
const PID_LINGER_TICKS: u64 = 30;

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

/// What the accounting needs to know about an adapter.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdapterMeta {
    pub luid: u64,
    pub name: String,
    pub kind: AdapterKind,
    pub up: bool,
    /// Part of the total (see `counted_adapters`).
    pub counted: bool,
}

/// Which adapters make up the total rate: physical ones that are up, never
/// loopback, virtual or tunnel adapters (their traffic also crosses a
/// physical adapter and would be counted twice). When no such adapter is up
/// (for example inside some virtual machines), the default-route adapter is
/// counted instead so the totals are not stuck at zero.
pub fn counted_adapters(adapters: &[AdapterInfo]) -> Vec<bool> {
    let real = |a: &AdapterInfo| {
        a.up && a.physical
            && !matches!(
                a.kind,
                AdapterKind::Loopback | AdapterKind::Virtual | AdapterKind::Tunnel
            )
    };
    let mut flags: Vec<bool> = adapters.iter().map(real).collect();
    if !flags.iter().any(|&f| f) {
        for (flag, a) in flags.iter_mut().zip(adapters) {
            *flag = a.up && a.is_default && a.kind != AdapterKind::Loopback;
        }
    }
    flags
}

/// The adapter name per-app usage is recorded under: the default adapter when
/// it is counted, else the first counted adapter, else the default adapter.
pub fn usage_adapter_name(adapters: &[AdapterInfo], counted: &[bool]) -> String {
    let is_counted = |i: usize| counted.get(i).copied().unwrap_or(false);
    adapters
        .iter()
        .enumerate()
        .find(|(i, a)| a.is_default && is_counted(*i))
        .or_else(|| adapters.iter().enumerate().find(|(i, _)| is_counted(*i)))
        .or_else(|| adapters.iter().enumerate().find(|(_, a)| a.is_default))
        .map(|(_, a)| a.name.clone())
        .unwrap_or_default()
}

#[derive(Debug, Default)]
struct AdapterAcc {
    tracker: RateTracker,
    session: Totals,
    seen: bool,
}

/// The result of one adapter tick.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NetTick {
    pub adapters: Vec<AdapterLive>,
    /// Sum over the counted adapters.
    pub rate: Rate,
    /// Bytes added this tick, summed over the counted adapters.
    pub added: Totals,
    /// Bytes added this tick per counted adapter: (index into the metas, bytes).
    pub deltas: Vec<(usize, Totals)>,
}

#[derive(Debug, Default)]
pub struct NetAccounting {
    adapters: HashMap<u64, AdapterAcc>,
    history: VecDeque<Rate>,
    peak: Rate,
    session: Totals,
}

fn add_totals(a: &mut Totals, b: Totals) {
    a.rx = a.rx.saturating_add(b.rx);
    a.tx = a.tx.saturating_add(b.tx);
}

impl NetAccounting {
    /// Feeds the counters read at `seconds` (monotonic). Adapters without a
    /// counter row report a zero rate; trackers of adapters that disappeared
    /// are dropped.
    pub fn tick(&mut self, seconds: f64, metas: &[AdapterMeta], counters: &[Counters]) -> NetTick {
        let mut out = NetTick {
            adapters: Vec::with_capacity(metas.len()),
            ..NetTick::default()
        };
        for acc in self.adapters.values_mut() {
            acc.seen = false;
        }
        for (i, meta) in metas.iter().enumerate() {
            let acc = self.adapters.entry(meta.luid).or_default();
            acc.seen = true;
            let (rate, added) = match counters.iter().find(|c| c.luid == meta.luid) {
                Some(c) => acc.tracker.update(seconds, c.rx, c.tx),
                None => (Rate::default(), Totals::default()),
            };
            add_totals(&mut acc.session, added);
            if meta.counted {
                out.rate.down += rate.down;
                out.rate.up += rate.up;
                add_totals(&mut out.added, added);
                if added.rx != 0 || added.tx != 0 {
                    out.deltas.push((i, added));
                }
            }
            out.adapters.push(AdapterLive {
                luid: meta.luid,
                name: meta.name.clone(),
                kind: meta.kind,
                up: meta.up,
                rate,
                session: acc.session,
            });
        }
        self.adapters.retain(|_, acc| acc.seen);

        add_totals(&mut self.session, out.added);
        self.peak.down = self.peak.down.max(out.rate.down);
        self.peak.up = self.peak.up.max(out.rate.up);
        if self.history.len() >= NET_HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(out.rate);
        out
    }

    pub fn history(&self) -> Vec<Rate> {
        self.history.iter().copied().collect()
    }

    pub fn peak(&self) -> Rate {
        self.peak
    }

    pub fn session(&self) -> Totals {
        self.session
    }
}

// ---------------------------------------------------------------------------
// Apps
// ---------------------------------------------------------------------------

/// Bytes of one process to / from one endpoint this tick, with the process
/// already mapped to its executable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppFlow<'a> {
    pub app: &'a str,
    pub path: &'a str,
    pub pid: u32,
    pub proto: Proto,
    pub remote: Option<IpAddr>,
    pub remote_port: u16,
    pub rx: u64,
    pub tx: u64,
}

/// One row of the connection table, with the process mapped to its executable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppConn<'a> {
    pub app: &'a str,
    pub path: &'a str,
    pub pid: u32,
    pub proto: Proto,
    pub remote: Option<IpAddr>,
    pub remote_port: u16,
    pub state: ConnState,
}

type EndpointKey = (Proto, IpAddr, u16);

#[derive(Debug, Default)]
struct AppAcc {
    path: String,
    session: Totals,
    rate: Rate,
    history: VecDeque<Rate>,
    endpoints: HashMap<EndpointKey, Totals>,
    /// (pid, tick of the last traffic).
    flow_pids: Vec<(u32, u64)>,
    conn_pids: Vec<u32>,
    conn_endpoints: Vec<EndpointKey>,
    connections: u32,
    last_active: u64,
}

impl AppAcc {
    fn in_use(&self) -> bool {
        !self.conn_pids.is_empty() || !self.flow_pids.is_empty()
    }
}

#[derive(Debug, Default)]
pub struct AppAccounting {
    apps: HashMap<String, AppAcc>,
    tick: u64,
}

impl AppAccounting {
    /// Accounts the flows of one tick that lasted `dt` seconds. Every known
    /// app gets a history sample (zero when it was idle). Returns the bytes
    /// per app for the usage database, largest first.
    pub fn tick(&mut self, flows: &[AppFlow<'_>], dt: f64) -> Vec<(String, Totals)> {
        self.tick += 1;
        let now = self.tick;
        let dt = if dt.is_finite() && dt > 0.0 { dt } else { 1.0 };

        let mut added: HashMap<&str, Totals> = HashMap::new();
        for f in flows {
            if f.app.is_empty() || (f.rx == 0 && f.tx == 0) {
                continue;
            }
            let acc = match self.apps.get_mut(f.app) {
                Some(acc) => acc,
                None => self.apps.entry(f.app.to_string()).or_default(),
            };
            if acc.path.is_empty() && !f.path.is_empty() {
                acc.path = f.path.to_string();
            }
            acc.last_active = now;
            match acc.flow_pids.iter_mut().find(|(pid, _)| *pid == f.pid) {
                Some(entry) => entry.1 = now,
                None => acc.flow_pids.push((f.pid, now)),
            }
            if let Some(remote) = f.remote {
                if !util::is_loopback_or_unspecified(&remote) {
                    let e = acc
                        .endpoints
                        .entry((f.proto, remote, f.remote_port))
                        .or_default();
                    e.rx = e.rx.saturating_add(f.rx);
                    e.tx = e.tx.saturating_add(f.tx);
                }
            }
            let t = added.entry(f.app).or_default();
            t.rx = t.rx.saturating_add(f.rx);
            t.tx = t.tx.saturating_add(f.tx);
        }

        for (name, acc) in self.apps.iter_mut() {
            let bytes = added.get(name.as_str()).copied().unwrap_or_default();
            add_totals(&mut acc.session, bytes);
            acc.rate = Rate {
                down: bytes.rx as f64 / dt,
                up: bytes.tx as f64 / dt,
            };
            if acc.history.len() >= APP_HISTORY {
                acc.history.pop_front();
            }
            acc.history.push_back(acc.rate);
            acc.flow_pids
                .retain(|(_, seen)| now.saturating_sub(*seen) <= PID_LINGER_TICKS);
            if acc.endpoints.len() > MAX_ENDPOINTS_PER_APP {
                trim_endpoints(&mut acc.endpoints);
            }
        }

        let mut out: Vec<(String, Totals)> = added
            .into_iter()
            .map(|(name, t)| (name.to_string(), t))
            .collect();
        out.sort_by(|a, b| b.1.sum().cmp(&a.1.sum()).then_with(|| a.0.cmp(&b.0)));

        self.forget_idle_apps();
        out
    }

    /// Replaces what is known from the connection table: which processes
    /// belong to an app, how many connections it has, and which endpoints it
    /// is connected to.
    pub fn set_connections(&mut self, conns: &[AppConn<'_>]) {
        for acc in self.apps.values_mut() {
            acc.conn_pids.clear();
            acc.conn_endpoints.clear();
            acc.connections = 0;
        }
        for c in conns {
            if c.app.is_empty() {
                continue;
            }
            let acc = match self.apps.get_mut(c.app) {
                Some(acc) => acc,
                None => self.apps.entry(c.app.to_string()).or_default(),
            };
            if acc.path.is_empty() && !c.path.is_empty() {
                acc.path = c.path.to_string();
            }
            if !acc.conn_pids.contains(&c.pid) {
                acc.conn_pids.push(c.pid);
            }
            let active_tcp = c.proto == Proto::Tcp
                && !matches!(c.state, ConnState::Listening | ConnState::Closed);
            if !active_tcp {
                continue;
            }
            acc.connections += 1;
            if let Some(remote) = c.remote {
                let key = (c.proto, remote, c.remote_port);
                if !util::is_loopback_or_unspecified(&remote)
                    && acc.conn_endpoints.len() < MAX_ENDPOINTS_PER_APP
                    && !acc.conn_endpoints.contains(&key)
                {
                    acc.conn_endpoints.push(key);
                }
            }
        }
        self.forget_idle_apps();
    }

    /// Apps without sockets, recent traffic or session bytes are dropped at
    /// once; beyond `MAX_APPS` the least-used apps without sockets go too.
    fn forget_idle_apps(&mut self) {
        self.apps
            .retain(|_, acc| acc.in_use() || acc.session.sum() != 0);
        if self.apps.len() <= MAX_APPS {
            return;
        }
        let mut idle: Vec<(u64, u64, String)> = self
            .apps
            .iter()
            .filter(|(_, acc)| !acc.in_use())
            .map(|(name, acc)| (acc.last_active, acc.session.sum(), name.clone()))
            .collect();
        idle.sort();
        let excess = self.apps.len() - MAX_APPS;
        for (_, _, name) in idle.into_iter().take(excess) {
            self.apps.remove(&name);
        }
    }

    pub fn len(&self) -> usize {
        self.apps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
    }

    /// The rows for the snapshot. `today` gives the bytes of an app today
    /// from the usage database (which already includes this tick), `host`
    /// the cached reverse-DNS name of an address. Sorted by session bytes,
    /// then connections, then name.
    pub fn build(
        &self,
        today: &dyn Fn(&str) -> Totals,
        host: &dyn Fn(&IpAddr) -> Option<String>,
    ) -> Vec<AppLive> {
        let mut out: Vec<AppLive> = self
            .apps
            .iter()
            .map(|(name, acc)| {
                let mut pids: Vec<u32> = acc
                    .conn_pids
                    .iter()
                    .copied()
                    .chain(acc.flow_pids.iter().map(|(pid, _)| *pid))
                    .collect();
                pids.sort_unstable();
                pids.dedup();
                AppLive {
                    name: name.clone(),
                    path: acc.path.clone(),
                    pids,
                    rate: acc.rate,
                    session: acc.session,
                    today: today(name),
                    connections: acc.connections,
                    endpoints: top_endpoints(acc, host),
                    history: acc.history.iter().copied().collect(),
                }
            })
            .collect();
        out.sort_by(|a, b| {
            b.session
                .sum()
                .cmp(&a.session.sum())
                .then_with(|| b.connections.cmp(&a.connections))
                .then_with(|| a.name.cmp(&b.name))
        });
        out
    }
}

/// Keeps the larger half of an endpoint map.
fn trim_endpoints(map: &mut HashMap<EndpointKey, Totals>) {
    let mut sizes: Vec<u64> = map.values().map(Totals::sum).collect();
    sizes.sort_unstable_by(|a, b| b.cmp(a));
    let keep = MAX_ENDPOINTS_PER_APP / 2;
    let threshold = sizes.get(keep).copied().unwrap_or(0);
    // Everything above the threshold stays (fewer than `keep` entries by
    // construction); ties at the threshold fill the remaining room.
    let above = sizes.iter().filter(|&&s| s > threshold).count();
    let mut ties_left = keep.saturating_sub(above);
    map.retain(|_, t| {
        let sum = t.sum();
        if sum > threshold {
            true
        } else if sum == threshold && ties_left > 0 {
            ties_left -= 1;
            true
        } else {
            false
        }
    });
}

/// Endpoints with bytes first (largest first), then connected endpoints
/// without counted bytes, up to `TOP_ENDPOINTS`.
fn top_endpoints(acc: &AppAcc, host: &dyn Fn(&IpAddr) -> Option<String>) -> Vec<Endpoint> {
    let mut with_bytes: Vec<(&EndpointKey, &Totals)> = acc.endpoints.iter().collect();
    with_bytes.sort_by(|a, b| b.1.sum().cmp(&a.1.sum()).then_with(|| a.0.cmp(b.0)));
    let mut out: Vec<Endpoint> = with_bytes
        .into_iter()
        .take(TOP_ENDPOINTS)
        .map(|(k, t)| Endpoint {
            proto: k.0,
            addr: k.1,
            port: k.2,
            host: host(&k.1),
            rx: t.rx,
            tx: t.tx,
        })
        .collect();
    if out.len() < TOP_ENDPOINTS {
        let mut rest: Vec<&EndpointKey> = acc
            .conn_endpoints
            .iter()
            .filter(|k| !acc.endpoints.contains_key(*k))
            .collect();
        rest.sort();
        for k in rest.into_iter().take(TOP_ENDPOINTS - out.len()) {
            out.push(Endpoint {
                proto: k.0,
                addr: k.1,
                port: k.2,
                host: host(&k.1),
                rx: 0,
                tx: 0,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usage::UsageDb;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("literal")
    }
    fn t(rx: u64, tx: u64) -> Totals {
        Totals { rx, tx }
    }
    fn no_today(_: &str) -> Totals {
        Totals::default()
    }
    fn no_host(_: &IpAddr) -> Option<String> {
        None
    }

    // ---- adapters ----

    fn adapter(
        name: &str,
        kind: AdapterKind,
        up: bool,
        physical: bool,
        default: bool,
    ) -> AdapterInfo {
        AdapterInfo {
            luid: name.len() as u64 * 1000 + name.bytes().map(u64::from).sum::<u64>(),
            name: name.into(),
            kind,
            up,
            physical,
            is_default: default,
            ..AdapterInfo::default()
        }
    }

    #[test]
    fn only_physical_adapters_that_are_up_are_counted() {
        let list = [
            adapter("Wi-Fi", AdapterKind::WiFi, true, true, true),
            adapter("Ethernet", AdapterKind::Ethernet, false, true, false),
            adapter("Ethernet 2", AdapterKind::Ethernet, true, true, false),
            adapter(
                "vEthernet (Default Switch)",
                AdapterKind::Virtual,
                true,
                false,
                false,
            ),
            adapter("Loopback", AdapterKind::Loopback, true, false, false),
            adapter("Tunnel", AdapterKind::Tunnel, true, false, false),
            // A driver that claims to be hardware but is classified virtual.
            adapter("Odd", AdapterKind::Virtual, true, true, false),
        ];
        assert_eq!(
            counted_adapters(&list),
            vec![true, false, true, false, false, false, false]
        );
        assert_eq!(usage_adapter_name(&list, &counted_adapters(&list)), "Wi-Fi");
    }

    #[test]
    fn default_adapter_is_the_fallback_when_nothing_physical_is_up() {
        let list = [
            adapter("Ethernet", AdapterKind::Ethernet, false, true, false),
            adapter("Synthetic", AdapterKind::Virtual, true, false, true),
            adapter("Loopback", AdapterKind::Loopback, true, false, false),
        ];
        let counted = counted_adapters(&list);
        assert_eq!(counted, vec![false, true, false]);
        assert_eq!(usage_adapter_name(&list, &counted), "Synthetic");
        // Nothing up at all.
        let list = [adapter(
            "Ethernet",
            AdapterKind::Ethernet,
            false,
            true,
            false,
        )];
        assert_eq!(counted_adapters(&list), vec![false]);
        assert_eq!(usage_adapter_name(&list, &[false]), "");
        assert!(counted_adapters(&[]).is_empty());
    }

    #[test]
    fn usage_adapter_prefers_default_then_first_counted() {
        // The default route goes through a VPN tunnel: usage is recorded
        // under the physical adapter that carries the traffic.
        let list = [
            adapter("VPN", AdapterKind::Tunnel, true, false, true),
            adapter("Ethernet", AdapterKind::Ethernet, true, true, false),
            adapter("Wi-Fi", AdapterKind::WiFi, true, true, false),
        ];
        let counted = counted_adapters(&list);
        assert_eq!(counted, vec![false, true, true]);
        assert_eq!(usage_adapter_name(&list, &counted), "Ethernet");
    }

    fn meta(luid: u64, name: &str, counted: bool) -> AdapterMeta {
        AdapterMeta {
            luid,
            name: name.into(),
            kind: AdapterKind::Ethernet,
            up: true,
            counted,
        }
    }
    fn c(luid: u64, rx: u64, tx: u64) -> Counters {
        Counters { luid, rx, tx }
    }

    #[test]
    fn net_tick_sums_counted_adapters_only() {
        let metas = [
            meta(1, "Wi-Fi", true),
            meta(2, "vEthernet", false),
            meta(3, "Ethernet", true),
        ];
        let mut net = NetAccounting::default();
        let first = net.tick(0.0, &metas, &[c(1, 1000, 100), c(2, 5000, 500), c(3, 0, 0)]);
        assert_eq!(first.rate, Rate::default());
        assert_eq!(first.added, Totals::default());
        assert!(first.deltas.is_empty());
        assert_eq!(first.adapters.len(), 3);

        let second = net.tick(
            1.0,
            &metas,
            &[c(1, 3000, 300), c(2, 9000, 900), c(3, 500, 50)],
        );
        assert_eq!(second.rate.down, 2500.0);
        assert_eq!(second.rate.up, 250.0);
        assert_eq!(second.added, t(2500, 250));
        assert_eq!(second.deltas, vec![(0, t(2000, 200)), (2, t(500, 50))]);
        // Every adapter still reports its own rate and session.
        assert_eq!(second.adapters[1].rate.down, 4000.0);
        assert_eq!(second.adapters[1].session, t(4000, 400));
        assert_eq!(second.adapters[0].name, "Wi-Fi");
        assert_eq!(net.session(), t(2500, 250));
        assert_eq!(net.history().len(), 2);
        assert_eq!(net.peak().down, 2500.0);
    }

    #[test]
    fn net_peak_is_per_direction_and_history_is_capped() {
        let metas = [meta(1, "Wi-Fi", true)];
        let mut net = NetAccounting::default();
        net.tick(0.0, &metas, &[c(1, 0, 0)]);
        net.tick(1.0, &metas, &[c(1, 1000, 10)]);
        net.tick(2.0, &metas, &[c(1, 1100, 510)]);
        net.tick(3.0, &metas, &[c(1, 1100, 510)]);
        assert_eq!(net.peak().down, 1000.0);
        assert_eq!(net.peak().up, 500.0);
        for i in 0..(NET_HISTORY as u64 + 50) {
            net.tick(4.0 + i as f64, &metas, &[c(1, 1100 + i * 7, 510)]);
        }
        let h = net.history();
        assert_eq!(h.len(), NET_HISTORY);
        assert_eq!(h[h.len() - 1].down, 7.0);
        assert_eq!(net.session(), t(1100 + (NET_HISTORY as u64 + 49) * 7, 510));
    }

    #[test]
    fn adapter_reset_missing_rows_and_reappearing_adapters() {
        let metas = [meta(1, "Wi-Fi", true)];
        let mut net = NetAccounting::default();
        net.tick(0.0, &metas, &[c(1, 10_000, 10_000)]);
        // Counter reset: no negative or huge spike.
        let out = net.tick(1.0, &metas, &[c(1, 100, 100)]);
        assert_eq!(out.added, Totals::default());
        let out = net.tick(2.0, &metas, &[c(1, 400, 100)]);
        assert_eq!(out.added, t(300, 0));
        // No counter row this tick: zero rate, session kept.
        let out = net.tick(3.0, &metas, &[]);
        assert_eq!(out.rate, Rate::default());
        assert_eq!(out.adapters[0].session, t(300, 0));
        // The adapter disappears and comes back: a fresh baseline, so the
        // bytes it counted while away are not billed as one burst.
        net.tick(4.0, &[], &[]);
        let out = net.tick(5.0, &metas, &[c(1, 900_000, 900_000)]);
        assert_eq!(out.added, Totals::default());
        assert_eq!(out.adapters[0].session, Totals::default());
        assert_eq!(net.session(), t(300, 0));
    }

    // ---- apps ----

    fn flow<'a>(app: &'a str, pid: u32, remote: &str, port: u16, rx: u64, tx: u64) -> AppFlow<'a> {
        AppFlow {
            app,
            path: "",
            pid,
            proto: Proto::Tcp,
            remote: Some(ip(remote)),
            remote_port: port,
            rx,
            tx,
        }
    }

    fn conn<'a>(
        app: &'a str,
        pid: u32,
        remote: Option<&str>,
        port: u16,
        state: ConnState,
    ) -> AppConn<'a> {
        AppConn {
            app,
            path: "",
            pid,
            proto: Proto::Tcp,
            remote: remote.map(ip),
            remote_port: port,
            state,
        }
    }

    #[test]
    fn processes_sharing_an_executable_are_one_app() {
        let mut apps = AppAccounting::default();
        let deltas = apps.tick(
            &[
                flow("browser.exe", 100, "198.51.100.20", 443, 4000, 400),
                flow("browser.exe", 104, "198.51.100.21", 443, 1000, 100),
                flow("browser.exe", 100, "198.51.100.20", 443, 1000, 0),
                flow("sync.exe", 200, "203.0.113.9", 443, 10, 2000),
            ],
            1.0,
        );
        assert_eq!(
            deltas,
            vec![
                ("browser.exe".to_string(), t(6000, 500)),
                ("sync.exe".to_string(), t(10, 2000)),
            ]
        );
        let rows = apps.build(&no_today, &no_host);
        assert_eq!(rows.len(), 2);
        let b = &rows[0];
        assert_eq!(b.name, "browser.exe");
        assert_eq!(b.pids, vec![100, 104]);
        assert_eq!(b.session, t(6000, 500));
        assert_eq!(b.rate.down, 6000.0);
        assert_eq!(b.rate.up, 500.0);
        assert_eq!(b.history, vec![b.rate]);
        assert_eq!(b.endpoints.len(), 2);
        assert_eq!(b.endpoints[0].addr, ip("198.51.100.20"));
        assert_eq!((b.endpoints[0].rx, b.endpoints[0].tx), (5000, 400));
        assert_eq!(b.endpoints[1].addr, ip("198.51.100.21"));
    }

    #[test]
    fn rate_uses_the_tick_length_and_idle_ticks_are_zero_samples() {
        let mut apps = AppAccounting::default();
        apps.tick(&[flow("a.exe", 1, "198.51.100.20", 443, 3000, 600)], 2.0);
        let rows = apps.build(&no_today, &no_host);
        assert_eq!(rows[0].rate.down, 1500.0);
        assert_eq!(rows[0].rate.up, 300.0);
        // A broken tick length falls back to one second.
        apps.tick(&[flow("a.exe", 1, "198.51.100.20", 443, 100, 0)], 0.0);
        assert_eq!(apps.build(&no_today, &no_host)[0].rate.down, 100.0);
        apps.tick(&[flow("a.exe", 1, "198.51.100.20", 443, 100, 0)], f64::NAN);
        assert_eq!(apps.build(&no_today, &no_host)[0].rate.down, 100.0);
        // Idle tick.
        let deltas = apps.tick(&[], 1.0);
        assert!(deltas.is_empty());
        let rows = apps.build(&no_today, &no_host);
        assert_eq!(rows[0].rate, Rate::default());
        assert_eq!(rows[0].history.len(), 4);
        assert_eq!(rows[0].history[3], Rate::default());
        assert_eq!(rows[0].session, t(3200, 600));
    }

    #[test]
    fn app_history_is_capped_at_sixty_samples() {
        let mut apps = AppAccounting::default();
        for i in 0..(APP_HISTORY as u64 + 25) {
            apps.tick(&[flow("a.exe", 1, "198.51.100.20", 443, i + 1, 0)], 1.0);
        }
        let rows = apps.build(&no_today, &no_host);
        assert_eq!(rows[0].history.len(), APP_HISTORY);
        assert_eq!(
            rows[0].history[APP_HISTORY - 1].down,
            (APP_HISTORY + 25) as f64
        );
        assert_eq!(rows[0].history[0].down, 26.0);
    }

    #[test]
    fn deltas_feed_the_usage_database_and_today_comes_back() {
        let day = Day {
            y: 2026,
            m: 11,
            d: 16,
        };
        let mut db = UsageDb::default();
        // Bytes from an earlier run today.
        db.add_app(day, "browser.exe", "Wi-Fi", 10_000, 1000);
        let mut apps = AppAccounting::default();
        for _ in 0..3 {
            let deltas = apps.tick(
                &[flow("browser.exe", 100, "198.51.100.20", 443, 500, 50)],
                1.0,
            );
            for (app, bytes) in &deltas {
                db.add_app(day, app, "Wi-Fi", bytes.rx, bytes.tx);
            }
        }
        let rows = apps.build(&|app| db.app_day_total(app, day), &no_host);
        assert_eq!(rows[0].session, t(1500, 150));
        assert_eq!(rows[0].today, t(11_500, 1150));
        // The per-app rows never leak into the adapter-level total.
        assert_eq!(db.day_total(day), Totals::default());
    }

    #[test]
    fn empty_names_zero_flows_and_loopback_endpoints() {
        let mut apps = AppAccounting::default();
        let deltas = apps.tick(
            &[
                flow("", 1, "198.51.100.20", 443, 100, 100),
                flow("a.exe", 1, "198.51.100.20", 443, 0, 0),
                flow("b.exe", 2, "127.0.0.1", 8080, 70, 30),
                AppFlow {
                    remote: None,
                    ..flow("b.exe", 2, "198.51.100.20", 0, 5, 5)
                },
            ],
            1.0,
        );
        // Bytes are counted even without a usable endpoint.
        assert_eq!(deltas, vec![("b.exe".to_string(), t(75, 35))]);
        let rows = apps.build(&no_today, &no_host);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].endpoints.is_empty());
    }

    #[test]
    fn endpoints_are_top_n_by_bytes_with_hosts() {
        let mut apps = AppAccounting::default();
        let addrs: Vec<String> = (1..=20).map(|i| format!("198.51.100.{i}")).collect();
        let flows: Vec<AppFlow> = addrs
            .iter()
            .enumerate()
            .map(|(i, a)| flow("a.exe", 1, a, 443, (i as u64 + 1) * 100, 0))
            .collect();
        apps.tick(&flows, 1.0);
        let host = |a: &IpAddr| (*a == ip("198.51.100.20")).then(|| "cdn.example.net".to_string());
        let rows = apps.build(&no_today, &host);
        let eps = &rows[0].endpoints;
        assert_eq!(eps.len(), TOP_ENDPOINTS);
        assert_eq!(eps[0].addr, ip("198.51.100.20"));
        assert_eq!(eps[0].rx, 2000);
        assert_eq!(eps[0].host.as_deref(), Some("cdn.example.net"));
        assert_eq!(eps[1].host, None);
        assert!(eps
            .windows(2)
            .all(|w| w[0].rx + w[0].tx >= w[1].rx + w[1].tx));
        assert_eq!(eps[TOP_ENDPOINTS - 1].addr, ip("198.51.100.13"));
    }

    #[test]
    fn endpoint_memory_is_bounded_and_keeps_the_largest() {
        let mut apps = AppAccounting::default();
        // One heavy endpoint, then thousands of small ones over many ticks.
        apps.tick(&[flow("a.exe", 1, "203.0.113.1", 443, 1_000_000, 0)], 1.0);
        let mut total = 1_000_000u64;
        for round in 0..40u32 {
            let addrs: Vec<String> = (0..100u32)
                .map(|i| format!("198.51.{}.{}", 100 + (round % 2), i + 1))
                .collect();
            let flows: Vec<AppFlow> = addrs
                .iter()
                .map(|a| flow("a.exe", 1, a, 1000 + round as u16, 10, 0))
                .collect();
            apps.tick(&flows, 1.0);
            total += 1000;
        }
        let acc = apps.apps.get("a.exe").expect("app");
        assert!(acc.endpoints.len() <= MAX_ENDPOINTS_PER_APP);
        assert_eq!(acc.session.rx, total);
        let rows = apps.build(&no_today, &no_host);
        assert_eq!(rows[0].endpoints[0].addr, ip("203.0.113.1"));
        assert_eq!(rows[0].endpoints[0].rx, 1_000_000);
    }

    #[test]
    fn connection_table_gives_counts_pids_and_zero_byte_endpoints() {
        let mut apps = AppAccounting::default();
        apps.set_connections(&[
            conn(
                "browser.exe",
                100,
                Some("198.51.100.20"),
                443,
                ConnState::Established,
            ),
            conn(
                "browser.exe",
                100,
                Some("198.51.100.20"),
                443,
                ConnState::Established,
            ),
            conn(
                "browser.exe",
                104,
                Some("198.51.100.30"),
                443,
                ConnState::CloseWait,
            ),
            conn(
                "browser.exe",
                104,
                Some("127.0.0.1"),
                9000,
                ConnState::Established,
            ),
            conn("server.exe", 300, None, 0, ConnState::Listening),
            AppConn {
                proto: Proto::Udp,
                state: ConnState::Stateless,
                ..conn("dns.exe", 400, None, 0, ConnState::Stateless)
            },
            conn("", 500, Some("198.51.100.40"), 443, ConnState::Established),
        ]);
        let rows = apps.build(&no_today, &no_host);
        assert_eq!(rows.len(), 3);
        let b = rows
            .iter()
            .find(|r| r.name == "browser.exe")
            .expect("browser");
        assert_eq!(b.connections, 4);
        assert_eq!(b.pids, vec![100, 104]);
        assert_eq!(b.session, Totals::default());
        // Connections-only view: endpoints without bytes, loopback left out.
        assert_eq!(b.endpoints.len(), 2);
        assert!(b.endpoints.iter().all(|e| e.rx == 0 && e.tx == 0));
        assert_eq!(b.endpoints[0].addr, ip("198.51.100.20"));
        let s = rows
            .iter()
            .find(|r| r.name == "server.exe")
            .expect("server");
        assert_eq!(s.connections, 0);
        assert_eq!(s.pids, vec![300]);
        assert!(s.endpoints.is_empty());
        let d = rows.iter().find(|r| r.name == "dns.exe").expect("dns");
        assert_eq!(d.connections, 0);
        // Most connections first when nobody has bytes.
        assert_eq!(rows[0].name, "browser.exe");
    }

    #[test]
    fn byte_endpoints_come_before_connection_endpoints_without_duplicates() {
        let mut apps = AppAccounting::default();
        apps.tick(&[flow("a.exe", 1, "198.51.100.20", 443, 500, 0)], 1.0);
        apps.set_connections(&[
            conn(
                "a.exe",
                1,
                Some("198.51.100.20"),
                443,
                ConnState::Established,
            ),
            conn(
                "a.exe",
                1,
                Some("198.51.100.99"),
                443,
                ConnState::Established,
            ),
        ]);
        let rows = apps.build(&no_today, &no_host);
        let eps = &rows[0].endpoints;
        assert_eq!(eps.len(), 2);
        assert_eq!((eps[0].addr, eps[0].rx), (ip("198.51.100.20"), 500));
        assert_eq!((eps[1].addr, eps[1].rx), (ip("198.51.100.99"), 0));
    }

    #[test]
    fn apps_without_sockets_or_bytes_disappear_and_pids_linger_briefly() {
        let mut apps = AppAccounting::default();
        apps.set_connections(&[conn(
            "quiet.exe",
            9,
            Some("198.51.100.20"),
            443,
            ConnState::Established,
        )]);
        assert_eq!(apps.len(), 1);
        apps.set_connections(&[]);
        assert!(apps.is_empty());

        // An app that moved bytes stays for the session, but its PID list
        // empties a while after the traffic stops.
        apps.tick(&[flow("loud.exe", 77, "198.51.100.20", 443, 10, 10)], 1.0);
        for _ in 0..PID_LINGER_TICKS {
            apps.tick(&[], 1.0);
        }
        assert_eq!(apps.build(&no_today, &no_host)[0].pids, vec![77]);
        apps.tick(&[], 1.0);
        let rows = apps.build(&no_today, &no_host);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].pids.is_empty());
        assert_eq!(rows[0].session, t(10, 10));
    }

    #[test]
    fn number_of_remembered_apps_is_bounded() {
        let mut apps = AppAccounting::default();
        let names: Vec<String> = (0..(MAX_APPS + 100))
            .map(|i| format!("app{i}.exe"))
            .collect();
        for (i, name) in names.iter().enumerate() {
            apps.tick(
                &[flow(
                    name,
                    i as u32 * 4 + 8,
                    "198.51.100.20",
                    443,
                    i as u64 + 1,
                    0,
                )],
                1.0,
            );
        }
        // Apps with recent traffic are "in use"; let the PIDs expire.
        for _ in 0..=PID_LINGER_TICKS {
            apps.tick(&[], 1.0);
        }
        assert!(apps.len() <= MAX_APPS, "{}", apps.len());
        // The most recently active apps survive.
        let last = names.last().expect("names");
        assert!(apps.apps.contains_key(last));
        assert!(!apps.apps.contains_key("app0.exe"));
    }

    #[test]
    fn rows_are_sorted_by_session_bytes() {
        let mut apps = AppAccounting::default();
        apps.tick(
            &[
                flow("small.exe", 1, "198.51.100.20", 443, 10, 0),
                flow("big.exe", 2, "198.51.100.20", 443, 10_000, 0),
                flow("mid.exe", 3, "198.51.100.20", 443, 500, 0),
            ],
            1.0,
        );
        let names: Vec<String> = apps
            .build(&no_today, &no_host)
            .into_iter()
            .map(|a| a.name)
            .collect();
        assert_eq!(names, vec!["big.exe", "mid.exe", "small.exe"]);
    }
}
