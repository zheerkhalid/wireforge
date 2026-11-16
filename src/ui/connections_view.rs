//! Connections page: the live TCP / UDP table with owning processes,
//! filters, optional host names, and "end process" behind a confirmation.

use super::app::{App, Confirm};
use super::theme::{pal, regular, semibold, Icon};
use super::widgets::{self, Col};
use crate::export::Table;
use crate::fmt;
use eframe::egui::{self, vec2, RichText, Ui};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{channel, Receiver, Sender};
use wf_traffic::{ConnState, Connection, Proto};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ConnFilter {
    #[default]
    All,
    Tcp,
    Udp,
    Established,
    Listening,
    Internet,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnSort {
    Process,
    Proto,
    Local,
    Remote,
    State,
    Age,
}

pub struct ConnectionsPage {
    pub paused: bool,
    pub filter: ConnFilter,
    pub search: String,
    pub sort: (ConnSort, bool),
    /// Index key of the selected row.
    pub selected: Option<String>,
    hosts: HashMap<IpAddr, Option<String>>,
    host_tx: Option<Sender<IpAddr>>,
    host_rx: Option<Receiver<(IpAddr, Option<String>)>>,
}

impl Default for ConnectionsPage {
    fn default() -> Self {
        ConnectionsPage {
            paused: false,
            filter: ConnFilter::All,
            search: String::new(),
            sort: (ConnSort::Process, true),
            selected: None,
            hosts: HashMap::new(),
            host_tx: None,
            host_rx: None,
        }
    }
}

/// Where an address lives, worked out offline.
pub fn scope(addr: &IpAddr) -> &'static str {
    match addr {
        IpAddr::V4(v) => {
            let o = v.octets();
            if v.is_loopback() {
                "This PC"
            } else if v.is_unspecified() {
                "Any"
            } else if v.is_private() || v.is_link_local() {
                "Local network"
            } else if o[0] == 100 && (64..128).contains(&o[1]) {
                "Provider network"
            } else if v.is_multicast() || v.is_broadcast() {
                "Multicast"
            } else {
                "Internet"
            }
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            if v.is_loopback() {
                "This PC"
            } else if v.is_unspecified() {
                "Any"
            } else if (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xfe00) == 0xfc00 {
                "Local network"
            } else if (s[0] & 0xff00) == 0xff00 {
                "Multicast"
            } else {
                "Internet"
            }
        }
    }
}

/// `192.0.2.1:443`, `[2001:db8::1]:443`, `192.0.2.1` when the port is 0.
pub fn endpoint(addr: &IpAddr, port: u16) -> String {
    match (addr, port) {
        (a, 0) => a.to_string(),
        (IpAddr::V4(a), p) => format!("{a}:{p}"),
        (IpAddr::V6(a), p) => format!("[{a}]:{p}"),
    }
}

/// A stable identity for a row between refreshes.
pub fn row_key(c: &Connection) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        c.proto.label(),
        c.local,
        c.local_port,
        c.remote.map(|r| r.to_string()).unwrap_or_default(),
        c.remote_port,
        c.pid
    )
}

pub fn matches(c: &Connection, filter: ConnFilter, needle: &str, host: Option<&str>) -> bool {
    let pass = match filter {
        ConnFilter::All => true,
        ConnFilter::Tcp => c.proto == Proto::Tcp,
        ConnFilter::Udp => c.proto == Proto::Udp,
        ConnFilter::Established => c.state == ConnState::Established,
        ConnFilter::Listening => c.state == ConnState::Listening,
        ConnFilter::Internet => c.remote.map(|r| scope(&r) == "Internet").unwrap_or(false),
    };
    if !pass {
        return false;
    }
    let needle = needle.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    c.process.to_lowercase().contains(&needle)
        || c.pid.to_string() == needle
        || c.local.to_string().contains(&needle)
        || c.local_port.to_string() == needle
        || c.remote_port.to_string() == needle
        || c.remote
            .map(|r| r.to_string().contains(&needle))
            .unwrap_or(false)
        || c.state.label().to_lowercase().contains(&needle)
        || host
            .map(|h| h.to_lowercase().contains(&needle))
            .unwrap_or(false)
}

pub fn sort_connections(list: &mut [Connection], sort: (ConnSort, bool)) {
    list.sort_by(|a, b| {
        let ord = match sort.0 {
            ConnSort::Process => a
                .process
                .to_lowercase()
                .cmp(&b.process.to_lowercase())
                .then(a.pid.cmp(&b.pid)),
            ConnSort::Proto => a.proto.label().cmp(b.proto.label()),
            ConnSort::Local => a.local_port.cmp(&b.local_port).then(a.local.cmp(&b.local)),
            ConnSort::Remote => a
                .remote
                .cmp(&b.remote)
                .then(a.remote_port.cmp(&b.remote_port)),
            ConnSort::State => a.state.label().cmp(b.state.label()),
            // Newest first when descending; unknown ages last.
            ConnSort::Age => b.created.unwrap_or(0).cmp(&a.created.unwrap_or(0)),
        };
        let ord = if sort.1 { ord } else { ord.reverse() };
        ord.then_with(|| row_key(a).cmp(&row_key(b)))
    });
}

pub fn connections_table(
    list: &[Connection],
    hosts: &HashMap<IpAddr, Option<String>>,
    now: i64,
) -> Table {
    let mut t = Table::new(
        "Connections",
        &[
            "Process",
            "PID",
            "Protocol",
            "Local address",
            "Local port",
            "Remote address",
            "Remote port",
            "Remote host",
            "Where",
            "State",
            "Open for",
            "Path",
        ],
    );
    for c in list {
        t.push(vec![
            c.process.clone(),
            c.pid.to_string(),
            c.proto.label().to_string(),
            c.local.to_string(),
            c.local_port.to_string(),
            c.remote.map(|r| r.to_string()).unwrap_or_default(),
            if c.remote.is_some() {
                c.remote_port.to_string()
            } else {
                String::new()
            },
            c.remote
                .and_then(|r| hosts.get(&r).cloned().flatten())
                .unwrap_or_default(),
            c.remote.map(|r| scope(&r).to_string()).unwrap_or_default(),
            c.state.label().to_string(),
            c.created
                .map(|t| fmt::duration(now - t))
                .unwrap_or_default(),
            c.path.clone(),
        ]);
    }
    t
}

const COLS: [Col; 6] = [
    Col::flex("Process", 1.0),
    Col::fixed("Protocol", 64.0),
    Col::flex("Local", 0.9),
    Col::flex("Remote", 1.55),
    Col::fixed("State", 108.0),
    Col::right("Open for", 78.0),
];

impl App {
    /// Starts the reverse-DNS worker the first time host names are wanted.
    fn conn_resolver(&mut self, ctx: &egui::Context) {
        if self.conns.host_tx.is_some() {
            return;
        }
        let (req_tx, req_rx) = channel::<IpAddr>();
        let (res_tx, res_rx) = channel::<(IpAddr, Option<String>)>();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            while let Ok(ip) = req_rx.recv() {
                let name = wf_traffic::rdns::reverse_dns(ip);
                if res_tx.send((ip, name)).is_err() {
                    break;
                }
                ctx.request_repaint();
            }
        });
        self.conns.host_tx = Some(req_tx);
        self.conns.host_rx = Some(res_rx);
    }

    fn conn_host(&mut self, ctx: &egui::Context, addr: IpAddr) -> Option<String> {
        if self.demo {
            return crate::demo::host_for(&addr);
        }
        if !self.settings.resolve_hosts || matches!(scope(&addr), "This PC" | "Any" | "Multicast") {
            return None;
        }
        if let Some(found) = self.conns.hosts.get(&addr) {
            return found.clone();
        }
        self.conn_resolver(ctx);
        self.conns.hosts.insert(addr, None);
        if let Some(tx) = &self.conns.host_tx {
            let _ = tx.send(addr);
        }
        None
    }

    pub(super) fn connections_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        if let Some(rx) = &self.conns.host_rx {
            while let Ok((ip, name)) = rx.try_recv() {
                self.conns.hosts.insert(ip, name);
            }
        }
        if let Some(pid) = self.confirmed_prefix("conn.end:") {
            if let Ok(pid) = pid.parse::<u32>() {
                if self.demo {
                    self.toast("Demo mode: nothing was ended.", false);
                } else {
                    match wf_traffic::procs::end_process(pid) {
                        Ok(()) => {
                            self.toast("The process was ended.", false);
                            self.poll.connections_now.store(true, Ordering::Relaxed);
                        }
                        Err(e) => self.toast(e, true),
                    }
                }
            }
        }
        // First visit: do not wait for the next poll.
        if !self.demo && self.connections_at.is_none() && self.connections_error.is_none() {
            self.poll.connections_now.store(true, Ordering::Relaxed);
        }

        let all = self.connections.clone();
        let count = |f: ConnFilter| all.iter().filter(|c| matches(c, f, "", None)).count();
        let subtitle = format!(
            "{} connections and open ports, {} listening{}",
            all.len(),
            count(ConnFilter::Listening),
            if self.conns.paused {
                ". Paused."
            } else {
                ", refreshed every two seconds."
            }
        );
        let mut export = false;
        widgets::page_header(ui, "Connections", &subtitle, |ui| {
            if widgets::ghost_button(ui, &Icon::EXPORT.with("Export"))
                .on_hover_text("The export contains addresses and program names from this PC.")
                .clicked()
            {
                export = true;
            }
            let label = if self.conns.paused {
                Icon::PLAY.with("Resume")
            } else {
                Icon::STOP.with("Pause")
            };
            if widgets::ghost_button(ui, &label)
                .on_hover_text("Freeze the list so rows stop moving")
                .clicked()
            {
                self.conns.paused = !self.conns.paused;
            }
        });

        ui.horizontal(|ui| {
            for (f, label) in [
                (ConnFilter::All, "All"),
                (ConnFilter::Tcp, "TCP"),
                (ConnFilter::Udp, "UDP"),
                (ConnFilter::Established, "Connected"),
                (ConnFilter::Listening, "Listening"),
                (ConnFilter::Internet, "To the internet"),
            ] {
                if widgets::chip(ui, label, Some(count(f)), self.conns.filter == f).clicked() {
                    self.conns.filter = f;
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                widgets::search_box(
                    ui,
                    &mut self.conns.search,
                    "Search process, address or port",
                    250.0,
                );
                ui.add_space(6.0);
                if !self.demo {
                    ui.label(RichText::new("Host names").size(13.0).color(p.muted));
                    if widgets::toggle(ui, self.settings.resolve_hosts, true)
                        .on_hover_text(
                            "Look up the name of each remote address. This asks your DNS \
                             server about every address in the list, so it is off by default.",
                        )
                        .clicked()
                    {
                        self.settings.resolve_hosts = !self.settings.resolve_hosts;
                        self.save_settings();
                        if let Some(m) = &self.monitor {
                            m.set_resolve_hosts(self.settings.resolve_hosts);
                        }
                    }
                }
            });
        });
        ui.add_space(8.0);

        if let Some(e) = &self.connections_error {
            widgets::notice(
                ui,
                Icon::WARNING,
                p.warn,
                &format!("The connection table could not be read: {e}"),
            );
            ui.add_space(8.0);
        }

        // Resolve names first so the search can use them.
        let mut hosts: HashMap<IpAddr, Option<String>> = HashMap::new();
        for c in &all {
            if let Some(r) = c.remote {
                if let std::collections::hash_map::Entry::Vacant(e) = hosts.entry(r) {
                    let name = self.conn_host(&ctx, r);
                    e.insert(name);
                }
            }
        }
        let mut list: Vec<Connection> = all
            .into_iter()
            .filter(|c| {
                let host = c.remote.and_then(|r| hosts.get(&r).cloned().flatten());
                matches(c, self.conns.filter, &self.conns.search, host.as_deref())
            })
            .collect();
        sort_connections(&mut list, self.conns.sort);
        if export {
            let table = connections_table(&list, &hosts, self.now);
            self.export(&[table], "Connections", "wireforge-connections");
        }

        let selected = self
            .conns
            .selected
            .as_ref()
            .and_then(|k| list.iter().find(|c| &row_key(c) == k))
            .cloned();
        let footer = if selected.is_some() { 74.0 } else { 0.0 };
        let now = self.now;
        widgets::card(ui, |ui| {
            ui.set_min_height(ui.available_height() - footer - 34.0);
            let sorts = [
                ConnSort::Process,
                ConnSort::Proto,
                ConnSort::Local,
                ConnSort::Remote,
                ConnSort::State,
                ConnSort::Age,
            ];
            let sorted = sorts
                .iter()
                .position(|s| *s == self.conns.sort.0)
                .map(|i| (i, self.conns.sort.1));
            if let Some(i) = widgets::table_header(ui, &COLS, sorted) {
                let s = sorts[i];
                self.conns.sort = if self.conns.sort.0 == s {
                    (s, !self.conns.sort.1)
                } else {
                    (s, true)
                };
            }
            if list.is_empty() {
                let loading =
                    !self.demo && self.connections_at.is_none() && self.connections_error.is_none();
                if loading {
                    widgets::busy_state(ui, "Reading the connection table", "");
                } else {
                    widgets::empty_state(
                        ui,
                        Icon::CONNECTIONS,
                        p.muted,
                        "Nothing matches",
                        "Change the filter or clear the search to see more connections.",
                    );
                }
                return;
            }
            let mut clicked: Option<String> = None;
            let max_h = ui.available_height() - footer;
            egui::ScrollArea::vertical()
                .id_salt("connections")
                .auto_shrink([false, false])
                .max_height(max_h.max(120.0))
                .show_rows(ui, 42.0, list.len(), |ui, range| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for c in &list[range] {
                        let key = row_key(c);
                        let is_sel = self.conns.selected.as_deref() == Some(&key);
                        let tex = self.icon(&c.process, &c.path);
                        let (cells, resp) = widgets::table_row(ui, &COLS, 42.0, is_sel);
                        // Process
                        let cell = cells[0];
                        let icon_rect = egui::Rect::from_center_size(
                            cell.left_center() + vec2(11.0, 0.0),
                            vec2(22.0, 22.0),
                        );
                        let shown = if c.process.is_empty() {
                            "Unknown process"
                        } else {
                            &c.process
                        };
                        widgets::program_icon(ui, icon_rect, shown, tex.as_ref());
                        let name = egui::Rect::from_min_max(
                            cell.left_top() + vec2(32.0, 4.0),
                            egui::pos2(cell.right(), cell.center().y + 2.0),
                        );
                        widgets::text_in(ui, name, shown, semibold(13.0), p.text);
                        let sub = egui::Rect::from_min_max(
                            egui::pos2(name.left(), cell.center().y + 1.0),
                            egui::pos2(cell.right(), cell.bottom() - 4.0),
                        );
                        widgets::text_in(
                            ui,
                            sub,
                            &format!("PID {}", c.pid),
                            regular(11.5),
                            p.faint,
                        );
                        // Protocol
                        widgets::paint_badge(
                            ui,
                            cells[1],
                            c.proto.label(),
                            if c.proto == Proto::Tcp {
                                p.accent
                            } else {
                                p.info
                            },
                        );
                        // Local
                        widgets::text_in(
                            ui,
                            cells[2],
                            &endpoint(&c.local, c.local_port),
                            regular(13.0),
                            p.muted,
                        );
                        // Remote
                        match c.remote {
                            Some(r) => {
                                let host = hosts.get(&r).cloned().flatten();
                                let top = egui::Rect::from_min_max(
                                    cells[3].left_top() + vec2(0.0, 4.0),
                                    egui::pos2(cells[3].right(), cells[3].center().y + 2.0),
                                );
                                let bottom = egui::Rect::from_min_max(
                                    egui::pos2(cells[3].left(), cells[3].center().y + 1.0),
                                    egui::pos2(cells[3].right(), cells[3].bottom() - 4.0),
                                );
                                let ep = endpoint(&r, c.remote_port);
                                match host {
                                    Some(h) => {
                                        widgets::text_in(ui, top, &h, regular(13.0), p.text);
                                        widgets::text_in(
                                            ui,
                                            bottom,
                                            &format!("{ep}, {}", scope(&r)),
                                            regular(11.5),
                                            p.faint,
                                        );
                                    }
                                    None => {
                                        widgets::text_in(ui, top, &ep, regular(13.0), p.text);
                                        widgets::text_in(
                                            ui,
                                            bottom,
                                            scope(&r),
                                            regular(11.5),
                                            p.faint,
                                        );
                                    }
                                }
                            }
                            None => {
                                widgets::text_in(
                                    ui,
                                    cells[3],
                                    if c.state == ConnState::Listening {
                                        "Waiting for incoming connections"
                                    } else {
                                        "Any (not connected to one address)"
                                    },
                                    regular(12.5),
                                    p.faint,
                                );
                            }
                        }
                        // State
                        let color = match c.state {
                            ConnState::Established => p.good,
                            ConnState::Listening => p.info,
                            ConnState::Stateless => p.muted,
                            _ => p.warn,
                        };
                        widgets::paint_badge(ui, cells[4], c.state.label(), color);
                        // Age
                        if let Some(t) = c.created {
                            widgets::text_in_right(
                                ui,
                                cells[5],
                                &fmt::duration(now - t),
                                regular(12.5),
                                p.muted,
                            );
                        }
                        if resp.clicked() {
                            clicked = Some(key);
                        }
                    }
                });
            if let Some(key) = clicked {
                self.conns.selected = if self.conns.selected.as_deref() == Some(&key) {
                    None
                } else {
                    Some(key)
                };
            }
        });

        if let Some(c) = selected {
            ui.add_space(8.0);
            let refusal =
                wf_traffic::procs::end_process_refusal(c.pid, &c.process, std::process::id());
            let mut end = false;
            let mut copy: Option<String> = None;
            widgets::card(ui, |ui| {
                ui.allocate_ui_with_layout(
                    vec2(ui.available_width(), 34.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 0.0;
                            ui.label(
                                RichText::new(format!(
                                    "{} (PID {})",
                                    if c.process.is_empty() {
                                        "Unknown process"
                                    } else {
                                        &c.process
                                    },
                                    c.pid
                                ))
                                .font(semibold(14.0)),
                            );
                            ui.add(
                                egui::Label::new(
                                    RichText::new(if c.path.is_empty() {
                                        "Path not available (protected or system process)"
                                    } else {
                                        &c.path
                                    })
                                    .size(12.0)
                                    .color(p.faint),
                                )
                                .truncate(),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let r = widgets::danger_button(
                                ui,
                                "End process\u{2026}",
                                refusal.is_none(),
                            );
                            if let Some(why) = &refusal {
                                r.on_hover_text(why);
                            } else if r.clicked() {
                                end = true;
                            }
                            if let Some(r) = c.remote {
                                if widgets::ghost_button(ui, &Icon::COPY.with("Copy address"))
                                    .clicked()
                                {
                                    copy = Some(r.to_string());
                                }
                            }
                        });
                    },
                );
            });
            if let Some(text) = copy {
                self.copy(&ctx, &text, "Address");
            }
            if end {
                let same = self.connections.iter().filter(|x| x.pid == c.pid).count();
                self.ask(Confirm {
                    title: format!("End {}?", c.process),
                    intro: "The program is closed immediately, without a chance to save. \
                            Unsaved work in it is lost."
                        .into(),
                    lines: vec![
                        format!("{} (process ID {})", c.process, c.pid),
                        format!("{same} connections and open ports belong to it"),
                    ],
                    button: "End process".into(),
                    danger: true,
                    tag: format!("conn.end:{}", c.pid),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn conn(
        process: &str,
        pid: u32,
        proto: Proto,
        remote: Option<&str>,
        state: ConnState,
    ) -> Connection {
        Connection {
            proto,
            local: IpAddr::V4(Ipv4Addr::new(192, 168, 50, 23)),
            local_port: 50_000 + pid as u16,
            remote: remote.map(|r| r.parse().unwrap()),
            remote_port: if remote.is_some() { 443 } else { 0 },
            state,
            pid,
            process: process.into(),
            path: String::new(),
            created: Some(1000 + pid as i64),
        }
    }

    #[test]
    fn scopes() {
        let s = |t: &str| scope(&t.parse().unwrap());
        assert_eq!(s("127.0.0.1"), "This PC");
        assert_eq!(s("0.0.0.0"), "Any");
        assert_eq!(s("192.168.1.9"), "Local network");
        assert_eq!(s("10.4.4.4"), "Local network");
        assert_eq!(s("169.254.3.3"), "Local network");
        assert_eq!(s("100.64.0.1"), "Provider network");
        assert_eq!(s("224.0.0.251"), "Multicast");
        assert_eq!(s("198.51.100.7"), "Internet");
        assert_eq!(s("::1"), "This PC");
        assert_eq!(s("::"), "Any");
        assert_eq!(s("fe80::1"), "Local network");
        assert_eq!(s("fd00::1"), "Local network");
        assert_eq!(s("ff02::fb"), "Multicast");
        assert_eq!(s("2001:db8::1"), "Internet");
    }

    #[test]
    fn endpoints() {
        assert_eq!(
            endpoint(&"192.0.2.1".parse().unwrap(), 443),
            "192.0.2.1:443"
        );
        assert_eq!(endpoint(&"192.0.2.1".parse().unwrap(), 0), "192.0.2.1");
        assert_eq!(endpoint(&IpAddr::V6(Ipv6Addr::LOCALHOST), 80), "[::1]:80");
    }

    #[test]
    fn filters_and_search() {
        let a = conn(
            "lumen.exe",
            10,
            Proto::Tcp,
            Some("198.51.100.7"),
            ConnState::Established,
        );
        let b = conn("svchost.exe", 20, Proto::Udp, None, ConnState::Stateless);
        let c = conn("parley.exe", 30, Proto::Tcp, None, ConnState::Listening);
        let d = conn(
            "nas.exe",
            40,
            Proto::Tcp,
            Some("192.168.50.9"),
            ConnState::Established,
        );
        assert!(matches(&a, ConnFilter::All, "", None));
        assert!(matches(&a, ConnFilter::Tcp, "", None) && !matches(&b, ConnFilter::Tcp, "", None));
        assert!(matches(&b, ConnFilter::Udp, "", None));
        assert!(matches(&c, ConnFilter::Listening, "", None));
        assert!(!matches(&c, ConnFilter::Established, "", None));
        assert!(matches(&a, ConnFilter::Internet, "", None));
        assert!(!matches(&d, ConnFilter::Internet, "", None));
        assert!(!matches(&b, ConnFilter::Internet, "", None));
        assert!(matches(&a, ConnFilter::All, " LUMEN ", None));
        assert!(matches(&a, ConnFilter::All, "443", None));
        assert!(matches(&a, ConnFilter::All, "198.51", None));
        assert!(matches(&a, ConnFilter::All, "10", None));
        assert!(!matches(&a, ConnFilter::All, "77777", None));
        assert!(matches(
            &a,
            ConnFilter::All,
            "videonest",
            Some("cdn.videonest.example")
        ));
        assert!(!matches(&a, ConnFilter::All, "videonest", None));
        assert!(matches(&c, ConnFilter::All, "listen", None));
    }

    #[test]
    fn sorting_is_stable_and_keys_are_unique() {
        let mut list = vec![
            conn(
                "b.exe",
                2,
                Proto::Tcp,
                Some("198.51.100.7"),
                ConnState::Established,
            ),
            conn("a.exe", 9, Proto::Udp, None, ConnState::Stateless),
            conn(
                "a.exe",
                1,
                Proto::Tcp,
                Some("198.51.100.3"),
                ConnState::Established,
            ),
        ];
        sort_connections(&mut list, (ConnSort::Process, true));
        assert_eq!(
            list.iter().map(|c| c.pid).collect::<Vec<_>>(),
            vec![1, 9, 2]
        );
        sort_connections(&mut list, (ConnSort::Process, false));
        assert_eq!(list[0].pid, 2);
        sort_connections(&mut list, (ConnSort::Age, true));
        assert_eq!(list[0].pid, 9);
        sort_connections(&mut list, (ConnSort::Remote, true));
        assert!(list[0].remote.is_none());
        let keys: std::collections::HashSet<String> = list.iter().map(row_key).collect();
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn export_table_shape() {
        let list = vec![
            conn(
                "a.exe",
                1,
                Proto::Tcp,
                Some("198.51.100.3"),
                ConnState::Established,
            ),
            conn("b.exe", 2, Proto::Udp, None, ConnState::Stateless),
        ];
        let mut hosts = HashMap::new();
        hosts.insert(
            "198.51.100.3".parse().unwrap(),
            Some("h.example".to_string()),
        );
        let t = connections_table(&list, &hosts, 2000);
        assert!(t.rows.iter().all(|r| r.len() == t.columns.len()));
        assert_eq!(t.rows[0][7], "h.example");
        assert_eq!(t.rows[0][8], "Internet");
        assert_eq!(t.rows[1][5], "");
        assert_eq!(t.rows[1][6], "");
    }
}
