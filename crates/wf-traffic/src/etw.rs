//! Per-process byte counts from the kernel network trace (needs administrator rights).
//!
//! A private real-time ETW session ("WireForge-Net") enables the manifest
//! provider Microsoft-Windows-Kernel-Network. That provider was chosen over
//! the "NT Kernel Logger" network flag because the kernel logger is a single
//! system-wide session that other tools (xperf, Process Explorer, ...) fight
//! over, while a private session with a manifest provider can coexist with
//! anything and can be filtered by keyword to the data events alone.
//!
//! Event payloads are parsed by pure functions over byte slices (unit-tested
//! with fabricated payloads).

use crate::types::*;
use crate::util;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, PROCESSTRACE_HANDLE,
};

/// The fixed, private session name.
pub const SESSION_NAME: &str = "WireForge-Net";

/// Microsoft-Windows-Kernel-Network {7DD42A49-5329-4832-8DFD-43D979153A88}.
const PROVIDER: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);
/// KERNEL_NETWORK_KEYWORD_IPV4 | KERNEL_NETWORK_KEYWORD_IPV6.
const KEYWORDS: u64 = 0x10 | 0x20;

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_ALREADY_EXISTS: u32 = 183;
const WNODE_FLAG_TRACED_GUID: u32 = 0x0002_0000;
const EVENT_TRACE_REAL_TIME_MODE: u32 = 0x0000_0100;
const PROCESS_TRACE_MODE_REAL_TIME: u32 = 0x0000_0100;
const PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 0x1000_0000;
const EVENT_CONTROL_CODE_ENABLE_PROVIDER: u32 = 1;
const TRACE_LEVEL_INFORMATION: u8 = 4;

/// Distinct (process, endpoint) flows kept between two drains. Bytes of flows
/// beyond the cap are still counted, against the process without an endpoint.
pub const MAX_FLOWS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EtwError {
    NeedsAdmin,
    Other(String),
}

impl std::fmt::Display for EtwError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EtwError::NeedsAdmin => write!(
                f,
                "Per-app byte counts need administrator rights. Run WireForge as administrator to see them."
            ),
            EtwError::Other(why) => write!(f, "The network trace could not be started: {why}"),
        }
    }
}

/// Bytes moved by one process to / from one remote endpoint since the last drain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowDelta {
    pub pid: u32,
    pub proto: Proto,
    pub remote: Option<IpAddr>,
    pub remote_port: u16,
    pub rx: u64,
    pub tx: u64,
}

// ---------------------------------------------------------------------------
// Pure parsing and aggregation
// ---------------------------------------------------------------------------

/// What a Kernel-Network event id means, for the ids that carry data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventKind {
    pub proto: Proto,
    pub sent: bool,
    pub v6: bool,
}

/// Maps an event id of Microsoft-Windows-Kernel-Network to its meaning;
/// `None` for connect / disconnect / retransmit and other ids.
pub fn event_kind(id: u16) -> Option<EventKind> {
    let (proto, sent, v6) = match id {
        10 => (Proto::Tcp, true, false),
        11 => (Proto::Tcp, false, false),
        26 => (Proto::Tcp, true, true),
        27 => (Proto::Tcp, false, true),
        42 => (Proto::Udp, true, false),
        43 => (Proto::Udp, false, false),
        58 => (Proto::Udp, true, true),
        59 => (Proto::Udp, false, true),
        _ => return None,
    };
    Some(EventKind { proto, sent, v6 })
}

/// One decoded send / receive event. `saddr` / `daddr` are the fields as the
/// provider names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetEvent {
    pub pid: u32,
    pub proto: Proto,
    pub sent: bool,
    pub size: u32,
    pub daddr: IpAddr,
    pub saddr: IpAddr,
    pub dport: u16,
    pub sport: u16,
}

fn le_u32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn be_u16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

/// Decodes the payload of a data event.
///
/// Layout (both TCP and UDP): `PID u32, size u32, daddr, saddr, dport u16,
/// sport u16, ...` with 4-byte addresses for IPv4 and 16-byte ones for IPv6;
/// addresses and ports are in network byte order. Trailing fields (sequence
/// number, connection id, ...) are ignored.
pub fn parse_event(id: u16, payload: &[u8]) -> Option<NetEvent> {
    let kind = event_kind(id)?;
    let pid = le_u32(payload, 0)?;
    let size = le_u32(payload, 4)?;
    let (daddr, saddr, ports) = if kind.v6 {
        let d: [u8; 16] = payload.get(8..24)?.try_into().ok()?;
        let s: [u8; 16] = payload.get(24..40)?.try_into().ok()?;
        (
            IpAddr::V6(Ipv6Addr::from(d)),
            IpAddr::V6(Ipv6Addr::from(s)),
            40,
        )
    } else {
        let d: [u8; 4] = payload.get(8..12)?.try_into().ok()?;
        let s: [u8; 4] = payload.get(12..16)?.try_into().ok()?;
        (
            IpAddr::V4(Ipv4Addr::from(d)),
            IpAddr::V4(Ipv4Addr::from(s)),
            16,
        )
    };
    Some(NetEvent {
        pid,
        proto: kind.proto,
        sent: kind.sent,
        size,
        daddr,
        saddr,
        dport: be_u16(payload, ports)?,
        sport: be_u16(payload, ports + 2)?,
    })
}

/// IPv4-mapped IPv6 addresses are compared and reported as IPv4.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        v4 => v4,
    }
}

/// Which side of an event is the remote endpoint.
///
/// The provider reports the local side as the source for both directions on
/// current Windows versions, but this is not documented, so the addresses of
/// this PC decide whenever they can: the side that is not a local address is
/// the remote one. Without that knowledge the destination is taken.
pub fn remote_of(ev: &NetEvent, is_local: &dyn Fn(&IpAddr) -> bool) -> (IpAddr, u16) {
    let s = canonical(ev.saddr);
    let d = canonical(ev.daddr);
    match (is_local(&s), is_local(&d)) {
        (false, true) => (s, ev.sport),
        _ => (d, ev.dport),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FlowKey {
    pid: u32,
    proto: Proto,
    remote: Option<IpAddr>,
    remote_port: u16,
}

/// Aggregates events into flows, with a bound on the number of distinct flows.
#[derive(Debug, Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, Totals>,
    local: Vec<IpAddr>,
}

impl FlowTable {
    /// The addresses of this PC (used to tell the remote side of an event).
    pub fn set_local_addrs(&mut self, addrs: &[IpAddr]) {
        self.local = addrs.iter().map(|a| canonical(*a)).collect();
        self.local.sort();
        self.local.dedup();
    }

    /// Adds one event. Traffic that never leaves the machine (loopback, or
    /// between two addresses of this PC) is not counted.
    pub fn record(&mut self, ev: &NetEvent) {
        if ev.size == 0 {
            return;
        }
        let s = canonical(ev.saddr);
        let d = canonical(ev.daddr);
        if util::is_loopback_or_unspecified(&s) && util::is_loopback_or_unspecified(&d) {
            return;
        }
        if s.is_loopback() || d.is_loopback() || s == d {
            return;
        }
        let local = &self.local;
        let is_local = |ip: &IpAddr| local.binary_search(ip).is_ok();
        if is_local(&s) && is_local(&d) {
            return;
        }
        let (remote, remote_port) = remote_of(ev, &is_local);
        let mut key = FlowKey {
            pid: ev.pid,
            proto: ev.proto,
            remote: Some(remote),
            remote_port,
        };
        if self.flows.len() >= MAX_FLOWS && !self.flows.contains_key(&key) {
            // Over the cap: keep counting, but without the endpoint detail.
            key.remote = None;
            key.remote_port = 0;
            if self.flows.len() >= MAX_FLOWS * 2 && !self.flows.contains_key(&key) {
                // Pathological number of processes: fold into the unknown process.
                key.pid = 0;
            }
        }
        let t = self.flows.entry(key).or_default();
        if ev.sent {
            t.tx = t.tx.saturating_add(ev.size as u64);
        } else {
            t.rx = t.rx.saturating_add(ev.size as u64);
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Everything counted since the previous call.
    pub fn drain(&mut self) -> Vec<FlowDelta> {
        let out: Vec<FlowDelta> = self
            .flows
            .drain()
            .map(|(k, t)| FlowDelta {
                pid: k.pid,
                proto: k.proto,
                remote: k.remote,
                remote_port: k.remote_port,
                rx: t.rx,
                tx: t.tx,
            })
            .collect();
        if self.flows.capacity() > MAX_FLOWS * 4 {
            self.flows.shrink_to(MAX_FLOWS);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

struct Shared {
    table: Mutex<FlowTable>,
    events: AtomicU64,
    /// Cleared by the consumer thread when ProcessTrace returns.
    running: AtomicBool,
}

/// `EVENT_TRACE_PROPERTIES` followed by room for the session name, in a
/// buffer aligned for the structure.
struct Props {
    buf: Vec<u64>,
}

impl Props {
    fn new() -> Props {
        let name_bytes = (SESSION_NAME.len() + 1) * 2;
        let total = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + name_bytes + 16;
        let mut props = Props {
            buf: vec![0u64; total.div_ceil(8)],
        };
        let size = (props.buf.len() * 8) as u32;
        // SAFETY: the buffer is zeroed, 8-byte aligned and larger than the
        // structure; all-zero is a valid EVENT_TRACE_PROPERTIES.
        let p = unsafe { &mut *props.ptr() };
        p.Wnode.BufferSize = size;
        p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        p.Wnode.ClientContext = 1; // QPC time stamps
        p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        p.BufferSize = 64; // KB per buffer
        p.MinimumBuffers = 4;
        p.MaximumBuffers = 32;
        p.FlushTimer = 1; // seconds
        p.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        props
    }

    fn ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
    }
}

/// Stops a session of our name, whoever started it. Returns the Win32 error.
fn stop_by_name() -> u32 {
    let name = util::wide(SESSION_NAME);
    let mut props = Props::new();
    // SAFETY: `name` is NUL terminated and `props` is a correctly sized and
    // initialised properties buffer; both outlive the call.
    unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            props.ptr(),
            EVENT_TRACE_CONTROL_STOP,
        )
        .0
    }
}

/// Called by ETW on the consumer thread for every event of the session.
unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    // SAFETY: ETW passes a valid record for the duration of the callback.
    let rec = unsafe { &*record };
    if rec.UserContext.is_null() || rec.EventHeader.ProviderId != PROVIDER {
        return;
    }
    let id = rec.EventHeader.EventDescriptor.Id;
    if event_kind(id).is_none() || rec.UserData.is_null() {
        return;
    }
    // SAFETY: `UserData` points to `UserDataLength` bytes owned by ETW while
    // the callback runs.
    let payload = unsafe {
        std::slice::from_raw_parts(rec.UserData as *const u8, rec.UserDataLength as usize)
    };
    let Some(ev) = parse_event(id, payload) else {
        return;
    };
    // SAFETY: `UserContext` is the `Arc<Shared>` pointer handed to OpenTraceW;
    // the consumer thread keeps that reference alive until ProcessTrace returns.
    let shared = unsafe { &*(rec.UserContext as *const Shared) };
    shared.events.fetch_add(1, Ordering::Relaxed);
    util::lock(&shared.table).record(&ev);
}

/// A running real-time trace session; stopped when dropped.
pub struct EtwSession {
    shared: Arc<Shared>,
    control: CONTROLTRACE_HANDLE,
    consumer: Option<std::thread::JoinHandle<()>>,
    done: Mutex<mpsc::Receiver<()>>,
}

impl EtwSession {
    pub fn start() -> Result<EtwSession, EtwError> {
        // A session left behind by a crash would make StartTraceW fail.
        let _ = stop_by_name();

        let name = util::wide(SESSION_NAME);
        let mut control = CONTROLTRACE_HANDLE::default();
        let mut err = 0u32;
        for _ in 0..2 {
            let mut props = Props::new();
            // SAFETY: valid out pointer, NUL-terminated name and a correctly
            // sized properties buffer.
            err = unsafe { StartTraceW(&mut control, PCWSTR(name.as_ptr()), props.ptr()).0 };
            if err != ERROR_ALREADY_EXISTS {
                break;
            }
            let _ = stop_by_name();
        }
        match err {
            0 => {}
            ERROR_ACCESS_DENIED => return Err(EtwError::NeedsAdmin),
            e => return Err(EtwError::Other(format!("StartTrace failed with error {e}"))),
        }

        // From here on the session exists: stop it on every error path.
        let fail = |what: &str, code: u32| -> EtwError {
            let _ = stop_by_name();
            if code == ERROR_ACCESS_DENIED {
                EtwError::NeedsAdmin
            } else {
                EtwError::Other(format!("{what} failed with error {code}"))
            }
        };

        // SAFETY: `control` is the handle just returned by StartTraceW and the
        // provider GUID outlives the call.
        let en = unsafe {
            EnableTraceEx2(
                control,
                &PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_INFORMATION,
                KEYWORDS,
                0,
                0,
                None,
            )
            .0
        };
        if en != 0 {
            return Err(fail("EnableTraceEx2", en));
        }

        let shared = Arc::new(Shared {
            table: Mutex::new(FlowTable::default()),
            events: AtomicU64::new(0),
            running: AtomicBool::new(true),
        });
        // One strong reference is owned by the trace (as the callback
        // context); the consumer thread releases it when ProcessTrace ends.
        let context = Arc::into_raw(Arc::clone(&shared));

        let mut name_buf = util::wide(SESSION_NAME);
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(name_buf.as_mut_ptr()),
            Context: context as *mut core::ffi::c_void,
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(on_event);
        // SAFETY: `logfile` is fully initialised; `name_buf` outlives the call
        // (OpenTraceW copies the name).
        let trace = unsafe { OpenTraceW(&mut logfile) };
        // INVALID_PROCESSTRACE_HANDLE is (TRACEHANDLE)INVALID_HANDLE_VALUE.
        if trace.Value == u64::MAX || trace.Value == u32::MAX as u64 {
            let code = std::io::Error::last_os_error()
                .raw_os_error()
                .map(|c| c as u32)
                .unwrap_or(0);
            // SAFETY: the trace was never opened, so the callback can never
            // run: take back the reference created by `into_raw` above.
            unsafe { drop(Arc::from_raw(context)) };
            return Err(fail("OpenTrace", code));
        }

        let (done_tx, done_rx) = mpsc::channel::<()>();
        let context_addr = context as usize;
        let spawn = std::thread::Builder::new()
            .name("wf-etw".into())
            .spawn(move || {
                consume(trace, context_addr);
                let _ = done_tx.send(());
            });
        let consumer = match spawn {
            Ok(handle) => handle,
            Err(e) => {
                // SAFETY: the trace handle is valid and not being processed;
                // after closing it the callback can never run, so the context
                // reference can be released.
                unsafe {
                    let _ = CloseTrace(trace);
                    drop(Arc::from_raw(context));
                }
                let _ = stop_by_name();
                return Err(EtwError::Other(format!(
                    "could not start the trace thread: {e}"
                )));
            }
        };

        Ok(EtwSession {
            shared,
            control,
            consumer: Some(consumer),
            done: Mutex::new(done_rx),
        })
    }

    /// Everything counted since the previous call.
    pub fn drain(&self) -> Vec<FlowDelta> {
        util::lock(&self.shared.table).drain()
    }

    /// Tells the session which addresses belong to this PC, so the remote
    /// side of every event is identified reliably.
    pub fn set_local_addrs(&self, addrs: &[IpAddr]) {
        util::lock(&self.shared.table).set_local_addrs(addrs);
    }

    /// False once the trace has ended (for example because another tool
    /// stopped the session); no more data will arrive then.
    pub fn is_running(&self) -> bool {
        self.shared.running.load(Ordering::Relaxed)
    }

    /// Number of data events received so far (diagnostics).
    pub fn events_seen(&self) -> u64 {
        self.shared.events.load(Ordering::Relaxed)
    }
}

/// Body of the consumer thread: blocks in ProcessTrace until the session stops.
fn consume(trace: PROCESSTRACE_HANDLE, context_addr: usize) {
    // SAFETY: `trace` is a valid handle from OpenTraceW owned by this thread;
    // it is closed exactly once, after which no callback can run and the
    // context reference created by `Arc::into_raw` is released.
    unsafe {
        let _ = ProcessTrace(&[trace], None, None);
        let _ = CloseTrace(trace);
        let shared = Arc::from_raw(context_addr as *const Shared);
        shared.running.store(false, Ordering::Relaxed);
        drop(shared);
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        let mut props = Props::new();
        // SAFETY: `control` is the handle of the session this value started;
        // `props` is a correctly sized properties buffer.
        let err = unsafe {
            ControlTraceW(
                self.control,
                PCWSTR::null(),
                props.ptr(),
                EVENT_TRACE_CONTROL_STOP,
            )
            .0
        };
        if err != 0 {
            let _ = stop_by_name();
        }
        // ProcessTrace returns once the stopped session has been drained. Do
        // not hang the caller if Windows takes unusually long: the thread
        // then finishes on its own and frees its resources.
        if util::lock(&self.done)
            .recv_timeout(Duration::from_secs(3))
            .is_ok()
        {
            if let Some(handle) = self.consumer.take() {
                let _ = handle.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("literal")
    }

    /// Builds an IPv4 payload the way the provider lays it out, with a few
    /// trailing fields (sequence number, connection id) as on a real system.
    fn payload_v4(
        pid: u32,
        size: u32,
        daddr: &str,
        saddr: &str,
        dport: u16,
        sport: u16,
    ) -> Vec<u8> {
        let (IpAddr::V4(d), IpAddr::V4(s)) = (ip(daddr), ip(saddr)) else {
            panic!("IPv4 literals expected");
        };
        let mut p = Vec::new();
        p.extend_from_slice(&pid.to_le_bytes());
        p.extend_from_slice(&size.to_le_bytes());
        p.extend_from_slice(&d.octets());
        p.extend_from_slice(&s.octets());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&[0u8; 12]);
        p
    }

    fn payload_v6(
        pid: u32,
        size: u32,
        daddr: &str,
        saddr: &str,
        dport: u16,
        sport: u16,
    ) -> Vec<u8> {
        let (IpAddr::V6(d), IpAddr::V6(s)) = (ip(daddr), ip(saddr)) else {
            panic!("IPv6 literals expected");
        };
        let mut p = Vec::new();
        p.extend_from_slice(&pid.to_le_bytes());
        p.extend_from_slice(&size.to_le_bytes());
        p.extend_from_slice(&d.octets());
        p.extend_from_slice(&s.octets());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&[0u8; 12]);
        p
    }

    #[test]
    fn event_ids() {
        let k = |id| event_kind(id).map(|k| (k.proto, k.sent, k.v6));
        assert_eq!(k(10), Some((Proto::Tcp, true, false)));
        assert_eq!(k(11), Some((Proto::Tcp, false, false)));
        assert_eq!(k(26), Some((Proto::Tcp, true, true)));
        assert_eq!(k(27), Some((Proto::Tcp, false, true)));
        assert_eq!(k(42), Some((Proto::Udp, true, false)));
        assert_eq!(k(43), Some((Proto::Udp, false, false)));
        assert_eq!(k(58), Some((Proto::Udp, true, true)));
        assert_eq!(k(59), Some((Proto::Udp, false, true)));
        // Connect, disconnect, retransmit, accept, copy, failures.
        for id in [
            0, 12, 13, 14, 15, 16, 17, 18, 28, 29, 30, 31, 32, 34, 49, 60, 1000,
        ] {
            assert_eq!(event_kind(id), None, "id {id}");
        }
    }

    #[test]
    fn parses_tcp_v4_send() {
        let p = payload_v4(4242, 1460, "198.51.100.20", "192.0.2.10", 443, 50_001);
        let ev = parse_event(10, &p).expect("parses");
        assert_eq!(
            ev,
            NetEvent {
                pid: 4242,
                proto: Proto::Tcp,
                sent: true,
                size: 1460,
                daddr: ip("198.51.100.20"),
                saddr: ip("192.0.2.10"),
                dport: 443,
                sport: 50_001,
            }
        );
    }

    #[test]
    fn ports_are_network_byte_order() {
        let p = payload_v4(1, 1, "198.51.100.20", "192.0.2.10", 443, 80);
        assert_eq!(&p[16..20], &[0x01, 0xBB, 0x00, 0x50]);
        let ev = parse_event(11, &p).expect("parses");
        assert_eq!((ev.dport, ev.sport), (443, 80));
        assert!(!ev.sent);
    }

    #[test]
    fn parses_v6_and_udp() {
        let p = payload_v6(900, 512, "2001:db8:1::5", "2001:db8::10", 853, 61_000);
        let ev = parse_event(27, &p).expect("parses");
        assert_eq!(ev.proto, Proto::Tcp);
        assert!(!ev.sent);
        assert_eq!(ev.size, 512);
        assert_eq!(ev.daddr, ip("2001:db8:1::5"));
        assert_eq!(ev.saddr, ip("2001:db8::10"));
        assert_eq!((ev.dport, ev.sport), (853, 61_000));

        let ev = parse_event(58, &p).expect("parses");
        assert_eq!(ev.proto, Proto::Udp);
        assert!(ev.sent);

        let p4 = payload_v4(31, 120, "203.0.113.53", "192.0.2.10", 53, 55_555);
        let ev = parse_event(42, &p4).expect("parses");
        assert_eq!(
            (ev.proto, ev.sent, ev.size, ev.pid),
            (Proto::Udp, true, 120, 31)
        );
        let ev = parse_event(43, &p4).expect("parses");
        assert_eq!((ev.proto, ev.sent), (Proto::Udp, false));
    }

    #[test]
    fn minimal_payloads_without_trailing_fields() {
        let p = payload_v4(1, 2, "198.51.100.20", "192.0.2.10", 3, 4);
        assert!(parse_event(10, &p[..20]).is_some());
        let p = payload_v6(1, 2, "2001:db8:1::5", "2001:db8::10", 3, 4);
        assert!(parse_event(26, &p[..44]).is_some());
    }

    #[test]
    fn short_or_foreign_payloads_are_rejected() {
        let p4 = payload_v4(1, 2, "198.51.100.20", "192.0.2.10", 3, 4);
        for len in 0..20 {
            assert_eq!(parse_event(10, &p4[..len]), None, "len {len}");
        }
        let p6 = payload_v6(1, 2, "2001:db8:1::5", "2001:db8::10", 3, 4);
        for len in 0..44 {
            assert_eq!(parse_event(26, &p6[..len]), None, "len {len}");
        }
        // An IPv4-sized payload under an IPv6 event id is too short.
        assert_eq!(parse_event(27, &p4), None);
        // Not a data event.
        assert_eq!(parse_event(12, &p4), None);
        assert_eq!(parse_event(17, &p4), None);
    }

    #[test]
    fn remote_side_is_decided_by_local_addresses() {
        let local = [ip("192.0.2.10")];
        let is_local = |a: &IpAddr| local.contains(a);
        // Local side reported as source (the usual layout).
        let ev = parse_event(
            11,
            &payload_v4(1, 9, "198.51.100.20", "192.0.2.10", 443, 50_001),
        )
        .expect("parses");
        assert_eq!(remote_of(&ev, &is_local), (ip("198.51.100.20"), 443));
        // Local side reported as destination (wire order on receive).
        let ev = parse_event(
            11,
            &payload_v4(1, 9, "192.0.2.10", "198.51.100.20", 50_001, 443),
        )
        .expect("parses");
        assert_eq!(remote_of(&ev, &is_local), (ip("198.51.100.20"), 443));
        // Nothing known about local addresses: the destination is taken.
        let none = |_: &IpAddr| false;
        assert_eq!(remote_of(&ev, &none), (ip("192.0.2.10"), 50_001));
    }

    fn table_with_local() -> FlowTable {
        let mut t = FlowTable::default();
        t.set_local_addrs(&[ip("192.0.2.10"), ip("2001:db8::10")]);
        t
    }

    #[test]
    fn aggregates_by_process_and_endpoint() {
        let mut t = table_with_local();
        let send = payload_v4(100, 1000, "198.51.100.20", "192.0.2.10", 443, 50_001);
        let recv = payload_v4(100, 4000, "198.51.100.20", "192.0.2.10", 443, 50_001);
        for _ in 0..3 {
            t.record(&parse_event(10, &send).expect("parses"));
        }
        for _ in 0..2 {
            t.record(&parse_event(11, &recv).expect("parses"));
        }
        // Another local port to the same endpoint merges into the same flow.
        let other_port = payload_v4(100, 10, "198.51.100.20", "192.0.2.10", 443, 50_002);
        t.record(&parse_event(10, &other_port).expect("parses"));
        // Another process, UDP.
        let dns = payload_v4(200, 60, "203.0.113.53", "192.0.2.10", 53, 40_000);
        t.record(&parse_event(42, &dns).expect("parses"));
        assert_eq!(t.len(), 2);

        let mut flows = t.drain();
        flows.sort_by_key(|f| f.pid);
        assert_eq!(
            flows,
            vec![
                FlowDelta {
                    pid: 100,
                    proto: Proto::Tcp,
                    remote: Some(ip("198.51.100.20")),
                    remote_port: 443,
                    rx: 8000,
                    tx: 3010,
                },
                FlowDelta {
                    pid: 200,
                    proto: Proto::Udp,
                    remote: Some(ip("203.0.113.53")),
                    remote_port: 53,
                    rx: 0,
                    tx: 60,
                },
            ]
        );
        // Drain empties.
        assert!(t.is_empty());
        assert!(t.drain().is_empty());
    }

    #[test]
    fn local_only_traffic_is_not_counted() {
        let mut t = table_with_local();
        let cases = [
            payload_v4(1, 500, "127.0.0.1", "127.0.0.1", 8080, 50_000),
            payload_v4(1, 500, "127.0.0.1", "192.0.2.10", 8080, 50_000),
            payload_v4(1, 500, "192.0.2.10", "192.0.2.10", 8080, 50_000),
            payload_v4(1, 0, "198.51.100.20", "192.0.2.10", 443, 50_000),
        ];
        for p in &cases {
            t.record(&parse_event(10, p).expect("parses"));
        }
        let v6 = payload_v6(1, 500, "::1", "::1", 8080, 50_000);
        t.record(&parse_event(26, &v6).expect("parses"));
        let v6 = payload_v6(1, 500, "2001:db8::10", "2001:db8::10", 8080, 50_000);
        t.record(&parse_event(26, &v6).expect("parses"));
        assert!(t.is_empty());
    }

    #[test]
    fn mapped_addresses_are_reported_as_ipv4() {
        let mut t = table_with_local();
        let p = payload_v6(
            7,
            100,
            "::ffff:198.51.100.20",
            "::ffff:192.0.2.10",
            443,
            50_000,
        );
        t.record(&parse_event(26, &p).expect("parses"));
        let flows = t.drain();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].remote, Some(ip("198.51.100.20")));
    }

    #[test]
    fn flow_count_is_bounded_and_bytes_are_kept() {
        let mut t = table_with_local();
        let mut expected: u64 = 0;
        // One process talking to far more endpoints than the cap.
        for i in 0..(MAX_FLOWS as u32 + 5000) {
            let d = Ipv4Addr::from(0xC633_6400u32.wrapping_add(i % 250)); // 198.51.100.x
            let ev = NetEvent {
                pid: 55,
                proto: Proto::Udp,
                sent: true,
                size: 10,
                daddr: IpAddr::V4(d),
                saddr: ip("192.0.2.10"),
                dport: (i / 250) as u16 + 1,
                sport: 40_000,
            };
            t.record(&ev);
            expected += 10;
        }
        assert!(t.len() <= MAX_FLOWS + 1, "len {}", t.len());
        let flows = t.drain();
        let total: u64 = flows.iter().map(|f| f.tx).sum();
        assert_eq!(total, expected);
        let overflow: Vec<_> = flows.iter().filter(|f| f.remote.is_none()).collect();
        assert_eq!(overflow.len(), 1);
        assert_eq!(overflow[0].pid, 55);
        assert_eq!(overflow[0].tx, 50_000);
    }

    #[test]
    fn pathological_process_counts_are_bounded_too() {
        let mut t = table_with_local();
        let mut expected: u64 = 0;
        for pid in 0..(MAX_FLOWS as u32 * 3) {
            let ev = NetEvent {
                pid: pid + 8,
                proto: Proto::Tcp,
                sent: false,
                size: 1,
                daddr: ip("198.51.100.20"),
                saddr: ip("192.0.2.10"),
                dport: 443,
                sport: 40_000,
            };
            t.record(&ev);
            expected += 1;
        }
        assert!(t.len() <= MAX_FLOWS * 2 + 1, "len {}", t.len());
        let total: u64 = t.drain().iter().map(|f| f.rx).sum();
        assert_eq!(total, expected);
    }

    #[test]
    fn session_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EtwSession>();
    }

    #[test]
    fn error_messages_are_sentences() {
        assert!(EtwError::NeedsAdmin.to_string().contains("administrator"));
        assert!(EtwError::Other("x".into()).to_string().contains('x'));
    }

    #[test]
    fn start_gives_a_session_or_a_clean_error() {
        // Elevated: the session starts, drains and stops. Not elevated: the
        // documented error, and nothing is left running either way.
        match EtwSession::start() {
            Ok(session) => {
                session.set_local_addrs(&[ip("192.0.2.10")]);
                let _ = session.drain();
                let _ = session.events_seen();
                drop(session);
            }
            Err(e) => assert_eq!(e, EtwError::NeedsAdmin),
        }
        // Whatever happened, no session of our name may be left: stopping it
        // must report "not found" (4201) or, unelevated, access denied (5).
        let code = stop_by_name();
        assert!(code == 4201 || code == 5, "unexpected stop result {code}");
    }
}
