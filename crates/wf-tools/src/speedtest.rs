//! Internet speed test against Measurement Lab's NDT7 service.
//!
//! The protocol (<https://github.com/m-lab/ndt-server/blob/main/spec/ndt7-protocol.md>)
//! is implemented here: the Locate API names a nearby server, then one
//! WebSocket-over-TLS connection measures the download for about ten seconds
//! and a second one the upload.

use crate::http::{self, HttpError, WebSocket, WsKind};
use crate::types::*;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The name stored in `SpeedResult::provider`.
pub const PROVIDER_NAME: &str = "M-Lab NDT7";

/// M-Lab asks that a person runs no more than this many tests a day.
pub const DAILY_LIMIT: usize = 40;

/// How many results `save_history` keeps.
pub const HISTORY_LIMIT: usize = 500;

const LOCATE_URL: &str = "https://locate.measurementlab.net/v2/nearest/ndt/ndt7";
const SUBPROTOCOL: &str = "net.measurementlab.ndt.v7";
const CLIENT_NAME: &str = "wireforge";
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Each direction is measured for this long.
const TEST_SECONDS: f64 = 10.0;
/// The protocol's hard limit for one direction.
const HARD_LIMIT: Duration = Duration::from_secs(14);
const LATENCY_SAMPLES: usize = 6;
const INITIAL_MESSAGE: usize = 1 << 13;
const MAX_MESSAGE: usize = 1 << 22;
const CANCELLED: &str = "Cancelled";

/// Which service is used and what the user must be told first.
pub fn provider() -> ProviderInfo {
    ProviderInfo {
        name: PROVIDER_NAME,
        operator: "Measurement Lab (M-Lab)",
        homepage: "https://www.measurementlab.net/",
        terms_url: "https://www.measurementlab.net/aup/",
        privacy_url: "https://www.measurementlab.net/privacy/",
        notice: "The speed test is run by Measurement Lab (M-Lab), an open research project, \
                 not by WireForge. To measure your connection, M-Lab's servers see your public \
                 IP address. M-Lab keeps the results of every test, including your IP address, \
                 the date and time and the measured speeds, and publishes them as open data \
                 for internet research. Published results are kept indefinitely. WireForge \
                 sends nothing else about you or this PC. Only run the test if you agree to \
                 M-Lab's privacy policy. M-Lab asks for no more than 40 tests a day.",
        data_note: "One run downloads for about 10 seconds and uploads for about 10 seconds at \
                    the full speed of your connection: roughly 250 MB in total on a 100 Mbit/s \
                    line, more on faster lines. Avoid it on a metered connection.",
    }
}

/// One server offered by the Locate API.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Target {
    /// "City, CC" as the service reports it.
    pub label: String,
    pub host: String,
    pub download_url: String,
    pub upload_url: String,
}

/// Adds `client_name` / `client_version` to a URL unless they are already
/// there (the protocol forbids duplicate keys). Nothing is removed.
pub(crate) fn with_client_params(url: &str) -> String {
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    let has = |key: &str| {
        query
            .split('&')
            .any(|pair| pair.split('=').next() == Some(key))
    };
    let mut out = url.to_string();
    for (key, value) in [
        ("client_name", CLIENT_NAME),
        ("client_version", CLIENT_VERSION),
    ] {
        if !has(key) {
            out.push(if out.contains('?') { '&' } else { '?' });
            out.push_str(&format!("{key}={value}"));
        }
    }
    out
}

/// Reads the Locate API v2 answer (pure, unit-tested).
pub(crate) fn parse_locate(json: &str) -> Result<Vec<Target>, String> {
    let bad = || "The speed-test service sent an answer that could not be read.".to_string();
    let value: serde_json::Value = serde_json::from_str(json).map_err(|_| bad())?;
    let results = value
        .get("results")
        .and_then(|r| r.as_array())
        .ok_or_else(bad)?;
    let mut targets = Vec::new();
    for result in results {
        let Some(urls) = result.get("urls").and_then(|u| u.as_object()) else {
            continue;
        };
        let find = |suffix: &str| {
            urls.iter()
                .find(|(key, _)| key.starts_with("wss://") && key.ends_with(suffix))
                .and_then(|(_, url)| url.as_str())
        };
        let (Some(download), Some(upload)) = (find("/ndt/v7/download"), find("/ndt/v7/upload"))
        else {
            continue;
        };
        // Only complete, well-formed wss:// URLs are used.
        let (Ok(parsed), Ok(_)) = (http::parse_url(download), http::parse_url(upload)) else {
            continue;
        };
        if !parsed.websocket {
            continue;
        }
        let text = |outer: &str, inner: &str| {
            result
                .get(outer)
                .and_then(|o| o.get(inner))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .unwrap_or("")
                .to_string()
        };
        let (city, country) = (text("location", "city"), text("location", "country"));
        let label = match (city.is_empty(), country.is_empty()) {
            (false, false) => format!("{city}, {country}"),
            (false, true) => city,
            (true, false) => country,
            (true, true) => "M-Lab server".to_string(),
        };
        targets.push(Target {
            label,
            host: parsed.host,
            download_url: with_client_params(download),
            upload_url: with_client_params(upload),
        });
    }
    if targets.is_empty() {
        return Err("The speed-test service has no server available right now.".into());
    }
    Ok(targets)
}

/// The parts of a server measurement message that are used.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Measurement {
    /// TCPInfo.MinRTT, microseconds.
    pub min_rtt_us: Option<i64>,
    /// TCPInfo.RTTVar, microseconds.
    pub rtt_var_us: Option<i64>,
    /// TCPInfo.BytesReceived: what the server has received (upload).
    pub bytes_received: Option<i64>,
    /// TCPInfo.ElapsedTime, microseconds.
    pub elapsed_us: Option<i64>,
}

/// Reads a measurement message (pure, unit-tested). Missing and extra fields
/// are fine; anything that is not a JSON object gives `None`.
pub(crate) fn parse_measurement(text: &str) -> Option<Measurement> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    value.as_object()?;
    let field = |name: &str| {
        value
            .get("TCPInfo")
            .and_then(|t| t.get(name))
            .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
            .filter(|n| *n >= 0)
    };
    Some(Measurement {
        min_rtt_us: field("MinRTT"),
        rtt_var_us: field("RTTVar"),
        bytes_received: field("BytesReceived"),
        elapsed_us: field("ElapsedTime"),
    })
}

impl Measurement {
    /// The upload rate the server saw, in Mbit/s.
    fn server_mbps(&self) -> Option<f64> {
        let (bytes, elapsed) = (self.bytes_received?, self.elapsed_us?);
        (bytes > 0 && elapsed > 0).then(|| mbps(bytes as u64, elapsed as f64 / 1e6))
    }
}

/// Megabits per second for `bytes` moved in `seconds` (pure, unit-tested).
pub fn mbps(bytes: u64, seconds: f64) -> f64 {
    if seconds > 0.0 && seconds.is_finite() {
        bytes as f64 * 8.0 / 1_000_000.0 / seconds
    } else {
        0.0
    }
}

/// The size of the next upload message: it doubles while it is smaller than
/// a sixteenth of what has been sent, as the protocol suggests.
pub(crate) fn next_message_size(current: usize, total_sent: u64) -> usize {
    if current < MAX_MESSAGE && (current as u64) < total_sent / 16 {
        (current * 2).min(MAX_MESSAGE)
    } else {
        current.clamp(INITIAL_MESSAGE, MAX_MESSAGE)
    }
}

/// How far through a phase `elapsed` of `total` seconds is, 0.0 ..= 1.0.
pub(crate) fn phase_fraction(elapsed: f64, total: f64) -> f32 {
    if total > 0.0 && elapsed.is_finite() {
        (elapsed / total).clamp(0.0, 1.0) as f32
    } else {
        0.0
    }
}

/// Mean absolute difference of consecutive samples.
pub(crate) fn jitter(samples: &[f64]) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }
    let sum: f64 = samples
        .windows(2)
        .map(|w| match w {
            [a, b] => (b - a).abs(),
            _ => 0.0,
        })
        .sum();
    sum / (samples.len() - 1) as f64
}

/// Latency and jitter from the connect samples, falling back to what the
/// server's TCP stack measured.
pub(crate) fn latency_of(samples: &[f64], server: Option<Measurement>) -> (f64, f64) {
    let server_latency = server
        .and_then(|m| m.min_rtt_us)
        .map(|us| us as f64 / 1000.0);
    let server_jitter = server
        .and_then(|m| m.rtt_var_us)
        .map(|us| us as f64 / 1000.0);
    let latency = samples
        .iter()
        .copied()
        .fold(None, |best: Option<f64>, s| {
            Some(best.map_or(s, |b| b.min(s)))
        })
        .or(server_latency)
        .unwrap_or(0.0);
    let jitter = if samples.len() >= 2 {
        jitter(samples)
    } else {
        server_jitter.unwrap_or(0.0)
    };
    (latency, jitter)
}

/// How many tests in `history` were run in the 24 hours before `now_unix`.
pub fn runs_last_day(history: &[SpeedResult], now_unix: i64) -> usize {
    history
        .iter()
        .filter(|r| r.when_unix <= now_unix && now_unix - r.when_unix < 86_400)
        .count()
}

/// `Err` with a sentence for the user when the daily limit has been reached.
pub fn check_daily_limit(history: &[SpeedResult], now_unix: i64) -> Result<(), String> {
    if runs_last_day(history, now_unix) >= DAILY_LIMIT {
        Err(format!(
            "M-Lab asks for no more than {DAILY_LIMIT} tests a day. Try again tomorrow."
        ))
    } else {
        Ok(())
    }
}

fn is_cancelled(cancel: &AtomicBool) -> bool {
    cancel.load(Ordering::Relaxed)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn locate(cancel: &AtomicBool) -> Result<Vec<Target>, String> {
    let url = with_client_params(LOCATE_URL);
    let response = http::get(
        &url,
        http::Options {
            max_body: 256 * 1024,
            cancel: Some(cancel),
            ..Default::default()
        },
    )
    .map_err(|e| match e {
        HttpError::Cancelled => CANCELLED.to_string(),
        other => other.to_string(),
    })?;
    match response.status {
        200 => parse_locate(&response.text()),
        204 | 429 => Err(
            "The speed-test service is limiting how often tests may run from this connection. \
             Try again later."
                .into(),
        ),
        status => Err(format!(
            "The speed-test service is not available right now (HTTP {status})."
        )),
    }
}

/// Times a few TCP connections to the server: each takes one round trip.
fn connect_samples(
    target: &Target,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(&SpeedProgress),
) -> Vec<f64> {
    let mut samples = Vec::new();
    let Some(addr) = (target.host.as_str(), 443)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
    else {
        return samples;
    };
    for i in 0..LATENCY_SAMPLES {
        if is_cancelled(cancel) {
            break;
        }
        let started = Instant::now();
        if TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok() {
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        let best = samples.iter().copied().fold(f64::INFINITY, f64::min);
        on_progress(&SpeedProgress {
            phase: SpeedPhase::Latency,
            fraction: phase_fraction((i + 1) as f64, LATENCY_SAMPLES as f64),
            current: if best.is_finite() { best } else { 0.0 },
            server: target.label.clone(),
        });
        std::thread::sleep(Duration::from_millis(40));
    }
    samples
}

/// What one direction measured.
#[derive(Clone, Copy, Debug, Default)]
struct Flow {
    bytes: u64,
    seconds: f64,
    last: Option<Measurement>,
}

enum FlowError {
    /// The server could not be reached at all: another one may work.
    Connect(String),
    Failed(String),
}

/// Ends `socket` when `cancel` is set or the hard time limit passes, so a
/// blocked send or receive always returns.
fn watchdog(socket: &WebSocket, cancel: &AtomicBool, done: &AtomicBool, started: Instant) {
    while !done.load(Ordering::Relaxed) {
        if is_cancelled(cancel) || started.elapsed() > HARD_LIMIT {
            socket.abort();
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn open_socket(url: &str) -> Result<WebSocket, FlowError> {
    WebSocket::connect(url, SUBPROTOCOL, 10_000).map_err(|e| FlowError::Connect(e.to_string()))
}

fn download(
    target: &Target,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(&SpeedProgress),
) -> Result<Flow, FlowError> {
    let socket = open_socket(&target.download_url)?;
    let started = Instant::now();
    let done = AtomicBool::new(false);
    let mut flow = Flow::default();
    std::thread::scope(|scope| {
        scope.spawn(|| watchdog(&socket, cancel, &done, started));
        let mut buf = vec![0u8; 1 << 20];
        let mut text = Vec::new();
        let mut last_report = Instant::now();
        // The server may drop the connection at the end of the test; what
        // was measured until then still counts.
        while let Ok(frame) = socket.receive(&mut buf) {
            let elapsed = started.elapsed().as_secs_f64();
            match frame.kind {
                WsKind::Close => break,
                WsKind::Binary => {}
                WsKind::Text => {
                    if text.len() + frame.len <= 64 * 1024 {
                        text.extend_from_slice(buf.get(..frame.len).unwrap_or(&[]));
                    }
                    if frame.end_of_message {
                        if let Some(m) = std::str::from_utf8(&text).ok().and_then(parse_measurement)
                        {
                            flow.last = Some(m);
                        }
                        text.clear();
                    }
                }
            }
            flow.bytes += frame.len as u64;
            flow.seconds = elapsed;
            if last_report.elapsed() >= Duration::from_millis(100) {
                last_report = Instant::now();
                on_progress(&SpeedProgress {
                    phase: SpeedPhase::Download,
                    fraction: phase_fraction(elapsed, TEST_SECONDS),
                    current: mbps(flow.bytes, elapsed),
                    server: target.label.clone(),
                });
            }
            if elapsed > TEST_SECONDS + 3.0 {
                break;
            }
        }
        socket.shutdown();
        done.store(true, Ordering::Relaxed);
    });
    socket.abort();
    if is_cancelled(cancel) {
        return Err(FlowError::Failed(CANCELLED.into()));
    }
    if flow.bytes == 0 || flow.seconds < 0.2 {
        return Err(FlowError::Failed(
            "The download test ended before any data arrived.".into(),
        ));
    }
    Ok(flow)
}

/// Fills a buffer with bytes that do not compress.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ (now_unix() as u64).rotate_left(17);
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn upload(
    target: &Target,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(&SpeedProgress),
) -> Result<Flow, FlowError> {
    let socket = open_socket(&target.upload_url)?;
    let started = Instant::now();
    let done = AtomicBool::new(false);
    let reader_done = AtomicBool::new(false);
    let latest: Mutex<Option<Measurement>> = Mutex::new(None);
    let read_latest = || latest.lock().ok().and_then(|guard| *guard);
    let data = noise(MAX_MESSAGE);
    let mut flow = Flow::default();
    std::thread::scope(|scope| {
        scope.spawn(|| watchdog(&socket, cancel, &done, started));
        // The server reports what it received in text messages while the
        // upload runs: they are read on a second thread.
        scope.spawn(|| {
            let mut buf = vec![0u8; 64 * 1024];
            let mut text = Vec::new();
            while let Ok(frame) = socket.receive(&mut buf) {
                match frame.kind {
                    WsKind::Close => break,
                    WsKind::Binary => {}
                    WsKind::Text => {
                        if text.len() + frame.len <= 64 * 1024 {
                            text.extend_from_slice(buf.get(..frame.len).unwrap_or(&[]));
                        }
                        if frame.end_of_message {
                            let parsed =
                                std::str::from_utf8(&text).ok().and_then(parse_measurement);
                            if let (Some(m), Ok(mut guard)) = (parsed, latest.lock()) {
                                *guard = Some(m);
                            }
                            text.clear();
                        }
                    }
                }
            }
            reader_done.store(true, Ordering::Relaxed);
        });

        let mut size = INITIAL_MESSAGE;
        let mut last_report = Instant::now();
        loop {
            let elapsed = started.elapsed().as_secs_f64();
            if elapsed >= TEST_SECONDS || is_cancelled(cancel) {
                break;
            }
            let Some(message) = data.get(..size) else {
                break;
            };
            if socket.send_binary(message).is_err() {
                break;
            }
            flow.bytes += size as u64;
            flow.seconds = started.elapsed().as_secs_f64();
            size = next_message_size(size, flow.bytes);
            if last_report.elapsed() >= Duration::from_millis(100) {
                last_report = Instant::now();
                let current = read_latest()
                    .and_then(|m| m.server_mbps())
                    .unwrap_or_else(|| mbps(flow.bytes, flow.seconds));
                on_progress(&SpeedProgress {
                    phase: SpeedPhase::Upload,
                    fraction: phase_fraction(flow.seconds, TEST_SECONDS),
                    current,
                    server: target.label.clone(),
                });
            }
        }
        // Say goodbye, then give the server a moment to send its last
        // measurement and its own close.
        socket.shutdown();
        let waited = Instant::now();
        while !reader_done.load(Ordering::Relaxed)
            && waited.elapsed() < Duration::from_millis(2500)
            && !is_cancelled(cancel)
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        done.store(true, Ordering::Relaxed);
        // Ends the reader if it is still waiting.
        socket.abort();
    });
    if is_cancelled(cancel) {
        return Err(FlowError::Failed(CANCELLED.into()));
    }
    flow.last = read_latest();
    if flow.bytes == 0 || flow.seconds < 0.2 {
        return Err(FlowError::Failed(
            "The upload test ended before any data was sent.".into(),
        ));
    }
    Ok(flow)
}

/// Runs latency, download and upload. Only ever called on a click.
pub fn run(
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(&SpeedProgress),
) -> Result<SpeedResult, String> {
    on_progress(&SpeedProgress {
        phase: SpeedPhase::Locating,
        ..Default::default()
    });
    let targets = locate(cancel)?;
    let mut last_error = "The speed-test server could not be reached.".to_string();
    // The service may turn a client away from one server: try the next one,
    // but never more than two.
    for target in targets.iter().take(2) {
        if is_cancelled(cancel) {
            return Err(CANCELLED.into());
        }
        on_progress(&SpeedProgress {
            phase: SpeedPhase::Latency,
            server: target.label.clone(),
            ..Default::default()
        });
        let samples = connect_samples(target, cancel, on_progress);
        if is_cancelled(cancel) {
            return Err(CANCELLED.into());
        }
        let down = match download(target, cancel, on_progress) {
            Ok(flow) => flow,
            Err(FlowError::Connect(e)) => {
                last_error = e;
                continue;
            }
            Err(FlowError::Failed(e)) => return Err(e),
        };
        let download_mbps = mbps(down.bytes, down.seconds);
        on_progress(&SpeedProgress {
            phase: SpeedPhase::Download,
            fraction: 1.0,
            current: download_mbps,
            server: target.label.clone(),
        });
        let up = match upload(target, cancel, on_progress) {
            Ok(flow) => flow,
            Err(FlowError::Connect(e)) | Err(FlowError::Failed(e)) => return Err(e),
        };
        // The server's count of what arrived is the honest upload figure;
        // what was handed to the local network stack is the fallback.
        let upload_mbps = up
            .last
            .and_then(|m| m.server_mbps())
            .unwrap_or_else(|| mbps(up.bytes, up.seconds));
        let (latency_ms, jitter_ms) = latency_of(&samples, down.last);
        on_progress(&SpeedProgress {
            phase: SpeedPhase::Done,
            fraction: 1.0,
            current: download_mbps,
            server: target.label.clone(),
        });
        return Ok(SpeedResult {
            when_unix: now_unix(),
            provider: PROVIDER_NAME.to_string(),
            server: target.label.clone(),
            download_mbps,
            upload_mbps,
            latency_ms,
            jitter_ms,
            bytes_down: down.bytes,
            bytes_up: up.bytes,
            adapter: String::new(),
        });
    }
    Err(last_error)
}

/// Past results, oldest first (a missing or damaged file gives none).
pub fn load_history(path: &Path) -> Vec<SpeedResult> {
    let Ok(meta) = std::fs::metadata(path) else {
        return Vec::new();
    };
    // 500 results are well under a megabyte; anything huge is not ours.
    if meta.len() > 8 * 1024 * 1024 {
        return Vec::new();
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut history: Vec<SpeedResult> = serde_json::from_str(&text).unwrap_or_default();
    history.sort_by_key(|r| r.when_unix);
    history
}

/// Keeps the newest 500.
pub fn save_history(path: &Path, history: &[SpeedResult]) -> Result<(), String> {
    let mut sorted: Vec<&SpeedResult> = history.iter().collect();
    sorted.sort_by_key(|r| r.when_unix);
    let skip = sorted.len().saturating_sub(HISTORY_LIMIT);
    let newest = sorted.get(skip..).unwrap_or(&[]);
    let json = serde_json::to_string_pretty(newest)
        .map_err(|e| format!("Could not save the speed-test history ({e})."))?;
    let io = |e: std::io::Error| format!("Could not save the speed-test history ({e}).");
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    // Written beside the file and renamed over it, so a crash part-way
    // leaves the old history intact.
    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    let temp = std::path::PathBuf::from(temp);
    std::fs::write(&temp, json).map_err(io)?;
    std::fs::rename(&temp, path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        io(e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCATE: &str = r#"{
      "results": [
        {
          "machine": "mlab1-xyz01.example.org",
          "location": {"city": "Springfield", "country": "ZZ"},
          "urls": {
            "ws:///ndt/v7/download": "ws://ndt-mlab1-xyz01.example.org/ndt/v7/download?access_token=aaa",
            "ws:///ndt/v7/upload": "ws://ndt-mlab1-xyz01.example.org/ndt/v7/upload?access_token=bbb",
            "wss:///ndt/v7/download": "wss://ndt-mlab1-xyz01.example.org/ndt/v7/download?access_token=ccc&index=0",
            "wss:///ndt/v7/upload": "wss://ndt-mlab1-xyz01.example.org/ndt/v7/upload?access_token=ddd&index=0"
          }
        },
        {
          "machine": "mlab2-xyz02.example.org",
          "location": {"city": "Shelbyville"},
          "urls": {
            "wss:///ndt/v7/download": "wss://ndt-mlab2-xyz02.example.org/ndt/v7/download?access_token=eee&client_name=wireforge",
            "wss:///ndt/v7/upload": "wss://ndt-mlab2-xyz02.example.org/ndt/v7/upload?access_token=fff&client_name=wireforge"
          }
        },
        {"machine": "broken", "urls": {"wss:///ndt/v7/download": "wss://only-download.example.org/x"}},
        {"machine": "plain", "urls": {
            "wss:///ndt/v7/download": "http://plain.example.org/ndt/v7/download",
            "wss:///ndt/v7/upload": "http://plain.example.org/ndt/v7/upload"}}
      ]
    }"#;

    #[test]
    fn locate_parsing() {
        let targets = parse_locate(LOCATE).unwrap();
        assert_eq!(targets.len(), 2);
        let first = &targets[0];
        assert_eq!(first.label, "Springfield, ZZ");
        assert_eq!(first.host, "ndt-mlab1-xyz01.example.org");
        // The secure URL is chosen and its token is kept exactly.
        assert!(first.download_url.starts_with(
            "wss://ndt-mlab1-xyz01.example.org/ndt/v7/download?access_token=ccc&index=0&"
        ));
        assert!(first.download_url.contains("client_name=wireforge"));
        assert!(first.download_url.contains("client_version="));
        assert!(first.upload_url.contains("access_token=ddd"));
        assert_eq!(targets[1].label, "Shelbyville");
    }

    #[test]
    fn locate_rejects_unusable_answers() {
        for bad in [
            "",
            "not json",
            "[]",
            "{}",
            r#"{"results": []}"#,
            r#"{"results": "x"}"#,
            r#"{"results": [{"machine": "m"}]}"#,
            r#"{"results": [{"urls": {"wss:///ndt/v7/download": 5, "wss:///ndt/v7/upload": 6}}]}"#,
            r#"{"error": {"status": 429}}"#,
        ] {
            assert!(parse_locate(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn client_params_are_added_once() {
        let version = CLIENT_VERSION;
        assert_eq!(
            with_client_params("https://example.org/a"),
            format!("https://example.org/a?client_name=wireforge&client_version={version}")
        );
        assert_eq!(
            with_client_params("wss://example.org/a?access_token=t"),
            format!(
                "wss://example.org/a?access_token=t&client_name=wireforge&client_version={version}"
            )
        );
        let done = "wss://example.org/a?client_name=other&client_version=9";
        assert_eq!(with_client_params(done), done);
        // A key that merely ends the same way does not count.
        assert!(with_client_params("wss://example.org/a?my_client_name=x")
            .contains("&client_name=wireforge"));
    }

    #[test]
    fn measurement_parsing() {
        let text = r#"{
          "AppInfo": {"ElapsedTime": 1234567, "NumBytes": 999},
          "ConnectionInfo": {"Client": "192.0.2.1:5000", "Server": "198.51.100.1:443", "UUID": "u"},
          "Origin": "server", "Test": "download",
          "TCPInfo": {"BusyTime": 1, "BytesAcked": 2, "BytesReceived": 2500000, "BytesSent": 4,
                      "ElapsedTime": 2000000, "MinRTT": 12345, "RTT": 15000, "RTTVar": 2500,
                      "SomethingNew": "ignored"}
        }"#;
        let m = parse_measurement(text).unwrap();
        assert_eq!(m.min_rtt_us, Some(12345));
        assert_eq!(m.rtt_var_us, Some(2500));
        assert_eq!(m.bytes_received, Some(2_500_000));
        assert_eq!(m.elapsed_us, Some(2_000_000));
        // 2.5 MB in 2 s = 10 Mbit/s.
        assert_eq!(m.server_mbps(), Some(10.0));
    }

    #[test]
    fn measurement_with_missing_or_odd_fields() {
        assert_eq!(parse_measurement("{}"), Some(Measurement::default()));
        let m = parse_measurement(
            r#"{"TCPInfo": {"MinRTT": 900.0, "RTTVar": -5, "BytesReceived": "x"}}"#,
        )
        .unwrap();
        assert_eq!(m.min_rtt_us, Some(900));
        assert_eq!(m.rtt_var_us, None);
        assert_eq!(m.bytes_received, None);
        assert_eq!(m.server_mbps(), None);
        let zero =
            parse_measurement(r#"{"TCPInfo": {"BytesReceived": 10, "ElapsedTime": 0}}"#).unwrap();
        assert_eq!(zero.server_mbps(), None);
        for bad in ["", "nope", "[1,2]", "42", "\"text\"", "{\"TCPInfo\":"] {
            assert_eq!(parse_measurement(bad), None, "{bad}");
        }
    }

    #[test]
    fn rate_maths() {
        assert_eq!(mbps(1_250_000, 1.0), 10.0);
        assert_eq!(mbps(125_000_000, 10.0), 100.0);
        assert_eq!(mbps(0, 5.0), 0.0);
        assert_eq!(mbps(1000, 0.0), 0.0);
        assert_eq!(mbps(1000, -1.0), 0.0);
        assert_eq!(mbps(1000, f64::NAN), 0.0);
    }

    #[test]
    fn message_scaling() {
        assert_eq!(next_message_size(8192, 0), 8192);
        assert_eq!(next_message_size(8192, 8192 * 16), 8192);
        assert_eq!(next_message_size(8192, 8192 * 16 + 16), 16384);
        assert_eq!(next_message_size(MAX_MESSAGE, u64::MAX), MAX_MESSAGE);
        assert_eq!(next_message_size(MAX_MESSAGE / 2, u64::MAX), MAX_MESSAGE);
        assert_eq!(next_message_size(1, 0), INITIAL_MESSAGE);
        // Following the rule from the start never exceeds the cap and grows.
        let (mut size, mut total) = (INITIAL_MESSAGE, 0u64);
        for _ in 0..10_000 {
            total += size as u64;
            let next = next_message_size(size, total);
            assert!(next >= size && next <= MAX_MESSAGE);
            assert!(next.is_power_of_two());
            size = next;
        }
        assert_eq!(size, MAX_MESSAGE);
    }

    #[test]
    fn phase_progress() {
        assert_eq!(phase_fraction(0.0, 10.0), 0.0);
        assert_eq!(phase_fraction(2.5, 10.0), 0.25);
        assert_eq!(phase_fraction(10.0, 10.0), 1.0);
        assert_eq!(phase_fraction(13.0, 10.0), 1.0);
        assert_eq!(phase_fraction(-1.0, 10.0), 0.0);
        assert_eq!(phase_fraction(1.0, 0.0), 0.0);
        assert_eq!(phase_fraction(f64::NAN, 10.0), 0.0);
    }

    #[test]
    fn latency_and_jitter() {
        assert_eq!(jitter(&[]), 0.0);
        assert_eq!(jitter(&[5.0]), 0.0);
        assert_eq!(jitter(&[10.0, 14.0, 12.0]), 3.0);
        let server = Measurement {
            min_rtt_us: Some(8000),
            rtt_var_us: Some(1500),
            ..Default::default()
        };
        // Own samples win.
        assert_eq!(latency_of(&[12.0, 10.0, 13.0], Some(server)), (10.0, 2.5));
        // No samples: the server's figures.
        assert_eq!(latency_of(&[], Some(server)), (8.0, 1.5));
        // One sample: its time, the server's variation.
        assert_eq!(latency_of(&[9.0], Some(server)), (9.0, 1.5));
        assert_eq!(latency_of(&[], None), (0.0, 0.0));
    }

    fn result(when: i64, down: f64) -> SpeedResult {
        SpeedResult {
            when_unix: when,
            provider: PROVIDER_NAME.into(),
            server: "Springfield, ZZ".into(),
            download_mbps: down,
            upload_mbps: 20.0,
            latency_ms: 9.5,
            jitter_ms: 1.25,
            bytes_down: 1000,
            bytes_up: 500,
            adapter: "Wi-Fi".into(),
        }
    }

    fn temp_file(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("wf-tools-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn history_round_trip() {
        let path = temp_file("history.json");
        let history = vec![result(300, 3.0), result(100, 1.0), result(200, 2.0)];
        save_history(&path, &history).unwrap();
        let loaded = load_history(&path);
        assert_eq!(
            loaded.iter().map(|r| r.when_unix).collect::<Vec<_>>(),
            vec![100, 200, 300]
        );
        assert_eq!(loaded[0], result(100, 1.0));
        // Saving again replaces the file.
        save_history(&path, &loaded[..1]).unwrap();
        assert_eq!(load_history(&path).len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn history_keeps_the_newest_500() {
        let path = temp_file("history-many.json");
        let history: Vec<SpeedResult> = (0..620).map(|i| result(i, i as f64)).collect();
        save_history(&path, &history).unwrap();
        let loaded = load_history(&path);
        assert_eq!(loaded.len(), HISTORY_LIMIT);
        assert_eq!(loaded.first().map(|r| r.when_unix), Some(120));
        assert_eq!(loaded.last().map(|r| r.when_unix), Some(619));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn history_missing_or_damaged() {
        assert!(load_history(&temp_file("no-such-file.json")).is_empty());
        let path = temp_file("history-bad.json");
        std::fs::write(&path, "{ not json").unwrap();
        assert!(load_history(&path).is_empty());
        // Unknown and missing fields are tolerated.
        std::fs::write(
            &path,
            r#"[{"when_unix": 5, "download_mbps": 7.5, "extra": true}]"#,
        )
        .unwrap();
        let loaded = load_history(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].download_mbps, 7.5);
        assert_eq!(loaded[0].provider, "");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn daily_limit() {
        let now = 1_000_000;
        let mut history: Vec<SpeedResult> = (0..39).map(|i| result(now - i * 60, 1.0)).collect();
        // Older than a day and in the future: not counted.
        history.push(result(now - 86_400, 1.0));
        history.push(result(now + 500, 1.0));
        assert_eq!(runs_last_day(&history, now), 39);
        assert!(check_daily_limit(&history, now).is_ok());
        history.push(result(now - 5, 1.0));
        assert!(check_daily_limit(&history, now).is_err());
    }

    #[test]
    fn provider_tells_the_truth() {
        let p = provider();
        assert_eq!(p.name, PROVIDER_NAME);
        for url in [p.homepage, p.terms_url, p.privacy_url] {
            assert!(url.starts_with("https://www.measurementlab.net/"), "{url}");
        }
        assert!(p.notice.contains("IP address"));
        assert!(p.notice.contains("publishes"));
        assert!(!p.data_note.is_empty());
    }

    #[test]
    fn noise_is_not_constant() {
        let n = noise(4096);
        assert_eq!(n.len(), 4096);
        let distinct: std::collections::HashSet<u8> = n.iter().copied().collect();
        assert!(distinct.len() > 200);
    }

    #[test]
    fn cancel_before_start_makes_no_request() {
        let cancel = AtomicBool::new(true);
        let mut phases = Vec::new();
        let r = run(&cancel, &mut |p| phases.push(p.phase));
        assert_eq!(r, Err(CANCELLED.to_string()));
        assert_eq!(phases, vec![SpeedPhase::Locating]);
    }
}
