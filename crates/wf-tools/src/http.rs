//! A small HTTPS client on WinHTTP (system TLS, certificate checks at defaults).
//!
//! TLS only (`https://` and `wss://`), certificate validation left at the
//! system defaults (never weakened), no redirects, no cookies, bounded
//! response size, timeouts, and an optional cancel flag and progress callback.
//! The WebSocket pieces are used by the speed test.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::Networking::WinHttp::*;

pub const USER_AGENT: &str = concat!("WireForge/", env!("CARGO_PKG_VERSION"));

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u32,
    pub body: Vec<u8>,
}

impl Response {
    /// The body as text (invalid UTF-8 replaced).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpError {
    /// The address is not an `https://` or `wss://` URL.
    BadUrl(String),
    /// Could not connect, TLS failed, or the request timed out.
    Unreachable(String),
    /// The response was larger than the caller allows.
    TooLarge,
    /// The cancel flag was set.
    Cancelled,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::BadUrl(e) => write!(f, "Not a usable address: {e}"),
            HttpError::Unreachable(e) => write!(
                f,
                "Could not reach the service. Check your internet connection. ({e})"
            ),
            HttpError::TooLarge => f.write_str("The service sent an unexpectedly large answer."),
            HttpError::Cancelled => f.write_str("Cancelled"),
        }
    }
}

/// The parts of a URL this client needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub host: String,
    pub port: u16,
    /// Path and query, always starting with `/`.
    pub path: String,
    /// `wss://` rather than `https://`.
    pub websocket: bool,
}

/// Splits an `https://` or `wss://` URL (pure, unit-tested). Plain `http://`
/// and `ws://` are refused: everything here goes over TLS.
pub fn parse_url(url: &str) -> Result<Url, HttpError> {
    let bad = |why: &str| HttpError::BadUrl(why.to_string());
    let url = url.trim();
    let (websocket, rest) = if let Some(rest) = strip_prefix_ignore_case(url, "https://") {
        (false, rest)
    } else if let Some(rest) = strip_prefix_ignore_case(url, "wss://") {
        (true, rest)
    } else {
        return Err(bad("only https:// and wss:// addresses are supported"));
    };
    let rest = rest.split('#').next().unwrap_or("");
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(split);
    if authority.contains('@') {
        return Err(bad("user names in addresses are not supported"));
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (addr, after) = v6.split_once(']').ok_or_else(|| bad("unclosed ["))?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse::<u16>().map_err(|_| bad("bad port"))?,
            None if after.is_empty() => 443,
            None => return Err(bad("bad port")),
        };
        (addr.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>().map_err(|_| bad("bad port"))?,
            ),
            None => (authority.to_string(), 443),
        }
    };
    if host.is_empty() || port == 0 {
        return Err(bad("the host name is missing"));
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    {
        return Err(bad("the host name has unexpected characters"));
    }
    let path = if tail.is_empty() {
        "/".to_string()
    } else if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_string()
    };
    if path.chars().any(|c| c.is_control() || c == ' ') {
        return Err(bad("the path has unexpected characters"));
    }
    Ok(Url {
        host,
        port,
        path,
        websocket,
    })
}

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        text.get(prefix.len()..)
    } else {
        None
    }
}

/// Options of one request.
pub struct Options<'a> {
    /// Extra request headers, each `"Name: value"`.
    pub headers: &'a [&'a str],
    /// The largest response body accepted, in bytes.
    pub max_body: usize,
    /// Timeout for resolving, connecting, sending and each receive.
    pub timeout_ms: u32,
    /// The longest the whole exchange may take.
    pub deadline_ms: u32,
    /// Checked between chunks; set it to stop.
    pub cancel: Option<&'a AtomicBool>,
    /// Called with the number of body bytes received so far.
    pub progress: Option<&'a mut dyn FnMut(u64)>,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Options {
            headers: &[],
            max_body: 1024 * 1024,
            timeout_ms: 10_000,
            deadline_ms: 45_000,
            cancel: None,
            progress: None,
        }
    }
}

struct Handle(*mut c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle came from WinHTTP and is closed exactly once.
            unsafe {
                let _ = WinHttpCloseHandle(self.0);
            }
        }
    }
}

fn last_error(what: &str) -> HttpError {
    HttpError::Unreachable(format!(
        "{what}: {}",
        windows::core::Error::from_win32().message()
    ))
}

fn win_error(what: &str, e: &windows::core::Error) -> HttpError {
    HttpError::Unreachable(format!("{what}: {}", e.message()))
}

fn code_error(what: &str, code: u32) -> HttpError {
    HttpError::Unreachable(format!(
        "{what}: {}",
        WIN32_ERROR(code).to_hresult().message()
    ))
}

fn cancelled(cancel: Option<&AtomicBool>) -> bool {
    cancel.is_some_and(|c| c.load(Ordering::Relaxed))
}

/// Session, connection and request handles for one exchange.
struct Exchange {
    // Dropped in declaration order: the request first, the session last.
    request: Handle,
    connect: Handle,
    session: Handle,
}

fn open(url: &Url, verb: &str, timeout_ms: u32) -> Result<Exchange, HttpError> {
    let host = HSTRING::from(url.host.as_str());
    let path = HSTRING::from(url.path.as_str());
    let agent = HSTRING::from(USER_AGENT);
    let verb = HSTRING::from(verb);
    let timeout = timeout_ms.clamp(1_000, 120_000) as i32;
    // SAFETY: every string passed below outlives the call it is passed to,
    // and every handle is owned by a guard that closes it once.
    unsafe {
        let session = Handle(WinHttpOpen(
            &agent,
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        ));
        if session.0.is_null() {
            return Err(last_error("open"));
        }
        let _ = WinHttpSetTimeouts(session.0, timeout, timeout, timeout, timeout);
        let protocols = (WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3)
            .to_le_bytes();
        if WinHttpSetOption(
            Some(session.0),
            WINHTTP_OPTION_SECURE_PROTOCOLS,
            Some(&protocols),
        )
        .is_err()
        {
            // Older Windows without TLS 1.3: ask for TLS 1.2 only.
            let tls12 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2.to_le_bytes();
            let _ = WinHttpSetOption(
                Some(session.0),
                WINHTTP_OPTION_SECURE_PROTOCOLS,
                Some(&tls12),
            );
        }
        let connect = Handle(WinHttpConnect(session.0, &host, url.port, 0));
        if connect.0.is_null() {
            return Err(last_error("connect"));
        }
        let request = Handle(WinHttpOpenRequest(
            connect.0,
            &verb,
            &path,
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        ));
        if request.0.is_null() {
            return Err(last_error("request"));
        }
        let never = WINHTTP_OPTION_REDIRECT_POLICY_NEVER.to_le_bytes();
        let _ = WinHttpSetOption(
            Some(request.0),
            WINHTTP_OPTION_REDIRECT_POLICY,
            Some(&never),
        );
        let no_cookies = WINHTTP_DISABLE_COOKIES.to_le_bytes();
        let _ = WinHttpSetOption(
            Some(request.0),
            WINHTTP_OPTION_DISABLE_FEATURE,
            Some(&no_cookies),
        );
        Ok(Exchange {
            request,
            connect,
            session,
        })
    }
}

fn status_of(request: &Handle) -> Result<u32, HttpError> {
    let mut status: u32 = 0;
    let mut size = 4u32;
    // SAFETY: `status` is a 4-byte buffer and `size` says so.
    unsafe {
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some(&mut status as *mut u32 as *mut c_void),
            &mut size,
            std::ptr::null_mut(),
        )
        .map_err(|e| win_error("status", &e))?;
    }
    Ok(status)
}

/// `GET` an `https://` URL.
pub fn get(url: &str, options: Options<'_>) -> Result<Response, HttpError> {
    request("GET", url, None, options)
}

/// `POST` a body to an `https://` URL. Give the content type in `headers`.
pub fn post(url: &str, body: &[u8], options: Options<'_>) -> Result<Response, HttpError> {
    request("POST", url, Some(body), options)
}

/// One request with any verb.
pub fn request(
    verb: &str,
    url: &str,
    body: Option<&[u8]>,
    mut options: Options<'_>,
) -> Result<Response, HttpError> {
    let url = parse_url(url)?;
    if url.websocket {
        return Err(HttpError::BadUrl("expected an https:// address".into()));
    }
    if cancelled(options.cancel) {
        return Err(HttpError::Cancelled);
    }
    let started = Instant::now();
    let deadline = Duration::from_millis(u64::from(options.deadline_ms.max(1_000)));
    let exchange = open(&url, verb, options.timeout_ms)?;
    let header_text: Vec<u16> = options.headers.join("\r\n").encode_utf16().collect();
    let header_arg = (!header_text.is_empty()).then_some(&header_text[..]);
    let body = body.unwrap_or(&[]);
    let body_len =
        u32::try_from(body.len()).map_err(|_| HttpError::BadUrl("the body is too large".into()))?;
    let body_arg = (!body.is_empty()).then_some(body.as_ptr() as *const c_void);
    // SAFETY: the header and body buffers outlive the calls; the request
    // handle is alive until `exchange` is dropped at the end of this function.
    unsafe {
        WinHttpSendRequest(
            exchange.request.0,
            header_arg,
            body_arg,
            body_len,
            body_len,
            0,
        )
        .map_err(|e| win_error("send", &e))?;
        WinHttpReceiveResponse(exchange.request.0, std::ptr::null_mut())
            .map_err(|e| win_error("receive", &e))?;
    }
    let status = status_of(&exchange.request)?;

    let mut out = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        if cancelled(options.cancel) {
            return Err(HttpError::Cancelled);
        }
        let mut read = 0u32;
        // SAFETY: `chunk` is a live buffer of the stated length.
        unsafe {
            WinHttpReadData(
                exchange.request.0,
                chunk.as_mut_ptr() as *mut c_void,
                chunk.len() as u32,
                &mut read,
            )
            .map_err(|e| win_error("read", &e))?;
        }
        if read == 0 {
            break;
        }
        let part = chunk.get(..read as usize).unwrap_or(&[]);
        if out.len() + part.len() > options.max_body {
            return Err(HttpError::TooLarge);
        }
        out.extend_from_slice(part);
        if let Some(progress) = options.progress.as_mut() {
            progress(out.len() as u64);
        }
        if started.elapsed() > deadline {
            return Err(HttpError::Unreachable("the download took too long".into()));
        }
    }
    Ok(Response { status, body: out })
}

/// What one `WebSocket::receive` call delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WsKind {
    Binary,
    Text,
    /// The server started (or answered) the closing handshake.
    Close,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WsFrame {
    pub kind: WsKind,
    /// Bytes written to the buffer.
    pub len: usize,
    /// `false` when more pieces of the same message follow.
    pub end_of_message: bool,
}

/// A client WebSocket over TLS. Calls block; `abort` may be called from
/// another thread to end a blocked call.
pub struct WebSocket {
    socket: AtomicUsize,
    _connect: Handle,
    _session: Handle,
}

// SAFETY: WinHTTP handles are not tied to a thread and WinHTTP allows one
// pending send and one pending receive on a WebSocket at the same time, plus
// closing the handle from any thread to cancel them. The socket handle is
// kept in an atomic so it is closed exactly once.
unsafe impl Send for WebSocket {}
// SAFETY: see above.
unsafe impl Sync for WebSocket {}

impl WebSocket {
    /// Opens `wss://...` and asks for `subprotocol` (empty for none).
    pub fn connect(url: &str, subprotocol: &str, timeout_ms: u32) -> Result<WebSocket, HttpError> {
        let url = parse_url(url)?;
        if !url.websocket {
            return Err(HttpError::BadUrl("expected a wss:// address".into()));
        }
        let exchange = open(&url, "GET", timeout_ms)?;
        let header_text: Vec<u16> = if subprotocol.is_empty() {
            Vec::new()
        } else {
            format!("Sec-WebSocket-Protocol: {subprotocol}")
                .encode_utf16()
                .collect()
        };
        let header_arg = (!header_text.is_empty()).then_some(&header_text[..]);
        // SAFETY: the handles are alive for the whole block; buffers outlive
        // the calls they are passed to.
        let socket = unsafe {
            WinHttpSetOption(
                Some(exchange.request.0),
                WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET,
                None,
            )
            .map_err(|e| win_error("websocket", &e))?;
            // Larger internal buffers help throughput; failure is harmless.
            let size = (256u32 * 1024).to_le_bytes();
            let _ = WinHttpSetOption(
                Some(exchange.request.0),
                WINHTTP_OPTION_WEB_SOCKET_RECEIVE_BUFFER_SIZE,
                Some(&size),
            );
            let _ = WinHttpSetOption(
                Some(exchange.request.0),
                WINHTTP_OPTION_WEB_SOCKET_SEND_BUFFER_SIZE,
                Some(&size),
            );
            WinHttpSendRequest(exchange.request.0, header_arg, None, 0, 0, 0)
                .map_err(|e| win_error("send", &e))?;
            WinHttpReceiveResponse(exchange.request.0, std::ptr::null_mut())
                .map_err(|e| win_error("receive", &e))?;
            let status = status_of(&exchange.request)?;
            if status != 101 {
                return Err(HttpError::Unreachable(format!(
                    "the server refused the connection (HTTP {status})"
                )));
            }
            let socket = WinHttpWebSocketCompleteUpgrade(exchange.request.0, 0);
            if socket.is_null() {
                return Err(last_error("upgrade"));
            }
            socket
        };
        let Exchange {
            request,
            connect,
            session,
        } = exchange;
        // The request handle is no longer needed once the upgrade is done.
        drop(request);
        Ok(WebSocket {
            socket: AtomicUsize::new(socket as usize),
            _connect: connect,
            _session: session,
        })
    }

    fn handle(&self) -> Result<*mut c_void, HttpError> {
        let h = self.socket.load(Ordering::Acquire);
        if h == 0 {
            Err(HttpError::Unreachable("the connection is closed".into()))
        } else {
            Ok(h as *mut c_void)
        }
    }

    /// Waits for the next piece of a message and writes it to `buf`.
    pub fn receive(&self, buf: &mut [u8]) -> Result<WsFrame, HttpError> {
        let handle = self.handle()?;
        let mut read = 0u32;
        let mut kind = WINHTTP_WEB_SOCKET_BUFFER_TYPE(0);
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `buf` is a live buffer of at least `len` bytes; the out
        // pointers are valid locals.
        let code = unsafe {
            WinHttpWebSocketReceive(
                handle,
                buf.as_mut_ptr() as *mut c_void,
                len,
                &mut read,
                &mut kind,
            )
        };
        if code != 0 {
            return Err(code_error("receive", code));
        }
        let (kind, end_of_message) = match kind {
            WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE => (WsKind::Binary, true),
            WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE => (WsKind::Binary, false),
            WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE => (WsKind::Text, true),
            WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE => (WsKind::Text, false),
            _ => (WsKind::Close, true),
        };
        Ok(WsFrame {
            kind,
            len: (read as usize).min(buf.len()),
            end_of_message,
        })
    }

    fn send(&self, kind: WINHTTP_WEB_SOCKET_BUFFER_TYPE, data: &[u8]) -> Result<(), HttpError> {
        let handle = self.handle()?;
        if u32::try_from(data.len()).is_err() {
            return Err(HttpError::BadUrl("the message is too large".into()));
        }
        // SAFETY: `data` outlives the blocking call.
        let code = unsafe { WinHttpWebSocketSend(handle, kind, Some(data)) };
        if code != 0 {
            return Err(code_error("send", code));
        }
        Ok(())
    }

    /// Sends one whole binary message.
    pub fn send_binary(&self, data: &[u8]) -> Result<(), HttpError> {
        self.send(WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE, data)
    }

    /// Sends one whole text message.
    pub fn send_text(&self, text: &str) -> Result<(), HttpError> {
        self.send(WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE, text.as_bytes())
    }

    /// Sends a normal-closure close frame without waiting for the answer;
    /// receiving may continue until the server's close arrives.
    pub fn shutdown(&self) {
        if let Ok(handle) = self.handle() {
            // SAFETY: the handle is a live WebSocket handle; no reason text.
            unsafe {
                let _ = WinHttpWebSocketShutdown(handle, 1000, None, 0);
            }
        }
    }

    /// Closes the handle now. Blocked `receive` / `send` calls on other
    /// threads return with an error. Safe to call more than once.
    pub fn abort(&self) {
        let h = self.socket.swap(0, Ordering::AcqRel);
        if h != 0 {
            // SAFETY: the swap guarantees the handle is closed exactly once.
            unsafe {
                let _ = WinHttpCloseHandle(h as *mut c_void);
            }
        }
    }
}

impl Drop for WebSocket {
    fn drop(&mut self) {
        self.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_https() {
        let u = parse_url("https://example.org/a/b?x=1&y=2").unwrap();
        assert_eq!(u.host, "example.org");
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/a/b?x=1&y=2");
        assert!(!u.websocket);
    }

    #[test]
    fn url_wss_with_port_and_no_path() {
        let u = parse_url("wss://ndt.example.org:4443").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("ndt.example.org", 4443, "/")
        );
        assert!(u.websocket);
        let u = parse_url("WSS://example.org?token=abc").unwrap();
        assert_eq!(u.path, "/?token=abc");
    }

    #[test]
    fn url_ipv6_literal() {
        let u = parse_url("https://[2001:db8::1]:8443/x").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("2001:db8::1", 8443));
        let u = parse_url("https://[2001:db8::1]/x#frag").unwrap();
        assert_eq!((u.port, u.path.as_str()), (443, "/x"));
    }

    #[test]
    fn url_rejects_plaintext_and_garbage() {
        for bad in [
            "http://example.org/",
            "ws://example.org/",
            "example.org",
            "https://",
            "https://user@example.org/",
            "https://example.org:0/",
            "https://example.org:99999/",
            "https://exa mple.org/",
            "https://example.org/a b",
            "https://[2001:db8::1/x",
            "",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn request_refuses_wrong_scheme_without_network() {
        assert!(matches!(
            get("wss://example.org/", Options::default()),
            Err(HttpError::BadUrl(_))
        ));
        assert!(matches!(
            WebSocket::connect("https://example.org/", "", 1000),
            Err(HttpError::BadUrl(_))
        ));
    }

    #[test]
    fn cancel_before_start() {
        let cancel = AtomicBool::new(true);
        let r = get(
            "https://example.org/",
            Options {
                cancel: Some(&cancel),
                ..Options::default()
            },
        );
        assert_eq!(r, Err(HttpError::Cancelled));
    }

    #[test]
    fn user_agent_names_the_app() {
        assert!(USER_AGENT.starts_with("WireForge/"));
    }
}
