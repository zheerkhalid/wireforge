//! Windows integration: elevation, time, the startup entry, the tray icon
//! and the small floating meter (both live on one background thread with a
//! hidden window, independent of the main window's frame loop).

use std::ffi::c_void;
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, COLORREF, ERROR_SUCCESS, HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT,
    WPARAM,
};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreateRoundRectRgn, CreateSolidBrush, DeleteObject, EndPaint,
    FillRect, InvalidateRect, SelectObject, SetBkMode, SetTextColor, SetWindowRgn, TextOutW,
    PAINTSTRUCT, TRANSPARENT,
};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
};
use windows::Win32::System::SystemInformation::{GetLocalTime, GetSystemTime};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::{
    ShellExecuteW, Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIM_ADD,
    NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
};
use windows::Win32::UI::WindowsAndMessaging::*;

use crate::fmt::days_from_civil;

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn hwnd(raw: isize) -> HWND {
    HWND(raw as *mut c_void)
}

/// Whether this process runs with administrator rights.
pub fn is_elevated() -> bool {
    // SAFETY: the token handle is opened, queried into a correctly sized
    // struct and closed again.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

fn shell_execute(verb: &str, file: &str, params: &str) -> Result<(), String> {
    let (v, f, p) = (wide(verb), wide(file), wide(params));
    // SAFETY: all strings are NUL-terminated and outlive the call.
    let r = unsafe {
        ShellExecuteW(
            HWND::default(),
            PCWSTR(v.as_ptr()),
            PCWSTR(f.as_ptr()),
            if params.is_empty() {
                PCWSTR::null()
            } else {
                PCWSTR(p.as_ptr())
            },
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if r.0 as usize > 32 {
        Ok(())
    } else {
        Err("Windows could not start it (the request was cancelled or refused).".into())
    }
}

/// Starts a second, elevated copy of the program (UAC prompt). The caller
/// closes this one when it worked.
pub fn restart_as_admin() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    shell_execute("runas", &exe.to_string_lossy(), "")
}

/// Whether `url` is a plain web link this program is willing to open.
pub fn is_web_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    match rest {
        Some(r) => {
            !r.is_empty()
                && !r.starts_with('/')
                && url
                    .chars()
                    .all(|c| !c.is_control() && !c.is_whitespace() && c != '"')
        }
        None => false,
    }
}

/// Opens a web link in the default browser.
pub fn open_url(url: &str) -> Result<(), String> {
    if !is_web_url(url) {
        return Err("Only http and https links can be opened.".into());
    }
    shell_execute("open", url, "")
}

/// Opens a folder in File Explorer.
pub fn open_folder(path: &std::path::Path) -> Result<(), String> {
    if !path.is_dir() {
        return Err("The folder does not exist yet.".into());
    }
    shell_execute("open", &path.to_string_lossy(), "")
}

/// A windowed program has no console; borrow the one it was started from so
/// that command-line output is visible.
pub fn attach_console() {
    use windows::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
    // SAFETY: plain Win32 call; failure only means there is no parent console.
    unsafe {
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Seconds to add to UTC to get local time (right now).
pub fn utc_offset() -> i64 {
    // SAFETY: both calls only fill a plain struct.
    let (l, u) = unsafe { (GetLocalTime(), GetSystemTime()) };
    let secs = |t: &windows::Win32::Foundation::SYSTEMTIME| {
        days_from_civil(t.wYear as i32, t.wMonth as u32, t.wDay as u32) * 86_400
            + t.wHour as i64 * 3600
            + t.wMinute as i64 * 60
            + t.wSecond as i64
    };
    // Round to the minute: the two clocks are read a moment apart.
    let diff = secs(&l) - secs(&u);
    (diff as f64 / 60.0).round() as i64 * 60
}

// --------------------------------------------------------------------------------------
// Start with Windows
// --------------------------------------------------------------------------------------

const RUN_KEY: PCWSTR = w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
const RUN_VALUE: PCWSTR = w!("WireForge");

/// The command line stored in the Run key (pure, unit-tested).
pub fn startup_command(exe: &str) -> String {
    format!("\"{}\" --minimized", exe.replace('"', ""))
}

/// Whether the per-user startup entry exists.
pub fn startup_enabled() -> bool {
    // SAFETY: the key is opened read-only, queried for existence and closed.
    unsafe {
        let mut key = HKEY::default();
        if RegOpenKeyExW(HKEY_CURRENT_USER, RUN_KEY, 0, KEY_QUERY_VALUE, &mut key) != ERROR_SUCCESS
        {
            return false;
        }
        let found = RegQueryValueExW(key, RUN_VALUE, None, None, None, None) == ERROR_SUCCESS;
        let _ = RegCloseKey(key);
        found
    }
}

/// Adds or removes the per-user startup entry (HKCU, no administrator rights needed).
pub fn set_startup(on: bool) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let command = wide(&startup_command(&exe.to_string_lossy()));
    // SAFETY: the key handle is closed on every path; the value buffer is a
    // NUL-terminated UTF-16 string passed with its exact byte length.
    unsafe {
        let mut key = HKEY::default();
        let status = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            RUN_KEY,
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut key,
            None,
        );
        if status != ERROR_SUCCESS {
            return Err(format!("Could not open the startup key ({}).", status.0));
        }
        let status = if on {
            let bytes =
                std::slice::from_raw_parts(command.as_ptr() as *const u8, command.len() * 2);
            RegSetValueExW(key, RUN_VALUE, 0, REG_SZ, Some(bytes))
        } else {
            let s = RegDeleteValueW(key, RUN_VALUE);
            // Already absent is fine.
            if s.0 == 2 {
                ERROR_SUCCESS
            } else {
                s
            }
        };
        let _ = RegCloseKey(key);
        if status != ERROR_SUCCESS {
            return Err(format!(
                "Could not change the startup entry ({}).",
                status.0
            ));
        }
    }
    Ok(())
}

// --------------------------------------------------------------------------------------
// Main window helpers
// --------------------------------------------------------------------------------------

/// Hides the main window (it stays alive; the tray icon brings it back).
pub fn hide_window(raw: isize) {
    if raw == 0 {
        return;
    }
    // SAFETY: a window handle of this process.
    unsafe {
        let _ = ShowWindow(hwnd(raw), SW_HIDE);
    }
}

pub fn show_and_focus(raw: isize) {
    if raw == 0 {
        return;
    }
    // SAFETY: a window handle of this process.
    unsafe {
        if IsIconic(hwnd(raw)).as_bool() {
            let _ = ShowWindow(hwnd(raw), SW_RESTORE);
        } else {
            let _ = ShowWindow(hwnd(raw), SW_SHOW);
        }
        let _ = SetForegroundWindow(hwnd(raw));
    }
}

// --------------------------------------------------------------------------------------
// Tray icon and floating meter
// --------------------------------------------------------------------------------------

/// What the tray thread tells the user interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SysEvent {
    /// The main window was shown from the tray.
    Shown,
    Exit,
    /// The meter was switched from the tray menu.
    MeterToggled(bool),
    /// The meter was dragged to a new place (screen pixels).
    MeterMoved(i32, i32),
}

/// What the tray tooltip and the meter show; produced once per second.
#[derive(Clone, Debug, Default)]
pub struct MeterFeed {
    pub down: String,
    pub up: String,
}

const WM_TRAY: u32 = WM_APP + 1;
const WM_SET_TRAY: u32 = WM_APP + 3;
const WM_QUIT_THREAD: u32 = WM_APP + 4;
const WM_SET_METER: u32 = WM_APP + 5;
const WM_NOTIFY_USER: u32 = WM_APP + 6;
const MENU_SHOW: usize = 1;
const MENU_METER: usize = 2;
const MENU_EXIT: usize = 3;
const TIMER_ID: usize = 1;

/// The meter is laid out for 96 DPI and scaled to the system DPI.
fn dpi_scaled(v: i32) -> i32 {
    // SAFETY: plain query.
    let dpi = unsafe { windows::Win32::UI::HiDpi::GetDpiForSystem() }.max(96);
    (v as i64 * dpi as i64 / 96) as i32
}

fn meter_w() -> i32 {
    dpi_scaled(152)
}

fn meter_h() -> i32 {
    dpi_scaled(52)
}

struct State {
    tx: Sender<SysEvent>,
    wake: Box<dyn Fn() + Send>,
    feed: Box<dyn Fn() -> MeterFeed + Send>,
    main_window: isize,
    tray: bool,
    meter: isize,
    last: MeterFeed,
    pending_note: Option<(String, String)>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn emit(event: SysEvent) {
    if let Ok(guard) = STATE.lock() {
        if let Some(s) = guard.as_ref() {
            let _ = s.tx.send(event);
            (s.wake)();
        }
    }
}

fn copy_wide(dst: &mut [u16], text: &str) {
    let max = dst.len().saturating_sub(1);
    for (i, c) in text.encode_utf16().take(max).enumerate() {
        dst[i] = c;
    }
}

/// The tooltip text for the tray icon (pure).
pub fn tray_tip(feed: &MeterFeed) -> String {
    if feed.down.is_empty() && feed.up.is_empty() {
        "WireForge".to_string()
    } else {
        format!("WireForge\nDown {}\nUp {}", feed.down, feed.up)
    }
}

unsafe fn tray_data(window: HWND, tip: &str) -> NOTIFYICONDATAW {
    let mut data = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: window,
        uID: 1,
        uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP,
        uCallbackMessage: WM_TRAY,
        ..Default::default()
    };
    let module = GetModuleHandleW(PCWSTR::null()).unwrap_or_default();
    // Icon resource 1 is the application icon embedded by the build script.
    data.hIcon = LoadIconW(HINSTANCE(module.0), PCWSTR(std::ptr::without_provenance(1)))
        .or_else(|_| LoadIconW(HINSTANCE::default(), IDI_APPLICATION))
        .unwrap_or_default();
    copy_wide(&mut data.szTip, tip);
    data
}

unsafe fn set_tray(window: HWND, on: bool) {
    let (was, tip) = STATE
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|s| (s.tray, tray_tip(&s.last))))
        .unwrap_or((false, "WireForge".into()));
    if on == was {
        return;
    }
    let data = tray_data(window, &tip);
    let _ = Shell_NotifyIconW(if on { NIM_ADD } else { NIM_DELETE }, &data);
    if let Ok(mut g) = STATE.lock() {
        if let Some(s) = g.as_mut() {
            s.tray = on;
        }
    }
}

unsafe fn meter_visible() -> bool {
    let meter = STATE
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|s| s.meter))
        .unwrap_or(0);
    meter != 0 && IsWindowVisible(hwnd(meter)).as_bool()
}

unsafe fn tray_menu(window: HWND) {
    let Ok(menu) = CreatePopupMenu() else { return };
    let meter_on = meter_visible();
    let _ = AppendMenuW(menu, MF_STRING, MENU_SHOW, w!("Open WireForge"));
    let _ = AppendMenuW(
        menu,
        if meter_on {
            MF_STRING | MF_CHECKED
        } else {
            MF_STRING
        },
        MENU_METER,
        w!("Floating meter"),
    );
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    let _ = AppendMenuW(menu, MF_STRING, MENU_EXIT, w!("Exit"));
    let mut pt = POINT::default();
    let _ = GetCursorPos(&mut pt);
    // Needed so the menu closes when the user clicks elsewhere.
    let _ = SetForegroundWindow(window);
    let choice = TrackPopupMenu(
        menu,
        TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
        pt.x,
        pt.y,
        0,
        window,
        None,
    );
    let _ = DestroyMenu(menu);
    match choice.0 as usize {
        MENU_SHOW => show_main(),
        MENU_METER => {
            show_meter(!meter_on, None);
            emit(SysEvent::MeterToggled(!meter_on));
        }
        MENU_EXIT => {
            // The main window may be hidden: show it so its loop runs and can close.
            show_main();
            emit(SysEvent::Exit);
        }
        _ => {}
    }
}

fn show_main() {
    let main = STATE
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|s| s.main_window))
        .unwrap_or(0);
    show_and_focus(main);
    emit(SysEvent::Shown);
}

unsafe fn show_meter(on: bool, pos: Option<(i32, i32)>) {
    let meter = STATE
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|s| s.meter))
        .unwrap_or(0);
    if meter == 0 {
        return;
    }
    let window = hwnd(meter);
    if !on {
        let _ = ShowWindow(window, SW_HIDE);
        return;
    }
    let (sw, sh) = (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    let (vx, vy) = (
        GetSystemMetrics(SM_XVIRTUALSCREEN),
        GetSystemMetrics(SM_YVIRTUALSCREEN),
    );
    let (vw, vh) = (
        GetSystemMetrics(SM_CXVIRTUALSCREEN),
        GetSystemMetrics(SM_CYVIRTUALSCREEN),
    );
    // Default: lower right, above the taskbar. A saved position is kept only
    // while it is still on a screen.
    let (mut x, mut y) = pos.unwrap_or((sw - meter_w() - 24, sh - meter_h() - 72));
    if x < vx || y < vy || x + meter_w() > vx + vw || y + meter_h() > vy + vh {
        x = sw - meter_w() - 24;
        y = sh - meter_h() - 72;
    }
    let flags = if pos.is_some() || !IsWindowVisible(window).as_bool() {
        SWP_NOACTIVATE | SWP_SHOWWINDOW
    } else {
        SWP_NOACTIVATE | SWP_SHOWWINDOW | SWP_NOMOVE
    };
    let _ = SetWindowPos(window, HWND_TOPMOST, x, y, meter_w(), meter_h(), flags);
}

unsafe fn paint_meter(window: HWND) {
    let mut ps = PAINTSTRUCT::default();
    let hdc = BeginPaint(window, &mut ps);
    let mut rect = RECT::default();
    let _ = GetClientRect(window, &mut rect);
    let bg = CreateSolidBrush(COLORREF(0x0025_1c15)); // BGR of #151c25
    FillRect(hdc, &rect, bg);
    let _ = DeleteObject(bg);
    let feed = STATE
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|s| s.last.clone()))
        .unwrap_or_default();
    let font = CreateFontW(
        -dpi_scaled(15),
        0,
        0,
        0,
        600,
        0,
        0,
        0,
        1, // DEFAULT_CHARSET
        0,
        0,
        5, // CLEARTYPE_QUALITY
        0,
        w!("Segoe UI"),
    );
    let old = SelectObject(hdc, font);
    SetBkMode(hdc, TRANSPARENT);
    let line = |y: i32, arrow: &str, color: u32, text: &str| {
        SetTextColor(hdc, COLORREF(color));
        let a: Vec<u16> = arrow.encode_utf16().collect();
        let _ = TextOutW(hdc, dpi_scaled(14), dpi_scaled(y), &a);
        SetTextColor(hdc, COLORREF(0x00f2_eee8)); // #e8eef2
        let t: Vec<u16> = if text.is_empty() { "0" } else { text }
            .encode_utf16()
            .collect();
        let _ = TextOutW(hdc, dpi_scaled(36), dpi_scaled(y), &t);
    };
    line(7, "\u{2193}", 0x00f0_8f2b, &feed.down); // #2b8ff0
    line(26, "\u{2191}", 0x0028_74d6, &feed.up); // #d67428
    SelectObject(hdc, old);
    let _ = DeleteObject(font);
    let _ = EndPaint(window, &ps);
}

unsafe extern "system" fn meter_proc(
    window: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_PAINT => {
            paint_meter(window);
            LRESULT(0)
        }
        // The whole window is a drag handle.
        WM_NCHITTEST => LRESULT(HTCAPTION as isize),
        WM_NCLBUTTONDBLCLK => {
            show_main();
            LRESULT(0)
        }
        WM_NCRBUTTONUP => {
            let owner = GetWindow(window, GW_OWNER).unwrap_or_default();
            tray_menu(if owner.0.is_null() { window } else { owner });
            LRESULT(0)
        }
        WM_EXITSIZEMOVE => {
            let mut r = RECT::default();
            if GetWindowRect(window, &mut r).is_ok() {
                emit(SysEvent::MeterMoved(r.left, r.top));
            }
            LRESULT(0)
        }
        _ => DefWindowProcW(window, msg, wparam, lparam),
    }
}

unsafe fn tick(window: HWND) {
    // Take the feed closure's result without holding the lock while it runs.
    let feed = {
        let Ok(guard) = STATE.lock() else { return };
        let Some(s) = guard.as_ref() else { return };
        if !s.tray && s.meter == 0 {
            return;
        }
        (s.feed)()
    };
    let (tray, meter) = {
        let Ok(mut guard) = STATE.lock() else { return };
        let Some(s) = guard.as_mut() else { return };
        s.last = feed.clone();
        (s.tray, s.meter)
    };
    if tray {
        let mut data = tray_data(window, &tray_tip(&feed));
        data.uFlags = NIF_TIP;
        let _ = Shell_NotifyIconW(NIM_MODIFY, &data);
    }
    if meter != 0 && IsWindowVisible(hwnd(meter)).as_bool() {
        let _ = InvalidateRect(hwnd(meter), None, false);
    }
}

unsafe extern "system" fn wnd_proc(
    window: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_TRAY => {
            match lparam.0 as u32 {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => show_main(),
                WM_RBUTTONUP | WM_CONTEXTMENU => tray_menu(window),
                _ => {}
            }
            LRESULT(0)
        }
        WM_TIMER => {
            tick(window);
            LRESULT(0)
        }
        WM_SET_TRAY => {
            set_tray(window, wparam.0 != 0);
            LRESULT(0)
        }
        WM_SET_METER => {
            let pos = (lparam.0 != isize::MIN).then_some((
                (lparam.0 & 0xffff_ffff) as u32 as i32,
                ((lparam.0 >> 32) & 0xffff_ffff) as u32 as i32,
            ));
            show_meter(wparam.0 != 0, pos);
            LRESULT(0)
        }
        WM_NOTIFY_USER => {
            let note = STATE
                .lock()
                .ok()
                .and_then(|mut g| g.as_mut().and_then(|s| s.pending_note.take()));
            let tray = STATE
                .lock()
                .ok()
                .and_then(|g| g.as_ref().map(|s| s.tray))
                .unwrap_or(false);
            if let (Some((title, text)), true) = (note, tray) {
                let mut data = tray_data(window, "WireForge");
                data.uFlags = NIF_INFO;
                data.dwInfoFlags = NIIF_INFO;
                copy_wide(&mut data.szInfoTitle, &title);
                copy_wide(&mut data.szInfo, &text);
                let _ = Shell_NotifyIconW(NIM_MODIFY, &data);
            }
            LRESULT(0)
        }
        WM_QUIT_THREAD => {
            let _ = KillTimer(window, TIMER_ID);
            set_tray(window, false);
            let meter = STATE
                .lock()
                .ok()
                .and_then(|mut g| g.as_mut().map(|s| std::mem::take(&mut s.meter)))
                .unwrap_or(0);
            if meter != 0 {
                let _ = DestroyWindow(hwnd(meter));
            }
            let _ = DestroyWindow(window);
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(window, msg, wparam, lparam),
    }
}

/// Handle to the background tray / meter thread.
pub struct SysWindow {
    window: isize,
}

impl SysWindow {
    /// Starts the background thread. `wake` is called after every event so the
    /// user interface runs and picks it up; `feed` is called once per second
    /// while the tray icon or the meter is shown.
    pub fn start(
        main_window: isize,
        tx: Sender<SysEvent>,
        wake: Box<dyn Fn() + Send>,
        feed: Box<dyn Fn() -> MeterFeed + Send>,
    ) -> Option<SysWindow> {
        if let Ok(mut g) = STATE.lock() {
            *g = Some(State {
                tx,
                wake,
                feed,
                main_window,
                tray: false,
                meter: 0,
                last: MeterFeed::default(),
                pending_note: None,
            });
        }
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<isize>();
        std::thread::Builder::new()
            .name("wireforge-sys".into())
            .spawn(move || {
                // SAFETY: standard window classes, windows and a message loop,
                // all owned by this thread.
                unsafe {
                    let module = GetModuleHandleW(PCWSTR::null()).unwrap_or_default();
                    let instance = HINSTANCE(module.0);
                    let class = WNDCLASSW {
                        lpfnWndProc: Some(wnd_proc),
                        hInstance: instance,
                        lpszClassName: w!("WireForgeSysWindow"),
                        ..Default::default()
                    };
                    RegisterClassW(&class);
                    let meter_class = WNDCLASSW {
                        style: CS_DBLCLKS,
                        lpfnWndProc: Some(meter_proc),
                        hInstance: instance,
                        hCursor: LoadCursorW(HINSTANCE::default(), IDC_SIZEALL).unwrap_or_default(),
                        lpszClassName: w!("WireForgeMeter"),
                        ..Default::default()
                    };
                    RegisterClassW(&meter_class);
                    let window = CreateWindowExW(
                        WS_EX_TOOLWINDOW,
                        w!("WireForgeSysWindow"),
                        w!("WireForge"),
                        WS_POPUP,
                        0,
                        0,
                        0,
                        0,
                        HWND::default(),
                        HMENU::default(),
                        instance,
                        None,
                    );
                    let Ok(window) = window else {
                        let _ = ready_tx.send(0);
                        return;
                    };
                    let meter = CreateWindowExW(
                        WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_NOACTIVATE,
                        w!("WireForgeMeter"),
                        w!("WireForge meter"),
                        WS_POPUP,
                        0,
                        0,
                        meter_w(),
                        meter_h(),
                        window,
                        HMENU::default(),
                        instance,
                        None,
                    );
                    if let Ok(meter) = meter {
                        let _ = SetLayeredWindowAttributes(meter, COLORREF(0), 238, LWA_ALPHA);
                        let region = CreateRoundRectRgn(
                            0,
                            0,
                            meter_w() + 1,
                            meter_h() + 1,
                            dpi_scaled(14),
                            dpi_scaled(14),
                        );
                        // The system owns the region after this call.
                        let _ = SetWindowRgn(meter, region, false);
                        if let Ok(mut g) = STATE.lock() {
                            if let Some(s) = g.as_mut() {
                                s.meter = meter.0 as isize;
                            }
                        }
                    }
                    let _ = SetTimer(window, TIMER_ID, 1000, None);
                    let _ = ready_tx.send(window.0 as isize);
                    let mut msg = MSG::default();
                    while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
            })
            .ok()?;
        let window = ready_rx.recv().ok().filter(|w| *w != 0)?;
        Some(SysWindow { window })
    }

    fn post(&self, msg: u32, wparam: usize, lparam: isize) {
        // SAFETY: posting to our own window; a stale handle just fails.
        unsafe {
            let _ = PostMessageW(hwnd(self.window), msg, WPARAM(wparam), LPARAM(lparam));
        }
    }

    pub fn set_tray(&self, on: bool) {
        self.post(WM_SET_TRAY, usize::from(on), 0);
    }

    /// Shows or hides the floating meter; `pos` is a saved screen position.
    pub fn set_meter(&self, on: bool, pos: Option<(i32, i32)>) {
        let packed = match pos {
            Some((x, y)) => ((y as u32 as u64) << 32 | x as u32 as u64) as isize,
            None => isize::MIN,
        };
        self.post(WM_SET_METER, usize::from(on), packed);
    }

    /// A balloon notification from the tray icon (does nothing without the icon).
    pub fn notify(&self, title: &str, text: &str) {
        if let Ok(mut g) = STATE.lock() {
            if let Some(s) = g.as_mut() {
                s.pending_note = Some((title.to_string(), text.to_string()));
            }
        }
        self.post(WM_NOTIFY_USER, 0, 0);
    }
}

impl Drop for SysWindow {
    fn drop(&mut self) {
        self.post(WM_QUIT_THREAD, 0, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_filtered() {
        for bad in [
            "file:///C:/Windows/System32/calc.exe",
            "javascript:alert(1)",
            "calc.exe /x",
            "ms-settings:",
            "https://",
            "https:///x",
            "https://a b",
            "",
        ] {
            assert!(!is_web_url(bad), "{bad}");
            assert!(open_url(bad).is_err(), "{bad}");
        }
        assert!(is_web_url("https://zheer.dev"));
        assert!(is_web_url("http://example.org/a?b=c"));
    }

    #[test]
    fn startup_command_is_quoted() {
        assert_eq!(
            startup_command("C:\\Program Files\\WireForge\\WireForge.exe"),
            "\"C:\\Program Files\\WireForge\\WireForge.exe\" --minimized"
        );
        assert_eq!(
            startup_command("C:\\a\"b.exe"),
            "\"C:\\ab.exe\" --minimized"
        );
    }

    #[test]
    fn tray_text() {
        assert_eq!(tray_tip(&MeterFeed::default()), "WireForge");
        let tip = tray_tip(&MeterFeed {
            down: "1.2 MB/s".into(),
            up: "300 KB/s".into(),
        });
        assert_eq!(tip, "WireForge\nDown 1.2 MB/s\nUp 300 KB/s");
        assert!(tip.encode_utf16().count() < 127);
        assert!(utc_offset().abs() <= 16 * 3600);
        let _ = startup_enabled();
        let _ = is_elevated();
    }
}
