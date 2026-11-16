//! Processes: names, icons, ending one.

use crate::types::*;
use crate::util;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Graphics::Gdi::{
    CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GdiFlush, SelectObject,
    BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, HBRUSH, HDC,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};
use windows::Win32::UI::Shell::{SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON};
use windows::Win32::UI::WindowsAndMessaging::{
    DestroyIcon, DrawIconEx, PrivateExtractIconsW, DI_FLAGS, DI_MASK, DI_NORMAL, HICON,
};

const ERROR_ACCESS_DENIED_HRESULT: i32 = 0x8007_0005_u32 as i32;
const ERROR_INVALID_PARAMETER_HRESULT: i32 = 0x8007_0057_u32 as i32;

/// Closes a kernel handle on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by a successful Open/Create call and
        // is closed exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// The file name component of a Windows path.
pub fn file_name_of(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Why the image path of a process could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NoPath {
    /// There is no such process (any more).
    Gone,
    /// The process exists but is protected from this one.
    Denied,
}

/// Full image path of a process, when Windows lets this process read it.
fn image_path(pid: u32) -> Result<String, NoPath> {
    let classify = |code: i32| {
        if code == ERROR_ACCESS_DENIED_HRESULT {
            NoPath::Denied
        } else {
            NoPath::Gone
        }
    };
    // SAFETY: plain call; the returned handle is owned by `OwnedHandle`.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(|e| classify(e.code().0))?;
    let handle = OwnedHandle(handle);
    let mut cap = 520usize;
    let mut last = NoPath::Gone;
    for _ in 0..3 {
        let mut buf = vec![0u16; cap];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` holds `len` writable UTF-16 units; `len` is updated to
        // the number of characters written.
        let res = unsafe {
            QueryFullProcessImageNameW(
                handle.0,
                PROCESS_NAME_WIN32,
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        };
        match res {
            Ok(()) => {
                let len = (len as usize).min(buf.len());
                let path = String::from_utf16_lossy(&buf[..len]);
                return if path.is_empty() {
                    Err(NoPath::Gone)
                } else {
                    Ok(path)
                };
            }
            Err(e) => last = classify(e.code().0),
        }
        cap *= 8; // ERROR_INSUFFICIENT_BUFFER for very long paths: 4160, 33280
    }
    Err(last)
}

/// File names of every running process (one Toolhelp snapshot).
pub fn snapshot_names() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    // SAFETY: plain call; the snapshot handle is owned by `OwnedHandle`.
    let Ok(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return map;
    };
    let snap = OwnedHandle(snap);
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: `entry` is a properly sized PROCESSENTRY32W with dwSize set.
    let mut more = unsafe { Process32FirstW(snap.0, &mut entry) }.is_ok();
    let mut guard = 0;
    while more && guard < 100_000 {
        guard += 1;
        map.insert(entry.th32ProcessID, util::from_wide_buf(&entry.szExeFile));
        // SAFETY: as above.
        more = unsafe { Process32NextW(snap.0, &mut entry) }.is_ok();
    }
    map
}

fn well_known(pid: u32) -> Option<&'static str> {
    match pid {
        0 => Some("System Idle Process"),
        4 => Some("System"),
        _ => None,
    }
}

/// `(file name, full path)` of a process; the path may be empty.
pub fn process_name(pid: u32) -> Option<(String, String)> {
    if let Some(name) = well_known(pid) {
        return Some((name.to_string(), String::new()));
    }
    match image_path(pid) {
        Ok(path) => return Some((file_name_of(&path).to_string(), path)),
        Err(NoPath::Gone) => return None,
        Err(NoPath::Denied) => {}
    }
    // Protected processes: the name is still in the process list.
    let name = snapshot_names().remove(&pid)?;
    (!name.is_empty()).then_some((name, String::new()))
}

/// Resolves many PIDs with at most one Toolhelp snapshot; results (including
/// failures) are remembered for the lifetime of the cache.
#[derive(Default)]
pub struct NameCache {
    known: HashMap<u32, Option<(String, String)>>,
    snapshot: Option<HashMap<u32, String>>,
}

impl NameCache {
    pub fn new() -> NameCache {
        NameCache::default()
    }

    /// `(file name, full path)`; `None` when the process is gone.
    pub fn get(&mut self, pid: u32) -> Option<&(String, String)> {
        if !self.known.contains_key(&pid) {
            let found = self.lookup(pid);
            self.known.insert(pid, found);
        }
        self.known.get(&pid).and_then(|v| v.as_ref())
    }

    fn lookup(&mut self, pid: u32) -> Option<(String, String)> {
        if let Some(name) = well_known(pid) {
            return Some((name.to_string(), String::new()));
        }
        match image_path(pid) {
            Ok(path) => return Some((file_name_of(&path).to_string(), path)),
            Err(NoPath::Gone) => return None,
            Err(NoPath::Denied) => {}
        }
        let names = self.snapshot.get_or_insert_with(snapshot_names);
        let name = names.get(&pid)?;
        (!name.is_empty()).then(|| (name.clone(), String::new()))
    }
}

/// How long a cached process name is trusted (a PID can be reused).
const NAME_TTL: Duration = Duration::from_secs(30);
/// The process list is costly on a busy PC: it is reused for this long ...
const SNAPSHOT_TTL: Duration = Duration::from_secs(300);
/// ... unless a PID is missing from it and it is at least this old.
const SNAPSHOT_MIN_AGE: Duration = Duration::from_secs(5);
/// Cached names kept before the stale ones are dropped.
const MAX_CACHED_NAMES: usize = 4096;

#[derive(Default)]
struct SharedNames {
    names: HashMap<u32, (Instant, Option<(String, String)>)>,
    snapshot: HashMap<u32, String>,
    snapshot_at: Option<Instant>,
}

impl SharedNames {
    fn lookup(&mut self, pid: u32, now: Instant) -> Option<(String, String)> {
        if let Some((at, found)) = self.names.get(&pid) {
            if now.saturating_duration_since(*at) < NAME_TTL {
                return found.clone();
            }
        }
        let found = self.resolve(pid, now);
        if self.names.len() >= MAX_CACHED_NAMES {
            self.names
                .retain(|_, (at, _)| now.saturating_duration_since(*at) < NAME_TTL);
        }
        self.names.insert(pid, (now, found.clone()));
        found
    }

    fn resolve(&mut self, pid: u32, now: Instant) -> Option<(String, String)> {
        match image_path(pid) {
            Ok(path) => return Some((file_name_of(&path).to_string(), path)),
            // Sockets outlive their process (TIME_WAIT): no process list needed.
            Err(NoPath::Gone) => return None,
            Err(NoPath::Denied) => {}
        }
        let age = self.snapshot_at.map(|at| now.saturating_duration_since(at));
        let stale = match age {
            None => true,
            Some(age) => {
                age >= SNAPSHOT_TTL
                    || (age >= SNAPSHOT_MIN_AGE && !self.snapshot.contains_key(&pid))
            }
        };
        if stale {
            self.snapshot = snapshot_names();
            self.snapshot_at = Some(now);
        }
        let name = self.snapshot.get(&pid)?;
        (!name.is_empty()).then(|| (name.clone(), String::new()))
    }
}

static SHARED_NAMES: OnceLock<Mutex<SharedNames>> = OnceLock::new();

/// Like `process_name`, but answered from a process-wide cache: a name is
/// trusted for 30 seconds, and the (costly) process list behind the names of
/// protected processes is reused for up to five minutes. This is what the
/// connection table and the monitor use, so polling them stays cheap.
pub fn process_name_cached(pid: u32) -> Option<(String, String)> {
    if let Some(name) = well_known(pid) {
        return Some((name.to_string(), String::new()));
    }
    let shared = SHARED_NAMES.get_or_init(|| Mutex::new(SharedNames::default()));
    util::lock(shared).lookup(pid, Instant::now())
}

// ---------------------------------------------------------------------------
// Icons
// ---------------------------------------------------------------------------

/// Destroys an icon handle on drop.
struct OwnedIcon(HICON);

impl Drop for OwnedIcon {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: the icon was created for us (PrivateExtractIconsW /
            // SHGetFileInfoW with SHGFI_ICON) and is destroyed exactly once.
            unsafe {
                let _ = DestroyIcon(self.0);
            }
        }
    }
}

fn load_icon(path: &str, size: u32) -> Option<OwnedIcon> {
    let w = util::wide(path);
    if w.len() <= 260 {
        let mut fixed = [0u16; 260];
        fixed[..w.len()].copy_from_slice(&w);
        let mut icons = [HICON::default()];
        // SAFETY: `fixed` is a NUL-terminated path and `icons` has room for
        // the one icon requested.
        let n = unsafe {
            PrivateExtractIconsW(
                &fixed,
                0,
                size as i32,
                size as i32,
                Some(&mut icons),
                None,
                0,
            )
        };
        if n != 0 && n != u32::MAX && !icons[0].is_invalid() {
            return Some(OwnedIcon(icons[0]));
        }
    }
    let mut info = SHFILEINFOW::default();
    // SAFETY: `w` is NUL terminated and `info` is a writable SHFILEINFOW of
    // the size passed.
    let ok = unsafe {
        SHGetFileInfoW(
            windows::core::PCWSTR(w.as_ptr()),
            windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0),
            Some(&mut info),
            std::mem::size_of::<SHFILEINFOW>() as u32,
            SHGFI_ICON | SHGFI_LARGEICON,
        )
    };
    (ok != 0 && !info.hIcon.is_invalid()).then_some(OwnedIcon(info.hIcon))
}

/// Draws an icon into a zeroed top-down 32-bit surface and returns its BGRA bytes.
fn draw_icon(icon: HICON, size: u32, flags: DI_FLAGS) -> Option<Vec<u8>> {
    let bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: size as i32,
            biHeight: -(size as i32), // top-down
            biPlanes: 1,
            biBitCount: 32,
            biCompression: 0, // BI_RGB
            ..Default::default()
        },
        ..Default::default()
    };
    let len = (size as usize) * (size as usize) * 4;
    // SAFETY: every GDI object created here is released before returning; the
    // DIB section memory (`bits`, `len` bytes) is only read while the bitmap
    // is alive.
    unsafe {
        let dc = CreateCompatibleDC(HDC::default());
        if dc.is_invalid() {
            return None;
        }
        let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
        let dib = match CreateDIBSection(dc, &bmi, DIB_RGB_COLORS, &mut bits, HANDLE::default(), 0)
        {
            Ok(dib) if !bits.is_null() => dib,
            Ok(dib) => {
                let _ = DeleteObject(dib);
                let _ = DeleteDC(dc);
                return None;
            }
            Err(_) => {
                let _ = DeleteDC(dc);
                return None;
            }
        };
        std::ptr::write_bytes(bits as *mut u8, 0, len);
        let old = SelectObject(dc, dib);
        let drawn = DrawIconEx(
            dc,
            0,
            0,
            icon,
            size as i32,
            size as i32,
            0,
            HBRUSH::default(),
            flags,
        )
        .is_ok();
        let _ = GdiFlush();
        let out = drawn.then(|| std::slice::from_raw_parts(bits as *const u8, len).to_vec());
        SelectObject(dc, old);
        let _ = DeleteObject(dib);
        let _ = DeleteDC(dc);
        out
    }
}

/// Converts what `DrawIconEx` produced into straight-alpha RGBA.
///
/// `color` is BGRA drawn over transparent black. Icons with an alpha channel
/// come out premultiplied; icons without one leave alpha at zero everywhere,
/// in which case `mask` (the AND mask drawn the same way: black = opaque,
/// white = transparent) decides the alpha. Pure, unit-tested.
pub fn icon_pixels_to_rgba(color: &[u8], mask: Option<&[u8]>) -> Vec<u8> {
    let has_alpha = color.as_chunks::<4>().0.iter().any(|p| p[3] != 0);
    let mut out = Vec::with_capacity(color.len());
    for (i, p) in color.as_chunks::<4>().0.iter().enumerate() {
        let (b, g, r, a) = (p[0], p[1], p[2], p[3]);
        if has_alpha {
            if a == 0 {
                out.extend_from_slice(&[0, 0, 0, 0]);
            } else if a >= 253 {
                // Scaled icons come out with 253/254 where they are opaque.
                out.extend_from_slice(&[r, g, b, 255]);
            } else {
                let un =
                    |c: u8| -> u8 { ((c as u32 * 255 + a as u32 / 2) / a as u32).min(255) as u8 };
                out.extend_from_slice(&[un(r), un(g), un(b), a]);
            }
        } else {
            let opaque = match mask.and_then(|m| m.get(i * 4..i * 4 + 3)) {
                // Any channel set means "white" in the AND mask: transparent.
                Some(m) => m[0] == 0 && m[1] == 0 && m[2] == 0,
                None => true,
            };
            if opaque {
                out.extend_from_slice(&[r, g, b, 255]);
            } else {
                out.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    out
}

/// The icon of an executable as `size` x `size` RGBA.
pub fn exe_icon(path: &str, size: u32) -> Option<IconImage> {
    if path.is_empty() || size == 0 || size > 512 {
        return None;
    }
    let icon = load_icon(path, size)?;
    let color = draw_icon(icon.0, size, DI_NORMAL)?;
    let has_alpha = color.as_chunks::<4>().0.iter().any(|p| p[3] != 0);
    let mask = if has_alpha {
        None
    } else {
        draw_icon(icon.0, size, DI_MASK)
    };
    let rgba = icon_pixels_to_rgba(&color, mask.as_deref());
    // A fully transparent result means the drawing silently failed.
    if rgba.as_chunks::<4>().0.iter().all(|p| p[3] == 0) {
        return None;
    }
    Some(IconImage {
        width: size,
        height: size,
        rgba,
    })
}

// ---------------------------------------------------------------------------
// Ending a process
// ---------------------------------------------------------------------------

/// Processes Windows needs to keep running (ending one logs the user out,
/// stops the session or crashes the system). Lower case.
const CRITICAL_PROCESSES: &[&str] = &[
    "system",
    "system idle process",
    "registry",
    "memory compression",
    "secure system",
    "ntoskrnl.exe",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
    "svchost.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "sihost.exe",
    "wudfhost.exe",
    "msmpeng.exe",
    "mpdefendercoreservice.exe",
    "nissrv.exe",
    "securityhealthservice.exe",
];

/// Why `pid` must not be ended (this program, PID 0 / 4, critical system
/// processes), or `None` when it may be. Pure, unit-tested.
pub fn end_process_refusal(pid: u32, name: &str, own_pid: u32) -> Option<String> {
    if pid == 0 || pid == 4 {
        return Some("This is the Windows kernel and cannot be ended.".into());
    }
    if pid == own_pid {
        return Some("This is WireForge itself. Close the window to exit.".into());
    }
    let lower = file_name_of(name.trim()).to_lowercase();
    if CRITICAL_PROCESSES.contains(&lower.as_str()) {
        return Some(format!(
            "{} is a critical Windows process. Ending it could crash or lock this PC.",
            file_name_of(name.trim())
        ));
    }
    None
}

/// Ends a process (TerminateProcess) after the checks above.
pub fn end_process(pid: u32) -> Result<(), String> {
    let own = std::process::id();
    if let Some(reason) = end_process_refusal(pid, "", own) {
        return Err(reason);
    }
    let Some((name, _)) = process_name(pid) else {
        return Err("The process is no longer running.".into());
    };
    if let Some(reason) = end_process_refusal(pid, &name, own) {
        return Err(reason);
    }
    // SAFETY: plain call; the returned handle is owned by `OwnedHandle`.
    let handle = match unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) } {
        Ok(h) => OwnedHandle(h),
        Err(e) => return Err(end_error(&name, e.code().0)),
    };
    // SAFETY: `handle` is a live process handle with PROCESS_TERMINATE access.
    unsafe { TerminateProcess(handle.0, 1) }.map_err(|e| end_error(&name, e.code().0))
}

fn end_error(name: &str, hresult: i32) -> String {
    match hresult {
        ERROR_ACCESS_DENIED_HRESULT => format!(
            "Windows refused to end {name}. Run WireForge as administrator to end this process."
        ),
        ERROR_INVALID_PARAMETER_HRESULT => "The process is no longer running.".into(),
        other => format!("Could not end {name} (error 0x{:08X}).", other as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names() {
        assert_eq!(
            file_name_of("C:\\Program Files\\Example\\app.exe"),
            "app.exe"
        );
        assert_eq!(file_name_of("C:/tools/x.exe"), "x.exe");
        assert_eq!(file_name_of("plain.exe"), "plain.exe");
        assert_eq!(file_name_of(""), "");
    }

    #[test]
    fn refuses_kernel_and_self() {
        assert!(end_process_refusal(0, "", 999).is_some());
        assert!(end_process_refusal(4, "System", 999).is_some());
        assert!(end_process_refusal(999, "WireForge.exe", 999).is_some());
        // Even with a harmless name, own pid is refused.
        assert!(end_process_refusal(1234, "notepad.exe", 1234).is_some());
    }

    #[test]
    fn refuses_critical_processes_case_insensitively() {
        for name in [
            "csrss.exe",
            "CSRSS.EXE",
            "wininit.exe",
            "winlogon.exe",
            "lsass.exe",
            "services.exe",
            "smss.exe",
            "svchost.exe",
            "dwm.exe",
            "System",
            "Registry",
            "MsMpEng.exe",
            "Memory Compression",
            "fontdrvhost.exe",
            " lsass.exe ",
            "C:\\Windows\\System32\\svchost.exe",
        ] {
            let reason = end_process_refusal(700, name, 999);
            assert!(reason.is_some(), "{name} must be refused");
            assert!(reason.unwrap_or_default().contains("critical"));
        }
    }

    #[test]
    fn allows_ordinary_processes() {
        for name in [
            "chrome.exe",
            "notepad.exe",
            "explorer.exe",
            "ping.exe",
            "",
            "svchost.exe.fake.exe",
            "mylsass.exe",
        ] {
            assert_eq!(end_process_refusal(700, name, 999), None, "{name}");
        }
    }

    #[test]
    fn end_process_refuses_before_touching_anything() {
        assert!(end_process(0).is_err());
        assert!(end_process(4).is_err());
        assert!(end_process(std::process::id()).is_err());
    }

    #[test]
    fn end_process_of_a_missing_pid_fails_cleanly() {
        // PIDs are multiples of 4; this one cannot exist.
        let err = end_process(0xFFFF_FFF3).expect_err("no such process");
        assert!(err.contains("no longer running"), "{err}");
    }

    #[test]
    fn own_process_has_a_name_and_path() {
        let (name, path) = process_name(std::process::id()).expect("own process");
        assert!(name.to_lowercase().ends_with(".exe"));
        assert!(path.ends_with(&name));
        assert_eq!(process_name(4).map(|p| p.0), Some("System".to_string()));
        assert_eq!(process_name(0xFFFF_FFF3), None);
    }

    #[test]
    fn name_cache_matches_single_lookups() {
        let mut cache = NameCache::new();
        let own = std::process::id();
        let first = cache.get(own).cloned().expect("own process");
        assert_eq!(Some(first.clone()), process_name(own));
        assert_eq!(cache.get(own), Some(&first));
        assert_eq!(cache.get(0xFFFF_FFF3), None);
        assert_eq!(cache.get(4).map(|p| p.0.as_str()), Some("System"));
        assert!(snapshot_names().contains_key(&own));
    }

    #[test]
    fn cached_names_match_and_are_reused() {
        let own = std::process::id();
        let first = process_name_cached(own);
        assert_eq!(first, process_name(own));
        assert_eq!(process_name_cached(own), first);
        assert_eq!(process_name_cached(4).map(|p| p.0), Some("System".into()));
        assert_eq!(process_name_cached(0xFFFF_FFF3), None);
        // The negative answer is cached too (no second process list).
        let started = std::time::Instant::now();
        for _ in 0..200 {
            assert_eq!(process_name_cached(0xFFFF_FFF3), None);
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn nearly_opaque_alpha_is_snapped() {
        let rgba = icon_pixels_to_rgba(&[10, 20, 30, 254, 10, 20, 30, 253], None);
        assert_eq!(rgba, vec![30, 20, 10, 255, 30, 20, 10, 255]);
    }

    #[test]
    fn ends_a_child_process_started_by_the_test() {
        let mut child = std::process::Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn ping");
        let pid = child.id();
        let result = end_process(pid);
        if result.is_err() {
            let _ = child.kill();
        }
        let status = child.wait().expect("wait for child");
        assert_eq!(result, Ok(()));
        assert_eq!(status.code(), Some(1));
    }

    #[test]
    fn premultiplied_alpha_is_made_straight() {
        // BGRA: opaque red, half-transparent white (premultiplied 128), clear.
        let color = [
            0, 0, 255, 255, //
            128, 128, 128, 128, //
            0, 0, 0, 0,
        ];
        let rgba = icon_pixels_to_rgba(&color, None);
        assert_eq!(&rgba[0..4], &[255, 0, 0, 255]);
        assert_eq!(&rgba[4..8], &[255, 255, 255, 128]);
        assert_eq!(&rgba[8..12], &[0, 0, 0, 0]);
    }

    #[test]
    fn unpremultiply_never_overflows() {
        // Invalid premultiplied data (colour above alpha) is clamped.
        let rgba = icon_pixels_to_rgba(&[200, 100, 50, 10], None);
        assert_eq!(rgba, vec![255, 255, 255, 10]);
        let rgba = icon_pixels_to_rgba(&[10, 20, 40, 80], None);
        assert_eq!(rgba, vec![128, 64, 32, 80]);
    }

    #[test]
    fn icons_without_alpha_use_the_mask() {
        // Two pixels, no alpha anywhere: blue (opaque by mask), green (masked out).
        let color = [255, 0, 0, 0, 0, 255, 0, 0];
        let mask = [0, 0, 0, 0, 255, 255, 255, 0];
        let rgba = icon_pixels_to_rgba(&color, Some(&mask));
        assert_eq!(rgba, vec![0, 0, 255, 255, 0, 0, 0, 0]);
        // Without a mask everything is opaque.
        let rgba = icon_pixels_to_rgba(&color, None);
        assert_eq!(rgba, vec![0, 0, 255, 255, 0, 255, 0, 255]);
        // A short mask leaves the missing pixels opaque.
        let rgba = icon_pixels_to_rgba(&color, Some(&mask[..4]));
        assert_eq!(rgba, vec![0, 0, 255, 255, 0, 255, 0, 255]);
    }

    #[test]
    fn icon_of_a_system_executable() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        for size in [16u32, 32, 48] {
            let icon = exe_icon(&format!("{root}\\System32\\notepad.exe"), size)
                .or_else(|| exe_icon(&format!("{root}\\explorer.exe"), size))
                .expect("a system icon");
            assert_eq!((icon.width, icon.height), (size, size));
            assert_eq!(icon.rgba.len(), (size * size * 4) as usize);
            assert!(icon.rgba.as_chunks::<4>().0.iter().any(|p| p[3] != 0));
        }
        assert_eq!(exe_icon("", 32), None);
        assert_eq!(exe_icon("C:\\Windows\\explorer.exe", 0), None);
    }
}
