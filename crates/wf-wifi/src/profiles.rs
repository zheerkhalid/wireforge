//! Saved Wi-Fi profiles and their keys.
//!
//! STRICTLY READ-ONLY: this module lists and reads profiles. It never sets,
//! deletes, reorders or connects to one.

use crate::types::*;
use crate::wlan::{classify, enum_interfaces, format_guid, wide_to_string, Client, WlanMemory};
use crate::xml;
use std::collections::HashSet;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::NetworkManagement::WiFi::{
    WlanFreeMemory, WlanGetProfile, WlanGetProfileList, WLAN_PROFILE_GET_PLAINTEXT_KEY,
    WLAN_PROFILE_GROUP_POLICY, WLAN_PROFILE_INFO, WLAN_PROFILE_INFO_LIST, WLAN_PROFILE_USER,
};

fn is_true(text: &str) -> bool {
    let t = text.trim();
    t.eq_ignore_ascii_case("true") || t == "1"
}

/// Bytes written as hexadecimal digits (white space allowed), as text.
fn hex_to_text(hex: &str) -> Option<String> {
    let digits: Vec<u32> = hex
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_digit(16))
        .collect::<Option<_>>()?;
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Vec<u8> = digits
        .chunks(2)
        .filter_map(|pair| Some((pair.first()? << 4 | pair.get(1)?) as u8))
        .collect();
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Parses a WLAN profile XML document (pure, unit-tested).
///
/// Understands namespaces, entity escapes, CDATA, SSIDs given only as
/// `<hex>`, several `authEncryption` blocks (the first is the main one, a
/// different second one becomes `transition_auth`), the `transitionMode`
/// flag, and the shared key with its type and `protected` flag. Error
/// messages never quote the document, because it contains the key.
pub fn parse_profile_xml(xml_text: &str) -> Result<ParsedProfile, String> {
    let root = xml::parse(xml_text.trim_end_matches('\0'))
        .map_err(|e| format!("The profile is not valid XML: {e}."))?;
    if !root.name.eq_ignore_ascii_case("WLANProfile") {
        return Err("The document is not a WLAN profile.".into());
    }
    let mut p = ParsedProfile {
        name: root
            .child("name")
            .map(|n| n.text.clone())
            .unwrap_or_default(),
        ..ParsedProfile::default()
    };

    let ssid_config = root.child("SSIDConfig");
    if let Some(ssid) = ssid_config.and_then(|c| c.child("SSID")) {
        let name = ssid.child("name").map(|n| n.text.as_str()).unwrap_or("");
        p.ssid = if !name.is_empty() {
            name.to_string()
        } else {
            ssid.child("hex")
                .and_then(|h| hex_to_text(&h.text))
                .unwrap_or_default()
        };
    }
    if p.name.is_empty() && p.ssid.is_empty() {
        return Err("The profile has neither a name nor a network name.".into());
    }
    if p.name.is_empty() {
        p.name = p.ssid.clone();
    }
    if p.ssid.is_empty() {
        p.ssid = p.name.clone();
    }
    p.hidden = ssid_config
        .and_then(|c| c.child("nonBroadcast"))
        .is_some_and(|n| is_true(&n.text));
    p.auto_connect = root
        .child("connectionMode")
        .is_some_and(|n| n.trimmed().eq_ignore_ascii_case("auto"));
    p.random_mac = root.find("enableRandomization").map(|n| is_true(&n.text));

    if let Some(security) = root.path(&["MSM", "security"]) {
        let mut blocks = security.children_named("authEncryption");
        if let Some(first) = blocks.next() {
            p.auth = first
                .child("authentication")
                .map(|n| n.trimmed().to_string())
                .unwrap_or_default();
            p.cipher = first
                .child("encryption")
                .map(|n| n.trimmed().to_string())
                .unwrap_or_default();
            p.use_one_x = first.child("useOneX").is_some_and(|n| is_true(&n.text));
            let transition = first
                .child("transitionMode")
                .is_some_and(|n| is_true(&n.text));
            // A second block with a different authentication is the other
            // half of a transition-mode network.
            p.transition_auth = blocks
                .filter_map(|b| b.child("authentication"))
                .map(|n| n.trimmed().to_string())
                .find(|a| !a.is_empty() && !a.eq_ignore_ascii_case(&p.auth));
            if p.transition_auth.is_none() && transition {
                p.transition_auth = match p.auth.to_ascii_uppercase().as_str() {
                    "WPA3SAE" => Some("WPA2PSK".to_string()),
                    "WPA3ENT" => Some("WPA2".to_string()),
                    "OWE" => Some("open".to_string()),
                    _ => None,
                };
            }
        }
        if let Some(key) = security.child("sharedKey") {
            p.key_type = key
                .child("keyType")
                .map(|n| n.trimmed().to_string())
                .unwrap_or_default();
            p.key_protected = key.child("protected").map(|n| is_true(&n.text));
            p.key_material = key.child("keyMaterial").map(|n| n.text.clone());
        }
    }
    Ok(p)
}

/// The display name for an authentication value ("WPA2PSK" -> "WPA2-Personal").
///
/// `cipher` tells "Open" from "WEP"; `transition` is the second
/// authentication of a transition-mode profile.
pub fn security_label(auth: &str, cipher: &str, transition: Option<&str>) -> String {
    let a = auth.trim().to_ascii_uppercase();
    let c = cipher.trim().to_ascii_uppercase();
    let t = transition.map(|t| t.trim().to_ascii_uppercase());
    let t = t.as_deref();
    let label = match a.as_str() {
        "OPEN" => {
            if c.starts_with("WEP") {
                "WEP"
            } else if t == Some("OWE") {
                "Open / OWE"
            } else {
                "Open"
            }
        }
        "SHARED" => "WEP",
        "WPAPSK" => {
            if t == Some("WPA2PSK") {
                "WPA/WPA2-Personal"
            } else {
                "WPA-Personal"
            }
        }
        "WPA" => "WPA-Enterprise",
        "WPA2PSK" => match t {
            Some("WPA3SAE") => "WPA2/WPA3-Personal",
            Some("WPAPSK") => "WPA/WPA2-Personal",
            _ => "WPA2-Personal",
        },
        "WPA2" => match t {
            Some("WPA3") | Some("WPA3ENT") | Some("WPA3ENT192") => "WPA2/WPA3-Enterprise",
            _ => "WPA2-Enterprise",
        },
        "WPA3SAE" => {
            if t == Some("WPA2PSK") {
                "WPA2/WPA3-Personal"
            } else {
                "WPA3-Personal"
            }
        }
        "WPA3" | "WPA3ENT192" => "WPA3-Enterprise (192-bit)",
        "WPA3ENT" => {
            if t == Some("WPA2") {
                "WPA2/WPA3-Enterprise"
            } else {
                "WPA3-Enterprise"
            }
        }
        "OWE" => {
            if t == Some("OPEN") {
                "Open / OWE"
            } else {
                "OWE"
            }
        }
        "" => "Unknown",
        _ => return auth.trim().to_string(),
    };
    label.to_string()
}

/// 802.1X: the credentials belong to a user, the profile holds no shared key.
pub fn is_enterprise(auth: &str, use_one_x: bool) -> bool {
    use_one_x
        || matches!(
            auth.trim().to_ascii_uppercase().as_str(),
            "WPA" | "WPA2" | "WPA3" | "WPA3ENT" | "WPA3ENT192"
        )
}

/// What can be shown as the key of a parsed profile.
pub fn key_state(p: &ParsedProfile) -> KeyState {
    if is_enterprise(&p.auth, p.use_one_x) {
        return KeyState::Enterprise;
    }
    let auth = p.auth.trim().to_ascii_uppercase();
    let cipher = p.cipher.trim().to_ascii_uppercase();
    if auth == "OWE" || (auth == "OPEN" && !cipher.starts_with("WEP")) {
        return KeyState::Open;
    }
    match (&p.key_material, p.key_protected) {
        (Some(key), Some(true)) if !key.is_empty() => KeyState::NeedsAdmin,
        (Some(key), _) if !key.is_empty() => KeyState::Key(key.clone()),
        _ => KeyState::Unavailable("The profile does not contain a saved key.".into()),
    }
}

/// One plain sentence for the UI explaining a key state.
pub fn key_explanation(key: &KeyState) -> &'static str {
    match key {
        KeyState::Open => "This is an open network: it has no password.",
        KeyState::Key(_) => "This is the password saved on this PC for the network.",
        KeyState::NeedsAdmin => {
            "Windows only hands out this password to an administrator: run WireForge as administrator to see it."
        }
        KeyState::Enterprise => {
            "This network signs each person in with their own account (802.1X), so there is no shared password to show."
        }
        KeyState::Unknown => "It is not known whether a password is saved for this network.",
        KeyState::Unavailable(_) => "Windows did not provide a password for this network.",
    }
}

/// Builds the UI record from a parsed profile.
fn to_saved(
    p: &ParsedProfile,
    all_users: bool,
    interface_guid: &str,
    priority: u32,
) -> SavedProfile {
    SavedProfile {
        name: p.name.clone(),
        ssid: p.ssid.clone(),
        security: security_label(&p.auth, &p.cipher, p.transition_auth.as_deref()),
        auth: p.auth.clone(),
        cipher: p.cipher.clone(),
        auto_connect: p.auto_connect,
        hidden: p.hidden,
        key: key_state(p),
        key_type: if p.key_material.is_some() {
            p.key_type.clone()
        } else {
            String::new()
        },
        all_users,
        interface_guid: interface_guid.to_string(),
        random_mac: p.random_mac,
        priority,
    }
}

/// Reads one profile's XML. Returns the text and the flags Windows set.
fn get_profile(
    client: &Client,
    guid: &windows::core::GUID,
    name: &[u16],
    ask_plaintext: bool,
) -> Result<(String, u32), u32> {
    let mut xml = PWSTR::null();
    let mut flags = if ask_plaintext {
        WLAN_PROFILE_GET_PLAINTEXT_KEY
    } else {
        0
    };
    let mut access = 0u32;
    // SAFETY: `name` is NUL-terminated (checked by the caller) and outlives
    // the call; the out pointers are valid; the XML is freed below.
    let rc = unsafe {
        WlanGetProfile(
            client.0,
            guid,
            PCWSTR(name.as_ptr()),
            None,
            &mut xml,
            Some(&mut flags),
            Some(&mut access),
        )
    };
    if rc != 0 {
        return Err(rc);
    }
    if xml.is_null() {
        return Err(13);
    }
    // SAFETY: on success `xml` is a NUL-terminated string allocated by the
    // service; it is copied and then freed exactly once.
    let text = unsafe {
        let text = String::from_utf16_lossy(xml.as_wide());
        WlanFreeMemory(xml.0 as *const std::ffi::c_void);
        text
    };
    Ok((text, flags))
}

/// Every saved profile on every Wi-Fi interface, with the key when Windows
/// hands it out (WlanGetProfile with WLAN_PROFILE_GET_PLAINTEXT_KEY).
/// Read-only: profiles are never changed.
pub fn saved_profiles() -> Result<Vec<SavedProfile>, WlanError> {
    let client = Client::open()?;
    let interfaces = enum_interfaces(&client)?;
    if interfaces.is_empty() {
        return Err(WlanError::NoWifi("no Wi-Fi adapter was found".into()));
    }
    let mut out: Vec<SavedProfile> = Vec::new();
    let mut seen: HashSet<(String, bool, String, String)> = HashSet::new();
    let mut first_error: Option<WlanError> = None;

    for info in &interfaces {
        let guid = info.InterfaceGuid;
        let guid_text = format_guid(&guid);
        let mut list: *mut WLAN_PROFILE_INFO_LIST = std::ptr::null_mut();
        // SAFETY: valid out pointer; the list is freed by the guard.
        let rc = unsafe { WlanGetProfileList(client.0, &guid, None, &mut list) };
        let guard = WlanMemory(list);
        if rc != 0 {
            first_error.get_or_insert(classify(rc, "listing the saved networks", false));
            continue;
        }
        if guard.0.is_null() {
            continue;
        }
        // SAFETY: on success the header is followed by `dwNumberOfItems`
        // entries, copied out here before the guard frees the list.
        let entries: Vec<WLAN_PROFILE_INFO> = unsafe {
            let count = ((*guard.0).dwNumberOfItems as usize).min(4096);
            let first = std::ptr::addr_of!((*guard.0).ProfileInfo) as *const WLAN_PROFILE_INFO;
            (0..count)
                .map(|i| std::ptr::read_unaligned(first.add(i)))
                .collect()
        };
        for (priority, entry) in entries.iter().enumerate() {
            let mut name = entry.strProfileName;
            // Make sure the name handed back to Windows is NUL-terminated.
            if let Some(last) = name.last_mut() {
                *last = 0;
            }
            let display_name = wide_to_string(&name);
            let (result, denied) = match get_profile(&client, &guid, &name, true) {
                Err(crate::wlan::ERROR_ACCESS_DENIED) => {
                    (get_profile(&client, &guid, &name, false), true)
                }
                other => (other, false),
            };
            let list_flags = entry.dwFlags;
            let saved = match result {
                Ok((text, flags)) => {
                    let per_user = (flags | list_flags) & WLAN_PROFILE_USER != 0;
                    match parse_profile_xml(&text) {
                        Ok(parsed) => {
                            let mut saved =
                                to_saved(&parsed, !per_user, &guid_text, priority as u32);
                            // Asked for the clear key but it came back
                            // encrypted (or the request itself was refused).
                            let got_plaintext = flags & WLAN_PROFILE_GET_PLAINTEXT_KEY != 0;
                            if (denied || !got_plaintext)
                                && matches!(saved.key, KeyState::Key(_))
                                && parsed.key_protected != Some(false)
                            {
                                saved.key = KeyState::NeedsAdmin;
                            }
                            if denied && matches!(saved.key, KeyState::Unavailable(_)) {
                                saved.key = KeyState::NeedsAdmin;
                            }
                            saved
                        }
                        Err(reason) => SavedProfile {
                            name: display_name.clone(),
                            ssid: display_name.clone(),
                            security: "Unknown".into(),
                            key: KeyState::Unavailable(reason),
                            all_users: !per_user,
                            interface_guid: guid_text.clone(),
                            priority: priority as u32,
                            ..SavedProfile::default()
                        },
                    }
                }
                Err(code) => SavedProfile {
                    name: display_name.clone(),
                    ssid: display_name.clone(),
                    security: "Unknown".into(),
                    key: if code == crate::wlan::ERROR_ACCESS_DENIED {
                        KeyState::NeedsAdmin
                    } else {
                        KeyState::Unavailable(format!(
                            "Windows could not read this profile (error {code})."
                        ))
                    },
                    all_users: list_flags & WLAN_PROFILE_USER == 0,
                    interface_guid: guid_text.clone(),
                    priority: priority as u32,
                    ..SavedProfile::default()
                },
            };
            // The same profile is listed once per adapter: keep the first.
            let key = (
                saved.name.clone(),
                saved.all_users,
                saved.ssid.clone(),
                saved.auth.clone(),
            );
            if seen.insert(key) {
                out.push(saved);
            }
        }
    }
    if out.is_empty() {
        if let Some(e) = first_error {
            return Err(e);
        }
    }
    Ok(out)
}

/// Whether a profile was pushed by group policy (`WLAN_PROFILE_GROUP_POLICY`).
pub fn is_group_policy(flags: u32) -> bool {
    flags & WLAN_PROFILE_GROUP_POLICY != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: &str = "http://www.microsoft.com/networking/WLAN/profile/v1";

    /// A profile document the way Windows writes them.
    fn doc(
        name: &str,
        ssid_part: &str,
        mode: &str,
        extra_ssid: &str,
        security: &str,
        tail: &str,
    ) -> String {
        format!(
            "<?xml version=\"1.0\"?>\r\n<WLANProfile xmlns=\"{NS}\">\r\n\t<name>{name}</name>\r\n\t<SSIDConfig>\r\n\t\t<SSID>\r\n{ssid_part}\t\t</SSID>\r\n{extra_ssid}\t</SSIDConfig>\r\n\t<connectionType>ESS</connectionType>\r\n\t<connectionMode>{mode}</connectionMode>\r\n\t<MSM>\r\n\t\t<security>\r\n{security}\t\t</security>\r\n\t</MSM>\r\n{tail}</WLANProfile>\r\n"
        )
    }

    fn ssid(hex: &str, name: &str) -> String {
        format!("\t\t\t<hex>{hex}</hex>\r\n\t\t\t<name>{name}</name>\r\n")
    }

    fn auth(a: &str, c: &str, one_x: bool) -> String {
        format!(
            "\t\t\t<authEncryption>\r\n\t\t\t\t<authentication>{a}</authentication>\r\n\t\t\t\t<encryption>{c}</encryption>\r\n\t\t\t\t<useOneX>{one_x}</useOneX>\r\n\t\t\t</authEncryption>\r\n"
        )
    }

    fn key(kind: &str, protected: bool, material: &str) -> String {
        format!(
            "\t\t\t<sharedKey>\r\n\t\t\t\t<keyType>{kind}</keyType>\r\n\t\t\t\t<protected>{protected}</protected>\r\n\t\t\t\t<keyMaterial>{material}</keyMaterial>\r\n\t\t\t</sharedKey>\r\n"
        )
    }

    fn parse(xml: &str) -> ParsedProfile {
        match parse_profile_xml(xml) {
            Ok(p) => p,
            Err(e) => panic!("profile should parse: {e}"),
        }
    }

    #[test]
    fn open_network() {
        let xml = doc(
            "Cafe Guest",
            &ssid("4361666520477565 7374", "Cafe Guest"),
            "manual",
            "",
            &auth("open", "none", false),
            "",
        );
        let p = parse(&xml);
        assert_eq!(p.name, "Cafe Guest");
        assert_eq!(p.ssid, "Cafe Guest");
        assert_eq!((p.auth.as_str(), p.cipher.as_str()), ("open", "none"));
        assert!(!p.use_one_x && !p.auto_connect && !p.hidden);
        assert_eq!(p.key_material, None);
        assert_eq!(p.key_protected, None);
        assert_eq!(key_state(&p), KeyState::Open);
        assert_eq!(security_label(&p.auth, &p.cipher, None), "Open");
    }

    #[test]
    fn wpa2_passphrase() {
        let sec = format!(
            "{}{}",
            auth("WPA2PSK", "AES", false),
            key("passPhrase", false, "correct horse battery")
        );
        let p = parse(&doc(
            "Maple-Home",
            &ssid("4D61706C652D486F6D65", "Maple-Home"),
            "auto",
            "",
            &sec,
            "",
        ));
        assert_eq!((p.auth.as_str(), p.cipher.as_str()), ("WPA2PSK", "AES"));
        assert!(p.auto_connect);
        assert_eq!(p.key_type, "passPhrase");
        assert_eq!(p.key_protected, Some(false));
        assert_eq!(p.key_material.as_deref(), Some("correct horse battery"));
        assert_eq!(key_state(&p), KeyState::Key("correct horse battery".into()));
        assert_eq!(
            security_label(&p.auth, &p.cipher, p.transition_auth.as_deref()),
            "WPA2-Personal"
        );
        let saved = to_saved(&p, true, "{00000000-0000-0000-0000-000000000000}", 2);
        assert_eq!(saved.security, "WPA2-Personal");
        assert_eq!(saved.key_type, "passPhrase");
        assert!(saved.all_users && saved.auto_connect);
        assert_eq!(saved.priority, 2);
    }

    #[test]
    fn wpa2_network_key_of_64_hex_digits() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let sec = format!(
            "{}{}",
            auth("WPA2PSK", "AES", false),
            key("networkKey", false, hex)
        );
        let p = parse(&doc(
            "Maple-Home",
            &ssid("4D61706C652D486F6D65", "Maple-Home"),
            "auto",
            "",
            &sec,
            "",
        ));
        assert_eq!(p.key_type, "networkKey");
        assert_eq!(p.key_material.as_deref(), Some(hex));
        assert_eq!(key_state(&p), KeyState::Key(hex.into()));
    }

    #[test]
    fn wpa3_sae() {
        let sec = format!(
            "{}{}",
            auth("WPA3SAE", "AES", false),
            key("passPhrase", false, "pine-needle-42")
        );
        let p = parse(&doc(
            "Maple-6G",
            &ssid("4D61706C652D3647", "Maple-6G"),
            "auto",
            "",
            &sec,
            "",
        ));
        assert_eq!(p.auth, "WPA3SAE");
        assert_eq!(p.transition_auth, None);
        assert_eq!(security_label(&p.auth, &p.cipher, None), "WPA3-Personal");
        assert_eq!(key_state(&p), KeyState::Key("pine-needle-42".into()));
    }

    #[test]
    fn wpa2_wpa3_transition_with_two_blocks() {
        let sec = format!(
            "{}{}{}",
            auth("WPA2PSK", "AES", false),
            auth("WPA3SAE", "AES", false),
            key("passPhrase", false, "pine-needle-42")
        );
        let p = parse(&doc(
            "Maple-Home",
            &ssid("4D61706C652D486F6D65", "Maple-Home"),
            "auto",
            "",
            &sec,
            "",
        ));
        assert_eq!(p.auth, "WPA2PSK");
        assert_eq!(p.transition_auth.as_deref(), Some("WPA3SAE"));
        assert_eq!(
            security_label(&p.auth, &p.cipher, p.transition_auth.as_deref()),
            "WPA2/WPA3-Personal"
        );
        assert_eq!(key_state(&p), KeyState::Key("pine-needle-42".into()));
    }

    #[test]
    fn wpa3_transition_mode_flag() {
        let block = "\t\t\t<authEncryption>\r\n\t\t\t\t<authentication>WPA3SAE</authentication>\r\n\t\t\t\t<encryption>AES</encryption>\r\n\t\t\t\t<useOneX>false</useOneX>\r\n\t\t\t\t<transitionMode xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v4\">true</transitionMode>\r\n\t\t\t</authEncryption>\r\n";
        let sec = format!("{block}{}", key("passPhrase", false, "pine-needle-42"));
        let p = parse(&doc(
            "Maple-Home",
            &ssid("4D61706C652D486F6D65", "Maple-Home"),
            "auto",
            "",
            &sec,
            "",
        ));
        assert_eq!(p.auth, "WPA3SAE");
        assert_eq!(p.transition_auth.as_deref(), Some("WPA2PSK"));
        assert_eq!(
            security_label(&p.auth, &p.cipher, p.transition_auth.as_deref()),
            "WPA2/WPA3-Personal"
        );
    }

    #[test]
    fn wpa2_enterprise_has_no_key() {
        let sec = format!(
            "{}\t\t\t<OneX xmlns=\"http://www.microsoft.com/networking/OneX/v1\"><authMode>user</authMode><EAPConfig><EapHostConfig xmlns=\"http://www.microsoft.com/provisioning/EapHostConfig\"><EapMethod><Type xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">25</Type></EapMethod></EapHostConfig></EAPConfig></OneX>\r\n",
            auth("WPA2", "AES", true)
        );
        let p = parse(&doc(
            "Office-Staff",
            &ssid("4F66666963652D5374616666", "Office-Staff"),
            "auto",
            "",
            &sec,
            "",
        ));
        assert!(p.use_one_x);
        assert_eq!(p.key_material, None);
        assert_eq!(key_state(&p), KeyState::Enterprise);
        assert_eq!(security_label(&p.auth, &p.cipher, None), "WPA2-Enterprise");
        assert_eq!(to_saved(&p, false, "", 0).key_type, "");
    }

    #[test]
    fn wep() {
        let sec = format!(
            "{}{}",
            auth("open", "WEP", false),
            key("networkKey", false, "0102030405")
        );
        let p = parse(&doc(
            "Old-Router",
            &ssid("4F6C642D526F75746572", "Old-Router"),
            "manual",
            "",
            &sec,
            "",
        ));
        assert_eq!(security_label(&p.auth, &p.cipher, None), "WEP");
        assert_eq!(key_state(&p), KeyState::Key("0102030405".into()));
        assert_eq!(security_label("shared", "WEP", None), "WEP");
    }

    #[test]
    fn protected_key_needs_admin() {
        let blob = "01000000D08C9DDF0115D1118C7A00C04FC297EB0100000012345678";
        let sec = format!(
            "{}{}",
            auth("WPA2PSK", "AES", false),
            key("passPhrase", true, blob)
        );
        let p = parse(&doc(
            "Maple-Home",
            &ssid("4D61706C652D486F6D65", "Maple-Home"),
            "auto",
            "",
            &sec,
            "",
        ));
        assert_eq!(p.key_protected, Some(true));
        assert_eq!(key_state(&p), KeyState::NeedsAdmin);
    }

    #[test]
    fn hex_only_ssid() {
        // "Maple-Home" given only as hexadecimal, no <name> inside <SSID>.
        let xml = doc(
            "Maple (hex)",
            "\t\t\t<hex>4D61706C652D486F6D65</hex>\r\n",
            "auto",
            "",
            &auth("open", "none", false),
            "",
        );
        let p = parse(&xml);
        assert_eq!(p.name, "Maple (hex)");
        assert_eq!(p.ssid, "Maple-Home");
        // Non-ASCII bytes: "Café" in UTF-8, lower-case digits.
        let xml = doc(
            "x",
            "\t\t\t<hex>436166c3a9</hex>\r\n",
            "auto",
            "",
            &auth("open", "none", false),
            "",
        );
        assert_eq!(parse(&xml).ssid, "Caf\u{e9}");
        // Broken hex falls back to the profile name.
        let xml = doc(
            "Fallback",
            "\t\t\t<hex>4D6</hex>\r\n",
            "auto",
            "",
            &auth("open", "none", false),
            "",
        );
        assert_eq!(parse(&xml).ssid, "Fallback");
    }

    #[test]
    fn odd_characters_in_names_and_passphrases() {
        // & < > " ' ; , : \ spaces, non-ASCII and an emoji, escaped the way Windows writes XML.
        let name_xml =
            "R&amp;D &lt;lab&gt; &quot;5G&quot; &apos;x&apos; ; , : \\  caf\u{e9} \u{1F4F6}";
        let name = "R&D <lab> \"5G\" 'x' ; , : \\  caf\u{e9} \u{1F4F6}";
        let pass_xml = " p&amp;ss&lt;w&gt;&quot;o&apos;rd;,:\\ \u{fc}\u{f1}\u{ee} &#x1F511;&#233; ";
        let pass = " p&ss<w>\"o'rd;,:\\ \u{fc}\u{f1}\u{ee} \u{1F511}\u{e9} ";
        let sec = format!(
            "{}{}",
            auth("WPA2PSK", "AES", false),
            key("passPhrase", false, pass_xml)
        );
        let p = parse(&doc(name_xml, &ssid("00", name_xml), "auto", "", &sec, ""));
        assert_eq!(p.name, name);
        assert_eq!(p.ssid, name);
        // The passphrase keeps its leading and trailing spaces.
        assert_eq!(p.key_material.as_deref(), Some(pass));
    }

    #[test]
    fn cdata_key() {
        let sec = format!(
            "{}{}",
            auth("WPA2PSK", "AES", false),
            key("passPhrase", false, "<![CDATA[a<b>&c]]>")
        );
        let p = parse(&doc(
            "Maple-Home",
            &ssid("00", "Maple-Home"),
            "auto",
            "",
            &sec,
            "",
        ));
        assert_eq!(p.key_material.as_deref(), Some("a<b>&c"));
    }

    #[test]
    fn manual_hidden_and_randomisation() {
        let tail = "\t<MacRandomization xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v3\">\r\n\t\t<enableRandomization>true</enableRandomization>\r\n\t\t<randomizationSeed>123456789</randomizationSeed>\r\n\t</MacRandomization>\r\n";
        let xml = doc(
            "Quiet",
            &ssid("5175696574", "Quiet"),
            "manual",
            "\t\t<nonBroadcast>true</nonBroadcast>\r\n",
            &auth("WPA2PSK", "AES", false),
            tail,
        );
        let p = parse(&xml);
        assert!(!p.auto_connect);
        assert!(p.hidden);
        assert_eq!(p.random_mac, Some(true));
        // A personal profile without a key is "unavailable", not open.
        assert!(matches!(key_state(&p), KeyState::Unavailable(_)));

        let tail = tail.replace("true", "false");
        let xml = doc(
            "Loud",
            &ssid("4C6F7564", "Loud"),
            "auto",
            "\t\t<nonBroadcast>false</nonBroadcast>\r\n",
            &auth("open", "none", false),
            &tail,
        );
        let p = parse(&xml);
        assert!(p.auto_connect && !p.hidden);
        assert_eq!(p.random_mac, Some(false));
        let p = parse(&doc(
            "Plain",
            &ssid("00", "Plain"),
            "auto",
            "",
            &auth("open", "none", false),
            "",
        ));
        assert_eq!(p.random_mac, None);
    }

    #[test]
    fn namespace_prefixes_are_understood() {
        let xml = format!(
            "<w:WLANProfile xmlns:w=\"{NS}\"><w:name>Maple-Home</w:name><w:SSIDConfig><w:SSID><w:name>Maple-Home</w:name></w:SSID></w:SSIDConfig><w:connectionMode>auto</w:connectionMode><w:MSM><w:security><w:authEncryption><w:authentication>WPA2PSK</w:authentication><w:encryption>AES</w:encryption><w:useOneX>false</w:useOneX></w:authEncryption><w:sharedKey><w:keyType>passPhrase</w:keyType><w:protected>false</w:protected><w:keyMaterial>pine-needle-42</w:keyMaterial></w:sharedKey></w:security></w:MSM></w:WLANProfile>"
        );
        let p = parse(&xml);
        assert_eq!(p.ssid, "Maple-Home");
        assert!(p.auto_connect);
        assert_eq!(key_state(&p), KeyState::Key("pine-needle-42".into()));
    }

    #[test]
    fn malformed_documents() {
        for xml in [
            "",
            "not xml at all",
            "<WLANProfile><name>Maple-Home</name>",
            "<WLANProfile><name>Maple-Home</WLANProfile></name>",
            "<SomethingElse><name>Maple-Home</name></SomethingElse>",
            "<WLANProfile></WLANProfile>",
            "<WLANProfile><MSM><security/></MSM></WLANProfile>",
        ] {
            assert!(parse_profile_xml(xml).is_err(), "{xml:?}");
        }
        // A minimal but well-formed profile is accepted.
        let p = parse("<WLANProfile><name>Maple-Home</name></WLANProfile>");
        assert_eq!(
            (p.name.as_str(), p.ssid.as_str(), p.auth.as_str()),
            ("Maple-Home", "Maple-Home", "")
        );
        assert!(matches!(key_state(&p), KeyState::Unavailable(_)));
        // Trailing NULs from a wide string are tolerated.
        assert!(
            parse_profile_xml("<WLANProfile><name>Maple-Home</name></WLANProfile>\0\0").is_ok()
        );
    }

    #[test]
    fn errors_and_debug_output_never_contain_the_key() {
        let secret = "pine-needle-42";
        let broken =
            format!("<WLANProfile><name>Maple-Home</name><keyMaterial>{secret}</keyMaterial>");
        let err = parse_profile_xml(&broken).err().unwrap_or_default();
        assert!(!err.is_empty() && !err.contains(secret));
        let sec = format!(
            "{}{}",
            auth("WPA2PSK", "AES", false),
            key("passPhrase", false, secret)
        );
        let p = parse(&doc(
            "Maple-Home",
            &ssid("00", "Maple-Home"),
            "auto",
            "",
            &sec,
            "",
        ));
        assert!(!format!("{p:?}").contains(secret));
        let saved = to_saved(&p, true, "", 0);
        assert!(matches!(saved.key, KeyState::Key(_)));
        assert!(!format!("{saved:?}").contains(secret));
        assert!(!format!("{:?}", saved.key).contains(secret));
    }

    #[test]
    fn labels() {
        assert_eq!(security_label("WPAPSK", "TKIP", None), "WPA-Personal");
        assert_eq!(security_label("wpa2psk", "aes", None), "WPA2-Personal");
        assert_eq!(
            security_label("WPA2PSK", "AES", Some("WPA3SAE")),
            "WPA2/WPA3-Personal"
        );
        assert_eq!(
            security_label("WPA3SAE", "AES", Some("WPA2PSK")),
            "WPA2/WPA3-Personal"
        );
        assert_eq!(security_label("WPA", "TKIP", None), "WPA-Enterprise");
        assert_eq!(security_label("WPA3ENT", "AES", None), "WPA3-Enterprise");
        assert_eq!(
            security_label("WPA3ENT192", "GCMP256", None),
            "WPA3-Enterprise (192-bit)"
        );
        assert_eq!(security_label("OWE", "AES", None), "OWE");
        assert_eq!(security_label("open", "none", None), "Open");
        assert_eq!(security_label("", "", None), "Unknown");
        assert_eq!(security_label("FutureAuth", "AES", None), "FutureAuth");
    }

    #[test]
    fn key_states_and_explanations() {
        let enterprise = ParsedProfile {
            auth: "WPA3ENT".into(),
            ..Default::default()
        };
        assert_eq!(key_state(&enterprise), KeyState::Enterprise);
        let one_x_wep = ParsedProfile {
            auth: "open".into(),
            cipher: "WEP".into(),
            use_one_x: true,
            ..Default::default()
        };
        assert_eq!(key_state(&one_x_wep), KeyState::Enterprise);
        let owe = ParsedProfile {
            auth: "OWE".into(),
            cipher: "AES".into(),
            ..Default::default()
        };
        assert_eq!(key_state(&owe), KeyState::Open);
        let empty_key = ParsedProfile {
            auth: "WPA2PSK".into(),
            key_material: Some(String::new()),
            ..Default::default()
        };
        assert!(matches!(key_state(&empty_key), KeyState::Unavailable(_)));
        for state in [
            KeyState::Open,
            KeyState::Key("x".into()),
            KeyState::NeedsAdmin,
            KeyState::Enterprise,
            KeyState::Unknown,
            KeyState::Unavailable("y".into()),
        ] {
            let text = key_explanation(&state);
            assert!(text.ends_with('.') && text.len() > 20);
        }
        assert!(is_group_policy(1) && !is_group_policy(2));
    }
}
