//! 802.11 information elements of a beacon / probe response (pure, unit-tested).
//!
//! Everything here reads untrusted bytes received over the air: no indexing,
//! no arithmetic that can overflow, and a truncated element simply ends the walk.

use crate::channels::channel_from_freq;
use crate::types::Band;

/// What the information elements of one access point say.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct IeInfo {
    /// "WPA2-Personal", "WPA3-Personal", "WPA2/WPA3-Personal", "Open", "WEP"...
    pub security: String,
    /// "802.11ax"
    pub phy: String,
    /// Wi-Fi generation 4..=7.
    pub generation: Option<u8>,
    pub width_mhz: Option<u16>,
    /// Centre of the whole channel in MHz.
    pub center_mhz: Option<u32>,
    pub stations: Option<u16>,
    /// Channel utilisation 0..=100.
    pub utilization: Option<u8>,
    pub country: Option<String>,
    /// Highest legacy rate in Mbit/s from the (extended) supported rates.
    pub max_rate_mbps: Option<f32>,
}

pub const ID_RATES: u8 = 1;
pub const ID_COUNTRY: u8 = 7;
pub const ID_BSS_LOAD: u8 = 11;
pub const ID_HT_CAP: u8 = 45;
pub const ID_RSN: u8 = 48;
pub const ID_EXT_RATES: u8 = 50;
pub const ID_HT_OP: u8 = 61;
pub const ID_VHT_CAP: u8 = 191;
pub const ID_VHT_OP: u8 = 192;
pub const ID_VENDOR: u8 = 221;
pub const ID_EXTENSION: u8 = 255;
pub const EXT_HE_CAP: u8 = 35;
pub const EXT_HE_OP: u8 = 36;
pub const EXT_EHT_OP: u8 = 106;
pub const EXT_EHT_CAP: u8 = 108;

/// Walks the elements: `(id, body)`. Stops at the first truncated element.
pub fn elements(ies: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut rest = ies;
    std::iter::from_fn(move || {
        let (&id, after_id) = rest.split_first()?;
        let (&len, after_len) = after_id.split_first()?;
        let body = after_len.get(..usize::from(len))?;
        rest = after_len.get(usize::from(len)..)?;
        Some((id, body))
    })
}

/// A cursor over bytes that never reads past the end.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let head = self.0.get(..n)?;
        self.0 = self.0.get(n..)?;
        Some(head)
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_le_bytes([*b.first()?, *b.get(1)?]))
    }
    fn suite(&mut self) -> Option<([u8; 3], u8)> {
        let b = self.take(4)?;
        Some(([*b.first()?, *b.get(1)?, *b.get(2)?], *b.get(3)?))
    }
}

/// The key-management part of an RSN or WPA element.
#[derive(Default)]
struct KeyMgmt {
    akms: Vec<([u8; 3], u8)>,
    mfp_required: bool,
}

/// Parses the body shared by the RSN element and (after its 4-byte header)
/// the WPA element. Every field after the version is optional.
fn parse_key_mgmt(body: &[u8]) -> Option<KeyMgmt> {
    let mut r = Reader(body);
    r.u16()?; // version
    let mut out = KeyMgmt::default();
    let mut rest = || -> Option<()> {
        r.suite()?; // group cipher
        let pairwise = r.u16()?;
        for _ in 0..pairwise {
            r.suite()?;
        }
        let akms = r.u16()?;
        for _ in 0..akms {
            out.akms.push(r.suite()?);
        }
        let caps = r.u16()?;
        out.mfp_required = caps & 0x0040 != 0;
        Some(())
    };
    let _ = rest();
    Some(out)
}

const OUI_IEEE: [u8; 3] = [0x00, 0x0F, 0xAC];
const OUI_MICROSOFT: [u8; 3] = [0x00, 0x50, 0xF2];
const OUI_WFA: [u8; 3] = [0x50, 0x6F, 0x9A];

/// The security of a network from its RSN / WPA elements and the privacy bit
/// of the capability field.
pub fn security_from_ies(ies: &[u8], capability: u16) -> String {
    let mut rsn: Option<KeyMgmt> = None;
    let mut wpa: Option<KeyMgmt> = None;
    for (id, body) in elements(ies) {
        if id == ID_RSN && rsn.is_none() {
            rsn = parse_key_mgmt(body);
        } else if id == ID_VENDOR
            && wpa.is_none()
            && body.get(..4) == Some(&[0x00, 0x50, 0xF2, 0x01])
        {
            wpa = body.get(4..).and_then(parse_key_mgmt);
        }
    }
    let wpa_psk = wpa
        .as_ref()
        .is_some_and(|w| w.akms.contains(&(OUI_MICROSOFT, 2)));
    let wpa_enterprise = wpa
        .as_ref()
        .is_some_and(|w| w.akms.is_empty() || w.akms.contains(&(OUI_MICROSOFT, 1)));

    if let Some(rsn) = rsn {
        let has = |types: &[u8]| {
            rsn.akms
                .iter()
                .any(|(oui, t)| *oui == OUI_IEEE && types.contains(t))
        };
        let sae = has(&[8, 9, 24, 25]);
        let psk = has(&[2, 4, 6]);
        let suite_b = has(&[11, 12, 13]);
        let one_x = has(&[1, 3]);
        let one_x_sha256 = has(&[5]);
        let owe = has(&[18]);
        let dpp = rsn.akms.contains(&(OUI_WFA, 2));
        let label = if sae && psk {
            "WPA2/WPA3-Personal"
        } else if sae {
            "WPA3-Personal"
        } else if psk {
            if wpa_psk {
                "WPA/WPA2-Personal"
            } else {
                "WPA2-Personal"
            }
        } else if suite_b || (one_x_sha256 && !one_x && rsn.mfp_required) {
            "WPA3-Enterprise"
        } else if one_x || one_x_sha256 || rsn.akms.is_empty() {
            // An RSN element without a key-management list means 802.1X.
            if wpa_enterprise && wpa.is_some() {
                "WPA/WPA2-Enterprise"
            } else {
                "WPA2-Enterprise"
            }
        } else if owe {
            "OWE"
        } else if dpp {
            "DPP"
        } else {
            "WPA2 (unknown key management)"
        };
        return label.to_string();
    }
    if wpa.is_some() {
        return if wpa_psk {
            "WPA-Personal"
        } else {
            "WPA-Enterprise"
        }
        .to_string();
    }
    let label = if capability & 0x0010 != 0 {
        "WEP"
    } else {
        "Open"
    };
    label.to_string()
}

fn base_of(band: Band) -> u32 {
    match band {
        Band::B24 => 2407,
        Band::B5 => 5000,
        Band::B6 => 5950,
    }
}

fn centre_from_channel(band: Band, channel: u8) -> Option<u32> {
    if channel == 0 {
        None
    } else {
        Some(base_of(band) + 5 * u32::from(channel))
    }
}

/// Width and centre from VHT-style operation information
/// (channel width, centre segment 0, centre segment 1).
fn vht_width(band: Band, cw: u8, seg0: u8, seg1: u8) -> Option<(u16, Option<u32>)> {
    match cw {
        1 => {
            let gap = seg0.abs_diff(seg1);
            if seg1 != 0 && gap == 8 {
                // 160 MHz: segment 1 is the centre of the whole channel.
                Some((160, centre_from_channel(band, seg1)))
            } else if seg1 != 0 && gap > 16 {
                // 80+80 MHz: two separate blocks; report the primary one's centre.
                Some((160, centre_from_channel(band, seg0)))
            } else {
                Some((80, centre_from_channel(band, seg0)))
            }
        }
        2 | 3 => Some((160, centre_from_channel(band, seg0))),
        _ => None,
    }
}

/// Reads everything this program shows from the information elements.
///
/// `capability` is the capability field of the beacon and `freq_mhz` the
/// centre frequency of the primary channel.
pub fn parse(ies: &[u8], capability: u16, freq_mhz: u32) -> IeInfo {
    let band = channel_from_freq(freq_mhz).map(|(b, _)| b);
    let mut info = IeInfo {
        security: security_from_ies(ies, capability),
        ..IeInfo::default()
    };

    let mut max_rate_units = 0u8;
    let (mut ht_cap, mut vht_cap, mut he_cap, mut eht) = (false, false, false, false);
    let mut ht_op: Option<&[u8]> = None;
    let mut vht_op: Option<&[u8]> = None;
    let mut he_op: Option<&[u8]> = None;
    let mut eht_op: Option<&[u8]> = None;

    for (id, body) in elements(ies) {
        match id {
            ID_RATES | ID_EXT_RATES => {
                for &b in body {
                    let units = b & 0x7F;
                    // Values above 54 Mbit/s are membership selectors, not rates.
                    if units <= 108 {
                        max_rate_units = max_rate_units.max(units);
                    }
                }
            }
            ID_COUNTRY => {
                if let Some(&[a, b]) = body.get(..2) {
                    if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() {
                        info.country = Some(
                            [
                                a.to_ascii_uppercase() as char,
                                b.to_ascii_uppercase() as char,
                            ]
                            .iter()
                            .collect(),
                        );
                    }
                }
            }
            ID_BSS_LOAD => {
                if let Some(&[s0, s1, util]) = body.get(..3) {
                    info.stations = Some(u16::from_le_bytes([s0, s1]));
                    info.utilization = Some(((u32::from(util) * 100 + 127) / 255) as u8);
                }
            }
            ID_HT_CAP => ht_cap = true,
            ID_HT_OP => ht_op = Some(body),
            ID_VHT_CAP => vht_cap = true,
            ID_VHT_OP => vht_op = Some(body),
            ID_EXTENSION => match body.split_first() {
                Some((&EXT_HE_CAP, _)) => he_cap = true,
                Some((&EXT_HE_OP, rest)) => he_op = Some(rest),
                Some((&EXT_EHT_CAP, _)) => eht = true,
                Some((&EXT_EHT_OP, rest)) => {
                    eht = true;
                    eht_op = Some(rest);
                }
                _ => {}
            },
            _ => {}
        }
    }

    if max_rate_units > 0 {
        info.max_rate_mbps = Some(f32::from(max_rate_units) / 2.0);
    }

    // Channel width: start at 20 MHz and let each newer element widen it.
    let mut width: u16 = 20;
    let mut centre: Option<u32> = Some(freq_mhz).filter(|f| *f > 0);
    if let Some(&[_, flags]) = ht_op.and_then(|b| b.get(..2)) {
        match flags & 0x03 {
            1 => {
                width = 40;
                centre = Some(freq_mhz.saturating_add(10));
            }
            3 => {
                width = 40;
                centre = Some(freq_mhz.saturating_sub(10));
            }
            _ => {}
        }
    }
    if band == Some(Band::B5) {
        if let Some(&[cw, seg0, seg1]) = vht_op.and_then(|b| b.get(..3)) {
            if let Some((w, c)) = vht_width(Band::B5, cw, seg0, seg1) {
                width = w;
                centre = c;
            }
        }
    }
    if let Some(he) = he_op {
        // HE Operation: parameters (3), BSS colour (1), basic MCS set (2),
        // then optional parts announced by bits of the parameters.
        if let Some(&[p0, p1, p2]) = he.get(..3) {
            let params = u32::from(p0) | u32::from(p1) << 8 | u32::from(p2) << 16;
            let mut at = 6usize;
            if params & (1 << 14) != 0 {
                if band == Some(Band::B5) && vht_op.is_none() {
                    if let Some(&[cw, seg0, seg1]) = he.get(at..at + 3) {
                        if let Some((w, c)) = vht_width(Band::B5, cw, seg0, seg1) {
                            width = w;
                            centre = c;
                        }
                    }
                }
                at += 3;
            }
            if params & (1 << 15) != 0 {
                at += 1;
            }
            if params & (1 << 17) != 0 && band == Some(Band::B6) {
                // 6 GHz operation information: primary channel, control,
                // centre segment 0, centre segment 1, minimum rate.
                if let Some(&[_, control, seg0, seg1]) = he.get(at..at + 4) {
                    let (w, c) = match control & 0x03 {
                        0 => (20, seg0),
                        1 => (40, seg0),
                        2 => (80, seg0),
                        _ => (160, if seg1 != 0 { seg1 } else { seg0 }),
                    };
                    width = w;
                    centre = centre_from_channel(Band::B6, c);
                }
            }
        }
    }
    if let Some(op) = eht_op {
        // EHT Operation: parameters (1), basic EHT-MCS and NSS set (4), then
        // the operation information when bit 0 of the parameters is set.
        if op.first().is_some_and(|p| p & 0x01 != 0) {
            if let (Some(&[control, ccfs0, ccfs1]), Some(band)) = (op.get(5..8), band) {
                let w = match control & 0x07 {
                    0 => Some(20u16),
                    1 => Some(40),
                    2 => Some(80),
                    3 => Some(160),
                    4 => Some(320),
                    _ => None,
                };
                if let Some(w) = w {
                    width = w;
                    let c = if ccfs1 != 0 { ccfs1 } else { ccfs0 };
                    centre = centre_from_channel(band, c).or(centre);
                }
            }
        }
    }

    let (phy, generation) = if eht {
        ("802.11be", Some(7))
    } else if he_cap || he_op.is_some() {
        ("802.11ax", Some(6))
    } else if (vht_cap || vht_op.is_some()) && band != Some(Band::B24) {
        ("802.11ac", Some(5))
    } else if ht_cap || ht_op.is_some() {
        ("802.11n", Some(4))
    } else if band == Some(Band::B24) {
        // 802.11b tops out at 11 Mbit/s (22 half-megabit units).
        if max_rate_units > 22 {
            ("802.11g", None)
        } else {
            ("802.11b", None)
        }
    } else {
        ("802.11a", None)
    };
    info.phy = phy.to_string();
    info.generation = generation;
    if !ies.is_empty() {
        info.width_mhz = Some(width);
        info.center_mhz = centre;
    }
    info
}

#[cfg(test)]
pub(crate) mod testdata {
    //! Builders for fabricated information elements.

    pub fn ie(id: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![id, body.len() as u8];
        out.extend_from_slice(body);
        out
    }

    pub fn ext(ext_id: u8, body: &[u8]) -> Vec<u8> {
        let mut inner = vec![ext_id];
        inner.extend_from_slice(body);
        ie(255, &inner)
    }

    /// An RSN element with CCMP ciphers and the given IEEE AKM suite types.
    pub fn rsn(akms: &[u8], caps: u16) -> Vec<u8> {
        let mut body = vec![1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 4];
        body.extend_from_slice(&(akms.len() as u16).to_le_bytes());
        for &a in akms {
            body.extend_from_slice(&[0x00, 0x0F, 0xAC, a]);
        }
        body.extend_from_slice(&caps.to_le_bytes());
        ie(48, &body)
    }

    /// A WPA (version 1) vendor element with TKIP and the given AKM type.
    pub fn wpa(akm: u8) -> Vec<u8> {
        let body = [
            0x00, 0x50, 0xF2, 0x01, 1, 0, 0x00, 0x50, 0xF2, 2, 1, 0, 0x00, 0x50, 0xF2, 2, 1, 0,
            0x00, 0x50, 0xF2, akm,
        ];
        ie(221, &body)
    }

    pub fn ht_cap() -> Vec<u8> {
        ie(45, &[0u8; 26])
    }

    /// HT operation with the given primary channel and secondary offset (0, 1 above, 3 below).
    pub fn ht_op(primary: u8, offset: u8) -> Vec<u8> {
        let mut body = [0u8; 22];
        body[0] = primary;
        body[1] = offset | if offset != 0 { 0x04 } else { 0 };
        ie(61, &body)
    }

    pub fn vht_cap() -> Vec<u8> {
        ie(191, &[0u8; 12])
    }

    pub fn vht_op(cw: u8, seg0: u8, seg1: u8) -> Vec<u8> {
        ie(192, &[cw, seg0, seg1, 0, 0])
    }

    pub fn he_cap() -> Vec<u8> {
        ext(35, &[0u8; 21])
    }

    /// HE operation; `six_ghz` is (primary, control, seg0, seg1).
    pub fn he_op(six_ghz: Option<(u8, u8, u8, u8)>) -> Vec<u8> {
        let mut body = vec![0u8, 0, 0, 0x01, 0xFC, 0xFF];
        if let Some((primary, control, seg0, seg1)) = six_ghz {
            body[2] |= 0x02; // bit 17: 6 GHz operation information present
            body.extend_from_slice(&[primary, control, seg0, seg1, 0]);
        }
        ext(36, &body)
    }

    pub fn eht_cap() -> Vec<u8> {
        ext(108, &[0u8; 11])
    }

    /// EHT operation with operation information (width code, CCFS0, CCFS1).
    pub fn eht_op(width_code: u8, ccfs0: u8, ccfs1: u8) -> Vec<u8> {
        ext(106, &[0x01, 0, 0, 0, 0, width_code, ccfs0, ccfs1])
    }

    pub fn rates(units: &[u8]) -> Vec<u8> {
        ie(1, units)
    }
}

#[cfg(test)]
mod tests {
    use super::testdata::*;
    use super::*;

    const PRIVACY: u16 = 0x0011;
    const OPEN: u16 = 0x0001;

    fn join(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }

    #[test]
    fn walker_stops_at_truncation() {
        let mut blob = join(&[ie(0, b"Maple-Home"), ie(1, &[0x82, 0x84])]);
        assert_eq!(elements(&blob).count(), 2);
        blob.extend_from_slice(&[48, 20, 1, 0]); // claims 20 bytes, has 2
        assert_eq!(elements(&blob).count(), 2);
        assert_eq!(elements(&[]).count(), 0);
        assert_eq!(elements(&[7]).count(), 0);
        assert_eq!(elements(&[7, 0]).count(), 1);
    }

    #[test]
    fn open_and_wep() {
        assert_eq!(security_from_ies(&[], OPEN), "Open");
        assert_eq!(security_from_ies(&[], PRIVACY), "WEP");
        assert_eq!(security_from_ies(&ie(0, b"Cafe Guest"), OPEN), "Open");
    }

    #[test]
    fn personal_networks() {
        assert_eq!(security_from_ies(&wpa(2), PRIVACY), "WPA-Personal");
        assert_eq!(security_from_ies(&rsn(&[2], 0), PRIVACY), "WPA2-Personal");
        assert_eq!(
            security_from_ies(&rsn(&[6], 0x80), PRIVACY),
            "WPA2-Personal"
        );
        assert_eq!(
            security_from_ies(&join(&[wpa(2), rsn(&[2], 0)]), PRIVACY),
            "WPA/WPA2-Personal"
        );
        assert_eq!(
            security_from_ies(&rsn(&[8], 0xC0), PRIVACY),
            "WPA3-Personal"
        );
        assert_eq!(
            security_from_ies(&rsn(&[24], 0xC0), PRIVACY),
            "WPA3-Personal"
        );
        assert_eq!(
            security_from_ies(&rsn(&[2, 8], 0x80), PRIVACY),
            "WPA2/WPA3-Personal"
        );
        assert_eq!(
            security_from_ies(&rsn(&[4, 9], 0x80), PRIVACY),
            "WPA2/WPA3-Personal"
        );
    }

    #[test]
    fn enterprise_and_owe() {
        assert_eq!(security_from_ies(&wpa(1), PRIVACY), "WPA-Enterprise");
        assert_eq!(security_from_ies(&rsn(&[1], 0), PRIVACY), "WPA2-Enterprise");
        assert_eq!(
            security_from_ies(&rsn(&[1, 5], 0x80), PRIVACY),
            "WPA2-Enterprise"
        );
        assert_eq!(
            security_from_ies(&rsn(&[5], 0xC0), PRIVACY),
            "WPA3-Enterprise"
        );
        assert_eq!(
            security_from_ies(&rsn(&[12], 0xC0), PRIVACY),
            "WPA3-Enterprise"
        );
        assert_eq!(security_from_ies(&rsn(&[18], 0xC0), PRIVACY), "OWE");
        assert_eq!(
            security_from_ies(&join(&[wpa(1), rsn(&[1], 0)]), PRIVACY),
            "WPA/WPA2-Enterprise"
        );
    }

    #[test]
    fn truncated_rsn_does_not_panic() {
        let full = rsn(&[2, 8], 0x80);
        for cut in 0..full.len() {
            let mut blob = full.get(..cut).unwrap_or(&[]).to_vec();
            // Fix up the length byte so the element itself is well formed.
            if let Some(len) = blob.get_mut(1) {
                *len = cut.saturating_sub(2) as u8;
            }
            let label = security_from_ies(&blob, PRIVACY);
            assert!(!label.is_empty());
        }
        // A suite count far larger than the element.
        let liar = ie(48, &[1, 0, 0, 0x0F, 0xAC, 4, 0xFF, 0xFF, 0, 0x0F, 0xAC, 4]);
        assert_eq!(security_from_ies(&liar, PRIVACY), "WPA2-Enterprise");
    }

    #[test]
    fn legacy_phys() {
        let b = parse(&rates(&[0x82, 0x84, 0x8B, 0x96]), OPEN, 2412);
        assert_eq!(
            (b.phy.as_str(), b.generation, b.width_mhz),
            ("802.11b", None, Some(20))
        );
        assert_eq!(b.max_rate_mbps, Some(11.0));
        let g = parse(
            &join(&[
                rates(&[0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]),
                ie(50, &[0x30, 0x48, 0x60, 0x6C]),
            ]),
            OPEN,
            2437,
        );
        assert_eq!(g.phy, "802.11g");
        assert_eq!(g.max_rate_mbps, Some(54.0));
        let a = parse(
            &rates(&[0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C]),
            OPEN,
            5180,
        );
        assert_eq!((a.phy.as_str(), a.generation), ("802.11a", None));
        assert_eq!(a.center_mhz, Some(5180));
    }

    #[test]
    fn membership_selectors_are_not_rates() {
        // 0xFF = "HT PHY required", 0xFB = "SAE hash-to-element only".
        let info = parse(&rates(&[0x8C, 0x98, 0xFF, 0xFB]), OPEN, 5180);
        assert_eq!(info.max_rate_mbps, Some(12.0));
    }

    #[test]
    fn ht_widths() {
        let n20 = parse(&join(&[ht_cap(), ht_op(6, 0)]), OPEN, 2437);
        assert_eq!(
            (n20.phy.as_str(), n20.generation, n20.width_mhz),
            ("802.11n", Some(4), Some(20))
        );
        assert_eq!(n20.center_mhz, Some(2437));
        let above = parse(&join(&[ht_cap(), ht_op(1, 1)]), OPEN, 2412);
        assert_eq!((above.width_mhz, above.center_mhz), (Some(40), Some(2422)));
        let below = parse(&join(&[ht_cap(), ht_op(11, 3)]), OPEN, 2462);
        assert_eq!((below.width_mhz, below.center_mhz), (Some(40), Some(2452)));
    }

    #[test]
    fn vht_widths() {
        let base = |op: Vec<u8>| join(&[ht_cap(), ht_op(36, 1), vht_cap(), op]);
        let w40 = parse(&base(vht_op(0, 0, 0)), OPEN, 5180);
        assert_eq!((w40.phy.as_str(), w40.generation), ("802.11ac", Some(5)));
        assert_eq!((w40.width_mhz, w40.center_mhz), (Some(40), Some(5190)));
        let w80 = parse(&base(vht_op(1, 42, 0)), OPEN, 5180);
        assert_eq!((w80.width_mhz, w80.center_mhz), (Some(80), Some(5210)));
        let w160 = parse(&base(vht_op(1, 42, 50)), OPEN, 5180);
        assert_eq!((w160.width_mhz, w160.center_mhz), (Some(160), Some(5250)));
        let old160 = parse(&base(vht_op(2, 50, 0)), OPEN, 5180);
        assert_eq!(
            (old160.width_mhz, old160.center_mhz),
            (Some(160), Some(5250))
        );
        let plus = parse(&base(vht_op(1, 42, 155)), OPEN, 5180);
        assert_eq!((plus.width_mhz, plus.center_mhz), (Some(160), Some(5210)));
    }

    #[test]
    fn vht_in_24_ghz_is_still_wifi_4() {
        let info = parse(
            &join(&[ht_cap(), ht_op(6, 0), vht_cap(), vht_op(1, 42, 0)]),
            OPEN,
            2437,
        );
        assert_eq!(
            (info.phy.as_str(), info.generation, info.width_mhz),
            ("802.11n", Some(4), Some(20))
        );
    }

    #[test]
    fn he_and_6_ghz() {
        let ax5 = parse(
            &join(&[
                ht_cap(),
                ht_op(36, 1),
                vht_cap(),
                vht_op(1, 42, 0),
                he_cap(),
                he_op(None),
            ]),
            OPEN,
            5180,
        );
        assert_eq!(
            (ax5.phy.as_str(), ax5.generation, ax5.width_mhz),
            ("802.11ax", Some(6), Some(80))
        );
        // 6 GHz, primary channel 37 (6135 MHz), 160 MHz centred on channel 47.
        let ax6 = parse(&join(&[he_cap(), he_op(Some((37, 3, 39, 47)))]), OPEN, 6135);
        assert_eq!((ax6.phy.as_str(), ax6.generation), ("802.11ax", Some(6)));
        assert_eq!((ax6.width_mhz, ax6.center_mhz), (Some(160), Some(6185)));
        let ax6_80 = parse(&join(&[he_cap(), he_op(Some((5, 2, 7, 0)))]), OPEN, 5975);
        assert_eq!(
            (ax6_80.width_mhz, ax6_80.center_mhz),
            (Some(80), Some(5985))
        );
    }

    #[test]
    fn eht_widths() {
        // 6 GHz, 320 MHz centred on channel 63.
        let be = parse(
            &join(&[
                he_cap(),
                he_op(Some((37, 3, 39, 47))),
                eht_cap(),
                eht_op(4, 47, 63),
            ]),
            OPEN,
            6135,
        );
        assert_eq!((be.phy.as_str(), be.generation), ("802.11be", Some(7)));
        assert_eq!((be.width_mhz, be.center_mhz), (Some(320), Some(6265)));
        // EHT capabilities alone still name the PHY.
        let only_cap = parse(&join(&[ht_cap(), eht_cap()]), OPEN, 2437);
        assert_eq!(
            (only_cap.generation, only_cap.width_mhz),
            (Some(7), Some(20))
        );
        // Operation element without operation information changes nothing.
        let no_info = parse(&join(&[he_cap(), ext(106, &[0, 0, 0, 0, 0])]), OPEN, 5180);
        assert_eq!(no_info.width_mhz, Some(20));
    }

    #[test]
    fn bss_load_country_and_rates() {
        let blob = join(&[
            ie(7, b"de\x20\x01\x0d\x14"),
            ie(11, &[7, 0, 128, 0, 0]),
            rates(&[0x82, 0x0C, 0x6C]),
        ]);
        let info = parse(&blob, OPEN, 2412);
        assert_eq!(info.country.as_deref(), Some("DE"));
        assert_eq!(info.stations, Some(7));
        assert_eq!(info.utilization, Some(50));
        assert_eq!(info.max_rate_mbps, Some(54.0));
        let full = parse(&ie(11, &[0xFF, 0xFF, 255, 0, 0]), OPEN, 2412);
        assert_eq!((full.stations, full.utilization), (Some(0xFFFF), Some(100)));
        // Junk in the country element is ignored.
        assert_eq!(parse(&ie(7, &[0x00, 0x01, 0x20]), OPEN, 2412).country, None);
        assert_eq!(parse(&ie(7, b"U"), OPEN, 2412).country, None);
    }

    #[test]
    fn empty_blob_gives_no_width() {
        let info = parse(&[], OPEN, 2412);
        assert_eq!(info.width_mhz, None);
        assert_eq!(info.center_mhz, None);
        assert_eq!(info.security, "Open");
        assert_eq!(info.max_rate_mbps, None);
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // A cheap deterministic generator: every prefix of several noisy blobs.
        let mut state = 0x2545_F491u32;
        let mut noise = Vec::new();
        for _ in 0..600 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            noise.push((state >> 8) as u8);
        }
        for start in (0..noise.len()).step_by(7) {
            let blob = noise.get(start..).unwrap_or(&[]);
            for freq in [0, 2412, 5180, 6135, u32::MAX] {
                let _ = parse(blob, 0xFFFF, freq);
            }
        }
        // Elements that are present but too short for their fixed parts.
        for id in [1u8, 7, 11, 45, 48, 50, 61, 191, 192, 221, 255] {
            for len in 0..6usize {
                let body = vec![0xFFu8; len];
                let _ = parse(&ie(id, &body), 0, 5180);
                let _ = parse(&ext(36, &body), 0, 6135);
                let _ = parse(&ext(106, &body), 0, 6135);
            }
        }
    }
}
