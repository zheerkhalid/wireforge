//! Frequencies, channels, signal maths, occupancy (pure, unit-tested).

use crate::types::*;

/// Centre frequency in MHz to band and channel number.
///
/// 2.4 GHz: channels 1..=13 at 2407 + 5 x channel, channel 14 at 2484.
/// 5 GHz: 5000 + 5 x channel (channels 32..=177).
/// 6 GHz: 5950 + 5 x channel (channels 1..=233), plus channel 2 at 5935.
pub fn channel_from_freq(mhz: u32) -> Option<(Band, u16)> {
    match mhz {
        2484 => Some((Band::B24, 14)),
        2412..=2472 if (mhz - 2407).is_multiple_of(5) => {
            Some((Band::B24, ((mhz - 2407) / 5) as u16))
        }
        5160..=5885 if mhz.is_multiple_of(5) => Some((Band::B5, ((mhz - 5000) / 5) as u16)),
        5935 => Some((Band::B6, 2)),
        // Channel number 2 belongs to the special channel at 5935 MHz.
        5960 => None,
        5955..=7115 if mhz.is_multiple_of(5) => Some((Band::B6, ((mhz - 5950) / 5) as u16)),
        _ => None,
    }
}

/// Channel number to centre frequency in MHz (see [`channel_from_freq`]).
///
/// In 6 GHz, channel 2 is the special 20 MHz channel at 5935 MHz.
pub fn freq_from_channel(band: Band, channel: u16) -> Option<u32> {
    let ch = u32::from(channel);
    match band {
        Band::B24 => match channel {
            1..=13 => Some(2407 + 5 * ch),
            14 => Some(2484),
            _ => None,
        },
        Band::B5 => match channel {
            32..=177 => Some(5000 + 5 * ch),
            _ => None,
        },
        Band::B6 => match channel {
            2 => Some(5935),
            1..=233 => Some(5950 + 5 * ch),
            _ => None,
        },
    }
}

/// Windows' convention: -100 dBm = 0 %, -50 dBm = 100 %, linear between.
pub fn quality_from_rssi(dbm: i32) -> u8 {
    (dbm.clamp(-100, -50) + 100).saturating_mul(2).clamp(0, 100) as u8
}

/// The inverse of [`quality_from_rssi`].
pub fn rssi_from_quality(quality: u8) -> i32 {
    -100 + i32::from(quality.min(100)) / 2
}

/// "Excellent", "Good", "Fair", "Weak".
pub fn signal_word(dbm: i32) -> &'static str {
    match dbm {
        d if d >= -55 => "Excellent",
        d if d >= -67 => "Good",
        d if d >= -75 => "Fair",
        _ => "Weak",
    }
}

/// 5 GHz channels on which a router must watch for radar (52..=144).
pub fn is_dfs(band: Band, channel: u16) -> bool {
    band == Band::B5 && (52..=144).contains(&channel)
}

/// The 20 MHz channels of the 5 GHz band shown by default.
const CHANNELS_5: [u16; 25] = [
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
];

/// The channels a band's table starts with (before channels in use are added).
pub fn standard_channels(band: Band) -> Vec<u16> {
    match band {
        Band::B24 => (1..=13).collect(),
        Band::B5 => CHANNELS_5.to_vec(),
        // Preferred scanning channels: every fourth 20 MHz channel.
        Band::B6 => (0..15).map(|k| 5 + 16 * k).collect(),
    }
}

/// How much a network's signal counts: 1.0 at -50 dBm and above, falling to a
/// small floor for barely audible networks (they still take air time).
fn signal_weight(dbm: i32) -> f32 {
    (f32::from(quality_from_rssi(dbm)) / 100.0).max(0.05)
}

/// The frequency range (low, high edge in MHz) a network occupies.
///
/// Uses the centre the beacon gave when it is plausible; otherwise the
/// standard channel plan decides where a wide channel lies.
pub fn span_mhz(bss: &Bss) -> (f32, f32) {
    let width = u32::from(bss.width_mhz.unwrap_or(20).clamp(20, 320));
    let freq = bss.freq_mhz;
    let half = width as f32 / 2.0;
    let plausible = |c: u32| c.abs_diff(freq).saturating_add(10) <= width / 2 + 1;
    let centre = match bss.center_mhz {
        Some(c) if plausible(c) => c as f32,
        _ => planned_centre(bss.band, bss.channel, width).unwrap_or(freq as f32),
    };
    (centre - half, centre + half)
}

/// Centre frequency of the standard bonded channel that contains `channel`.
fn planned_centre(band: Band, channel: u16, width: u32) -> Option<f32> {
    if width <= 20 {
        return None;
    }
    let group = width / 20;
    let (first, base) = match band {
        Band::B24 => return None,
        Band::B5 => match channel {
            36..=144 => (36u32, 5000u32),
            149..=177 => (149, 5000),
            _ => return None,
        },
        Band::B6 => match channel {
            1..=233 => (1, 5950),
            _ => return None,
        },
    };
    let index = (u32::from(channel).checked_sub(first)?) / 4;
    let start = first + 4 * (index - index % group);
    let low_centre = base + 5 * start;
    Some(low_centre as f32 - 10.0 + width as f32 / 2.0)
}

/// How strongly `bss` disturbs the 20 MHz channel centred on `mhz` (0..=1,
/// before the signal weight).
///
/// 2.4 GHz channels are 5 MHz apart but 20 MHz wide, so a network disturbs
/// its four neighbours on each side with falling weight (1, 0.8, 0.6, 0.4,
/// 0.2). In 5 and 6 GHz channels do not overlap: a network counts fully on
/// every 20 MHz channel inside its width and not at all elsewhere.
fn overlap(bss: &Bss, mhz: u32) -> f32 {
    let (low, high) = span_mhz(bss);
    let x = mhz as f32;
    match bss.band {
        Band::B24 => {
            let centre = (low + high) / 2.0;
            let extra = ((high - low) - 20.0).max(0.0) / 2.0;
            let distance = ((x - centre).abs() - extra).max(0.0);
            (1.0 - distance / 25.0).clamp(0.0, 1.0)
        }
        Band::B5 | Band::B6 => {
            if x + 10.0 > low + 0.5 && x - 10.0 < high - 0.5 {
                1.0
            } else {
                0.0
            }
        }
    }
}

/// Interference score of one channel and how many networks contribute.
fn channel_score(networks: &[Bss], band: Band, channel: u16) -> (f32, u32) {
    let Some(mhz) = freq_from_channel(band, channel) else {
        return (0.0, 0);
    };
    let mut score = 0.0f32;
    let mut overlapping = 0u32;
    for bss in networks.iter().filter(|b| b.band == band) {
        let o = overlap(bss, mhz);
        if o > 0.0 {
            score += o * signal_weight(bss.rssi_dbm);
            overlapping += 1;
        }
    }
    (score, overlapping)
}

/// The channels worth showing for a band (2.4 GHz: 1..=13; 5 GHz: the
/// 20 MHz channels 36..=165; 6 GHz: the preferred scanning channels plus
/// any channel in use), each with its load.
pub fn occupancy(networks: &[Bss], band: Band) -> Vec<ChannelLoad> {
    let mut channels = standard_channels(band);
    for bss in networks.iter().filter(|b| b.band == band) {
        if freq_from_channel(band, bss.channel).is_some() && !channels.contains(&bss.channel) {
            channels.push(bss.channel);
        }
    }
    channels.sort_unstable();
    channels
        .into_iter()
        .map(|channel| {
            let on_channel = networks
                .iter()
                .filter(|b| b.band == band && b.channel == channel);
            let count = on_channel.clone().count() as u32;
            let strongest = on_channel.map(|b| b.rssi_dbm).max();
            let (score, _) = channel_score(networks, band, channel);
            ChannelLoad {
                channel,
                networks: count,
                score,
                strongest_dbm: strongest,
            }
        })
        .collect()
}

fn plural(n: u32) -> String {
    if n == 1 {
        "1 network overlaps it".to_string()
    } else {
        format!("{n} networks overlap it")
    }
}

/// The least crowded channel of a band (2.4 GHz only ever suggests 1, 6 or 11).
///
/// 5 GHz prefers a channel without radar duties (non-DFS) when it is as quiet
/// as the quietest DFS channel, and says so when the pick is a DFS channel.
/// 6 GHz gives `None` when no 6 GHz network was seen: the scan cannot tell
/// whether this PC or the router can use that band at all.
pub fn best_channel(networks: &[Bss], band: Band) -> Option<ChannelSuggestion> {
    const TIE: f32 = 0.005;
    let in_band = networks.iter().filter(|b| b.band == band).count();
    let candidates: Vec<u16> = match band {
        Band::B24 => vec![1, 6, 11],
        Band::B5 => CHANNELS_5.to_vec(),
        Band::B6 => {
            if in_band == 0 {
                return None;
            }
            standard_channels(Band::B6)
        }
    };
    let scored: Vec<(u16, f32, u32)> = candidates
        .iter()
        .map(|&c| {
            let (score, n) = channel_score(networks, band, c);
            (c, score, n)
        })
        .collect();
    let lowest = scored.iter().map(|s| s.1).fold(f32::INFINITY, f32::min);
    // Among the (near) ties: non-DFS first, then fewer overlapping networks,
    // then the lower channel.
    let &(channel, _, overlapping) = scored
        .iter()
        .filter(|s| s.1 <= lowest + TIE)
        .min_by_key(|s| (is_dfs(band, s.0), s.2, s.0))?;

    let reason = match band {
        Band::B24 => {
            if in_band == 0 {
                format!(
                    "No 2.4 GHz networks were seen, so channel {channel} is as good as the other non-overlapping channels (1, 6 and 11)."
                )
            } else if overlapping == 0 {
                format!(
                    "Channel {channel} is free: none of the {in_band} networks nearby overlap it (only 1, 6 and 11 are suggested because they do not overlap each other)."
                )
            } else {
                format!(
                    "Channel {channel} has the least interference of the non-overlapping channels 1, 6 and 11 ({} out of {in_band} nearby).",
                    plural(overlapping)
                )
            }
        }
        Band::B5 => {
            if is_dfs(band, channel) {
                let fallback = scored
                    .iter()
                    .filter(|s| !is_dfs(band, s.0))
                    .min_by(|a, b| a.1.total_cmp(&b.1).then(a.0.cmp(&b.0)))
                    .map(|s| s.0)
                    .unwrap_or(36);
                format!(
                    "Channel {channel} is the quietest 5 GHz channel ({}), but it is a DFS channel: the router must give way to radar there and may switch away by itself; the quietest channel without that duty is {fallback}.",
                    plural(overlapping)
                )
            } else if overlapping == 0 {
                format!(
                    "Channel {channel} is free (no network overlaps it) and it is not a DFS channel, so the router never has to leave it for radar."
                )
            } else {
                format!(
                    "Channel {channel} is the quietest 5 GHz channel ({}) and it is not a DFS channel, so the router never has to leave it for radar.",
                    plural(overlapping)
                )
            }
        }
        Band::B6 => {
            if overlapping == 0 {
                format!(
                    "Channel {channel} is the first free one of the preferred 6 GHz scanning channels: no network overlaps it."
                )
            } else {
                format!(
                    "Channel {channel} is the quietest of the preferred 6 GHz scanning channels ({}).",
                    plural(overlapping)
                )
            }
        }
    };
    Some(ChannelSuggestion {
        band,
        channel,
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(band: Band, channel: u16, dbm: i32, width: u16) -> Bss {
        Bss {
            ssid: format!("Test-{channel}"),
            band,
            channel,
            freq_mhz: freq_from_channel(band, channel).unwrap_or(0),
            rssi_dbm: dbm,
            quality: quality_from_rssi(dbm),
            width_mhz: Some(width),
            ..Default::default()
        }
    }

    #[test]
    fn band_24_frequencies() {
        assert_eq!(channel_from_freq(2412), Some((Band::B24, 1)));
        assert_eq!(channel_from_freq(2437), Some((Band::B24, 6)));
        assert_eq!(channel_from_freq(2462), Some((Band::B24, 11)));
        assert_eq!(channel_from_freq(2472), Some((Band::B24, 13)));
        assert_eq!(channel_from_freq(2484), Some((Band::B24, 14)));
        assert_eq!(channel_from_freq(2407), None);
        assert_eq!(channel_from_freq(2413), None);
        assert_eq!(channel_from_freq(2477), None);
        assert_eq!(freq_from_channel(Band::B24, 1), Some(2412));
        assert_eq!(freq_from_channel(Band::B24, 13), Some(2472));
        assert_eq!(freq_from_channel(Band::B24, 14), Some(2484));
        assert_eq!(freq_from_channel(Band::B24, 0), None);
        assert_eq!(freq_from_channel(Band::B24, 15), None);
    }

    #[test]
    fn band_5_frequencies() {
        assert_eq!(channel_from_freq(5180), Some((Band::B5, 36)));
        assert_eq!(channel_from_freq(5210), Some((Band::B5, 42)));
        assert_eq!(channel_from_freq(5500), Some((Band::B5, 100)));
        assert_eq!(channel_from_freq(5745), Some((Band::B5, 149)));
        assert_eq!(channel_from_freq(5825), Some((Band::B5, 165)));
        assert_eq!(channel_from_freq(5885), Some((Band::B5, 177)));
        assert_eq!(channel_from_freq(5182), None);
        assert_eq!(channel_from_freq(5890), None);
        assert_eq!(freq_from_channel(Band::B5, 36), Some(5180));
        assert_eq!(freq_from_channel(Band::B5, 165), Some(5825));
        assert_eq!(freq_from_channel(Band::B5, 31), None);
        assert_eq!(freq_from_channel(Band::B5, 178), None);
    }

    #[test]
    fn band_6_frequencies() {
        assert_eq!(channel_from_freq(5935), Some((Band::B6, 2)));
        assert_eq!(channel_from_freq(5955), Some((Band::B6, 1)));
        assert_eq!(channel_from_freq(5975), Some((Band::B6, 5)));
        assert_eq!(channel_from_freq(6115), Some((Band::B6, 33)));
        assert_eq!(channel_from_freq(7115), Some((Band::B6, 233)));
        assert_eq!(channel_from_freq(7120), None);
        assert_eq!(channel_from_freq(5950), None);
        assert_eq!(freq_from_channel(Band::B6, 1), Some(5955));
        assert_eq!(freq_from_channel(Band::B6, 2), Some(5935));
        assert_eq!(freq_from_channel(Band::B6, 5), Some(5975));
        assert_eq!(freq_from_channel(Band::B6, 233), Some(7115));
        assert_eq!(freq_from_channel(Band::B6, 0), None);
        assert_eq!(freq_from_channel(Band::B6, 234), None);
    }

    #[test]
    fn every_channel_round_trips() {
        for (band, range) in [
            (Band::B24, 1..=14u16),
            (Band::B5, 32..=177),
            (Band::B6, 1..=233),
        ] {
            for ch in range {
                let f = freq_from_channel(band, ch);
                assert!(f.is_some(), "{band:?} {ch}");
                assert_eq!(f.and_then(channel_from_freq), Some((band, ch)));
            }
        }
        // No frequency ever maps to an inconsistent channel, and nothing panics.
        for mhz in 0..8000u32 {
            if let Some((band, ch)) = channel_from_freq(mhz) {
                assert_eq!(freq_from_channel(band, ch), Some(mhz));
            }
        }
        assert_eq!(channel_from_freq(u32::MAX), None);
    }

    #[test]
    fn quality_and_dbm() {
        assert_eq!(quality_from_rssi(-100), 0);
        assert_eq!(quality_from_rssi(-120), 0);
        assert_eq!(quality_from_rssi(-75), 50);
        assert_eq!(quality_from_rssi(-50), 100);
        assert_eq!(quality_from_rssi(-20), 100);
        assert_eq!(quality_from_rssi(i32::MIN), 0);
        assert_eq!(quality_from_rssi(i32::MAX), 100);
        assert_eq!(rssi_from_quality(0), -100);
        assert_eq!(rssi_from_quality(50), -75);
        assert_eq!(rssi_from_quality(100), -50);
        assert_eq!(rssi_from_quality(255), -50);
        for q in (0..=100u8).step_by(2) {
            assert_eq!(quality_from_rssi(rssi_from_quality(q)), q);
        }
    }

    #[test]
    fn signal_words() {
        assert_eq!(signal_word(-40), "Excellent");
        assert_eq!(signal_word(-55), "Excellent");
        assert_eq!(signal_word(-60), "Good");
        assert_eq!(signal_word(-67), "Good");
        assert_eq!(signal_word(-70), "Fair");
        assert_eq!(signal_word(-75), "Fair");
        assert_eq!(signal_word(-80), "Weak");
    }

    #[test]
    fn occupancy_24_overlap_falls_with_distance() {
        let nets = [net(Band::B24, 6, -50, 20)];
        let load = occupancy(&nets, Band::B24);
        assert_eq!(load.len(), 13);
        let score = |ch: u16| {
            load.iter()
                .find(|l| l.channel == ch)
                .map(|l| l.score)
                .unwrap_or(-1.0)
        };
        assert!((score(6) - 1.0).abs() < 1e-4);
        assert!((score(5) - 0.8).abs() < 1e-4);
        assert!((score(7) - 0.8).abs() < 1e-4);
        assert!((score(4) - 0.6).abs() < 1e-4);
        assert!((score(3) - 0.4).abs() < 1e-4);
        assert!((score(2) - 0.2).abs() < 1e-4);
        assert!((score(10) - 0.2).abs() < 1e-4);
        assert_eq!(score(1), 0.0);
        assert_eq!(score(11), 0.0);
        let six = load
            .iter()
            .find(|l| l.channel == 6)
            .cloned()
            .unwrap_or_default();
        assert_eq!(six.networks, 1);
        assert_eq!(six.strongest_dbm, Some(-50));
        let five = load
            .iter()
            .find(|l| l.channel == 5)
            .cloned()
            .unwrap_or_default();
        assert_eq!(five.networks, 0);
        assert_eq!(five.strongest_dbm, None);
    }

    #[test]
    fn occupancy_weights_by_signal() {
        let strong = occupancy(&[net(Band::B24, 1, -50, 20)], Band::B24);
        let weak = occupancy(&[net(Band::B24, 1, -90, 20)], Band::B24);
        let first = |l: &[ChannelLoad]| l.first().map(|c| c.score).unwrap_or(0.0);
        assert!(first(&strong) > first(&weak));
        assert!(first(&weak) > 0.0);
    }

    #[test]
    fn occupancy_24_shows_channel_14_only_when_used() {
        assert!(!occupancy(&[], Band::B24).iter().any(|l| l.channel == 14));
        let load = occupancy(&[net(Band::B24, 14, -60, 20)], Band::B24);
        assert_eq!(load.last().map(|l| l.channel), Some(14));
        assert_eq!(load.last().map(|l| l.networks), Some(1));
    }

    #[test]
    fn occupancy_5_covers_the_whole_width() {
        // An 80 MHz network with primary channel 44 covers 36..=48.
        let nets = [net(Band::B5, 44, -50, 80)];
        let load = occupancy(&nets, Band::B5);
        assert_eq!(load.len(), 25);
        for l in &load {
            let covered = (36..=48).contains(&l.channel);
            assert_eq!(l.score > 0.0, covered, "channel {}", l.channel);
            assert_eq!(l.networks, u32::from(l.channel == 44));
        }
        // 160 MHz from channel 100 covers 100..=128 and nothing else.
        let load = occupancy(&[net(Band::B5, 112, -60, 160)], Band::B5);
        for l in &load {
            assert_eq!(
                l.score > 0.0,
                (100..=128).contains(&l.channel),
                "channel {}",
                l.channel
            );
        }
        // 40 MHz on 157 covers 157 and 161; 20 MHz on 165 only itself.
        let load = occupancy(
            &[net(Band::B5, 157, -60, 40), net(Band::B5, 165, -60, 20)],
            Band::B5,
        );
        let busy: Vec<u16> = load
            .iter()
            .filter(|l| l.score > 0.0)
            .map(|l| l.channel)
            .collect();
        assert_eq!(busy, vec![157, 161, 165]);
    }

    #[test]
    fn occupancy_uses_the_beacon_centre_when_given() {
        // A 40 MHz network on channel 6 that extends upwards (centre 2447).
        let mut up = net(Band::B24, 6, -50, 40);
        up.center_mhz = Some(2447);
        let load = occupancy(&[up], Band::B24);
        let score = |ch: u16| {
            load.iter()
                .find(|l| l.channel == ch)
                .map(|l| l.score)
                .unwrap_or(-1.0)
        };
        assert!((score(6) - 1.0).abs() < 1e-4);
        assert!((score(10) - 1.0).abs() < 1e-4);
        assert!(score(11) > score(1));
        // An implausible centre is ignored.
        let mut odd = net(Band::B5, 36, -50, 80);
        odd.center_mhz = Some(5900);
        assert_eq!(span_mhz(&odd), (5170.0, 5250.0));
    }

    #[test]
    fn occupancy_6_adds_channels_in_use() {
        let load = occupancy(&[net(Band::B6, 1, -60, 20)], Band::B6);
        assert_eq!(load.first().map(|l| l.channel), Some(1));
        assert!(load.iter().any(|l| l.channel == 5));
        assert!(load.iter().any(|l| l.channel == 229));
        // A 160 MHz network on channel 37 covers the preferred channels 37 and 53 (33..=61).
        let load = occupancy(&[net(Band::B6, 37, -60, 160)], Band::B6);
        let busy: Vec<u16> = load
            .iter()
            .filter(|l| l.score > 0.0)
            .map(|l| l.channel)
            .collect();
        assert_eq!(busy, vec![37, 53]);
    }

    #[test]
    fn other_bands_are_ignored() {
        let nets = [net(Band::B5, 36, -40, 20), net(Band::B6, 5, -40, 20)];
        assert!(occupancy(&nets, Band::B24)
            .iter()
            .all(|l| l.score == 0.0 && l.networks == 0));
    }

    #[test]
    fn best_24_only_suggests_1_6_11() {
        // Crowd everything except channels around 11.
        let nets = [
            net(Band::B24, 1, -45, 20),
            net(Band::B24, 2, -50, 20),
            net(Band::B24, 6, -55, 20),
            net(Band::B24, 5, -60, 20),
            net(Band::B24, 13, -90, 20),
        ];
        let pick = best_channel(&nets, Band::B24).unwrap_or_default();
        assert_eq!(pick.band, Band::B24);
        assert_eq!(pick.channel, 11);
        assert!(pick.reason.ends_with('.'));
        assert_eq!(
            pick.reason.matches(". ").count(),
            0,
            "one sentence: {}",
            pick.reason
        );

        // Whatever the input, the answer is one of the three.
        for seed in 0..200u32 {
            let nets: Vec<Bss> = (0..(seed % 9))
                .map(|i| {
                    let ch = ((seed * 7 + i * 5) % 13 + 1) as u16;
                    net(Band::B24, ch, -40 - ((seed + i * 11) % 50) as i32, 20)
                })
                .collect();
            let pick = best_channel(&nets, Band::B24).unwrap_or_default();
            assert!([1, 6, 11].contains(&pick.channel));
        }
    }

    #[test]
    fn best_24_empty_and_free() {
        let pick = best_channel(&[], Band::B24).unwrap_or_default();
        assert_eq!(pick.channel, 1);
        assert!(pick.reason.contains("No 2.4 GHz networks"));
        let pick = best_channel(&[net(Band::B24, 1, -50, 20)], Band::B24).unwrap_or_default();
        assert_eq!(pick.channel, 6);
        assert!(pick.reason.contains("free"));
    }

    #[test]
    fn best_24_prefers_weaker_interference() {
        // One network on each of 1, 6, 11: the weakest neighbour wins.
        let nets = [
            net(Band::B24, 1, -50, 20),
            net(Band::B24, 6, -85, 20),
            net(Band::B24, 11, -60, 20),
        ];
        assert_eq!(best_channel(&nets, Band::B24).map(|s| s.channel), Some(6));
    }

    #[test]
    fn best_5_prefers_non_dfs_on_ties() {
        // Nothing seen: everything ties at zero, 36 wins and is not DFS.
        let pick = best_channel(&[], Band::B5).unwrap_or_default();
        assert_eq!(pick.channel, 36);
        assert!(pick.reason.contains("not a DFS channel"));

        // 36..=48 busy: the free upper non-DFS block beats the free DFS channels.
        let nets = [net(Band::B5, 36, -50, 80)];
        let pick = best_channel(&nets, Band::B5).unwrap_or_default();
        assert_eq!(pick.channel, 149);
        assert!(!is_dfs(Band::B5, pick.channel));
    }

    #[test]
    fn best_5_says_when_the_pick_is_dfs() {
        // Every non-DFS channel is busy, the DFS range is empty.
        let nets = [
            net(Band::B5, 36, -50, 80),
            net(Band::B5, 149, -55, 80),
            net(Band::B5, 165, -70, 20),
        ];
        let pick = best_channel(&nets, Band::B5).unwrap_or_default();
        assert_eq!(pick.channel, 52);
        assert!(is_dfs(Band::B5, pick.channel));
        assert!(pick.reason.contains("DFS channel"));
        assert!(pick.reason.contains("radar"));
        // It names the quietest alternative without radar duty.
        assert!(pick.reason.contains("is 165."), "{}", pick.reason);
        assert_eq!(
            pick.reason.matches(". ").count(),
            0,
            "one sentence: {}",
            pick.reason
        );
    }

    #[test]
    fn best_6() {
        assert_eq!(best_channel(&[], Band::B6), None);
        assert_eq!(best_channel(&[net(Band::B5, 36, -50, 20)], Band::B6), None);
        let pick = best_channel(&[net(Band::B6, 5, -50, 80)], Band::B6).unwrap_or_default();
        // Channels 1..=13 are covered, so the next preferred channel is 21.
        assert_eq!(pick.channel, 21);
        assert_eq!(pick.band, Band::B6);
    }

    #[test]
    fn dfs_ranges() {
        assert!(!is_dfs(Band::B5, 36));
        assert!(!is_dfs(Band::B5, 48));
        assert!(is_dfs(Band::B5, 52));
        assert!(is_dfs(Band::B5, 100));
        assert!(is_dfs(Band::B5, 144));
        assert!(!is_dfs(Band::B5, 149));
        assert!(!is_dfs(Band::B24, 60));
        assert!(!is_dfs(Band::B6, 60));
    }

    #[test]
    fn odd_input_never_panics() {
        let mut weird = net(Band::B5, 36, 500, 20);
        weird.channel = 9999;
        weird.freq_mhz = 0;
        weird.width_mhz = Some(0);
        weird.center_mhz = Some(u32::MAX);
        let nets = [
            weird.clone(),
            Bss {
                band: Band::B6,
                ..weird.clone()
            },
            Bss {
                band: Band::B24,
                ..weird
            },
        ];
        for band in [Band::B24, Band::B5, Band::B6] {
            let _ = occupancy(&nets, band);
            let _ = best_channel(&nets, band);
        }
    }
}
