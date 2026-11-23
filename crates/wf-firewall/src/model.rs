//! Plain data: profiles, actions, rules and the status of each profile.

use serde::{Deserialize, Serialize};

/// A firewall profile (network location).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Profile {
    Domain,
    Private,
    Public,
}

impl Profile {
    pub const ALL: [Profile; 3] = [Profile::Domain, Profile::Private, Profile::Public];

    pub fn bit(self) -> u8 {
        match self {
            Profile::Domain => 1,
            Profile::Private => 2,
            Profile::Public => 4,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Profile::Domain => "Domain",
            Profile::Private => "Private",
            Profile::Public => "Public",
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Profile::Domain => "domain",
            Profile::Private => "private",
            Profile::Public => "public",
        }
    }
}

/// A set of profiles as a bit mask (1 domain, 2 private, 4 public).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Profiles(pub u8);

impl Default for Profiles {
    fn default() -> Self {
        Profiles::ALL
    }
}

impl Profiles {
    pub const NONE: Profiles = Profiles(0);
    pub const ALL: Profiles = Profiles(7);

    pub fn contains(self, p: Profile) -> bool {
        self.0 & p.bit() != 0
    }

    pub fn with(self, p: Profile, on: bool) -> Profiles {
        if on {
            Profiles(self.0 | p.bit())
        } else {
            Profiles(self.0 & !p.bit())
        }
    }

    pub fn is_empty(self) -> bool {
        self.0 & 7 == 0
    }

    /// The firewall API's mask: all three become `NET_FW_PROFILE2_ALL`.
    pub fn to_mask(self) -> i32 {
        if self.0 & 7 == 7 {
            0x7FFF_FFFF
        } else {
            (self.0 & 7) as i32
        }
    }

    pub fn from_mask(mask: i32) -> Profiles {
        Profiles((mask & 7) as u8)
    }

    /// "All networks", "Private, Public", ...
    pub fn label(self) -> String {
        if self.0 & 7 == 7 {
            return "All networks".into();
        }
        if self.is_empty() {
            return "No network".into();
        }
        Profile::ALL
            .iter()
            .filter(|p| self.contains(**p))
            .map(|p| p.label())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `all` or `domain,private` (command line).
    pub fn arg(self) -> String {
        if self.0 & 7 == 7 {
            return "all".into();
        }
        Profile::ALL
            .iter()
            .filter(|p| self.contains(**p))
            .map(|p| p.key())
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn parse(text: &str) -> Result<Profiles, String> {
        let mut out = Profiles::NONE;
        for part in text.split(',').map(|s| s.trim().to_ascii_lowercase()) {
            out = match part.as_str() {
                "all" => Profiles::ALL,
                "domain" => out.with(Profile::Domain, true),
                "private" => out.with(Profile::Private, true),
                "public" => out.with(Profile::Public, true),
                "" => out,
                other => return Err(format!("Unknown network profile '{other}'.")),
            };
        }
        if out.is_empty() {
            return Err("No network profile given.".into());
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FwAction {
    Allow,
    Block,
}

impl FwAction {
    pub fn label(self) -> &'static str {
        match self {
            FwAction::Allow => "Allow",
            FwAction::Block => "Block",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    Out,
    In,
}

impl Direction {
    pub fn label(self) -> &'static str {
        match self {
            Direction::Out => "Outgoing",
            Direction::In => "Incoming",
        }
    }
}

/// One firewall rule, as read from or written to Windows Firewall.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FwRule {
    pub name: String,
    pub group: String,
    pub description: String,
    /// Full program path, environment variables expanded; empty = any program.
    pub program: String,
    pub service: String,
    pub direction: Direction,
    pub action: FwAction,
    pub enabled: bool,
    pub profiles: Profiles,
    /// IANA protocol number, 256 = any.
    pub protocol: i32,
    pub local_ports: String,
    pub remote_ports: String,
    pub remote_addrs: String,
}

impl Default for FwRule {
    fn default() -> Self {
        FwRule {
            name: String::new(),
            group: String::new(),
            description: String::new(),
            program: String::new(),
            service: String::new(),
            direction: Direction::Out,
            action: FwAction::Block,
            enabled: true,
            profiles: Profiles::ALL,
            protocol: 256,
            local_ports: String::new(),
            remote_ports: String::new(),
            remote_addrs: String::new(),
        }
    }
}

impl FwRule {
    pub fn protocol_label(&self) -> String {
        match self.protocol {
            256 => "Any".into(),
            6 => "TCP".into(),
            17 => "UDP".into(),
            1 => "ICMPv4".into(),
            58 => "ICMPv6".into(),
            n => format!("Protocol {n}"),
        }
    }
}

/// The state of one profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileStatus {
    pub profile: Profile,
    pub enabled: bool,
    pub default_in: FwAction,
    pub default_out: FwAction,
    /// The profile of a network this PC is connected to right now.
    pub active: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FwStatus {
    pub profiles: Vec<ProfileStatus>,
}

impl FwStatus {
    pub fn get(&self, p: Profile) -> Option<&ProfileStatus> {
        self.profiles.iter().find(|s| s.profile == p)
    }

    /// The usual Windows defaults: on, block in, allow out.
    pub fn windows_default() -> FwStatus {
        FwStatus {
            profiles: Profile::ALL
                .iter()
                .map(|p| ProfileStatus {
                    profile: *p,
                    enabled: true,
                    default_in: FwAction::Block,
                    default_out: FwAction::Allow,
                    active: *p == Profile::Private,
                })
                .collect(),
        }
    }
}

/// How long a block lasts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Lifetime {
    Always,
    /// Until this Unix time.
    Until(i64),
    /// Until Windows restarts; the boot time when the block was made.
    UntilRestart {
        boot: i64,
    },
}

impl Lifetime {
    /// Whether the block should be gone by now. A different boot time (more
    /// than two minutes apart, to absorb clock rounding) means a restart.
    pub fn expired(self, now: i64, boot: i64) -> bool {
        match self {
            Lifetime::Always => false,
            Lifetime::Until(t) => now >= t,
            Lifetime::UntilRestart { boot: b } => (boot - b).abs() > 120,
        }
    }

    pub fn is_temporary(self) -> bool {
        !matches!(self, Lifetime::Always)
    }
}

/// A program blocked by WireForge, assembled from its rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockedApp {
    pub path: String,
    /// File name, for display ("app.exe").
    pub name: String,
    pub since: i64,
    pub lifetime: Lifetime,
    pub outbound: bool,
    pub inbound: bool,
    pub profiles: Profiles,
    pub rule_names: Vec<String>,
}

/// Lockdown as recorded in the firewall itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lockdown {
    pub since: i64,
    /// The default outbound action of each profile before lockdown.
    pub saved: Vec<(Profile, FwAction)>,
    /// Programs allowed through while lockdown is on.
    pub allowed: Vec<String>,
}

/// The file name part of a Windows path.
pub fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .trim()
        .to_string()
}

/// Paths compare case-insensitively, with either slash.
pub fn same_path(a: &str, b: &str) -> bool {
    norm_path(a) == norm_path(b)
}

pub fn norm_path(p: &str) -> String {
    p.trim().trim_matches('"').replace('/', "\\").to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_masks_and_labels() {
        assert_eq!(Profiles::ALL.to_mask(), 0x7FFF_FFFF);
        assert_eq!(Profiles::from_mask(0x7FFF_FFFF), Profiles::ALL);
        assert_eq!(Profiles(6).to_mask(), 6);
        assert_eq!(Profiles(6).label(), "Private, Public");
        assert_eq!(Profiles::ALL.label(), "All networks");
        assert_eq!(Profiles::parse("all").unwrap(), Profiles::ALL);
        assert_eq!(Profiles::parse("Public, private").unwrap(), Profiles(6));
        assert_eq!(Profiles(5).arg(), "domain,public");
        assert!(Profiles::parse("office").is_err());
        assert!(Profiles::parse("").is_err());
        assert_eq!(
            Profiles::parse(&Profiles(3).arg()).unwrap(),
            Profiles(3),
            "round trip"
        );
    }

    #[test]
    fn lifetimes_expire() {
        assert!(!Lifetime::Always.expired(i64::MAX, 0));
        assert!(!Lifetime::Until(1000).expired(999, 0));
        assert!(Lifetime::Until(1000).expired(1000, 0));
        let r = Lifetime::UntilRestart { boot: 50_000 };
        assert!(!r.expired(60_000, 50_000));
        assert!(
            !r.expired(60_000, 50_090),
            "small clock jitter is the same boot"
        );
        assert!(r.expired(60_000, 58_000), "a later boot means a restart");
        assert!(r.is_temporary() && !Lifetime::Always.is_temporary());
    }

    #[test]
    fn paths() {
        assert_eq!(
            file_name("C:\\Program Files\\Lumen\\lumen.exe"),
            "lumen.exe"
        );
        assert_eq!(file_name("lumen.exe"), "lumen.exe");
        assert!(same_path("C:\\A\\b.EXE", "\"c:/a/B.exe\""));
        assert!(!same_path("C:\\A\\b.exe", "C:\\A\\c.exe"));
    }
}
