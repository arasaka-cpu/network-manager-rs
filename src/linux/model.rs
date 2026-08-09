use std::fmt;
use std::io;
use std::net::IpAddr;

/// Errors surfaced by the Linux netlink backends.
///
/// Malformed protocol data is reported as a controlled [`NetlinkError`] value
/// instead of a panic so that callers can decide how to react.
#[derive(Debug)]
pub enum NetlinkError {
    /// Underlying socket I/O failed.
    Io(io::Error),
    /// The kernel returned a negative errno-style netlink error code.
    Kernel(i32),
    /// Protocol data did not conform to the expected structure.
    MalformedMessage(&'static str),
}

impl fmt::Display for NetlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "netlink I/O failed: {err}"),
            Self::Kernel(code) => write!(f, "kernel returned netlink error {code}"),
            Self::MalformedMessage(msg) => write!(f, "malformed netlink message: {msg}"),
        }
    }
}

impl std::error::Error for NetlinkError {}

impl From<io::Error> for NetlinkError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// A kernel network link snapshot (rtnetlink).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link {
    pub index: i32,
    pub name: String,
    pub flags: LinkFlags,
}

/// Raw interface flags as reported by the kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkFlags(u32);

impl LinkFlags {
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn is_up(self) -> bool {
        self.0 & 0x1 != 0
    }

    pub const fn is_loopback(self) -> bool {
        self.0 & 0x8 != 0
    }
}

/// A kernel interface address snapshot (rtnetlink).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Address {
    pub interface_index: u32,
    pub address: IpAddr,
    pub prefix_length: u8,
}

/// Typed network events emitted by the daemon's event sources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkEvent {
    Link(LinkEvent),
    Address(AddressEvent),
    Wifi(WifiEvent),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkEvent {
    pub kind: LinkEventKind,
    pub link: Link,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkEventKind {
    Created,
    Removed,
    Changed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressEvent {
    pub kind: AddressEventKind,
    pub address: Address,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressEventKind {
    Added,
    Removed,
}

/// A blocking source of typed [`NetworkEvent`] values.
pub trait NetworkEventSource {
    /// Returns the next event, or `None` once a shutdown has been requested.
    fn next_event(&mut self) -> Result<Option<NetworkEvent>, NetlinkError>;
}

/// Map a center frequency in MHz to the 802.11 channel number.
pub fn frequency_to_channel(freq_mhz: u32) -> Option<u16> {
    if (2412..=2472).contains(&freq_mhz) {
        Some(((freq_mhz - 2407) / 5) as u16)
    } else if freq_mhz == 2484 {
        Some(14)
    } else if (5000..=5895).contains(&freq_mhz) {
        Some(((freq_mhz - 5000) / 5) as u16)
    } else if (5955..=7115).contains(&freq_mhz) {
        Some(((freq_mhz - 5950) / 5) as u16)
    } else {
        None
    }
}

/// An 802.11 service set identifier (0..32 octets).
///
/// SSIDs are octet strings and are not required to be valid UTF-8, so the raw
/// bytes are preserved and a display form is derived on demand.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Ssid(pub Vec<u8>);

impl Ssid {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        (bytes.len() <= 32).then(|| Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Human-readable form with non-printable octets escaped as `\xNN`.
    pub fn display_string(&self) -> String {
        if self.0.is_empty() {
            return "(hidden)".to_string();
        }
        let mut out = String::new();
        for &byte in &self.0 {
            if (0x20..=0x7e).contains(&byte) && byte != b'\\' {
                out.push(byte as char);
            } else {
                out.push_str(&format!("\\x{byte:02x}"));
            }
        }
        out
    }
}

impl fmt::Display for Ssid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_string())
    }
}

/// An 802.11 basic service set identifier (48-bit MAC address).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Bssid(pub [u8; 6]);

impl Bssid {
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Display for Bssid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// nl80211 interface mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceType {
    Unspecified,
    Adhoc,
    Station,
    Ap,
    ApVlan,
    Wds,
    Monitor,
    MeshPoint,
    P2pClient,
    P2pGo,
    P2pDevice,
    Ocb,
    Nan,
    NanData,
    Other(u8),
}

impl InterfaceType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Unspecified,
            1 => Self::Adhoc,
            2 => Self::Station,
            3 => Self::Ap,
            4 => Self::ApVlan,
            5 => Self::Wds,
            6 => Self::Monitor,
            7 => Self::MeshPoint,
            8 => Self::P2pClient,
            9 => Self::P2pGo,
            10 => Self::P2pDevice,
            11 => Self::Ocb,
            12 => Self::Nan,
            13 => Self::NanData,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for InterfaceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => f.write_str("unspecified"),
            Self::Adhoc => f.write_str("adhoc"),
            Self::Station => f.write_str("station"),
            Self::Ap => f.write_str("access-point"),
            Self::ApVlan => f.write_str("ap-vlan"),
            Self::Wds => f.write_str("wds"),
            Self::Monitor => f.write_str("monitor"),
            Self::MeshPoint => f.write_str("mesh-point"),
            Self::P2pClient => f.write_str("p2p-client"),
            Self::P2pGo => f.write_str("p2p-group-owner"),
            Self::P2pDevice => f.write_str("p2p-device"),
            Self::Ocb => f.write_str("ocb"),
            Self::Nan => f.write_str("nan"),
            Self::NanData => f.write_str("nan-data"),
            Self::Other(value) => write!(f, "unknown({value})"),
        }
    }
}

/// 802.11 radio band identifiers reported by nl80211.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WifiBandId {
    Ghz2,
    Ghz5,
    Ghz60,
    Ghz6,
    SubGhz,
    Lc,
    Other(u8),
}

impl WifiBandId {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Ghz2,
            1 => Self::Ghz5,
            2 => Self::Ghz60,
            3 => Self::Ghz6,
            4 => Self::SubGhz,
            5 => Self::Lc,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for WifiBandId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ghz2 => f.write_str("2.4GHz"),
            Self::Ghz5 => f.write_str("5GHz"),
            Self::Ghz60 => f.write_str("60GHz"),
            Self::Ghz6 => f.write_str("6GHz"),
            Self::SubGhz => f.write_str("sub-GHz"),
            Self::Lc => f.write_str("light-communication"),
            Self::Other(value) => write!(f, "band({value})"),
        }
    }
}

/// A single 802.11 operating band with the channels/frequencies it supports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WifiBand {
    pub id: WifiBandId,
    pub channels: Vec<u16>,
    pub frequencies: Vec<u32>,
    pub ht_capabilities: Option<u16>,
    pub vht_capabilities: Option<u32>,
}

/// IEEE 802.11 cipher suites (well-known OUI 00-0F-AC values).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WifiCipher {
    Wep40,
    Wep104,
    Tkip,
    Ccmp,
    Ccmp256,
    Gcmp,
    Gcmp256,
    AesCmac,
    BipCmac256,
    BipGmac128,
    BipGmac256,
    WapiSms4,
    Other(u32),
}

impl WifiCipher {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0x000FAC01 => Self::Wep40,
            0x000FAC05 => Self::Wep104,
            0x000FAC02 => Self::Tkip,
            0x000FAC04 => Self::Ccmp,
            0x000FAC0A => Self::Ccmp256,
            0x000FAC08 => Self::Gcmp,
            0x000FAC09 => Self::Gcmp256,
            0x000FAC06 => Self::AesCmac,
            0x000FAC0B => Self::BipCmac256,
            0x000FAC0C => Self::BipGmac128,
            0x000FAC0D => Self::BipGmac256,
            0x00147201 => Self::WapiSms4,
            other => Self::Other(other),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wep40 => "WEP-40",
            Self::Wep104 => "WEP-104",
            Self::Tkip => "TKIP",
            Self::Ccmp => "CCMP",
            Self::Ccmp256 => "CCMP-256",
            Self::Gcmp => "GCMP",
            Self::Gcmp256 => "GCMP-256",
            Self::AesCmac => "AES-CMAC",
            Self::BipCmac256 => "BIP-CMAC-256",
            Self::BipGmac128 => "BIP-GMAC-128",
            Self::BipGmac256 => "BIP-GMAC-256",
            Self::WapiSms4 => "WAPI-SMS4",
            Self::Other(_) => "other",
        }
    }
}

impl fmt::Display for WifiCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(value) => write!(f, "other(0x{value:08x})"),
            _ => f.write_str(self.as_str()),
        }
    }
}

/// A wiphy's Wi-Fi capabilities as advertised through nl80211.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WifiCapabilities {
    pub supported_interfaces: Vec<InterfaceType>,
    pub cipher_suites: Vec<WifiCipher>,
    pub bands: Vec<WifiBand>,
    pub max_scan_ssids: Option<u32>,
    pub scan_supported: bool,
}

/// A discovered wireless interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WirelessInterface {
    pub index: i32,
    pub name: String,
    pub wiphy_index: Option<u32>,
    pub wiphy_name: Option<String>,
    pub interface_type: InterfaceType,
    pub mac: Option<[u8; 6]>,
    pub up: bool,
    pub capabilities: WifiCapabilities,
}

/// Key management / authentication suites advertised by an access point.
///
/// WPA (vendor IE) uses suite values 1 (IEEE 802.1X) and 2 (PSK); RSN uses the
/// IEEE 802.11 AKM suite identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WifiAuthSuite {
    Wpa1Psk,
    Wpa18021x,
    Rsn8021x,
    RsnPsk,
    RsnFt8021x,
    RsnFtPsk,
    Rsn8021xSha256,
    RsnPskSha256,
    RsnSae,
    RsnSaeFt,
    RsnApPsk,
    RsnSuiteB,
    RsnSuiteB192,
    RsnFt8021xSha384,
    RsnFilsSha256,
    RsnFilsSha384,
    RsnFtFilsSha256,
    RsnFtFilsSha384,
    RsnOwe,
    RsnFtPskSha384,
    RsnPskSha384,
    RsnPasn,
    Other(u32),
}

impl WifiAuthSuite {
    pub fn from_rsn_akm(value: u32) -> Self {
        match value {
            0x000FAC01 => Self::Rsn8021x,
            0x000FAC02 => Self::RsnPsk,
            0x000FAC03 => Self::RsnFt8021x,
            0x000FAC04 => Self::RsnFtPsk,
            0x000FAC05 => Self::Rsn8021xSha256,
            0x000FAC06 => Self::RsnPskSha256,
            0x000FAC08 => Self::RsnSae,
            0x000FAC09 => Self::RsnSaeFt,
            0x000FAC0A => Self::RsnApPsk,
            0x000FAC0B => Self::RsnSuiteB,
            0x000FAC0C => Self::RsnSuiteB192,
            0x000FAC0D => Self::RsnFt8021xSha384,
            0x000FAC0E => Self::RsnFilsSha256,
            0x000FAC0F => Self::RsnFilsSha384,
            0x000FAC10 => Self::RsnFtFilsSha256,
            0x000FAC11 => Self::RsnFtFilsSha384,
            0x000FAC12 => Self::RsnOwe,
            0x000FAC13 => Self::RsnFtPskSha384,
            0x000FAC14 => Self::RsnPskSha384,
            0x000FAC15 => Self::RsnPasn,
            other => Self::Other(other),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wpa1Psk => "WPA-PSK",
            Self::Wpa18021x => "WPA-802.1X",
            Self::Rsn8021x => "WPA2-802.1X",
            Self::RsnPsk => "WPA2-PSK",
            Self::RsnFt8021x => "FT-802.1X",
            Self::RsnFtPsk => "FT-PSK",
            Self::Rsn8021xSha256 => "802.1X-SHA256",
            Self::RsnPskSha256 => "PSK-SHA256",
            Self::RsnSae => "SAE",
            Self::RsnSaeFt => "FT-SAE",
            Self::RsnApPsk => "AP-PSK",
            Self::RsnSuiteB => "SUITE-B",
            Self::RsnSuiteB192 => "SUITE-B-192",
            Self::RsnFt8021xSha384 => "FT-802.1X-SHA384",
            Self::RsnFilsSha256 => "FILS-SHA256",
            Self::RsnFilsSha384 => "FILS-SHA384",
            Self::RsnFtFilsSha256 => "FT-FILS-SHA256",
            Self::RsnFtFilsSha384 => "FT-FILS-SHA384",
            Self::RsnOwe => "OWE",
            Self::RsnFtPskSha384 => "FT-PSK-SHA384",
            Self::RsnPskSha384 => "PSK-SHA384",
            Self::RsnPasn => "PASN",
            Self::Other(_) => "other",
        }
    }
}

impl fmt::Display for WifiAuthSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(value) => write!(f, "other(0x{value:08x})"),
            _ => f.write_str(self.as_str()),
        }
    }
}

/// Security/authentication capabilities of an access point.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccessPointSecurity {
    pub wep: bool,
    pub wpa1: bool,
    pub wpa2: bool,
    pub wpa3: bool,
    pub enterprise: bool,
    pub management_frame_protection: bool,
    pub auth_suites: Vec<WifiAuthSuite>,
}

/// A typed Wi-Fi access point discovered through nl80211 scanning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessPoint {
    pub bssid: Option<Bssid>,
    pub ssid: Option<Ssid>,
    pub frequency: Option<u32>,
    pub channel: Option<u16>,
    pub signal_dbm: Option<i32>,
    pub signal_unspecified: Option<u8>,
    pub capability: Option<u16>,
    pub security: AccessPointSecurity,
    pub seen_millis_ago: Option<u32>,
}

/// Wi-Fi related network events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WifiEvent {
    pub kind: WifiEventKind,
    pub interface_index: i32,
    pub interface_name: Option<String>,
    pub frequency: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WifiEventKind {
    ScanResults,
    ScanAborted,
}
