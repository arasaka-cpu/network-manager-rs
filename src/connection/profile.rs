//! Connection profile model.
//!
//! A [`ConnectionProfile`] is the declarative description of a network
//! connection: what it connects to, which device it may use, how IP
//! configuration is intended, and how authentication is referenced. Secrets
//! are never stored inline; only a [`SecretReference`](crate::connection::secrets::SecretReference)
//! is kept.
//!
//! The model is intentionally extensible. This milestone fully models Wi-Fi
//! and establishes an Ethernet foundation; VLAN, bridge, bond and WireGuard
//! settings can be added as new [`ConnectionType`] variants later.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::connection::device::{DeviceInfo, DeviceKind, MacAddress};
use crate::connection::secrets::SecretReference;
use crate::linux::model::{Bssid, Ssid};

/// Stable identifier of a connection profile.
pub type ProfileId = String;

/// Validation failures reported by [`ConnectionProfile::validate`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileValidationError {
    EmptyId,
    InvalidIdChars(String),
    EmptyName,
    EmptySsid,
    SsidTooLong(usize),
    MissingSecret,
    SecretNotAllowed,
    MissingIdentity,
    InvalidSpeed,
    ManualAddressRequired,
    ManualPrefixRequired,
    PrefixOutOfRange(u8),
    AddressFamilyMismatch,
}

impl fmt::Display for ProfileValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyId => f.write_str("profile id must not be empty"),
            Self::InvalidIdChars(id) => write!(
                f,
                "profile id {id:?} may only contain ASCII alphanumerics, '-' and '_'"
            ),
            Self::EmptyName => f.write_str("profile name must not be empty"),
            Self::EmptySsid => f.write_str("wifi ssid must not be empty"),
            Self::SsidTooLong(len) => write!(f, "wifi ssid exceeds 32 octets ({len})"),
            Self::MissingSecret => f.write_str("wifi security requires a secret reference"),
            Self::SecretNotAllowed => {
                f.write_str("open or OWE wifi security must not carry a secret")
            }
            Self::MissingIdentity => f.write_str("enterprise wifi security requires an identity"),
            Self::InvalidSpeed => f.write_str("ethernet link speed must be non-zero"),
            Self::ManualAddressRequired => {
                f.write_str("manual IP configuration requires an address")
            }
            Self::ManualPrefixRequired => {
                f.write_str("manual IP configuration requires a prefix length")
            }
            Self::PrefixOutOfRange(prefix) => write!(
                f,
                "IP prefix length {prefix} is out of range for the configured family"
            ),
            Self::AddressFamilyMismatch => {
                f.write_str("IPv4/IPv6 configuration holds an address of the wrong family")
            }
        }
    }
}

impl std::error::Error for ProfileValidationError {}

/// A complete, validated connection profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConnectionProfile {
    pub id: ProfileId,
    pub name: String,
    pub connection_type: ConnectionType,
    #[serde(default)]
    pub device_match: DeviceMatch,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "default_true")]
    pub autoconnect: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub ipv4: IpConfig,
    #[serde(default)]
    pub ipv6: IpConfig,
}

const fn default_true() -> bool {
    true
}

impl ConnectionProfile {
    /// Builds a Wi-Fi profile. The profile is fully validated on construction.
    pub fn wifi(
        id: impl Into<ProfileId>,
        name: impl Into<String>,
        ssid: Ssid,
        security: WifiSecurity,
    ) -> Result<Self, ProfileValidationError> {
        let profile = Self {
            id: id.into(),
            name: name.into(),
            connection_type: ConnectionType::Wifi(WifiSettings {
                ssid,
                bssid: None,
                hidden: false,
                security,
            }),
            device_match: DeviceMatch::default(),
            priority: 0,
            autoconnect: true,
            enabled: true,
            ipv4: IpConfig::default(),
            ipv6: IpConfig::default(),
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Builds an Ethernet profile. The profile is fully validated on construction.
    pub fn ethernet(
        id: impl Into<ProfileId>,
        name: impl Into<String>,
    ) -> Result<Self, ProfileValidationError> {
        let profile = Self {
            id: id.into(),
            name: name.into(),
            connection_type: ConnectionType::Ethernet(EthernetSettings::default()),
            device_match: DeviceMatch::default(),
            priority: 0,
            autoconnect: true,
            enabled: true,
            ipv4: IpConfig::default(),
            ipv6: IpConfig::default(),
        };
        profile.validate()?;
        Ok(profile)
    }

    /// The kind of device this profile applies to.
    pub fn device_kind(&self) -> DeviceKind {
        match &self.connection_type {
            ConnectionType::Wifi(_) => DeviceKind::Wifi,
            ConnectionType::Ethernet(_) => DeviceKind::Ethernet,
        }
    }

    /// Decides deterministically whether this profile can be applied to `device`.
    ///
    /// A profile applies only when the device kind matches the connection
    /// type and, when present, the interface-name and MAC constraints of
    /// [`DeviceMatch`] are satisfied.
    pub fn matches(&self, device: &DeviceInfo) -> bool {
        if self.device_kind() != device.kind {
            return false;
        }
        if let Some(expected) = &self.device_match.interface_name {
            if expected != &device.interface_name {
                return false;
            }
        }
        if let Some(expected) = self.device_match.mac_address {
            if device.mac_address != Some(expected) {
                return false;
            }
        }
        true
    }

    /// Validates the profile and reports the first problem found.
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        if self.id.is_empty() {
            return Err(ProfileValidationError::EmptyId);
        }
        if !self
            .id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        {
            return Err(ProfileValidationError::InvalidIdChars(self.id.clone()));
        }
        if self.name.is_empty() {
            return Err(ProfileValidationError::EmptyName);
        }
        match &self.connection_type {
            ConnectionType::Wifi(settings) => {
                let len = settings.ssid.as_bytes().len();
                if len == 0 {
                    return Err(ProfileValidationError::EmptySsid);
                }
                if len > 32 {
                    return Err(ProfileValidationError::SsidTooLong(len));
                }
                match settings.security.key_management {
                    KeyManagement::WpaPsk | KeyManagement::Sae => {
                        if settings.security.secret.is_none() {
                            return Err(ProfileValidationError::MissingSecret);
                        }
                    }
                    KeyManagement::WpaEap => {
                        let has_identity = settings
                            .security
                            .identity
                            .as_deref()
                            .is_some_and(|identity| !identity.is_empty());
                        if !has_identity {
                            return Err(ProfileValidationError::MissingIdentity);
                        }
                    }
                    KeyManagement::Open | KeyManagement::Owe => {
                        if settings.security.secret.is_some() {
                            return Err(ProfileValidationError::SecretNotAllowed);
                        }
                    }
                }
            }
            ConnectionType::Ethernet(settings) => {
                if settings.speed_mbit == Some(0) {
                    return Err(ProfileValidationError::InvalidSpeed);
                }
            }
        }
        Self::validate_ip_config(&self.ipv4, true)?;
        Self::validate_ip_config(&self.ipv6, false)?;
        Ok(())
    }

    fn validate_ip_config(
        config: &IpConfig,
        expect_v4: bool,
    ) -> Result<(), ProfileValidationError> {
        if config.method != IpMethod::Manual {
            return Ok(());
        }
        let Some(address) = config.address else {
            return Err(ProfileValidationError::ManualAddressRequired);
        };
        if address.is_ipv4() != expect_v4 {
            return Err(ProfileValidationError::AddressFamilyMismatch);
        }
        let Some(prefix) = config.prefix_length else {
            return Err(ProfileValidationError::ManualPrefixRequired);
        };
        let max = if expect_v4 { 32 } else { 128 };
        if prefix > max {
            return Err(ProfileValidationError::PrefixOutOfRange(prefix));
        }
        Ok(())
    }
}

/// The transport a profile describes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConnectionType {
    Wifi(WifiSettings),
    Ethernet(EthernetSettings),
}

impl fmt::Display for ConnectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Wifi(_) => "wifi",
            Self::Ethernet(_) => "ethernet",
        })
    }
}

/// Constraints used to select the device a profile applies to.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceMatch {
    #[serde(default)]
    pub interface_name: Option<String>,
    #[serde(default)]
    pub mac_address: Option<MacAddress>,
}

/// Wi-Fi specific settings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WifiSettings {
    pub ssid: Ssid,
    #[serde(default)]
    pub bssid: Option<Bssid>,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub security: WifiSecurity,
}

/// Wi-Fi authentication configuration reference.
///
/// The security field points at key-management intent and at a
/// [`SecretReference`]; it never embeds a password.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WifiSecurity {
    pub key_management: KeyManagement,
    #[serde(default)]
    pub secret: Option<SecretReference>,
    #[serde(default)]
    pub identity: Option<String>,
}

impl Default for WifiSecurity {
    fn default() -> Self {
        Self {
            key_management: KeyManagement::Open,
            secret: None,
            identity: None,
        }
    }
}

impl WifiSecurity {
    pub const fn open() -> Self {
        Self {
            key_management: KeyManagement::Open,
            secret: None,
            identity: None,
        }
    }

    pub fn psk(secret: SecretReference) -> Self {
        Self {
            key_management: KeyManagement::WpaPsk,
            secret: Some(secret),
            identity: None,
        }
    }

    pub fn sae(secret: SecretReference) -> Self {
        Self {
            key_management: KeyManagement::Sae,
            secret: Some(secret),
            identity: None,
        }
    }

    pub const fn owe() -> Self {
        Self {
            key_management: KeyManagement::Owe,
            secret: None,
            identity: None,
        }
    }

    pub fn enterprise(identity: impl Into<String>) -> Self {
        Self {
            key_management: KeyManagement::WpaEap,
            secret: None,
            identity: Some(identity.into()),
        }
    }
}

/// Wi-Fi key management intent.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum KeyManagement {
    #[default]
    Open,
    WpaPsk,
    WpaEap,
    Sae,
    Owe,
}

impl fmt::Display for KeyManagement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Open => "open",
            Self::WpaPsk => "wpa-psk",
            Self::WpaEap => "wpa-eap",
            Self::Sae => "sae",
            Self::Owe => "owe",
        })
    }
}

/// Ethernet specific settings (foundation for this milestone).
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EthernetSettings {
    #[serde(default)]
    pub autonegotiation: Option<bool>,
    #[serde(default)]
    pub speed_mbit: Option<u32>,
    #[serde(default)]
    pub duplex: Option<EthernetDuplex>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum EthernetDuplex {
    Half,
    Full,
}

/// IP configuration intent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpConfig {
    pub method: IpMethod,
    #[serde(default)]
    pub address: Option<IpAddr>,
    #[serde(default)]
    pub prefix_length: Option<u8>,
    #[serde(default)]
    pub gateway: Option<IpAddr>,
    #[serde(default)]
    pub dns_servers: Vec<IpAddr>,
}

impl Default for IpConfig {
    fn default() -> Self {
        Self {
            method: IpMethod::Automatic,
            address: None,
            prefix_length: None,
            gateway: None,
            dns_servers: Vec::new(),
        }
    }
}

/// IP configuration method.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum IpMethod {
    #[default]
    Automatic,
    Manual,
    Disabled,
}

impl fmt::Display for IpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Automatic => "automatic",
            Self::Manual => "manual",
            Self::Disabled => "disabled",
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{
        ConnectionProfile, ConnectionType, DeviceMatch, IpConfig, IpMethod, KeyManagement,
        ProfileValidationError, WifiSecurity,
    };
    use crate::connection::device::DeviceInfo;
    use crate::connection::secrets::SecretReference;
    use crate::linux::model::Ssid;

    fn secret() -> SecretReference {
        SecretReference::Keyring {
            identifier: "nmd/test".to_string(),
        }
    }

    fn wifi_device() -> DeviceInfo {
        DeviceInfo::wifi("wlan0", Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
    }

    fn wifi_profile(id: &str) -> ConnectionProfile {
        ConnectionProfile::wifi(
            id,
            id,
            Ssid::from_bytes(b"home").unwrap(),
            WifiSecurity::open(),
        )
        .unwrap()
    }

    #[test]
    fn open_wifi_profile_validates() {
        wifi_profile("home").validate().unwrap();
    }

    #[test]
    fn psk_wifi_profile_requires_a_secret_reference() {
        let ok = ConnectionProfile::wifi(
            "home",
            "home",
            Ssid::from_bytes(b"home").unwrap(),
            WifiSecurity::psk(secret()),
        );
        assert!(ok.is_ok());

        let missing = WifiSecurity {
            secret: None,
            ..WifiSecurity::psk(secret())
        };
        assert_eq!(
            ConnectionProfile::wifi("home", "home", Ssid::from_bytes(b"home").unwrap(), missing)
                .unwrap_err(),
            ProfileValidationError::MissingSecret
        );
    }

    #[test]
    fn enterprise_wifi_profile_requires_an_identity() {
        let ok = ConnectionProfile::wifi(
            "corp",
            "corp",
            Ssid::from_bytes(b"corp").unwrap(),
            WifiSecurity::enterprise("user@example.org"),
        );
        assert!(ok.is_ok());

        let without_identity = WifiSecurity {
            key_management: KeyManagement::WpaEap,
            secret: None,
            identity: None,
        };
        assert_eq!(
            ConnectionProfile::wifi(
                "corp",
                "corp",
                Ssid::from_bytes(b"corp").unwrap(),
                without_identity
            )
            .unwrap_err(),
            ProfileValidationError::MissingIdentity
        );
    }

    #[test]
    fn open_wifi_must_not_carry_a_secret() {
        let with_secret = WifiSecurity {
            secret: Some(secret()),
            ..WifiSecurity::open()
        };
        assert_eq!(
            ConnectionProfile::wifi(
                "home",
                "home",
                Ssid::from_bytes(b"home").unwrap(),
                with_secret
            )
            .unwrap_err(),
            ProfileValidationError::SecretNotAllowed
        );
    }

    #[test]
    fn ssid_length_is_checked() {
        let mut profile = wifi_profile("home");
        if let ConnectionType::Wifi(settings) = &mut profile.connection_type {
            settings.ssid = super::Ssid(vec![b'a'; 33]);
        }
        assert_eq!(
            profile.validate(),
            Err(ProfileValidationError::SsidTooLong(33))
        );

        let mut boundary = wifi_profile("home");
        if let ConnectionType::Wifi(settings) = &mut boundary.connection_type {
            settings.ssid = super::Ssid(vec![b'a'; 32]);
        }
        assert!(boundary.validate().is_ok());
    }

    #[test]
    fn id_must_be_non_empty_and_sanitized() {
        assert_eq!(
            wifi_profile("home").validate().unwrap(),
            (),
            "valid profile passes"
        );

        let mut empty = wifi_profile("home");
        empty.id = String::new();
        assert_eq!(empty.validate(), Err(ProfileValidationError::EmptyId));

        let mut unsafe_chars = wifi_profile("home");
        unsafe_chars.id = "a/b".to_string();
        assert_eq!(
            unsafe_chars.validate(),
            Err(ProfileValidationError::InvalidIdChars("a/b".to_string()))
        );

        let mut uppercase = wifi_profile("home");
        uppercase.id = "Home_Net-2".to_string();
        assert!(uppercase.validate().is_ok());
    }

    #[test]
    fn manual_ip_configuration_is_fully_validated() {
        let mut profile = wifi_profile("home");

        profile.ipv4 = IpConfig {
            method: IpMethod::Manual,
            ..IpConfig::default()
        };
        assert_eq!(
            profile.validate(),
            Err(ProfileValidationError::ManualAddressRequired)
        );

        profile.ipv4 = IpConfig {
            method: IpMethod::Manual,
            address: Some(IpAddr::from([192, 168, 1, 10])),
            ..IpConfig::default()
        };
        assert_eq!(
            profile.validate(),
            Err(ProfileValidationError::ManualPrefixRequired)
        );

        profile.ipv4.prefix_length = Some(40);
        assert_eq!(
            profile.validate(),
            Err(ProfileValidationError::PrefixOutOfRange(40))
        );

        profile.ipv4 = IpConfig {
            method: IpMethod::Manual,
            address: Some(IpAddr::from([192, 168, 1, 10])),
            prefix_length: Some(24),
            gateway: Some(IpAddr::from([192, 168, 1, 1])),
            dns_servers: vec![IpAddr::from([192, 168, 1, 1])],
        };
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn manual_config_rejects_address_of_the_wrong_family() {
        let mut profile = wifi_profile("home");
        profile.ipv6 = IpConfig {
            method: IpMethod::Manual,
            address: Some(IpAddr::from([192, 168, 1, 10])),
            prefix_length: Some(24),
            ..IpConfig::default()
        };
        assert_eq!(
            profile.validate(),
            Err(ProfileValidationError::AddressFamilyMismatch)
        );
    }

    #[test]
    fn device_matching_checks_kind_name_and_mac() {
        let mut profile = wifi_profile("home");
        assert!(profile.matches(&wifi_device()));
        assert!(!profile.matches(&DeviceInfo::ethernet("eth0", None)));

        profile.device_match = DeviceMatch {
            interface_name: Some("wlan0".to_string()),
            mac_address: None,
        };
        assert!(profile.matches(&wifi_device()));
        assert!(!profile.matches(&DeviceInfo::wifi("wlan1", None)));

        profile.device_match = DeviceMatch {
            interface_name: None,
            mac_address: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55].into()),
        };
        assert!(profile.matches(&wifi_device()));
        assert!(!profile.matches(&DeviceInfo::wifi(
            "wlan0",
            Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x00])
        )));
    }

    #[test]
    fn ethernet_profile_validates_and_matches_ethernet() {
        let mut profile = ConnectionProfile::ethernet("eth", "eth").unwrap();
        if let ConnectionType::Ethernet(settings) = &mut profile.connection_type {
            settings.speed_mbit = Some(0);
        }
        assert_eq!(
            profile.validate(),
            Err(ProfileValidationError::InvalidSpeed)
        );

        let profile = ConnectionProfile::ethernet("eth", "eth").unwrap();
        assert!(profile.matches(&DeviceInfo::ethernet("eth0", None)));
        assert!(!profile.matches(&wifi_device()));
    }

    #[test]
    fn connection_type_and_key_management_are_self_describing() {
        assert_eq!(wifi_profile("home").connection_type.to_string(), "wifi");
        assert_eq!(
            ConnectionType::Ethernet(super::EthernetSettings::default()).to_string(),
            "ethernet"
        );
        assert_eq!(KeyManagement::Sae.to_string(), "sae");
        assert_eq!(IpMethod::Disabled.to_string(), "disabled");
    }

    #[test]
    fn profile_round_trips_through_toml() {
        let profile = wifi_profile("home");
        let encoded = toml::to_string(&profile).unwrap();
        let decoded: ConnectionProfile = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded, profile);
    }
}
