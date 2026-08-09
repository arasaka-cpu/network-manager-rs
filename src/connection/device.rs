//! Device model used by profile matching and activation.
//!
//! The daemon's connection logic works against this small, platform-neutral
//! [`DeviceInfo`] description instead of raw rtnetlink/nl80211 structures, so
//! the Linux backends stay below the abstraction boundary.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::linux::model::{WirelessInterface, format_mac_address, parse_mac_address};

/// The kind of network device a profile can apply to.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DeviceKind {
    Wifi,
    Ethernet,
}

impl fmt::Display for DeviceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Wifi => "wifi",
            Self::Ethernet => "ethernet",
        })
    }
}

/// A 48-bit IEEE MAC address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl From<[u8; 6]> for MacAddress {
    fn from(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format_mac_address(&self.0))
    }
}

impl Serialize for MacAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MacAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let input = String::deserialize(deserializer)?;
        parse_mac_address(&input)
            .map(Self)
            .ok_or_else(|| serde::de::Error::custom("invalid mac address"))
    }
}

/// Minimal device description used by the profile matcher and activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceInfo {
    pub kind: DeviceKind,
    pub interface_name: String,
    pub mac_address: Option<MacAddress>,
}

impl From<&WirelessInterface> for DeviceInfo {
    fn from(interface: &WirelessInterface) -> Self {
        Self {
            kind: DeviceKind::Wifi,
            interface_name: interface.name.clone(),
            mac_address: interface.mac.map(MacAddress),
        }
    }
}

/// Convenience constructors for building devices in tests and adapters.
impl DeviceInfo {
    pub fn wifi(interface_name: impl Into<String>, mac_address: Option<[u8; 6]>) -> Self {
        Self {
            kind: DeviceKind::Wifi,
            interface_name: interface_name.into(),
            mac_address: mac_address.map(MacAddress),
        }
    }

    pub fn ethernet(interface_name: impl Into<String>, mac_address: Option<[u8; 6]>) -> Self {
        Self {
            kind: DeviceKind::Ethernet,
            interface_name: interface_name.into(),
            mac_address: mac_address.map(MacAddress),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceInfo, DeviceKind, MacAddress};
    use crate::linux::model::{
        InterfaceType, WifiBand, WifiBandId, WifiCapabilities, WifiCipher, WirelessInterface,
    };

    fn wireless_interface(name: &str, mac: Option<[u8; 6]>) -> WirelessInterface {
        WirelessInterface {
            index: 2,
            name: name.to_string(),
            wiphy_index: Some(0),
            wiphy_name: Some("phy0".to_string()),
            interface_type: InterfaceType::Station,
            mac,
            up: true,
            capabilities: WifiCapabilities {
                supported_interfaces: vec![InterfaceType::Station],
                cipher_suites: vec![WifiCipher::Ccmp],
                bands: vec![WifiBand {
                    id: WifiBandId::Ghz2,
                    channels: vec![1],
                    frequencies: vec![2412],
                    ht_capabilities: None,
                    vht_capabilities: None,
                }],
                max_scan_ssids: Some(4),
                scan_supported: true,
            },
        }
    }

    #[test]
    fn converts_wireless_interface_to_device_info() {
        let interface = wireless_interface("wlan0", Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        let device = DeviceInfo::from(&interface);
        assert_eq!(device.kind, DeviceKind::Wifi);
        assert_eq!(device.interface_name, "wlan0");
        assert_eq!(
            device.mac_address,
            Some(MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
    }

    #[test]
    fn preserves_missing_mac_address() {
        let interface = wireless_interface("wlan1", None);
        assert_eq!(DeviceInfo::from(&interface).mac_address, None);
    }

    #[test]
    fn mac_address_formats_and_round_trips_through_serde() {
        let mac = MacAddress([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        assert_eq!(mac.to_string(), "de:ad:be:ef:00:01");

        #[derive(serde::Serialize, serde::Deserialize)]
        struct Wrapper {
            mac: MacAddress,
        }
        let encoded = toml::to_string(&Wrapper { mac }).unwrap();
        assert!(encoded.contains("mac = \"de:ad:be:ef:00:01\""), "{encoded}");
        let decoded: Wrapper = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.mac, mac);
    }

    #[test]
    fn mac_address_rejects_invalid_input() {
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct Wrapper {
            mac: MacAddress,
        }
        let result: Result<Wrapper, _> = toml::from_str("mac = \"not-a-mac\"");
        assert!(result.is_err());
    }

    #[test]
    fn device_kind_is_self_describing() {
        assert_eq!(DeviceKind::Wifi.to_string(), "wifi");
        assert_eq!(DeviceKind::Ethernet.to_string(), "ethernet");
    }
}
