//! Translation between the typed connection model and NetworkManager's
//! `a{sa{sv}}` settings dictionary on D-Bus.
//!
//! NetworkManager represents a connection as a nested dictionary of settings
//! (section name -> property name -> value). This module converts
//! [`ConnectionProfile`] values into that representation for
//! `GetSettings`/`GetAppliedConnection` and back for
//! `AddConnection`/`Update`. Conversion is lossy by design: properties the
//! domain does not model are dropped, and secrets are never emitted or stored.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use zbus::zvariant::{Array, OwnedValue, Str, Value};

use crate::connection::profile::{
    ConnectionProfile, ConnectionType, IpConfig, IpMethod, KeyManagement, WifiSecurity,
};
use crate::connection::secrets::SecretReference;
use crate::linux::model::{IpFamily, Route, RouteKind, RouteScope, Ssid};

use super::error::FacadeError;

/// A NetworkManager connection settings dictionary (`a{sa{sv}}`).
pub type SettingsDict = HashMap<String, HashMap<String, OwnedValue>>;

// --- Builders -------------------------------------------------------------

fn val_str(value: impl Into<String>) -> OwnedValue {
    OwnedValue::from(Str::from(value.into()))
}

fn val_u32(value: u32) -> OwnedValue {
    OwnedValue::from(value)
}

fn val_i32(value: i32) -> OwnedValue {
    OwnedValue::from(value)
}

fn val_bool(value: bool) -> OwnedValue {
    OwnedValue::from(value)
}

fn val_bytes(value: Vec<u8>) -> OwnedValue {
    OwnedValue::try_from(Value::from(value)).expect("byte array converts to an owned value")
}

fn val_dict_array(value: Vec<HashMap<String, OwnedValue>>) -> OwnedValue {
    OwnedValue::try_from(Value::from(value)).expect("dict array converts to an owned value")
}

fn val_str_array(value: Vec<String>) -> OwnedValue {
    OwnedValue::try_from(Array::from(
        value.into_iter().map(Str::from).collect::<Vec<_>>(),
    ))
    .expect("string array converts to an owned value")
}

// --- Accessors -------------------------------------------------------------

fn as_value(value: &OwnedValue) -> Value<'_> {
    Value::from(value.clone())
}

fn get_str(section: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    let value = as_value(section.get(key)?);
    String::try_from(&value).ok()
}

fn get_str_array(section: &HashMap<String, OwnedValue>, key: &str) -> Option<Vec<String>> {
    let value = as_value(section.get(key)?);
    let array = match value {
        Value::Array(array) => array,
        _ => return None,
    };
    array
        .iter()
        .map(|element| match element {
            Value::Str(s) => Some(s.to_string()),
            _ => None,
        })
        .collect()
}

fn get_u32(section: &HashMap<String, OwnedValue>, key: &str) -> Option<u32> {
    let value = as_value(section.get(key)?);
    u32::try_from(&value).ok()
}

fn get_i32(section: &HashMap<String, OwnedValue>, key: &str) -> Option<i32> {
    let value = as_value(section.get(key)?);
    i32::try_from(&value).ok()
}

fn get_bool(section: &HashMap<String, OwnedValue>, key: &str) -> Option<bool> {
    let value = as_value(section.get(key)?);
    bool::try_from(&value).ok()
}

fn get_bytes(section: &HashMap<String, OwnedValue>, key: &str) -> Option<Vec<u8>> {
    let value = as_value(section.get(key)?);
    Vec::<u8>::try_from(value).ok()
}

fn get_dict_array(
    section: &HashMap<String, OwnedValue>,
    key: &str,
) -> Option<Vec<HashMap<String, OwnedValue>>> {
    let value = as_value(section.get(key)?);
    Vec::<HashMap<String, OwnedValue>>::try_from(value).ok()
}

// --- Static routes ----------------------------------------------------------

/// Parses the `ipv4.routes` (`aau`) or `ipv6.routes` (`a(ayuayu)`) setting into
/// model routes. Each NetworkManager route tuple is
/// `[destination, prefix, next-hop, metric]` with IPv4 scalars in the same
/// little-endian `u32` encoding the config objects use.
fn parse_routes(
    section: &HashMap<String, OwnedValue>,
    expect_v4: bool,
) -> Result<Vec<Route>, FacadeError> {
    let Some(value) = section.get("routes") else {
        return Ok(Vec::new());
    };
    let value = as_value(value);
    if expect_v4 {
        let entries: Vec<Vec<u32>> = Vec::try_from(value).map_err(|_| {
            FacadeError::InvalidProperty("ipv4.routes is not an array of u32 tuples".to_string())
        })?;
        entries
            .into_iter()
            .map(|entry| {
                if entry.len() != 4 {
                    return Err(FacadeError::InvalidProperty(
                        "ipv4.routes entry is not [dest, prefix, next-hop, metric]".to_string(),
                    ));
                }
                let prefix = entry[1];
                if prefix > 32 {
                    return Err(FacadeError::InvalidProperty(
                        "ipv4.routes prefix exceeds 32".to_string(),
                    ));
                }
                let next_hop = entry[2];
                Ok(Route {
                    family: IpFamily::V4,
                    destination: IpAddr::V4(Ipv4Addr::from(entry[0].to_le_bytes())),
                    prefix_length: prefix as u8,
                    gateway: (next_hop != 0)
                        .then(|| IpAddr::V4(Ipv4Addr::from(next_hop.to_le_bytes()))),
                    output_interface: None,
                    metric: (entry[3] != 0).then_some(entry[3]),
                    kind: RouteKind::Unicast,
                    scope: if prefix == 0 {
                        RouteScope::Universe
                    } else {
                        RouteScope::Link
                    },
                })
            })
            .collect()
    } else {
        let entries: Vec<(Vec<u8>, u32, Vec<u8>, u32)> = Vec::try_from(value).map_err(|_| {
            FacadeError::InvalidProperty("ipv6.routes is not a(ayuayu)".to_string())
        })?;
        entries
            .into_iter()
            .map(|(dest, prefix, next_hop, metric)| {
                if dest.len() != 16 || next_hop.len() != 16 {
                    return Err(FacadeError::InvalidProperty(
                        "ipv6.routes addresses are not 16 octets".to_string(),
                    ));
                }
                if prefix > 128 {
                    return Err(FacadeError::InvalidProperty(
                        "ipv6.routes prefix exceeds 128".to_string(),
                    ));
                }
                let mut gateway_bytes = [0u8; 16];
                gateway_bytes.copy_from_slice(&next_hop);
                let gateway = Ipv6Addr::from(gateway_bytes);
                Ok(Route {
                    family: IpFamily::V6,
                    destination: IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(dest).expect("len checked above"),
                    )),
                    prefix_length: prefix as u8,
                    gateway: (!gateway.is_unspecified()).then_some(IpAddr::V6(gateway)),
                    output_interface: None,
                    metric: (metric != 0).then_some(metric),
                    kind: RouteKind::Unicast,
                    scope: if prefix == 0 {
                        RouteScope::Universe
                    } else {
                        RouteScope::Link
                    },
                })
            })
            .collect()
    }
}

/// Serializes a route as the `ipv4.routes` `aau` tuple NetworkManager uses.
fn route_v4_entry(route: &Route) -> Vec<u32> {
    let destination = match route.destination {
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    };
    let next_hop = match route.gateway {
        Some(IpAddr::V4(address)) => address,
        _ => Ipv4Addr::UNSPECIFIED,
    };
    vec![
        u32::from_le_bytes(destination.octets()),
        u32::from(route.prefix_length),
        u32::from_le_bytes(next_hop.octets()),
        route.metric.unwrap_or(0),
    ]
}

/// Serializes a route as the `ipv6.routes` `a(ayuayu)` tuple NetworkManager uses.
fn route_v6_entry(route: &Route) -> (Vec<u8>, u32, Vec<u8>, u32) {
    let destination = match route.destination {
        IpAddr::V6(address) => address,
        IpAddr::V4(_) => Ipv6Addr::UNSPECIFIED,
    };
    let next_hop = match route.gateway {
        Some(IpAddr::V6(address)) => address,
        _ => Ipv6Addr::UNSPECIFIED,
    };
    (
        destination.octets().to_vec(),
        u32::from(route.prefix_length),
        next_hop.octets().to_vec(),
        route.metric.unwrap_or(0),
    )
}

fn val_v4_routes(routes: Vec<Vec<u32>>) -> OwnedValue {
    OwnedValue::try_from(Value::from(routes)).expect("u32 route arrays convert to an owned value")
}

fn val_v6_routes(routes: Vec<(Vec<u8>, u32, Vec<u8>, u32)>) -> OwnedValue {
    OwnedValue::try_from(Value::from(routes)).expect("route tuples convert to an owned value")
}

// --- Type and security mapping --------------------------------------------

/// The `connection.type` string for a profile.
pub fn connection_type_string(profile: &ConnectionProfile) -> String {
    match &profile.connection_type {
        ConnectionType::Wifi(_) => "802-11-wireless".to_string(),
        ConnectionType::Ethernet(_) => "802-3-ethernet".to_string(),
    }
}

/// The `802-11-wireless-security.key-mgmt` string for a key management mode.
pub fn key_management_string(key_management: KeyManagement) -> &'static str {
    match key_management {
        KeyManagement::Open => "none",
        KeyManagement::WpaPsk => "wpa-psk",
        KeyManagement::WpaEap => "wpa-eap",
        KeyManagement::Sae => "sae",
        KeyManagement::Owe => "owe",
    }
}

fn parse_key_management(value: &str) -> Result<WifiSecurity, FacadeError> {
    let security = match value {
        "none" | "" => WifiSecurity::open(),
        "owe" => WifiSecurity::owe(),
        "wpa-psk" => WifiSecurity::psk(SecretReference::Keyring {
            identifier: "nmd/wifi-psk".to_string(),
        }),
        "sae" => WifiSecurity::sae(SecretReference::Keyring {
            identifier: "nmd/wifi-sae".to_string(),
        }),
        "wpa-eap" => WifiSecurity::enterprise("nmd-enterprise".to_string()),
        other => {
            return Err(FacadeError::InvalidSetting(format!(
                "unsupported key management {other:?}"
            )));
        }
    };
    Ok(security)
}

// --- Profile -> dict --------------------------------------------------------

/// Renders a profile as a NetworkManager settings dictionary.
///
/// Secrets are never included: a Wi-Fi profile carrying a key management mode
/// only advertises the key-mgmt string, matching what NetworkManager exposes
/// to clients that lack the secret.
pub fn profile_to_settings(profile: &ConnectionProfile) -> SettingsDict {
    let mut dict = HashMap::new();

    let mut connection = HashMap::new();
    connection.insert("id".to_string(), val_str(&profile.id));
    connection.insert("uuid".to_string(), val_str(stable_uuid(&profile.id)));
    connection.insert("type".to_string(), val_str(connection_type_string(profile)));
    if let Some(interface_name) = &profile.device_match.interface_name {
        connection.insert("interface-name".to_string(), val_str(interface_name));
    }
    connection.insert("autoconnect".to_string(), val_bool(profile.autoconnect));
    connection.insert("priority".to_string(), val_i32(profile.priority));
    dict.insert("connection".to_string(), connection);

    match &profile.connection_type {
        ConnectionType::Wifi(settings) => {
            let mut wifi = HashMap::new();
            wifi.insert(
                "ssid".to_string(),
                val_bytes(settings.ssid.as_bytes().to_vec()),
            );
            wifi.insert("mode".to_string(), val_str("infrastructure"));
            if settings.hidden {
                wifi.insert("hidden".to_string(), val_bool(true));
            }
            if !matches!(settings.security.key_management, KeyManagement::Open) {
                wifi.insert("security".to_string(), val_str("802-11-wireless-security"));
            }
            dict.insert("802-11-wireless".to_string(), wifi);

            if !matches!(settings.security.key_management, KeyManagement::Open) {
                let mut security = HashMap::new();
                security.insert(
                    "key-mgmt".to_string(),
                    val_str(key_management_string(settings.security.key_management)),
                );
                dict.insert("802-11-wireless-security".to_string(), security);
            }
        }
        ConnectionType::Ethernet(_) => {}
    }

    dict.insert("ipv4".to_string(), ip_config_section(&profile.ipv4, true));
    dict.insert("ipv6".to_string(), ip_config_section(&profile.ipv6, false));

    dict
}

fn ip_config_section(config: &IpConfig, expect_v4: bool) -> HashMap<String, OwnedValue> {
    let mut section = HashMap::new();
    let method = match config.method {
        IpMethod::Automatic => "auto",
        IpMethod::Manual => "manual",
        IpMethod::Disabled => "disabled",
    };
    section.insert("method".to_string(), val_str(method));
    if config.method == IpMethod::Manual {
        if let Some(address) = config.address {
            let mut entry = HashMap::new();
            entry.insert("address".to_string(), val_str(address.to_string()));
            if let Some(prefix) = config.prefix_length {
                entry.insert("prefix".to_string(), val_u32(prefix.into()));
            }
            section.insert("address-data".to_string(), val_dict_array(vec![entry]));
        }
        if let Some(gateway) = config.gateway {
            section.insert("gateway".to_string(), val_str(gateway.to_string()));
        }
        if !config.dns_servers.is_empty() {
            section.insert(
                "dns".to_string(),
                val_str_array(
                    config
                        .dns_servers
                        .iter()
                        .map(|server| server.to_string())
                        .collect(),
                ),
            );
        }
    }
    if !config.routes.is_empty() {
        if expect_v4 {
            let routes = config
                .routes
                .iter()
                .filter(|route| route.family == IpFamily::V4)
                .map(route_v4_entry)
                .collect();
            section.insert("routes".to_string(), val_v4_routes(routes));
        } else {
            let routes = config
                .routes
                .iter()
                .filter(|route| route.family == IpFamily::V6)
                .map(route_v6_entry)
                .collect();
            section.insert("routes".to_string(), val_v6_routes(routes));
        }
    }
    section
}

// --- Dict -> profile ---------------------------------------------------------

/// Builds a validated profile from a NetworkManager settings dictionary.
///
/// Any embedded secrets in the incoming dictionary (for example `psk`) are
/// deliberately dropped; the profile only stores a [`SecretReference`].
pub fn settings_to_profile(dict: &SettingsDict) -> Result<ConnectionProfile, FacadeError> {
    let connection = dict
        .get("connection")
        .ok_or_else(|| FacadeError::MissingSetting("connection".to_string()))?;
    let id = get_str(connection, "id")
        .ok_or_else(|| FacadeError::InvalidProperty("connection.id is required".to_string()))?;
    let name = get_str(connection, "id").unwrap_or_default();
    let type_name = get_str(connection, "type")
        .ok_or_else(|| FacadeError::MissingSetting("connection.type".to_string()))?;

    let profile = match type_name.as_str() {
        "802-11-wireless" => {
            let wifi = dict
                .get("802-11-wireless")
                .ok_or_else(|| FacadeError::MissingSetting("802-11-wireless".to_string()))?;
            let ssid_bytes = get_bytes(wifi, "ssid").ok_or_else(|| {
                FacadeError::InvalidProperty("802-11-wireless.ssid is required".to_string())
            })?;
            let ssid = Ssid::from_bytes(&ssid_bytes).ok_or_else(|| {
                FacadeError::InvalidProperty("802-11-wireless.ssid exceeds 32 octets".to_string())
            })?;
            let key_management = dict
                .get("802-11-wireless-security")
                .and_then(|security| get_str(security, "key-mgmt"))
                .unwrap_or_else(|| "none".to_string());
            let security = parse_key_management(&key_management)?;
            ConnectionProfile::wifi(id, name, ssid, security).map_err(FacadeError::from)?
        }
        "802-3-ethernet" => ConnectionProfile::ethernet(id, name).map_err(FacadeError::from)?,
        other => {
            return Err(FacadeError::InvalidSetting(format!(
                "unsupported connection type {other:?}"
            )));
        }
    };

    let mut profile = profile;
    if let Some(interface_name) = get_str(connection, "interface-name") {
        profile.device_match.interface_name = Some(interface_name);
    }
    if let Some(autoconnect) = get_bool(connection, "autoconnect") {
        profile.autoconnect = autoconnect;
    }
    if let Some(priority) = get_i32(connection, "priority") {
        profile.priority = priority;
    }
    if let Some(ipv4) = dict.get("ipv4") {
        profile.ipv4 = parse_ip_config(ipv4, true)?;
    }
    if let Some(ipv6) = dict.get("ipv6") {
        profile.ipv6 = parse_ip_config(ipv6, false)?;
    }

    profile.validate().map_err(FacadeError::from)?;
    Ok(profile)
}

fn parse_ip_config(
    section: &HashMap<String, OwnedValue>,
    expect_v4: bool,
) -> Result<IpConfig, FacadeError> {
    let mut config = IpConfig::default();
    let method = get_str(section, "method").unwrap_or_else(|| "auto".to_string());
    config.method = match method.as_str() {
        "auto" | "" => IpMethod::Automatic,
        "manual" => IpMethod::Manual,
        "disabled" => IpMethod::Disabled,
        other => {
            return Err(FacadeError::InvalidSetting(format!(
                "unsupported IP method {other:?}"
            )));
        }
    };
    if config.method == IpMethod::Manual {
        let address_data = get_dict_array(section, "address-data").ok_or_else(|| {
            FacadeError::MissingSetting("ip method requires address-data".to_string())
        })?;
        let first = address_data.first().ok_or_else(|| {
            FacadeError::MissingSetting("manual IP configuration requires an address".to_string())
        })?;
        let address = get_str(first, "address")
            .ok_or_else(|| FacadeError::InvalidProperty("address missing".to_string()))?;
        let address: std::net::IpAddr = address.parse().map_err(|_| {
            FacadeError::InvalidProperty("address is not a valid IP address".to_string())
        })?;
        if address.is_ipv4() != expect_v4 {
            return Err(FacadeError::InvalidProperty(
                "address family does not match the setting".to_string(),
            ));
        }
        let prefix = get_u32(first, "prefix")
            .ok_or_else(|| FacadeError::MissingSetting("address prefix required".to_string()))?;
        config.address = Some(address);
        config.prefix_length = Some(prefix as u8);
        if let Some(gateway) = get_str(section, "gateway") {
            if let Ok(gateway) = gateway.parse() {
                config.gateway = Some(gateway);
            }
        }
        if let Some(dns) = get_str_array(section, "dns") {
            config.dns_servers = dns
                .into_iter()
                .filter_map(|server| server.parse().ok())
                .collect();
        }
    }
    config.routes = parse_routes(section, expect_v4)?;
    Ok(config)
}

// --- Stable identifiers -------------------------------------------------------

/// Deterministically derives a v5-style UUID from a profile id.
///
/// NetworkManager connections are addressed by UUID; the domain identifies
/// profiles by id. Deriving the UUID from the id keeps object paths and UUIDs
/// stable across daemon restarts without introducing a separate identity store.
pub fn stable_uuid(id: &str) -> String {
    let first = fnv1a(id.as_bytes(), 0xcbf2_9ce4_8422_2325);
    let second = fnv1a(id.as_bytes(), 0x8422_2325_cbf2_9ce4);
    format!(
        "{:08x}-{:04x}-5{:03x}-8{:03x}-{:012x}",
        (first >> 32) as u32,
        (first & 0xffff) as u16,
        ((first >> 16) & 0x0fff) as u16,
        (second & 0x0fff) as u16,
        (second >> 16) & 0xffff_ffff_ffff
    )
}

fn fnv1a(bytes: &[u8], mut hash: u64) -> u64 {
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

// --- Tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{profile_to_settings, settings_to_profile, stable_uuid};
    use crate::connection::profile::{
        ConnectionProfile, ConnectionType, IpConfig, IpMethod, WifiSecurity,
    };
    use crate::connection::secrets::SecretReference;
    use crate::linux::model::{IpFamily, Route, RouteKind, RouteScope, Ssid};

    fn open_profile(id: &str) -> ConnectionProfile {
        ConnectionProfile::wifi(
            id,
            id,
            Ssid::from_bytes(b"home").unwrap(),
            WifiSecurity::open(),
        )
        .unwrap()
    }

    fn psk_profile(id: &str) -> ConnectionProfile {
        ConnectionProfile::wifi(
            id,
            id,
            Ssid::from_bytes(b"home").unwrap(),
            WifiSecurity::psk(SecretReference::Keyring {
                identifier: format!("nmd/{id}"),
            }),
        )
        .unwrap()
    }

    #[test]
    fn profile_round_trips_through_the_settings_dict() {
        let mut profile = psk_profile("home");
        profile.ipv4 = IpConfig {
            method: IpMethod::Manual,
            address: Some(IpAddr::from([192, 168, 1, 10])),
            prefix_length: Some(24),
            gateway: Some(IpAddr::from([192, 168, 1, 1])),
            dns_servers: vec![IpAddr::from([192, 168, 1, 1])],
            routes: Vec::new(),
        };

        let dict = profile_to_settings(&profile);
        let decoded = settings_to_profile(&dict).unwrap();
        assert_eq!(decoded.id, profile.id);
        assert_eq!(decoded.autoconnect, profile.autoconnect);
        let ConnectionType::Wifi(decoded_wifi) = &decoded.connection_type else {
            panic!("decoded profile is not a wifi profile");
        };
        let ConnectionType::Wifi(original_wifi) = &profile.connection_type else {
            panic!("original profile is not a wifi profile");
        };
        assert_eq!(decoded_wifi.ssid, original_wifi.ssid);
        assert_eq!(decoded_wifi.hidden, original_wifi.hidden);
        assert_eq!(
            decoded_wifi.security.key_management,
            original_wifi.security.key_management
        );
        assert_eq!(decoded.ipv4, profile.ipv4);
    }

    #[test]
    fn open_wifi_dict_round_trips() {
        let dict = profile_to_settings(&open_profile("open"));
        assert!(!dict.contains_key("802-11-wireless-security"));
        let decoded = settings_to_profile(&dict).unwrap();
        assert_eq!(
            decoded.connection_type,
            open_profile("open").connection_type
        );
    }

    #[test]
    fn secrets_are_never_emitted() {
        let dict = profile_to_settings(&psk_profile("home"));
        let security = &dict["802-11-wireless-security"];
        assert!(!security.contains_key("psk"), "secrets must not leak");
    }

    #[test]
    fn stable_uuid_is_deterministic_and_formatted() {
        let first = stable_uuid("home");
        assert_eq!(first, stable_uuid("home"));
        assert_ne!(first, stable_uuid("office"));
        let parts: Vec<&str> = first.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
    }

    #[test]
    fn unsupported_connection_types_are_rejected() {
        let mut dict = profile_to_settings(&open_profile("home"));
        let connection = dict.get_mut("connection").unwrap();
        connection.insert("type".to_string(), super::val_str("vpn"));
        assert!(settings_to_profile(&dict).is_err());
    }

    #[test]
    fn profile_validation_error_becomes_invalid_setting() {
        let mut profile = open_profile("home");
        profile.id = "a/b".to_string();
        let error: super::super::error::FacadeError =
            super::super::error::FacadeError::from(profile.validate().unwrap_err());
        assert!(matches!(
            error,
            super::super::error::FacadeError::InvalidSetting(_)
        ));
    }

    #[test]
    fn manual_address_family_mismatch_is_reported() {
        let mut profile = open_profile("home");
        profile.ipv6 = IpConfig {
            method: IpMethod::Manual,
            address: Some(IpAddr::from([192, 168, 1, 10])),
            prefix_length: Some(24),
            ..IpConfig::default()
        };
        let dict = profile_to_settings(&profile);
        assert!(settings_to_profile(&dict).is_err());
    }

    fn static_v4_route(
        destination: Ipv4Addr,
        prefix_length: u8,
        gateway: Option<Ipv4Addr>,
        metric: Option<u32>,
    ) -> Route {
        Route {
            family: IpFamily::V4,
            destination: IpAddr::V4(destination),
            prefix_length,
            gateway: gateway.map(IpAddr::V4),
            output_interface: None,
            metric,
            kind: RouteKind::Unicast,
            scope: if prefix_length == 0 {
                RouteScope::Universe
            } else {
                RouteScope::Link
            },
        }
    }

    fn static_v6_route(
        destination: Ipv6Addr,
        prefix_length: u8,
        gateway: Option<Ipv6Addr>,
        metric: Option<u32>,
    ) -> Route {
        Route {
            family: IpFamily::V6,
            destination: IpAddr::V6(destination),
            prefix_length,
            gateway: gateway.map(IpAddr::V6),
            output_interface: None,
            metric,
            kind: RouteKind::Unicast,
            scope: if prefix_length == 0 {
                RouteScope::Universe
            } else {
                RouteScope::Link
            },
        }
    }

    #[test]
    fn ipv4_routes_round_trip_through_the_settings_dict() {
        let mut profile = open_profile("home");
        profile.ipv4 = IpConfig {
            method: IpMethod::Manual,
            address: Some(IpAddr::from([10, 0, 0, 5])),
            prefix_length: Some(24),
            gateway: Some(IpAddr::from([10, 0, 0, 1])),
            dns_servers: Vec::new(),
            routes: vec![
                static_v4_route(
                    Ipv4Addr::new(10, 10, 0, 0),
                    16,
                    Some(Ipv4Addr::new(10, 0, 0, 1)),
                    Some(100),
                ),
                static_v4_route(
                    Ipv4Addr::new(172, 16, 0, 0),
                    12,
                    Some(Ipv4Addr::new(10, 0, 0, 1)),
                    Some(200),
                ),
                static_v4_route(
                    Ipv4Addr::new(0, 0, 0, 0),
                    0,
                    Some(Ipv4Addr::new(10, 0, 0, 1)),
                    Some(50),
                ),
                static_v4_route(Ipv4Addr::new(10, 20, 0, 0), 24, None, None),
            ],
        };

        let dict = profile_to_settings(&profile);
        let decoded = settings_to_profile(&dict).unwrap();
        assert_eq!(decoded.ipv4.routes, profile.ipv4.routes);
    }

    #[test]
    fn ipv6_routes_round_trip_through_the_settings_dict() {
        let mut profile = open_profile("home");
        profile.ipv6 = IpConfig {
            method: IpMethod::Manual,
            address: Some("2001:db8:1::2".parse().unwrap()),
            prefix_length: Some(64),
            gateway: Some("2001:db8:1::1".parse().unwrap()),
            dns_servers: Vec::new(),
            routes: vec![
                static_v6_route(
                    "fd00::".parse().unwrap(),
                    8,
                    Some("2001:db8:1::1".parse().unwrap()),
                    Some(100),
                ),
                static_v6_route(
                    "2001:db8:10::".parse().unwrap(),
                    64,
                    Some("2001:db8:1::1".parse().unwrap()),
                    Some(200),
                ),
                static_v6_route(
                    "::".parse().unwrap(),
                    0,
                    Some("2001:db8:1::1".parse().unwrap()),
                    Some(50),
                ),
                static_v6_route("fd11::".parse().unwrap(), 32, None, None),
            ],
        };

        let dict = profile_to_settings(&profile);
        let decoded = settings_to_profile(&dict).unwrap();
        assert_eq!(decoded.ipv6.routes, profile.ipv6.routes);
    }

    #[test]
    fn routes_of_the_wrong_family_are_dropped_from_the_section() {
        let mut profile = open_profile("home");
        profile.ipv4 = IpConfig {
            method: IpMethod::Manual,
            address: Some(IpAddr::from([10, 0, 0, 5])),
            prefix_length: Some(24),
            gateway: Some(IpAddr::from([10, 0, 0, 1])),
            dns_servers: Vec::new(),
            routes: vec![static_v6_route(
                "fd00::".parse().unwrap(),
                8,
                Some("2001:db8:1::1".parse().unwrap()),
                Some(100),
            )],
        };

        let dict = profile_to_settings(&profile);
        let decoded = settings_to_profile(&dict).unwrap();
        assert!(
            decoded.ipv4.routes.is_empty(),
            "a v6 route in ipv4.routes must not survive the round trip"
        );
    }

    #[test]
    fn invalid_v4_route_prefixes_are_rejected() {
        let mut profile = open_profile("home");
        profile.ipv4 = IpConfig {
            method: IpMethod::Manual,
            address: Some(IpAddr::from([10, 0, 0, 5])),
            prefix_length: Some(24),
            gateway: Some(IpAddr::from([10, 0, 0, 1])),
            dns_servers: Vec::new(),
            routes: Vec::new(),
        };
        let mut dict = profile_to_settings(&profile);
        dict.get_mut("ipv4").unwrap().insert(
            "routes".to_string(),
            super::val_v4_routes(vec![vec![0, 33, 0, 0]]),
        );
        assert!(settings_to_profile(&dict).is_err());
    }
}
