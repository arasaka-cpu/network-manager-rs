#![cfg_attr(not(target_os = "linux"), allow(unused))]

pub mod connection;
pub mod daemon;
pub mod dbus;
pub mod linux;

pub use connection::{
    ActivationEngine, ActivationError, ActivationManager, ActiveConnection, ActiveConnectionId,
    ConnectionEvent, ConnectionProfile, ConnectionState, DeviceInfo, DeviceKind, DeviceMatch,
    EnvSecretProvider, EthernetDuplex, EthernetSettings, FileProfileStore, InMemoryProfileStore,
    IpConfig, IpMethod, KeyManagement, MacAddress, ProfileStore, SecretError, SecretProvider,
    SecretReference, StateError, StoreError, UnsupportedActivationEngine, WifiSecurity,
    WifiSettings, WpaSupplicantActivationEngine,
};
pub use daemon::{Daemon, NetworkBackend};
pub use linux::model::{
    AccessPoint, AccessPointSecurity, Address, AddressEvent, AddressEventKind, Bssid,
    InterfaceType, IpFamily, Link, LinkEvent, LinkEventKind, LinkFlags, NetlinkError, NetworkEvent,
    NetworkEventSource, Route, RouteEvent, RouteEventKind, RouteKind, RouteScope, Ssid,
    WifiAuthSuite, WifiBand, WifiBandId, WifiCapabilities, WifiCipher, WifiEvent, WifiEventKind,
    WirelessInterface, frequency_to_channel,
};
pub use linux::netlink::RtnetlinkBackend;
pub use linux::supplicant::{SupplicantControl, SupplicantError, WpaSupplicant};
pub use linux::wifi::{WifiEventSource, access_points, scan_wifi, wifi_interfaces};
