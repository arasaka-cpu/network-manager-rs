#![cfg_attr(not(target_os = "linux"), allow(unused))]

pub mod daemon;
pub mod linux;

pub use daemon::{Daemon, NetworkBackend};
pub use linux::model::{
    AccessPoint, AccessPointSecurity, Address, AddressEvent, AddressEventKind, Bssid,
    InterfaceType, Link, LinkEvent, LinkEventKind, LinkFlags, NetlinkError, NetworkEvent,
    NetworkEventSource, Ssid, WifiAuthSuite, WifiBand, WifiBandId, WifiCapabilities, WifiCipher,
    WifiEvent, WifiEventKind, WirelessInterface, frequency_to_channel,
};
pub use linux::netlink::RtnetlinkBackend;
pub use linux::wifi::{WifiEventSource, access_points, scan_wifi, wifi_interfaces};
