//! High-level Wi-Fi discovery built on the read-only nl80211 connection.

use std::io;
use std::thread;
use std::time::Duration;

use crate::linux::model::{
    AccessPoint, InterfaceType, NetlinkError, NetworkEvent, NetworkEventSource, WifiEvent,
    WirelessInterface,
};
use crate::linux::netlink::shutdown_requested;
use crate::linux::nl80211::{Nl80211Connection, WiphyInfo};

/// Opens a connection and dumps every wireless interface, merging wiphy
/// capability information where the wiphy can be resolved.
pub fn wifi_interfaces() -> Result<Vec<WirelessInterface>, NetlinkError> {
    let mut connection = Nl80211Connection::open()?;
    let mut interfaces = connection.dump_interfaces()?;
    let wiphys = connection.dump_wiphys()?;
    for interface in &mut interfaces {
        if let Some(wiphy) = lookup_wiphy(&wiphys, interface.wiphy_index) {
            interface.wiphy_name = Some(wiphy.name.clone());
            interface.capabilities = wiphy.capabilities.clone();
        }
    }
    Ok(interfaces)
}

/// Returns the cached scan results for the first suitable wireless interface.
pub fn access_points() -> Result<Vec<AccessPoint>, NetlinkError> {
    let mut connection = Nl80211Connection::open()?;
    let index = scan_interface_index(&connection.dump_interfaces()?)?;
    connection.dump_scan(index)
}

/// Triggers a scan on the first suitable wireless interface and returns the
/// resulting access points.
pub fn scan_wifi() -> Result<Vec<AccessPoint>, NetlinkError> {
    let mut connection = Nl80211Connection::open()?;
    let index = scan_interface_index(&connection.dump_interfaces()?)?;
    connection.trigger_scan(index)?;
    connection.dump_scan(index)
}

fn lookup_wiphy(wiphys: &[WiphyInfo], index: Option<u32>) -> Option<&WiphyInfo> {
    index.and_then(|index| wiphys.iter().find(|wiphy| wiphy.index == index))
}

/// Picks the interface to scan with: the first station, falling back to the
/// first non-monitor interface.
fn scan_interface_index(interfaces: &[WirelessInterface]) -> Result<i32, NetlinkError> {
    interfaces
        .iter()
        .find(|interface| interface.interface_type == InterfaceType::Station)
        .or_else(|| {
            interfaces
                .iter()
                .find(|interface| interface.interface_type != InterfaceType::Monitor)
        })
        .map(|interface| interface.index)
        .ok_or(NetlinkError::MalformedMessage(
            "no wireless interface available for scanning",
        ))
}

/// A blocking source of Wi-Fi scan events delivered through the nl80211
/// "scan" multicast group.
pub struct WifiEventSource {
    connection: Nl80211Connection,
    pending: Vec<WifiEvent>,
}

impl WifiEventSource {
    pub fn open() -> Result<Self, NetlinkError> {
        let connection = Nl80211Connection::open()?;
        connection.set_nonblocking()?;
        Ok(Self {
            connection,
            pending: Vec::new(),
        })
    }
}

impl NetworkEventSource for WifiEventSource {
    fn next_event(&mut self) -> Result<Option<NetworkEvent>, NetlinkError> {
        loop {
            if let Some(event) = self.pending.pop() {
                return Ok(Some(NetworkEvent::Wifi(event)));
            }
            if shutdown_requested() {
                return Ok(None);
            }
            match self.connection.read_scan_events() {
                Ok(mut events) => {
                    events.reverse();
                    self.pending = events;
                }
                Err(NetlinkError::Io(err))
                    if matches!(
                        err.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    if shutdown_requested() {
                        return Ok(None);
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                Err(err) => return Err(err),
            }
        }
    }
}
