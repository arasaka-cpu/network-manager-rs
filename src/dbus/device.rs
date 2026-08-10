//! D-Bus device objects.
//!
//! The `Device` interface and its per-type sub-interfaces are rendered from
//! snapshots of the daemon's kernel state ([`crate::linux::model::Link`] and
//! [`crate::linux::model::WirelessInterface`]). The D-Bus layer keeps no
//! second device model; every property is derived from the domain on access.

use std::sync::Arc;

use zbus::blocking::Connection;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::interface;

use crate::connection::device::{DeviceInfo, DeviceKind as DomainDeviceKind};
use crate::daemon::Daemon;
use crate::linux::model::format_mac_address;

use super::convert::SettingsDict;
use super::error::FacadeError;
use super::shared::Shared;
use super::{
    NM_CONNECTIVITY_FULL, NM_CONNECTIVITY_NONE, NM_DEVICE_STATE_ACTIVATED,
    NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_UNAVAILABLE, NM_DEVICE_TYPE_ETHERNET,
    NM_DEVICE_TYPE_LOOPBACK, NM_DEVICE_TYPE_WIFI,
};

/// The device types the facade can render.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceKind {
    Wifi,
    Ethernet,
    Loopback,
}

impl DeviceKind {
    pub const fn nm_type(self) -> u32 {
        match self {
            Self::Wifi => NM_DEVICE_TYPE_WIFI,
            Self::Ethernet => NM_DEVICE_TYPE_ETHERNET,
            Self::Loopback => NM_DEVICE_TYPE_LOOPBACK,
        }
    }

    pub const fn driver(self) -> &'static str {
        match self {
            Self::Wifi => "wifi",
            Self::Ethernet => "ethernet",
            Self::Loopback => "loopback",
        }
    }

    pub const fn domain_kind(self) -> DomainDeviceKind {
        match self {
            Self::Wifi => DomainDeviceKind::Wifi,
            Self::Ethernet | Self::Loopback => DomainDeviceKind::Ethernet,
        }
    }
}

/// A read-only projection of one kernel interface for the D-Bus layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceView {
    pub index: i32,
    pub interface: String,
    pub kind: DeviceKind,
    pub mac: Option<[u8; 6]>,
    pub up: bool,
}

impl DeviceView {
    pub fn to_device_info(&self) -> DeviceInfo {
        DeviceInfo {
            kind: self.kind.domain_kind(),
            interface_name: self.interface.clone(),
            mac_address: self.mac.map(crate::connection::device::MacAddress),
        }
    }
}

/// Enumerates the daemon's devices as a deterministic, index-sorted list.
pub fn enumerate_devices(
    daemon: &Daemon<impl crate::daemon::NetworkBackend>,
) -> Result<Vec<DeviceView>, FacadeError> {
    let mut devices: Vec<DeviceView> = daemon
        .wifi_interfaces()?
        .iter()
        .map(|interface| DeviceView {
            index: interface.index,
            interface: interface.name.clone(),
            kind: DeviceKind::Wifi,
            mac: interface.mac,
            up: interface.up,
        })
        .collect();

    for link in daemon.links()? {
        if devices.iter().any(|device| device.index == link.index) {
            continue;
        }
        let kind = if link.flags.is_loopback() {
            DeviceKind::Loopback
        } else {
            DeviceKind::Ethernet
        };
        devices.push(DeviceView {
            index: link.index,
            interface: link.name.clone(),
            kind,
            mac: None,
            up: link.flags.is_up(),
        });
    }

    devices.sort_by_key(|device| device.index);
    Ok(devices)
}

/// The base `org.freedesktop.NetworkManager.Device` interface.
pub struct DeviceIface<B> {
    shared: Arc<Shared<B>>,
    index: i32,
    _conn: Connection,
}

impl<B: crate::daemon::NetworkBackend + Send + Sync + 'static> DeviceIface<B> {
    pub fn new(shared: Arc<Shared<B>>, index: i32, conn: Connection) -> Self {
        Self {
            shared,
            index,
            _conn: conn,
        }
    }

    fn view(&self) -> Result<DeviceView, FacadeError> {
        let daemon = self.shared.daemon();
        let view = enumerate_devices(&daemon)?
            .into_iter()
            .find(|device| device.index == self.index)
            .ok_or_else(|| FacadeError::UnknownDevice(format!("device {}", self.index)))?;
        Ok(view)
    }

    fn active(&self) -> Result<Option<crate::connection::activation::ActiveConnection>, FacadeError> {
        let view = self.view()?;
        Ok(self.shared.device_active(&view.interface))
    }

    fn current_state(&self) -> Result<u32, FacadeError> {
        let view = self.view()?;
        Ok(match self.active()? {
            Some(active)
                if active.device.interface_name == view.interface
                    && active.state == crate::connection::state::ConnectionState::Activated =>
            {
                NM_DEVICE_STATE_ACTIVATED
            }
            _ if view.up => NM_DEVICE_STATE_DISCONNECTED,
            _ => NM_DEVICE_STATE_UNAVAILABLE,
        })
    }

    fn interface_name(&self) -> Result<String, FacadeError> {
        Ok(self.view()?.interface)
    }
}

#[interface(name = "org.freedesktop.NetworkManager.Device")]
impl<B: crate::daemon::NetworkBackend + Send + Sync + 'static> DeviceIface<B> {
    #[zbus(signal)]
    #[zbus(name = "StateChanged")]
    async fn state_changed_signal(
        emitter: &SignalEmitter<'_>,
        state: u32,
        reason: u32,
        prev_state: u32,
    ) -> zbus::Result<()>;

    fn reapply(
        &self,
        _connection: SettingsDict,
        _version_id: u64,
        _flags: u32,
    ) -> Result<(), FacadeError> {
        Err(FacadeError::not_supported("Reapply"))
    }

    fn get_applied_connection(&self, _flags: u32) -> Result<(SettingsDict, u64), FacadeError> {
        let dict = match self.active()? {
            Some(active) => super::convert::profile_to_settings(&active.profile),
            None => SettingsDict::new(),
        };
        Ok((dict, 0))
    }

    fn set_managed(&self, _managed: u32, _flags: u32) -> Result<(), FacadeError> {
        Err(FacadeError::not_supported("SetManaged"))
    }

    fn disconnect(&self, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) -> Result<(), FacadeError> {
        let current = self.current_state()?;
        let iface = self.interface_name()?;
        let active = self
            .active()?
            .ok_or(FacadeError::NotActive(iface))?;
        self.shared.daemon_mut().deactivate(active.id)?;
        let new = self.current_state()?;
        super::emit(Self::state_changed_signal(&emitter, new, current, 0))?;
        Ok(())
    }

    fn delete(&self, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) -> Result<(), FacadeError> {
        let iface = self.interface_name()?;
        let active = self
            .active()?
            .ok_or(FacadeError::NotActive(iface))?;
        let profile_id = active.profile.id.clone();
        self.shared.daemon_mut().delete_profile(&profile_id)?;
        self.shared.unregister_connection(&profile_id)?;
        super::emit(Self::state_changed_signal(
            &emitter,
            NM_DEVICE_STATE_DISCONNECTED,
            NM_DEVICE_STATE_ACTIVATED,
            0,
        ))?;
        Ok(())
    }

    #[zbus(property)]
    fn udi(&self) -> Result<String, zbus::fdo::Error> {
        Ok(String::new())
    }

    #[zbus(property)]
    fn path(&self) -> Result<String, zbus::fdo::Error> {
        Ok(String::new())
    }

    #[zbus(property)]
    fn interface(&self) -> Result<String, zbus::fdo::Error> {
        self.interface_name().map_err(Into::into)
    }

    #[zbus(property)]
    fn ip_interface(&self) -> Result<String, zbus::fdo::Error> {
        self.interface_name().map_err(Into::into)
    }

    #[zbus(property)]
    fn driver(&self) -> Result<String, zbus::fdo::Error> {
        Ok(self
            .view()?
            .kind
            .driver()
            .to_string())
    }

    #[zbus(property)]
    fn driver_version(&self) -> Result<String, zbus::fdo::Error> {
        Ok(String::new())
    }

    #[zbus(property)]
    fn firmware_version(&self) -> Result<String, zbus::fdo::Error> {
        Ok(String::new())
    }

    #[zbus(property)]
    fn capabilities(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(0)
    }

    #[zbus(property)]
    fn ip4_address(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(0)
    }

    #[zbus(property)]
    fn state(&self) -> Result<u32, zbus::fdo::Error> {
        self.current_state().map_err(Into::into)
    }

    #[zbus(property)]
    fn state_reason(&self) -> Result<(u32, u32), zbus::fdo::Error> {
        Ok((self.current_state()?, 0))
    }

    #[zbus(property)]
    fn active_connection(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        Ok(self
            .active()?
            .map(|active| OwnedObjectPath::try_from(super::active_path(active.id)).unwrap_or_else(|_| super::root_object_path()))
            .unwrap_or_else(super::root_object_path))
    }

    #[zbus(property)]
    fn ip4_config(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        Ok(self
            .active()?
            .map(|active| OwnedObjectPath::try_from(super::ip4_path(active.id)).unwrap_or_else(|_| super::root_object_path()))
            .unwrap_or_else(super::root_object_path))
    }

    #[zbus(property)]
    fn dhcp4_config(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        Ok(self
            .active()?
            .map(|active| OwnedObjectPath::try_from(super::dhcp4_path(active.id)).unwrap_or_else(|_| super::root_object_path()))
            .unwrap_or_else(super::root_object_path))
    }

    #[zbus(property)]
    fn ip6_config(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        Ok(self
            .active()?
            .map(|active| OwnedObjectPath::try_from(super::ip6_path(active.id)).unwrap_or_else(|_| super::root_object_path()))
            .unwrap_or_else(super::root_object_path))
    }

    #[zbus(property)]
    fn dhcp6_config(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        Ok(super::root_object_path())
    }

    #[zbus(property)]
    fn managed(&self) -> Result<bool, zbus::fdo::Error> {
        Ok(true)
    }

    #[zbus(property)]
    fn autoconnect(&self) -> Result<bool, zbus::fdo::Error> {
        Ok(true)
    }

    #[zbus(property)]
    fn set_autoconnect(&self, _autoconnect: bool) -> Result<(), FacadeError> {
        Ok(())
    }

    #[zbus(property)]
    fn firmware_missing(&self) -> Result<bool, zbus::fdo::Error> {
        Ok(false)
    }

    #[zbus(property)]
    fn nm_plugin_missing(&self) -> Result<bool, zbus::fdo::Error> {
        Ok(false)
    }

    #[zbus(property)]
    fn device_type(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(self.view()?.kind.nm_type())
    }

    #[zbus(property)]
    fn available_connections(&self) -> Result<Vec<OwnedObjectPath>, zbus::fdo::Error> {
        let daemon = self.shared.daemon();
        let view = self.view()?;
        let device_info = view.to_device_info();
        Ok(daemon
            .list_profiles()
            .map_err(FacadeError::from)?
            .iter()
            .filter(|profile| profile.matches(&device_info))
            .filter_map(|profile| self.shared.connection_path_lookup(&profile.id))
            .filter_map(|path| OwnedObjectPath::try_from(path).ok())
            .collect())
    }

    #[zbus(property)]
    fn physical_port_id(&self) -> Result<String, zbus::fdo::Error> {
        Ok(String::new())
    }

    #[zbus(property)]
    fn mtu(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(0)
    }

    #[zbus(property)]
    fn metered(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(0)
    }

    #[zbus(property)]
    fn lldp_neighbors(
        &self,
    ) -> Result<Vec<std::collections::HashMap<String, OwnedValue>>, zbus::fdo::Error> {
        Ok(Vec::new())
    }

    #[zbus(property)]
    fn real(&self) -> Result<bool, zbus::fdo::Error> {
        Ok(true)
    }

    #[zbus(property)]
    fn ip4_connectivity(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(if self.active()?.is_some() {
            NM_CONNECTIVITY_FULL
        } else {
            NM_CONNECTIVITY_NONE
        })
    }

    #[zbus(property)]
    fn ip6_connectivity(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(NM_CONNECTIVITY_NONE)
    }

    #[zbus(property)]
    fn interface_flags(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(if self.view()?.up { 3 } else { 0 })
    }

    #[zbus(property)]
    fn hw_address(&self) -> Result<String, zbus::fdo::Error> {
        Ok(self
            .view()?
            .mac
            .map(|mac| format_mac_address(&mac))
            .unwrap_or_default())
    }

    #[zbus(property)]
    fn ports(&self) -> Result<Vec<OwnedObjectPath>, zbus::fdo::Error> {
        Ok(Vec::new())
    }
}

/// The `org.freedesktop.NetworkManager.Device.Wired` interface.
pub struct WiredIface<B> {
    shared: Arc<Shared<B>>,
    index: i32,
}

impl<B> WiredIface<B> {
    pub fn new(shared: Arc<Shared<B>>, index: i32) -> Self {
        Self { shared, index }
    }
}

#[interface(name = "org.freedesktop.NetworkManager.Device.Wired")]
impl<B: crate::daemon::NetworkBackend + Send + Sync + 'static> WiredIface<B> {
    #[zbus(property)]
    fn hw_address(&self) -> Result<String, zbus::fdo::Error> {
        Ok(self
            .shared
            .device_view(self.index)?
            .mac
            .map(|mac| format_mac_address(&mac))
            .unwrap_or_default())
    }

    #[zbus(property)]
    fn perm_hw_address(&self) -> Result<String, zbus::fdo::Error> {
        Ok(String::new())
    }

    #[zbus(property)]
    fn speed(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(0)
    }

    #[zbus(property)]
    fn s390_subchannels(&self) -> Result<Vec<String>, zbus::fdo::Error> {
        Ok(Vec::new())
    }

    #[zbus(property)]
    fn carrier(&self) -> Result<bool, zbus::fdo::Error> {
        Ok(self.shared.device_view(self.index)?.up)
    }
}

/// The `org.freedesktop.NetworkManager.Device.Wireless` interface.
pub struct WirelessIface<B> {
    shared: Arc<Shared<B>>,
    index: i32,
}

impl<B> WirelessIface<B> {
    pub fn new(shared: Arc<Shared<B>>, index: i32) -> Self {
        Self { shared, index }
    }
}

#[interface(name = "org.freedesktop.NetworkManager.Device.Wireless")]
impl<B: crate::daemon::NetworkBackend + Send + Sync + 'static> WirelessIface<B> {
    #[zbus(signal)]
    async fn access_point_added(
        emitter: &SignalEmitter<'_>,
        access_point: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn access_point_removed(
        emitter: &SignalEmitter<'_>,
        access_point: OwnedObjectPath,
    ) -> zbus::Result<()>;

    fn get_access_points(&self) -> Result<Vec<OwnedObjectPath>, FacadeError> {
        self.all_access_points()
    }

    fn get_all_access_points(&self) -> Result<Vec<OwnedObjectPath>, FacadeError> {
        self.all_access_points()
    }

    fn request_scan(
        &self,
        _options: std::collections::HashMap<String, OwnedValue>,
    ) -> Result<(), FacadeError> {
        Ok(self.shared.daemon_mut().scan_wifi().map(|_| ())?)
    }

    fn all_access_points(&self) -> Result<Vec<OwnedObjectPath>, FacadeError> {
        let daemon = self.shared.daemon();
        let is_primary = enumerate_devices(&daemon)?
            .iter()
            .filter(|device| device.kind == DeviceKind::Wifi)
            .map(|device| device.index)
            .min()
            == Some(self.index);
        if !is_primary {
            return Ok(Vec::new());
        }
        Ok(self
            .shared
            .access_point_paths()
            .into_iter()
            .filter_map(|path| OwnedObjectPath::try_from(path).ok())
            .collect())
    }

    #[zbus(property)]
    fn hw_address(&self) -> Result<String, zbus::fdo::Error> {
        Ok(self
            .shared
            .device_view(self.index)?
            .mac
            .map(|mac| format_mac_address(&mac))
            .unwrap_or_default())
    }

    #[zbus(property)]
    fn perm_hw_address(&self) -> Result<String, zbus::fdo::Error> {
        Ok(String::new())
    }

    #[zbus(property)]
    fn mode(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(2)
    }

    #[zbus(property)]
    fn bitrate(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(0)
    }

    #[zbus(property)]
    fn access_points(&self) -> Result<Vec<OwnedObjectPath>, zbus::fdo::Error> {
        self.all_access_points().map_err(Into::into)
    }

    #[zbus(property)]
    fn active_access_point(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        Ok(super::root_object_path())
    }

    #[zbus(property)]
    fn wireless_capabilities(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(0x3)
    }

    #[zbus(property)]
    fn last_scan(&self) -> Result<i64, zbus::fdo::Error> {
        Ok(0)
    }
}

/// The `org.freedesktop.NetworkManager.Device.Statistics` interface.
pub struct StatisticsIface;

#[interface(name = "org.freedesktop.NetworkManager.Device.Statistics")]
impl StatisticsIface {
    #[zbus(property)]
    fn refresh_rate_ms(&self) -> u32 {
        0
    }

    #[zbus(property)]
    fn set_refresh_rate_ms(&self, _refresh_rate_ms: u32) {}

    #[zbus(property)]
    fn tx_bytes(&self) -> u64 {
        0
    }

    #[zbus(property)]
    fn rx_bytes(&self) -> u64 {
        0
    }
}
