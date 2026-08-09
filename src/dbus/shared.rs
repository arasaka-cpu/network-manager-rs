//! Shared daemon state behind the D-Bus facade.
//!
//! [`Shared`] owns the single [`Daemon`] instance plus the connection object
//! registry. Every interface object on the bus holds an `Arc<Shared>` and
//! renders its properties from the daemon's live state on access, so there is
//! exactly one source of truth for both the kernel-backed view and the D-Bus
//! view. Newly created domain objects (connection profiles, active
//! connections, access points) are registered and unregistered through here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use zbus::blocking::Connection;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::connection::activation::ActiveConnection;
use crate::connection::profile::ConnectionProfile;
use crate::daemon::{Daemon, NetworkBackend};

use super::device::DeviceView;
use super::error::FacadeError;

/// Shared daemon state and the object registry.
///
/// Methods that register D-Bus objects take a `&Arc<Self>` receiver because the
/// interface constructors need a shared handle back to this state.
pub struct Shared<B> {
    daemon: Mutex<Daemon<B>>,
    conn: Connection,
    /// Maps profile id to the object path of its registered connection object.
    connections: Mutex<HashMap<String, String>>,
}

impl<B: NetworkBackend + Send + Sync + 'static> Shared<B> {
    pub fn new(daemon: Daemon<B>, conn: Connection) -> Self {
        Self {
            daemon: Mutex::new(daemon),
            conn,
            connections: Mutex::new(HashMap::new()),
        }
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    // --- Daemon access ---------------------------------------------------

    pub fn daemon(&self) -> MutexGuard<'_, Daemon<B>> {
        self.daemon.lock().expect("daemon mutex poisoned")
    }

    pub fn daemon_mut(&self) -> MutexGuard<'_, Daemon<B>> {
        self.daemon.lock().expect("daemon mutex poisoned")
    }

    // --- Device lookups ----------------------------------------------------

    /// Resolves a device by kernel interface index.
    pub fn device_view(&self, index: i32) -> Result<DeviceView, FacadeError> {
        let daemon = self.daemon();
        super::device::enumerate_devices(&daemon)?
            .into_iter()
            .find(|device| device.index == index)
            .ok_or_else(|| FacadeError::UnknownDevice(format!("device {index}")))
    }

    /// Resolves the kernel index of a device by interface name.
    pub fn device_index_by_name(&self, interface: &str) -> Option<i32> {
        let daemon = self.daemon();
        super::device::enumerate_devices(&daemon)
            .ok()?
            .into_iter()
            .find(|device| device.interface == interface)
            .map(|device| device.index)
    }

    /// Returns the active connection bound to an interface, if any.
    pub fn device_active(&self, interface: &str) -> Option<ActiveConnection> {
        self.daemon()
            .active_connections()
            .iter()
            .find(|active| active.device.interface_name == interface)
            .cloned()
    }

    /// Returns an active connection by its daemon id.
    pub fn active_by_id(
        &self,
        id: crate::connection::activation::ActiveConnectionId,
    ) -> Option<ActiveConnection> {
        self.daemon()
            .active_connections()
            .iter()
            .find(|active| active.id == id)
            .cloned()
    }

    // --- Object registration ----------------------------------------------

    /// Registers every object required by the current daemon state.
    pub fn register_all(self: &Arc<Self>) -> zbus::Result<()> {
        let daemon = self.daemon();
        let devices = super::device::enumerate_devices(&daemon)?;
        let profiles = daemon.list_profiles().map_err(|error| {
            zbus::Error::Failure(format!("failed to list profiles: {error}"))
        })?;
        let active_connections = daemon.active_connections().to_vec();
        let access_points = daemon.access_points().map_err(|error| {
            zbus::Error::Failure(format!("failed to list access points: {error}"))
        })?;
        drop(daemon);

        for view in devices {
            self.register_device_object(&view)?;
        }
        for profile in &profiles {
            self.register_connection_object(profile)?;
        }
        for active in &active_connections {
            self.register_active_connection_object(active)?;
        }
        for ap in access_points.iter().filter_map(|ap| ap.bssid.as_ref()) {
            self.register_access_point_object(ap.as_bytes())?;
        }
        Ok(())
    }

    /// Registers the Device interfaces for one kernel interface.
    pub fn register_device_object(self: &Arc<Self>, view: &DeviceView) -> zbus::Result<()> {
        let server = self.conn.object_server();
        let path: ObjectPath = super::device_path(view.index).try_into()?;
        server.at(
            path.clone(),
            super::device::DeviceIface::new(self.clone(), view.index, self.conn.clone()),
        )?;
        match view.kind {
            super::device::DeviceKind::Wifi => {
                server.at(
                    path.clone(),
                    super::device::WirelessIface::new(self.clone(), view.index),
                )?;
            }
            super::device::DeviceKind::Ethernet | super::device::DeviceKind::Loopback => {
                server.at(
                    path.clone(),
                    super::device::WiredIface::new(self.clone(), view.index),
                )?;
            }
        }
        server.at(path, super::device::StatisticsIface)?;
        Ok(())
    }

    /// Registers a Settings.Connection object for a profile.
    pub fn register_connection_object(
        self: &Arc<Self>,
        profile: &ConnectionProfile,
    ) -> zbus::Result<()> {
        let path = super::settings_connection_path(&super::convert::stable_uuid(&profile.id));
        let path_ref: ObjectPath = path.clone().try_into()?;
        self.conn.object_server().at(
            path_ref,
            super::settings::SettingsConnectionIface::new(self.clone(), profile.id.clone()),
        )?;
        self.connections
            .lock()
            .expect("connection registry mutex poisoned")
            .insert(profile.id.clone(), path);
        Ok(())
    }

    /// Registers an active connection and its IP/DHCP config children.
    pub fn register_active_connection_object(
        self: &Arc<Self>,
        active: &ActiveConnection,
    ) -> zbus::Result<()> {
        let server = self.conn.object_server();
        let id = active.id;
        server.at(
            OwnedObjectPath::try_from(super::active_path(id))?,
            super::active_connection::ActiveConnectionIface::new(self.clone(), id),
        )?;
        server.at(
            OwnedObjectPath::try_from(super::ip4_path(id))?,
            super::ipconfig::Ip4ConfigIface::new(self.clone(), id),
        )?;
        server.at(
            OwnedObjectPath::try_from(super::ip6_path(id))?,
            super::ipconfig::Ip6ConfigIface::new(self.clone(), id),
        )?;
        server.at(
            OwnedObjectPath::try_from(super::dhcp4_path(id))?,
            super::ipconfig::Dhcp4ConfigIface::new(self.clone(), id),
        )?;
        server.at(
            OwnedObjectPath::try_from(super::dhcp6_path(id))?,
            super::ipconfig::Dhcp6ConfigIface::new(self.clone(), id),
        )?;
        Ok(())
    }

    /// Registers an access point object.
    pub fn register_access_point_object(self: &Arc<Self>, bssid: &[u8; 6]) -> zbus::Result<()> {
        let primary_wifi = {
            let daemon = self.daemon();
            super::device::enumerate_devices(&daemon)?
                .iter()
                .filter(|device| device.kind == super::device::DeviceKind::Wifi)
                .map(|device| device.index)
                .min()
                .unwrap_or(0)
        };
        self.conn.object_server().at(
            OwnedObjectPath::try_from(super::access_point_path(primary_wifi, bssid))?,
            super::access_point::AccessPointIface::new(self.clone(), *bssid),
        )?;
        Ok(())
    }

    // --- Connection object registry --------------------------------------

    /// Looks up the registered connection object path for a profile id.
    pub fn connection_path_lookup(&self, profile_id: &str) -> Option<String> {
        self.connections
            .lock()
            .expect("connection registry mutex poisoned")
            .get(profile_id)
            .cloned()
    }

    /// Drops the registry entry for a profile id and returns its path.
    fn take_connection_path(&self, profile_id: &str) -> Option<String> {
        self.connections
            .lock()
            .expect("connection registry mutex poisoned")
            .remove(profile_id)
    }

    /// Unregisters and removes the connection object for a profile id.
    pub fn unregister_connection(&self, profile_id: &str) -> Result<(), FacadeError> {
        if let Some(path) = self.take_connection_path(profile_id) {
            self.remove_connection_object::<super::settings::SettingsConnectionIface<B>>(&path)?;
        }
        Ok(())
    }

    /// Removes an interface of type `T` from the object server.
    pub fn remove_connection_object<T: zbus::object_server::Interface>(
        &self,
        path: &str,
    ) -> Result<(), FacadeError> {
        self.conn
            .object_server()
            .remove::<T, _>(path.to_string())
            .map_err(|error| {
                FacadeError::Internal(format!("failed to unregister {path}: {error}"))
            })?;
        Ok(())
    }

    // --- Access points -----------------------------------------------------

    /// Object paths for every access point currently visible on the bus.
    pub fn access_point_paths(&self) -> Vec<String> {
        let daemon = self.daemon();
        let device_count = super::device::enumerate_devices(&daemon).unwrap_or_default();
        let primary_wifi = device_count
            .iter()
            .filter(|device| device.kind == super::device::DeviceKind::Wifi)
            .map(|device| device.index)
            .min();
        let Some(primary_wifi) = primary_wifi else {
            return Vec::new();
        };
        daemon
            .access_points()
            .unwrap_or_default()
            .iter()
            .filter_map(|ap| ap.bssid.as_ref())
            .map(|bssid| super::access_point_path(primary_wifi, bssid.as_bytes()))
            .collect()
    }
}
