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
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::connection::activation::{ActiveConnection, ActiveConnectionId};
use crate::connection::profile::ConnectionProfile;
use crate::connection::state::ConnectionEvent;
use crate::daemon::{Daemon, NetworkBackend};

use super::active_connection::{ActiveConnectionIfaceSignals, nm_state as active_nm_state};
use super::device::{DeviceIfaceSignals, DeviceView, connection_to_device_state};
use super::error::FacadeError;
use super::root::RootIfaceSignals;
use super::{NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_UNKNOWN};

/// Shared daemon state and the object registry.
///
/// Methods that register D-Bus objects take a `&Arc<Self>` receiver because the
/// interface constructors need a shared handle back to this state.
pub struct Shared<B> {
    daemon: Mutex<Daemon<B>>,
    conn: Connection,
    /// Maps profile id to the object path of its registered connection object.
    connections: Mutex<HashMap<String, String>>,
    /// Registered device objects: kernel index -> interface name.
    devices: Mutex<HashMap<i32, String>>,
    /// Last device state emitted per registered device index.
    device_states: Mutex<HashMap<i32, u32>>,
    /// Registered access point objects, keyed by BSSID.
    access_points: Mutex<HashMap<[u8; 6], ()>>,
    /// Registered active connection objects, keyed by daemon id.
    active_connections: Mutex<HashMap<u64, ()>>,
    /// Last root `State` value emitted on the bus.
    root_state: Mutex<u32>,
}

impl<B: NetworkBackend + Send + Sync + 'static> Shared<B> {
    pub fn new(daemon: Daemon<B>, conn: Connection) -> Self {
        Self {
            daemon: Mutex::new(daemon),
            conn,
            connections: Mutex::new(HashMap::new()),
            devices: Mutex::new(HashMap::new()),
            device_states: Mutex::new(HashMap::new()),
            access_points: Mutex::new(HashMap::new()),
            active_connections: Mutex::new(HashMap::new()),
            root_state: Mutex::new(super::NM_STATE_DISCONNECTED),
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
        let profiles = daemon
            .list_profiles()
            .map_err(|error| zbus::Error::Failure(format!("failed to list profiles: {error}")))?;
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
        self.devices
            .lock()
            .expect("device registry mutex poisoned")
            .insert(view.index, view.interface.clone());
        let state =
            super::device::device_state(self, view.index).unwrap_or(NM_DEVICE_STATE_UNKNOWN);
        self.device_states
            .lock()
            .expect("device state registry mutex poisoned")
            .insert(view.index, state);
        Ok(())
    }

    /// Unregisters every interface of a device object at `index`.
    pub fn unregister_device(&self, index: i32) -> Result<(), FacadeError> {
        let path = super::device_path(index);
        let _ = self
            .conn
            .object_server()
            .remove::<super::device::DeviceIface<B>, _>(path.clone());
        let _ = self
            .conn
            .object_server()
            .remove::<super::device::WiredIface<B>, _>(path.clone());
        let _ = self
            .conn
            .object_server()
            .remove::<super::device::WirelessIface<B>, _>(path.clone());
        let _ = self
            .conn
            .object_server()
            .remove::<super::device::StatisticsIface, _>(path.clone());
        self.devices
            .lock()
            .expect("device registry mutex poisoned")
            .remove(&index);
        self.device_states
            .lock()
            .expect("device state registry mutex poisoned")
            .remove(&index);
        Ok(())
    }

    /// Returns whether a device object is registered for `index`.
    pub fn is_device_registered(&self, index: i32) -> bool {
        self.devices
            .lock()
            .expect("device registry mutex poisoned")
            .contains_key(&index)
    }

    /// Interface name of a registered device, removed from the registry.
    pub fn take_device_interface(&self, index: i32) -> Option<String> {
        self.devices
            .lock()
            .expect("device registry mutex poisoned")
            .remove(&index)
    }

    /// Indices of every registered device object.
    pub fn registered_device_indices(&self) -> Vec<i32> {
        self.devices
            .lock()
            .expect("device registry mutex poisoned")
            .keys()
            .copied()
            .collect()
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
        self.active_connections
            .lock()
            .expect("active connection registry mutex poisoned")
            .insert(id.as_u64(), ());
        Ok(())
    }

    /// Unregisters an active connection object and all of its config children.
    pub fn unregister_active_connection(&self, id: ActiveConnectionId) -> Result<(), FacadeError> {
        let _ = self
            .conn
            .object_server()
            .remove::<super::active_connection::ActiveConnectionIface<B>, _>(super::active_path(
                id,
            ));
        let _ = self
            .conn
            .object_server()
            .remove::<super::ipconfig::Ip4ConfigIface<B>, _>(super::ip4_path(id));
        let _ = self
            .conn
            .object_server()
            .remove::<super::ipconfig::Ip6ConfigIface<B>, _>(super::ip6_path(id));
        let _ = self
            .conn
            .object_server()
            .remove::<super::ipconfig::Dhcp4ConfigIface<B>, _>(super::dhcp4_path(id));
        let _ = self
            .conn
            .object_server()
            .remove::<super::ipconfig::Dhcp6ConfigIface<B>, _>(super::dhcp6_path(id));
        self.active_connections
            .lock()
            .expect("active connection registry mutex poisoned")
            .remove(&id.as_u64());
        Ok(())
    }

    /// Returns whether an active connection object is registered for `id`.
    pub fn is_active_connection_registered(&self, id: ActiveConnectionId) -> bool {
        self.active_connections
            .lock()
            .expect("active connection registry mutex poisoned")
            .contains_key(&id.as_u64())
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
        self.access_points
            .lock()
            .expect("access point registry mutex poisoned")
            .insert(*bssid, ());
        Ok(())
    }

    /// Unregisters an access point object.
    pub fn unregister_access_point(&self, bssid: &[u8; 6]) -> Result<(), FacadeError> {
        let primary_wifi = {
            let daemon = self.daemon();
            super::device::enumerate_devices(&daemon)
                .unwrap_or_default()
                .iter()
                .filter(|device| device.kind == super::device::DeviceKind::Wifi)
                .map(|device| device.index)
                .min()
                .unwrap_or(0)
        };
        let _ = self
            .conn
            .object_server()
            .remove::<super::access_point::AccessPointIface<B>, _>(super::access_point_path(
                primary_wifi,
                bssid,
            ));
        self.access_points
            .lock()
            .expect("access point registry mutex poisoned")
            .remove(bssid);
        Ok(())
    }

    /// BSSIDs of every registered access point object.
    pub fn registered_access_point_bssids(&self) -> Vec<[u8; 6]> {
        self.access_points
            .lock()
            .expect("access point registry mutex poisoned")
            .keys()
            .copied()
            .collect()
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

    // --- Signal emission ---------------------------------------------------

    /// Builds a signal emitter bound to `path` on this connection.
    pub fn emitter(&self, path: &str) -> Result<SignalEmitter<'_>, FacadeError> {
        let path = OwnedObjectPath::try_from(path)
            .map_err(|error| FacadeError::Internal(error.to_string()))?;
        SignalEmitter::new(self.conn.inner(), path)
            .map_err(|error| FacadeError::Internal(error.to_string()))
    }

    /// Emits `org.freedesktop.DBus.Properties.PropertiesChanged` for `interface`
    /// at `path` with the given changed properties.
    pub fn emit_properties_changed(
        &self,
        path: &str,
        interface: &str,
        changed: HashMap<String, zbus::zvariant::OwnedValue>,
        invalidated: &[&str],
    ) -> Result<(), FacadeError> {
        let emitter = self.emitter(path)?;
        super::emit(emitter.emit(
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &(interface, changed, invalidated),
        ))
    }

    /// Emits `Device.StateChanged` and a `PropertiesChanged(State)` update when
    /// the device state at `index` actually changed from what was last emitted.
    pub fn emit_device_state(&self, index: i32, new_state: u32) -> Result<(), FacadeError> {
        let mut tracked = self
            .device_states
            .lock()
            .expect("device state registry mutex poisoned");
        let previous = *tracked.get(&index).unwrap_or(&NM_DEVICE_STATE_UNKNOWN);
        if previous == new_state {
            return Ok(());
        }
        tracked.insert(index, new_state);
        let path = super::device_path(index);
        let emitter = self.emitter(&path)?;
        super::emit(DeviceIfaceSignals::state_changed_signal(
            &emitter, new_state, 0, previous,
        ))?;
        let mut changed = HashMap::new();
        changed.insert(
            "State".to_string(),
            zbus::zvariant::OwnedValue::from(new_state),
        );
        self.emit_properties_changed(&path, "org.freedesktop.NetworkManager.Device", changed, &[])
    }

    /// Emits `StateChanged` on the root object when the daemon-wide state
    /// changed from what was last emitted.
    pub fn emit_root_state_if_changed(&self) -> Result<(), FacadeError> {
        let new_state = super::root::current_nm_state(&self.daemon());
        let mut tracked = self.root_state.lock().expect("root state mutex poisoned");
        if new_state == *tracked {
            return Ok(());
        }
        *tracked = new_state;
        let emitter = self.emitter(super::ROOT_PATH)?;
        super::emit(RootIfaceSignals::state_changed(&emitter, new_state))
    }

    /// Drains the daemon's pending connection events and mirrors them onto the
    /// bus as active-connection, device and root state signals.
    ///
    /// Callers invoke this after any operation that moves an active connection
    /// through its lifecycle (activation, deactivation, engine-driven teardown)
    /// so the bus view tracks the domain state machine exactly.
    pub fn emit_connection_events(&self) -> Result<(), FacadeError> {
        let events = self.daemon_mut().connection_events();
        let mut device_by_active: HashMap<ActiveConnectionId, i32> = HashMap::new();
        for event in events {
            match event {
                ConnectionEvent::StateChanged {
                    active_id,
                    previous,
                    current,
                    ..
                } => {
                    let emitter = self.emitter(&super::active_path(active_id))?;
                    super::emit(ActiveConnectionIfaceSignals::state_changed_signal(
                        &emitter,
                        active_nm_state(current),
                        0,
                        active_nm_state(previous),
                    ))?;
                    if let Some(active) = self.active_by_id(active_id) {
                        if let Some(index) =
                            self.device_index_by_name(&active.device.interface_name)
                        {
                            device_by_active.insert(active_id, index);
                            self.emit_device_state(index, connection_to_device_state(current))?;
                        }
                    }
                }
                ConnectionEvent::Activated { .. } => {}
                ConnectionEvent::Deactivated { active_id, .. } => {
                    self.unregister_active_connection(active_id)?;
                    let path = OwnedObjectPath::try_from(super::active_path(active_id))
                        .map_err(|error| FacadeError::Internal(error.to_string()))?;
                    let emitter = self.emitter(super::ROOT_PATH)?;
                    super::emit(RootIfaceSignals::active_connection_removed(&emitter, path))?;
                    if let Some(index) = device_by_active.remove(&active_id) {
                        self.emit_device_state(index, NM_DEVICE_STATE_DISCONNECTED)?;
                    }
                }
                // Failures are already mirrored by the preceding `StateChanged`
                // event (which drives both the active-connection state signal
                // and the device into FAILED), so nothing extra is needed here.
                ConnectionEvent::Failed { .. } => {}
            }
        }
        self.emit_root_state_if_changed()
    }
}
