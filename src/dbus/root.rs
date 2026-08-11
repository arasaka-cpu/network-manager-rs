//! The `org.freedesktop.NetworkManager` root service.
//!
//! The root object is the entry point every client talks to first: it
//! enumerates devices and active connections, drives activation/deactivation,
//! and reports the daemon-wide flags (networking/wireless enablement,
//! connectivity, version).

use std::sync::Arc;

use zbus::interface;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;

use crate::connection::activation::ActiveConnectionId;
use crate::connection::profile::ConnectionProfile;
use crate::daemon::NetworkBackend;

use super::convert::{settings_to_profile, stable_uuid};
use super::error::FacadeError;
use super::shared::Shared;
use super::{
    NM_CONNECTIVITY_FULL, NM_CONNECTIVITY_NONE, NM_STATE_CONNECTED_GLOBAL, NM_STATE_DISCONNECTED,
    active_path, device_path, dhcp4_path, ip4_path, ip6_path, settings_connection_path,
};

/// Parses the trailing integer id from an object path like
/// `/org/freedesktop/NetworkManager/Devices/2`.
fn path_index(path: &str, prefix: &str) -> Option<u64> {
    path.strip_prefix(prefix)?
        .split('/')
        .next()
        .and_then(|part| part.parse().ok())
}

/// The daemon-wide `State` as NM_STATE_* from the current active connections.
pub fn current_nm_state(daemon: &crate::daemon::Daemon<impl crate::daemon::NetworkBackend>) -> u32 {
    if daemon.active_connections().is_empty() {
        NM_STATE_DISCONNECTED
    } else {
        NM_STATE_CONNECTED_GLOBAL
    }
}

/// The `org.freedesktop.NetworkManager` interface.
pub struct RootIface<B> {
    shared: Arc<Shared<B>>,
}

impl<B: NetworkBackend + Send + Sync + 'static> RootIface<B> {
    pub fn new(shared: Arc<Shared<B>>) -> Self {
        Self { shared }
    }

    fn device_info(
        &self,
        device: &str,
    ) -> Result<crate::connection::device::DeviceInfo, FacadeError> {
        let index = path_index(device, "/org/freedesktop/NetworkManager/Devices/")
            .ok_or_else(|| FacadeError::UnknownDevice(device.to_string()))?;
        Ok(self.shared.device_view(index as i32)?.to_device_info())
    }

    fn active_id(&self, path: &str) -> Result<ActiveConnectionId, FacadeError> {
        path_index(path, "/org/freedesktop/NetworkManager/ActiveConnection/")
            .map(ActiveConnectionId::new)
            .ok_or_else(|| FacadeError::UnknownActiveConnection(path.to_string()))
    }

    fn activate(
        &self,
        settings: super::convert::SettingsDict,
        device: &str,
    ) -> Result<crate::connection::activation::ActiveConnection, FacadeError> {
        let info = self.device_info(device)?;
        let mut daemon = self.shared.daemon_mut();
        if settings.is_empty() {
            daemon.activate(&info).map_err(FacadeError::from)
        } else {
            let profile = settings_to_profile(&settings)?;
            daemon
                .activate_profile(&profile.id, &info)
                .map_err(FacadeError::from)
        }
    }

    fn add_and_activate(
        &self,
        emitter: &SignalEmitter<'_>,
        settings: super::convert::SettingsDict,
        device: &OwnedObjectPath,
    ) -> Result<(String, String), FacadeError> {
        let profile: ConnectionProfile = settings_to_profile(&settings)?;
        self.shared.daemon_mut().create_profile(profile.clone())?;
        self.shared
            .register_connection_object(&profile)
            .map_err(|error| FacadeError::Internal(error.to_string()))?;
        let connection_path = settings_connection_path(&stable_uuid(&profile.id));

        let active = self.activate(settings, device.as_str())?;
        self.shared
            .register_active_connection_object(&active)
            .map_err(|error| FacadeError::Internal(error.to_string()))?;
        let active_connection_path = active_path(active.id);
        super::emit(Self::active_connection_added(
            emitter,
            OwnedObjectPath::try_from(active_connection_path.clone())
                .map_err(|e| FacadeError::Internal(e.to_string()))?,
        ))?;
        self.shared.emit_connection_events()?;
        Ok((connection_path, active_connection_path))
    }

    fn device_paths(&self) -> Result<Vec<String>, FacadeError> {
        let daemon = self.shared.daemon();
        Ok(super::device::enumerate_devices(&daemon)?
            .into_iter()
            .map(|device| device_path(device.index))
            .collect())
    }
}

#[interface(name = "org.freedesktop.NetworkManager")]
impl<B: NetworkBackend + Send + Sync + 'static> RootIface<B> {
    #[zbus(signal)]
    async fn state_changed(emitter: &SignalEmitter<'_>, state: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn device_added(emitter: &SignalEmitter<'_>, device: OwnedObjectPath)
    -> zbus::Result<()>;

    #[zbus(signal)]
    async fn device_removed(
        emitter: &SignalEmitter<'_>,
        device: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn active_connection_added(
        emitter: &SignalEmitter<'_>,
        active: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn active_connection_removed(
        emitter: &SignalEmitter<'_>,
        active: OwnedObjectPath,
    ) -> zbus::Result<()>;

    fn get_devices(&self) -> Result<Vec<OwnedObjectPath>, FacadeError> {
        Ok(self
            .device_paths()?
            .into_iter()
            .filter_map(|path| OwnedObjectPath::try_from(path).ok())
            .collect())
    }

    fn get_all_devices(&self) -> Result<Vec<OwnedObjectPath>, FacadeError> {
        self.get_devices()
    }

    fn get_device_by_ip_iface(&self, iface: String) -> Result<OwnedObjectPath, FacadeError> {
        let index = self
            .shared
            .device_index_by_name(&iface)
            .ok_or(FacadeError::UnknownDevice(iface))?;
        OwnedObjectPath::try_from(device_path(index))
            .map_err(|error| FacadeError::Internal(error.to_string()))
    }

    fn activate_connection(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        settings: super::convert::SettingsDict,
        device: OwnedObjectPath,
        _specific_object: OwnedObjectPath,
    ) -> Result<OwnedObjectPath, FacadeError> {
        let active = self.activate(settings, device.as_str())?;
        self.shared
            .register_active_connection_object(&active)
            .map_err(|error| FacadeError::Internal(error.to_string()))?;
        let path = active_path(active.id);
        super::emit(Self::active_connection_added(
            &emitter,
            OwnedObjectPath::try_from(path.clone())
                .map_err(|e| FacadeError::Internal(e.to_string()))?,
        ))?;
        self.shared.emit_connection_events()?;
        OwnedObjectPath::try_from(path).map_err(|error| FacadeError::Internal(error.to_string()))
    }

    fn add_and_activate_connection(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        settings: super::convert::SettingsDict,
        device: OwnedObjectPath,
        _specific_object: OwnedObjectPath,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), FacadeError> {
        let (connection_path, active_connection_path) =
            self.add_and_activate(&emitter, settings, &device)?;
        Ok((
            OwnedObjectPath::try_from(connection_path)
                .map_err(|error| FacadeError::Internal(error.to_string()))?,
            OwnedObjectPath::try_from(active_connection_path)
                .map_err(|error| FacadeError::Internal(error.to_string()))?,
        ))
    }

    fn add_and_activate_connection2(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        settings: super::convert::SettingsDict,
        device: OwnedObjectPath,
        _specific_object: OwnedObjectPath,
        _options: std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
    ) -> Result<
        (
            OwnedObjectPath,
            OwnedObjectPath,
            std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
        ),
        FacadeError,
    > {
        let (connection_path, active_connection_path) =
            self.add_and_activate(&emitter, settings, &device)?;
        Ok((
            OwnedObjectPath::try_from(connection_path)
                .map_err(|error| FacadeError::Internal(error.to_string()))?,
            OwnedObjectPath::try_from(active_connection_path)
                .map_err(|error| FacadeError::Internal(error.to_string()))?,
            std::collections::HashMap::new(),
        ))
    }

    fn deactivate_connection(&self, active: OwnedObjectPath) -> Result<(), FacadeError> {
        self.shared
            .daemon_mut()
            .deactivate(self.active_id(active.as_str())?)?;
        self.shared.emit_connection_events()?;
        Ok(())
    }

    fn sleep(&self, _sleep: bool) {}

    fn enable(&self, _enable: bool) {}

    fn reload(&self, _flags: u32) {}

    fn set_logging(&self, _level: String, _domains: String) {}

    fn get_logging(&self) -> (String, String) {
        ("INFO".to_string(), String::new())
    }

    fn get_permissions(&self) -> Vec<(String, String)> {
        vec![
            (
                "org.freedesktop.NetworkManager.enable-disable-network".to_string(),
                "yes".to_string(),
            ),
            (
                "org.freedesktop.NetworkManager.enable-disable-wifi".to_string(),
                "yes".to_string(),
            ),
            (
                "org.freedesktop.NetworkManager.network-control".to_string(),
                "yes".to_string(),
            ),
            (
                "org.freedesktop.NetworkManager.wifi.share.protected".to_string(),
                "yes".to_string(),
            ),
            (
                "org.freedesktop.NetworkManager.wifi.share.open".to_string(),
                "yes".to_string(),
            ),
            (
                "org.freedesktop.NetworkManager.settings.modify.system".to_string(),
                "yes".to_string(),
            ),
            (
                "org.freedesktop.NetworkManager.settings.modify.own".to_string(),
                "yes".to_string(),
            ),
            (
                "org.freedesktop.NetworkManager.reload".to_string(),
                "yes".to_string(),
            ),
            (
                "org.freedesktop.NetworkManager.checkpoint-rollback".to_string(),
                "yes".to_string(),
            ),
            (
                "org.freedesktop.NetworkManager.enable-disable-statistics".to_string(),
                "yes".to_string(),
            ),
            (
                "org.freedesktop.NetworkManager.enable-disable-connectivity-check".to_string(),
                "yes".to_string(),
            ),
        ]
    }

    fn check_connectivity(&self) -> u32 {
        if self.shared.daemon().active_connections().is_empty() {
            NM_CONNECTIVITY_NONE
        } else {
            NM_CONNECTIVITY_FULL
        }
    }

    fn check_connectivity_full(&self) -> u32 {
        self.check_connectivity()
    }

    fn get_connectivity(&self) -> u32 {
        self.check_connectivity()
    }

    fn device_state_reasons(&self) -> Vec<(OwnedObjectPath, u32)> {
        Vec::new()
    }

    fn get_device_state_reasons(&self, _device: OwnedObjectPath) -> Vec<u32> {
        Vec::new()
    }

    #[zbus(property)]
    fn devices(&self) -> Result<Vec<OwnedObjectPath>, zbus::fdo::Error> {
        self.get_devices().map_err(Into::into)
    }

    #[zbus(property)]
    fn all_devices(&self) -> Result<Vec<OwnedObjectPath>, zbus::fdo::Error> {
        self.get_all_devices().map_err(Into::into)
    }

    #[zbus(property)]
    fn active_connections(&self) -> Result<Vec<OwnedObjectPath>, zbus::fdo::Error> {
        let daemon = self.shared.daemon();
        Ok(daemon
            .active_connections()
            .iter()
            .filter_map(|active| OwnedObjectPath::try_from(active_path(active.id)).ok())
            .collect())
    }

    #[zbus(property)]
    fn connectivity(&self) -> u32 {
        self.check_connectivity()
    }

    #[zbus(property(emits_changed_signal = "false"), name = "State")]
    fn nm_state(&self) -> u32 {
        if self.shared.daemon().active_connections().is_empty() {
            NM_STATE_DISCONNECTED
        } else {
            NM_STATE_CONNECTED_GLOBAL
        }
    }

    #[zbus(property)]
    fn wireless_enabled(&self) -> bool {
        true
    }

    #[zbus(property)]
    fn set_wireless_enabled(&self, _wireless_enabled: bool) {}

    #[zbus(property)]
    fn wireless_hardware_enabled(&self) -> bool {
        let daemon = self.shared.daemon();
        super::device::enumerate_devices(&daemon)
            .unwrap_or_default()
            .iter()
            .any(|device| device.kind == super::device::DeviceKind::Wifi)
    }

    #[zbus(property)]
    fn wwan_enabled(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn set_wwan_enabled(&self, _wwan_enabled: bool) {}

    #[zbus(property)]
    fn wwan_hardware_enabled(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn networking_enabled(&self) -> bool {
        true
    }

    #[zbus(property)]
    fn set_networking_enabled(&self, _networking_enabled: bool) {}

    #[zbus(property)]
    fn startup(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    #[zbus(property)]
    fn version_info(&self) -> Vec<u32> {
        let parts: Vec<&str> = env!("CARGO_PKG_VERSION").split('.').collect();
        let major = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
        let micro = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);
        vec![major, minor, micro, 0]
    }

    #[zbus(property)]
    fn capabilities(&self) -> Vec<u32> {
        Vec::new()
    }

    #[zbus(property)]
    fn metered(&self) -> u32 {
        0
    }

    #[zbus(property)]
    fn primary_connection(&self) -> OwnedObjectPath {
        self.shared
            .daemon()
            .active_connections()
            .first()
            .map(|active| {
                OwnedObjectPath::try_from(active_path(active.id))
                    .unwrap_or_else(|_| super::root_object_path())
            })
            .unwrap_or(super::root_object_path())
    }

    #[zbus(property)]
    fn activating_connection(&self) -> OwnedObjectPath {
        let root = super::root_object_path();
        self.shared
            .daemon()
            .active_connections()
            .iter()
            .find(|active| active.state == crate::connection::state::ConnectionState::Activating)
            .and_then(|active| OwnedObjectPath::try_from(active_path(active.id)).ok())
            .unwrap_or(root)
    }

    #[zbus(property)]
    fn primary_connection_type(&self) -> String {
        self.shared
            .daemon()
            .active_connections()
            .first()
            .map(|active| super::convert::connection_type_string(&active.profile))
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn device_reasons(&self) -> Vec<OwnedObjectPath> {
        Vec::new()
    }

    #[zbus(property)]
    fn ip4_config(&self) -> OwnedObjectPath {
        self.shared
            .daemon()
            .active_connections()
            .first()
            .and_then(|active| OwnedObjectPath::try_from(ip4_path(active.id)).ok())
            .unwrap_or(super::root_object_path())
    }

    #[zbus(property)]
    fn dhcp4_config(&self) -> OwnedObjectPath {
        self.shared
            .daemon()
            .active_connections()
            .first()
            .and_then(|active| OwnedObjectPath::try_from(dhcp4_path(active.id)).ok())
            .unwrap_or(super::root_object_path())
    }

    #[zbus(property)]
    fn ip6_config(&self) -> OwnedObjectPath {
        self.shared
            .daemon()
            .active_connections()
            .first()
            .and_then(|active| OwnedObjectPath::try_from(ip6_path(active.id)).ok())
            .unwrap_or(super::root_object_path())
    }

    #[zbus(property)]
    fn dhcp6_config(&self) -> OwnedObjectPath {
        super::root_object_path()
    }

    #[zbus(property)]
    fn global_dns_configuration(
        &self,
    ) -> std::collections::HashMap<String, zbus::zvariant::OwnedValue> {
        std::collections::HashMap::new()
    }
}
