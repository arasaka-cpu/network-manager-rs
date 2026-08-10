//! The `org.freedesktop.NetworkManager.Settings` service and its per-connection
//! objects.
//!
//! Connections are addressed on the bus by their UUID (derived deterministically
//! from the profile id via [`crate::dbus::convert::stable_uuid`]). Adding or
//! updating a connection through D-Bus round-trips through the profile store, so
//! the bus view and the domain view never diverge.

use std::sync::Arc;

use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;
use zbus::interface;

use crate::daemon::NetworkBackend;

use super::convert::{SettingsDict, profile_to_settings, settings_to_profile, stable_uuid};
use super::error::FacadeError;
use super::shared::Shared;
use super::settings_connection_path;

/// The `org.freedesktop.NetworkManager.Settings` interface.
pub struct SettingsIface<B> {
    shared: Arc<Shared<B>>,
}

impl<B: NetworkBackend + Send + Sync + 'static> SettingsIface<B> {
    pub fn new(shared: Arc<Shared<B>>) -> Self {
        Self { shared }
    }

    fn connection_paths(&self) -> Result<Vec<String>, FacadeError> {
        let daemon = self.shared.daemon();
        Ok(daemon
            .list_profiles()?
            .iter()
            .filter_map(|profile| self.shared.connection_path_lookup(&profile.id))
            .collect())
    }
}

#[interface(name = "org.freedesktop.NetworkManager.Settings")]
impl<B: NetworkBackend + Send + Sync + 'static> SettingsIface<B> {
    #[zbus(signal)]
    async fn new_connection(
        emitter: &SignalEmitter<'_>,
        connection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn connection_removed(
        emitter: &SignalEmitter<'_>,
        connection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn connection_updated(
        emitter: &SignalEmitter<'_>,
        connection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    fn list_connections(&self) -> Result<Vec<OwnedObjectPath>, FacadeError> {
        Ok(self
            .connection_paths()?
            .into_iter()
            .filter_map(|path| OwnedObjectPath::try_from(path).ok())
            .collect())
    }

    fn get_connection_by_uuid(&self, uuid: String) -> Result<OwnedObjectPath, FacadeError> {
        let daemon = self.shared.daemon();
        for profile in daemon.list_profiles()? {
            if stable_uuid(&profile.id) == uuid {
                if let Some(path) = self.shared.connection_path_lookup(&profile.id) {
                    return OwnedObjectPath::try_from(path)
                        .map_err(|error| FacadeError::Internal(error.to_string()));
                }
            }
        }
        Err(FacadeError::UnknownConnection(uuid))
    }

    fn add_connection(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        settings: SettingsDict,
    ) -> Result<OwnedObjectPath, FacadeError> {
        let profile = settings_to_profile(&settings)?;
        self.shared.daemon_mut().create_profile(profile.clone())?;
        self.shared.register_connection_object(&profile).map_err(|error| {
            FacadeError::Internal(format!("failed to register connection object: {error}"))
        })?;
        let path = settings_connection_path(&stable_uuid(&profile.id));
        super::emit(Self::new_connection(
            &emitter,
            OwnedObjectPath::try_from(path.clone())
                .map_err(|e| FacadeError::Internal(e.to_string()))?,
        ))?;
        OwnedObjectPath::try_from(path).map_err(|error| FacadeError::Internal(error.to_string()))
    }

    fn add_connection_unsaved(
        &self,
        #[zbus(signal_emitter)] _emitter: SignalEmitter<'_>,
        settings: SettingsDict,
    ) -> Result<OwnedObjectPath, FacadeError> {
        // The facade persists everything immediately; "unsaved" is accepted for
        // client compatibility but behaves identically to a saved connection.
        let profile = settings_to_profile(&settings)?;
        self.shared.daemon_mut().create_profile(profile.clone())?;
        self.shared.register_connection_object(&profile).map_err(|error| {
            FacadeError::Internal(format!("failed to register connection object: {error}"))
        })?;
        let path = settings_connection_path(&stable_uuid(&profile.id));
        OwnedObjectPath::try_from(path).map_err(|error| FacadeError::Internal(error.to_string()))
    }

    fn add_connection2(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        settings: SettingsDict,
        _flags: u32,
        _args: std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
    ) -> Result<
        (
            OwnedObjectPath,
            std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
        ),
        FacadeError,
    > {
        let profile = settings_to_profile(&settings)?;
        self.shared.daemon_mut().create_profile(profile.clone())?;
        self.shared.register_connection_object(&profile).map_err(|error| {
            FacadeError::Internal(format!("failed to register connection object: {error}"))
        })?;
        let path = settings_connection_path(&stable_uuid(&profile.id));
        super::emit(Self::new_connection(
            &emitter,
            OwnedObjectPath::try_from(path.clone())
                .map_err(|e| FacadeError::Internal(e.to_string()))?,
        ))?;
        Ok((
            OwnedObjectPath::try_from(path).map_err(|error| FacadeError::Internal(error.to_string()))?,
            std::collections::HashMap::new(),
        ))
    }

    fn load_connections(&self, _filenames: Vec<String>) -> (bool, Vec<String>) {
        (true, Vec::new())
    }

    fn reload_connections(&self) -> bool {
        true
    }

    fn save_hostname(&self, _hostname: String) {}

    #[zbus(property)]
    fn connections(&self) -> Result<Vec<OwnedObjectPath>, zbus::fdo::Error> {
        self.list_connections().map_err(Into::into)
    }

    #[zbus(property)]
    fn hostname(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn can_modify(&self) -> bool {
        true
    }
}

/// The `org.freedesktop.NetworkManager.Settings.Connection` interface.
///
/// A live projection of one profile in the store, addressed by its UUID. Every
/// property and method reads (or mutates) the profile through the store, so the
/// object never holds a stale copy.
pub struct SettingsConnectionIface<B> {
    shared: Arc<Shared<B>>,
    profile_id: String,
}

impl<B> SettingsConnectionIface<B> {
    pub fn new(shared: Arc<Shared<B>>, profile_id: String) -> Self {
        Self { shared, profile_id }
    }
}

impl<B: NetworkBackend + Send + Sync + 'static> SettingsConnectionIface<B> {
    fn profile(&self) -> Result<crate::connection::profile::ConnectionProfile, FacadeError> {
        self.shared
            .daemon()
            .get_profile(&self.profile_id)
            .map_err(FacadeError::from)
    }
}

#[interface(name = "org.freedesktop.NetworkManager.Settings.Connection")]
impl<B: NetworkBackend + Send + Sync + 'static> SettingsConnectionIface<B> {
    #[zbus(signal)]
    async fn updated(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn removed(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    fn get_settings(&self) -> Result<SettingsDict, FacadeError> {
        Ok(profile_to_settings(&self.profile()?))
    }

    fn get_secrets(&self, _setting_name: String) -> Result<SettingsDict, FacadeError> {
        Ok(SettingsDict::new())
    }

    fn update(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        settings: SettingsDict,
    ) -> Result<(), FacadeError> {
        let profile = settings_to_profile(&settings)?;
        if profile.id != self.profile_id {
            return Err(FacadeError::InvalidProperty(
                "connection.id cannot change on update".to_string(),
            ));
        }
        self.shared.daemon_mut().update_profile(profile)?;
        super::emit(Self::updated(&emitter))?;
        Ok(())
    }

    fn update_unsaved(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        settings: SettingsDict,
    ) -> Result<(), FacadeError> {
        self.update(emitter, settings)
    }

    fn delete(&self, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) -> Result<(), FacadeError> {
        self.shared
            .daemon_mut()
            .delete_profile(&self.profile_id)?;
        super::emit(Self::removed(&emitter))?;
        self.shared.unregister_connection(&self.profile_id)
    }

    fn get_settings_flags(&self) -> u32 {
        super::NM_SETTING_CONNECTION_FLAG_NONE
    }

    fn get_applied_connection(
        &self,
        _flags: u32,
    ) -> Result<(SettingsDict, u64), FacadeError> {
        Ok((profile_to_settings(&self.profile()?), 0))
    }

    #[zbus(property)]
    fn unsaved(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn flags(&self) -> u32 {
        super::NM_SETTING_CONNECTION_FLAG_NONE
    }

    #[zbus(property)]
    fn filename(&self) -> String {
        String::new()
    }
}
