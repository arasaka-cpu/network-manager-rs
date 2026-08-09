//! The `org.freedesktop.NetworkManager.Connection.Active` interface.
//!
//! One object per active connection, rendering the daemon's
//! [`crate::connection::activation::ActiveConnection`] live. The device list,
//! profile references and IP configuration child paths are all derived on
//! access.

use std::sync::Arc;

use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;
use zbus::interface;

use crate::connection::activation::ActiveConnectionId;
use crate::connection::state::ConnectionState;
use crate::daemon::NetworkBackend;

use super::convert::{connection_type_string, stable_uuid};
use super::error::FacadeError;
use super::shared::Shared;
use super::{
    NM_ACTIVE_CONNECTION_STATE_ACTIVATED, NM_ACTIVE_CONNECTION_STATE_ACTIVATING,
    NM_ACTIVE_CONNECTION_STATE_DEACTIVATING, NM_ACTIVE_CONNECTION_STATE_DEACTIVATED, dhcp4_path,
    dhcp6_path, ip4_path, ip6_path, root_object_path, settings_connection_path,
};

fn nm_state(state: ConnectionState) -> u32 {
    match state {
        ConnectionState::Activated => NM_ACTIVE_CONNECTION_STATE_ACTIVATED,
        ConnectionState::Preparing
        | ConnectionState::Configuring
        | ConnectionState::Activating => NM_ACTIVE_CONNECTION_STATE_ACTIVATING,
        ConnectionState::Deactivating => NM_ACTIVE_CONNECTION_STATE_DEACTIVATING,
        ConnectionState::Unknown
        | ConnectionState::Disconnected
        | ConnectionState::Failed => NM_ACTIVE_CONNECTION_STATE_DEACTIVATED,
    }
}

/// The `org.freedesktop.NetworkManager.Connection.Active` interface.
pub struct ActiveConnectionIface<B> {
    shared: Arc<Shared<B>>,
    id: ActiveConnectionId,
}

impl<B: NetworkBackend + Send + Sync + 'static> ActiveConnectionIface<B> {
    pub fn new(shared: Arc<Shared<B>>, id: ActiveConnectionId) -> Self {
        Self { shared, id }
    }

    fn active(&self) -> Result<crate::connection::activation::ActiveConnection, FacadeError> {
        self.shared
            .active_by_id(self.id)
            .ok_or_else(|| FacadeError::UnknownActiveConnection(self.id.to_string()))
    }
}

#[interface(name = "org.freedesktop.NetworkManager.Connection.Active")]
impl<B: NetworkBackend + Send + Sync + 'static> ActiveConnectionIface<B> {
    #[zbus(signal)]
    #[zbus(name = "StateChanged")]
    async fn state_changed_signal(
        emitter: &SignalEmitter<'_>,
        state: u32,
        reason: u32,
        prev_state: u32,
    ) -> zbus::Result<()>;

    #[zbus(property)]
    fn connection(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        let profile_id = self.active()?.profile.id;
        OwnedObjectPath::try_from(settings_connection_path(&stable_uuid(&profile_id)))
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))
    }

    #[zbus(property)]
    fn id(&self) -> Result<String, zbus::fdo::Error> {
        Ok(self.active()?.profile.id)
    }

    #[zbus(property)]
    fn uuid(&self) -> Result<String, zbus::fdo::Error> {
        Ok(stable_uuid(&self.active()?.profile.id))
    }

    #[zbus(property)]
    fn type_(&self) -> Result<String, zbus::fdo::Error> {
        Ok(connection_type_string(&self.active()?.profile))
    }

    #[zbus(property)]
    fn specific_object(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        Ok(root_object_path())
    }

    #[zbus(property)]
    fn devices(&self) -> Result<Vec<OwnedObjectPath>, zbus::fdo::Error> {
        let interface = self.active()?.device.interface_name;
        Ok(self
            .shared
            .device_index_by_name(&interface)
            .and_then(|index| OwnedObjectPath::try_from(super::device_path(index)).ok())
            .into_iter()
            .collect())
    }

    #[zbus(property)]
    fn state(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(nm_state(self.active()?.state))
    }

    #[zbus(property)]
    fn default(&self) -> Result<bool, zbus::fdo::Error> {
        Ok(self.active()?.state == ConnectionState::Activated)
    }

    #[zbus(property)]
    fn default6(&self) -> Result<bool, zbus::fdo::Error> {
        Ok(false)
    }

    #[zbus(property)]
    fn vpn(&self) -> Result<bool, zbus::fdo::Error> {
        Ok(false)
    }

    #[zbus(property)]
    fn master(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        Ok(root_object_path())
    }

    #[zbus(property)]
    fn ip4_config(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        Ok(OwnedObjectPath::try_from(ip4_path(self.id))
            .map_err(|error| FacadeError::Internal(error.to_string()))?)
    }

    #[zbus(property)]
    fn dhcp4_config(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        Ok(OwnedObjectPath::try_from(dhcp4_path(self.id))
            .map_err(|error| FacadeError::Internal(error.to_string()))?)
    }

    #[zbus(property)]
    fn ip6_config(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        Ok(OwnedObjectPath::try_from(ip6_path(self.id))
            .map_err(|error| FacadeError::Internal(error.to_string()))?)
    }

    #[zbus(property)]
    fn dhcp6_config(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        Ok(OwnedObjectPath::try_from(dhcp6_path(self.id))
            .map_err(|error| FacadeError::Internal(error.to_string()))?)
    }

    #[zbus(property)]
    fn controller(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        Ok(root_object_path())
    }

    #[zbus(property)]
    fn connection_type(&self) -> Result<String, zbus::fdo::Error> {
        Ok(connection_type_string(&self.active()?.profile))
    }

    #[zbus(property)]
    fn state_flags(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(0)
    }

    #[zbus(property)]
    fn unmetered(&self) -> Result<bool, zbus::fdo::Error> {
        Ok(true)
    }
}
