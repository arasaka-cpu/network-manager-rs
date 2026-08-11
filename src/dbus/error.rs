//! D-Bus error mapping.
//!
//! The compatibility facade surfaces the same error names that NetworkManager
//! uses, so existing clients receive familiar failures instead of generic
//! ones. Domain errors (store, activation, validation) are translated into
//! these names at the interface boundary.

use zbus::DBusError;

use crate::connection::activation::ActivationError;
use crate::connection::profile::ProfileValidationError;
use crate::connection::store::StoreError;

/// Errors reported by the NetworkManager-compatible D-Bus layer.
#[derive(Clone, Debug, DBusError)]
#[zbus(prefix = "org.freedesktop.NetworkManager")]
pub enum FacadeError {
    /// The referenced connection profile does not exist.
    #[zbus(name = "org.freedesktop.NetworkManager.Settings.Connection.UnknownConnection")]
    UnknownConnection(String),

    /// A settings dictionary was structurally invalid.
    #[zbus(name = "org.freedesktop.NetworkManager.Settings.Connection.InvalidSetting")]
    InvalidSetting(String),

    /// A settings dictionary held an invalid value for a known property.
    #[zbus(name = "org.freedesktop.NetworkManager.Settings.Connection.InvalidProperty")]
    InvalidProperty(String),

    /// A settings dictionary was missing a required setting section.
    #[zbus(name = "org.freedesktop.NetworkManager.Settings.Connection.MissingSetting")]
    MissingSetting(String),

    /// The referenced device does not exist.
    #[zbus(name = "org.freedesktop.NetworkManager.UnknownDevice")]
    UnknownDevice(String),

    /// The referenced active connection does not exist.
    #[zbus(name = "org.freedesktop.NetworkManager.UnknownActiveConnection")]
    UnknownActiveConnection(String),

    /// The connection is not currently active.
    #[zbus(name = "org.freedesktop.NetworkManager.NotActive")]
    NotActive(String),

    /// The connection is already active.
    #[zbus(name = "org.freedesktop.NetworkManager.AlreadyActive")]
    AlreadyActive(String),

    /// The caller lacks the permission to perform the operation.
    #[zbus(name = "org.freedesktop.NetworkManager.PermissionDenied")]
    PermissionDenied(String),

    /// The requested operation is not implemented by this facade.
    #[zbus(name = "org.freedesktop.NetworkManager.NotSupported")]
    NotSupported(String),

    /// The backend failed while serving the request.
    #[zbus(name = "org.freedesktop.DBus.Error.Failed")]
    Internal(String),
}

impl FacadeError {
    /// Builds an [`FacadeError::NotSupported`] for an operation that the
    /// facade deliberately does not implement.
    pub fn not_supported(operation: &str) -> Self {
        Self::NotSupported(format!("{operation} is not supported by this daemon"))
    }
}

impl From<FacadeError> for zbus::Error {
    fn from(value: FacadeError) -> Self {
        zbus::Error::Failure(value.to_string())
    }
}

impl From<FacadeError> for zbus::fdo::Error {
    fn from(value: FacadeError) -> Self {
        zbus::fdo::Error::ZBus(zbus::Error::from(value))
    }
}

impl From<StoreError> for FacadeError {
    fn from(value: StoreError) -> Self {
        match value {
            StoreError::NotFound(id) => Self::UnknownConnection(id),
            StoreError::AlreadyExists(id) => {
                Self::InvalidSetting(format!("connection {id:?} already exists"))
            }
            StoreError::Invalid(reason) => Self::InvalidSetting(reason.to_string()),
            StoreError::Malformed { id, reason } => {
                Self::InvalidSetting(format!("profile {id:?} is malformed: {reason}"))
            }
            StoreError::Io(err) => Self::InvalidSetting(format!("store I/O failed: {err}")),
        }
    }
}

impl From<ProfileValidationError> for FacadeError {
    fn from(value: ProfileValidationError) -> Self {
        Self::InvalidSetting(value.to_string())
    }
}

impl From<crate::linux::model::NetlinkError> for FacadeError {
    fn from(value: crate::linux::model::NetlinkError) -> Self {
        Self::Internal(value.to_string())
    }
}

impl From<ActivationError> for FacadeError {
    fn from(value: ActivationError) -> Self {
        match value {
            ActivationError::ProfileNotFound(id) => Self::UnknownConnection(id),
            ActivationError::DeviceIncompatible { profile_id, device } => {
                Self::InvalidProperty(format!(
                    "profile {profile_id:?} does not match device {} ({})",
                    device.interface_name, device.kind
                ))
            }
            ActivationError::NoSuitableProfile(device) => Self::InvalidSetting(format!(
                "no suitable connection profile for device {} ({})",
                device.interface_name, device.kind
            )),
            ActivationError::AlreadyActive(id) => Self::AlreadyActive(id),
            ActivationError::UnknownActiveConnection(id) => {
                Self::UnknownActiveConnection(id.to_string())
            }
            ActivationError::InvalidState { active_id, .. } => {
                Self::NotActive(format!("active connection {active_id} is not active"))
            }
            ActivationError::State(err) => Self::NotActive(err.to_string()),
            ActivationError::Store(err) => Self::from(err),
            ActivationError::Engine(reason) => Self::NotSupported(reason),
        }
    }
}
