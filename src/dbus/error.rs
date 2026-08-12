//! D-Bus error mapping.
//!
//! The compatibility facade surfaces the same error names that NetworkManager
//! uses, so existing clients receive familiar failures instead of generic
//! ones. Domain errors (store, activation, validation) are translated into
//! these names at the interface boundary.

use zbus::names::ErrorName;

use crate::connection::activation::ActivationError;
use crate::connection::profile::ProfileValidationError;
use crate::connection::store::StoreError;

/// Errors reported by the NetworkManager-compatible D-Bus layer.
///
/// The [`zbus::DBusError`] implementation below maps every variant to the
/// exact error name NetworkManager uses on the bus. The error-name derive
/// cannot express these because it prefixes every variant with a single
/// struct-level prefix, but the standard generic failure
/// (`org.freedesktop.DBus.Error.Failed`) lives under a different prefix than
/// the NetworkManager errors.
#[derive(Clone, Debug)]
pub enum FacadeError {
    /// The referenced connection profile does not exist.
    UnknownConnection(String),

    /// A settings dictionary was structurally invalid.
    InvalidSetting(String),

    /// A settings dictionary held an invalid value for a known property.
    InvalidProperty(String),

    /// A settings dictionary was missing a required setting section.
    MissingSetting(String),

    /// The referenced device does not exist.
    UnknownDevice(String),

    /// The referenced active connection does not exist.
    UnknownActiveConnection(String),

    /// The connection is not currently active.
    NotActive(String),

    /// The connection is already active.
    AlreadyActive(String),

    /// The caller lacks the permission to perform the operation.
    PermissionDenied(String),

    /// The requested operation is not implemented by this facade.
    NotSupported(String),

    /// The backend failed while serving the request.
    Internal(String),
}

impl zbus::DBusError for FacadeError {
    fn name(&self) -> zbus::names::ErrorName<'_> {
        match self {
            Self::UnknownConnection(_) => ErrorName::from_static_str_unchecked(
                "org.freedesktop.NetworkManager.Settings.Connection.UnknownConnection",
            ),
            Self::InvalidSetting(_) => ErrorName::from_static_str_unchecked(
                "org.freedesktop.NetworkManager.Settings.Connection.InvalidSetting",
            ),
            Self::InvalidProperty(_) => ErrorName::from_static_str_unchecked(
                "org.freedesktop.NetworkManager.Settings.Connection.InvalidProperty",
            ),
            Self::MissingSetting(_) => ErrorName::from_static_str_unchecked(
                "org.freedesktop.NetworkManager.Settings.Connection.MissingSetting",
            ),
            Self::UnknownDevice(_) => {
                ErrorName::from_static_str_unchecked("org.freedesktop.NetworkManager.UnknownDevice")
            }
            Self::UnknownActiveConnection(_) => ErrorName::from_static_str_unchecked(
                "org.freedesktop.NetworkManager.UnknownActiveConnection",
            ),
            Self::NotActive(_) => {
                ErrorName::from_static_str_unchecked("org.freedesktop.NetworkManager.NotActive")
            }
            Self::AlreadyActive(_) => {
                ErrorName::from_static_str_unchecked("org.freedesktop.NetworkManager.AlreadyActive")
            }
            Self::PermissionDenied(_) => ErrorName::from_static_str_unchecked(
                "org.freedesktop.NetworkManager.PermissionDenied",
            ),
            Self::NotSupported(_) => {
                ErrorName::from_static_str_unchecked("org.freedesktop.NetworkManager.NotSupported")
            }
            Self::Internal(_) => {
                ErrorName::from_static_str_unchecked("org.freedesktop.DBus.Error.Failed")
            }
        }
    }

    fn description(&self) -> Option<&str> {
        Some(match self {
            Self::UnknownConnection(desc)
            | Self::InvalidSetting(desc)
            | Self::InvalidProperty(desc)
            | Self::MissingSetting(desc)
            | Self::UnknownDevice(desc)
            | Self::UnknownActiveConnection(desc)
            | Self::NotActive(desc)
            | Self::AlreadyActive(desc)
            | Self::PermissionDenied(desc)
            | Self::NotSupported(desc)
            | Self::Internal(desc) => desc.as_str(),
        })
    }

    fn create_reply(&self, call: &zbus::message::Header) -> zbus::Result<zbus::message::Message> {
        let name = self.name();
        match self {
            Self::UnknownConnection(desc)
            | Self::InvalidSetting(desc)
            | Self::InvalidProperty(desc)
            | Self::MissingSetting(desc)
            | Self::UnknownDevice(desc)
            | Self::UnknownActiveConnection(desc)
            | Self::NotActive(desc)
            | Self::AlreadyActive(desc)
            | Self::PermissionDenied(desc)
            | Self::NotSupported(desc)
            | Self::Internal(desc) => {
                zbus::message::Message::error(call, name)?.build(&(desc.as_str()))
            }
        }
    }
}

impl std::fmt::Display for FacadeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = zbus::DBusError::name(self);
        let description = zbus::DBusError::description(self).unwrap_or("no description");
        write!(f, "{name}: {description}")
    }
}

impl std::error::Error for FacadeError {}

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
