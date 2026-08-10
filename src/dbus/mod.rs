//! NetworkManager-compatible D-Bus facade.
//!
//! This module renders the daemon's domain state ([`crate::daemon::Daemon`])
//! behind the `org.freedesktop.NetworkManager` well-known name. It is a
//! *compatibility* layer: properties and methods match NetworkManager's D-Bus
//! API so existing clients (nmcli, GNOME settings, iwd-style tools) can talk
//! to the daemon without changes. The facade holds no second model; every
//! interface object projects the live domain or kernel state on access.

pub mod active_connection;
pub mod convert;
pub mod device;
pub mod error;
pub mod ipconfig;
pub mod settings;

mod access_point;
mod root;
mod shared;

#[cfg(test)]
mod testutil;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use zbus::blocking::Connection;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::daemon::{Daemon, NetworkBackend};

pub use shared::Shared;

/// The object path used for "no object" references (`/`).
pub fn root_object_path() -> OwnedObjectPath {
    OwnedObjectPath::from(ObjectPath::try_from("/").expect("root object path is valid"))
}

// --- Well-known object paths ----------------------------------------------

pub const ROOT_PATH: &str = "/org/freedesktop/NetworkManager";
pub const SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";

/// Object path for a device, keyed by kernel interface index.
pub fn device_path(index: i32) -> String {
    format!("/org/freedesktop/NetworkManager/Devices/{index}")
}

/// Object path for an active connection, keyed by its daemon id.
pub fn active_path(id: crate::connection::activation::ActiveConnectionId) -> String {
    format!("/org/freedesktop/NetworkManager/ActiveConnection/{}", id.as_u64())
}

/// Object path for the IPv4 config of an active connection.
pub fn ip4_path(id: crate::connection::activation::ActiveConnectionId) -> String {
    format!("/org/freedesktop/NetworkManager/IP4Config/{}", id.as_u64())
}

/// Object path for the IPv6 config of an active connection.
pub fn ip6_path(id: crate::connection::activation::ActiveConnectionId) -> String {
    format!("/org/freedesktop/NetworkManager/IP6Config/{}", id.as_u64())
}

/// Object path for the DHCPv4 config of an active connection.
pub fn dhcp4_path(id: crate::connection::activation::ActiveConnectionId) -> String {
    format!("/org/freedesktop/NetworkManager/DHCP4Config/{}", id.as_u64())
}

/// Object path for the DHCPv6 config of an active connection.
pub fn dhcp6_path(id: crate::connection::activation::ActiveConnectionId) -> String {
    format!("/org/freedesktop/NetworkManager/DHCP6Config/{}", id.as_u64())
}

/// Object path for a settings connection, keyed by its UUID.
pub fn settings_connection_path(uuid: &str) -> String {
    format!("/org/freedesktop/NetworkManager/Settings/{uuid}")
}

/// Object path for an access point, keyed by device index and BSSID.
pub fn access_point_path(device_index: i32, bssid: &[u8; 6]) -> String {
    format!(
        "/org/freedesktop/NetworkManager/AccessPoint/{device_index}_{}",
        bssid.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
    )
}

// --- NetworkManager enum constants -----------------------------------------
// Values mirror NetworkManager's public headers so clients see familiar ints.

pub const NM_DEVICE_TYPE_ETHERNET: u32 = 1;
pub const NM_DEVICE_TYPE_WIFI: u32 = 2;
pub const NM_DEVICE_TYPE_LOOPBACK: u32 = 32;

pub const NM_DEVICE_STATE_UNKNOWN: u32 = 0;
pub const NM_DEVICE_STATE_UNMANAGED: u32 = 10;
pub const NM_DEVICE_STATE_UNAVAILABLE: u32 = 20;
pub const NM_DEVICE_STATE_DISCONNECTED: u32 = 30;
pub const NM_DEVICE_STATE_PREPARE: u32 = 40;
pub const NM_DEVICE_STATE_CONFIG: u32 = 50;
pub const NM_DEVICE_STATE_NEED_AUTH: u32 = 60;
pub const NM_DEVICE_STATE_IP_CONFIG: u32 = 70;
pub const NM_DEVICE_STATE_IP_CHECK: u32 = 80;
pub const NM_DEVICE_STATE_SECONDARIES: u32 = 90;
pub const NM_DEVICE_STATE_ACTIVATED: u32 = 100;
pub const NM_DEVICE_STATE_DEACTIVATING: u32 = 110;
pub const NM_DEVICE_STATE_FAILED: u32 = 120;

pub const NM_CONNECTIVITY_UNKNOWN: u32 = 0;
pub const NM_CONNECTIVITY_NONE: u32 = 1;
pub const NM_CONNECTIVITY_PORTAL: u32 = 2;
pub const NM_CONNECTIVITY_LIMITED: u32 = 3;
pub const NM_CONNECTIVITY_FULL: u32 = 4;

pub const NM_STATE_UNKNOWN: u32 = 0;
pub const NM_STATE_ASLEEP: u32 = 10;
pub const NM_STATE_DISCONNECTED: u32 = 20;
pub const NM_STATE_CONNECTING: u32 = 40;
pub const NM_STATE_CONNECTED_LOCAL: u32 = 50;
pub const NM_STATE_CONNECTED_SITE: u32 = 60;
pub const NM_STATE_CONNECTED_GLOBAL: u32 = 70;

pub const NM_ACTIVE_CONNECTION_STATE_UNKNOWN: u32 = 0;
pub const NM_ACTIVE_CONNECTION_STATE_ACTIVATING: u32 = 1;
pub const NM_ACTIVE_CONNECTION_STATE_ACTIVATED: u32 = 2;
pub const NM_ACTIVE_CONNECTION_STATE_DEACTIVATING: u32 = 3;
pub const NM_ACTIVE_CONNECTION_STATE_DEACTIVATED: u32 = 4;

pub const NM_ACCESS_POINT_FLAGS_NONE: u32 = 0;
pub const NM_ACCESS_POINT_FLAGS_PRIVACY: u32 = 0x1;

pub const NM_802_11_AP_SEC_NONE: u32 = 0x0;
pub const NM_802_11_AP_SEC_KEY_MGMT_PSK: u32 = 0x100;
pub const NM_802_11_AP_SEC_KEY_MGMT_802_1X: u32 = 0x200;
pub const NM_802_11_AP_SEC_KEY_MGMT_SAE: u32 = 0x400;
pub const NM_802_11_AP_SEC_KEY_MGMT_OWE: u32 = 0x800;

pub const NM_SETTING_CONNECTION_FLAG_NONE: u32 = 0;
pub const NM_SETTING_CONNECTION_FLAG_UNSAVED: u32 = 0x1;
pub const NM_SETTING_CONNECTION_FLAG_NM_GENERATED: u32 = 0x2;

/// The bus name this daemon claims.
pub const BUS_NAME: &str = "org.freedesktop.NetworkManager";

/// Runs a generated signal future to completion on the blocking facade and maps
/// zbus errors into [`FacadeError`].
pub fn emit(
    future: impl std::future::Future<Output = zbus::Result<()>>,
) -> Result<(), error::FacadeError> {
    zbus::block_on(future).map_err(|error| error::FacadeError::Internal(error.to_string()))
}

/// D-Bus entry point: claims the well-known name and registers every object
/// that the current daemon state requires.
///
/// Registration is deterministic and idempotent, so a daemon restart rebuilds
/// the exact same object tree (minus the ephemeral kernel-backed views).
pub struct Server<B> {
    pub conn: Connection,
    pub shared: Arc<Shared<B>>,
}

impl<B: NetworkBackend + Send + Sync + 'static> Server<B> {
    /// Connects to the session bus and registers all objects.
    pub fn serve(daemon: Daemon<B>) -> zbus::Result<Self> {
        Self::connect(daemon, BUS_NAME)
    }

    /// Connects to the bus with an explicit well-known name (tests).
    pub fn serve_with_name(daemon: Daemon<B>, name: &str) -> zbus::Result<Self> {
        Self::connect(daemon, name)
    }

    /// Registers every object on an already-connected connection.
    ///
    /// Tests use this with a peer-to-peer connection so the facade can be
    /// exercised without a message bus.
    pub fn attach(daemon: Daemon<B>, conn: Connection) -> zbus::Result<Self> {
        let shared = Arc::new(Shared::new(daemon, conn.clone()));
        let server = Self {
            conn: conn.clone(),
            shared: shared.clone(),
        };
        server.conn.object_server().at(
            OwnedObjectPath::try_from(ROOT_PATH)?,
            root::RootIface::new(shared.clone()),
        )?;
        server.conn.object_server().at(
            OwnedObjectPath::try_from(SETTINGS_PATH)?,
            settings::SettingsIface::new(shared.clone()),
        )?;
        server.shared.register_all()?;
        Ok(server)
    }

    fn connect(daemon: Daemon<B>, name: &str) -> zbus::Result<Self> {
        let conn = Connection::session()?;
        conn.request_name(name)
            .map_err(|error| zbus::Error::Failure(format!("cannot claim {name}: {error}")))?;
        Self::attach(daemon, conn)
    }
}
