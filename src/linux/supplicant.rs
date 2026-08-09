//! Typed wpa_supplicant D-Bus control client.
//!
//! The host's native Wi-Fi authentication infrastructure is
//! [`wpa_supplicant`](https://w1.fi/wpa_supplicant/), which exposes a control
//! interface on the system bus as `fi.w1.wpa_supplicant1`. This module speaks
//! that D-Bus API directly (the native IPC/control API) over the pure-Rust
//! [`zbus`] client; it never shells out to `wpa_cli` or other utilities and it
//! never re-implements WPA/EAP cryptography.
//!
//! # Security boundary
//!
//! Passphrases are accepted as raw bytes and serialized into the network
//! configuration sent to the supplicant. They are never stored on this client,
//! never printed, and never included in [`SupplicantError`] messages.

use std::fmt;
use std::time::{Duration, Instant};

use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, Value};

use crate::linux::model::{Bssid, Ssid};

/// The D-Bus well-known name of the wpa_supplicant control service.
const SUPPLICANT_DESTINATION: &str = "fi.w1.wpa_supplicant1";
/// Object path of the service root object.
const SUPPLICANT_ROOT_PATH: &str = "/fi/w1/wpa_supplicant1";
/// D-Bus interface of the service root object.
const SUPPLICANT_ROOT_INTERFACE: &str = "fi.w1.wpa_supplicant1";
/// D-Bus interface of a per-interface control object.
const SUPPLICANT_INTERFACE_INTERFACE: &str = "fi.w1.wpa_supplicant1.Interface";

/// Time between state polls while waiting for association to complete.
const STATE_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Errors surfaced by the wpa_supplicant control client.
///
/// The [`Display`](fmt::Display) output deliberately never contains secret
/// material; passphrases are never placed in error strings.
#[derive(Debug)]
pub enum SupplicantError {
    /// The system D-Bus connection or a method call on it failed.
    Bus(String),
    /// The named wireless interface is not registered with the supplicant.
    InterfaceNotFound(String),
    /// The key-management configuration was rejected by the supplicant.
    NetworkRejected(String),
    /// The supplicant left the associated state (association or handshake).
    Disassociated { reason: i32 },
    /// The supplicant stopped connecting before reaching `completed`.
    NotConnected { state: String },
    /// The supplicant did not reach `completed` within the timeout.
    AssociationTimeout,
}

impl fmt::Display for SupplicantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bus(err) => write!(f, "wpa_supplicant D-Bus failure: {err}"),
            Self::InterfaceNotFound(name) => {
                write!(
                    f,
                    "wireless interface {name} is not registered with wpa_supplicant"
                )
            }
            Self::NetworkRejected(reason) => {
                write!(
                    f,
                    "wpa_supplicant rejected the network configuration: {reason}"
                )
            }
            Self::Disassociated { reason } => {
                write!(f, "wpa_supplicant disassociated (reason code {reason})")
            }
            Self::NotConnected { state } => {
                write!(
                    f,
                    "wpa_supplicant stopped connecting while in state {state:?}"
                )
            }
            Self::AssociationTimeout => {
                f.write_str("wpa_supplicant did not complete association within the timeout")
            }
        }
    }
}

impl std::error::Error for SupplicantError {}

/// The subset of the supplicant control API the activation engine needs.
///
/// This trait is the test seam between the daemon and the live D-Bus client:
/// engine logic is exercised against a fake control implementation while the
/// real [`WpaSupplicant`] is exercised only against a real bus. The key
/// management mode is passed as the raw supplicant string (for example
/// `"WPA-PSK"`) so this trait stays independent of the connection layer.
pub trait SupplicantControl {
    /// The wireless interface name this control is bound to.
    fn ifname(&self) -> &str;

    /// Registers a network configuration and returns its object path.
    fn add_network(
        &mut self,
        ssid: &Ssid,
        key_mgmt: &str,
        psk: Option<&[u8]>,
        identity: Option<&str>,
        bssid: Option<&Bssid>,
        hidden: bool,
    ) -> Result<String, SupplicantError>;

    /// Instructs the supplicant to associate with the given network.
    fn select_network(&mut self, network_path: &str) -> Result<(), SupplicantError>;

    /// Removes a previously registered network configuration.
    fn remove_network(&mut self, network_path: &str) -> Result<(), SupplicantError>;

    /// Disconnects from the current network, if any.
    fn disconnect(&mut self) -> Result<(), SupplicantError>;

    /// Blocks until association reaches `completed`, a terminal failure, or
    /// `timeout` elapses.
    fn wait_for_completed(&mut self, timeout: Duration) -> Result<(), SupplicantError>;
}

/// A live wpa_supplicant control client bound to one wireless interface.
pub struct WpaSupplicant {
    connection: Connection,
    ifname: String,
}

impl WpaSupplicant {
    /// Opens a system-bus connection and resolves `ifname`.
    pub fn connect(ifname: &str) -> Result<Self, SupplicantError> {
        let connection =
            Connection::system().map_err(|err| SupplicantError::Bus(err.to_string()))?;
        Self::with_connection(connection, ifname)
    }

    /// Binds an existing system-bus connection to `ifname`.
    pub fn with_connection(connection: Connection, ifname: &str) -> Result<Self, SupplicantError> {
        // Any failure here means the interface is not registered; wpa_supplicant
        // raises an unknown-interface error rather than returning a value.
        {
            let root = root_proxy(&connection)?;
            root.call::<_, _, OwnedObjectPath>("GetInterface", &(ifname,))
                .map_err(|_| SupplicantError::InterfaceNotFound(ifname.to_string()))?;
        }
        Ok(Self {
            connection,
            ifname: ifname.to_string(),
        })
    }

    fn root(&self) -> Result<Proxy<'_>, SupplicantError> {
        root_proxy(&self.connection)
    }

    fn interface(&self) -> Result<Proxy<'_>, SupplicantError> {
        let root = self.root()?;
        let path: OwnedObjectPath = root
            .call("GetInterface", &(self.ifname.as_str(),))
            .map_err(|err| SupplicantError::Bus(err.to_string()))?;
        Proxy::new(
            &self.connection,
            SUPPLICANT_DESTINATION,
            path,
            SUPPLICANT_INTERFACE_INTERFACE,
        )
        .map_err(|err| SupplicantError::Bus(err.to_string()))
    }
}

fn root_proxy(connection: &Connection) -> Result<Proxy<'_>, SupplicantError> {
    Proxy::new(
        connection,
        SUPPLICANT_DESTINATION,
        SUPPLICANT_ROOT_PATH,
        SUPPLICANT_ROOT_INTERFACE,
    )
    .map_err(|err| SupplicantError::Bus(err.to_string()))
}

impl SupplicantControl for WpaSupplicant {
    fn ifname(&self) -> &str {
        &self.ifname
    }

    fn add_network(
        &mut self,
        ssid: &Ssid,
        key_mgmt: &str,
        psk: Option<&[u8]>,
        identity: Option<&str>,
        bssid: Option<&Bssid>,
        hidden: bool,
    ) -> Result<String, SupplicantError> {
        let config = network_config_dict(ssid, key_mgmt, psk, identity, bssid, hidden);
        let interface = self.interface()?;
        let path: OwnedObjectPath = interface
            .call("AddNetwork", &(config,))
            .map_err(|err| SupplicantError::NetworkRejected(err.to_string()))?;
        Ok(path.to_string())
    }

    fn select_network(&mut self, network_path: &str) -> Result<(), SupplicantError> {
        let path = owned_path(network_path)?;
        let interface = self.interface()?;
        interface
            .call::<_, _, ()>("SelectNetwork", &(path,))
            .map_err(|err| SupplicantError::Bus(err.to_string()))
    }

    fn remove_network(&mut self, network_path: &str) -> Result<(), SupplicantError> {
        let path = owned_path(network_path)?;
        let interface = self.interface()?;
        interface
            .call::<_, _, ()>("RemoveNetwork", &(path,))
            .map_err(|err| SupplicantError::Bus(err.to_string()))
    }

    fn disconnect(&mut self) -> Result<(), SupplicantError> {
        let interface = self.interface()?;
        interface
            .call::<_, _, ()>("Disconnect", &())
            .map_err(|err| SupplicantError::Bus(err.to_string()))
    }

    fn wait_for_completed(&mut self, timeout: Duration) -> Result<(), SupplicantError> {
        let interface = self.interface()?;
        wait_for_completed(&interface, timeout)
    }
}

fn owned_path(network_path: &str) -> Result<OwnedObjectPath, SupplicantError> {
    OwnedObjectPath::try_from(network_path.to_string())
        .map_err(|err| SupplicantError::Bus(err.to_string()))
}

/// Builds the `a{sv}` dictionary for [`fi.w1.wpa_supplicant1.Interface::AddNetwork`].
///
/// Pure function so the argument construction is unit-tested without a bus.
/// The passphrase (when present) is copied into the returned dictionary; it is
/// never logged or echoed back in errors.
fn network_config_dict(
    ssid: &Ssid,
    key_mgmt: &str,
    psk: Option<&[u8]>,
    identity: Option<&str>,
    bssid: Option<&Bssid>,
    hidden: bool,
) -> std::collections::HashMap<String, Value<'static>> {
    let mut config = std::collections::HashMap::new();
    config.insert("ssid".to_string(), Value::from(ssid.as_bytes().to_vec()));
    config.insert("key_mgmt".to_string(), Value::from(key_mgmt.to_string()));
    if let Some(passphrase) = psk {
        config.insert(
            "psk".to_string(),
            Value::from(String::from_utf8_lossy(passphrase).into_owned()),
        );
    }
    if let Some(identity) = identity {
        config.insert("identity".to_string(), Value::from(identity.to_string()));
    }
    if let Some(bssid) = bssid {
        config.insert(
            "bssid".to_string(),
            Value::from(crate::linux::model::format_mac_address(bssid.as_bytes())),
        );
    }
    if hidden {
        config.insert("scan_ssid".to_string(), Value::from(1_u32));
    }
    config
}

/// Classifies a supplicant `State` / `DisconnectReason` snapshot.
///
/// Returns `None` while connection progress is still ongoing, `Some(Ok(()))`
/// once the connection is `completed`, and `Some(Err(..))` for terminal
/// failures. Pure so the decision logic is unit-tested without a bus.
fn classify_state(state: &str, disconnect_reason: i32) -> Option<Result<(), SupplicantError>> {
    match state {
        "completed" => Some(Ok(())),
        "disconnected" => {
            if disconnect_reason != 0 {
                Some(Err(SupplicantError::Disassociated {
                    reason: disconnect_reason,
                }))
            } else {
                None
            }
        }
        "inactive" => Some(Err(SupplicantError::NotConnected {
            state: state.to_string(),
        })),
        _ => None,
    }
}

/// Polls the supplicant `State` property until association completes or fails.
///
/// The supplicant reports connection state through the `State` property
/// (`disconnected`, `scanning`, `authenticating`, `associating`,
/// `4way_handshake`, `group_handshake`, `completed`, ...) and the
/// `DisconnectReason` property carries a non-zero reason code when a connection
/// attempt terminates in failure. A connection is only reported as established
/// when the state is `completed`.
fn wait_for_completed(interface: &Proxy<'_>, timeout: Duration) -> Result<(), SupplicantError> {
    let deadline = Instant::now() + timeout;
    loop {
        let state: String = interface
            .get_property("State")
            .map_err(|err| SupplicantError::Bus(err.to_string()))?;
        let reason: i32 = interface
            .get_property("DisconnectReason")
            .map_err(|err| SupplicantError::Bus(err.to_string()))?;
        if let Some(result) = classify_state(&state, reason) {
            return result;
        }
        if Instant::now() >= deadline {
            return Err(SupplicantError::AssociationTimeout);
        }
        std::thread::sleep(STATE_POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::{SupplicantControl, SupplicantError, network_config_dict};
    use crate::linux::model::Ssid;
    use std::collections::HashMap;
    use std::time::Duration;
    use zbus::zvariant::Value;

    /// A scripted control implementation used to exercise the trait contract
    /// without a bus.
    struct FakeControl {
        ifname: String,
    }

    impl SupplicantControl for FakeControl {
        fn ifname(&self) -> &str {
            &self.ifname
        }

        fn add_network(
            &mut self,
            _ssid: &Ssid,
            _key_mgmt: &str,
            _psk: Option<&[u8]>,
            _identity: Option<&str>,
            _bssid: Option<&crate::linux::model::Bssid>,
            _hidden: bool,
        ) -> Result<String, SupplicantError> {
            Ok("/fi/w1/wpa_supplicant1/Interfaces/1/Networks/1".to_string())
        }

        fn select_network(&mut self, _network_path: &str) -> Result<(), SupplicantError> {
            Ok(())
        }

        fn remove_network(&mut self, _network_path: &str) -> Result<(), SupplicantError> {
            Ok(())
        }

        fn disconnect(&mut self) -> Result<(), SupplicantError> {
            Ok(())
        }

        fn wait_for_completed(&mut self, _timeout: Duration) -> Result<(), SupplicantError> {
            Ok(())
        }
    }

    fn config_of<'a>(
        dict: &'a HashMap<String, Value<'static>>,
        key: &str,
    ) -> Option<&'a Value<'static>> {
        dict.get(key)
    }

    fn as_string(value: &Value<'_>) -> Option<String> {
        match value {
            Value::Str(string) => Some(string.as_str().to_string()),
            _ => None,
        }
    }

    fn as_bytes(value: &Value<'_>) -> Option<Vec<u8>> {
        match value {
            Value::Array(array) => array
                .inner()
                .iter()
                .map(|element| match element {
                    Value::U8(byte) => Some(*byte),
                    _ => None,
                })
                .collect(),
            _ => None,
        }
    }

    #[test]
    fn open_network_config_omits_secret_fields() {
        let ssid = Ssid::from_bytes(b"OpenNet").unwrap();
        let config = network_config_dict(&ssid, "NONE", None, None, None, false);

        assert_eq!(
            as_string(config_of(&config, "key_mgmt").unwrap()),
            Some("NONE".to_string())
        );
        assert_eq!(
            as_string(config_of(&config, "ssid").unwrap()),
            None,
            "ssid is bytes, not a string"
        );
        assert_eq!(
            as_bytes(config_of(&config, "ssid").unwrap()),
            Some(b"OpenNet".to_vec())
        );
        assert!(!config.contains_key("psk"));
        assert!(!config.contains_key("identity"));
        assert!(!config.contains_key("scan_ssid"));
    }

    #[test]
    fn psk_network_config_carries_passphrase_without_leaking_it_as_a_key() {
        let ssid = Ssid::from_bytes(b"home").unwrap();
        let config =
            network_config_dict(&ssid, "WPA-PSK", Some(b"correct horse"), None, None, false);

        assert_eq!(
            as_string(config_of(&config, "psk").unwrap()),
            Some("correct horse".to_string())
        );
        assert_eq!(
            as_string(config_of(&config, "key_mgmt").unwrap()),
            Some("WPA-PSK".to_string())
        );
    }

    #[test]
    fn hidden_networks_set_scan_ssid() {
        let ssid = Ssid::from_bytes(b"hidden").unwrap();
        let config = network_config_dict(&ssid, "WPA-PSK", None, None, None, true);
        assert!(config.contains_key("scan_ssid"));
    }

    #[test]
    fn enterprise_and_bssid_config_fields_are_present() {
        let ssid = Ssid::from_bytes(b"corp").unwrap();
        let bssid = crate::linux::model::Bssid([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let config = network_config_dict(
            &ssid,
            "WPA-EAP",
            None,
            Some("user@example.org"),
            Some(&bssid),
            false,
        );
        assert_eq!(
            as_string(config_of(&config, "identity").unwrap()),
            Some("user@example.org".to_string())
        );
        assert_eq!(
            as_string(config_of(&config, "bssid").unwrap()),
            Some("00:11:22:33:44:55".to_string())
        );
    }

    #[test]
    fn supplicant_errors_never_contain_passphrase_material() {
        for error in [
            SupplicantError::Bus("method failed".to_string()),
            SupplicantError::NetworkRejected("invalid psk".to_string()),
            SupplicantError::Disassociated { reason: 15 },
            SupplicantError::NotConnected {
                state: "disconnected".to_string(),
            },
            SupplicantError::AssociationTimeout,
        ] {
            assert!(!error.to_string().contains("correct horse"));
            assert!(!format!("{error:?}").contains("correct horse"));
        }
    }

    #[test]
    fn fake_control_honors_the_trait_contract() {
        let mut control = FakeControl {
            ifname: "wlan0".to_string(),
        };
        let path = control
            .add_network(
                &Ssid::from_bytes(b"home").unwrap(),
                "WPA-PSK",
                Some(b"hunter2"),
                None,
                None,
                false,
            )
            .unwrap();
        assert!(path.contains("Networks/1"));
        control.select_network(&path).unwrap();
        control.remove_network(&path).unwrap();
        control.disconnect().unwrap();
        control.wait_for_completed(Duration::from_secs(1)).unwrap();
        assert_eq!(control.ifname(), "wlan0");
    }

    #[test]
    fn timeout_error_is_self_describing() {
        assert!(
            SupplicantError::AssociationTimeout
                .to_string()
                .contains("timeout")
        );
    }

    #[test]
    fn state_classification_is_exact() {
        use super::classify_state;
        assert!(matches!(classify_state("completed", 0), Some(Ok(()))));
        assert!(matches!(
            classify_state("disconnected", 15),
            Some(Err(SupplicantError::Disassociated { reason: 15 }))
        ));
        assert!(matches!(
            classify_state("inactive", 0),
            Some(Err(SupplicantError::NotConnected { .. }))
        ));
        for state in [
            "scanning",
            "authenticating",
            "associating",
            "4way_handshake",
            "group_handshake",
        ] {
            assert!(classify_state(state, 0).is_none(), "{state} is ongoing");
            assert!(classify_state(state, 2).is_none(), "{state} is ongoing");
        }
        assert!(classify_state("disconnected", 0).is_none());
    }
}
