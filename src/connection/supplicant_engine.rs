//! Linux-backed activation engine that drives wpa_supplicant over D-Bus.
//!
//! This engine implements the connection-layer [`ActivationEngine`] boundary
//! on top of the host's native Wi-Fi authentication infrastructure: it talks
//! to wpa_supplicant through its D-Bus control interface, adds the profile's
//! network configuration, asks the supplicant to associate, and reports
//! success only after the supplicant reaches the `completed` state.
//!
//! The engine never re-implements WPA/EAP cryptography, never shells out to
//! `wpa_cli` or friends, and never places secret material in errors or logs.
//! Enterprise (WPA-EAP) authentication is deliberately reported as
//! unsupported in this milestone.

use std::time::Duration;

use crate::connection::activation::{ActivationEngine, ActivationError};
use crate::connection::device::DeviceInfo;
use crate::connection::profile::{ConnectionProfile, ConnectionType, KeyManagement, WifiSettings};
use crate::connection::secrets::{SecretError, SecretProvider};
use crate::linux::supplicant::{SupplicantControl, SupplicantError};

/// Default time to wait for the supplicant to reach `completed`.
const DEFAULT_ASSOCIATION_TIMEOUT: Duration = Duration::from_secs(30);

/// An [`ActivationEngine`] backed by a [`SupplicantControl`] client.
///
/// Secrets referenced by a profile are retrieved through the injected
/// [`SecretProvider`] at activation time and handed to the supplicant as raw
/// bytes; they are never retained, logged, or echoed in errors.
pub struct WpaSupplicantActivationEngine {
    control: Box<dyn SupplicantControl>,
    secrets: Box<dyn SecretProvider>,
    timeout: Duration,
    /// The network path the supplicant currently associates with, keyed by
    /// the profile that requested it.
    active_network: Option<(String, String)>,
}

impl WpaSupplicantActivationEngine {
    /// Creates an engine with the default association timeout.
    pub fn new(control: Box<dyn SupplicantControl>, secrets: Box<dyn SecretProvider>) -> Self {
        Self::with_timeout(control, secrets, DEFAULT_ASSOCIATION_TIMEOUT)
    }

    /// Creates an engine with a custom association timeout.
    pub fn with_timeout(
        control: Box<dyn SupplicantControl>,
        secrets: Box<dyn SecretProvider>,
        timeout: Duration,
    ) -> Self {
        Self {
            control,
            secrets,
            timeout,
            active_network: None,
        }
    }
}

/// Maps a profile key-management mode to the string wpa_supplicant expects in
/// the network configuration dictionary.
fn supplicant_key_mgmt(key_management: KeyManagement) -> &'static str {
    match key_management {
        KeyManagement::Open => "NONE",
        KeyManagement::WpaPsk => "WPA-PSK",
        KeyManagement::WpaEap => "WPA-EAP",
        KeyManagement::Sae => "SAE",
        KeyManagement::Owe => "OWE",
    }
}

fn engine_err(err: SupplicantError) -> ActivationError {
    ActivationError::Engine(err.to_string())
}

/// Retrieves the passphrase for a PSK/SAE profile through the provider,
/// mapping a missing or unavailable secret to an honest engine error that
/// contains no secret material.
fn retrieve_passphrase(
    secrets: &dyn SecretProvider,
    security: &crate::connection::profile::WifiSecurity,
) -> Result<Vec<u8>, ActivationError> {
    let reference = security.secret.as_ref().ok_or_else(|| {
        ActivationError::Engine("profile is missing a secret reference".to_string())
    })?;
    match secrets.retrieve(reference) {
        Ok(Some(secret)) => Ok(secret),
        Ok(None) => Err(ActivationError::Engine(
            "no secret is available for this profile's authentication".to_string(),
        )),
        Err(SecretError::NotFound) => Err(ActivationError::Engine(
            "no secret is available for this profile's authentication".to_string(),
        )),
        Err(SecretError::Unavailable) => Err(ActivationError::Engine(
            "the secret provider is unavailable".to_string(),
        )),
    }
}

impl ActivationEngine for WpaSupplicantActivationEngine {
    fn activate(
        &mut self,
        profile: &ConnectionProfile,
        device: &DeviceInfo,
    ) -> Result<crate::connection::ip::ActivationOutcome, ActivationError> {
        if self.active_network.is_some() {
            return Err(ActivationError::Engine(
                "an activation is already in progress".to_string(),
            ));
        }
        let WifiSettings {
            ssid,
            bssid,
            hidden,
            security,
        } = match &profile.connection_type {
            ConnectionType::Wifi(settings) => settings,
            _ => {
                return Err(ActivationError::Engine(
                    "the supplicant engine only activates Wi-Fi profiles".to_string(),
                ));
            }
        };
        if self.control.ifname() != device.interface_name {
            return Err(ActivationError::Engine(format!(
                "the supplicant control is bound to interface {} but the profile was requested for {}",
                self.control.ifname(),
                device.interface_name
            )));
        }
        if security.key_management == KeyManagement::WpaEap {
            return Err(ActivationError::Engine(
                "enterprise (WPA-EAP) authentication is not yet implemented".to_string(),
            ));
        }
        let passphrase = match security.key_management {
            KeyManagement::WpaPsk | KeyManagement::Sae => {
                Some(retrieve_passphrase(self.secrets.as_ref(), security)?)
            }
            KeyManagement::Open | KeyManagement::Owe | KeyManagement::WpaEap => None,
        };

        let network_path = self
            .control
            .add_network(
                ssid,
                supplicant_key_mgmt(security.key_management),
                passphrase.as_deref(),
                security.identity.as_deref(),
                bssid.as_ref(),
                *hidden,
            )
            .map_err(engine_err)?;

        let outcome = self
            .control
            .select_network(&network_path)
            .map_err(|err| {
                let _ = self.control.remove_network(&network_path);
                engine_err(err)
            })
            .and_then(|()| {
                self.control
                    .wait_for_completed(self.timeout)
                    .map_err(|err| {
                        let _ = self.control.remove_network(&network_path);
                        engine_err(err)
                    })
            });

        match outcome {
            Ok(()) => {
                self.active_network = Some((profile.id.clone(), network_path));
                // This engine only brings the 802.11 link up; IP configuration
                // is layered on top by the composite engine.
                Ok(crate::connection::ip::ActivationOutcome::default())
            }
            Err(err) => Err(err),
        }
    }

    fn deactivate(&mut self, profile: &ConnectionProfile) -> Result<(), ActivationError> {
        let Some((active_profile, network_path)) = &self.active_network else {
            return Err(ActivationError::Engine(
                "there is no active supplicant network for this profile".to_string(),
            ));
        };
        if active_profile != &profile.id {
            return Err(ActivationError::Engine(
                "the active supplicant network belongs to a different profile".to_string(),
            ));
        }
        let network_path = network_path.clone();
        let disconnected = self.control.disconnect().map_err(engine_err);
        let removed = self
            .control
            .remove_network(&network_path)
            .map_err(engine_err);
        self.active_network = None;
        disconnected.and(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::{WpaSupplicantActivationEngine, supplicant_key_mgmt};
    use crate::connection::activation::{ActivationEngine, ActivationError};
    use crate::connection::device::DeviceInfo;
    use crate::connection::profile::{ConnectionProfile, KeyManagement, WifiSecurity};
    use crate::connection::secrets::{SecretError, SecretProvider, SecretReference};
    use crate::linux::model::Ssid;
    use crate::linux::supplicant::{SupplicantControl, SupplicantError};
    use std::time::Duration;

    const PASSPHRASE: &str = "correct-horse-battery-staple";

    /// A static provider returning a passphrase for any reference.
    struct StaticProvider {
        present: bool,
    }

    impl SecretProvider for StaticProvider {
        fn retrieve(&self, _reference: &SecretReference) -> Result<Option<Vec<u8>>, SecretError> {
            if self.present {
                Ok(Some(PASSPHRASE.as_bytes().to_vec()))
            } else {
                Ok(None)
            }
        }
    }

    /// Shared recording state captured by the scripted control and readable
    /// by the test after the control has been moved into the engine.
    #[derive(Default)]
    struct RecordingData {
        added_ssid: Option<Ssid>,
        added_key_mgmt: Option<String>,
        added_psk: Option<Vec<u8>>,
        added_identity: Option<String>,
        added_bssid: Option<crate::linux::model::Bssid>,
        added_hidden: Option<bool>,
        selected: Option<String>,
        removed: Vec<String>,
        disconnect_count: usize,
    }

    /// A recording, scripted supplicant control used to exercise the engine.
    struct RecordingControl {
        ifname: String,
        add_ok: bool,
        completed: bool,
        data: std::sync::Arc<std::sync::Mutex<RecordingData>>,
    }

    impl RecordingControl {
        fn ok() -> Self {
            Self {
                ifname: "wlan0".to_string(),
                add_ok: true,
                completed: true,
                data: std::sync::Arc::new(std::sync::Mutex::new(RecordingData::default())),
            }
        }
    }

    impl SupplicantControl for RecordingControl {
        fn ifname(&self) -> &str {
            &self.ifname
        }

        fn add_network(
            &mut self,
            ssid: &Ssid,
            key_mgmt: &str,
            psk: Option<&[u8]>,
            identity: Option<&str>,
            bssid: Option<&crate::linux::model::Bssid>,
            hidden: bool,
        ) -> Result<String, SupplicantError> {
            if !self.add_ok {
                return Err(SupplicantError::NetworkRejected("simulated".to_string()));
            }
            let mut data = self.data.lock().unwrap();
            data.added_ssid = Some(ssid.clone());
            data.added_key_mgmt = Some(key_mgmt.to_string());
            data.added_psk = psk.map(|bytes| bytes.to_vec());
            data.added_identity = identity.map(|value| value.to_string());
            data.added_bssid = bssid.cloned();
            data.added_hidden = Some(hidden);
            Ok("/fi/w1/wpa_supplicant1/Interfaces/1/Networks/1".to_string())
        }

        fn select_network(&mut self, network_path: &str) -> Result<(), SupplicantError> {
            self.data.lock().unwrap().selected = Some(network_path.to_string());
            Ok(())
        }

        fn remove_network(&mut self, network_path: &str) -> Result<(), SupplicantError> {
            self.data
                .lock()
                .unwrap()
                .removed
                .push(network_path.to_string());
            Ok(())
        }

        fn disconnect(&mut self) -> Result<(), SupplicantError> {
            self.data.lock().unwrap().disconnect_count += 1;
            Ok(())
        }

        fn wait_for_completed(&mut self, _timeout: Duration) -> Result<(), SupplicantError> {
            if self.completed {
                Ok(())
            } else {
                Err(SupplicantError::Disassociated { reason: 15 })
            }
        }
    }

    fn wifi_device() -> DeviceInfo {
        DeviceInfo::wifi("wlan0", Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
    }

    fn psk_profile(id: &str) -> ConnectionProfile {
        ConnectionProfile::wifi(
            id,
            id,
            Ssid::from_bytes(b"home").unwrap(),
            WifiSecurity::psk(SecretReference::Keyring {
                identifier: format!("nmd/{id}"),
            }),
        )
        .unwrap()
    }

    fn open_profile(id: &str) -> ConnectionProfile {
        ConnectionProfile::wifi(
            id,
            id,
            Ssid::from_bytes(b"open").unwrap(),
            WifiSecurity::open(),
        )
        .unwrap()
    }

    fn engine(control: RecordingControl) -> WpaSupplicantActivationEngine {
        WpaSupplicantActivationEngine::with_timeout(
            Box::new(control),
            Box::new(StaticProvider { present: true }),
            Duration::from_millis(1),
        )
    }

    #[test]
    fn psk_activation_reaches_completed_and_passes_the_passphrase() {
        let control = RecordingControl::ok();
        let data = control.data.clone();
        let mut engine = engine(control);
        engine
            .activate(&psk_profile("home"), &wifi_device())
            .unwrap();

        let data = data.lock().unwrap();
        assert_eq!(data.added_ssid, Some(Ssid::from_bytes(b"home").unwrap()));
        assert_eq!(data.added_key_mgmt.as_deref(), Some("WPA-PSK"));
        assert_eq!(data.added_psk.as_deref(), Some(PASSPHRASE.as_bytes()));
        assert_eq!(data.added_identity, None);
        assert_eq!(
            data.selected.as_deref(),
            Some("/fi/w1/wpa_supplicant1/Interfaces/1/Networks/1")
        );
        assert!(engine.active_network.is_some());
    }

    #[test]
    fn open_activation_passes_no_secret() {
        let control = RecordingControl::ok();
        let data = control.data.clone();
        let mut engine = engine(control);
        engine
            .activate(&open_profile("open"), &wifi_device())
            .unwrap();

        let data = data.lock().unwrap();
        assert_eq!(data.added_key_mgmt.as_deref(), Some("NONE"));
        assert!(data.added_psk.is_none());
    }

    #[test]
    fn activation_failure_is_honest_and_cleans_up() {
        let control = RecordingControl {
            completed: false,
            ..RecordingControl::ok()
        };
        let data = control.data.clone();
        let mut engine = engine(control);

        let err = engine
            .activate(&psk_profile("home"), &wifi_device())
            .unwrap_err();
        assert!(matches!(err, ActivationError::Engine(_)));
        assert!(!err.to_string().contains(PASSPHRASE));
        assert!(engine.active_network.is_none());
        assert_eq!(
            data.lock().unwrap().removed.len(),
            1,
            "failed network is removed"
        );
    }

    #[test]
    fn missing_secret_is_reported_without_material() {
        let control = RecordingControl::ok();
        let mut engine = WpaSupplicantActivationEngine::with_timeout(
            Box::new(control),
            Box::new(StaticProvider { present: false }),
            Duration::from_millis(1),
        );
        let err = engine
            .activate(&psk_profile("home"), &wifi_device())
            .unwrap_err();
        assert!(matches!(err, ActivationError::Engine(_)));
        assert!(!err.to_string().contains(PASSPHRASE));
        assert!(!format!("{err:?}").contains(PASSPHRASE));
    }

    #[test]
    fn enterprise_profiles_are_rejected_honestly() {
        let control = RecordingControl::ok();
        let mut engine = engine(control);
        let profile = ConnectionProfile::wifi(
            "corp",
            "corp",
            Ssid::from_bytes(b"corp").unwrap(),
            WifiSecurity::enterprise("user@example.org"),
        )
        .unwrap();
        let err = engine.activate(&profile, &wifi_device()).unwrap_err();
        assert!(matches!(err, ActivationError::Engine(_)));
        assert!(err.to_string().contains("not yet implemented"));
    }

    #[test]
    fn non_wifi_profiles_are_rejected() {
        let control = RecordingControl::ok();
        let mut engine = engine(control);
        let profile = ConnectionProfile::ethernet("eth", "eth").unwrap();
        let err = engine
            .activate(&profile, &DeviceInfo::ethernet("eth0", None))
            .unwrap_err();
        assert!(matches!(err, ActivationError::Engine(_)));
    }

    #[test]
    fn mismatched_interface_is_rejected() {
        let control = RecordingControl {
            ifname: "wlan1".to_string(),
            ..RecordingControl::ok()
        };
        let mut engine = engine(control);
        let err = engine
            .activate(&open_profile("open"), &wifi_device())
            .unwrap_err();
        assert!(matches!(err, ActivationError::Engine(_)));
    }

    #[test]
    fn second_activation_while_active_is_rejected() {
        let control = RecordingControl::ok();
        let mut engine = engine(control);
        engine
            .activate(&psk_profile("home"), &wifi_device())
            .unwrap();
        let err = engine
            .activate(&psk_profile("office"), &wifi_device())
            .unwrap_err();
        assert!(matches!(err, ActivationError::Engine(_)));
        assert!(err.to_string().contains("in progress"));
    }

    #[test]
    fn deactivation_disconnects_and_removes_the_network() {
        let control = RecordingControl::ok();
        let data = control.data.clone();
        let mut engine = engine(control);
        let profile = psk_profile("home");
        engine.activate(&profile, &wifi_device()).unwrap();

        engine.deactivate(&profile).unwrap();
        assert_eq!(data.lock().unwrap().disconnect_count, 1);
        assert_eq!(data.lock().unwrap().removed.len(), 1);
        assert!(engine.active_network.is_none());
    }

    #[test]
    fn deactivation_without_an_active_network_errors() {
        let control = RecordingControl::ok();
        let mut engine = engine(control);
        let err = engine.deactivate(&psk_profile("home")).unwrap_err();
        assert!(matches!(err, ActivationError::Engine(_)));
    }

    #[test]
    fn deactivation_of_a_different_profile_errors() {
        let control = RecordingControl::ok();
        let mut engine = engine(control);
        engine
            .activate(&psk_profile("home"), &wifi_device())
            .unwrap();
        let err = engine.deactivate(&psk_profile("office")).unwrap_err();
        assert!(matches!(err, ActivationError::Engine(_)));
    }

    #[test]
    fn hidden_and_bssid_constraints_reach_the_supplicant() {
        let control = RecordingControl::ok();
        let data = control.data.clone();
        let mut engine = engine(control);
        let mut profile = psk_profile("home");
        let bssid = crate::linux::model::Bssid([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        if let crate::connection::profile::ConnectionType::Wifi(settings) =
            &mut profile.connection_type
        {
            settings.hidden = true;
            settings.bssid = Some(bssid);
        }
        engine.activate(&profile, &wifi_device()).unwrap();

        let data = data.lock().unwrap();
        assert_eq!(data.added_hidden, Some(true));
        assert_eq!(data.added_bssid, Some(bssid));
    }

    #[test]
    fn key_management_strings_match_supplicant_expected_values() {
        assert_eq!(supplicant_key_mgmt(KeyManagement::Open), "NONE");
        assert_eq!(supplicant_key_mgmt(KeyManagement::WpaPsk), "WPA-PSK");
        assert_eq!(supplicant_key_mgmt(KeyManagement::Sae), "SAE");
        assert_eq!(supplicant_key_mgmt(KeyManagement::Owe), "OWE");
        assert_eq!(supplicant_key_mgmt(KeyManagement::WpaEap), "WPA-EAP");
    }
}
