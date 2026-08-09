use crate::connection::activation::{
    ActivationEngine, ActivationError, ActivationManager, ActiveConnection, ActiveConnectionId,
    UnsupportedActivationEngine,
};
use crate::connection::device::DeviceInfo;
use crate::connection::profile::{ConnectionProfile, ProfileId};
use crate::connection::state::ConnectionEvent;
use crate::connection::store::{InMemoryProfileStore, ProfileStore, StoreError};
use crate::linux::model::{
    AccessPoint, Address, Link, NetlinkError, NetworkEvent, NetworkEventSource, Route,
    WirelessInterface,
};

/// Minimal backend boundary for daemon networking state.
pub trait NetworkBackend {
    fn links(&self) -> Result<Vec<Link>, NetlinkError>;

    fn addresses(&self) -> Result<Vec<Address>, NetlinkError>;

    fn routes(&self) -> Result<Vec<Route>, NetlinkError>;

    fn events(&self) -> Result<Box<dyn NetworkEventSource>, NetlinkError>;

    fn wifi_interfaces(&self) -> Result<Vec<WirelessInterface>, NetlinkError>;

    fn access_points(&self) -> Result<Vec<AccessPoint>, NetlinkError>;

    fn scan_wifi(&self) -> Result<Vec<AccessPoint>, NetlinkError>;

    fn wifi_events(&self) -> Result<Box<dyn NetworkEventSource>, NetlinkError>;
}

/// Daemon coordinator.
///
/// Owns a network [`NetworkBackend`], a connection-profile store and the
/// [`ActivationManager`]. The daemon itself never touches filesystem or
/// netlink details directly; those live behind the backend and store traits.
pub struct Daemon<B> {
    backend: B,
    profiles: Box<dyn ProfileStore>,
    activation: ActivationManager,
}

impl<B> Daemon<B>
where
    B: NetworkBackend,
{
    /// Creates a daemon with an in-memory profile store and a placeholder
    /// activation engine (real activation arrives in a later phase).
    pub fn new(backend: B) -> Self {
        Self::with_components(
            backend,
            Box::new(InMemoryProfileStore::new()),
            Box::new(UnsupportedActivationEngine),
        )
    }

    /// Creates a daemon with a custom profile store.
    pub fn with_store(backend: B, store: Box<dyn ProfileStore>) -> Self {
        Self::with_components(backend, store, Box::new(UnsupportedActivationEngine))
    }

    /// Creates a daemon with a custom activation engine.
    pub fn with_engine(backend: B, engine: Box<dyn ActivationEngine>) -> Self {
        Self::with_components(backend, Box::new(InMemoryProfileStore::new()), engine)
    }

    /// Creates a daemon with both a custom store and a custom engine.
    pub fn with_components(
        backend: B,
        store: Box<dyn ProfileStore>,
        engine: Box<dyn ActivationEngine>,
    ) -> Self {
        Self {
            backend,
            profiles: store,
            activation: ActivationManager::new(engine),
        }
    }

    // --- Network state ---------------------------------------------------

    pub fn links(&self) -> Result<Vec<Link>, NetlinkError> {
        self.backend.links()
    }

    pub fn addresses(&self) -> Result<Vec<Address>, NetlinkError> {
        self.backend.addresses()
    }

    pub fn routes(&self) -> Result<Vec<Route>, NetlinkError> {
        self.backend.routes()
    }

    pub fn events(&self) -> Result<Box<dyn NetworkEventSource>, NetlinkError> {
        self.backend.events()
    }

    pub fn wifi_interfaces(&self) -> Result<Vec<WirelessInterface>, NetlinkError> {
        self.backend.wifi_interfaces()
    }

    pub fn access_points(&self) -> Result<Vec<AccessPoint>, NetlinkError> {
        self.backend.access_points()
    }

    pub fn scan_wifi(&self) -> Result<Vec<AccessPoint>, NetlinkError> {
        self.backend.scan_wifi()
    }

    pub fn wifi_events(&self) -> Result<Box<dyn NetworkEventSource>, NetlinkError> {
        self.backend.wifi_events()
    }

    pub fn next_event(
        source: &mut dyn NetworkEventSource,
    ) -> Result<Option<NetworkEvent>, NetlinkError> {
        source.next_event()
    }

    /// Returns devices suitable for profile matching and activation.
    ///
    /// Phase 4 exposes the wireless devices enumerated by the nl80211 backend;
    /// wired device classification arrives with the full device model.
    pub fn devices(&self) -> Result<Vec<DeviceInfo>, NetlinkError> {
        Ok(self
            .backend
            .wifi_interfaces()?
            .iter()
            .map(DeviceInfo::from)
            .collect())
    }

    // --- Profiles --------------------------------------------------------

    pub fn list_profiles(&self) -> Result<Vec<ConnectionProfile>, StoreError> {
        self.profiles.list()
    }

    pub fn get_profile(&self, id: &ProfileId) -> Result<ConnectionProfile, StoreError> {
        self.profiles.get(id)
    }

    pub fn create_profile(&mut self, profile: ConnectionProfile) -> Result<(), StoreError> {
        self.profiles.create(profile)
    }

    pub fn update_profile(&mut self, profile: ConnectionProfile) -> Result<(), StoreError> {
        self.profiles.update(profile)
    }

    pub fn delete_profile(&mut self, id: &ProfileId) -> Result<(), StoreError> {
        self.profiles.delete(id)
    }

    // --- Activation ------------------------------------------------------

    pub fn activate(&mut self, device: &DeviceInfo) -> Result<ActiveConnection, ActivationError> {
        self.activation.activate(self.profiles.as_ref(), device)
    }

    pub fn activate_profile(
        &mut self,
        profile_id: &ProfileId,
        device: &DeviceInfo,
    ) -> Result<ActiveConnection, ActivationError> {
        self.activation
            .activate_profile(self.profiles.as_ref(), profile_id, device)
    }

    pub fn deactivate(&mut self, active_id: ActiveConnectionId) -> Result<(), ActivationError> {
        self.activation.deactivate(active_id)
    }

    pub fn active_connections(&self) -> &[ActiveConnection] {
        self.activation.active_connections()
    }

    pub fn connection_events(&mut self) -> Vec<ConnectionEvent> {
        self.activation.drain_events()
    }
}

#[cfg(test)]
mod tests {
    use super::{Daemon, NetworkBackend};
    use crate::connection::activation::{ActivationEngine, ActivationError};
    use crate::connection::device::DeviceInfo;
    use crate::connection::profile::{ConnectionProfile, WifiSecurity};
    use crate::connection::secrets::SecretReference;
    use crate::connection::state::ConnectionState;
    use crate::linux::model::{
        AccessPoint, Address, InterfaceType, Link, NetlinkError, NetworkEvent, NetworkEventSource,
        Route, WifiBand, WifiBandId, WifiCapabilities, WifiCipher, WirelessInterface,
    };

    struct EmptyEventSource;

    impl NetworkEventSource for EmptyEventSource {
        fn next_event(&mut self) -> Result<Option<NetworkEvent>, NetlinkError> {
            Ok(None)
        }
    }

    #[derive(Default)]
    struct FakeBackend {
        links: Vec<Link>,
        addresses: Vec<Address>,
        routes: Vec<Route>,
        wifi: Vec<WirelessInterface>,
        access_points: Vec<AccessPoint>,
    }

    impl FakeBackend {
        fn with_wifi_interface(mut self, index: i32, name: &str, mac: [u8; 6]) -> Self {
            self.wifi.push(WirelessInterface {
                index,
                name: name.to_string(),
                wiphy_index: Some(index as u32),
                wiphy_name: Some(format!("phy{index}")),
                interface_type: InterfaceType::Station,
                mac: Some(mac),
                up: true,
                capabilities: WifiCapabilities {
                    supported_interfaces: vec![InterfaceType::Station],
                    cipher_suites: vec![WifiCipher::Ccmp],
                    bands: vec![WifiBand {
                        id: WifiBandId::Ghz2,
                        channels: vec![1, 6, 11],
                        frequencies: vec![2412, 2437, 2462],
                        ht_capabilities: None,
                        vht_capabilities: None,
                    }],
                    max_scan_ssids: Some(4),
                    scan_supported: true,
                },
            });
            self
        }
    }

    impl NetworkBackend for FakeBackend {
        fn links(&self) -> Result<Vec<Link>, NetlinkError> {
            Ok(self.links.clone())
        }

        fn addresses(&self) -> Result<Vec<Address>, NetlinkError> {
            Ok(self.addresses.clone())
        }

        fn routes(&self) -> Result<Vec<Route>, NetlinkError> {
            Ok(self.routes.clone())
        }

        fn events(&self) -> Result<Box<dyn NetworkEventSource>, NetlinkError> {
            Ok(Box::new(EmptyEventSource))
        }

        fn wifi_interfaces(&self) -> Result<Vec<WirelessInterface>, NetlinkError> {
            Ok(self.wifi.clone())
        }

        fn access_points(&self) -> Result<Vec<AccessPoint>, NetlinkError> {
            Ok(self.access_points.clone())
        }

        fn scan_wifi(&self) -> Result<Vec<AccessPoint>, NetlinkError> {
            Ok(self.access_points.clone())
        }

        fn wifi_events(&self) -> Result<Box<dyn NetworkEventSource>, NetlinkError> {
            Ok(Box::new(EmptyEventSource))
        }
    }

    struct SuccessEngine;

    impl ActivationEngine for SuccessEngine {
        fn activate(
            &mut self,
            _profile: &ConnectionProfile,
            _device: &DeviceInfo,
        ) -> Result<(), ActivationError> {
            Ok(())
        }

        fn deactivate(&mut self, _profile: &ConnectionProfile) -> Result<(), ActivationError> {
            Ok(())
        }
    }

    fn open_profile(id: &str) -> ConnectionProfile {
        ConnectionProfile::wifi(
            id,
            id,
            crate::linux::model::Ssid::from_bytes(b"home").unwrap(),
            WifiSecurity::open(),
        )
        .unwrap()
    }

    fn psk_profile(id: &str) -> ConnectionProfile {
        ConnectionProfile::wifi(
            id,
            id,
            crate::linux::model::Ssid::from_bytes(b"home").unwrap(),
            WifiSecurity::psk(SecretReference::Keyring {
                identifier: format!("nmd/{id}"),
            }),
        )
        .unwrap()
    }

    #[test]
    fn daemon_exposes_backend_network_state() {
        let backend = FakeBackend::default().with_wifi_interface(
            2,
            "wlan0",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        );
        let daemon = Daemon::new(backend);

        assert_eq!(daemon.links().unwrap().len(), 0);
        assert_eq!(daemon.addresses().unwrap().len(), 0);
        let wifi = daemon.wifi_interfaces().unwrap();
        assert_eq!(wifi.len(), 1);
        assert_eq!(wifi[0].name, "wlan0");
        assert_eq!(daemon.scan_wifi().unwrap().len(), 0);
    }

    #[test]
    fn daemon_derives_devices_from_wireless_interfaces() {
        let backend = FakeBackend::default().with_wifi_interface(
            2,
            "wlan0",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        );
        let daemon = Daemon::new(backend);

        let devices = daemon.devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].interface_name, "wlan0");
        assert!(matches!(
            devices[0].kind,
            crate::connection::device::DeviceKind::Wifi
        ));
    }

    #[test]
    fn daemon_profile_crud_and_activation_integration() {
        let backend = FakeBackend::default().with_wifi_interface(
            2,
            "wlan0",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        );
        let mut daemon = Daemon::with_engine(backend, Box::new(SuccessEngine));

        assert!(daemon.list_profiles().unwrap().is_empty());
        daemon.create_profile(psk_profile("home")).unwrap();
        daemon.create_profile(psk_profile("office")).unwrap();
        assert_eq!(daemon.list_profiles().unwrap().len(), 2);

        let device = daemon.devices().unwrap().remove(0);
        let active = daemon.activate(&device).unwrap();
        assert_eq!(active.profile.id, "home");
        assert_eq!(active.state, ConnectionState::Activated);

        daemon.deactivate(active.id).unwrap();
        assert!(matches!(
            daemon.connection_events().last(),
            Some(crate::connection::state::ConnectionEvent::Deactivated { .. })
        ));

        daemon.delete_profile(&"office".to_string()).unwrap();
        assert_eq!(daemon.list_profiles().unwrap().len(), 1);
    }

    #[test]
    fn daemon_activation_failure_is_reported() {
        struct FailingEngine;
        impl ActivationEngine for FailingEngine {
            fn activate(
                &mut self,
                _profile: &ConnectionProfile,
                _device: &DeviceInfo,
            ) -> Result<(), ActivationError> {
                Err(ActivationError::Engine("simulated failure".to_string()))
            }

            fn deactivate(&mut self, _profile: &ConnectionProfile) -> Result<(), ActivationError> {
                Ok(())
            }
        }

        let backend = FakeBackend::default().with_wifi_interface(
            2,
            "wlan0",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        );
        let mut daemon = Daemon::with_engine(backend, Box::new(FailingEngine));
        daemon.create_profile(open_profile("home")).unwrap();

        let device = daemon.devices().unwrap().remove(0);
        assert!(matches!(
            daemon.activate(&device).unwrap_err(),
            ActivationError::Engine(_)
        ));
        assert!(matches!(
            daemon.connection_events().last(),
            Some(crate::connection::state::ConnectionEvent::Failed { .. })
        ));
    }

    #[test]
    fn daemon_reports_unsupported_activation_without_pretense() {
        let backend = FakeBackend::default().with_wifi_interface(
            2,
            "wlan0",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        );
        let mut daemon = Daemon::new(backend);
        daemon.create_profile(open_profile("home")).unwrap();

        let device = daemon.devices().unwrap().remove(0);
        let err = daemon.activate(&device).unwrap_err();
        assert!(matches!(err, ActivationError::Engine(_)));
        assert_eq!(
            daemon.active_connections()[0].state,
            ConnectionState::Failed
        );
    }
}
