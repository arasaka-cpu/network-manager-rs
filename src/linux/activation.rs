//! Composite Linux activation engine.
//!
//! [`LinuxActivationEngine`] implements the connection-layer
//! [`ActivationEngine`] boundary end to end for a Linux host: it first drives
//! wpa_supplicant to bring the 802.11 link up (reusing the supplicant engine),
//! then runs the [`LinuxIpEngine`] to obtain IPv4/IPv6 configuration, and it
//! remembers the resulting [`ActiveIpState`] so deactivation tears everything
//! down again in the right order.
//!
//! If IP configuration fails after the link is up, the supplicant association
//! is rolled back so the device is not left half-configured.

use std::time::Duration;

use crate::connection::activation::{ActivationEngine, ActivationError};
use crate::connection::device::DeviceInfo;
use crate::connection::ip::{ActiveIpState, DhcpClient, DnsManager, IpConfigurator};
use crate::connection::profile::ConnectionProfile;
use crate::connection::secrets::SecretProvider;
use crate::connection::supplicant_engine::WpaSupplicantActivationEngine;
use crate::linux::dhcp::Dhcpv4Client;
use crate::linux::dns::LinuxDnsManager;
use crate::linux::ip_engine::{IpEngineError, LinuxIpEngine, resolve_interface_index};
use crate::linux::ipconfig::LinuxIpConfigurator;
use crate::linux::supplicant::SupplicantControl;

fn engine_err(err: IpEngineError) -> ActivationError {
    ActivationError::Engine(err.to_string())
}

/// A Linux activation engine: wpa_supplicant for the link, then IP.
///
/// Generic over the IP backends so tests can inject scripted ones; the
/// defaults bind the real Linux implementations.
pub struct LinuxActivationEngine<C = LinuxIpConfigurator, D = Dhcpv4Client, N = LinuxDnsManager> {
    supplicant: WpaSupplicantActivationEngine,
    ip: LinuxIpEngine<C, D, N>,
    active: Option<(String, ActiveIpState)>,
}

impl LinuxActivationEngine {
    /// Creates the engine with default Linux backends and the default
    /// association timeout.
    pub fn new(control: Box<dyn SupplicantControl>, secrets: Box<dyn SecretProvider>) -> Self {
        Self {
            supplicant: WpaSupplicantActivationEngine::new(control, secrets),
            ip: LinuxIpEngine::new(),
            active: None,
        }
    }
}

impl<C: IpConfigurator, D: DhcpClient, N: DnsManager> LinuxActivationEngine<C, D, N> {
    /// Creates the engine with a custom IP engine and association timeout.
    pub fn with_components(
        control: Box<dyn SupplicantControl>,
        secrets: Box<dyn SecretProvider>,
        ip: LinuxIpEngine<C, D, N>,
        timeout: Duration,
    ) -> Self {
        Self {
            supplicant: WpaSupplicantActivationEngine::with_timeout(control, secrets, timeout),
            ip,
            active: None,
        }
    }

    /// Deactivates the active connection, reporting the IP teardown result and
    /// attempting the supplicant disconnect regardless.
    fn rollback(&mut self, profile: &ConnectionProfile) -> Result<(), ActivationError> {
        let mut failures = Vec::new();
        if let Some((_, state)) = self.active.take() {
            if let Err(err) = self.ip.teardown(&state) {
                failures.push(err.to_string());
            }
        }
        if let Err(err) = self.supplicant.deactivate(profile) {
            failures.push(err.to_string());
        }
        match failures.len() {
            0 => Ok(()),
            1 => Err(ActivationError::Engine(failures.remove(0))),
            _ => Err(ActivationError::Engine(format!(
                "{} (and also {})",
                failures[0],
                failures[1..].join("; ")
            ))),
        }
    }
}

impl<C, D, N> ActivationEngine for LinuxActivationEngine<C, D, N>
where
    C: IpConfigurator + Send,
    D: DhcpClient + Send,
    N: DnsManager + Send,
{
    fn activate(
        &mut self,
        profile: &ConnectionProfile,
        device: &DeviceInfo,
    ) -> Result<crate::connection::ip::ActivationOutcome, ActivationError> {
        if self.active.is_some() {
            return Err(ActivationError::Engine(
                "an activation is already in progress".to_string(),
            ));
        }
        let interface_index =
            resolve_interface_index(&device.interface_name).map_err(engine_err)?;
        // Bring the 802.11 link up first; IP configuration depends on it.
        self.supplicant.activate(profile, device)?;

        let dns_owner = format!("nmd/{}/{}", profile.id, device.interface_name);
        let ip_result = self.ip.activate(
            interface_index,
            &device.interface_name,
            &profile.ipv4,
            &profile.ipv6,
            &dns_owner,
        );
        match ip_result {
            Ok((outcome, state)) => {
                self.active = Some((profile.id.clone(), state));
                Ok(outcome)
            }
            Err(err) => {
                let _ = self.supplicant.deactivate(profile);
                Err(engine_err(err))
            }
        }
    }

    fn deactivate(&mut self, profile: &ConnectionProfile) -> Result<(), ActivationError> {
        let Some((active_profile, _)) = &self.active else {
            return Err(ActivationError::Engine(
                "there is no active connection to deactivate".to_string(),
            ));
        };
        if active_profile != &profile.id {
            return Err(ActivationError::Engine(
                "the active connection belongs to a different profile".to_string(),
            ));
        }
        self.rollback(profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::device::DeviceInfo;
    use crate::connection::ip::{
        DhcpError, DhcpLease, DhcpRequest, DnsConfig, DnsError, DnsOwnership, IpConfigError,
        Ipv4Config, Ipv6Config,
    };
    use crate::connection::profile::{ConnectionProfile, WifiSecurity};
    use crate::connection::secrets::{SecretError, SecretProvider, SecretReference};
    use crate::linux::model::{Bssid, Route, Ssid};
    use crate::linux::supplicant::{SupplicantControl, SupplicantError};
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    // --- Scripted backends with shared recording state --------------------

    #[derive(Default)]
    struct Recording {
        connected: bool,
        disconnect_count: usize,
        networks_removed: usize,
        dhcp_acquire_count: usize,
        fail_dhcp: bool,
    }

    #[derive(Clone)]
    struct OkControl {
        ifname: String,
        record: Arc<Mutex<Recording>>,
    }

    impl SupplicantControl for OkControl {
        fn ifname(&self) -> &str {
            &self.ifname
        }

        fn add_network(
            &mut self,
            _ssid: &Ssid,
            _key_mgmt: &str,
            _psk: Option<&[u8]>,
            _identity: Option<&str>,
            _bssid: Option<&Bssid>,
            _hidden: bool,
        ) -> Result<String, SupplicantError> {
            Ok("/networks/1".to_string())
        }

        fn select_network(&mut self, _network_path: &str) -> Result<(), SupplicantError> {
            Ok(())
        }

        fn remove_network(&mut self, _network_path: &str) -> Result<(), SupplicantError> {
            self.record.lock().unwrap().networks_removed += 1;
            Ok(())
        }

        fn disconnect(&mut self) -> Result<(), SupplicantError> {
            self.record.lock().unwrap().disconnect_count += 1;
            self.record.lock().unwrap().connected = false;
            Ok(())
        }

        fn wait_for_completed(&mut self, _timeout: Duration) -> Result<(), SupplicantError> {
            self.record.lock().unwrap().connected = true;
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct FakeIpConfigurator;

    impl IpConfigurator for FakeIpConfigurator {
        fn configure_ipv4(
            &mut self,
            _interface_index: i32,
            _config: &Ipv4Config,
        ) -> Result<(), IpConfigError> {
            Ok(())
        }

        fn remove_ipv4(
            &mut self,
            _interface_index: i32,
            _config: &Ipv4Config,
        ) -> Result<(), IpConfigError> {
            Ok(())
        }

        fn configure_ipv6(
            &mut self,
            _interface_index: i32,
            _config: &Ipv6Config,
        ) -> Result<(), IpConfigError> {
            Ok(())
        }

        fn remove_ipv6(
            &mut self,
            _interface_index: i32,
            _config: &Ipv6Config,
        ) -> Result<(), IpConfigError> {
            Ok(())
        }

        fn add_route(&mut self, _route: &Route) -> Result<(), IpConfigError> {
            Ok(())
        }

        fn remove_route(&mut self, _route: &Route) -> Result<(), IpConfigError> {
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct FakeDhcpClient {
        record: Arc<Mutex<Recording>>,
    }

    impl DhcpClient for FakeDhcpClient {
        fn acquire(&mut self, request: &DhcpRequest) -> Result<DhcpLease, DhcpError> {
            let mut record = self.record.lock().unwrap();
            if record.fail_dhcp {
                return Err(DhcpError::Timeout {
                    interface: request.interface_name.clone(),
                });
            }
            record.dhcp_acquire_count += 1;
            Ok(DhcpLease {
                interface_index: request.interface_index,
                interface_name: request.interface_name.clone(),
                address: Ipv4Addr::new(10, 99, 0, 50),
                prefix_length: 24,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                gateway: Some(Ipv4Addr::new(10, 99, 0, 1)),
                dns_servers: vec![Ipv4Addr::new(10, 99, 0, 1)],
                search_domains: vec!["nmd.test".to_string()],
                server_identifier: Some(Ipv4Addr::new(10, 99, 0, 1)),
                lease_seconds: Some(600),
                t1_seconds: Some(300),
                t2_seconds: Some(525),
            })
        }

        fn release(&mut self, _lease: &DhcpLease) -> Result<(), DhcpError> {
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct FakeDnsManager;

    impl DnsManager for FakeDnsManager {
        fn apply(&mut self, _owner: &str, _config: &DnsConfig) -> Result<DnsOwnership, DnsError> {
            Ok(DnsOwnership {
                owner: _owner.to_string(),
                path: "/etc/resolv.conf".to_string(),
            })
        }

        fn remove(&mut self, _ownership: &DnsOwnership) -> Result<(), DnsError> {
            Ok(())
        }
    }

    /// A harness bundling the composite engine with its shared recording state.
    struct Harness {
        engine: LinuxActivationEngine<FakeIpConfigurator, FakeDhcpClient, FakeDnsManager>,
        record: Arc<Mutex<Recording>>,
    }

    impl Harness {
        fn new() -> Self {
            let record = Arc::new(Mutex::new(Recording::default()));
            let ip = LinuxIpEngine::with_components(
                FakeIpConfigurator,
                FakeDhcpClient {
                    record: record.clone(),
                },
                FakeDnsManager,
            );
            let control: Box<dyn SupplicantControl> = Box::new(OkControl {
                ifname: "lo".to_string(),
                record: record.clone(),
            });
            let engine = LinuxActivationEngine::with_components(
                control,
                Box::new(StaticProvider),
                ip,
                Duration::from_millis(1),
            );
            Self { engine, record }
        }
    }

    struct StaticProvider;

    impl SecretProvider for StaticProvider {
        fn retrieve(&self, _reference: &SecretReference) -> Result<Option<Vec<u8>>, SecretError> {
            Ok(Some(b"passphrase".to_vec()))
        }
    }

    fn wifi_profile() -> ConnectionProfile {
        ConnectionProfile::wifi(
            "home",
            "home",
            Ssid::from_bytes(b"home").unwrap(),
            WifiSecurity::open(),
        )
        .unwrap()
    }

    /// The loopback interface exists on every Linux host; the fake IP backends
    /// never touch the kernel, so observing it is safe in tests.
    fn loopback_device() -> DeviceInfo {
        DeviceInfo::wifi("lo", Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
    }

    #[test]
    fn activation_brings_up_supplicant_then_ip_and_records_state() {
        let mut harness = Harness::new();
        let profile = wifi_profile();
        let outcome = harness
            .engine
            .activate(&profile, &loopback_device())
            .unwrap();

        let record = harness.record.lock().unwrap();
        assert!(record.connected, "supplicant reached completed");
        assert_eq!(record.dhcp_acquire_count, 1, "IP ran after the link");

        let ipv4 = outcome.ipv4.expect("outcome carries ipv4");
        assert_eq!(ipv4.address, Ipv4Addr::new(10, 99, 0, 50));
        drop(record);

        harness.engine.deactivate(&profile).unwrap();
        let record = harness.record.lock().unwrap();
        assert_eq!(record.disconnect_count, 1);
        assert_eq!(record.networks_removed, 1);
    }

    #[test]
    fn ip_failure_rolls_back_the_supplicant_link() {
        let mut harness = Harness::new();
        harness.record.lock().unwrap().fail_dhcp = true;
        let profile = wifi_profile();

        let err = harness
            .engine
            .activate(&profile, &loopback_device())
            .unwrap_err();
        assert!(matches!(err, ActivationError::Engine(_)));

        let record = harness.record.lock().unwrap();
        assert_eq!(
            record.disconnect_count, 1,
            "link is torn down on IP failure"
        );
        assert_eq!(record.networks_removed, 1);
    }

    #[test]
    fn deactivation_tears_down_ip_state() {
        let mut harness = Harness::new();
        let profile = wifi_profile();
        harness
            .engine
            .activate(&profile, &loopback_device())
            .unwrap();
        harness.engine.deactivate(&profile).unwrap();

        // teardown ran: the DHCP release + route removal went through the fake
        // configurator without error, which is what teardown() calls.
        let record = harness.record.lock().unwrap();
        assert_eq!(record.disconnect_count, 1);
        drop(record);
    }

    #[test]
    fn deactivation_without_an_active_connection_errors() {
        let mut harness = Harness::new();
        let err = harness.engine.deactivate(&wifi_profile()).unwrap_err();
        assert!(matches!(err, ActivationError::Engine(_)));
    }

    #[test]
    fn second_activation_while_active_is_rejected() {
        let mut harness = Harness::new();
        let profile = wifi_profile();
        harness
            .engine
            .activate(&profile, &loopback_device())
            .unwrap();
        let err = harness
            .engine
            .activate(&profile, &loopback_device())
            .unwrap_err();
        assert!(matches!(err, ActivationError::Engine(_)));
    }

    #[test]
    fn ip_engine_error_impl_is_self_describing() {
        let err = IpEngineError::InterfaceNotFound("ghost0".to_string());
        assert!(err.to_string().contains("ghost0"));
        let err: IpEngineError =
            crate::linux::model::NetlinkError::Io(std::io::Error::other("test")).into();
        assert!(err.to_string().contains("test"));
    }
}
