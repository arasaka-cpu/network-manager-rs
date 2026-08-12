//! Test support for the D-Bus facade.
//!
//! The facade is exercised over a peer-to-peer [`zbus`] connection pair instead
//! of a message bus, so every test is deterministic and needs no external
//! services. A configurable [`FakeBackend`] drives the daemon state the facade
//! renders.

// Test scaffolding is intentionally built ahead of the tests that consume it.
#![allow(dead_code)]

use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use zbus::blocking::connection::Builder as ConnectionBuilder;
use zbus::blocking::{Connection, Proxy};

use crate::authorization::Authorization;
use crate::connection::activation::{ActivationEngine, ActivationError};
use crate::connection::device::DeviceInfo;
use crate::connection::ip::ActivationOutcome;
use crate::connection::profile::ConnectionProfile;
use crate::daemon::{Daemon, NetworkBackend};
use crate::linux::model::{
    AccessPoint, AccessPointSecurity, Address, Bssid, InterfaceType, Link, LinkFlags, NetlinkError,
    NetworkEvent, NetworkEventSource, Route, Ssid, WifiBand, WifiBandId, WifiCapabilities,
    WifiCipher, WirelessInterface,
};

struct EmptyEventSource;

impl NetworkEventSource for EmptyEventSource {
    fn next_event(&mut self) -> Result<Option<NetworkEvent>, NetlinkError> {
        Ok(None)
    }
}

/// A configurable [`NetworkBackend`] for driving the facade in tests.
#[derive(Clone, Default)]
pub struct FakeBackend {
    pub links: Vec<Link>,
    pub wifi: Vec<WirelessInterface>,
    pub access_points: Vec<AccessPoint>,
}

impl FakeBackend {
    pub fn with_link(mut self, link: Link) -> Self {
        self.links.push(link);
        self
    }

    pub fn with_wifi(mut self, interface: WirelessInterface) -> Self {
        self.wifi.push(interface);
        self
    }

    pub fn with_access_point(mut self, access_point: AccessPoint) -> Self {
        self.access_points.push(access_point);
        self
    }
}

impl NetworkBackend for FakeBackend {
    fn links(&self) -> Result<Vec<Link>, NetlinkError> {
        Ok(self.links.clone())
    }

    fn addresses(&self) -> Result<Vec<Address>, NetlinkError> {
        Ok(Vec::new())
    }

    fn routes(&self) -> Result<Vec<Route>, NetlinkError> {
        Ok(Vec::new())
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

pub fn ethernet_link(index: i32, name: &str, up: bool) -> Link {
    Link {
        index,
        name: name.to_string(),
        flags: LinkFlags::from_bits(if up { 0x1 } else { 0 }),
    }
}

pub fn loopback_link(index: i32) -> Link {
    Link {
        index,
        name: "lo".to_string(),
        flags: LinkFlags::from_bits(0x1 | 0x8),
    }
}

pub fn wifi_interface(index: i32, name: &str, mac: [u8; 6]) -> WirelessInterface {
    WirelessInterface {
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
    }
}

pub fn access_point(
    bssid: [u8; 6],
    ssid: &str,
    frequency_mhz: u32,
    signal_dbm: i32,
) -> AccessPoint {
    AccessPoint {
        bssid: Some(Bssid(bssid)),
        ssid: Ssid::from_bytes(ssid.as_bytes()),
        frequency: Some(frequency_mhz),
        channel: None,
        signal_dbm: Some(signal_dbm),
        signal_unspecified: None,
        capability: Some(0x0401),
        security: AccessPointSecurity::default(),
        seen_millis_ago: Some(1000),
    }
}

/// An activation engine that installs a fixed IPv4 configuration.
///
/// The fixed values mirror what a real NetworkManager reports for a
/// `192.168.1.184/24` connection (gateway `192.168.1.1`) so D-Bus value tests
/// can lock the exact wire encoding.
#[derive(Default)]
pub struct SuccessEngine;

impl ActivationEngine for SuccessEngine {
    fn activate(
        &mut self,
        _profile: &ConnectionProfile,
        _device: &DeviceInfo,
    ) -> Result<ActivationOutcome, ActivationError> {
        let outcome = ActivationOutcome {
            ipv4: Some(crate::connection::ip::Ipv4Outcome {
                address: "192.168.1.184".parse().unwrap(),
                prefix_length: 24,
                gateway: Some("192.168.1.1".parse().unwrap()),
                dns_servers: vec!["192.168.1.1".parse().unwrap()],
                search_domains: vec!["lan".to_string()],
                source: crate::connection::ip::Ipv4Source::AutomaticDhcp,
                routes: vec![crate::linux::model::Route {
                    family: crate::linux::model::IpFamily::V4,
                    destination: IpAddr::V4("192.168.1.0".parse().unwrap()),
                    prefix_length: 24,
                    gateway: None,
                    output_interface: None,
                    metric: Some(600),
                    kind: crate::linux::model::RouteKind::Unicast,
                    scope: crate::linux::model::RouteScope::Link,
                }],
                lease: None,
            }),
            ipv6: None,
            degradation: None,
        };
        Ok(outcome)
    }

    fn deactivate(&mut self, _profile: &ConnectionProfile) -> Result<(), ActivationError> {
        Ok(())
    }
}

/// An activation engine that additionally produces a manual IPv6 outcome with
/// connected, static and default routes, mirroring what the IP engine installs
/// for a manual IPv6 profile with static routes.
#[derive(Default)]
pub struct DualStackEngine;

impl ActivationEngine for DualStackEngine {
    fn activate(
        &mut self,
        _profile: &ConnectionProfile,
        _device: &DeviceInfo,
    ) -> Result<ActivationOutcome, ActivationError> {
        let outcome = ActivationOutcome {
            ipv4: Some(crate::connection::ip::Ipv4Outcome {
                address: "192.168.1.184".parse().unwrap(),
                prefix_length: 24,
                gateway: Some("192.168.1.1".parse().unwrap()),
                dns_servers: vec!["192.168.1.1".parse().unwrap()],
                search_domains: vec!["lan".to_string()],
                source: crate::connection::ip::Ipv4Source::AutomaticDhcp,
                routes: vec![crate::linux::model::Route {
                    family: crate::linux::model::IpFamily::V4,
                    destination: IpAddr::V4("192.168.1.0".parse().unwrap()),
                    prefix_length: 24,
                    gateway: None,
                    output_interface: None,
                    metric: Some(600),
                    kind: crate::linux::model::RouteKind::Unicast,
                    scope: crate::linux::model::RouteScope::Link,
                }],
                lease: None,
            }),
            ipv6: Some(crate::connection::ip::Ipv6Outcome {
                address: Some("2001:db8:1::184".parse().unwrap()),
                prefix_length: 64,
                gateway: Some("2001:db8:1::1".parse().unwrap()),
                dns_servers: vec!["2001:db8:1::1".parse().unwrap()],
                search_domains: Vec::new(),
                routes: vec![
                    crate::linux::model::Route {
                        family: crate::linux::model::IpFamily::V6,
                        destination: IpAddr::V6("2001:db8:1::".parse().unwrap()),
                        prefix_length: 64,
                        gateway: None,
                        output_interface: None,
                        metric: None,
                        kind: crate::linux::model::RouteKind::Unicast,
                        scope: crate::linux::model::RouteScope::Link,
                    },
                    crate::linux::model::Route {
                        family: crate::linux::model::IpFamily::V6,
                        destination: IpAddr::V6("2001:db8:10::".parse().unwrap()),
                        prefix_length: 64,
                        gateway: Some(IpAddr::V6("2001:db8:1::1".parse().unwrap())),
                        output_interface: None,
                        metric: Some(100),
                        kind: crate::linux::model::RouteKind::Unicast,
                        scope: crate::linux::model::RouteScope::Link,
                    },
                    crate::linux::model::Route {
                        family: crate::linux::model::IpFamily::V6,
                        destination: IpAddr::V6("::".parse().unwrap()),
                        prefix_length: 0,
                        gateway: Some(IpAddr::V6("2001:db8:1::1".parse().unwrap())),
                        output_interface: None,
                        metric: Some(50),
                        kind: crate::linux::model::RouteKind::Unicast,
                        scope: crate::linux::model::RouteScope::Universe,
                    },
                ],
                link_local: None,
                source: crate::connection::ip::Ipv6Source::Manual,
            }),
            degradation: None,
        };
        Ok(outcome)
    }

    fn deactivate(&mut self, _profile: &ConnectionProfile) -> Result<(), ActivationError> {
        Ok(())
    }
}

/// A running facade over a peer-to-peer connection pair, plus a client end.
///
/// The `_gate` guard serializes p2p tests: each `TestServer` holds a lock for
/// its whole lifetime so at most one connection pair exists at a time. Running
/// many zbus blocking p2p connections concurrently is unreliable — the shared
/// async-io reactor occasionally fails to wake a server executor thread and a
/// method call waits forever — so the p2p suite deliberately runs alone.
pub struct TestServer {
    pub server: super::Server<FakeBackend>,
    pub client: Connection,
    _gate: MutexGuard<'static, ()>,
}

/// Guards the p2p tests against running more than one connection pair at once.
static P2P_GATE: OnceLock<Mutex<()>> = OnceLock::new();

impl TestServer {
    pub fn start(daemon: Daemon<FakeBackend>) -> zbus::Result<Self> {
        Self::start_authorized(
            daemon,
            Arc::new(crate::authorization::AllowAllAuthorization),
        )
    }

    pub fn start_authorized(
        daemon: Daemon<FakeBackend>,
        authorization: Arc<dyn Authorization>,
    ) -> zbus::Result<Self> {
        let _gate = P2P_GATE
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (server_side, client_side) = UnixStream::pair()?;
        let guid = zbus::Guid::generate();
        let server_handle = std::thread::spawn(move || {
            ConnectionBuilder::unix_stream(server_side)
                .server(guid)?
                .p2p()
                .build()
        });
        let client_conn = ConnectionBuilder::unix_stream(client_side).p2p().build()?;
        let server_conn = server_handle
            .join()
            .expect("server connection thread panics")?;
        let server = super::Server::attach_authorized(daemon, server_conn, authorization)?;
        Ok(Self {
            server,
            client: client_conn,
            _gate,
        })
    }

    pub fn proxy(&self, path: &str, interface: &str) -> zbus::Result<Proxy<'static>> {
        Proxy::new_owned(
            self.client.clone(),
            super::BUS_NAME.to_string(),
            path.to_string(),
            interface.to_string(),
        )
    }

    pub fn daemon(&self) -> MutexGuard<'_, Daemon<FakeBackend>> {
        self.server.shared.daemon()
    }
}
