//! Linux IP orchestration engine.
//!
//! [`LinuxIpEngine`] is the concrete component that brings IPv4 configuration
//! up and down for a connection activation. It composes the address/route
//! configurator, the DHCP client and the DNS manager into one order-important
//! flow:
//!
//! 1. resolve the interface index from the device name,
//! 2. obtain an address either from DHCP (`IpMethod::Automatic`) or from the
//!    profile (`IpMethod::Manual`),
//! 3. install the address and default route,
//! 4. apply the effective DNS configuration,
//! 5. hand back an [`ActiveIpState`] that can tear everything down again.
//!
//! The engine is generic over the three trait boundaries so unit tests can
//! inject scripted implementations; the default type parameters bind the real
//! Linux backends used in production.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::connection::ip::{
    ActivationOutcome, ActiveIpState, ActiveIpv4, ActiveIpv6, DhcpClient, DhcpError, DhcpRequest,
    DnsConfig, DnsError, DnsManager, IpConfigError, IpConfigurator, Ipv4Config, Ipv4Outcome,
    Ipv4Source, Ipv6Config, Ipv6Outcome, Ipv6Source,
};
use crate::connection::profile::{IpConfig, IpMethod};
use crate::linux::dhcp::Dhcpv4Client;
use crate::linux::dns::LinuxDnsManager;
use crate::linux::ipconfig::LinuxIpConfigurator;
use crate::linux::model::{IpFamily, NetlinkError, Route, RouteKind, RouteScope};
use crate::linux::netlink::{get_addresses, get_links};

/// Resolves a network interface's kernel index from its name.
pub fn resolve_interface_index(interface_name: &str) -> Result<i32, IpEngineError> {
    get_links()?
        .into_iter()
        .find(|link| link.name == interface_name)
        .map(|link| link.index)
        .ok_or_else(|| IpEngineError::InterfaceNotFound(interface_name.to_string()))
}

/// The link-local IPv6 address the kernel assigned to an interface, if any.
fn link_local_address(interface_index: i32) -> Option<std::net::Ipv6Addr> {
    get_addresses()
        .ok()?
        .into_iter()
        .find(|address| {
            address.interface_index == interface_index as u32
                && matches!(address.address, IpAddr::V6(address) if address.is_unicast_link_local())
        })
        .and_then(|address| match address.address {
            IpAddr::V6(address) => Some(address),
            _ => None,
        })
}

/// Errors from orchestrating IP configuration.
#[derive(Debug)]
pub enum IpEngineError {
    Netlink(NetlinkError),
    IpConfig(IpConfigError),
    Dhcp(DhcpError),
    Dns(DnsError),
    InvalidConfig(&'static str),
    InterfaceNotFound(String),
}

impl fmt::Display for IpEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Netlink(err) => write!(f, "netlink: {err}"),
            Self::IpConfig(err) => write!(f, "{err}"),
            Self::Dhcp(err) => write!(f, "dhcp: {err}"),
            Self::Dns(err) => write!(f, "{err}"),
            Self::InvalidConfig(msg) => write!(f, "invalid IP configuration: {msg}"),
            Self::InterfaceNotFound(name) => {
                write!(f, "no network interface named {name:?} is present")
            }
        }
    }
}

impl std::error::Error for IpEngineError {}

impl From<NetlinkError> for IpEngineError {
    fn from(value: NetlinkError) -> Self {
        Self::Netlink(value)
    }
}

impl From<IpConfigError> for IpEngineError {
    fn from(value: IpConfigError) -> Self {
        Self::IpConfig(value)
    }
}

impl From<DhcpError> for IpEngineError {
    fn from(value: DhcpError) -> Self {
        Self::Dhcp(value)
    }
}

impl From<DnsError> for IpEngineError {
    fn from(value: DnsError) -> Self {
        Self::Dns(value)
    }
}

/// Brings IPv4 configuration up and down for one connection activation.
#[derive(Debug)]
pub struct LinuxIpEngine<C = LinuxIpConfigurator, D = Dhcpv4Client, N = LinuxDnsManager> {
    ip: C,
    dhcp: D,
    dns: N,
}

impl LinuxIpEngine {
    pub fn new() -> Self {
        Self {
            ip: LinuxIpConfigurator::new(),
            dhcp: Dhcpv4Client::default(),
            dns: LinuxDnsManager::default(),
        }
    }
}

impl Default for LinuxIpEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: IpConfigurator, D: DhcpClient, N: DnsManager> LinuxIpEngine<C, D, N> {
    /// Creates an engine from explicit components (used by tests and the
    /// daemon when it wants to inject non-default backends).
    pub fn with_components(ip: C, dhcp: D, dns: N) -> Self {
        Self { ip, dhcp, dns }
    }

    /// Brings up the IPv4 and IPv6 configuration described by `ipv4`/`ipv6`
    /// for the interface identified by `interface_index`/`interface_name`.
    ///
    /// Returns the observable [`ActivationOutcome`] (for rendering) together
    /// with the [`ActiveIpState`] the caller must keep and pass to
    /// [`LinuxIpEngine::teardown`] later.
    ///
    /// Activation is all-or-nothing: if the IPv6 phase fails after IPv4 state
    /// was applied, everything installed so far (addresses, routes, DNS, the
    /// DHCP lease) is torn down before the error is returned.
    pub fn activate(
        &mut self,
        interface_index: i32,
        interface_name: &str,
        ipv4: &IpConfig,
        ipv6: &IpConfig,
        dns_owner: &str,
    ) -> Result<(ActivationOutcome, ActiveIpState), IpEngineError> {
        let mut state = ActiveIpState::default();
        let mut outcome = ActivationOutcome::default();
        let result = self
            .activate_ipv4(
                interface_index,
                interface_name,
                ipv4,
                dns_owner,
                &mut state,
                &mut outcome,
            )
            .and_then(|_| self.activate_ipv6(interface_index, ipv6, &mut state, &mut outcome));
        if let Err(error) = result {
            let _ = self.teardown(&state);
            return Err(error);
        }
        Ok((outcome, state))
    }

    fn activate_ipv4(
        &mut self,
        interface_index: i32,
        interface_name: &str,
        ipv4: &IpConfig,
        dns_owner: &str,
        state: &mut ActiveIpState,
        outcome: &mut ActivationOutcome,
    ) -> Result<(), IpEngineError> {
        match ipv4.method {
            IpMethod::Disabled => return Ok(()),
            IpMethod::Automatic => {
                let lease = self.dhcp.acquire(&DhcpRequest {
                    interface_index,
                    interface_name: interface_name.to_string(),
                    hostname: None,
                    requested_address: None,
                    timeout: std::time::Duration::default(),
                })?;
                let static_routes = ipv4_static_routes(ipv4);
                let mut routes = ipv4_routes_for(
                    interface_index,
                    lease.address,
                    lease.prefix_length,
                    lease.gateway,
                );
                routes.extend(static_routes.iter().cloned());
                state.ipv4 = Some(ActiveIpv4 {
                    interface_index,
                    address: lease.address,
                    prefix_length: lease.prefix_length,
                    lease: Some(lease.clone()),
                    routes: routes.clone(),
                    source: Ipv4Source::AutomaticDhcp,
                });
                let dns_config = DnsConfig {
                    search_domains: lease.search_domains.clone(),
                    servers: lease
                        .dns_servers
                        .iter()
                        .map(|server| IpAddr::V4(*server))
                        .collect(),
                };
                let config = Ipv4Config {
                    address: lease.address,
                    prefix_length: lease.prefix_length,
                    gateway: lease.gateway,
                };
                (|| -> Result<(), IpEngineError> {
                    self.ip.configure_ipv4(interface_index, &config)?;
                    self.install_routes(&static_routes)?;
                    let dns_ownership =
                        if dns_config.servers.is_empty() && dns_config.search_domains.is_empty() {
                            None
                        } else {
                            Some(self.dns.apply(dns_owner, &dns_config)?)
                        };
                    state.dns_owner = dns_ownership;
                    Ok(())
                })()?;
                outcome.ipv4 = Some(Ipv4Outcome {
                    address: lease.address,
                    prefix_length: lease.prefix_length,
                    gateway: lease.gateway,
                    dns_servers: dns_config.servers,
                    search_domains: dns_config.search_domains,
                    source: Ipv4Source::AutomaticDhcp,
                    routes,
                    lease: Some(lease),
                });
            }
            IpMethod::Manual => {
                let address = ipv4
                    .address
                    .and_then(|address| match address {
                        IpAddr::V4(address) => Some(address),
                        IpAddr::V6(_) => None,
                    })
                    .ok_or({
                        IpEngineError::InvalidConfig("manual IPv4 needs a valid IPv4 address")
                    })?;
                let prefix_length = ipv4.prefix_length.ok_or(IpEngineError::InvalidConfig(
                    "manual IPv4 needs a prefix length",
                ))?;
                let gateway = ipv4.gateway.and_then(|gateway| match gateway {
                    IpAddr::V4(address) => Some(address),
                    IpAddr::V6(_) => None,
                });
                let static_routes = ipv4_static_routes(ipv4);
                let mut routes = ipv4_routes_for(interface_index, address, prefix_length, gateway);
                routes.extend(static_routes.iter().cloned());
                state.ipv4 = Some(ActiveIpv4 {
                    interface_index,
                    address,
                    prefix_length,
                    lease: None,
                    routes: routes.clone(),
                    source: Ipv4Source::Manual,
                });
                let config = Ipv4Config {
                    address,
                    prefix_length,
                    gateway,
                };
                (|| -> Result<(), IpEngineError> {
                    self.ip.configure_ipv4(interface_index, &config)?;
                    self.install_routes(&static_routes)?;
                    let servers: Vec<IpAddr> = ipv4.dns_servers.clone();
                    if !servers.is_empty() {
                        state.dns_owner = Some(self.dns.apply(
                            dns_owner,
                            &DnsConfig {
                                search_domains: Vec::new(),
                                servers,
                            },
                        )?);
                    }
                    Ok(())
                })()?;
                outcome.ipv4 = Some(Ipv4Outcome {
                    address,
                    prefix_length,
                    gateway,
                    dns_servers: ipv4.dns_servers.clone(),
                    search_domains: Vec::new(),
                    source: Ipv4Source::Manual,
                    routes,
                    lease: None,
                });
            }
        }
        Ok(())
    }

    fn activate_ipv6(
        &mut self,
        interface_index: i32,
        ipv6: &IpConfig,
        state: &mut ActiveIpState,
        outcome: &mut ActivationOutcome,
    ) -> Result<(), IpEngineError> {
        match ipv6.method {
            IpMethod::Disabled => outcome.ipv6 = None,
            IpMethod::Automatic => {
                let link_local = link_local_address(interface_index);
                outcome.ipv6 = Some(crate::connection::ip::Ipv6Outcome {
                    address: None,
                    prefix_length: 64,
                    gateway: None,
                    dns_servers: Vec::new(),
                    search_domains: Vec::new(),
                    routes: Vec::new(),
                    link_local,
                    source: crate::connection::ip::Ipv6Source::AutomaticLinkLocal,
                });
            }
            IpMethod::Manual => {
                let address = match ipv6.address {
                    Some(IpAddr::V6(address)) => address,
                    _ => {
                        return Err(IpEngineError::InvalidConfig(
                            "manual IPv6 needs a valid IPv6 address",
                        ));
                    }
                };
                let prefix_length = ipv6.prefix_length.ok_or(IpEngineError::InvalidConfig(
                    "manual IPv6 needs a prefix length",
                ))?;
                let gateway = match ipv6.gateway {
                    Some(IpAddr::V6(address)) => Some(address),
                    _ => None,
                };
                let config = Ipv6Config {
                    address,
                    prefix_length,
                    gateway,
                };
                let static_routes = ipv6_static_routes(ipv6);
                let mut routes = ipv6_routes_for(interface_index, address, prefix_length, gateway);
                routes.extend(static_routes.iter().cloned());
                state.ipv6 = Some(ActiveIpv6 {
                    interface_index,
                    link_local: Some(address),
                    prefix_length,
                    routes: routes.clone(),
                    source: Ipv6Source::Manual,
                });
                (|| -> Result<(), IpEngineError> {
                    self.ip.configure_ipv6(interface_index, &config)?;
                    self.install_routes(&static_routes)?;
                    Ok(())
                })()?;
                outcome.ipv6 = Some(Ipv6Outcome {
                    address: Some(address),
                    prefix_length,
                    gateway,
                    dns_servers: ipv6.dns_servers.clone(),
                    search_domains: Vec::new(),
                    routes,
                    link_local: None,
                    source: Ipv6Source::Manual,
                });
            }
        }
        Ok(())
    }

    /// Installs each route the caller's profile requested, one at a time.
    fn install_routes(&mut self, routes: &[Route]) -> Result<(), IpEngineError> {
        for route in routes {
            self.ip.add_route(route)?;
        }
        Ok(())
    }

    /// Removes every piece of state in `state` (routes, addresses, lease, DNS).
    ///
    /// Every step is attempted even when an earlier step fails; the first
    /// error is returned once all steps have run. Removal of routes and the
    /// lease is best-effort (a route may already be gone), while address and
    /// DNS removal errors are reported.
    pub fn teardown(&mut self, state: &ActiveIpState) -> Result<(), IpEngineError> {
        let mut first_error: Option<IpEngineError> = None;
        if let Some(ownership) = &state.dns_owner {
            if let Err(error) = self.dns.remove(ownership) {
                first_error = first_error.or(Some(IpEngineError::Dns(error)));
            }
        }
        if let Some(ipv4) = &state.ipv4 {
            for route in &ipv4.routes {
                let _ = self.ip.remove_route(route);
            }
            if let Some(lease) = &ipv4.lease {
                let _ = self.dhcp.release(lease);
            }
            let gateway = ipv4.routes.iter().find_map(|route| match route.gateway {
                Some(IpAddr::V4(address)) => Some(address),
                _ => None,
            });
            if let Err(error) = self.ip.remove_ipv4(
                ipv4.interface_index,
                &Ipv4Config {
                    address: ipv4.address,
                    prefix_length: ipv4.prefix_length,
                    gateway,
                },
            ) {
                first_error = first_error.or(Some(IpEngineError::IpConfig(error)));
            }
        }
        if let Some(ipv6) = &state.ipv6 {
            for route in &ipv6.routes {
                let _ = self.ip.remove_route(route);
            }
            if ipv6.source == Ipv6Source::Manual {
                if let Some(address) = ipv6.link_local {
                    if let Err(error) = self.ip.remove_ipv6(
                        ipv6.interface_index,
                        &Ipv6Config {
                            address,
                            prefix_length: ipv6.prefix_length,
                            gateway: None,
                        },
                    ) {
                        first_error = first_error.or(Some(IpEngineError::IpConfig(error)));
                    }
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

/// The network address of `address` for the given prefix.
fn network_address_v4(address: Ipv4Addr, prefix_length: u8) -> Ipv4Addr {
    let bits = u32::from_be_bytes(address.octets());
    let mask = if prefix_length == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_length).min(32))
    };
    Ipv4Addr::from((bits & mask).to_be_bytes())
}

/// The network address of `address` for the given prefix.
fn network_address_v6(address: Ipv6Addr, prefix_length: u8) -> Ipv6Addr {
    let bits = u128::from_be_bytes(address.octets());
    let mask = if prefix_length == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_length).min(128))
    };
    Ipv6Addr::from((bits & mask).to_be_bytes())
}

/// The connected route the kernel installs for an address (`net/prefix dev`).
fn connected_route_v4(interface_index: i32, address: Ipv4Addr, prefix_length: u8) -> Route {
    Route {
        family: IpFamily::V4,
        destination: IpAddr::V4(network_address_v4(address, prefix_length)),
        prefix_length,
        gateway: None,
        output_interface: Some(interface_index),
        metric: None,
        kind: RouteKind::Unicast,
        scope: RouteScope::Link,
    }
}

/// The connected route the kernel installs for an address (`net/prefix dev`).
fn connected_route_v6(interface_index: i32, address: Ipv6Addr, prefix_length: u8) -> Route {
    Route {
        family: IpFamily::V6,
        destination: IpAddr::V6(network_address_v6(address, prefix_length)),
        prefix_length,
        gateway: None,
        output_interface: Some(interface_index),
        metric: None,
        kind: RouteKind::Unicast,
        scope: RouteScope::Link,
    }
}

/// The IPv4 default route through `gateway`.
fn default_route_v4(interface_index: i32, gateway: Ipv4Addr) -> Route {
    Route {
        family: IpFamily::V4,
        destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        prefix_length: 0,
        gateway: Some(IpAddr::V4(gateway)),
        output_interface: Some(interface_index),
        metric: None,
        kind: RouteKind::Unicast,
        scope: RouteScope::Universe,
    }
}

/// The IPv6 default route through `gateway`.
fn default_route_v6(interface_index: i32, gateway: Ipv6Addr) -> Route {
    Route {
        family: IpFamily::V6,
        destination: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        prefix_length: 0,
        gateway: Some(IpAddr::V6(gateway)),
        output_interface: Some(interface_index),
        metric: None,
        kind: RouteKind::Unicast,
        scope: RouteScope::Universe,
    }
}

/// The connected and default routes an IPv4 configuration implies.
fn ipv4_routes_for(
    interface_index: i32,
    address: Ipv4Addr,
    prefix_length: u8,
    gateway: Option<Ipv4Addr>,
) -> Vec<Route> {
    let mut routes = vec![connected_route_v4(interface_index, address, prefix_length)];
    if let Some(gateway) = gateway {
        routes.push(default_route_v4(interface_index, gateway));
    }
    routes
}

/// The connected and default routes an IPv6 configuration implies.
fn ipv6_routes_for(
    interface_index: i32,
    address: Ipv6Addr,
    prefix_length: u8,
    gateway: Option<Ipv6Addr>,
) -> Vec<Route> {
    let mut routes = vec![connected_route_v6(interface_index, address, prefix_length)];
    if let Some(gateway) = gateway {
        routes.push(default_route_v6(interface_index, gateway));
    }
    routes
}

/// The static routes a manual IPv4 configuration actually installs.
///
/// Only routes whose family matches the configuration are honoured: a v6 route
/// placed in `ipv4.routes` is a profile authoring mistake and is ignored rather
/// than being installed on the wrong address family.
fn ipv4_static_routes(config: &IpConfig) -> Vec<Route> {
    config
        .routes
        .iter()
        .filter(|route| route.family == IpFamily::V4)
        .cloned()
        .collect()
}

/// The static routes a manual IPv6 configuration actually installs.
fn ipv6_static_routes(config: &IpConfig) -> Vec<Route> {
    config
        .routes
        .iter()
        .filter(|route| route.family == IpFamily::V6)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::ip::{DnsOwnership, Ipv4Config};
    use crate::linux::model::Route;
    use std::cell::RefCell;
    use std::rc::Rc;

    // --- Scripted backends with shared recording state --------------------

    #[derive(Default)]
    struct Recording {
        configured: Vec<(i32, Ipv4Config)>,
        removed: Vec<(i32, Ipv4Config)>,
        routes_added: usize,
        routes_removed: usize,
        acquire_count: usize,
        released: Vec<String>,
        dns_applied: Vec<String>,
        dns_removed: Vec<String>,
        fail_configure: bool,
        fail_acquire: bool,
        fail_route_at: Option<usize>,
    }

    #[derive(Clone, Default)]
    struct FakeIpConfigurator {
        record: Rc<RefCell<Recording>>,
    }

    impl IpConfigurator for FakeIpConfigurator {
        fn configure_ipv4(
            &mut self,
            interface_index: i32,
            config: &Ipv4Config,
        ) -> Result<(), IpConfigError> {
            let mut record = self.record.borrow_mut();
            if record.fail_configure {
                return Err(IpConfigError::InvalidConfig("simulated"));
            }
            record.configured.push((interface_index, config.clone()));
            Ok(())
        }

        fn remove_ipv4(
            &mut self,
            interface_index: i32,
            config: &Ipv4Config,
        ) -> Result<(), IpConfigError> {
            self.record
                .borrow_mut()
                .removed
                .push((interface_index, config.clone()));
            Ok(())
        }

        fn configure_ipv6(
            &mut self,
            _interface_index: i32,
            _config: &crate::connection::ip::Ipv6Config,
        ) -> Result<(), IpConfigError> {
            Ok(())
        }

        fn remove_ipv6(
            &mut self,
            _interface_index: i32,
            _config: &crate::connection::ip::Ipv6Config,
        ) -> Result<(), IpConfigError> {
            Ok(())
        }

        fn add_route(&mut self, _route: &Route) -> Result<(), IpConfigError> {
            let mut record = self.record.borrow_mut();
            if record.fail_route_at == Some(record.routes_added + 1) {
                return Err(IpConfigError::InvalidConfig("simulated route failure"));
            }
            record.routes_added += 1;
            Ok(())
        }

        fn remove_route(&mut self, _route: &Route) -> Result<(), IpConfigError> {
            self.record.borrow_mut().routes_removed += 1;
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct FakeDhcpClient {
        record: Rc<RefCell<Recording>>,
    }

    impl DhcpClient for FakeDhcpClient {
        fn acquire(
            &mut self,
            request: &DhcpRequest,
        ) -> Result<crate::connection::ip::DhcpLease, DhcpError> {
            let mut record = self.record.borrow_mut();
            if record.fail_acquire {
                return Err(DhcpError::Timeout {
                    interface: request.interface_name.clone(),
                });
            }
            record.acquire_count += 1;
            Ok(crate::connection::ip::DhcpLease {
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

        fn release(&mut self, lease: &crate::connection::ip::DhcpLease) -> Result<(), DhcpError> {
            self.record
                .borrow_mut()
                .released
                .push(lease.interface_name.clone());
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct FakeDnsManager {
        record: Rc<RefCell<Recording>>,
    }

    impl DnsManager for FakeDnsManager {
        fn apply(&mut self, owner: &str, _config: &DnsConfig) -> Result<DnsOwnership, DnsError> {
            self.record.borrow_mut().dns_applied.push(owner.to_string());
            Ok(DnsOwnership {
                owner: owner.to_string(),
                path: "/etc/resolv.conf".to_string(),
            })
        }

        fn remove(&mut self, ownership: &DnsOwnership) -> Result<(), DnsError> {
            self.record
                .borrow_mut()
                .dns_removed
                .push(ownership.owner.clone());
            Ok(())
        }
    }

    /// A test harness bundling the engine with its shared recording state.
    struct Harness {
        engine: LinuxIpEngine<FakeIpConfigurator, FakeDhcpClient, FakeDnsManager>,
        record: Rc<RefCell<Recording>>,
    }

    impl Harness {
        fn new() -> Self {
            let record = Rc::new(RefCell::new(Recording::default()));
            let engine = LinuxIpEngine::with_components(
                FakeIpConfigurator {
                    record: record.clone(),
                },
                FakeDhcpClient {
                    record: record.clone(),
                },
                FakeDnsManager {
                    record: record.clone(),
                },
            );
            Self { engine, record }
        }
    }

    fn automatic_config() -> IpConfig {
        IpConfig {
            method: IpMethod::Automatic,
            ..IpConfig::default()
        }
    }

    fn manual_config() -> IpConfig {
        IpConfig {
            method: IpMethod::Manual,
            address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            prefix_length: Some(24),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            dns_servers: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            routes: Vec::new(),
        }
    }

    fn disabled_config() -> IpConfig {
        IpConfig {
            method: IpMethod::Disabled,
            ..IpConfig::default()
        }
    }

    #[test]
    fn automatic_activation_acquires_dhcp_installs_address_route_and_dns() {
        let mut harness = Harness::new();
        let (outcome, state) = harness
            .engine
            .activate(
                1,
                "veth0",
                &automatic_config(),
                &IpConfig::default(),
                "profile-dhcp",
            )
            .unwrap();

        let record = harness.record.borrow();
        assert_eq!(record.acquire_count, 1);
        assert_eq!(record.configured.len(), 1);
        assert_eq!(record.configured[0].1.address, Ipv4Addr::new(10, 99, 0, 50));
        assert_eq!(record.dns_applied, vec!["profile-dhcp"]);

        let ipv4 = outcome.ipv4.expect("automatic outcome has ipv4");
        assert_eq!(ipv4.address, Ipv4Addr::new(10, 99, 0, 50));
        assert_eq!(ipv4.gateway, Some(Ipv4Addr::new(10, 99, 0, 1)));
        assert_eq!(
            ipv4.dns_servers,
            vec![IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1))]
        );
        assert_eq!(ipv4.search_domains, vec!["nmd.test"]);
        assert_eq!(ipv4.source, Ipv4Source::AutomaticDhcp);

        let active = state.ipv4.unwrap();
        assert_eq!(active.interface_index, 1);
        assert!(active.lease.is_some());
        assert_eq!(active.routes.len(), 2, "connected and default route");
        assert!(state.dns_owner.is_some());
    }

    #[test]
    fn manual_activation_installs_static_address_and_dns() {
        let mut harness = Harness::new();
        let (outcome, state) = harness
            .engine
            .activate(
                1,
                "eth0",
                &manual_config(),
                &IpConfig::default(),
                "profile-manual",
            )
            .unwrap();

        let record = harness.record.borrow();
        assert_eq!(record.acquire_count, 0, "manual mode never runs DHCP");
        assert_eq!(record.configured.len(), 1);
        assert_eq!(record.configured[0].1.address, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(record.dns_applied, vec!["profile-manual"]);

        let ipv4 = outcome.ipv4.unwrap();
        assert_eq!(ipv4.source, Ipv4Source::Manual);
        assert_eq!(ipv4.address, Ipv4Addr::new(10, 0, 0, 5));
        assert!(state.ipv4.unwrap().lease.is_none());
    }

    #[test]
    fn manual_activation_without_address_is_rejected_before_kernel_changes() {
        let mut harness = Harness::new();
        let config = IpConfig {
            method: IpMethod::Manual,
            ..IpConfig::default()
        };
        let err = harness
            .engine
            .activate(1, "eth0", &config, &IpConfig::default(), "profile-manual")
            .unwrap_err();
        assert!(matches!(err, IpEngineError::InvalidConfig(_)));
        assert!(harness.record.borrow().configured.is_empty());
    }

    #[test]
    fn disabled_method_changes_nothing() {
        let mut harness = Harness::new();
        let (outcome, state) = harness
            .engine
            .activate(
                1,
                "eth0",
                &disabled_config(),
                &IpConfig::default(),
                "profile-off",
            )
            .unwrap();
        assert!(outcome.ipv4.is_none());
        assert!(state.ipv4.is_none());
        assert!(state.dns_owner.is_none());
        assert!(harness.record.borrow().configured.is_empty());
    }

    #[test]
    fn dhcp_failure_propagates_and_changes_nothing() {
        let mut harness = Harness::new();
        harness.record.borrow_mut().fail_acquire = true;
        let err = harness
            .engine
            .activate(
                1,
                "eth0",
                &automatic_config(),
                &IpConfig::default(),
                "profile-dhcp",
            )
            .unwrap_err();
        assert!(matches!(err, IpEngineError::Dhcp(_)));
        assert!(harness.record.borrow().configured.is_empty());
        assert!(harness.record.borrow().dns_applied.is_empty());
    }

    #[test]
    fn teardown_reverses_everything_in_order() {
        let mut harness = Harness::new();
        let (_, state) = harness
            .engine
            .activate(
                1,
                "veth0",
                &automatic_config(),
                &IpConfig::default(),
                "profile-dhcp",
            )
            .unwrap();
        harness.engine.teardown(&state).unwrap();

        let record = harness.record.borrow();
        assert_eq!(record.dns_removed, vec!["profile-dhcp"]);
        assert_eq!(record.released, vec!["veth0"]);
        assert_eq!(record.routes_removed, 2, "connected and default route");
        assert_eq!(record.removed.len(), 1);
        assert_eq!(record.removed[0].1.address, Ipv4Addr::new(10, 99, 0, 50));
    }

    fn static_route_v4(
        destination: Ipv4Addr,
        prefix_length: u8,
        gateway: Ipv4Addr,
        metric: u32,
    ) -> Route {
        Route {
            family: IpFamily::V4,
            destination: IpAddr::V4(destination),
            prefix_length,
            gateway: Some(IpAddr::V4(gateway)),
            output_interface: None,
            metric: Some(metric),
            kind: RouteKind::Unicast,
            scope: RouteScope::Universe,
        }
    }

    fn static_route_v6(
        destination: Ipv6Addr,
        prefix_length: u8,
        gateway: Ipv6Addr,
        metric: u32,
    ) -> Route {
        Route {
            family: IpFamily::V6,
            destination: IpAddr::V6(destination),
            prefix_length,
            gateway: Some(IpAddr::V6(gateway)),
            output_interface: None,
            metric: Some(metric),
            kind: RouteKind::Unicast,
            scope: RouteScope::Universe,
        }
    }

    #[test]
    fn manual_activation_installs_and_reports_the_static_routes() {
        let mut harness = Harness::new();
        let static_10 = static_route_v4(
            Ipv4Addr::new(10, 10, 0, 0),
            16,
            Ipv4Addr::new(10, 0, 0, 1),
            100,
        );
        let static_172 = static_route_v4(
            Ipv4Addr::new(172, 16, 0, 0),
            12,
            Ipv4Addr::new(10, 0, 0, 1),
            200,
        );
        let config = IpConfig {
            method: IpMethod::Manual,
            address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            prefix_length: Some(24),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            routes: vec![static_10.clone(), static_172.clone()],
            ..IpConfig::default()
        };
        let (outcome, state) = harness
            .engine
            .activate(1, "eth0", &config, &IpConfig::default(), "profile-manual")
            .unwrap();

        assert_eq!(harness.record.borrow().routes_added, 2);
        let ipv4 = outcome.ipv4.unwrap();
        assert!(ipv4.routes.contains(&static_10));
        assert!(ipv4.routes.contains(&static_172));
        assert_eq!(
            ipv4.routes.len(),
            4,
            "connected, default, and the two static routes"
        );
        let active = state.ipv4.as_ref().unwrap();
        assert!(active.routes.contains(&static_10));
        assert!(active.routes.contains(&static_172));

        harness.engine.teardown(&state).unwrap();
        assert_eq!(
            harness.record.borrow().routes_removed,
            4,
            "teardown removes every tracked route"
        );
    }

    #[test]
    fn automatic_activation_installs_and_reports_the_static_routes() {
        let mut harness = Harness::new();
        let static_10 = static_route_v4(
            Ipv4Addr::new(10, 10, 0, 0),
            16,
            Ipv4Addr::new(10, 99, 0, 1),
            100,
        );
        let config = IpConfig {
            method: IpMethod::Automatic,
            routes: vec![static_10.clone()],
            ..IpConfig::default()
        };
        let (outcome, _state) = harness
            .engine
            .activate(1, "veth0", &config, &IpConfig::default(), "profile-dhcp")
            .unwrap();

        assert_eq!(harness.record.borrow().routes_added, 1);
        let ipv4 = outcome.ipv4.unwrap();
        assert!(ipv4.routes.contains(&static_10));
        assert_eq!(
            ipv4.routes.len(),
            3,
            "connected, default, and the static route"
        );
    }

    #[test]
    fn routes_of_the_other_family_are_ignored() {
        let mut harness = Harness::new();
        let v6_route = static_route_v6(
            "2001:db8:10::".parse().unwrap(),
            64,
            "2001:db8:1::1".parse().unwrap(),
            200,
        );
        let v4_config = IpConfig {
            method: IpMethod::Manual,
            address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            prefix_length: Some(24),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            routes: vec![v6_route.clone()],
            ..IpConfig::default()
        };
        let (outcome, state) = harness
            .engine
            .activate(
                1,
                "eth0",
                &v4_config,
                &IpConfig::default(),
                "profile-manual",
            )
            .unwrap();

        assert_eq!(
            harness.record.borrow().routes_added,
            0,
            "a v6 route in ipv4.routes is never installed"
        );
        let ipv4 = outcome.ipv4.unwrap();
        assert!(!ipv4.routes.contains(&v6_route));
        assert_eq!(ipv4.routes.len(), 2, "only connected and default route");
        let active = state.ipv4.unwrap();
        assert!(!active.routes.contains(&v6_route));
    }

    #[test]
    fn manual_ipv6_activation_installs_and_reports_the_static_routes() {
        let mut harness = Harness::new();
        let static_fd = static_route_v6(
            "fd00::".parse().unwrap(),
            8,
            "2001:db8:1::1".parse().unwrap(),
            100,
        );
        let v4_route = static_route_v4(
            Ipv4Addr::new(10, 10, 0, 0),
            16,
            Ipv4Addr::new(10, 0, 0, 1),
            100,
        );
        let v6_config = IpConfig {
            method: IpMethod::Manual,
            address: Some("2001:db8:1::2".parse().unwrap()),
            prefix_length: Some(64),
            gateway: Some("2001:db8:1::1".parse().unwrap()),
            routes: vec![static_fd.clone(), v4_route.clone()],
            ..IpConfig::default()
        };
        let (outcome, state) = harness
            .engine
            .activate(
                1,
                "eth0",
                &IpConfig {
                    method: IpMethod::Disabled,
                    ..IpConfig::default()
                },
                &v6_config,
                "profile-manual",
            )
            .unwrap();

        assert_eq!(
            harness.record.borrow().routes_added,
            1,
            "only the v6 route is installed from ipv6.routes"
        );
        let ipv6 = outcome.ipv6.unwrap();
        assert!(ipv6.routes.contains(&static_fd));
        assert!(!ipv6.routes.contains(&v4_route));
        assert_eq!(
            ipv6.routes.len(),
            3,
            "connected, default, and the static route"
        );

        harness.engine.teardown(&state).unwrap();
        assert_eq!(harness.record.borrow().routes_removed, 3);
    }

    #[test]
    fn a_failed_static_route_rolls_back_everything() {
        let mut harness = Harness::new();
        let static_10 = static_route_v4(
            Ipv4Addr::new(10, 10, 0, 0),
            16,
            Ipv4Addr::new(10, 0, 0, 1),
            100,
        );
        let static_bad = static_route_v4(
            Ipv4Addr::new(10, 30, 0, 0),
            16,
            Ipv4Addr::new(10, 200, 0, 1),
            100,
        );
        let config = IpConfig {
            method: IpMethod::Manual,
            address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            prefix_length: Some(24),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            routes: vec![static_10.clone(), static_bad.clone()],
            ..IpConfig::default()
        };
        harness.record.borrow_mut().fail_route_at = Some(2);

        let err = harness
            .engine
            .activate(
                1,
                "eth0",
                &config,
                &IpConfig {
                    method: IpMethod::Disabled,
                    ..IpConfig::default()
                },
                "profile-manual",
            )
            .unwrap_err();
        assert!(matches!(err, IpEngineError::IpConfig(_)));

        let record = harness.record.borrow();
        assert_eq!(
            record.routes_added, 1,
            "the failing route is the second add_route call"
        );
        assert_eq!(
            record.routes_removed, 4,
            "rollback attempts to remove every tracked route exactly once"
        );
        assert_eq!(record.removed.len(), 1, "the configured address is removed");
        assert!(
            record.dns_applied.is_empty(),
            "DNS is never applied on failure"
        );
    }
}
