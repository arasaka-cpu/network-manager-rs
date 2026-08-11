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
use std::net::{IpAddr, Ipv4Addr};

use crate::connection::ip::{
    ActivationOutcome, ActiveIpState, ActiveIpv4, ActiveIpv6, DhcpClient, DhcpError, DhcpRequest,
    DnsConfig, DnsError, DnsManager, IpConfigError, IpConfigurator, Ipv4Config, Ipv4Outcome,
    Ipv4Source, Ipv6Config, Ipv6Source,
};
use crate::connection::profile::{IpConfig, IpMethod};
use crate::linux::dhcp::Dhcpv4Client;
use crate::linux::dns::LinuxDnsManager;
use crate::linux::ipconfig::LinuxIpConfigurator;
use crate::linux::model::NetlinkError;
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

    /// Brings up the IPv4 configuration described by `ipv4` for the interface
    /// identified by `interface_index`/`interface_name`.
    ///
    /// Returns the observable [`ActivationOutcome`] (for rendering) together
    /// with the [`ActiveIpState`] the caller must keep and pass to
    /// [`LinuxIpEngine::teardown`] later.
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

        self.activate_ipv4(
            interface_index,
            interface_name,
            ipv4,
            dns_owner,
            &mut state,
            &mut outcome,
        )?;
        self.activate_ipv6(interface_index, ipv6, &mut state, &mut outcome)?;
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
                self.ip.configure_ipv4(
                    interface_index,
                    &Ipv4Config {
                        address: lease.address,
                        prefix_length: lease.prefix_length,
                        gateway: lease.gateway,
                    },
                )?;
                let dns_config = DnsConfig {
                    search_domains: lease.search_domains.clone(),
                    servers: lease
                        .dns_servers
                        .iter()
                        .map(|server| IpAddr::V4(*server))
                        .collect(),
                };
                let dns_ownership =
                    if dns_config.servers.is_empty() && dns_config.search_domains.is_empty() {
                        None
                    } else {
                        Some(self.dns.apply(dns_owner, &dns_config)?)
                    };
                state.ipv4 = Some(ActiveIpv4 {
                    interface_index,
                    address: lease.address,
                    prefix_length: lease.prefix_length,
                    lease: Some(lease.clone()),
                    routes: default_route_for(interface_index, lease.gateway),
                    source: Ipv4Source::AutomaticDhcp,
                });
                state.dns_owner = dns_ownership;
                outcome.ipv4 = Some(Ipv4Outcome {
                    address: lease.address,
                    prefix_length: lease.prefix_length,
                    gateway: lease.gateway,
                    dns_servers: dns_config.servers,
                    search_domains: dns_config.search_domains,
                    source: Ipv4Source::AutomaticDhcp,
                    routes: default_route_for(interface_index, lease.gateway),
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
                self.ip.configure_ipv4(
                    interface_index,
                    &Ipv4Config {
                        address,
                        prefix_length,
                        gateway,
                    },
                )?;
                let servers: Vec<IpAddr> = ipv4.dns_servers.clone();
                let dns_ownership = if servers.is_empty() {
                    None
                } else {
                    Some(self.dns.apply(
                        dns_owner,
                        &DnsConfig {
                            search_domains: Vec::new(),
                            servers,
                        },
                    )?)
                };
                state.ipv4 = Some(ActiveIpv4 {
                    interface_index,
                    address,
                    prefix_length,
                    lease: None,
                    routes: default_route_for(interface_index, gateway),
                    source: Ipv4Source::Manual,
                });
                state.dns_owner = dns_ownership;
                let routes = default_route_for(interface_index, gateway);
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
                let config = crate::connection::ip::Ipv6Config {
                    address: match ipv6.address {
                        Some(IpAddr::V6(address)) => address,
                        _ => {
                            return Err(IpEngineError::InvalidConfig(
                                "manual IPv6 needs a valid IPv6 address",
                            ));
                        }
                    },
                    prefix_length: ipv6.prefix_length.ok_or({
                        IpEngineError::InvalidConfig("manual IPv6 needs a prefix length")
                    })?,
                    gateway: match ipv6.gateway {
                        Some(IpAddr::V6(address)) => Some(address),
                        _ => None,
                    },
                };
                self.ip.configure_ipv6(interface_index, &config)?;
                state.ipv6 = Some(ActiveIpv6 {
                    interface_index,
                    link_local: Some(config.address),
                    prefix_length: config.prefix_length,
                    routes: Vec::new(),
                    source: crate::connection::ip::Ipv6Source::Manual,
                });
                outcome.ipv6 = Some(crate::connection::ip::Ipv6Outcome {
                    address: Some(config.address),
                    prefix_length: config.prefix_length,
                    gateway: config.gateway,
                    dns_servers: ipv6.dns_servers.clone(),
                    search_domains: Vec::new(),
                    routes: Vec::new(),
                    link_local: None,
                    source: crate::connection::ip::Ipv6Source::Manual,
                });
            }
        }
        Ok(())
    }

    /// Removes every piece of state in `state` (routes, address, lease, DNS).
    pub fn teardown(&mut self, state: &ActiveIpState) -> Result<(), IpEngineError> {
        if let Some(ownership) = &state.dns_owner {
            self.dns.remove(ownership)?;
        }
        if let Some(ipv4) = &state.ipv4 {
            for route in &ipv4.routes {
                let _ = self.ip.remove_route(route);
            }
            if let Some(lease) = &ipv4.lease {
                let _ = self.dhcp.release(lease);
            }
            self.ip.remove_ipv4(
                ipv4.interface_index,
                &Ipv4Config {
                    address: ipv4.address,
                    prefix_length: ipv4.prefix_length,
                    gateway: ipv4.routes.first().and_then(|route| match route.gateway {
                        Some(IpAddr::V4(address)) => Some(address),
                        _ => None,
                    }),
                },
            )?;
        }
        if let Some(ipv6) = &state.ipv6 {
            if let Some(address) = ipv6.link_local {
                if ipv6.source == Ipv6Source::Manual {
                    self.ip.remove_ipv6(
                        ipv6.interface_index,
                        &Ipv6Config {
                            address,
                            prefix_length: ipv6.prefix_length,
                            gateway: None,
                        },
                    )?;
                }
            }
        }
        Ok(())
    }
}

fn default_route_for(
    interface_index: i32,
    gateway: Option<Ipv4Addr>,
) -> Vec<crate::linux::model::Route> {
    use crate::linux::model::{IpFamily, RouteKind, RouteScope};
    match gateway {
        Some(gateway) => vec![crate::linux::model::Route {
            family: IpFamily::V4,
            destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_length: 0,
            gateway: Some(IpAddr::V4(gateway)),
            output_interface: Some(interface_index),
            metric: None,
            kind: RouteKind::Unicast,
            scope: RouteScope::Universe,
        }],
        None => Vec::new(),
    }
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
            self.record.borrow_mut().routes_added += 1;
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
        assert_eq!(active.routes.len(), 1);
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
        assert_eq!(record.routes_removed, 1);
        assert_eq!(record.removed.len(), 1);
        assert_eq!(record.removed[0].1.address, Ipv4Addr::new(10, 99, 0, 50));
    }
}
