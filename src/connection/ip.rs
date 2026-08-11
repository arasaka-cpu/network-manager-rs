//! IP configuration abstractions.
//!
//! This module defines the boundary between connection activation and the
//! Linux networking stack. Three traits split the concerns:
//!
//! * [`IpConfigurator`] — installs/removes addresses and routes on an
//!   interface (rtnetlink backed in production).
//! * [`DhcpClient`] — acquires and releases a DHCPv4 lease.
//! * [`DnsManager`] — owns a system DNS configuration and can remove it.
//!
//! Concrete Linux implementations live in `linux::ipconfig`, `linux::dhcp`
//! and `linux::dns`. The values produced here (leases, outcomes) are plain
//! data so higher layers can render them without knowing kernel details.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::linux::model::{NetlinkError, Route};

/// A manual IPv4 configuration to install on an interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4Config {
    pub address: Ipv4Addr,
    pub prefix_length: u8,
    pub gateway: Option<Ipv4Addr>,
}

/// A manual IPv6 configuration to install on an interface.
///
/// Automatic IPv6 ("link-local only") is intentionally not represented here:
/// in this milestone automatic IPv6 is passive observation of the link-local
/// address rather than active configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6Config {
    pub address: Ipv6Addr,
    pub prefix_length: u8,
    pub gateway: Option<Ipv6Addr>,
}

/// A request to acquire a DHCPv4 lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhcpRequest {
    pub interface_index: i32,
    pub interface_name: String,
    pub hostname: Option<String>,
    pub requested_address: Option<Ipv4Addr>,
    pub timeout: Duration,
}

/// A DHCPv4 lease obtained by the client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhcpLease {
    pub interface_index: i32,
    pub interface_name: String,
    pub address: Ipv4Addr,
    pub prefix_length: u8,
    pub netmask: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub search_domains: Vec<String>,
    pub server_identifier: Option<Ipv4Addr>,
    pub lease_seconds: Option<u32>,
    pub t1_seconds: Option<u32>,
    pub t2_seconds: Option<u32>,
}

/// A DNS configuration the daemon wants the system to use.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsConfig {
    pub search_domains: Vec<String>,
    pub servers: Vec<IpAddr>,
}

/// Opaque ownership handle returned by [`DnsManager::apply`].
///
/// The owner string is a stable daemon-owned marker (e.g. the profile id plus
/// a timestamp) used to recognise and remove exactly the configuration this
/// daemon wrote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsOwnership {
    pub owner: String,
    pub path: String,
}

/// How an IPv4 configuration was established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4Source {
    AutomaticDhcp,
    Manual,
}

impl fmt::Display for Ipv4Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AutomaticDhcp => "dhcp",
            Self::Manual => "manual",
        })
    }
}

/// How an IPv6 configuration was established.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Ipv6Source {
    #[default]
    AutomaticLinkLocal,
    Manual,
    Disabled,
}

impl fmt::Display for Ipv6Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AutomaticLinkLocal => "link-local",
            Self::Manual => "manual",
            Self::Disabled => "disabled",
        })
    }
}

/// IPv4 portion of an activation outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4Outcome {
    pub address: Ipv4Addr,
    pub prefix_length: u8,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub source: Ipv4Source,
    /// Routes installed for this connection (a default route at minimum when
    /// a gateway is configured).
    pub routes: Vec<Route>,
    /// The DHCPv4 lease backing this configuration, when it came from DHCP.
    pub lease: Option<DhcpLease>,
}

/// IPv6 portion of an activation outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6Outcome {
    /// The configured global (or manual) address, if any.
    pub address: Option<Ipv6Addr>,
    pub prefix_length: u8,
    pub gateway: Option<Ipv6Addr>,
    pub dns_servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub routes: Vec<Route>,
    /// The link-local address observed on the interface.
    pub link_local: Option<Ipv6Addr>,
    pub source: Ipv6Source,
}

/// An optional, non-fatal degradation reported alongside a successful activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Degradation {
    pub reason: String,
}

/// Everything an engine managed to configure for an activation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ActivationOutcome {
    pub ipv4: Option<Ipv4Outcome>,
    pub ipv6: Option<Ipv6Outcome>,
    pub degradation: Option<Degradation>,
}

impl ActivationOutcome {
    /// The effective DNS servers to expose to callers (manual first).
    pub fn dns_servers(&self) -> Vec<IpAddr> {
        self.ipv4
            .as_ref()
            .map(|ipv4| ipv4.dns_servers.clone())
            .unwrap_or_default()
    }

    pub fn search_domains(&self) -> Vec<String> {
        self.ipv4
            .as_ref()
            .map(|ipv4| ipv4.search_domains.clone())
            .unwrap_or_default()
    }
}

/// Address/route/DNS state the engine owns for one active connection, used to
/// tear it down again.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ActiveIpState {
    pub ipv4: Option<ActiveIpv4>,
    pub ipv6: Option<ActiveIpv6>,
    pub dns_owner: Option<DnsOwnership>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveIpv4 {
    pub interface_index: i32,
    pub address: Ipv4Addr,
    pub prefix_length: u8,
    pub lease: Option<DhcpLease>,
    pub routes: Vec<Route>,
    pub source: Ipv4Source,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ActiveIpv6 {
    pub interface_index: i32,
    pub link_local: Option<Ipv6Addr>,
    pub prefix_length: u8,
    pub routes: Vec<Route>,
    pub source: Ipv6Source,
}

/// Errors from installing or removing kernel IP state.
#[derive(Debug)]
pub enum IpConfigError {
    Netlink(NetlinkError),
    InvalidConfig(&'static str),
    Io(io::Error),
}

impl fmt::Display for IpConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Netlink(err) => write!(f, "IP configuration failed: {err}"),
            Self::InvalidConfig(msg) => write!(f, "invalid IP configuration: {msg}"),
            Self::Io(err) => write!(f, "IP configuration I/O failed: {err}"),
        }
    }
}

impl std::error::Error for IpConfigError {}

impl From<NetlinkError> for IpConfigError {
    fn from(value: NetlinkError) -> Self {
        Self::Netlink(value)
    }
}

impl From<io::Error> for IpConfigError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Errors from the DHCP client.
#[derive(Debug)]
pub enum DhcpError {
    Io(io::Error),
    MalformedPacket(&'static str),
    Timeout { interface: String },
    InvalidConfig(&'static str),
}

impl fmt::Display for DhcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "DHCP I/O failed: {err}"),
            Self::MalformedPacket(msg) => write!(f, "malformed DHCP packet: {msg}"),
            Self::Timeout { interface } => write!(f, "DHCP timed out on {interface}"),
            Self::InvalidConfig(msg) => write!(f, "invalid DHCP configuration: {msg}"),
        }
    }
}

impl std::error::Error for DhcpError {}

impl From<io::Error> for DhcpError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Errors from the DNS manager.
#[derive(Debug)]
pub enum DnsError {
    /// The DNS file is managed by something else and will not be overwritten.
    ForeignManaged { path: String },
    Io(io::Error),
    InvalidConfig(&'static str),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignManaged { path } => {
                write!(f, "refusing to manage DNS: {path} is managed by another component")
            }
            Self::Io(err) => write!(f, "DNS I/O failed: {err}"),
            Self::InvalidConfig(msg) => write!(f, "invalid DNS configuration: {msg}"),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<io::Error> for DnsError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Installs and removes addresses and routes on an interface.
///
/// Implementations must be idempotent-friendly: removing state that is not
/// present is reported as an error (never silently ignored).
pub trait IpConfigurator {
    fn configure_ipv4(&mut self, interface_index: i32, config: &Ipv4Config)
        -> Result<(), IpConfigError>;

    fn remove_ipv4(&mut self, interface_index: i32, config: &Ipv4Config) -> Result<(), IpConfigError>;

    fn configure_ipv6(&mut self, interface_index: i32, config: &Ipv6Config)
        -> Result<(), IpConfigError>;

    fn remove_ipv6(&mut self, interface_index: i32, config: &Ipv6Config) -> Result<(), IpConfigError>;

    fn add_route(&mut self, route: &Route) -> Result<(), IpConfigError>;

    fn remove_route(&mut self, route: &Route) -> Result<(), IpConfigError>;
}

/// Acquires and releases DHCPv4 leases.
pub trait DhcpClient {
    fn acquire(&mut self, request: &DhcpRequest) -> Result<DhcpLease, DhcpError>;

    fn release(&mut self, lease: &DhcpLease) -> Result<(), DhcpError>;
}

/// Applies and removes a system DNS configuration.
pub trait DnsManager {
    /// Writes `config` under the given `owner` marker and returns the ownership
    /// handle needed to remove it later.
    fn apply(&mut self, owner: &str, config: &DnsConfig) -> Result<DnsOwnership, DnsError>;

    /// Removes a previously applied DNS configuration if it is still owned by
    /// `ownership.owner`.
    fn remove(&mut self, ownership: &DnsOwnership) -> Result<(), DnsError>;
}
