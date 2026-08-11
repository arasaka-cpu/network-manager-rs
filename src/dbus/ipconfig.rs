//! The `org.freedesktop.NetworkManager.IP4Config`, `IP6Config`,
//! `DHCP4Config` and `DHCP6Config` interfaces.
//!
//! These objects render the IP configuration an engine actually installed for
//! an active connection ([`crate::connection::ip::ActivationOutcome`]). They
//! are mostly read by clients to display addresses, gateways, routes and DNS
//! servers. Property names and types match the NetworkManager running on the
//! host (IP4Config `Addresses`/`Routes`/`Nameservers`/`NameserverData`,
//! IP6Config `a(ayuay)` address tuples, DHCP4Config `Options` as `a{sv}`).
//!
//! Nothing is fabricated: an absent value renders as the correct empty form
//! (empty string, empty array, `0` metric), and the objects disappear when the
//! active connection they belong to is removed.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use zbus::interface;
use zbus::zvariant::{OwnedValue, Str};

use crate::connection::activation::ActiveConnectionId;
use crate::connection::ip::{Ipv4Outcome, Ipv6Outcome};
use crate::daemon::NetworkBackend;
use crate::linux::model::Route;

use super::shared::Shared;

fn val_str(value: impl Into<String>) -> OwnedValue {
    OwnedValue::from(Str::from(value.into()))
}

fn val_u32(value: u32) -> OwnedValue {
    OwnedValue::from(value)
}

/// Renders the IPv4 address as the big-endian `u32` NetworkManager uses in
/// the deprecated `Addresses`/`Nameservers` arrays.
fn ipv4_u32(address: Ipv4Addr) -> u32 {
    u32::from_be_bytes(address.octets())
}

/// Masks `address` down to its network address for the given prefix, matching
/// the destination NetworkManager reports for a connected route.
fn network_address(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let bits = u32::from_be_bytes(address.octets());
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix).min(32))
            };
            IpAddr::V4(Ipv4Addr::from((bits & mask).to_be_bytes()))
        }
        IpAddr::V6(address) => {
            let bits = u128::from_be_bytes(address.octets());
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix).min(128))
            };
            IpAddr::V6(Ipv6Addr::from((bits & mask).to_be_bytes()))
        }
    }
}

fn ipv4_route_entry(route: &Route, gateway: Option<Ipv4Addr>) -> Vec<u32> {
    let destination = match route.destination {
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    };
    let next_hop = match (route.gateway, gateway) {
        (Some(IpAddr::V4(hop)), _) => Some(hop),
        (_, Some(gateway)) => Some(gateway),
        _ => None,
    };
    vec![
        ipv4_u32(destination),
        u32::from(route.prefix_length),
        next_hop.map(ipv4_u32).unwrap_or(0),
        route.metric.unwrap_or(0),
    ]
}

fn ipv6_route_entry(route: &Route) -> (Vec<u8>, u32, Vec<u8>, u32) {
    let destination = match route.destination {
        IpAddr::V6(address) => address,
        IpAddr::V4(_) => Ipv6Addr::UNSPECIFIED,
    };
    let next_hop = match route.gateway {
        Some(IpAddr::V6(hop)) => hop,
        _ => Ipv6Addr::UNSPECIFIED,
    };
    (
        destination.octets().to_vec(),
        u32::from(route.prefix_length),
        next_hop.octets().to_vec(),
        route.metric.unwrap_or(0),
    )
}

fn route_data_entry(route: &Route) -> HashMap<String, OwnedValue> {
    let mut entry = HashMap::new();
    entry.insert(
        "dest".to_string(),
        val_str(network_address(route.destination, route.prefix_length).to_string()),
    );
    entry.insert(
        "prefix".to_string(),
        val_u32(u32::from(route.prefix_length)),
    );
    if let Some(gateway) = route.gateway {
        entry.insert("next-hop".to_string(), val_str(gateway.to_string()));
    }
    entry.insert("metric".to_string(), val_u32(route.metric.unwrap_or(0)));
    entry
}

fn v4_route_data(ipv4: &Ipv4Outcome) -> Vec<HashMap<String, OwnedValue>> {
    ipv4.routes.iter().map(route_data_entry).collect()
}

fn v6_route_data(ipv6: &Ipv6Outcome) -> Vec<HashMap<String, OwnedValue>> {
    ipv6.routes.iter().map(route_data_entry).collect()
}

fn address_entries(
    address: Option<IpAddr>,
    prefix: Option<u8>,
) -> Vec<HashMap<String, OwnedValue>> {
    address
        .map(|address| {
            let mut entry = HashMap::new();
            entry.insert("address".to_string(), val_str(address.to_string()));
            if let Some(prefix) = prefix {
                entry.insert("prefix".to_string(), val_u32(u32::from(prefix)));
            }
            entry
        })
        .into_iter()
        .collect()
}

/// Renders `NameserverData` (`aa{sv}`) for a list of IPv4 servers, matching the
/// `{address, uri}` entries NetworkManager exposes.
fn nameserver_data_v4(servers: &[IpAddr]) -> Vec<HashMap<String, OwnedValue>> {
    servers
        .iter()
        .filter_map(|server| match server {
            IpAddr::V4(address) => Some(*address),
            IpAddr::V6(_) => None,
        })
        .map(|address| {
            let mut entry = HashMap::new();
            let text = address.to_string();
            entry.insert("address".to_string(), val_str(text.clone()));
            entry.insert("uri".to_string(), val_str(text));
            entry
        })
        .collect()
}

fn dns_servers_v4(servers: &[IpAddr]) -> Vec<u32> {
    servers
        .iter()
        .filter_map(|server| match server {
            IpAddr::V4(address) => Some(ipv4_u32(*address)),
            IpAddr::V6(_) => None,
        })
        .collect()
}

fn dns_servers_v6(servers: &[IpAddr]) -> Vec<Vec<u8>> {
    servers
        .iter()
        .filter_map(|server| match server {
            IpAddr::V6(address) => Some(address.octets().to_vec()),
            IpAddr::V4(_) => None,
        })
        .collect()
}

/// The `org.freedesktop.NetworkManager.IP4Config` interface.
pub struct Ip4ConfigIface<B> {
    shared: Arc<Shared<B>>,
    id: ActiveConnectionId,
}

impl<B: NetworkBackend + Send + Sync + 'static> Ip4ConfigIface<B> {
    pub fn new(shared: Arc<Shared<B>>, id: ActiveConnectionId) -> Self {
        Self { shared, id }
    }

    fn outcome(&self) -> Option<Ipv4Outcome> {
        self.shared
            .active_by_id(self.id)
            .and_then(|active| active.outcome.ipv4)
    }
}

#[interface(name = "org.freedesktop.NetworkManager.IP4Config")]
impl<B: NetworkBackend + Send + Sync + 'static> Ip4ConfigIface<B> {
    #[zbus(property)]
    fn addresses(&self) -> Vec<Vec<u32>> {
        self.outcome()
            .map(|ipv4| {
                vec![vec![
                    ipv4_u32(ipv4.address),
                    u32::from(ipv4.prefix_length),
                    ipv4.gateway.map(ipv4_u32).unwrap_or(0),
                ]]
            })
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn address_data(&self) -> Vec<HashMap<String, OwnedValue>> {
        self.outcome()
            .map(|ipv4| address_entries(Some(IpAddr::from(ipv4.address)), Some(ipv4.prefix_length)))
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn clat_address(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn gateway(&self) -> String {
        self.outcome()
            .and_then(|ipv4| ipv4.gateway.map(|gateway| gateway.to_string()))
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn routes(&self) -> Vec<Vec<u32>> {
        self.outcome()
            .map(|ipv4| {
                ipv4.routes
                    .iter()
                    .map(|route| ipv4_route_entry(route, ipv4.gateway))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn route_data(&self) -> Vec<HashMap<String, OwnedValue>> {
        self.outcome()
            .map(|ipv4| v4_route_data(&ipv4))
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn nameserver_data(&self) -> Vec<HashMap<String, OwnedValue>> {
        self.outcome()
            .map(|ipv4| nameserver_data_v4(&ipv4.dns_servers))
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn nameservers(&self) -> Vec<u32> {
        self.outcome()
            .map(|ipv4| dns_servers_v4(&ipv4.dns_servers))
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn domains(&self) -> Vec<String> {
        Vec::new()
    }

    #[zbus(property)]
    fn searches(&self) -> Vec<String> {
        self.outcome()
            .map(|ipv4| ipv4.search_domains)
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn dns_options(&self) -> Vec<String> {
        Vec::new()
    }

    #[zbus(property)]
    fn dns_priority(&self) -> i32 {
        0
    }

    #[zbus(property)]
    fn wins_server_data(&self) -> Vec<String> {
        Vec::new()
    }

    #[zbus(property)]
    fn wins_servers(&self) -> Vec<u32> {
        Vec::new()
    }
}

/// The `org.freedesktop.NetworkManager.IP6Config` interface.
pub struct Ip6ConfigIface<B> {
    shared: Arc<Shared<B>>,
    id: ActiveConnectionId,
}

impl<B: NetworkBackend + Send + Sync + 'static> Ip6ConfigIface<B> {
    pub fn new(shared: Arc<Shared<B>>, id: ActiveConnectionId) -> Self {
        Self { shared, id }
    }

    fn outcome(&self) -> Option<Ipv6Outcome> {
        self.shared
            .active_by_id(self.id)
            .and_then(|active| active.outcome.ipv6)
    }

    /// The primary IPv6 address to report: the configured address, or the
    /// observed link-local address for automatic link-local-only operation.
    fn address(&self) -> Option<(Ipv6Addr, u8)> {
        self.outcome().and_then(|ipv6| {
            ipv6.address
                .map(|address| (address, ipv6.prefix_length))
                .or_else(|| ipv6.link_local.map(|address| (address, 64)))
        })
    }
}

#[interface(name = "org.freedesktop.NetworkManager.IP6Config")]
impl<B: NetworkBackend + Send + Sync + 'static> Ip6ConfigIface<B> {
    #[zbus(property)]
    fn addresses(&self) -> Vec<(Vec<u8>, u32, Vec<u8>)> {
        self.address()
            .map(|(address, prefix)| {
                vec![(
                    address.octets().to_vec(),
                    u32::from(prefix),
                    [0u8; 16].to_vec(),
                )]
            })
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn address_data(&self) -> Vec<HashMap<String, OwnedValue>> {
        self.address()
            .map(|(address, prefix)| address_entries(Some(IpAddr::from(address)), Some(prefix)))
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn clat_address(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn clat_pref64(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn gateway(&self) -> String {
        self.outcome()
            .and_then(|ipv6| ipv6.gateway.map(|gateway| gateway.to_string()))
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn routes(&self) -> Vec<(Vec<u8>, u32, Vec<u8>, u32)> {
        self.outcome()
            .map(|ipv6| ipv6.routes.iter().map(ipv6_route_entry).collect())
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn route_data(&self) -> Vec<HashMap<String, OwnedValue>> {
        self.outcome()
            .map(|ipv6| v6_route_data(&ipv6))
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn nameservers(&self) -> Vec<Vec<u8>> {
        self.outcome()
            .map(|ipv6| dns_servers_v6(&ipv6.dns_servers))
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn domains(&self) -> Vec<String> {
        Vec::new()
    }

    #[zbus(property)]
    fn searches(&self) -> Vec<String> {
        self.outcome()
            .map(|ipv6| ipv6.search_domains)
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn dns_options(&self) -> Vec<String> {
        Vec::new()
    }

    #[zbus(property)]
    fn dns_priority(&self) -> i32 {
        0
    }
}

/// The `org.freedesktop.NetworkManager.DHCP4Config` interface.
pub struct Dhcp4ConfigIface<B> {
    shared: Arc<Shared<B>>,
    id: ActiveConnectionId,
}

impl<B> Dhcp4ConfigIface<B> {
    pub fn new(shared: Arc<Shared<B>>, id: ActiveConnectionId) -> Self {
        Self { shared, id }
    }
}

/// IPv4 subnet mask for a prefix length, as `255.255.255.0`.
fn subnet_mask(prefix_length: u8) -> Ipv4Addr {
    let mask = if prefix_length == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_length).min(32))
    };
    Ipv4Addr::from(mask.to_be_bytes())
}

/// Broadcast address for an address/prefix pair.
fn broadcast_address(address: Ipv4Addr, prefix_length: u8) -> Ipv4Addr {
    let bits = u32::from_be_bytes(address.octets());
    let host_mask = if prefix_length == 0 {
        u32::MAX
    } else {
        (1u32 << (32 - u32::from(prefix_length).min(32))) - 1
    };
    Ipv4Addr::from((bits | host_mask).to_be_bytes())
}

#[interface(name = "org.freedesktop.NetworkManager.DHCP4Config")]
impl<B: NetworkBackend + Send + Sync + 'static> Dhcp4ConfigIface<B> {
    #[zbus(property)]
    fn options(&self) -> HashMap<String, OwnedValue> {
        let Some(active) = self.shared.active_by_id(self.id) else {
            return HashMap::new();
        };
        let Some(ipv4) = active.outcome.ipv4 else {
            return HashMap::new();
        };
        let mut options = HashMap::new();
        options.insert("ip_address".to_string(), val_str(ipv4.address.to_string()));
        options.insert(
            "ip_prefix".to_string(),
            val_u32(u32::from(ipv4.prefix_length)),
        );
        options.insert(
            "subnet_mask".to_string(),
            val_str(subnet_mask(ipv4.prefix_length).to_string()),
        );
        if let Some(gateway) = ipv4.gateway {
            options.insert("routers".to_string(), val_str(gateway.to_string()));
        }
        let v4_dns: Vec<String> = ipv4
            .dns_servers
            .iter()
            .filter_map(|server| match server {
                IpAddr::V4(address) => Some(address.to_string()),
                IpAddr::V6(_) => None,
            })
            .collect();
        if !v4_dns.is_empty() {
            options.insert("domain_name_servers".to_string(), val_str(v4_dns.join(",")));
        }
        if let Some(lease) = ipv4.lease {
            if let Some(server) = lease.server_identifier {
                options.insert(
                    "dhcp_server_identifier".to_string(),
                    val_str(server.to_string()),
                );
            }
            if let Some(lease_seconds) = lease.lease_seconds {
                options.insert(
                    "dhcp_lease_time".to_string(),
                    val_str(lease_seconds.to_string()),
                );
                let expiry = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|now| now.as_secs() + u64::from(lease_seconds))
                    .unwrap_or(0);
                options.insert("expiry".to_string(), val_str(expiry.to_string()));
            }
            options.insert(
                "broadcast_address".to_string(),
                val_str(broadcast_address(ipv4.address, ipv4.prefix_length).to_string()),
            );
        }
        options
    }
}

/// The `org.freedesktop.NetworkManager.DHCP6Config` interface.
pub struct Dhcp6ConfigIface<B> {
    _shared: Arc<Shared<B>>,
    _id: ActiveConnectionId,
}

impl<B> Dhcp6ConfigIface<B> {
    pub fn new(shared: Arc<Shared<B>>, id: ActiveConnectionId) -> Self {
        Self {
            _shared: shared,
            _id: id,
        }
    }
}

#[interface(name = "org.freedesktop.NetworkManager.DHCP6Config")]
impl<B: NetworkBackend + Send + Sync + 'static> Dhcp6ConfigIface<B> {
    #[zbus(property)]
    fn options(&self) -> HashMap<String, OwnedValue> {
        HashMap::new()
    }
}
