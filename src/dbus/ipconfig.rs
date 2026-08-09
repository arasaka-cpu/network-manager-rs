//! The `org.freedesktop.NetworkManager.IP4Config`, `IP6Config`,
//! `DHCP4Config` and `DHCP6Config` interfaces.
//!
//! These objects render the IP configuration an engine actually installed for
//! an active connection ([`crate::connection::ip::ActivationOutcome`]). They
//! are mostly read by clients to display addresses, gateways and DNS servers.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use zbus::zvariant::{Array, OwnedValue, Str};
use zbus::interface;

use crate::connection::activation::ActiveConnectionId;
use crate::daemon::NetworkBackend;

use super::shared::Shared;

fn val_str(value: impl Into<String>) -> OwnedValue {
    OwnedValue::from(Str::from(value.into()))
}

fn val_u32(value: u32) -> OwnedValue {
    OwnedValue::from(value)
}

fn val_i32(value: i32) -> OwnedValue {
    OwnedValue::from(value)
}

fn address_entries(address: Option<IpAddr>, prefix: Option<u8>) -> Vec<HashMap<String, OwnedValue>> {
    address.map(|address| {
        let mut entry = HashMap::new();
        entry.insert("address".to_string(), val_str(address.to_string()));
        if let Some(prefix) = prefix {
            entry.insert("prefix".to_string(), val_u32(u32::from(prefix)));
        }
        entry
    }).into_iter().collect()
}

fn dns_entries(servers: &[IpAddr]) -> Vec<HashMap<String, OwnedValue>> {
    servers
        .iter()
        .map(|server| {
            let mut entry = HashMap::new();
            entry.insert("address".to_string(), val_str(server.to_string()));
            entry.insert("priority".to_string(), val_i32(0));
            entry
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

    fn outcome(&self) -> Option<crate::connection::ip::Ipv4Outcome> {
        self.shared.active_by_id(self.id).and_then(|active| active.outcome.ipv4)
    }
}

#[interface(name = "org.freedesktop.NetworkManager.IP4Config")]
impl<B: NetworkBackend + Send + Sync + 'static> Ip4ConfigIface<B> {
    #[zbus(property)]
    fn address_data(&self) -> Vec<HashMap<String, OwnedValue>> {
        self.outcome()
            .map(|ipv4| address_entries(Some(IpAddr::from(ipv4.address)), Some(ipv4.prefix_length)))
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn gateway(&self) -> String {
        self.outcome()
            .and_then(|ipv4| ipv4.gateway.map(|gateway| gateway.to_string()))
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn routes(&self) -> Vec<HashMap<String, OwnedValue>> {
        Vec::new()
    }

    #[zbus(property)]
    fn dns_data(&self) -> Vec<HashMap<String, OwnedValue>> {
        self.outcome()
            .map(|ipv4| dns_entries(&ipv4.dns_servers))
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn dns_domain(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn dns_searches(&self) -> Vec<String> {
        self.outcome()
            .map(|ipv4| ipv4.search_domains)
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn nameservers(&self) -> Vec<u32> {
        Vec::new()
    }

    #[zbus(property)]
    fn wins_servers(&self) -> Vec<u32> {
        Vec::new()
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

/// The `org.freedesktop.NetworkManager.IP6Config` interface.
pub struct Ip6ConfigIface<B> {
    shared: Arc<Shared<B>>,
    id: ActiveConnectionId,
}

impl<B: NetworkBackend + Send + Sync + 'static> Ip6ConfigIface<B> {
    pub fn new(shared: Arc<Shared<B>>, id: ActiveConnectionId) -> Self {
        Self { shared, id }
    }

    fn outcome(&self) -> Option<crate::connection::ip::Ipv6Outcome> {
        self.shared.active_by_id(self.id).and_then(|active| active.outcome.ipv6)
    }
}

#[interface(name = "org.freedesktop.NetworkManager.IP6Config")]
impl<B: NetworkBackend + Send + Sync + 'static> Ip6ConfigIface<B> {
    #[zbus(property)]
    fn address_data(&self) -> Vec<HashMap<String, OwnedValue>> {
        self.outcome()
            .and_then(|ipv6| ipv6.link_local.map(|address| address_entries(Some(IpAddr::from(address)), Some(64))))
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn gateway(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn routes(&self) -> Vec<HashMap<String, OwnedValue>> {
        Vec::new()
    }

    #[zbus(property)]
    fn dns_data(&self) -> Vec<HashMap<String, OwnedValue>> {
        Vec::new()
    }

    #[zbus(property)]
    fn dns_domain(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn dns_searches(&self) -> Vec<String> {
        Vec::new()
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
        options.insert("ip_prefix".to_string(), val_u32(u32::from(ipv4.prefix_length)));
        if let Some(gateway) = ipv4.gateway {
            options.insert("routers".to_string(), val_str(gateway.to_string()));
        }
        if !ipv4.dns_servers.is_empty() {
            let servers = ipv4
                .dns_servers
                .iter()
                .map(|server| Str::from(server.to_string()))
                .collect::<Vec<_>>();
            options.insert(
                "domain_name_servers".to_string(),
                OwnedValue::try_from(Array::from(servers)).unwrap(),
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
        Self { _shared: shared, _id: id }
    }
}

#[interface(name = "org.freedesktop.NetworkManager.DHCP6Config")]
impl<B: NetworkBackend + Send + Sync + 'static> Dhcp6ConfigIface<B> {
    #[zbus(property)]
    fn options(&self) -> HashMap<String, OwnedValue> {
        HashMap::new()
    }
}
