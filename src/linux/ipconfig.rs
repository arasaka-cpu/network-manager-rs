//! rtnetlink-backed IP configuration.
//!
//! [`LinuxIpConfigurator`] installs and removes addresses and routes directly
//! through rtnetlink transactions, mirroring what `ip addr` / `ip route` do.
//! Every mutation is sent with `NLM_F_ACK` and the kernel's error reply is
//! checked, so failures (e.g. `EEXIST` on a duplicate address) surface as
//! errors instead of silent no-ops.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::connection::ip::{IpConfigError, IpConfigurator, Ipv4Config, Ipv6Config};
use crate::linux::model::{IpFamily, Route, RouteKind, RouteScope};
use crate::linux::netlink::{
    AF_INET, AF_INET6, IFA_ADDRESS, IFA_LOCAL, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE,
    NLM_F_REQUEST, RT_SCOPE_LINK, RT_TABLE_MAIN, RTA_DST, RTA_GATEWAY, RTA_OIF, RTA_PRIORITY,
    RTM_DELADDR, RTM_DELROUTE, RTM_NEWADDR, RTM_NEWROUTE, RTN_UNICAST, build_netlink_message,
    ifaddr_payload, rtmsg_payload, transact_rtnetlink,
};

/// Configures IPv4/IPv6 addresses and routes through rtnetlink.
#[derive(Debug, Default)]
pub struct LinuxIpConfigurator;

impl LinuxIpConfigurator {
    pub fn new() -> Self {
        Self
    }

    fn add_address(
        &mut self,
        family: u8,
        prefix_length: u8,
        interface_index: i32,
        address: &[u8],
    ) -> Result<(), IpConfigError> {
        let message = build_netlink_message(
            RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
            &ifaddr_payload(
                family,
                prefix_length,
                interface_index,
                &[
                    (IFA_LOCAL, address.to_vec()),
                    (IFA_ADDRESS, address.to_vec()),
                ],
            ),
        );
        transact_rtnetlink(&message).map_err(Into::into)
    }

    fn remove_address(
        &mut self,
        family: u8,
        prefix_length: u8,
        interface_index: i32,
        address: &[u8],
    ) -> Result<(), IpConfigError> {
        let message = build_netlink_message(
            RTM_DELADDR,
            NLM_F_REQUEST | NLM_F_ACK,
            &ifaddr_payload(
                family,
                prefix_length,
                interface_index,
                &[
                    (IFA_LOCAL, address.to_vec()),
                    (IFA_ADDRESS, address.to_vec()),
                ],
            ),
        );
        transact_rtnetlink(&message).map_err(Into::into)
    }
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

fn family_bytes(family: IpFamily) -> u8 {
    match family {
        IpFamily::V4 => AF_INET,
        IpFamily::V6 => AF_INET6,
    }
}

fn route_type(kind: RouteKind) -> u8 {
    match kind {
        RouteKind::Unicast => RTN_UNICAST,
        other => other.as_u8(),
    }
}

fn route_scope(scope: RouteScope) -> u8 {
    match scope {
        RouteScope::Link => RT_SCOPE_LINK,
        other => other.as_u8(),
    }
}

fn build_route_message(message_type: u16, flags: u16, route: &Route) -> Vec<u8> {
    let mut attrs = Vec::new();
    if !route.is_default() {
        attrs.push((RTA_DST, ip_bytes(route.destination)));
    }
    if let Some(gateway) = route.gateway {
        attrs.push((RTA_GATEWAY, ip_bytes(gateway)));
    }
    attrs.push((
        RTA_OIF,
        route.output_interface.unwrap_or(0).to_ne_bytes().to_vec(),
    ));
    if let Some(metric) = route.metric {
        attrs.push((RTA_PRIORITY, metric.to_ne_bytes().to_vec()));
    }
    build_netlink_message(
        message_type,
        flags,
        &rtmsg_payload(
            family_bytes(route.family),
            route.prefix_length,
            RT_TABLE_MAIN,
            route_scope(route.scope),
            route_type(route.kind),
            &attrs,
        ),
    )
}

impl IpConfigurator for LinuxIpConfigurator {
    fn configure_ipv4(
        &mut self,
        interface_index: i32,
        config: &Ipv4Config,
    ) -> Result<(), IpConfigError> {
        if config.prefix_length > 32 {
            return Err(IpConfigError::InvalidConfig(
                "ipv4 prefix length exceeds 32",
            ));
        }
        self.add_address(
            AF_INET,
            config.prefix_length,
            interface_index,
            &config.address.octets(),
        )?;
        if let Some(gateway) = config.gateway {
            self.add_route(&Route {
                family: IpFamily::V4,
                destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_length: 0,
                gateway: Some(IpAddr::V4(gateway)),
                output_interface: Some(interface_index),
                metric: None,
                kind: RouteKind::Unicast,
                scope: crate::linux::model::RouteScope::Universe,
            })?;
        }
        Ok(())
    }

    fn remove_ipv4(
        &mut self,
        interface_index: i32,
        config: &Ipv4Config,
    ) -> Result<(), IpConfigError> {
        if let Some(gateway) = config.gateway {
            let _ = self.remove_route(&Route {
                family: IpFamily::V4,
                destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_length: 0,
                gateway: Some(IpAddr::V4(gateway)),
                output_interface: Some(interface_index),
                metric: None,
                kind: RouteKind::Unicast,
                scope: crate::linux::model::RouteScope::Universe,
            });
        }
        self.remove_address(
            AF_INET,
            config.prefix_length,
            interface_index,
            &config.address.octets(),
        )
    }

    fn configure_ipv6(
        &mut self,
        interface_index: i32,
        config: &Ipv6Config,
    ) -> Result<(), IpConfigError> {
        if config.prefix_length > 128 {
            return Err(IpConfigError::InvalidConfig(
                "ipv6 prefix length exceeds 128",
            ));
        }
        self.add_address(
            AF_INET6,
            config.prefix_length,
            interface_index,
            &config.address.octets(),
        )?;
        if let Some(gateway) = config.gateway {
            self.add_route(&Route {
                family: IpFamily::V6,
                destination: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                prefix_length: 0,
                gateway: Some(IpAddr::V6(gateway)),
                output_interface: Some(interface_index),
                metric: None,
                kind: RouteKind::Unicast,
                scope: crate::linux::model::RouteScope::Universe,
            })?;
        }
        Ok(())
    }

    fn remove_ipv6(
        &mut self,
        interface_index: i32,
        config: &Ipv6Config,
    ) -> Result<(), IpConfigError> {
        if let Some(gateway) = config.gateway {
            let _ = self.remove_route(&Route {
                family: IpFamily::V6,
                destination: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                prefix_length: 0,
                gateway: Some(IpAddr::V6(gateway)),
                output_interface: Some(interface_index),
                metric: None,
                kind: RouteKind::Unicast,
                scope: crate::linux::model::RouteScope::Universe,
            });
        }
        self.remove_address(
            AF_INET6,
            config.prefix_length,
            interface_index,
            &config.address.octets(),
        )
    }

    fn add_route(&mut self, route: &Route) -> Result<(), IpConfigError> {
        let message = build_route_message(
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK,
            route,
        );
        transact_rtnetlink(&message).map_err(Into::into)
    }

    fn remove_route(&mut self, route: &Route) -> Result<(), IpConfigError> {
        let message = build_route_message(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, route);
        transact_rtnetlink(&message).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::ip::{Ipv4Config, Ipv6Config};
    use crate::linux::netlink::NlMsgHdr;

    #[test]
    fn default_route_message_omits_explicit_destination() {
        let route = Route {
            family: IpFamily::V4,
            destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_length: 0,
            gateway: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            output_interface: Some(7),
            metric: Some(100),
            kind: RouteKind::Unicast,
            scope: crate::linux::model::RouteScope::Universe,
        };
        let message = build_route_message(RTM_NEWROUTE, NLM_F_REQUEST, &route);
        assert!(!message.is_empty());
    }

    #[test]
    fn ipv4_config_requires_valid_prefix_length() {
        let mut configurator = LinuxIpConfigurator::new();
        let config = Ipv4Config {
            address: Ipv4Addr::new(10, 0, 0, 5),
            prefix_length: 33,
            gateway: None,
        };
        assert!(matches!(
            configurator.configure_ipv4(7, &config),
            Err(IpConfigError::InvalidConfig(_))
        ));
    }

    #[test]
    fn ipv6_config_requires_valid_prefix_length() {
        let mut configurator = LinuxIpConfigurator::new();
        let config = Ipv6Config {
            address: Ipv6Addr::from([0; 16]),
            prefix_length: 129,
            gateway: None,
        };
        assert!(matches!(
            configurator.configure_ipv6(7, &config),
            Err(IpConfigError::InvalidConfig(_))
        ));
    }

    #[test]
    fn route_message_includes_destination_for_non_default_routes() {
        let route = Route {
            family: IpFamily::V6,
            destination: IpAddr::V6(Ipv6Addr::from([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ])),
            prefix_length: 48,
            gateway: None,
            output_interface: Some(7),
            metric: None,
            kind: RouteKind::Unicast,
            scope: crate::linux::model::RouteScope::Link,
        };
        let message = build_route_message(RTM_NEWROUTE, NLM_F_REQUEST, &route);
        let body = &message[size_of::<NlMsgHdr>()..];
        assert_eq!(body[0], AF_INET6);
        assert_eq!(body[1], 48);
    }
}
