//! Static-route scenarios for the netns harness.
//!
//! Each scenario builds a fresh veth pair, activates a manual profile through
//! the real [`LinuxIpEngine`] and rtnetlink, asserts the resulting kernel route
//! table, then tears the connection down and asserts the kernel returned to its
//! prior state (or that foreign routes survived, in the ownership scenario).
//!
//! The ground truth asserted here is the kernel's own route table as reported
//! by `RtnetlinkBackend`, not the engine's accounting: coexistence rules such
//! as "two default routes with different metrics both stay" and "a default
//! route identical to the gateway-derived one is deduplicated" are kernel
//! semantics that only a live kernel can verify. One such kernel quirk drives
//! the ownership scenario's shape: deleting a device's last IPv4 address
//! flushes every route bound to that device, so foreign routes are asserted
//! on interfaces the engine never touches.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use network_manager_rs::NetworkBackend;
use network_manager_rs::connection::ip::{IpConfigurator, Ipv4Config, Ipv6Config};
use network_manager_rs::connection::profile::{IpConfig, IpMethod};
use network_manager_rs::linux::ip_engine::{LinuxIpEngine, resolve_interface_index};
use network_manager_rs::linux::ipconfig::LinuxIpConfigurator;
use network_manager_rs::linux::model::{IpFamily, Route, RouteKind, RouteScope};
use network_manager_rs::linux::netlink::RtnetlinkBackend;

use crate::sys::{bring_link_up, create_veth_pair, disable_ipv6, disable_ipv6_dad, remove_link};

const SERVER_V4: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 50);
const SERVER_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0xff);
const CLIENT_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 2);
/// The IPv6 gateway must not be assigned to any interface here: the kernel
/// refuses a route whose gateway is a local address ("Gateway can not be a
/// local address"), unlike IPv4.
const V6_GATEWAY: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 1);

/// Runs every static-route scenario in the harness namespace, in order.
pub fn run_all() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("scenario: static-v4");
    static_v4_scenario()?;
    eprintln!("scenario: static-v6");
    static_v6_scenario()?;
    eprintln!("scenario: ownership");
    ownership_scenario()?;
    eprintln!("scenario: partial-failure");
    partial_failure_scenario()?;
    eprintln!("scenario: default-conflict");
    default_conflict_scenario()?;
    Ok(())
}

/// A veth pair with IPv6 disabled on the client end, both links up.
///
/// IPv4 scenarios want an exact route-table comparison, which the automatic
/// `fe80::/64` link-local route would pollute.
fn v4_topology(client: &str, server: &str) -> Result<(i32, i32), Box<dyn std::error::Error>> {
    create_veth_pair(client, server)?;
    disable_ipv6(client)?;
    let client_index = resolve_interface_index(client)?;
    let server_index = resolve_interface_index(server)?;
    bring_link_up(server_index)?;
    bring_link_up(client_index)?;
    bring_link_up(resolve_interface_index("lo")?)?;
    Ok((client_index, server_index))
}

/// A veth pair with DAD disabled on the client end, both links up.
fn v6_topology(client: &str, server: &str) -> Result<(i32, i32), Box<dyn std::error::Error>> {
    create_veth_pair(client, server)?;
    disable_ipv6_dad(client)?;
    let client_index = resolve_interface_index(client)?;
    let server_index = resolve_interface_index(server)?;
    bring_link_up(server_index)?;
    bring_link_up(client_index)?;
    bring_link_up(resolve_interface_index("lo")?)?;
    Ok((client_index, server_index))
}

/// Removes a scenario's veth pair (deleting either end destroys both).
fn cleanup(client_index: i32, _server_index: i32) -> Result<(), Box<dyn std::error::Error>> {
    remove_link(client_index)?;
    Ok(())
}

/// A route to install from a profile, bound to the connection's interface so
/// the kernel cannot resolve the gateway onto the server-side veth end.
fn v4_route(
    interface: i32,
    destination: Ipv4Addr,
    prefix_length: u8,
    gateway: Option<Ipv4Addr>,
    metric: Option<u32>,
) -> Route {
    Route {
        family: IpFamily::V4,
        destination: IpAddr::V4(destination),
        prefix_length,
        gateway: gateway.map(IpAddr::V4),
        output_interface: Some(interface),
        metric,
        kind: RouteKind::Unicast,
        scope: RouteScope::Universe,
    }
}

fn v6_route(
    interface: i32,
    destination: Ipv6Addr,
    prefix_length: u8,
    gateway: Option<Ipv6Addr>,
    metric: Option<u32>,
) -> Route {
    Route {
        family: IpFamily::V6,
        destination: IpAddr::V6(destination),
        prefix_length,
        gateway: gateway.map(IpAddr::V6),
        output_interface: Some(interface),
        metric,
        kind: RouteKind::Unicast,
        scope: RouteScope::Universe,
    }
}

/// The full kernel route set (any interface).
fn kernel_routes() -> Vec<Route> {
    RtnetlinkBackend::new()
        .routes()
        .expect("route dump must succeed")
}

/// The kernel route set for one interface.
fn kernel_routes_on(interface_index: i32) -> Vec<Route> {
    kernel_routes()
        .into_iter()
        .filter(|route| route.output_interface == Some(interface_index))
        .collect()
}

/// The kernel address set for one interface.
fn kernel_addresses_on(interface_index: i32) -> Vec<IpAddr> {
    RtnetlinkBackend::new()
        .addresses()
        .expect("address dump must succeed")
        .into_iter()
        .filter(|address| address.interface_index == interface_index as u32)
        .map(|address| address.address)
        .collect()
}

/// Fields that identify a route in the kernel: everything except the scope
/// (normalized by the kernel) and the output interface (uniform per filter).
#[derive(Clone, Debug, Eq, PartialEq)]
struct RouteKey {
    family: IpFamily,
    destination: IpAddr,
    prefix_length: u8,
    gateway: Option<IpAddr>,
    metric: u32,
    kind: RouteKind,
}

fn route_key(route: &Route) -> RouteKey {
    RouteKey {
        family: route.family,
        destination: route.destination,
        prefix_length: route.prefix_length,
        gateway: route.gateway,
        metric: route.metric.unwrap_or(0),
        kind: route.kind,
    }
}

fn route_sort_key(route: &Route) -> (IpFamily, IpAddr, u8, Option<IpAddr>, u32, u8) {
    let key = route_key(route);
    (
        key.family,
        key.destination,
        key.prefix_length,
        key.gateway,
        key.metric,
        key.kind.as_u8(),
    )
}

fn assert_has_route(routes: &[Route], expected: &Route) {
    assert!(
        routes
            .iter()
            .any(|route| route_key(route) == route_key(expected)),
        "kernel routes missing {expected:?}; found {routes:?}"
    );
}

fn assert_lacks_route(routes: &[Route], expected: &Route) {
    assert!(
        !routes
            .iter()
            .any(|route| route_key(route) == route_key(expected)),
        "kernel routes still contain {expected:?}: {routes:?}"
    );
}

fn assert_exact_routes(routes: &[Route], expected: &[Route]) {
    let mut actual: Vec<_> = routes.iter().map(route_sort_key).collect();
    let mut want: Vec<_> = expected.iter().map(route_sort_key).collect();
    actual.sort();
    want.sort();
    assert_eq!(actual, want, "kernel route set differs from expectation");
}

/// A manual profile default route is identical to the gateway-derived default
/// and must be deduplicated by the kernel: after activation there is exactly
/// one default route, plus the connected and two metric-ed statics.
fn static_v4_scenario() -> Result<(), Box<dyn std::error::Error>> {
    let (client_index, server_index) = v4_topology("nmrv0", "nmrs0")?;
    let mut server = LinuxIpConfigurator::new();
    server.configure_ipv4(
        server_index,
        &Ipv4Config {
            address: SERVER_V4,
            prefix_length: 24,
            gateway: None,
        },
    )?;

    let static_routes = vec![
        v4_route(
            client_index,
            Ipv4Addr::new(10, 10, 0, 0),
            16,
            Some(SERVER_V4),
            Some(100),
        ),
        v4_route(
            client_index,
            Ipv4Addr::new(172, 16, 0, 0),
            12,
            Some(SERVER_V4),
            Some(200),
        ),
        v4_route(
            client_index,
            Ipv4Addr::UNSPECIFIED,
            0,
            Some(SERVER_V4),
            None,
        ),
    ];
    let ipv4 = IpConfig {
        method: IpMethod::Manual,
        address: Some(IpAddr::V4(CLIENT_V4)),
        prefix_length: Some(24),
        gateway: Some(IpAddr::V4(SERVER_V4)),
        dns_servers: Vec::new(),
        routes: static_routes.clone(),
    };
    let ipv6 = IpConfig {
        method: IpMethod::Disabled,
        ..IpConfig::default()
    };

    let mut engine = LinuxIpEngine::new();
    let (outcome, state) = engine.activate(client_index, "nmrv0", &ipv4, &ipv6, "nmd/routes")?;
    let routes = kernel_routes_on(client_index);
    assert_exact_routes(
        &routes,
        &[
            v4_route(client_index, Ipv4Addr::new(10, 99, 0, 0), 24, None, None),
            v4_route(
                client_index,
                Ipv4Addr::UNSPECIFIED,
                0,
                Some(SERVER_V4),
                None,
            ),
            v4_route(
                client_index,
                Ipv4Addr::new(10, 10, 0, 0),
                16,
                Some(SERVER_V4),
                Some(100),
            ),
            v4_route(
                client_index,
                Ipv4Addr::new(172, 16, 0, 0),
                12,
                Some(SERVER_V4),
                Some(200),
            ),
        ],
    );
    let defaults = routes.iter().filter(|route| route.is_default()).count();
    assert_eq!(
        defaults, 1,
        "profile default must collapse into the gateway default"
    );
    assert_eq!(
        outcome
            .ipv4
            .as_ref()
            .expect("manual ipv4 outcome")
            .routes
            .len(),
        5,
        "the engine still accounts for the duplicate default it requested"
    );

    engine.teardown(&state)?;
    let after = kernel_routes_on(client_index);
    assert!(
        after.is_empty(),
        "teardown must leave the client veth with no routes: {after:?}"
    );
    cleanup(client_index, server_index)
}

/// Manual IPv6 installs the connected route, the default route through the
/// gateway, and both static routes; teardown removes the global address and
/// every route it implied (leaving only the automatic link-local state).
fn static_v6_scenario() -> Result<(), Box<dyn std::error::Error>> {
    let (client_index, server_index) = v6_topology("nmr6", "nmr6s")?;
    let mut server = LinuxIpConfigurator::new();
    server.configure_ipv6(
        server_index,
        &Ipv6Config {
            address: SERVER_V6,
            prefix_length: 64,
            gateway: None,
        },
    )?;

    let static_routes = vec![
        v6_route(
            client_index,
            Ipv6Addr::new(0x2001, 0x0db8, 0x0010, 0, 0, 0, 0, 0),
            64,
            Some(V6_GATEWAY),
            Some(200),
        ),
        v6_route(
            client_index,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            8,
            Some(V6_GATEWAY),
            Some(100),
        ),
    ];
    let ipv4 = IpConfig {
        method: IpMethod::Disabled,
        ..IpConfig::default()
    };
    let ipv6 = IpConfig {
        method: IpMethod::Manual,
        address: Some(IpAddr::V6(CLIENT_V6)),
        prefix_length: Some(64),
        gateway: Some(IpAddr::V6(V6_GATEWAY)),
        dns_servers: Vec::new(),
        routes: static_routes.clone(),
    };

    let mut engine = LinuxIpEngine::new();
    let (outcome, state) = engine.activate(client_index, "nmr6", &ipv4, &ipv6, "nmd/routes6")?;
    let routes = kernel_routes_on(client_index);
    // The kernel normalizes IPv6 metrics: connected routes get 256 and default
    // routes without an explicit priority get 1024.
    assert_has_route(
        &routes,
        &v6_route(
            client_index,
            Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0),
            64,
            None,
            Some(256),
        ),
    );
    assert_has_route(
        &routes,
        &v6_route(
            client_index,
            Ipv6Addr::UNSPECIFIED,
            0,
            Some(V6_GATEWAY),
            Some(1024),
        ),
    );
    for static_route in &static_routes {
        assert_has_route(&routes, static_route);
    }
    let defaults = routes.iter().filter(|route| route.is_default()).count();
    assert_eq!(defaults, 1, "exactly one ipv6 default route");
    assert_eq!(
        outcome
            .ipv6
            .as_ref()
            .expect("manual ipv6 outcome")
            .routes
            .len(),
        4,
        "connected + default + two statics"
    );

    engine.teardown(&state)?;
    let after = kernel_routes_on(client_index);
    assert_lacks_route(
        &after,
        &v6_route(
            client_index,
            Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0),
            64,
            None,
            Some(256),
        ),
    );
    assert_lacks_route(
        &after,
        &v6_route(
            client_index,
            Ipv6Addr::UNSPECIFIED,
            0,
            Some(V6_GATEWAY),
            Some(1024),
        ),
    );
    for static_route in &static_routes {
        assert_lacks_route(&after, static_route);
    }
    let addresses = kernel_addresses_on(client_index);
    assert!(
        !addresses.contains(&IpAddr::V6(CLIENT_V6)),
        "manual ipv6 address must be removed on teardown: {addresses:?}"
    );
    cleanup(client_index, server_index)
}

/// Routes installed by someone else survive the engine's teardown untouched.
///
/// The kernel flushes every route bound to a device when that device's last
/// IPv4 address is deleted, so a foreign route on the *same* interface cannot
/// be expected to outlive the engine's teardown. The ownership property is
/// instead checked where the kernel preserves it: a blackhole route (no
/// device) and a route on an unrelated interface must still be present, which
/// proves the engine only removes what it recorded.
fn ownership_scenario() -> Result<(), Box<dyn std::error::Error>> {
    let (client_index, server_index) = v4_topology("nmro0", "nmro1")?;
    create_veth_pair("nmro2", "nmro3")?;
    let other_index = resolve_interface_index("nmro2")?;
    bring_link_up(other_index)?;
    bring_link_up(resolve_interface_index("nmro3")?)?;

    let mut server = LinuxIpConfigurator::new();
    server.configure_ipv4(
        server_index,
        &Ipv4Config {
            address: SERVER_V4,
            prefix_length: 24,
            gateway: None,
        },
    )?;

    let foreign_blackhole = Route {
        family: IpFamily::V4,
        destination: IpAddr::V4(Ipv4Addr::new(10, 40, 0, 0)),
        prefix_length: 24,
        gateway: None,
        output_interface: None,
        metric: None,
        kind: RouteKind::Blackhole,
        scope: RouteScope::Universe,
    };
    let foreign_other_device = Route {
        family: IpFamily::V4,
        destination: IpAddr::V4(Ipv4Addr::new(10, 50, 0, 0)),
        prefix_length: 24,
        gateway: None,
        output_interface: Some(other_index),
        metric: None,
        kind: RouteKind::Unicast,
        scope: RouteScope::Link,
    };
    let mut configurator = LinuxIpConfigurator::new();
    configurator.add_route(&foreign_blackhole)?;
    configurator.add_route(&foreign_other_device)?;

    let ipv4 = IpConfig {
        method: IpMethod::Manual,
        address: Some(IpAddr::V4(CLIENT_V4)),
        prefix_length: Some(24),
        gateway: Some(IpAddr::V4(SERVER_V4)),
        dns_servers: Vec::new(),
        routes: vec![v4_route(
            client_index,
            Ipv4Addr::new(10, 10, 0, 0),
            16,
            Some(SERVER_V4),
            Some(100),
        )],
    };
    let ipv6 = IpConfig {
        method: IpMethod::Disabled,
        ..IpConfig::default()
    };

    let mut engine = LinuxIpEngine::new();
    let (_outcome, state) = engine.activate(client_index, "nmro0", &ipv4, &ipv6, "nmd/own")?;

    assert_has_route(&kernel_routes(), &foreign_blackhole);
    assert_has_route(&kernel_routes_on(other_index), &foreign_other_device);
    let routes = kernel_routes_on(client_index);
    assert_has_route(
        &routes,
        &v4_route(client_index, Ipv4Addr::new(10, 99, 0, 0), 24, None, None),
    );
    assert_has_route(
        &routes,
        &v4_route(
            client_index,
            Ipv4Addr::UNSPECIFIED,
            0,
            Some(SERVER_V4),
            None,
        ),
    );
    assert_has_route(
        &routes,
        &v4_route(
            client_index,
            Ipv4Addr::new(10, 10, 0, 0),
            16,
            Some(SERVER_V4),
            Some(100),
        ),
    );

    engine.teardown(&state)?;
    let after = kernel_routes_on(client_index);
    assert!(after.is_empty(), "client routes remain: {after:?}");
    assert_has_route(&kernel_routes(), &foreign_blackhole);
    assert_has_route(&kernel_routes_on(other_index), &foreign_other_device);

    remove_link(other_index)?;
    cleanup(client_index, server_index)
}

/// A static route whose gateway is unreachable fails activation, and the
/// exactly-once rollback leaves the interface completely clean (including the
/// static route that was already installed before the failure).
fn partial_failure_scenario() -> Result<(), Box<dyn std::error::Error>> {
    let (client_index, server_index) = v4_topology("nmrp0", "nmrp1")?;
    let mut server = LinuxIpConfigurator::new();
    server.configure_ipv4(
        server_index,
        &Ipv4Config {
            address: SERVER_V4,
            prefix_length: 24,
            gateway: None,
        },
    )?;

    let unreachable = Ipv4Addr::new(10, 200, 0, 1);
    let ipv4 = IpConfig {
        method: IpMethod::Manual,
        address: Some(IpAddr::V4(CLIENT_V4)),
        prefix_length: Some(24),
        gateway: None,
        dns_servers: Vec::new(),
        routes: vec![
            v4_route(
                client_index,
                Ipv4Addr::new(10, 10, 0, 0),
                16,
                Some(SERVER_V4),
                Some(100),
            ),
            v4_route(
                client_index,
                Ipv4Addr::new(10, 30, 0, 0),
                16,
                Some(unreachable),
                Some(100),
            ),
        ],
    };
    let ipv6 = IpConfig {
        method: IpMethod::Disabled,
        ..IpConfig::default()
    };

    let mut engine = LinuxIpEngine::new();
    let result = engine.activate(client_index, "nmrp0", &ipv4, &ipv6, "nmd/fail");
    assert!(
        result.is_err(),
        "route via unreachable gateway {unreachable} must fail activation"
    );
    let routes = kernel_routes_on(client_index);
    assert!(
        routes.is_empty(),
        "failed activation must leave no residual routes: {routes:?}"
    );
    let addresses = kernel_addresses_on(client_index);
    assert!(
        !addresses.contains(&IpAddr::V4(CLIENT_V4)),
        "failed activation must leave no residual address: {addresses:?}"
    );
    cleanup(client_index, server_index)
}

/// Default routes differing only in metric legitimately coexist in the kernel:
/// the gateway default (metric 0) plus both profile defaults stay distinct,
/// and teardown removes all three.
fn default_conflict_scenario() -> Result<(), Box<dyn std::error::Error>> {
    let (client_index, server_index) = v4_topology("nmrd0", "nmrd1")?;
    let mut server = LinuxIpConfigurator::new();
    server.configure_ipv4(
        server_index,
        &Ipv4Config {
            address: SERVER_V4,
            prefix_length: 24,
            gateway: None,
        },
    )?;

    let ipv4 = IpConfig {
        method: IpMethod::Manual,
        address: Some(IpAddr::V4(CLIENT_V4)),
        prefix_length: Some(24),
        gateway: Some(IpAddr::V4(SERVER_V4)),
        dns_servers: Vec::new(),
        routes: vec![
            v4_route(
                client_index,
                Ipv4Addr::UNSPECIFIED,
                0,
                Some(SERVER_V4),
                Some(50),
            ),
            v4_route(
                client_index,
                Ipv4Addr::UNSPECIFIED,
                0,
                Some(SERVER_V4),
                Some(100),
            ),
        ],
    };
    let ipv6 = IpConfig {
        method: IpMethod::Disabled,
        ..IpConfig::default()
    };

    let mut engine = LinuxIpEngine::new();
    let (_outcome, state) = engine.activate(client_index, "nmrd0", &ipv4, &ipv6, "nmd/conflict")?;
    let routes = kernel_routes_on(client_index);
    let mut metrics: Vec<u32> = routes
        .iter()
        .filter(|route| route.is_default())
        .map(|route| route.metric.unwrap_or(0))
        .collect();
    metrics.sort();
    assert_eq!(
        metrics,
        vec![0, 50, 100],
        "three default routes must coexist, one per metric"
    );

    engine.teardown(&state)?;
    let after = kernel_routes_on(client_index);
    assert!(
        after.is_empty(),
        "teardown must remove every default route: {after:?}"
    );
    cleanup(client_index, server_index)
}
