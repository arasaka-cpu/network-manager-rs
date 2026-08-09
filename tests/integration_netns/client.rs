//! Client-side half of the integration harness.
//!
//! The harness re-executes its own test binary with the `client-helper`
//! argument. The helper starts in a fresh network namespace (the "client"
//! namespace, mirroring `ip netns add nmdclient`), waits for the harness to
//! move the client veth end into it, and then drives the real DHCP client and
//! the IP engine against the test server on the far end of the veth.
//!
//! Everything here runs in a separate process because `unshare(CLONE_NEWNET)`
//! affects only the calling process, not its threads.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use network_manager_rs::connection::ip::{DhcpClient, DhcpRequest, Ipv4Source};
use network_manager_rs::connection::profile::{IpConfig, IpMethod};
use network_manager_rs::linux::dhcp::Dhcpv4Client;
use network_manager_rs::linux::ip_engine::LinuxIpEngine;
use network_manager_rs::linux::model::IpFamily;
use network_manager_rs::linux::netlink::{get_addresses, get_routes};

use super::dhcp_server;
use super::sys;

const CLIENT_IFACE: &str = "nmdc0";
const PREFIX_LENGTH: u8 = 24;
const SERVER_IP: Ipv4Addr = dhcp_server::SERVER_ADDRESS;
const LEASE_IP: Ipv4Addr = dhcp_server::OFFERED_ADDRESS;
const NETMASK: Ipv4Addr = dhcp_server::NETMASK;

/// Runs the client-side phase to completion, printing a machine-readable
/// report on stdout. Any failed assertion panics (nonzero exit), which fails
/// the harness.
pub fn run() {
    enter_client_netns().expect("client namespace must be created");
    println!("READY");
    let client_index = wait_for_link(CLIENT_IFACE);
    sys::bring_link_up(client_index).expect("client veth must come up");
    sys::disable_rp_filter(CLIENT_IFACE).expect("rp_filter must be disabled on the client");

    let mac = std::fs::read_to_string(format!("/sys/class/net/{CLIENT_IFACE}/address"))
        .expect("client MAC must be readable from sysfs");
    println!("MAC {}", mac.trim());

    // Phase 1: the raw client negotiates a lease. This must NOT touch kernel
    // state -- installing addresses/routes/DNS is the IP engine's job.
    let mut client = Dhcpv4Client::default();
    let lease = client
        .acquire(&DhcpRequest {
            interface_index: client_index,
            interface_name: CLIENT_IFACE.to_string(),
            hostname: Some("nmd-integration".to_string()),
            requested_address: None,
            timeout: Duration::from_secs(10),
        })
        .expect("direct DHCP acquire must lease an address");
    assert_eq!(lease.address, LEASE_IP, "the offered address is granted");
    assert_eq!(lease.netmask, NETMASK);
    assert_eq!(lease.prefix_length, PREFIX_LENGTH);
    assert_eq!(lease.gateway, Some(SERVER_IP));
    assert_eq!(lease.dns_servers, vec![SERVER_IP]);
    assert_eq!(lease.search_domains, vec!["nmd.test".to_string()]);
    assert!(!kernel_has_lease(client_index), "negotiation alone must not touch the kernel");

    // Phase 2: the IP engine activates the connection, applying the lease.
    let mut engine = LinuxIpEngine::new();
    let (outcome, state) = engine
        .activate(
            client_index,
            CLIENT_IFACE,
            &IpConfig {
                method: IpMethod::Automatic,
                ..IpConfig::default()
            },
            &IpConfig::default(),
            "integration-auto",
        )
        .expect("IP engine auto activation must succeed");

    let ipv4 = outcome.ipv4.expect("automatic activation produces ipv4 outcome");
    assert_eq!(ipv4.address, LEASE_IP);
    assert_eq!(ipv4.prefix_length, PREFIX_LENGTH);
    assert_eq!(ipv4.gateway, Some(SERVER_IP));
    assert_eq!(ipv4.source, Ipv4Source::AutomaticDhcp);
    assert_eq!(ipv4.dns_servers, vec![IpAddr::V4(SERVER_IP)]);
    assert!(state.ipv4.is_some());
    assert!(state.dns_owner.is_some(), "engine must own the resolv.conf it wrote");
    verify_kernel_state(client_index, true);

    // Phase 3: teardown removes the address, the route and the DNS file.
    engine.teardown(&state).expect("teardown must succeed");
    verify_kernel_state(client_index, false);

    println!("CLIENT OK");
}

/// Enters a private network namespace with private mounts and fresh `/proc` /
/// `/sys` views, mirroring `ip netns add nmdclient` plus the script's mount
/// setup for `/etc`.
fn enter_client_netns() -> io::Result<()> {
    sys::enter_private_netns()?;
    sys::make_mounts_private()?;
    sys::mount_fresh_proc_and_sysfs()?;
    Ok(())
}

/// Polls until the harness moves the client veth end into this namespace.
fn wait_for_link(ifname: &str) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(links) = network_manager_rs::linux::netlink::get_links() {
            if let Some(link) = links.iter().find(|link| link.name == ifname) {
                return link.index;
            }
        }
        if Instant::now() > deadline {
            panic!("link {ifname} never appeared in the client namespace");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Asserts the lease address, the default route and `resolv.conf` are present
/// or absent exactly as `present` demands.
fn verify_kernel_state(client_index: i32, present: bool) {
    assert_eq!(
        kernel_has_lease(client_index),
        present,
        "lease address must be {}",
        if present { "installed" } else { "removed" }
    );

    let routes = get_routes().expect("route dump must succeed");
    let has_default = routes.iter().any(|route| {
        route.family == IpFamily::V4
            && route.output_interface == Some(client_index)
            && route.gateway == Some(IpAddr::V4(SERVER_IP))
    });
    assert_eq!(
        has_default,
        present,
        "default route via the server must be {}",
        if present { "installed" } else { "removed" }
    );

    let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    assert_eq!(
        resolv.contains(&format!("nameserver {SERVER_IP}")),
        present,
        "resolv.conf must be {}",
        if present { "populated" } else { "cleaned up" }
    );
}

/// Whether the lease address is installed on the client veth.
fn kernel_has_lease(client_index: i32) -> bool {
    get_addresses()
        .expect("address dump must succeed")
        .iter()
        .any(|address| {
            address.interface_index == client_index as u32
                && address.address == IpAddr::V4(LEASE_IP)
                && address.prefix_length == PREFIX_LENGTH
        })
}
