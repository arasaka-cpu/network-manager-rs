//! Acquires a DHCPv4 lease on an interface using the native client.
//!
//! `nmd_dhcp_client <ifname> [timeout_seconds]`. Prints the resulting lease,
//! or exits non-zero on failure. Designed for the netns integration test.

use std::time::Duration;

use network_manager_rs::connection::ip::{DhcpClient, DhcpRequest, IpConfigurator, Ipv4Config};
use network_manager_rs::linux::dhcp::Dhcpv4Client;
use network_manager_rs::linux::ipconfig::LinuxIpConfigurator;
use network_manager_rs::linux::netlink::get_links;

fn main() {
    let interface = std::env::args()
        .nth(1)
        .unwrap_or_else(|| {
            eprintln!("usage: nmd_dhcp_client <ifname> [timeout_seconds]");
            std::process::exit(2);
        });
    let interface_index = get_links()
        .ok()
        .and_then(|links| links.into_iter().find(|link| link.name == interface).map(|link| link.index))
        .unwrap_or(-1);
    let timeout_seconds = std::env::args()
        .nth(2)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(8);
    let request = DhcpRequest {
        interface_index,
        interface_name: interface.clone(),
        hostname: Some("nmd-test-client".to_string()),
        requested_address: None,
        timeout: Duration::from_secs(timeout_seconds),
    };
    let mut client = Dhcpv4Client::default();
    let lease = match client.acquire(&request) {
        Ok(lease) => lease,
        Err(err) => {
            eprintln!("dhcp failed: {err}");
            std::process::exit(1);
        }
    };
    println!(
        "interface={}\taddress={}/{}\tgateway={}\tdns={}\tdomain={}\tserver={}\tlease={}s",
        lease.interface_name,
        lease.address,
        lease.prefix_length,
        lease
            .gateway
            .map(|gateway| gateway.to_string())
            .unwrap_or_else(|| "-".to_string()),
        lease
            .dns_servers
            .iter()
            .map(|server| server.to_string())
            .collect::<Vec<_>>()
            .join(","),
        lease.search_domains.join(","),
        lease
            .server_identifier
            .map(|server| server.to_string())
            .unwrap_or_else(|| "-".to_string()),
        lease.lease_seconds.unwrap_or(0),
    );

    let config = Ipv4Config {
        address: lease.address,
        prefix_length: lease.prefix_length,
        gateway: lease.gateway,
    };
    let mut ip = LinuxIpConfigurator::new();
    if let Err(err) = ip.configure_ipv4(lease.interface_index, &config) {
        eprintln!("configure_ipv4 failed: {err}");
        std::process::exit(1);
    }
    println!("DHCP OK");
}
