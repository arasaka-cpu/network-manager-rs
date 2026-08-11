//! Adds and removes an IPv4 address + default route through the rtnetlink
//! configurator, then verifies the kernel state with the read-only backend.
//!
//! `nmd_ipconfig_probe <ifname>`. Used by `scripts/integration-netns.sh` to
//! exercise `LinuxIpConfigurator` against a real kernel in an isolated netns.

use network_manager_rs::connection::ip::{IpConfigurator, Ipv4Config};
use network_manager_rs::linux::ipconfig::LinuxIpConfigurator;
use network_manager_rs::linux::netlink::{get_addresses, get_links, get_routes};

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: nmd_ipconfig_probe <ifname>");
        std::process::exit(2);
    });
    let links = get_links().unwrap_or_else(|err| {
        eprintln!("get_links failed: {err}");
        std::process::exit(1);
    });
    let Some(index) = links
        .iter()
        .find(|link| link.name == name)
        .map(|link| link.index)
    else {
        eprintln!("interface {name} not found");
        std::process::exit(1);
    };

    let config = Ipv4Config {
        address: "10.99.0.51".parse().unwrap(),
        prefix_length: 24,
        gateway: Some("10.99.0.1".parse().unwrap()),
    };

    let mut ip = LinuxIpConfigurator::new();
    if let Err(err) = ip.configure_ipv4(index, &config) {
        eprintln!("configure_ipv4 failed: {err}");
        std::process::exit(1);
    }

    let addresses = get_addresses().unwrap();
    let has_address = addresses.iter().any(|address| {
        address.interface_index == index as u32
            && address.address.to_string() == "10.99.0.51"
            && address.prefix_length == 24
    });
    let routes = get_routes().unwrap();
    let has_route = routes.iter().any(|route| {
        route.destination.is_unspecified()
            && route.gateway == Some("10.99.0.1".parse().unwrap())
            && route.output_interface == Some(index)
    });
    if !has_address || !has_route {
        eprintln!("ipconfig probe: address={has_address} route={has_route}");
        std::process::exit(1);
    }
    println!("ipconfig probe: address and route installed");

    if let Err(err) = ip.remove_ipv4(index, &config) {
        eprintln!("remove_ipv4 failed: {err}");
        std::process::exit(1);
    }
    let addresses = get_addresses().unwrap();
    let still_address = addresses.iter().any(|address| {
        address.interface_index == index as u32 && address.address.to_string() == "10.99.0.51"
    });
    let routes = get_routes().unwrap();
    let still_route = routes.iter().any(|route| {
        route.destination.is_unspecified()
            && route.gateway == Some("10.99.0.1".parse().unwrap())
            && route.output_interface == Some(index)
    });
    if still_address || still_route {
        eprintln!("ipconfig probe: cleanup incomplete address={still_address} route={still_route}");
        std::process::exit(1);
    }
    println!("ipconfig probe: cleanup verified");
    println!("IPCONFIG PROBE OK");
}
