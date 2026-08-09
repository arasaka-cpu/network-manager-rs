//! Exercises the IP engine's full bring-up and teardown in a netns.
//!
//! `nmd_ip_engine_demo <ifname> <auto|manual>`. In `auto` mode the DHCP test
//! server must be reachable on the interface's segment. The demo verifies the
//! kernel address appears after activation and disappears after teardown,
//! then exits non-zero on any mismatch.

use std::net::{IpAddr, Ipv4Addr};

use network_manager_rs::connection::profile::{IpConfig, IpMethod};
use network_manager_rs::linux::ip_engine::{resolve_interface_index, LinuxIpEngine};
use network_manager_rs::linux::netlink::{get_addresses, get_links};

fn main() {
    let interface = std::env::args()
        .nth(1)
        .unwrap_or_else(|| {
            eprintln!("usage: nmd_ip_engine_demo <ifname> <auto|manual>");
            std::process::exit(2);
        });
    let mode = std::env::args().nth(2).unwrap_or_else(|| {
        eprintln!("usage: nmd_ip_engine_demo <ifname> <auto|manual>");
        std::process::exit(2);
    });
    let interface_index = match resolve_interface_index(&interface) {
        Ok(index) => index,
        Err(err) => {
            eprintln!("resolve failed: {err}");
            std::process::exit(1);
        }
    };

    let (ipv4, expected_address) = match mode.as_str() {
        "auto" => (
            IpConfig {
                method: IpMethod::Automatic,
                ..IpConfig::default()
            },
            Ipv4Addr::new(10, 99, 0, 50),
        ),
        "manual" => (
            IpConfig {
                method: IpMethod::Manual,
                address: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 51))),
                prefix_length: Some(24),
                gateway: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1))),
                dns_servers: vec![IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1))],
                ..IpConfig::default()
            },
            Ipv4Addr::new(10, 99, 0, 51),
        ),
        other => {
            eprintln!("unknown mode '{other}' (expected auto or manual)");
            std::process::exit(2);
        }
    };

    let mut engine = LinuxIpEngine::new();
    let (outcome, state) = match engine.activate(
        interface_index,
        &interface,
        &ipv4,
        &IpConfig {
            method: IpMethod::Disabled,
            ..IpConfig::default()
        },
        "nmd/engine-demo",
    ) {
        Ok(both) => both,
        Err(err) => {
            eprintln!("activate failed: {err}");
            std::process::exit(1);
        }
    };

    let ipv4_outcome = outcome.ipv4.expect("demo expects an ipv4 outcome");
    println!(
        "activated address={}/{} gateway={} source={}",
        ipv4_outcome.address,
        ipv4_outcome.prefix_length,
        ipv4_outcome
            .gateway
            .map(|gateway| gateway.to_string())
            .unwrap_or_else(|| "-".to_string()),
        ipv4_outcome.source
    );
    if !kernel_has_address(&interface, expected_address) {
        eprintln!("activation left no address on the interface");
        std::process::exit(1);
    }
    println!("engine demo: kernel address verified");

    if let Err(err) = engine.teardown(&state) {
        eprintln!("teardown failed: {err}");
        std::process::exit(1);
    }
    if kernel_has_address(&interface, expected_address) {
        eprintln!("teardown left the address in place");
        std::process::exit(1);
    }
    println!("engine demo: teardown verified");
    println!("IP ENGINE {mode} OK");
}

fn kernel_has_address(interface_name: &str, address: Ipv4Addr) -> bool {
    let Ok(links) = get_links() else {
        return false;
    };
    let Some(index) = links.into_iter().find(|link| link.name == interface_name) else {
        return false;
    };
    let Ok(addresses) = get_addresses() else {
        return false;
    };
    addresses
        .iter()
        .any(|entry| entry.interface_index == index.index as u32 && entry.address == IpAddr::V4(address))
}
