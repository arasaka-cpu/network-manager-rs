//! End-to-end DHCPv4 integration harness (Rust-native).
//!
//! This replaces `scripts/integration-netns.sh`. It sets up the exact topology
//! the shell script uses -- two isolated network namespaces joined by a veth
//! pair, with the crate's own DHCP test server on one end and the real DHCP
//! client + IP engine on the other -- but performs every setup step through
//! kernel interfaces instead of shelling out to `ip`/`netns`/`sysctl`:
//!
//! * `unshare(2)` creates the namespaces,
//! * `mount(2)` privatizes mounts and installs a disposable `tmpfs` over `/etc`
//!   (and fresh `/proc` + `/sys` views per namespace),
//! * raw rtnetlink fabricates the veth pair, brings interfaces up and moves
//!   the client end into the client namespace.
//!
//! The client half runs in a re-executed child process (a single process
//! cannot be in two network namespaces at once), mirroring `ip netns exec`.
//!
//! Run as root:
//!
//! ```text
//! sudo cargo test --test integration_netns
//! ```
//!
//! Unprivileged runs skip the test: creating a network namespace needs
//! `CAP_SYS_ADMIN`.

mod client;
mod dhcp_server;
mod routes;
mod sys;

use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use network_manager_rs::connection::ip::{IpConfigurator, Ipv4Config};
use network_manager_rs::linux::ip_engine::resolve_interface_index;
use network_manager_rs::linux::ipconfig::LinuxIpConfigurator;

use dhcp_server::ServerEvent;
use sys::{
    bring_link_up, create_veth_pair, disable_rp_filter, enter_private_netns, make_mounts_private,
    mount_fresh_proc_and_sysfs, mount_tmpfs_over_etc, move_link_to_pid,
};

const CLIENT_IFACE: &str = "nmdc0";
const SERVER_IFACE: &str = "nmds0";
const SERVER_IP: Ipv4Addr = dhcp_server::SERVER_ADDRESS;

/// Custom harness entry point (`harness = false` in Cargo.toml).
///
/// With no arguments this runs the integration test in the current process
/// (the "server" namespace). With `client-helper` it is the re-executed child
/// that performs the DHCP client work inside the "client" namespace.
fn main() {
    if std::env::args().any(|arg| arg == "client-helper") {
        client::run();
        return;
    }
    if let Err(err) = run_integration_test() {
        eprintln!("INTEGRATION NETNS TEST FAILED: {err}");
        std::process::exit(1);
    }
    println!("INTEGRATION NETNS TEST PASSED");
}

fn run_integration_test() -> Result<(), Box<dyn std::error::Error>> {
    if let Err(err) = enter_private_netns() {
        eprintln!("skipping: cannot create a network namespace ({err}); run as root");
        return Ok(());
    }
    make_mounts_private()?;
    mount_fresh_proc_and_sysfs()?;
    mount_tmpfs_over_etc()?;

    // The "server" namespace owns both ends initially; the client end is moved
    // into the child's namespace below.
    create_veth_pair(CLIENT_IFACE, SERVER_IFACE)?;
    let server_index = resolve_interface_index(SERVER_IFACE)?;
    let client_index = resolve_interface_index(CLIENT_IFACE)?;
    bring_link_up(server_index)?;
    bring_link_up(resolve_interface_index("lo")?)?;

    let mut ip = LinuxIpConfigurator::new();
    ip.configure_ipv4(
        server_index,
        &Ipv4Config {
            address: SERVER_IP,
            prefix_length: 24,
            gateway: None,
        },
    )?;
    disable_rp_filter(SERVER_IFACE)?;

    // The crate's own test server sits on the far end of the virtual cable and
    // records every message it observes.
    let (events_tx, events_rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let server_thread = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            dhcp_server::run(SERVER_IFACE, events_tx, stop, Duration::from_secs(120))
        })
    };
    match events_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(ServerEvent::Listening) => {}
        Ok(other) => return Err(format!("unexpected early server event: {other:?}").into()),
        Err(_) => return Err("dhcp server never started listening".into()),
    }

    // Spawn the client half in its own namespace, then hand the client veth
    // end to it. The child signals READY only after `unshare(CLONE_NEWNET)`.
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .arg("client-helper")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;
    let mut lines = BufReader::new(child.stdout.take().expect("child stdout is piped")).lines();
    match lines.next() {
        Some(Ok(line)) if line == "READY" => {}
        other => {
            let _ = child.kill();
            return Err(format!("child did not reach READY: {other:?}").into());
        }
    }
    move_link_to_pid(client_index, child.id())?;

    // Drain the child's report until it exits.
    let mut report = Vec::new();
    for line in lines {
        report.push(line?);
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(format!("client helper exited with {status}").into());
    }
    let client_mac = report
        .iter()
        .find_map(|line| line.strip_prefix("MAC ").map(str::to_string))
        .ok_or("client helper never reported its MAC")?;
    if !report.iter().any(|line| line == "CLIENT OK") {
        return Err("client helper did not report CLIENT OK".into());
    }
    let expected_mac = parse_mac(&client_mac);

    // The server must have seen one DISCOVER/REQUEST pair per client phase,
    // all from the client veth's own MAC.
    stop.store(true, Ordering::Relaxed);
    if let Err(error) = server_thread.join() {
        return Err(format!("dhcp server thread panicked: {error:?}").into());
    }
    let observed = dhcp_server::collect_until_shutdown(&events_rx, Duration::from_secs(1));
    let discovers = observed
        .iter()
        .filter(|event| matches!(event, ServerEvent::Discover { .. }))
        .count();
    let requests = observed
        .iter()
        .filter(|event| matches!(event, ServerEvent::Request { .. }))
        .count();
    assert!(
        discovers >= 2,
        "both phases DISCOVER (observed {discovers})"
    );
    assert!(requests >= 2, "both phases REQUEST (observed {requests})");
    for event in observed.iter().filter(|event| {
        matches!(
            event,
            ServerEvent::Discover { .. } | ServerEvent::Request { .. }
        )
    }) {
        match event {
            ServerEvent::Discover {
                xid,
                mac,
                requested_addr,
            } => {
                assert_eq!(*mac, expected_mac, "client MAC must identify the lease");
                assert!(*xid != 0, "transaction id must be nonzero");
                assert_eq!(
                    *requested_addr, None,
                    "the DISCOVER must not ask for a specific address"
                );
            }
            ServerEvent::Request {
                xid,
                mac,
                requested_addr,
            } => {
                assert_eq!(*mac, expected_mac, "client MAC must identify the lease");
                assert!(*xid != 0, "transaction id must be nonzero");
                assert_eq!(
                    *requested_addr,
                    Some(dhcp_server::OFFERED_ADDRESS),
                    "the REQUEST echoes the offered address (RFC 2131 section 4.3.2)"
                );
            }
            _ => unreachable!("filtered above"),
        }
    }
    routes::run_all()?;
    Ok(())
}

/// Parses a sysfs MAC address (e.g. `02:00:00:00:00:01`) into bytes.
fn parse_mac(input: &str) -> [u8; 6] {
    let bytes: Vec<u8> = input
        .trim()
        .split(':')
        .map(|part| u8::from_str_radix(part, 16).expect("MAC octet must be hex"))
        .collect();
    bytes.try_into().expect("MAC must have six octets")
}
