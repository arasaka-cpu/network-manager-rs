use std::env;

use network_manager_rs::linux::model::format_mac_address;
use network_manager_rs::linux::netlink::install_sigint_shutdown_handler;
use network_manager_rs::linux::supplicant::WpaSupplicant;
use network_manager_rs::{
    AddressEventKind, Daemon, EnvSecretProvider, FileProfileStore, LinkEventKind, NetworkEvent,
    ProfileStore, RouteEventKind, RtnetlinkBackend, SupplicantControl, WifiEventKind,
    WpaSupplicantActivationEngine,
};

/// Default directory holding one TOML profile per connection.
const DEFAULT_PROFILE_DIR: &str = "/etc/network-manager-rs/profiles";

fn main() {
    if let Err(err) = run() {
        eprintln!("nmd: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        None | Some("links") => print_links(),
        Some("addresses") => print_addresses(),
        Some("routes") => print_routes(),
        Some("wifi") => match args.next().as_deref() {
            None => print_wifi(),
            Some("scan") => scan_and_print(),
            Some(other) => Err(format!("unknown wifi subcommand '{other}'").into()),
        },
        Some("connections") => print_connections(),
        Some("connect") => {
            let profile = args
                .next()
                .ok_or("usage: nmd connect <profile-id> <ifname>")?;
            let ifname = args
                .next()
                .ok_or("usage: nmd connect <profile-id> <ifname>")?;
            activate(&profile, &ifname)
        }
        Some("disconnect") => {
            let ifname = args.next().ok_or("usage: nmd disconnect <ifname>")?;
            disconnect(&ifname)
        }
        Some("monitor") => monitor(),
        Some("--help" | "-h") => {
            println!(
                "Usage: nmd [command]\n\n\
                 links                 List kernel network links (read-only)\n\
                 addresses             List kernel interface addresses (read-only)\n\
                 routes                List kernel routes (read-only)\n\
                 wifi                  List wireless interfaces (read-only)\n\
                 wifi scan             Trigger a scan and list access points (read-only)\n\
                 connections           List connection profiles (read-only)\n\
                 connect <id> <if>     Activate profile <id> on interface <if> via wpa_supplicant\n\
                 disconnect <if>       Ask wpa_supplicant to disconnect interface <if>\n\
                 monitor               Monitor link, address and scan events (read-only)"
            );
            Ok(())
        }
        Some(command) => Err(format!("unknown command '{command}'").into()),
    }
}

/// Opens the profile store used by the CLI. The directory defaults to
/// [`DEFAULT_PROFILE_DIR`] and can be overridden with `NMD_PROFILE_DIR`.
fn profile_store() -> Result<Box<dyn ProfileStore>, Box<dyn std::error::Error>> {
    let directory = env::var("NMD_PROFILE_DIR").unwrap_or_else(|_| DEFAULT_PROFILE_DIR.to_string());
    Ok(Box::new(FileProfileStore::new(directory)?))
}

fn print_links() -> Result<(), Box<dyn std::error::Error>> {
    let daemon = Daemon::new(RtnetlinkBackend::new());
    for link in daemon.links()? {
        println!(
            "{}\t{}\tflags=0x{:x}\tup={}\tloopback={}",
            link.index,
            link.name,
            link.flags.bits(),
            link.flags.is_up(),
            link.flags.is_loopback()
        );
    }
    Ok(())
}

fn print_addresses() -> Result<(), Box<dyn std::error::Error>> {
    let daemon = Daemon::new(RtnetlinkBackend::new());
    for address in daemon.addresses()? {
        println!(
            "ifindex={}\taddress={}/{}",
            address.interface_index, address.address, address.prefix_length
        );
    }
    Ok(())
}

fn print_routes() -> Result<(), Box<dyn std::error::Error>> {
    let daemon = Daemon::new(RtnetlinkBackend::new());
    for route in daemon.routes()? {
        let gateway = route
            .gateway
            .map(|gateway| gateway.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "family={}\tdestination={}/{}\tgateway={}\toif={}\tmetric={}\tkind={:?}\tscope={:?}",
            route.family,
            route.destination,
            route.prefix_length,
            gateway,
            route.output_interface.map(|oif| oif.to_string()).unwrap_or_else(|| "-".to_string()),
            route.metric.map(|metric| metric.to_string()).unwrap_or_else(|| "-".to_string()),
            route.kind,
            route.scope
        );
    }
    Ok(())
}

fn print_wifi() -> Result<(), Box<dyn std::error::Error>> {
    let daemon = Daemon::new(RtnetlinkBackend::new());
    for interface in daemon.wifi_interfaces()? {
        let mac = interface
            .mac
            .map(|mac| format_mac_address(&mac))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "ifindex={}\tname={}\twiphy={}\ttype={:?}\tmac={}\tup={}",
            interface.index,
            interface.name,
            interface.wiphy_name.as_deref().unwrap_or("-"),
            interface.interface_type,
            mac,
            interface.up
        );
    }
    Ok(())
}

fn scan_and_print() -> Result<(), Box<dyn std::error::Error>> {
    let daemon = Daemon::new(RtnetlinkBackend::new());
    let points = daemon.scan_wifi()?;
    for point in points {
        let bssid = point
            .bssid
            .map(|bssid| format_mac_address(bssid.as_bytes()))
            .unwrap_or_else(|| "-".to_string());
        let ssid = point
            .ssid
            .as_ref()
            .map(|ssid| ssid.display_string())
            .unwrap_or_else(|| "(hidden)".to_string());
        let signal = point
            .signal_dbm
            .map(|signal| signal.to_string())
            .unwrap_or_else(|| "-".to_string());
        let security = match (
            point.security.wpa1,
            point.security.wpa2,
            point.security.wpa3,
        ) {
            (true, true, _) => "wpa1+wpa2",
            (_, true, true) => "wpa2+wpa3",
            (true, _, _) => "wpa1",
            (_, true, _) => "wpa2",
            (_, _, true) => "wpa3",
            _ => {
                if point.security.wep {
                    "wep"
                } else {
                    "open"
                }
            }
        };
        println!(
            "{}\t{}\tfreq={}\tchan={}\tsignal={}dbm\tsecurity={}",
            bssid,
            ssid,
            point.frequency.unwrap_or(0),
            point
                .channel
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string()),
            signal,
            security
        );
    }
    Ok(())
}

fn print_connections() -> Result<(), Box<dyn std::error::Error>> {
    let store = profile_store()?;
    for profile in store.list()? {
        println!(
            "profile\tid={}\tname={}\ttype={}\tpriority={}\tautoconnect={}\tenabled={}",
            profile.id,
            profile.name,
            profile.connection_type,
            profile.priority,
            profile.autoconnect,
            profile.enabled
        );
    }
    Ok(())
}

/// Activates `profile` on `ifname` by driving wpa_supplicant over D-Bus.
///
/// This command changes live network state and requires access to the system
/// bus (typically root) plus a configured secret provider (see
/// [`EnvSecretProvider`]).
fn activate(profile_id: &str, ifname: &str) -> Result<(), Box<dyn std::error::Error>> {
    let control: Box<dyn SupplicantControl> = Box::new(WpaSupplicant::connect(ifname)?);
    let engine = WpaSupplicantActivationEngine::new(control, Box::new(EnvSecretProvider));
    let mut daemon =
        Daemon::with_components(RtnetlinkBackend::new(), profile_store()?, Box::new(engine));

    let device = daemon
        .devices()?
        .into_iter()
        .find(|device| device.interface_name == ifname)
        .ok_or_else(|| format!("no wireless device named {ifname:?}"))?;
    let active = daemon.activate_profile(&profile_id.to_string(), &device)?;
    println!(
        "activated id={} profile={} device={} state={:?}",
        active.id, active.profile.id, active.device.interface_name, active.state
    );
    Ok(())
}

/// Asks wpa_supplicant to disconnect `ifname` from its current network.
///
/// This changes live network state and requires access to the system bus.
fn disconnect(ifname: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut control = WpaSupplicant::connect(ifname)?;
    control.disconnect()?;
    println!("disconnected {ifname}");
    Ok(())
}

fn monitor() -> Result<(), Box<dyn std::error::Error>> {
    install_sigint_shutdown_handler();
    let daemon = Daemon::new(RtnetlinkBackend::new());
    let mut source = daemon.events()?;
    eprintln!("monitoring rtnetlink link/address events; press Ctrl-C to stop");
    while let Some(event) = Daemon::<RtnetlinkBackend>::next_event(source.as_mut())? {
        match event {
            NetworkEvent::Link(event) => {
                let action = match event.kind {
                    LinkEventKind::Created => "link-created",
                    LinkEventKind::Removed => "link-removed",
                    LinkEventKind::Changed => "link-changed",
                };
                println!(
                    "{action}\tindex={}\tname={}\tflags=0x{:x}\tup={}\tloopback={}",
                    event.link.index,
                    event.link.name,
                    event.link.flags.bits(),
                    event.link.flags.is_up(),
                    event.link.flags.is_loopback()
                );
            }
            NetworkEvent::Address(event) => {
                let action = match event.kind {
                    AddressEventKind::Added => "address-added",
                    AddressEventKind::Removed => "address-removed",
                };
                println!(
                    "{action}\tifindex={}\taddress={}/{}",
                    event.address.interface_index,
                    event.address.address,
                    event.address.prefix_length
                );
            }
            NetworkEvent::Wifi(event) => {
                let action = match event.kind {
                    WifiEventKind::ScanResults => "scan-results",
                    WifiEventKind::ScanAborted => "scan-aborted",
                };
                let frequency = event
                    .frequency
                    .map(|freq| freq.to_string())
                    .unwrap_or_else(|| "?".to_string());
                println!(
                    "{action}\tifindex={}\tfrequency={}",
                    event.interface_index, frequency
                );
            }
            NetworkEvent::Route(event) => {
                let action = match event.kind {
                    RouteEventKind::Added => "route-added",
                    RouteEventKind::Removed => "route-removed",
                    RouteEventKind::Changed => "route-changed",
                };
                let gateway = event
                    .route
                    .gateway
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "{action}\tfamily={}\tdestination={}/{}\tgateway={}\tmetric={}",
                    event.route.family,
                    event.route.destination,
                    event.route.prefix_length,
                    gateway,
                    event
                        .route
                        .metric
                        .map(|metric| metric.to_string())
                        .unwrap_or_else(|| "-".to_string())
                );
            }
        }
    }
    eprintln!("monitor stopped");
    Ok(())
}
