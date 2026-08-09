use network_manager_rs::linux::netlink::install_sigint_shutdown_handler;
use network_manager_rs::{AddressEventKind, Daemon, LinkEventKind, NetworkEvent, RtnetlinkBackend};

fn main() {
    if let Err(err) = run() {
        eprintln!("nmd: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None | Some("links") => print_links(),
        Some("addresses") => print_addresses(),
        Some("monitor") => monitor(),
        Some("--help" | "-h") => {
            println!(
                "Usage: nmd [links|addresses|monitor]\n\nlinks      List kernel network links via rtnetlink (read-only)\naddresses  List kernel interface addresses via rtnetlink (read-only)\nmonitor    Monitor link and address events via rtnetlink multicast (read-only)"
            );
            Ok(())
        }
        Some(command) => Err(format!("unknown command '{command}'").into()),
    }
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
        }
    }
    eprintln!("monitor stopped");
    Ok(())
}
