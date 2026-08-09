use network_manager_rs::{Daemon, RtnetlinkBackend};

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
        Some("--help" | "-h") => {
            println!(
                "Usage: nmd [links]\n\nlinks  List kernel network links via rtnetlink (read-only)"
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
