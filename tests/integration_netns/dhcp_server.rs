//! DHCPv4 test server for the integration harness.
//!
//! Mirrors `examples/dhcp_test_server.rs` as an in-process thread so the
//! harness can `join()` it and assert on its observed traffic. It uses the
//! production `packet` module, so DISCOVER -> OFFER and REQUEST -> ACK are
//! exercised with the exact same packet encoder/decoder as the real client.

use std::io;
use std::net::Ipv4Addr;
use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{Duration, Instant};

use network_manager_rs::linux::dhcp::packet::{self, DhcpMessageType, DhcpPacket};

const AF_INET: c_int = 2;
const SOCK_DGRAM: c_int = 2;
const IPPROTO_UDP: c_int = 17;
const SOL_SOCKET: c_int = 1;
const SO_BROADCAST: c_int = 6;
const SO_REUSEADDR: c_int = 2;
const SO_BINDTODEVICE: c_int = 25;
const POLLIN: i16 = 0x0001;
pub const SERVER_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
pub const OFFERED_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 50);
pub const NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

unsafe extern "C" {
    fn socket(domain: c_int, typ: c_int, protocol: c_int) -> c_int;
    fn setsockopt(sockfd: c_int, level: c_int, optname: c_int, optval: *const c_void, optlen: u32) -> c_int;
    fn bind(sockfd: c_int, addr: *const c_void, addrlen: u32) -> c_int;
    fn sendto(sockfd: c_int, buf: *const c_void, len: usize, flags: c_int, dest: *const SockAddrIn, addrlen: u32) -> isize;
    fn recvfrom(sockfd: c_int, buf: *mut c_void, len: usize, flags: c_int, src: *mut SockAddrIn, addrlen: *mut u32) -> isize;
    fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
}

fn sockaddr(port: u16, address: Ipv4Addr) -> SockAddrIn {
    SockAddrIn {
        sin_family: AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: address.octets(),
        sin_zero: [0; 8],
    }
}

fn send_to(fd: c_int, bytes: &[u8], port: u16, address: Ipv4Addr) -> io::Result<()> {
    let dest = sockaddr(port, address);
    // SAFETY: bytes is readable, dest is a valid SockAddrIn for the call.
    let n = unsafe { sendto(fd, bytes.as_ptr().cast(), bytes.len(), 0, &dest, size_of::<SockAddrIn>() as u32) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != bytes.len() {
        return Err(io::Error::other("short sendto"));
    }
    Ok(())
}

fn lease_options() -> Vec<(u8, Vec<u8>)> {
    vec![
        (1, NETMASK.octets().to_vec()),
        (3, SERVER_ADDRESS.octets().to_vec()),
        (6, SERVER_ADDRESS.octets().to_vec()),
        (15, b"nmd.test".to_vec()),
        (51, 600_u32.to_be_bytes().to_vec()),
        (54, SERVER_ADDRESS.octets().to_vec()),
        (58, 300_u32.to_be_bytes().to_vec()),
        (59, 525_u32.to_be_bytes().to_vec()),
    ]
}

/// Runs the test server on the given interface until `stop` is set (or
/// `deadline` elapses), reporting each observed message to `events`. Returns
/// `Ok` once it has shut down.
pub fn run(
    interface: &str,
    events: Sender<ServerEvent>,
    stop: Arc<AtomicBool>,
    deadline: Duration,
) -> io::Result<()> {
    let deadline = Instant::now() + deadline;
    // SAFETY: socket with constant args, return value checked.
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = run_inner(fd, interface, &events, &stop, deadline);
    // SAFETY: fd was created by socket() above.
    unsafe { close(fd) };
    result
}

fn run_inner(
    fd: c_int,
    interface: &str,
    events: &Sender<ServerEvent>,
    stop: &AtomicBool,
    deadline: Instant,
) -> io::Result<()> {
    for (level, option, value) in [(SOL_SOCKET, SO_REUSEADDR, 1), (SOL_SOCKET, SO_BROADCAST, 1)] {
        // SAFETY: value is a valid i32 buffer.
        let rc = unsafe { setsockopt(fd, level, option, (&value as *const i32).cast(), 4) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let interface_bytes = format!("{interface}\0");
    // SAFETY: interface_bytes is NUL-terminated and readable for the call.
    let rc = unsafe {
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface_bytes.as_ptr().cast(), interface_bytes.len() as u32)
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let local = sockaddr(67, Ipv4Addr::UNSPECIFIED);
    // SAFETY: local is a valid SockAddrIn for the call.
    let rc = unsafe { bind(fd, (&local as *const SockAddrIn).cast(), size_of::<SockAddrIn>() as u32) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let _ = events.send(ServerEvent::Listening);
    eprintln!("dhcp_test_server: listening on 0.0.0.0:67 via {interface}");

    let mut buffer = [0_u8; 4096];
    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        let mut poll_fd = PollFd { fd, events: POLLIN, revents: 0 };
        // SAFETY: poll_fd is a single valid PollFd.
        let ready = unsafe { poll(&mut poll_fd, 1, 1000) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        if ready == 0 {
            continue;
        }
        let mut address_len: u32 = size_of::<SockAddrIn>() as u32;
        // SAFETY: buffer is writable and large enough for any UDP datagram.
        let n = unsafe { recvfrom(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0, std::ptr::null_mut(), &mut address_len) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let Ok(packet) = packet::parse(&buffer[..n as usize]) else {
            eprintln!("dhcp_test_server: ignoring unparseable datagram");
            continue;
        };
        let mac = packet.hardware_address();
        let xid = packet.xid;
        let requested_addr = packet
            .get_option(50)
            .and_then(|value| {
                if value.len() == 4 {
                    Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]))
                } else {
                    None
                }
            });
        match packet.message_type() {
            DhcpMessageType::Discover => {
                let _ = events.send(ServerEvent::Discover { xid, mac, requested_addr });
                eprintln!("dhcp_test_server: DISCOVER xid=0x{xid:08x} mac={mac:02x?}");
                let reply = DhcpPacket::build_reply(DhcpMessageType::Offer, xid, mac, OFFERED_ADDRESS, &lease_options());
                send_to(fd, &reply, 68, Ipv4Addr::BROADCAST)?;
                eprintln!("dhcp_test_server: sent OFFER for {OFFERED_ADDRESS}");
            }
            DhcpMessageType::Request => {
                let _ = events.send(ServerEvent::Request { xid, mac, requested_addr });
                eprintln!("dhcp_test_server: REQUEST xid=0x{xid:08x} mac={mac:02x?}");
                let reply = DhcpPacket::build_reply(DhcpMessageType::Ack, xid, mac, OFFERED_ADDRESS, &lease_options());
                send_to(fd, &reply, 68, Ipv4Addr::BROADCAST)?;
            }
            DhcpMessageType::Release => {
                let _ = events.send(ServerEvent::Release { xid, mac });
            }
            other => {
                let _ = events.send(ServerEvent::Other { message_type: other, xid, mac });
            }
        }
    }
    let _ = events.send(ServerEvent::ShuttingDown);
    eprintln!("dhcp_test_server: shutting down");
    Ok(())
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum ServerEvent {
    Listening,
    Discover {
        xid: u32,
        mac: [u8; 6],
        requested_addr: Option<Ipv4Addr>,
    },
    Request {
        xid: u32,
        mac: [u8; 6],
        requested_addr: Option<Ipv4Addr>,
    },
    Release {
        xid: u32,
        mac: [u8; 6],
    },
    Other {
        message_type: DhcpMessageType,
        xid: u32,
        mac: [u8; 6],
    },
    ShuttingDown,
}

/// Drains `receiver` until `ShuttingDown` (or a timeout), returning every
/// message class observed in order.
pub fn collect_until_shutdown(receiver: &mpsc::Receiver<ServerEvent>, timeout: Duration) -> Vec<ServerEvent> {
    let deadline = Instant::now() + timeout;
    let mut seen = Vec::new();
    while let Ok(event) = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        match event {
            ServerEvent::ShuttingDown => break,
            other => seen.push(other),
        }
    }
    seen
}

/// Builds a DNS `server=` hint map for `Dhcpv4Client::acquire`.
#[allow(dead_code)]
pub fn option_hints() -> std::collections::HashMap<u8, Vec<u8>> {
    std::collections::HashMap::from([(1, Vec::new()), (3, Vec::new()), (6, Vec::new()), (15, Vec::new()), (51, Vec::new())])
}
