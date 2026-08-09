//! Minimal DHCPv4 test server for validating the native client end-to-end.
//!
//! Listens on UDP port 67, answers DISCOVER with OFFER and REQUEST with ACK
//! (RFC 2131). Used together with `scripts/integration-netns.sh` inside an
//! isolated network namespace; this is test infrastructure, not the daemon.

use std::io;
use std::net::Ipv4Addr;
use std::os::raw::{c_int, c_void};
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
const SERVER_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
const OFFERED_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 50);
const NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

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
        return Err(io::Error::new(io::ErrorKind::Other, "short sendto"));
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

fn main() -> io::Result<()> {
    let interface = std::env::args()
        .nth(1)
        .unwrap_or_else(|| {
            eprintln!("usage: dhcp_test_server <ifname>");
            std::process::exit(2);
        });
    let deadline = Instant::now() + Duration::from_secs(120);
    // SAFETY: socket with constant args, return value checked.
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    for (level, option, value) in [(SOL_SOCKET, SO_REUSEADDR, 1), (SOL_SOCKET, SO_BROADCAST, 1)] {
        // SAFETY: value is a valid i32 buffer.
        let rc = unsafe { setsockopt(fd, level, option, (&value as *const i32).cast(), 4) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SO_BINDTODEVICE gives sendto an interface (oif), which lets the kernel
    // fabricate a limited-broadcast (255.255.255.255) route without a table
    // entry -- exactly how a client without an address receives its reply.
    let interface_bytes = format!("{interface}\0");
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
    eprintln!("dhcp_test_server: listening on 0.0.0.0:67 via {interface}");

    let mut buffer = [0_u8; 4096];
    while Instant::now() < deadline {
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
        // SAFETY: buffer is writable; sockaddr is writable.
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
        // Reply to the limited broadcast: the client has no address yet, so a
        // subnet broadcast would not be delivered to it.
        match packet.message_type() {
            DhcpMessageType::Discover => {
                eprintln!("dhcp_test_server: DISCOVER xid=0x{xid:08x} mac={mac:02x?}");
                let reply = DhcpPacket::build_reply(DhcpMessageType::Offer, xid, mac, OFFERED_ADDRESS, &lease_options());
                send_to(fd, &reply, 68, Ipv4Addr::BROADCAST)?;
            }
            DhcpMessageType::Request => {
                eprintln!("dhcp_test_server: REQUEST xid=0x{xid:08x} mac={mac:02x?}");
                let reply = DhcpPacket::build_reply(DhcpMessageType::Ack, xid, mac, OFFERED_ADDRESS, &lease_options());
                send_to(fd, &reply, 68, Ipv4Addr::BROADCAST)?;
            }
            DhcpMessageType::Release => {
                eprintln!("dhcp_test_server: RELEASE mac={mac:02x?}");
            }
            _ => eprintln!("dhcp_test_server: message type {:?}", packet.message_type()),
        }
    }
    unsafe extern "C" {
        fn close(fd: c_int) -> c_int;
    }
    // SAFETY: fd was created by socket() above.
    unsafe { close(fd) };
    eprintln!("dhcp_test_server: shutting down");
    Ok(())
}
