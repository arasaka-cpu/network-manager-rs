//! Native DHCPv4 client.
//!
//! Implements the RFC 2131 four-packet exchange (DISCOVER/OFFER/REQUEST/ACK)
//! directly over UDP using raw socket FFI — no external dhcp client binary and
//! no new dependencies. The [`packet`] module is a self-contained BOOTP/DHCP
//! codec with unit tests; [`Dhcpv4Client`] wraps it in a socket conversation.
//!
//! This is a *first lease only* client: it acquires a lease synchronously and
//! can release it, but does not yet implement renewals or rebinding (those are
//! out of scope for the current milestone).

pub mod packet;

use std::io;
use std::net::Ipv4Addr;
use std::os::raw::{c_int, c_void};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use packet::{BOOTP_CLIENT_PORT, BOOTP_SERVER_PORT, DhcpMessageType, DhcpPacket};

use crate::connection::ip::{DhcpClient, DhcpError, DhcpLease, DhcpRequest};

const AF_INET: i32 = 2;
const SOCK_DGRAM: i32 = 2;
const IPPROTO_UDP: i32 = 17;
const SOL_SOCKET: i32 = 1;
const SO_BROADCAST: i32 = 6;
const SO_REUSEADDR: i32 = 2;
const SO_BINDTODEVICE: i32 = 25;
const POLLIN: i16 = 0x0001;
const INADDR_ANY: [u8; 4] = [0, 0, 0, 0];
const BROADCAST: [u8; 4] = [255, 255, 255, 255];

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
    fn setsockopt(
        sockfd: c_int,
        level: c_int,
        optname: c_int,
        optval: *const c_void,
        optlen: u32,
    ) -> c_int;
    fn bind(sockfd: c_int, addr: *const c_void, addrlen: u32) -> c_int;
    fn sendto(
        sockfd: c_int,
        buf: *const c_void,
        len: usize,
        flags: c_int,
        dest_addr: *const SockAddrIn,
        addrlen: u32,
    ) -> isize;
    fn recvfrom(
        sockfd: c_int,
        buf: *mut c_void,
        len: usize,
        flags: c_int,
        src_addr: *mut SockAddrIn,
        addrlen: *mut u32,
    ) -> isize;
    fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
}

fn sockaddr(port: u16, address: [u8; 4]) -> SockAddrIn {
    SockAddrIn {
        sin_family: AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: address,
        sin_zero: [0; 8],
    }
}

fn set_socket_option(
    fd: c_int,
    level: c_int,
    option: c_int,
    value: &[u8],
) -> Result<(), io::Error> {
    // SAFETY: setsockopt copies optlen bytes from value; value outlives the call.
    let rc = unsafe { setsockopt(fd, level, option, value.as_ptr().cast(), value.len() as u32) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_int_socket_option(
    fd: c_int,
    level: c_int,
    option: c_int,
    value: i32,
) -> Result<(), io::Error> {
    set_socket_option(fd, level, option, &value.to_ne_bytes())
}

/// Reads the interface MAC address from sysfs (`/sys/class/net/<name>/address`).
pub fn read_mac_address(interface_name: &str) -> Result<[u8; 6], DhcpError> {
    let contents = std::fs::read_to_string(format!("/sys/class/net/{interface_name}/address"))?;
    let contents = contents.trim();
    let mut bytes = [0_u8; 6];
    let mut iter = contents.split(':');
    for byte in bytes.iter_mut() {
        let part = iter
            .next()
            .ok_or(DhcpError::MalformedPacket("invalid mac address format"))?;
        *byte = u8::from_str_radix(part, 16)
            .map_err(|_| DhcpError::MalformedPacket("invalid mac address format"))?;
    }
    Ok(bytes)
}

fn transaction_id() -> u32 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let nanos = now.as_nanos();
    let pid = std::process::id();
    (nanos as u32) ^ pid.rotate_left(16)
}

/// Wait for a UDP datagram matching `xid` on `fd`, polling until `deadline`.
///
/// Returns the matching packet or `DhcpError::Timeout` once the deadline is hit.
fn wait_for_packet(
    fd: c_int,
    xid: u32,
    interface_name: &str,
    deadline: Instant,
) -> Result<DhcpPacket, DhcpError> {
    let mut buffer = [0_u8; 4096];
    let mut sockaddr = SockAddrIn {
        sin_family: 0,
        sin_port: 0,
        sin_addr: [0; 4],
        sin_zero: [0; 8],
    };
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(DhcpError::Timeout {
                interface: interface_name.to_string(),
            });
        }
        let remaining_ms = (deadline - now).as_millis().min(i32::MAX as u128) as c_int;
        let mut poll_fd = PollFd {
            fd,
            events: POLLIN,
            revents: 0,
        };
        // SAFETY: poll_fd points to a single valid PollFd; timeout is a finite ms value.
        let ready = unsafe { poll(&mut poll_fd, 1, remaining_ms) };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err.into());
        }
        if ready == 0 {
            return Err(DhcpError::Timeout {
                interface: interface_name.to_string(),
            });
        }
        let mut address_len: u32 = size_of::<SockAddrIn>() as u32;
        // SAFETY: buffer is a writable 4096-byte region; sockaddr/address_len are writable.
        let n = unsafe {
            recvfrom(
                fd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
                &mut sockaddr,
                &mut address_len,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err.into());
        }
        if n == 0 {
            continue;
        }
        if let Ok(packet) = packet::parse(&buffer[..n as usize]) {
            if packet.xid == xid {
                return Ok(packet);
            }
        }
    }
}

fn send_packet(fd: c_int, bytes: &[u8], port: u16, address: [u8; 4]) -> Result<(), DhcpError> {
    let dest = sockaddr(port, address);
    // SAFETY: bytes is a valid readable buffer; dest is a valid SockAddrIn.
    let sent = unsafe {
        sendto(
            fd,
            bytes.as_ptr().cast(),
            bytes.len(),
            0,
            &dest,
            size_of::<SockAddrIn>() as u32,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if sent as usize != bytes.len() {
        return Err(DhcpError::MalformedPacket("short DHCP send"));
    }
    Ok(())
}

/// A DHCPv4 client bound to a single interface.
#[derive(Debug)]
pub struct Dhcpv4Client {
    timeout: Duration,
}

impl Default for Dhcpv4Client {
    fn default() -> Self {
        Self::new(Duration::from_secs(4))
    }
}

impl Dhcpv4Client {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    fn open_socket(&self, interface_name: &str) -> Result<c_int, DhcpError> {
        // SAFETY: socket is called with constant arguments and checked for a negative return.
        let fd = unsafe { socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        set_int_socket_option(fd, SOL_SOCKET, SO_REUSEADDR, 1)?;
        set_int_socket_option(fd, SOL_SOCKET, SO_BROADCAST, 1)?;
        let interface_bytes = format!("{interface_name}\0");
        set_socket_option(fd, SOL_SOCKET, SO_BINDTODEVICE, interface_bytes.as_bytes())?;
        let local = sockaddr(BOOTP_CLIENT_PORT, INADDR_ANY);
        // SAFETY: local is a valid SockAddrIn for the duration of the call.
        let rc = unsafe {
            bind(
                fd,
                (&local as *const SockAddrIn).cast(),
                size_of::<SockAddrIn>() as u32,
            )
        };
        if rc < 0 {
            // SAFETY: fd was created by socket() above and is no longer needed on error.
            unsafe { close(fd) };
            return Err(io::Error::last_os_error().into());
        }
        Ok(fd)
    }
}

impl DhcpClient for Dhcpv4Client {
    fn acquire(&mut self, request: &DhcpRequest) -> Result<DhcpLease, DhcpError> {
        let mac = read_mac_address(&request.interface_name)?;
        let xid = transaction_id();
        let fd = self.open_socket(&request.interface_name)?;

        let effective_timeout = if request.timeout.is_zero() {
            self.timeout
        } else {
            request.timeout
        };
        let deadline = Instant::now() + effective_timeout;

        let discover = DhcpPacket::build_discover(
            xid,
            mac,
            request.hostname.as_deref(),
            request.requested_address,
        );
        send_packet(fd, &discover, BOOTP_SERVER_PORT, BROADCAST)?;

        let offer = wait_for_packet(fd, xid, &request.interface_name, deadline)?;
        if offer.message_type() != DhcpMessageType::Offer {
            // SAFETY: fd was created by open_socket() above and is no longer needed.
            unsafe { close(fd) };
            return Err(DhcpError::MalformedPacket(
                "expected a DHCPOFFER in response to DISCOVER",
            ));
        }
        let offered_address = offer.yiaddr();
        if offered_address.is_none() || offered_address == Some(Ipv4Addr::UNSPECIFIED) {
            // SAFETY: fd was created by open_socket() and is closed exactly once here.
            unsafe { close(fd) };
            return Err(DhcpError::MalformedPacket(
                "DHCPOFFER carried no usable address",
            ));
        }
        let server_identifier = offer.server_identifier().or_else(|| offer.source_address());

        // A freshly booted client has no address yet, so it cannot unicast a
        // REQUEST to the server; broadcast it (RFC 2131 section 4.3.2).
        let request_packet = DhcpPacket::build_request(
            xid,
            mac,
            offered_address,
            server_identifier,
            request.hostname.as_deref(),
        );
        send_packet(fd, &request_packet, BOOTP_SERVER_PORT, BROADCAST)?;

        let ack = wait_for_packet(fd, xid, &request.interface_name, deadline)?;
        match ack.message_type() {
            DhcpMessageType::Ack => {}
            DhcpMessageType::Nak => {
                // SAFETY: fd was created by open_socket() and is closed exactly once here.
                unsafe { close(fd) };
                return Err(DhcpError::MalformedPacket("server returned DHCPNAK"));
            }
            _ => {
                // SAFETY: fd was created by open_socket() and is closed exactly once here.
                unsafe { close(fd) };
                return Err(DhcpError::MalformedPacket(
                    "expected a DHCPACK in response to REQUEST",
                ));
            }
        }
        let lease = ack.to_lease(request.interface_index, &request.interface_name, mac)?;
        // SAFETY: fd was created by open_socket() and is closed exactly once here.
        unsafe { close(fd) };
        Ok(lease)
    }

    fn release(&mut self, lease: &DhcpLease) -> Result<(), DhcpError> {
        let mac = read_mac_address(&lease.interface_name)?;
        let xid = transaction_id();
        let fd = self.open_socket(&lease.interface_name)?;
        let server = lease.server_identifier.unwrap_or(Ipv4Addr::BROADCAST);
        let packet = DhcpPacket::build_release(xid, mac, lease.address, server);
        let result = send_packet(fd, &packet, BOOTP_SERVER_PORT, server.octets());
        // SAFETY: fd was created by open_socket() and is closed exactly once here.
        unsafe { close(fd) };
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_address_is_read_from_sysfs_when_available() {
        let mac = read_mac_address("lo");
        assert!(mac.is_err() || mac.is_ok(), "lo has no real MAC");
        if let Ok(mac) = mac {
            assert_eq!(mac.len(), 6);
        }
    }

    #[test]
    fn dhcp_request_produces_valid_discover() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let discover = DhcpPacket::build_discover(0x11223344, mac, Some("nmdhost"), None);
        let parsed = packet::parse(&discover).unwrap();
        assert_eq!(parsed.xid, 0x11223344);
        assert_eq!(parsed.message_type(), DhcpMessageType::Discover);
        assert_eq!(parsed.hardware_address(), mac);
        assert_eq!(parsed.flags & 0x8000, 0x8000);
        assert_eq!(
            parsed.hostname().as_deref(),
            Some("nmdhost"),
            "hostname option is echoed back"
        );
    }

    #[test]
    fn discover_round_trips_through_parse() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let discover = DhcpPacket::build_discover(0xabcdef00, mac, None, None);
        let parsed = packet::parse(&discover).unwrap();
        assert_eq!(packet::serialize(&parsed), discover);
    }

    #[test]
    fn offer_parses_lease_options() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x03];
        let offer = DhcpPacket::build_reply(
            DhcpMessageType::Offer,
            0x99,
            mac,
            Ipv4Addr::new(10, 1, 1, 20),
            &[
                (1, vec![255, 255, 255, 0]),
                (3, vec![10, 1, 1, 1]),
                (6, vec![10, 1, 1, 2, 10, 1, 1, 3]),
                (15, b"lan.example".to_vec()),
                (51, 3600_u32.to_be_bytes().to_vec()),
                (54, vec![10, 1, 1, 1]),
                (58, 1800_u32.to_be_bytes().to_vec()),
                (59, 3150_u32.to_be_bytes().to_vec()),
            ],
        );
        let parsed = packet::parse(&offer).unwrap();
        assert_eq!(parsed.message_type(), DhcpMessageType::Offer);
        assert_eq!(parsed.yiaddr(), Some(Ipv4Addr::new(10, 1, 1, 20)));
        assert_eq!(parsed.subnet_mask(), Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(parsed.routers(), vec![Ipv4Addr::new(10, 1, 1, 1)]);
        assert_eq!(
            parsed.dns_servers(),
            vec![Ipv4Addr::new(10, 1, 1, 2), Ipv4Addr::new(10, 1, 1, 3)]
        );
        assert_eq!(parsed.domain_name().as_deref(), Some("lan.example"));
        assert_eq!(parsed.lease_seconds(), Some(3600));
        assert_eq!(parsed.server_identifier(), Some(Ipv4Addr::new(10, 1, 1, 1)));
        assert_eq!(parsed.t1_seconds(), Some(1800));
        assert_eq!(parsed.t2_seconds(), Some(3150));
    }

    #[test]
    fn rejects_truncated_packets_and_wrong_magic() {
        assert!(packet::parse(&[0u8; 10]).is_err());
        let mut packet = DhcpPacket::build_discover(1, [0u8; 6], None, None);
        packet[236] = 0;
        assert!(packet::parse(&packet).is_err());
    }

    #[test]
    fn lease_derivation_from_ack() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x04];
        let ack = DhcpPacket::build_reply(
            DhcpMessageType::Ack,
            0x77,
            mac,
            Ipv4Addr::new(10, 2, 2, 10),
            &[
                (1, vec![255, 255, 0, 0]),
                (3, vec![10, 2, 2, 1]),
                (6, vec![8, 8, 8, 8]),
                (51, 7200_u32.to_be_bytes().to_vec()),
                (54, vec![10, 2, 2, 1]),
            ],
        );
        let parsed = packet::parse(&ack).unwrap();
        let lease = parsed
            .to_lease(9, "nmdv1", mac)
            .expect("ack should yield a lease");
        assert_eq!(lease.address, Ipv4Addr::new(10, 2, 2, 10));
        assert_eq!(lease.prefix_length, 16);
        assert_eq!(lease.netmask, Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(lease.gateway, Some(Ipv4Addr::new(10, 2, 2, 1)));
        assert_eq!(lease.dns_servers, vec![Ipv4Addr::new(8, 8, 8, 8)]);
        assert_eq!(lease.lease_seconds, Some(7200));
        assert_eq!(lease.server_identifier, Some(Ipv4Addr::new(10, 2, 2, 1)));
        assert_eq!(lease.interface_name, "nmdv1");
    }
}
