use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::daemon::NetworkBackend;
use crate::linux::wifi;

pub use crate::linux::model::{
    Address, AddressEvent, AddressEventKind, Link, LinkEvent, LinkEventKind, LinkFlags,
    NetlinkError, NetworkEvent, NetworkEventSource,
};

pub(crate) const AF_NETLINK: i32 = 16;
pub(crate) const SOCK_RAW: i32 = 3;
const NETLINK_ROUTE: i32 = 0;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
const NLM_F_CREATE: u16 = 0x0400;
const RTM_GETLINK: u16 = 18;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const NLMSG_ALIGNTO: usize = 4;
const RTA_ALIGNTO: usize = 4;
const RTMGRP_LINK: u32 = 1;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
const SIGINT: i32 = 2;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const O_NONBLOCK: i32 = 0o4000;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

#[repr(C)]
struct SockAddrNl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct NlMsgHdr {
    pub(crate) nlmsg_len: u32,
    pub(crate) nlmsg_type: u16,
    pub(crate) nlmsg_flags: u16,
    pub(crate) nlmsg_seq: u32,
    pub(crate) nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfInfoMsg {
    ifi_family: u8,
    __ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtAttr {
    rta_len: u16,
    rta_type: u16,
}

unsafe extern "C" {
    fn socket(domain: i32, typ: i32, protocol: i32) -> i32;
    fn bind(sockfd: i32, addr: *const SockAddrNl, addrlen: u32) -> i32;
    fn send(sockfd: i32, buf: *const c_void, len: usize, flags: i32) -> isize;
    fn recv(sockfd: i32, buf: *mut c_void, len: usize, flags: i32) -> isize;
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}

#[derive(Debug)]
pub struct RtnetlinkEventSource {
    fd: OwnedFd,
    buf: Vec<u8>,
    pending: Vec<NetworkEvent>,
}

impl NetworkEventSource for RtnetlinkEventSource {
    fn next_event(&mut self) -> Result<Option<NetworkEvent>, NetlinkError> {
        loop {
            if let Some(event) = self.pending.pop() {
                return Ok(Some(event));
            }
            if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                return Ok(None);
            }
            match recv_into(self.fd.as_raw_fd(), &mut self.buf) {
                Ok(n) => {
                    let mut events = parse_network_events(&self.buf[..n])?;
                    events.reverse();
                    self.pending = events;
                }
                Err(NetlinkError::Io(err))
                    if matches!(
                        err.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                        return Ok(None);
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                Err(err) => return Err(err),
            }
        }
    }
}

extern "C" fn request_shutdown(_signum: i32) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

pub fn install_sigint_shutdown_handler() {
    // SAFETY: request_shutdown is an extern "C" signal handler that only stores to an AtomicBool.
    let _previous = unsafe { signal(SIGINT, request_shutdown) };
}

#[derive(Default)]
pub struct RtnetlinkBackend;

impl RtnetlinkBackend {
    pub fn new() -> Self {
        Self
    }
}

impl NetworkBackend for RtnetlinkBackend {
    fn links(&self) -> Result<Vec<Link>, NetlinkError> {
        get_links()
    }

    fn addresses(&self) -> Result<Vec<Address>, NetlinkError> {
        get_addresses()
    }

    fn events(&self) -> Result<Box<dyn NetworkEventSource>, NetlinkError> {
        Ok(Box::new(open_link_event_source()?))
    }

    fn wifi_interfaces(&self) -> Result<Vec<crate::linux::model::WirelessInterface>, NetlinkError> {
        wifi::wifi_interfaces()
    }

    fn access_points(&self) -> Result<Vec<crate::linux::model::AccessPoint>, NetlinkError> {
        wifi::access_points()
    }

    fn scan_wifi(&self) -> Result<Vec<crate::linux::model::AccessPoint>, NetlinkError> {
        wifi::scan_wifi()
    }

    fn wifi_events(&self) -> Result<Box<dyn NetworkEventSource>, NetlinkError> {
        Ok(Box::new(wifi::WifiEventSource::open()?))
    }
}

pub fn get_addresses() -> Result<Vec<Address>, NetlinkError> {
    let fd = open_route_socket()?;
    let request = AddressDumpRequest::new(2);
    send_all(fd.as_raw_fd(), request.as_bytes())?;

    let mut addresses = Vec::new();
    let mut buf = vec![0_u8; 8192];
    loop {
        let n = recv_into(fd.as_raw_fd(), &mut buf)?;
        let done = parse_address_messages(&buf[..n], &mut addresses)?;
        if done {
            addresses.sort_by_key(|address| (address.interface_index, address.address));
            return Ok(addresses);
        }
    }
}

pub fn get_links() -> Result<Vec<Link>, NetlinkError> {
    let fd = open_route_socket()?;
    let request = LinkDumpRequest::new(1);
    send_all(fd.as_raw_fd(), request.as_bytes())?;

    let mut links = Vec::new();
    let mut buf = vec![0_u8; 8192];
    loop {
        let n = recv_into(fd.as_raw_fd(), &mut buf)?;
        let done = parse_link_messages(&buf[..n], &mut links)?;
        if done {
            links.sort_by_key(|link| link.index);
            return Ok(links);
        }
    }
}

#[repr(C)]
struct LinkDumpRequest {
    header: NlMsgHdr,
    info: IfInfoMsg,
}

#[repr(C)]
struct AddressDumpRequest {
    header: NlMsgHdr,
    info: IfAddrMsg,
}

impl AddressDumpRequest {
    fn new(sequence: u32) -> Self {
        Self {
            header: NlMsgHdr {
                nlmsg_len: size_of::<Self>() as u32,
                nlmsg_type: RTM_GETADDR,
                nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
                nlmsg_seq: sequence,
                nlmsg_pid: 0,
            },
            info: IfAddrMsg {
                ifa_family: 0,
                ifa_prefixlen: 0,
                ifa_flags: 0,
                ifa_scope: 0,
                ifa_index: 0,
            },
        }
    }

    fn as_bytes(&self) -> &[u8] {
        let ptr = self as *const Self as *const u8;
        // SAFETY: AddressDumpRequest is repr(C), plain data, and lives for the returned slice lifetime.
        unsafe { std::slice::from_raw_parts(ptr, size_of::<Self>()) }
    }
}

impl LinkDumpRequest {
    fn new(sequence: u32) -> Self {
        Self {
            header: NlMsgHdr {
                nlmsg_len: size_of::<Self>() as u32,
                nlmsg_type: RTM_GETLINK,
                nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
                nlmsg_seq: sequence,
                nlmsg_pid: 0,
            },
            info: IfInfoMsg {
                ifi_family: 0,
                __ifi_pad: 0,
                ifi_type: 0,
                ifi_index: 0,
                ifi_flags: 0,
                ifi_change: 0,
            },
        }
    }

    fn as_bytes(&self) -> &[u8] {
        let ptr = self as *const Self as *const u8;
        // SAFETY: LinkDumpRequest is repr(C), plain data, and lives for the returned slice lifetime.
        unsafe { std::slice::from_raw_parts(ptr, size_of::<Self>()) }
    }
}

fn open_route_socket() -> Result<OwnedFd, NetlinkError> {
    open_socket_with_groups(NETLINK_ROUTE, 0)
}

fn open_link_event_source() -> Result<RtnetlinkEventSource, NetlinkError> {
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
    let fd = open_socket_with_groups(NETLINK_ROUTE, RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR)?;
    set_nonblocking(fd.as_raw_fd())?;
    Ok(RtnetlinkEventSource {
        fd,
        buf: vec![0_u8; 8192],
        pending: Vec::new(),
    })
}

pub(crate) fn open_socket_with_groups(
    protocol: i32,
    groups: u32,
) -> Result<OwnedFd, NetlinkError> {
    // SAFETY: socket is called with constant arguments and checked for a negative return value.
    let raw = unsafe { socket(AF_NETLINK, SOCK_RAW, protocol) };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: raw is a newly-created file descriptor owned by this function.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let addr = SockAddrNl {
        nl_family: AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: groups,
    };
    // SAFETY: addr points to a valid SockAddrNl for the duration of the call.
    let rc = unsafe { bind(fd.as_raw_fd(), &addr, size_of::<SockAddrNl>() as u32) };
    if rc < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(fd)
}

pub(crate) fn set_nonblocking(fd: i32) -> Result<(), NetlinkError> {
    set_flag(fd, O_NONBLOCK, true)
}

fn set_flag(fd: i32, flag: i32, enabled: bool) -> Result<(), NetlinkError> {
    // SAFETY: fcntl is called with a valid file descriptor and F_GETFL command.
    let flags = unsafe { fcntl(fd, F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let updated = if enabled {
        flags | flag
    } else {
        flags & !flag
    };
    // SAFETY: fcntl is called with a valid file descriptor and F_SETFL command.
    let rc = unsafe { fcntl(fd, F_SETFL, updated) };
    if rc < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

pub(crate) fn send_all(fd: i32, bytes: &[u8]) -> Result<(), NetlinkError> {
    // SAFETY: bytes is a valid readable buffer for the supplied length.
    let sent = unsafe { send(fd, bytes.as_ptr().cast(), bytes.len(), 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if sent as usize != bytes.len() {
        return Err(NetlinkError::MalformedMessage("short netlink send"));
    }
    Ok(())
}

pub(crate) fn recv_into(fd: i32, buf: &mut [u8]) -> Result<usize, NetlinkError> {
    // SAFETY: buf is a valid writable buffer for the supplied length.
    let n = unsafe { recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(n as usize)
}

fn parse_link_messages(buf: &[u8], links: &mut Vec<Link>) -> Result<bool, NetlinkError> {
    let mut offset = 0;
    while offset + size_of::<NlMsgHdr>() <= buf.len() {
        let header = read_unaligned::<NlMsgHdr>(&buf[offset..])?;
        let len = header.nlmsg_len as usize;
        if len < size_of::<NlMsgHdr>() || offset + len > buf.len() {
            return Err(NetlinkError::MalformedMessage("invalid nlmsghdr length"));
        }
        let payload = &buf[offset + size_of::<NlMsgHdr>()..offset + len];
        match header.nlmsg_type {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => return Err(parse_kernel_error(payload)),
            RTM_NEWLINK => {
                if let Some(link) = parse_link(payload)? {
                    links.push(link);
                }
            }
            _ => {}
        }
        offset += align(len, NLMSG_ALIGNTO);
    }
    Ok(false)
}

fn parse_address_messages(buf: &[u8], addresses: &mut Vec<Address>) -> Result<bool, NetlinkError> {
    let mut offset = 0;
    while offset + size_of::<NlMsgHdr>() <= buf.len() {
        let header = read_unaligned::<NlMsgHdr>(&buf[offset..])?;
        let len = header.nlmsg_len as usize;
        if len < size_of::<NlMsgHdr>() || offset + len > buf.len() {
            return Err(NetlinkError::MalformedMessage("invalid nlmsghdr length"));
        }
        let payload = &buf[offset + size_of::<NlMsgHdr>()..offset + len];
        match header.nlmsg_type {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => return Err(parse_kernel_error(payload)),
            RTM_NEWADDR => {
                if let Some(address) = parse_address(payload)? {
                    addresses.push(address);
                }
            }
            _ => {}
        }
        offset += align(len, NLMSG_ALIGNTO);
    }
    Ok(false)
}

fn parse_network_events(buf: &[u8]) -> Result<Vec<NetworkEvent>, NetlinkError> {
    let mut events = Vec::new();
    let mut offset = 0;
    while offset + size_of::<NlMsgHdr>() <= buf.len() {
        let header = read_unaligned::<NlMsgHdr>(&buf[offset..])?;
        let len = header.nlmsg_len as usize;
        if len < size_of::<NlMsgHdr>() || offset + len > buf.len() {
            return Err(NetlinkError::MalformedMessage("invalid nlmsghdr length"));
        }
        let payload = &buf[offset + size_of::<NlMsgHdr>()..offset + len];
        match header.nlmsg_type {
            NLMSG_DONE => return Ok(events),
            NLMSG_ERROR => return Err(parse_kernel_error(payload)),
            RTM_NEWLINK => {
                if let Some(link) = parse_link(payload)? {
                    let kind = if header.nlmsg_flags & NLM_F_CREATE != 0 {
                        LinkEventKind::Created
                    } else {
                        LinkEventKind::Changed
                    };
                    events.push(NetworkEvent::Link(LinkEvent { kind, link }));
                }
            }
            RTM_DELLINK => {
                if let Some(link) = parse_link(payload)? {
                    events.push(NetworkEvent::Link(LinkEvent {
                        kind: LinkEventKind::Removed,
                        link,
                    }));
                }
            }
            RTM_NEWADDR => {
                if let Some(address) = parse_address(payload)? {
                    events.push(NetworkEvent::Address(AddressEvent {
                        kind: AddressEventKind::Added,
                        address,
                    }));
                }
            }
            RTM_DELADDR => {
                if let Some(address) = parse_address(payload)? {
                    events.push(NetworkEvent::Address(AddressEvent {
                        kind: AddressEventKind::Removed,
                        address,
                    }));
                }
            }
            _ => {}
        }
        offset += align(len, NLMSG_ALIGNTO);
    }

    if offset != buf.len() {
        return Err(NetlinkError::MalformedMessage("trailing partial nlmsghdr"));
    }

    Ok(events)
}

pub(crate) fn parse_kernel_error(payload: &[u8]) -> NetlinkError {
    if payload.len() < size_of::<i32>() {
        return NetlinkError::MalformedMessage("short nlmsgerr");
    }
    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(&payload[..4]);
    NetlinkError::Kernel(i32::from_ne_bytes(bytes))
}

fn parse_address(payload: &[u8]) -> Result<Option<Address>, NetlinkError> {
    if payload.len() < size_of::<IfAddrMsg>() {
        return Err(NetlinkError::MalformedMessage("short ifaddrmsg"));
    }
    let info = read_unaligned::<IfAddrMsg>(payload)?;
    let expected_len = match info.ifa_family {
        AF_INET => 4,
        AF_INET6 => 16,
        _ => return Ok(None),
    };
    let mut address_bytes = None;
    let mut offset = size_of::<IfAddrMsg>();
    while offset + size_of::<RtAttr>() <= payload.len() {
        let attr = read_unaligned::<RtAttr>(&payload[offset..])?;
        let len = attr.rta_len as usize;
        if len < size_of::<RtAttr>() || offset + len > payload.len() {
            return Err(NetlinkError::MalformedMessage("invalid rtattr length"));
        }
        let value = &payload[offset + size_of::<RtAttr>()..offset + len];
        if matches!(attr.rta_type, IFA_LOCAL | IFA_ADDRESS) && address_bytes.is_none() {
            if value.len() != expected_len {
                return Err(NetlinkError::MalformedMessage(
                    "invalid address attribute length",
                ));
            }
            address_bytes = Some(value.to_vec());
        }
        offset += align(len, RTA_ALIGNTO);
    }

    let Some(address_bytes) = address_bytes else {
        return Ok(None);
    };

    let address = match info.ifa_family {
        AF_INET => IpAddr::V4(Ipv4Addr::new(
            address_bytes[0],
            address_bytes[1],
            address_bytes[2],
            address_bytes[3],
        )),
        AF_INET6 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&address_bytes);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return Ok(None),
    };

    Ok(Some(Address {
        interface_index: info.ifa_index,
        address,
        prefix_length: info.ifa_prefixlen,
    }))
}

fn parse_link(payload: &[u8]) -> Result<Option<Link>, NetlinkError> {
    if payload.len() < size_of::<IfInfoMsg>() {
        return Err(NetlinkError::MalformedMessage("short ifinfomsg"));
    }
    let info = read_unaligned::<IfInfoMsg>(payload)?;
    let mut name = None;
    let mut offset = size_of::<IfInfoMsg>();
    while offset + size_of::<RtAttr>() <= payload.len() {
        let attr = read_unaligned::<RtAttr>(&payload[offset..])?;
        let len = attr.rta_len as usize;
        if len < size_of::<RtAttr>() || offset + len > payload.len() {
            return Err(NetlinkError::MalformedMessage("invalid rtattr length"));
        }
        let value = &payload[offset + size_of::<RtAttr>()..offset + len];
        if attr.rta_type == IFLA_IFNAME {
            let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
            name = Some(String::from_utf8_lossy(&value[..end]).into_owned());
        }
        offset += align(len, RTA_ALIGNTO);
    }
    Ok(name.map(|name| Link {
        index: info.ifi_index,
        name,
        flags: LinkFlags::from_bits(info.ifi_flags),
    }))
}

pub(crate) fn read_unaligned<T: Copy>(bytes: &[u8]) -> Result<T, NetlinkError> {
    if bytes.len() < size_of::<T>() {
        return Err(NetlinkError::MalformedMessage("short structured data"));
    }
    let ptr = bytes.as_ptr().cast::<T>();
    // SAFETY: length is checked above and read_unaligned permits unaligned packet data.
    Ok(unsafe { ptr.read_unaligned() })
}

pub(crate) const fn align(len: usize, to: usize) -> usize {
    (len + to - 1) & !(to - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_struct<T>(buf: &mut Vec<u8>, value: &T) {
        let ptr = value as *const T as *const u8;
        // SAFETY: value is valid for size_of::<T>() bytes while this function copies it.
        let bytes = unsafe { std::slice::from_raw_parts(ptr, size_of::<T>()) };
        buf.extend_from_slice(bytes);
    }

    fn link_message(
        message_type: u16,
        flags: u16,
        index: i32,
        name: &[u8],
        link_flags: u32,
    ) -> Vec<u8> {
        let attr_len = size_of::<RtAttr>() + name.len();
        let payload_len = size_of::<IfInfoMsg>() + align(attr_len, RTA_ALIGNTO);
        let mut message = Vec::new();
        push_struct(
            &mut message,
            &NlMsgHdr {
                nlmsg_len: (size_of::<NlMsgHdr>() + payload_len) as u32,
                nlmsg_type: message_type,
                nlmsg_flags: flags,
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            },
        );
        push_struct(
            &mut message,
            &IfInfoMsg {
                ifi_family: 0,
                __ifi_pad: 0,
                ifi_type: 1,
                ifi_index: index,
                ifi_flags: link_flags,
                ifi_change: 0,
            },
        );
        push_struct(
            &mut message,
            &RtAttr {
                rta_len: attr_len as u16,
                rta_type: IFLA_IFNAME,
            },
        );
        message.extend_from_slice(name);
        message.resize(size_of::<NlMsgHdr>() + payload_len, 0);
        message
    }

    fn unsupported_message() -> Vec<u8> {
        let mut message = Vec::new();
        push_struct(
            &mut message,
            &NlMsgHdr {
                nlmsg_len: size_of::<NlMsgHdr>() as u32,
                nlmsg_type: 999,
                nlmsg_flags: 0,
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            },
        );
        message
    }

    fn address_message(
        message_type: u16,
        family: u8,
        index: u32,
        prefix_length: u8,
        address: &[u8],
    ) -> Vec<u8> {
        let attr_len = size_of::<RtAttr>() + address.len();
        let payload_len = size_of::<IfAddrMsg>() + align(attr_len, RTA_ALIGNTO);
        let mut message = Vec::new();
        push_struct(
            &mut message,
            &NlMsgHdr {
                nlmsg_len: (size_of::<NlMsgHdr>() + payload_len) as u32,
                nlmsg_type: message_type,
                nlmsg_flags: 0,
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            },
        );
        push_struct(
            &mut message,
            &IfAddrMsg {
                ifa_family: family,
                ifa_prefixlen: prefix_length,
                ifa_flags: 0,
                ifa_scope: 0,
                ifa_index: index,
            },
        );
        push_struct(
            &mut message,
            &RtAttr {
                rta_len: attr_len as u16,
                rta_type: IFA_LOCAL,
            },
        );
        message.extend_from_slice(address);
        message.resize(size_of::<NlMsgHdr>() + payload_len, 0);
        message
    }

    #[test]
    fn parses_link_dump_fixture() {
        let mut message = link_message(RTM_NEWLINK, 0, 7, b"eth0\0", 0x1);
        push_struct(
            &mut message,
            &NlMsgHdr {
                nlmsg_len: size_of::<NlMsgHdr>() as u32,
                nlmsg_type: NLMSG_DONE,
                nlmsg_flags: 0,
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            },
        );

        let mut links = Vec::new();
        assert!(parse_link_messages(&message, &mut links).unwrap());
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].index, 7);
        assert_eq!(links[0].name, "eth0");
        assert!(links[0].flags.is_up());
    }

    #[test]
    fn parses_valid_link_creation_event() {
        let events =
            parse_network_events(&link_message(RTM_NEWLINK, NLM_F_CREATE, 7, b"eth0\0", 0x1))
                .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            NetworkEvent::Link(LinkEvent {
                kind: LinkEventKind::Created,
                link: Link {
                    index: 7,
                    name: "eth0".to_string(),
                    flags: LinkFlags::from_bits(0x1),
                },
            })
        );
    }

    #[test]
    fn parses_valid_link_removal_event() {
        let events = parse_network_events(&link_message(RTM_DELLINK, 0, 8, b"veth0\0", 0)).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            NetworkEvent::Link(LinkEvent {
                kind: LinkEventKind::Removed,
                link: Link {
                    index: 8,
                    name: "veth0".to_string(),
                    flags: LinkFlags::from_bits(0),
                },
            })
        );
    }

    #[test]
    fn parses_valid_link_state_change_event() {
        let events =
            parse_network_events(&link_message(RTM_NEWLINK, 0, 9, b"wlan0\0", 0x1000)).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            NetworkEvent::Link(LinkEvent {
                kind: LinkEventKind::Changed,
                link: Link {
                    index: 9,
                    name: "wlan0".to_string(),
                    flags: LinkFlags::from_bits(0x1000),
                },
            })
        );
    }

    #[test]
    fn rejects_truncated_header_length() {
        let mut message = Vec::new();
        push_struct(
            &mut message,
            &NlMsgHdr {
                nlmsg_len: 8,
                nlmsg_type: RTM_NEWLINK,
                nlmsg_flags: 0,
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            },
        );
        let mut links = Vec::new();
        assert!(matches!(
            parse_link_messages(&message, &mut links),
            Err(NetlinkError::MalformedMessage(_))
        ));
        assert!(matches!(
            parse_network_events(&message),
            Err(NetlinkError::MalformedMessage(_))
        ));
    }

    #[test]
    fn ignores_unsupported_message_type() {
        let events = parse_network_events(&unsupported_message()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn rejects_malformed_attributes() {
        let mut message = link_message(RTM_NEWLINK, 0, 10, b"bad0\0", 0);
        let attr_offset = size_of::<NlMsgHdr>() + size_of::<IfInfoMsg>();
        message[attr_offset] = 1;
        message[attr_offset + 1] = 0;
        assert!(matches!(
            parse_network_events(&message),
            Err(NetlinkError::MalformedMessage(_))
        ));
    }

    #[test]
    fn parses_multiple_messages_in_one_buffer() {
        let mut message = link_message(RTM_NEWLINK, NLM_F_CREATE, 11, b"a0\0", 0x1);
        message.extend_from_slice(&unsupported_message());
        message.extend_from_slice(&link_message(RTM_DELLINK, 0, 12, b"b0\0", 0));

        let events = parse_network_events(&message).unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0],
            NetworkEvent::Link(LinkEvent {
                kind: LinkEventKind::Created,
                ..
            })
        ));
        assert!(matches!(
            events[1],
            NetworkEvent::Link(LinkEvent {
                kind: LinkEventKind::Removed,
                ..
            })
        ));
    }

    #[test]
    fn parses_ipv4_address_enumeration() {
        let mut message = address_message(RTM_NEWADDR, AF_INET, 2, 24, &[192, 0, 2, 10]);
        push_struct(
            &mut message,
            &NlMsgHdr {
                nlmsg_len: size_of::<NlMsgHdr>() as u32,
                nlmsg_type: NLMSG_DONE,
                nlmsg_flags: 0,
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            },
        );
        let mut addresses = Vec::new();
        assert!(parse_address_messages(&message, &mut addresses).unwrap());
        assert_eq!(
            addresses,
            vec![Address {
                interface_index: 2,
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                prefix_length: 24,
            }]
        );
    }

    #[test]
    fn parses_ipv6_address_enumeration() {
        let octets = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut message = address_message(RTM_NEWADDR, AF_INET6, 3, 64, &octets);
        push_struct(
            &mut message,
            &NlMsgHdr {
                nlmsg_len: size_of::<NlMsgHdr>() as u32,
                nlmsg_type: NLMSG_DONE,
                nlmsg_flags: 0,
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            },
        );
        let mut addresses = Vec::new();
        assert!(parse_address_messages(&message, &mut addresses).unwrap());
        assert_eq!(
            addresses,
            vec![Address {
                interface_index: 3,
                address: IpAddr::V6(Ipv6Addr::from(octets)),
                prefix_length: 64,
            }]
        );
    }

    #[test]
    fn parses_address_added_event() {
        let events = parse_network_events(&address_message(
            RTM_NEWADDR,
            AF_INET,
            4,
            24,
            &[198, 51, 100, 7],
        ))
        .unwrap();
        assert_eq!(
            events,
            vec![NetworkEvent::Address(AddressEvent {
                kind: AddressEventKind::Added,
                address: Address {
                    interface_index: 4,
                    address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                    prefix_length: 24,
                },
            })]
        );
    }

    #[test]
    fn parses_address_removed_event() {
        let events = parse_network_events(&address_message(
            RTM_DELADDR,
            AF_INET,
            5,
            32,
            &[203, 0, 113, 9],
        ))
        .unwrap();
        assert_eq!(
            events,
            vec![NetworkEvent::Address(AddressEvent {
                kind: AddressEventKind::Removed,
                address: Address {
                    interface_index: 5,
                    address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                    prefix_length: 32,
                },
            })]
        );
    }

    #[test]
    fn rejects_truncated_address_message() {
        let mut message = Vec::new();
        push_struct(
            &mut message,
            &NlMsgHdr {
                nlmsg_len: (size_of::<NlMsgHdr>() + 2) as u32,
                nlmsg_type: RTM_NEWADDR,
                nlmsg_flags: 0,
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            },
        );
        message.extend_from_slice(&[AF_INET, 24]);
        assert!(matches!(
            parse_network_events(&message),
            Err(NetlinkError::MalformedMessage(_))
        ));
    }

    #[test]
    fn rejects_malformed_address_attributes() {
        let mut message = address_message(RTM_NEWADDR, AF_INET, 6, 24, &[192, 0, 2, 1]);
        let attr_offset = size_of::<NlMsgHdr>() + size_of::<IfAddrMsg>();
        message[attr_offset] = 1;
        message[attr_offset + 1] = 0;
        assert!(matches!(
            parse_network_events(&message),
            Err(NetlinkError::MalformedMessage(_))
        ));
    }

    #[test]
    fn ignores_unsupported_address_family() {
        let events =
            parse_network_events(&address_message(RTM_NEWADDR, 42, 7, 24, &[1, 2, 3, 4])).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parses_multiple_mixed_messages_in_one_buffer() {
        let mut message = link_message(RTM_NEWLINK, NLM_F_CREATE, 21, b"mix0\0", 0x1);
        message.extend_from_slice(&address_message(
            RTM_NEWADDR,
            AF_INET,
            21,
            24,
            &[10, 0, 0, 1],
        ));
        message.extend_from_slice(&address_message(
            RTM_DELADDR,
            AF_INET6,
            21,
            64,
            &[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ));

        let events = parse_network_events(&message).unwrap();
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0], NetworkEvent::Link(_)));
        assert!(matches!(
            events[1],
            NetworkEvent::Address(AddressEvent {
                kind: AddressEventKind::Added,
                ..
            })
        ));
        assert!(matches!(
            events[2],
            NetworkEvent::Address(AddressEvent {
                kind: AddressEventKind::Removed,
                ..
            })
        ));
    }
}
