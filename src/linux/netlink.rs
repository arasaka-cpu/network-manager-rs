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
    Address, AddressEvent, AddressEventKind, IpFamily, Link, LinkEvent, LinkEventKind, LinkFlags,
    NetlinkError, NetworkEvent, NetworkEventSource, Route, RouteEvent, RouteEventKind, RouteKind,
    RouteScope,
};

pub(crate) const AF_NETLINK: i32 = 16;
pub(crate) const SOCK_RAW: i32 = 3;
const NETLINK_ROUTE: i32 = 0;
pub(crate) const NLM_F_REQUEST: u16 = 0x0001;
pub(crate) const NLM_F_ACK: u16 = 0x0004;
pub(crate) const NLM_F_REPLACE: u16 = 0x0100;
pub(crate) const NLM_F_ROOT: u16 = 0x0100;
pub(crate) const NLM_F_MATCH: u16 = 0x0200;
pub(crate) const NLM_F_EXCL: u16 = 0x0200;
pub(crate) const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
pub(crate) const NLM_F_CREATE: u16 = 0x0400;
pub(crate) const RTM_GETLINK: u16 = 18;
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const IFLA_IFNAME: u16 = 3;
pub(crate) const IFA_ADDRESS: u16 = 1;
pub(crate) const IFA_LOCAL: u16 = 2;
pub(crate) const RTA_DST: u16 = 1;
pub(crate) const RTA_OIF: u16 = 4;
pub(crate) const RTA_GATEWAY: u16 = 5;
pub(crate) const RTA_PRIORITY: u16 = 6;
pub(crate) const RT_TABLE_MAIN: u8 = 254;
pub(crate) const RTN_UNICAST: u8 = 1;
pub(crate) const RTPROT_STATIC: u8 = 4;
pub(crate) const RT_SCOPE_LINK: u8 = 253;
pub(crate) const AF_INET: u8 = 2;
pub(crate) const AF_INET6: u8 = 10;
pub(crate) const RTM_NEWLINK: u16 = 16;
pub(crate) const RTM_DELLINK: u16 = 17;
pub(crate) const RTM_NEWADDR: u16 = 20;
pub(crate) const RTM_DELADDR: u16 = 21;
pub(crate) const RTM_GETADDR: u16 = 22;
pub(crate) const RTM_NEWROUTE: u16 = 24;
pub(crate) const RTM_DELROUTE: u16 = 25;
pub(crate) const RTM_GETROUTE: u16 = 26;
pub(crate) const NLMSG_ALIGNTO: usize = 4;
pub(crate) const RTA_ALIGNTO: usize = 4;
const RTMGRP_LINK: u32 = 1;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
const RTMGRP_IPV4_ROUTE: u32 = 0x40;
const RTMGRP_IPV6_ROUTE: u32 = 0x400;
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
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtAttr {
    rta_len: u16,
    rta_type: u16,
}

unsafe extern "C" {
    fn socket(domain: i32, typ: i32, protocol: i32) -> i32;
    fn bind(sockfd: i32, addr: *const c_void, addrlen: u32) -> i32;
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

    fn routes(&self) -> Result<Vec<Route>, NetlinkError> {
        get_routes()
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

pub fn get_routes() -> Result<Vec<Route>, NetlinkError> {
    let fd = open_route_socket()?;
    let request = RouteDumpRequest::new(3);
    send_all(fd.as_raw_fd(), request.as_bytes())?;

    let mut routes = Vec::new();
    let mut buf = vec![0_u8; 8192];
    loop {
        let n = recv_into(fd.as_raw_fd(), &mut buf)?;
        let done = parse_route_messages(&buf[..n], &mut routes)?;
        if done {
            routes.sort_by_key(|route| {
                (
                    route.family,
                    route.destination,
                    route.prefix_length,
                    route.metric,
                    route.output_interface,
                )
            });
            return Ok(routes);
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

#[repr(C)]
struct RouteDumpRequest {
    header: NlMsgHdr,
    info: RtMsg,
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

impl RouteDumpRequest {
    fn new(sequence: u32) -> Self {
        Self {
            header: NlMsgHdr {
                nlmsg_len: size_of::<Self>() as u32,
                nlmsg_type: RTM_GETROUTE,
                nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
                nlmsg_seq: sequence,
                nlmsg_pid: 0,
            },
            info: RtMsg {
                rtm_family: 0,
                rtm_dst_len: 0,
                rtm_src_len: 0,
                rtm_tos: 0,
                rtm_table: 0,
                rtm_protocol: 0,
                rtm_scope: 0,
                rtm_type: 0,
                rtm_flags: 0,
            },
        }
    }

    fn as_bytes(&self) -> &[u8] {
        let ptr = self as *const Self as *const u8;
        // SAFETY: RouteDumpRequest is repr(C), plain data, and lives for the returned slice lifetime.
        unsafe { std::slice::from_raw_parts(ptr, size_of::<Self>()) }
    }
}

fn open_route_socket() -> Result<OwnedFd, NetlinkError> {
    open_socket_with_groups(NETLINK_ROUTE, 0)
}

fn open_link_event_source() -> Result<RtnetlinkEventSource, NetlinkError> {
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
    let fd = open_socket_with_groups(
        NETLINK_ROUTE,
        RTMGRP_LINK
            | RTMGRP_IPV4_IFADDR
            | RTMGRP_IPV6_IFADDR
            | RTMGRP_IPV4_ROUTE
            | RTMGRP_IPV6_ROUTE,
    )?;
    set_nonblocking(fd.as_raw_fd())?;
    Ok(RtnetlinkEventSource {
        fd,
        buf: vec![0_u8; 8192],
        pending: Vec::new(),
    })
}

pub(crate) fn open_socket_with_groups(protocol: i32, groups: u32) -> Result<OwnedFd, NetlinkError> {
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
    let rc = unsafe {
        bind(
            fd.as_raw_fd(),
            (&addr as *const SockAddrNl).cast(),
            size_of::<SockAddrNl>() as u32,
        )
    };
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
    let updated = if enabled { flags | flag } else { flags & !flag };
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

fn push_struct<T>(buf: &mut Vec<u8>, value: &T) {
    let ptr = value as *const T as *const u8;
    // SAFETY: value is valid for size_of::<T>() bytes while this function copies it.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, size_of::<T>()) };
    buf.extend_from_slice(bytes);
}

/// Appends a netlink attribute (header + value, 4-byte aligned).
pub(crate) fn push_attr(message: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    let attr_len = size_of::<RtAttr>() + value.len();
    push_struct(
        message,
        &RtAttr {
            rta_len: attr_len as u16,
            rta_type: attr_type,
        },
    );
    message.extend_from_slice(value);
    let pad = align(attr_len, RTA_ALIGNTO) - attr_len;
    message.extend_from_slice(&[0; 4][..pad]);
}

/// Builds a single netlink message from a type, flags and raw payload.
pub(crate) fn build_netlink_message(message_type: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(size_of::<NlMsgHdr>() + payload.len());
    push_struct(
        &mut message,
        &NlMsgHdr {
            nlmsg_len: (size_of::<NlMsgHdr>() + payload.len()) as u32,
            nlmsg_type: message_type,
            nlmsg_flags: flags,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        },
    );
    message.extend_from_slice(payload);
    message
}

/// Builds an ifaddrmsg payload with the given attributes (e.g. IFA_LOCAL/IFA_ADDRESS).
pub(crate) fn ifaddr_payload(
    family: u8,
    prefix_length: u8,
    index: i32,
    attrs: &[(u16, Vec<u8>)],
) -> Vec<u8> {
    let mut payload = Vec::new();
    push_struct(
        &mut payload,
        &IfAddrMsg {
            ifa_family: family,
            ifa_prefixlen: prefix_length,
            ifa_flags: 0,
            ifa_scope: 0,
            ifa_index: index as u32,
        },
    );
    for (attr_type, value) in attrs {
        push_attr(&mut payload, *attr_type, value);
    }
    payload
}

/// Builds an rtmsg payload for the given family, scope, type and attributes.
pub(crate) fn rtmsg_payload(
    family: u8,
    dst_len: u8,
    table: u8,
    scope: u8,
    route_type: u8,
    attrs: &[(u16, Vec<u8>)],
) -> Vec<u8> {
    let mut payload = Vec::new();
    push_struct(
        &mut payload,
        &RtMsg {
            rtm_family: family,
            rtm_dst_len: dst_len,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: table,
            rtm_protocol: RTPROT_STATIC,
            rtm_scope: scope,
            rtm_type: route_type,
            rtm_flags: 0,
        },
    );
    for (attr_type, value) in attrs {
        push_attr(&mut payload, *attr_type, value);
    }
    payload
}

/// Sends a single request with `NLM_F_ACK` and waits for the kernel's error
/// reply, returning `Err(Kernel(code))` when the operation was rejected.
pub(crate) fn transact_rtnetlink(message: &[u8]) -> Result<(), NetlinkError> {
    let fd = open_route_socket()?;
    send_all(fd.as_raw_fd(), message)?;
    let mut buf = vec![0_u8; 4096];
    loop {
        let n = recv_into(fd.as_raw_fd(), &mut buf)?;
        let mut offset = 0;
        while offset + size_of::<NlMsgHdr>() <= n {
            let header = read_unaligned::<NlMsgHdr>(&buf[offset..])?;
            let len = header.nlmsg_len as usize;
            if len < size_of::<NlMsgHdr>() || offset + len > n {
                return Err(NetlinkError::MalformedMessage("invalid ack length"));
            }
            let payload = &buf[offset + size_of::<NlMsgHdr>()..offset + len];
            if header.nlmsg_type == NLMSG_ERROR {
                let error = parse_kernel_error_code(payload)?;
                if error == 0 {
                    return Ok(());
                }
                return Err(NetlinkError::Kernel(error));
            }
            offset += align(len, NLMSG_ALIGNTO);
        }
    }
}

fn parse_kernel_error_code(payload: &[u8]) -> Result<i32, NetlinkError> {
    if payload.len() < size_of::<i32>() {
        return Err(NetlinkError::MalformedMessage("short nlmsgerr"));
    }
    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(&payload[..4]);
    Ok(i32::from_ne_bytes(bytes))
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
            RTM_NEWROUTE => {
                if let Some(route) = parse_route(payload)? {
                    let kind = if header.nlmsg_flags & NLM_F_CREATE != 0 {
                        RouteEventKind::Added
                    } else {
                        RouteEventKind::Changed
                    };
                    events.push(NetworkEvent::Route(RouteEvent { kind, route }));
                }
            }
            RTM_DELROUTE => {
                if let Some(route) = parse_route(payload)? {
                    events.push(NetworkEvent::Route(RouteEvent {
                        kind: RouteEventKind::Removed,
                        route,
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
    match parse_kernel_error_code(payload) {
        Ok(code) => NetlinkError::Kernel(code),
        Err(err) => err,
    }
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

fn parse_route_messages(buf: &[u8], routes: &mut Vec<Route>) -> Result<bool, NetlinkError> {
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
            RTM_NEWROUTE => {
                if let Some(route) = parse_route(payload)? {
                    routes.push(route);
                }
            }
            _ => {}
        }
        offset += align(len, NLMSG_ALIGNTO);
    }
    Ok(false)
}

fn parse_route(payload: &[u8]) -> Result<Option<Route>, NetlinkError> {
    if payload.len() < size_of::<RtMsg>() {
        return Err(NetlinkError::MalformedMessage("short rtmsg"));
    }
    let info = read_unaligned::<RtMsg>(payload)?;
    let family = match info.rtm_family {
        AF_INET => IpFamily::V4,
        AF_INET6 => IpFamily::V6,
        _ => return Ok(None),
    };
    let table = if info.rtm_table == 0 {
        RT_TABLE_MAIN
    } else {
        info.rtm_table
    };
    if table != RT_TABLE_MAIN {
        return Ok(None);
    }
    let kind = RouteKind::from_u8(info.rtm_type);
    if !matches!(
        kind,
        RouteKind::Unicast | RouteKind::Blackhole | RouteKind::Unreachable
    ) {
        return Ok(None);
    }

    let expected_len = match family {
        IpFamily::V4 => 4,
        IpFamily::V6 => 16,
    };
    let mut destination = None;
    let mut gateway = None;
    let mut output_interface = None;
    let mut metric = None;
    let mut offset = size_of::<RtMsg>();
    while offset + size_of::<RtAttr>() <= payload.len() {
        let attr = read_unaligned::<RtAttr>(&payload[offset..])?;
        let len = attr.rta_len as usize;
        if len < size_of::<RtAttr>() || offset + len > payload.len() {
            return Err(NetlinkError::MalformedMessage("invalid rtattr length"));
        }
        let value = &payload[offset + size_of::<RtAttr>()..offset + len];
        match attr.rta_type {
            RTA_DST => {
                if value.len() != expected_len {
                    return Err(NetlinkError::MalformedMessage(
                        "invalid route destination length",
                    ));
                }
                destination = Some(value.to_vec());
            }
            RTA_GATEWAY => {
                if value.len() != expected_len {
                    return Err(NetlinkError::MalformedMessage(
                        "invalid route gateway length",
                    ));
                }
                gateway = Some(value.to_vec());
            }
            RTA_OIF => {
                if value.len() != size_of::<u32>() {
                    return Err(NetlinkError::MalformedMessage("invalid route oif length"));
                }
                let mut bytes = [0_u8; 4];
                bytes.copy_from_slice(value);
                output_interface = Some(i32::from_ne_bytes(bytes));
            }
            RTA_PRIORITY => {
                if value.len() != size_of::<u32>() {
                    return Err(NetlinkError::MalformedMessage(
                        "invalid route metric length",
                    ));
                }
                let mut bytes = [0_u8; 4];
                bytes.copy_from_slice(value);
                metric = Some(u32::from_ne_bytes(bytes));
            }
            _ => {}
        }
        offset += align(len, RTA_ALIGNTO);
    }

    let destination = match destination {
        Some(bytes) => address_from_bytes(family, &bytes),
        None => match family {
            IpFamily::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpFamily::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
    };
    let gateway = gateway.map(|bytes| address_from_bytes(family, &bytes));

    Ok(Some(Route {
        family,
        destination,
        prefix_length: info.rtm_dst_len,
        gateway,
        output_interface,
        metric,
        kind,
        scope: RouteScope::from_u8(info.rtm_scope),
    }))
}

fn address_from_bytes(family: IpFamily, bytes: &[u8]) -> IpAddr {
    match family {
        IpFamily::V4 => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
        IpFamily::V6 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[..16]);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
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

    fn push_attr(message: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
        super::push_attr(message, attr_type, value);
    }

    fn route_message(
        message_type: u16,
        family: u8,
        dst_len: u8,
        table: u8,
        route_type: u8,
        scope: u8,
        attrs: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut attrs_bytes = Vec::new();
        for (attr_type, value) in attrs {
            push_attr(&mut attrs_bytes, *attr_type, value);
        }
        let payload_len = size_of::<RtMsg>() + attrs_bytes.len();
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
            &RtMsg {
                rtm_family: family,
                rtm_dst_len: dst_len,
                rtm_src_len: 0,
                rtm_tos: 0,
                rtm_table: table,
                rtm_protocol: 4,
                rtm_scope: scope,
                rtm_type: route_type,
                rtm_flags: 0,
            },
        );
        message.extend_from_slice(&attrs_bytes);
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

    #[test]
    fn parses_ipv4_default_route_enumeration() {
        let mut message = route_message(
            RTM_NEWROUTE,
            AF_INET,
            0,
            254,
            1,
            0,
            &[
                (RTA_GATEWAY, vec![192, 168, 1, 1]),
                (RTA_OIF, 3_i32.to_ne_bytes().to_vec()),
                (RTA_PRIORITY, 100_u32.to_ne_bytes().to_vec()),
            ],
        );
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

        let mut routes = Vec::new();
        assert!(parse_route_messages(&message, &mut routes).unwrap());
        assert_eq!(routes.len(), 1);
        assert!(routes[0].is_default());
        assert_eq!(routes[0].family, IpFamily::V4);
        assert_eq!(
            routes[0].gateway,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(routes[0].output_interface, Some(3));
        assert_eq!(routes[0].metric, Some(100));
        assert_eq!(routes[0].kind, RouteKind::Unicast);
        assert_eq!(routes[0].scope, RouteScope::Universe);
    }

    #[test]
    fn parses_ipv6_static_route_enumeration() {
        let destination = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let gateway = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut message = route_message(
            RTM_NEWROUTE,
            AF_INET6,
            48,
            254,
            1,
            0,
            &[
                (RTA_DST, destination.to_vec()),
                (RTA_GATEWAY, gateway.to_vec()),
                (RTA_OIF, 3_i32.to_ne_bytes().to_vec()),
            ],
        );
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

        let mut routes = Vec::new();
        assert!(parse_route_messages(&message, &mut routes).unwrap());
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].destination,
            IpAddr::V6(Ipv6Addr::from(destination))
        );
        assert_eq!(routes[0].prefix_length, 48);
        assert_eq!(routes[0].family, IpFamily::V6);
    }

    #[test]
    fn parses_route_added_and_removed_events() {
        let added = route_message(
            RTM_NEWROUTE,
            AF_INET,
            0,
            254,
            1,
            0,
            &[
                (RTA_GATEWAY, vec![10, 0, 0, 1]),
                (RTA_OIF, 4_i32.to_ne_bytes().to_vec()),
            ],
        );
        let events = parse_network_events(&added).unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            NetworkEvent::Route(RouteEvent {
                kind: RouteEventKind::Changed,
                ..
            })
        ));

        let removed = route_message(
            RTM_DELROUTE,
            AF_INET,
            0,
            254,
            1,
            0,
            &[
                (RTA_GATEWAY, vec![10, 0, 0, 1]),
                (RTA_OIF, 4_i32.to_ne_bytes().to_vec()),
            ],
        );
        let events = parse_network_events(&removed).unwrap();
        assert!(matches!(
            events[0],
            NetworkEvent::Route(RouteEvent {
                kind: RouteEventKind::Removed,
                ..
            })
        ));
    }

    #[test]
    fn route_dump_skips_non_main_tables_and_special_routes() {
        let in_local_table = route_message(RTM_NEWROUTE, AF_INET, 24, 255, 2, 0, &[]);
        let local_route = route_message(RTM_NEWROUTE, AF_INET, 24, 254, 2, 0, &[]);
        let unicast = route_message(RTM_NEWROUTE, AF_INET, 24, 254, 1, 253, &[]);
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&in_local_table);
        buffer.extend_from_slice(&local_route);
        buffer.extend_from_slice(&unicast);

        let routes = parse_network_events(&buffer).unwrap();
        assert_eq!(
            routes.len(),
            1,
            "only the main-table unicast route is reported"
        );
        match &routes[0] {
            NetworkEvent::Route(RouteEvent { route, .. }) => {
                assert_eq!(route.kind, RouteKind::Unicast);
                assert_eq!(route.scope, RouteScope::Link);
            }
            _ => panic!("expected a route event"),
        }
    }

    #[test]
    fn rejects_malformed_route_attributes() {
        let mut message = route_message(
            RTM_NEWROUTE,
            AF_INET,
            0,
            254,
            1,
            0,
            &[(RTA_GATEWAY, vec![10, 0, 0, 1])],
        );
        let attr_offset = size_of::<NlMsgHdr>() + size_of::<RtMsg>();
        message[attr_offset] = 1;
        message[attr_offset + 1] = 0;
        assert!(matches!(
            parse_network_events(&message),
            Err(NetlinkError::MalformedMessage(_))
        ));
    }

    #[test]
    fn builds_ipv4_address_request() {
        let message = build_netlink_message(
            RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
            &ifaddr_payload(
                AF_INET,
                24,
                5,
                &[
                    (IFA_LOCAL, vec![10, 0, 0, 5]),
                    (IFA_ADDRESS, vec![10, 0, 0, 5]),
                ],
            ),
        );
        let header = read_unaligned::<NlMsgHdr>(&message).unwrap();
        assert_eq!(header.nlmsg_type, RTM_NEWADDR);
        assert_eq!(
            header.nlmsg_flags,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK
        );
        assert_eq!(header.nlmsg_len as usize, message.len());
        let info = read_unaligned::<IfAddrMsg>(&message[size_of::<NlMsgHdr>()..]).unwrap();
        assert_eq!(info.ifa_family, AF_INET);
        assert_eq!(info.ifa_prefixlen, 24);
        assert_eq!(info.ifa_index, 5);
    }

    #[test]
    fn builds_route_request_with_attributes() {
        let message = build_netlink_message(
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK,
            &rtmsg_payload(
                AF_INET,
                24,
                RT_TABLE_MAIN,
                RT_SCOPE_LINK,
                RTN_UNICAST,
                &[
                    (RTA_DST, vec![192, 168, 5, 0]),
                    (RTA_OIF, 5_i32.to_ne_bytes().to_vec()),
                ],
            ),
        );
        let info = read_unaligned::<RtMsg>(&message[size_of::<NlMsgHdr>()..]).unwrap();
        assert_eq!(info.rtm_family, AF_INET);
        assert_eq!(info.rtm_dst_len, 24);
        assert_eq!(info.rtm_table, RT_TABLE_MAIN);
        assert_eq!(info.rtm_scope, RT_SCOPE_LINK);
        assert_eq!(info.rtm_type, RTN_UNICAST);
        assert_eq!(info.rtm_protocol, RTPROT_STATIC);
    }

    #[test]
    fn ack_transaction_interprets_kernel_error_codes() {
        assert_eq!(parse_kernel_error_code(&0_i32.to_ne_bytes()).unwrap(), 0);
        assert_eq!(
            parse_kernel_error_code(&(-17_i32).to_ne_bytes()).unwrap(),
            -17
        );
        assert!(matches!(
            parse_kernel_error_code(&[]),
            Err(NetlinkError::MalformedMessage(_))
        ));

        let failure = {
            let mut message = Vec::new();
            push_struct(
                &mut message,
                &NlMsgHdr {
                    nlmsg_len: (size_of::<NlMsgHdr>() + size_of::<i32>()) as u32,
                    nlmsg_type: NLMSG_ERROR,
                    nlmsg_flags: 0,
                    nlmsg_seq: 1,
                    nlmsg_pid: 0,
                },
            );
            push_struct(&mut message, &(-17_i32));
            message
        };
        let events = parse_network_events(&failure);
        assert!(matches!(
            events,
            Err(NetlinkError::Kernel(code)) if code == -17
        ));
    }
}
