use std::ffi::c_void;
use std::fmt;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::daemon::NetworkBackend;

const AF_NETLINK: i32 = 16;
const SOCK_RAW: i32 = 3;
const NETLINK_ROUTE: i32 = 0;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
const RTM_GETLINK: u16 = 18;
const RTM_NEWLINK: u16 = 16;
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const NLMSG_ALIGNTO: usize = 4;
const RTA_ALIGNTO: usize = 4;

#[repr(C)]
struct SockAddrNl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
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
struct RtAttr {
    rta_len: u16,
    rta_type: u16,
}

unsafe extern "C" {
    fn socket(domain: i32, typ: i32, protocol: i32) -> i32;
    fn bind(sockfd: i32, addr: *const SockAddrNl, addrlen: u32) -> i32;
    fn send(sockfd: i32, buf: *const c_void, len: usize, flags: i32) -> isize;
    fn recv(sockfd: i32, buf: *mut c_void, len: usize, flags: i32) -> isize;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link {
    pub index: i32,
    pub name: String,
    pub flags: LinkFlags,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkFlags(u32);

impl LinkFlags {
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn is_up(self) -> bool {
        self.0 & 0x1 != 0
    }

    pub const fn is_loopback(self) -> bool {
        self.0 & 0x8 != 0
    }
}

#[derive(Debug)]
pub enum NetlinkError {
    Io(io::Error),
    Kernel(i32),
    MalformedMessage(&'static str),
}

impl fmt::Display for NetlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "netlink I/O failed: {err}"),
            Self::Kernel(code) => write!(f, "kernel returned netlink error {code}"),
            Self::MalformedMessage(msg) => write!(f, "malformed netlink message: {msg}"),
        }
    }
}

impl std::error::Error for NetlinkError {}

impl From<io::Error> for NetlinkError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
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
    // SAFETY: socket is called with constant arguments and checked for a negative return value.
    let raw = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: raw is a newly-created file descriptor owned by this function.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let addr = SockAddrNl {
        nl_family: AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };
    // SAFETY: addr points to a valid SockAddrNl for the duration of the call.
    let rc = unsafe { bind(fd.as_raw_fd(), &addr, size_of::<SockAddrNl>() as u32) };
    if rc < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(fd)
}

fn send_all(fd: i32, bytes: &[u8]) -> Result<(), NetlinkError> {
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

fn recv_into(fd: i32, buf: &mut [u8]) -> Result<usize, NetlinkError> {
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

fn parse_kernel_error(payload: &[u8]) -> NetlinkError {
    if payload.len() < size_of::<i32>() {
        return NetlinkError::MalformedMessage("short nlmsgerr");
    }
    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(&payload[..4]);
    NetlinkError::Kernel(i32::from_ne_bytes(bytes))
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

fn read_unaligned<T: Copy>(bytes: &[u8]) -> Result<T, NetlinkError> {
    if bytes.len() < size_of::<T>() {
        return Err(NetlinkError::MalformedMessage("short structured data"));
    }
    let ptr = bytes.as_ptr().cast::<T>();
    // SAFETY: length is checked above and read_unaligned permits unaligned packet data.
    Ok(unsafe { ptr.read_unaligned() })
}

const fn align(len: usize, to: usize) -> usize {
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

    #[test]
    fn parses_link_dump_fixture() {
        let mut message = Vec::new();
        let name = b"eth0\0";
        let attr_len = size_of::<RtAttr>() + name.len();
        let payload_len = size_of::<IfInfoMsg>() + align(attr_len, RTA_ALIGNTO);
        let header = NlMsgHdr {
            nlmsg_len: (size_of::<NlMsgHdr>() + payload_len) as u32,
            nlmsg_type: RTM_NEWLINK,
            nlmsg_flags: 0,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        };
        push_struct(&mut message, &header);
        push_struct(
            &mut message,
            &IfInfoMsg {
                ifi_family: 0,
                __ifi_pad: 0,
                ifi_type: 1,
                ifi_index: 7,
                ifi_flags: 0x1,
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
    }
}
