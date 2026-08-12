//! Kernel facility access for the integration harness.
//!
//! The Rust-native replacement for `scripts/integration-netns.sh` needs four
//! kernel operations that have no in-crate userspace helper:
//!
//! 1. `unshare(2)` — create a private network + mount namespace;
//! 2. `mount(2)`  — make mounts private and mount an empty tmpfs over `/etc`;
//! 3. rtnetlink  — fabricate a `veth` pair (the virtual cable the DHCP test
//!    server and the DHCP client sit on);
//! 4. rtnetlink  — bring an interface up, and a `/proc` write to disable
//!    reverse-path filtering on the unaddressed client end.
//!
//! These are genuine kernel ABIs (not shelling out to `ip`/`ifconfig`), so the
//! raw FFI is kept here behind tiny safe wrappers. Every `unsafe` block
//! documents the invariant the surrounding safe code upholds. There is no C
//! source: the declarations below are the standard Linux syscall/struct ABIs.

use std::ffi::{c_char, c_void};
use std::io;
use std::mem::size_of;
use std::os::raw::c_int;

pub const CLONE_NEWNS: c_int = 0x0002_0000;
pub const CLONE_NEWNET: c_int = 0x4000_0000;
pub const MS_REC: usize = 0x0000_4000;
pub const MS_PRIVATE: usize = 0x0002_0000;

const AF_NETLINK: c_int = 16;
const SOCK_RAW: c_int = 3;
const NETLINK_ROUTE: c_int = 0;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_CREATE: u16 = 0x0400;
const NLM_F_EXCL: u16 = 0x0200;
const NLMSG_ERROR: u16 = 2;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const IFLA_VETH_PEER: u16 = 1;
const IFLA_NET_NS_PID: u16 = 19;
const RTA_ALIGNTO: usize = 4;
const IFF_UP: u32 = 0x0001;

unsafe extern "C" {
    fn unshare(flags: c_int) -> c_int;
    fn mount(
        source: *const c_char,
        target: *const c_char,
        fstype: *const c_char,
        flags: usize,
        data: *const c_char,
    ) -> c_int;
    fn socket(domain: c_int, typ: c_int, protocol: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn send(fd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize;
    fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
}

/// Returns `Ok(())` only if the process can create its own network namespace.
///
/// `unshare(CLONE_NEWNET)` needs `CAP_SYS_ADMIN` (or a user namespace that
/// provides it). On failure (typically `EPERM` when running unprivileged) the
/// harness reports a skip instead of mutating the host.
pub fn enter_private_netns() -> io::Result<()> {
    // SAFETY: unshare takes integer flags and has no pointer arguments; the
    // only possible effect on failure is that the process stays in its
    // current namespaces, which the caller already treated as "skip".
    let rc = unsafe { unshare(CLONE_NEWNET | CLONE_NEWNS) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Detaches the new mount namespace from the host's shared propagation so the
/// `tmpfs` mounted over `/etc` below cannot leak into the host (and host
/// mount events cannot re-appear here). This is the recipe from
/// `mount_namespaces(7)` for a namespace root, which forbids `MS_SLAVE` here.
pub fn make_mounts_private() -> io::Result<()> {
    // SAFETY: mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) carries no user
    // pointers to de-reference; on failure the caller aborts the test.
    let rc = unsafe {
        mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            MS_REC | MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Mounts an empty `tmpfs` over `/etc` so the DNS manager owns a disposable
/// `resolv.conf` and can never observe or overwrite the host's file.
pub fn mount_tmpfs_over_etc() -> io::Result<()> {
    // SAFETY: source/target are NUL-terminated string literals and fstype is
    // the "tmpfs" literal; the kernel copies them during the syscall. data is
    // NULL. This is a pure filesystem operation inside our private namespace.
    let rc = unsafe {
        mount(
            c"tmpfs".as_ptr(),
            c"/etc".as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Replaces the inherited `/proc` and `/sys` mounts with fresh ones.
///
/// The mount points the process inherited at boot reflect the *initial*
/// network namespace: `/proc/sys/net/...` and `/sys/class/net/...` would not
/// show the veth pair created after `unshare(CLONE_NEWNET)`. Remounting both
/// filesystems inside the already-private mount namespace gives a view of the
/// current namespace (this is exactly what `ip netns exec` does underneath).
pub fn mount_fresh_proc_and_sysfs() -> io::Result<()> {
    // SAFETY: source/fstype are NUL-terminated literals, target "/proc" is a
    // mount point inside our private namespace, data is NULL. On failure the
    // caller aborts the test.
    let rc = unsafe {
        mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: source/fstype are NUL-terminated literals, target "/sys" is a
    // mount point inside our private namespace, data is NULL.
    let rc = unsafe {
        mount(
            c"sysfs".as_ptr(),
            c"/sys".as_ptr(),
            c"sysfs".as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Disables reverse-path filtering on `ifname` via `/proc`.
///
/// The unaddressed DHCP client would otherwise drop the server's broadcast
/// OFFER because reverse-path lookup of its source address fails.
pub fn disable_rp_filter(ifname: &str) -> io::Result<()> {
    std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter"),
        b"0\n",
    )
}

/// Disables IPv6 duplicate-address detection on `ifname`.
///
/// An address that is still `tentative` cannot serve as the gateway for static
/// routes (the kernel reports the gateway subnet as unreachable until DAD
/// settles), which would make the IPv6 scenario depend on DAD timing.
pub fn disable_ipv6_dad(ifname: &str) -> io::Result<()> {
    std::fs::write(
        format!("/proc/sys/net/ipv6/conf/{ifname}/dad_transmits"),
        b"0\n",
    )
}

/// Disables IPv6 entirely on `ifname`.
///
/// Keeps the IPv4 route scenarios deterministic: without this, bringing the
/// veth up would auto-assign a `fe80::/64` link-local route that shows up in
/// the main table dump and breaks "exactly these routes" assertions.
pub fn disable_ipv6(ifname: &str) -> io::Result<()> {
    std::fs::write(
        format!("/proc/sys/net/ipv6/conf/{ifname}/disable_ipv6"),
        b"1\n",
    )
}

fn push_struct<T>(buf: &mut Vec<u8>, value: &T) {
    let ptr = value as *const T as *const u8;
    // SAFETY: value is valid for size_of::<T>() bytes while this copies it.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, size_of::<T>()) };
    buf.extend_from_slice(bytes);
}

fn push_attr(buf: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    let len = size_of::<RtAttr>() + value.len();
    push_struct(
        buf,
        &RtAttr {
            rta_len: len as u16,
            rta_type: attr_type,
        },
    );
    buf.extend_from_slice(value);
    let pad = align4(len) - len;
    buf.extend_from_slice(&[0; 4][..pad]);
}

const fn align4(value: usize) -> usize {
    (value + RTA_ALIGNTO - 1) & !(RTA_ALIGNTO - 1)
}

fn build_netlink_message(message_type: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
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

/// Sends `message` and waits for the kernel's `NLMSG_ERROR` acknowledgement.
fn transact_rtnetlink(message: &[u8]) -> io::Result<()> {
    // SAFETY: socket() with constant arguments; return value checked.
    let fd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        // SAFETY: message is a valid readable buffer; send() copies from it.
        let sent = unsafe { send(fd, message.as_ptr().cast(), message.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != message.len() {
            return Err(io::Error::other("short netlink send"));
        }
        let mut buf = [0_u8; 4096];
        loop {
            // SAFETY: buf is a writable buffer of 4096 bytes.
            let n = unsafe { recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let n = n as usize;
            let mut offset = 0;
            while offset + size_of::<NlMsgHdr>() <= n {
                let header = read_unaligned::<NlMsgHdr>(&buf[offset..]);
                let len = header.nlmsg_len as usize;
                if len < size_of::<NlMsgHdr>() || offset + len > n {
                    return Err(io::Error::other("bad netlink ack"));
                }
                let payload = &buf[offset + size_of::<NlMsgHdr>()..offset + len];
                if header.nlmsg_type == NLMSG_ERROR {
                    if payload.len() < size_of::<i32>() {
                        return Err(io::Error::other("short nlmsgerr"));
                    }
                    let mut bytes = [0_u8; 4];
                    bytes.copy_from_slice(&payload[..4]);
                    let code = i32::from_ne_bytes(bytes);
                    if code == 0 {
                        return Ok(());
                    }
                    return Err(io::Error::from_raw_os_error(-code));
                }
                offset += align4(len);
            }
        }
    })();
    // SAFETY: fd was created by socket() above and is no longer needed.
    unsafe { close(fd) };
    result
}

/// Creates a `veth` pair named `peer_a`/`peer_b` (both ends land in the
/// caller's current network namespace).
pub fn create_veth_pair(peer_a: &str, peer_b: &str) -> io::Result<()> {
    let mut peer = Vec::new();
    push_struct(
        &mut peer,
        &IfInfoMsg {
            ifi_family: 0,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: 0,
            ifi_flags: 0,
            ifi_change: 0,
        },
    );
    push_attr(&mut peer, IFLA_IFNAME, &c_string(peer_b));

    let mut data = Vec::new();
    push_attr(&mut data, IFLA_VETH_PEER, &peer);

    let mut link_info = Vec::new();
    push_attr(&mut link_info, IFLA_INFO_KIND, &c_string("veth"));
    push_attr(&mut link_info, IFLA_INFO_DATA, &data);

    let mut payload = Vec::new();
    push_struct(
        &mut payload,
        &IfInfoMsg {
            ifi_family: 0,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: 0,
            ifi_flags: 0,
            ifi_change: 0,
        },
    );
    push_attr(&mut payload, IFLA_IFNAME, &c_string(peer_a));
    push_attr(&mut payload, IFLA_LINKINFO, &link_info);

    let message = build_netlink_message(
        RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
        &payload,
    );
    transact_rtnetlink(&message)
}

/// A NUL-terminated byte copy of `value` for netlink string attributes.
fn c_string(value: &str) -> Vec<u8> {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

/// Deletes the link `index`, freeing its kernel state.
///
/// Used by the route scenarios to leave the harness namespace as clean as it
/// was found (a removed veth drops its addresses and routes with it).
pub fn remove_link(index: i32) -> io::Result<()> {
    let mut payload = Vec::new();
    push_struct(
        &mut payload,
        &IfInfoMsg {
            ifi_family: 0,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: index,
            ifi_flags: 0,
            ifi_change: 0,
        },
    );
    let message = build_netlink_message(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, &payload);
    transact_rtnetlink(&message)
}

/// Brings the link `index` up (`IFF_UP`).
pub fn bring_link_up(index: i32) -> io::Result<()> {
    let mut payload = Vec::new();
    push_struct(
        &mut payload,
        &IfInfoMsg {
            ifi_family: 0,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: index,
            ifi_flags: IFF_UP,
            ifi_change: u32::MAX,
        },
    );
    let message = build_netlink_message(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, &payload);
    transact_rtnetlink(&message)
}

/// Moves the link `ifindex` into the network namespace of process `pid`.
///
/// This is the raw-netlink equivalent of `ip link set ... netns <pid>` and is
/// what places the client veth end into the child helper's namespace, giving
/// the harness the two-namespace topology the DHCP exchange requires.
pub fn move_link_to_pid(ifindex: i32, pid: u32) -> io::Result<()> {
    let mut payload = Vec::new();
    push_struct(
        &mut payload,
        &IfInfoMsg {
            ifi_family: 0,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: ifindex,
            ifi_flags: 0,
            ifi_change: 0,
        },
    );
    push_attr(&mut payload, IFLA_NET_NS_PID, &(pid as i32).to_ne_bytes());
    let message = build_netlink_message(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, &payload);
    transact_rtnetlink(&message)
}

fn read_unaligned<T: Copy>(bytes: &[u8]) -> T {
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    // SAFETY: callers guarantee bytes.len() >= size_of::<T>(); copying bytes
    // into a correctly aligned local is the standard unaligned-read pattern.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            value.as_mut_ptr() as *mut u8,
            size_of::<T>(),
        );
        value.assume_init()
    }
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
struct RtAttr {
    rta_len: u16,
    rta_type: u16,
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
