#![cfg_attr(not(target_os = "linux"), allow(unused))]

pub mod daemon;
pub mod linux;

pub use daemon::{Daemon, NetworkBackend};
pub use linux::netlink::{
    Address, AddressEvent, AddressEventKind, Link, LinkEvent, LinkEventKind, LinkFlags,
    NetlinkError, NetworkEvent, NetworkEventSource, RtnetlinkBackend,
};
