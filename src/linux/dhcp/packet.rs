//! BOOTP/DHCP packet codec (RFC 2131, RFC 2132).
//!
//! Self-contained, no external dependencies. Serialization and parsing are
//! symmetric and covered by round-trip tests so the client and the test
//! server can talk over a real socket using the same codec.

use std::net::Ipv4Addr;

use crate::connection::ip::{DhcpError, DhcpLease};

/// Server UDP port (67).
pub const BOOTP_SERVER_PORT: u16 = 67;
/// Client UDP port (68).
pub const BOOTP_CLIENT_PORT: u16 = 68;

const OP_BOOTREQUEST: u8 = 1;
const OP_BOOTREPLY: u8 = 2;
const HTYPE_ETHERNET: u8 = 1;
const HLEN_ETHERNET: u8 = 6;
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
/// BOOTP fixed header size (fields up to and including `file`).
const FIXED_LENGTH: usize = 236;
/// Fixed header + magic cookie; options start here.
const OPTIONS_OFFSET: usize = FIXED_LENGTH + 4;

const OPTION_PAD: u8 = 0;
const OPTION_SUBNET_MASK: u8 = 1;
const OPTION_ROUTER: u8 = 3;
const OPTION_DNS: u8 = 6;
const OPTION_HOSTNAME: u8 = 12;
const OPTION_DOMAIN_NAME: u8 = 15;
const OPTION_REQUESTED_IP: u8 = 50;
const OPTION_LEASE_TIME: u8 = 51;
const OPTION_MESSAGE_TYPE: u8 = 53;
const OPTION_SERVER_ID: u8 = 54;
const OPTION_T1: u8 = 58;
const OPTION_T2: u8 = 59;
const OPTION_END: u8 = 255;

/// DHCP message type (option 53).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DhcpMessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    Unknown(u8),
}

impl DhcpMessageType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
            Self::Unknown(value) => value,
        }
    }
}

/// A parsed BOOTP/DHCP message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhcpPacket {
    pub op: u8,
    pub xid: u32,
    pub flags: u16,
    pub ciaddr: [u8; 4],
    pub yiaddr: [u8; 4],
    pub siaddr: [u8; 4],
    pub giaddr: [u8; 4],
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub options: Vec<(u8, Vec<u8>)>,
}

fn copy4(target: &mut [u8; 4], value: Ipv4Addr) {
    target.copy_from_slice(&value.octets());
}

fn as_ipv4(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

fn base_packet(
    op: u8,
    xid: u32,
    flags: u16,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    mac: [u8; 6],
) -> DhcpPacket {
    let mut chaddr = [0_u8; 16];
    chaddr[..6].copy_from_slice(&mac);
    let mut packet = DhcpPacket {
        op,
        xid,
        flags,
        ciaddr: [0; 4],
        yiaddr: [0; 4],
        siaddr: [0; 4],
        giaddr: [0; 4],
        chaddr,
        sname: [0; 64],
        file: [0; 128],
        options: Vec::new(),
    };
    copy4(&mut packet.ciaddr, ciaddr);
    copy4(&mut packet.yiaddr, yiaddr);
    packet
}

/// Encodes a list of DHCP options as raw bytes (with pad bytes and END).
pub fn build_options(entries: Vec<(u8, Vec<u8>)>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (code, value) in entries {
        if code == OPTION_PAD || code == OPTION_END {
            continue;
        }
        bytes.push(code);
        bytes.push(value.len() as u8);
        bytes.extend_from_slice(&value);
    }
    bytes.push(OPTION_END);
    bytes
}

fn serialize_with_options(packet: &DhcpPacket, extra_options: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(OPTIONS_OFFSET + 64);
    bytes.push(packet.op);
    bytes.push(HTYPE_ETHERNET);
    bytes.push(HLEN_ETHERNET);
    bytes.push(0);
    bytes.extend_from_slice(&packet.xid.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&packet.flags.to_be_bytes());
    bytes.extend_from_slice(&packet.ciaddr);
    bytes.extend_from_slice(&packet.yiaddr);
    bytes.extend_from_slice(&packet.siaddr);
    bytes.extend_from_slice(&packet.giaddr);
    bytes.extend_from_slice(&packet.chaddr);
    bytes.extend_from_slice(&packet.sname);
    bytes.extend_from_slice(&packet.file);
    bytes.extend_from_slice(&MAGIC_COOKIE);
    let mut options = packet.options.clone();
    options.extend_from_slice(extra_options);
    bytes.extend_from_slice(&build_options(options));
    bytes
}

/// Serializes a packet to raw UDP payload bytes.
pub fn serialize(packet: &DhcpPacket) -> Vec<u8> {
    serialize_with_options(packet, &[])
}

/// Parses a raw UDP payload into a [`DhcpPacket`], validating the magic cookie.
pub fn parse(bytes: &[u8]) -> Result<DhcpPacket, DhcpError> {
    if bytes.len() < OPTIONS_OFFSET {
        return Err(DhcpError::MalformedPacket(
            "packet shorter than fixed header",
        ));
    }
    if bytes[OPTIONS_OFFSET - 4..OPTIONS_OFFSET] != MAGIC_COOKIE {
        return Err(DhcpError::MalformedPacket("missing DHCP magic cookie"));
    }
    let mut options = Vec::new();
    let mut offset = OPTIONS_OFFSET;
    while offset < bytes.len() {
        let code = bytes[offset];
        if code == OPTION_END {
            break;
        }
        if code == OPTION_PAD {
            offset += 1;
            continue;
        }
        if offset + 2 > bytes.len() {
            return Err(DhcpError::MalformedPacket("truncated DHCP option header"));
        }
        let len = bytes[offset + 1] as usize;
        if offset + 2 + len > bytes.len() {
            return Err(DhcpError::MalformedPacket("truncated DHCP option value"));
        }
        options.push((code, bytes[offset + 2..offset + 2 + len].to_vec()));
        offset += 2 + len;
    }

    let mut chaddr = [0_u8; 16];
    chaddr.copy_from_slice(&bytes[28..44]);
    let mut sname = [0_u8; 64];
    sname.copy_from_slice(&bytes[44..108]);
    let mut file = [0_u8; 128];
    file.copy_from_slice(&bytes[108..236]);

    let mut ciaddr = [0_u8; 4];
    ciaddr.copy_from_slice(&bytes[12..16]);
    let mut yiaddr = [0_u8; 4];
    yiaddr.copy_from_slice(&bytes[16..20]);
    let mut siaddr = [0_u8; 4];
    siaddr.copy_from_slice(&bytes[20..24]);
    let mut giaddr = [0_u8; 4];
    giaddr.copy_from_slice(&bytes[24..28]);

    let mut xid_bytes = [0_u8; 4];
    xid_bytes.copy_from_slice(&bytes[4..8]);
    let mut flags_bytes = [0_u8; 2];
    flags_bytes.copy_from_slice(&bytes[10..12]);

    Ok(DhcpPacket {
        op: bytes[0],
        xid: u32::from_be_bytes(xid_bytes),
        flags: u16::from_be_bytes(flags_bytes),
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        chaddr,
        sname,
        file,
        options,
    })
}

impl DhcpPacket {
    /// Builds a DISCOVER request as raw bytes.
    pub fn build_discover(
        xid: u32,
        mac: [u8; 6],
        hostname: Option<&str>,
        requested_address: Option<Ipv4Addr>,
    ) -> Vec<u8> {
        let mut options = vec![(OPTION_MESSAGE_TYPE, vec![DhcpMessageType::Discover.as_u8()])];
        if let Some(hostname) = hostname {
            options.push((OPTION_HOSTNAME, hostname.as_bytes().to_vec()));
        }
        if let Some(address) = requested_address {
            options.push((OPTION_REQUESTED_IP, address.octets().to_vec()));
        }
        let packet = base_packet(
            OP_BOOTREQUEST,
            xid,
            0x8000,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            mac,
        );
        serialize_with_options(&packet, &options)
    }

    /// Builds a REQUEST confirming the offered address.
    pub fn build_request(
        xid: u32,
        mac: [u8; 6],
        requested_address: Option<Ipv4Addr>,
        server_identifier: Option<Ipv4Addr>,
        hostname: Option<&str>,
    ) -> Vec<u8> {
        let mut options = vec![(OPTION_MESSAGE_TYPE, vec![DhcpMessageType::Request.as_u8()])];
        if let Some(address) = requested_address {
            options.push((OPTION_REQUESTED_IP, address.octets().to_vec()));
        }
        if let Some(server) = server_identifier {
            options.push((OPTION_SERVER_ID, server.octets().to_vec()));
        }
        if let Some(hostname) = hostname {
            options.push((OPTION_HOSTNAME, hostname.as_bytes().to_vec()));
        }
        let packet = base_packet(
            OP_BOOTREQUEST,
            xid,
            0x8000,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            mac,
        );
        serialize_with_options(&packet, &options)
    }

    /// Builds a RELEASE for a lease the client no longer needs.
    pub fn build_release(
        xid: u32,
        mac: [u8; 6],
        address: Ipv4Addr,
        server_identifier: Ipv4Addr,
    ) -> Vec<u8> {
        let options = vec![
            (OPTION_MESSAGE_TYPE, vec![DhcpMessageType::Release.as_u8()]),
            (OPTION_SERVER_ID, server_identifier.octets().to_vec()),
        ];
        let packet = base_packet(OP_BOOTREQUEST, xid, 0, address, Ipv4Addr::UNSPECIFIED, mac);
        serialize_with_options(&packet, &options)
    }

    /// Builds a server reply (used by the test DHCP server).
    pub fn build_reply(
        message_type: DhcpMessageType,
        xid: u32,
        mac: [u8; 6],
        yiaddr: Ipv4Addr,
        extra_options: &[(u8, Vec<u8>)],
    ) -> Vec<u8> {
        let mut packet = base_packet(OP_BOOTREPLY, xid, 0, Ipv4Addr::UNSPECIFIED, yiaddr, mac);
        packet.options = vec![(OPTION_MESSAGE_TYPE, vec![message_type.as_u8()])];
        packet.options.extend_from_slice(extra_options);
        serialize(&packet)
    }

    pub fn message_type(&self) -> DhcpMessageType {
        self.get_option(OPTION_MESSAGE_TYPE)
            .and_then(|bytes| bytes.first().copied())
            .map(DhcpMessageType::from_u8)
            .unwrap_or(DhcpMessageType::Unknown(0))
    }

    pub fn get_option(&self, code: u8) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, value)| value.as_slice())
    }

    pub fn hardware_address(&self) -> [u8; 6] {
        let mut mac = [0_u8; 6];
        mac.copy_from_slice(&self.chaddr[..6]);
        mac
    }

    pub fn yiaddr(&self) -> Option<Ipv4Addr> {
        let address = as_ipv4(&self.yiaddr);
        (!address.is_unspecified()).then_some(address)
    }

    pub fn ciaddr(&self) -> Option<Ipv4Addr> {
        let address = as_ipv4(&self.ciaddr);
        (!address.is_unspecified()).then_some(address)
    }

    pub fn source_address(&self) -> Option<Ipv4Addr> {
        let address = as_ipv4(&self.siaddr);
        (!address.is_unspecified()).then_some(address)
    }

    pub fn subnet_mask(&self) -> Option<Ipv4Addr> {
        self.get_option(OPTION_SUBNET_MASK)
            .filter(|bytes| bytes.len() == 4)
            .map(as_ipv4)
    }

    pub fn routers(&self) -> Vec<Ipv4Addr> {
        self.get_option(OPTION_ROUTER)
            .map(|bytes| bytes.chunks_exact(4).map(as_ipv4).collect())
            .unwrap_or_default()
    }

    pub fn dns_servers(&self) -> Vec<Ipv4Addr> {
        self.get_option(OPTION_DNS)
            .map(|bytes| bytes.chunks_exact(4).map(as_ipv4).collect())
            .unwrap_or_default()
    }

    fn string_option(&self, code: u8) -> Option<String> {
        self.get_option(code).map(|bytes| {
            let end = bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(bytes.len());
            String::from_utf8_lossy(&bytes[..end]).trim().to_string()
        })
    }

    pub fn hostname(&self) -> Option<String> {
        self.string_option(OPTION_HOSTNAME)
    }

    pub fn domain_name(&self) -> Option<String> {
        self.string_option(OPTION_DOMAIN_NAME)
    }

    fn u32_option(&self, code: u8) -> Option<u32> {
        self.get_option(code)
            .filter(|bytes| bytes.len() == 4)
            .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    pub fn lease_seconds(&self) -> Option<u32> {
        self.u32_option(OPTION_LEASE_TIME)
    }

    pub fn t1_seconds(&self) -> Option<u32> {
        self.u32_option(OPTION_T1)
    }

    pub fn t2_seconds(&self) -> Option<u32> {
        self.u32_option(OPTION_T2)
    }

    pub fn server_identifier(&self) -> Option<Ipv4Addr> {
        self.get_option(OPTION_SERVER_ID)
            .filter(|bytes| bytes.len() == 4)
            .map(as_ipv4)
    }

    /// Derives a lease from a validated DHCPACK.
    pub fn to_lease(
        &self,
        interface_index: i32,
        interface_name: &str,
        mac: [u8; 6],
    ) -> Result<DhcpLease, DhcpError> {
        let address = self
            .yiaddr()
            .ok_or(DhcpError::MalformedPacket("DHCPACK carried no address"))?;
        if self.hardware_address() != mac {
            return Err(DhcpError::MalformedPacket(
                "DHCPACK addressed to another client",
            ));
        }
        let netmask = self.subnet_mask().unwrap_or_else(|| {
            // RFC 2132 §3.3: when the mask is missing, use the classful default.
            let octets = address.octets();
            let mask = if octets[0] < 128 {
                [255, 0, 0, 0]
            } else if octets[0] < 192 {
                [255, 255, 0, 0]
            } else {
                [255, 255, 255, 0]
            };
            Ipv4Addr::from(mask)
        });
        let prefix_length = prefix_length_from_netmask(netmask);
        Ok(DhcpLease {
            interface_index,
            interface_name: interface_name.to_string(),
            address,
            prefix_length,
            netmask,
            gateway: self.routers().first().copied(),
            dns_servers: self.dns_servers(),
            search_domains: self
                .domain_name()
                .map(|domain| vec![domain])
                .unwrap_or_default(),
            server_identifier: self.server_identifier(),
            lease_seconds: self.lease_seconds(),
            t1_seconds: self.t1_seconds(),
            t2_seconds: self.t2_seconds(),
        })
    }
}

/// Counts the leading set bits of an IPv4 netmask (its prefix length).
pub fn prefix_length_from_netmask(netmask: Ipv4Addr) -> u8 {
    netmask
        .octets()
        .iter()
        .fold(0_u8, |count, byte| count + byte.leading_ones() as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_length_from_common_netmasks() {
        assert_eq!(
            prefix_length_from_netmask(Ipv4Addr::new(255, 255, 255, 0)),
            24
        );
        assert_eq!(
            prefix_length_from_netmask(Ipv4Addr::new(255, 255, 0, 0)),
            16
        );
        assert_eq!(prefix_length_from_netmask(Ipv4Addr::new(255, 0, 0, 0)), 8);
        assert_eq!(prefix_length_from_netmask(Ipv4Addr::new(0, 0, 0, 0)), 0);
    }

    #[test]
    fn message_type_round_trip() {
        for value in [1, 2, 3, 4, 5, 6, 7, 8, 99] {
            assert_eq!(DhcpMessageType::from_u8(value).as_u8(), value);
        }
        assert_eq!(DhcpMessageType::from_u8(99), DhcpMessageType::Unknown(99));
    }

    #[test]
    fn packet_round_trip_keeps_header_fields() {
        let mut packet = base_packet(
            OP_BOOTREQUEST,
            0xdead_beef,
            0x8000,
            Ipv4Addr::new(192, 168, 1, 50),
            Ipv4Addr::UNSPECIFIED,
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x0a],
        );
        packet.options = vec![(OPTION_MESSAGE_TYPE, vec![DhcpMessageType::Discover.as_u8()])];
        let bytes = serialize(&packet);
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.xid, 0xdead_beef);
        assert_eq!(parsed.flags, 0x8000);
        assert_eq!(parsed.ciaddr(), Some(Ipv4Addr::new(192, 168, 1, 50)));
        assert_eq!(
            parsed.hardware_address(),
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x0a]
        );
        assert_eq!(parsed.message_type(), DhcpMessageType::Discover);
    }
}
