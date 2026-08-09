//! Read-only nl80211 access over the generic netlink (genl) socket.
//!
//! This module implements just enough of the cfg80211/nl80211 wire protocol to
//! support Wi-Fi discovery: family resolution, wiphy/interface dumps, scan
//! triggering, scan-result dumps, and scan multicast events. All parsing is
//! performed by pure functions over byte buffers so it can be tested
//! deterministically without wireless hardware.

use std::mem::size_of;
use std::os::fd::{AsRawFd, OwnedFd};

use crate::linux::model::{
    AccessPoint, AccessPointSecurity, Bssid, InterfaceType, NetlinkError, Ssid, WifiAuthSuite,
    WifiBand, WifiBandId, WifiCapabilities, WifiCipher, WifiEvent, WifiEventKind,
    WirelessInterface, frequency_to_channel,
};
use crate::linux::netlink::{
    NlMsgHdr, align, open_socket_with_groups, parse_kernel_error, read_unaligned, recv_into,
    send_all, set_nonblocking,
};

const NETLINK_GENERIC: i32 = 16;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_DUMP: u16 = 0x0300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = 0x3fff;
const NLA_ALIGNTO: usize = 4;
const GENL_HDRLEN: usize = 4;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

const NL80211_CMD_GET_WIPHY: u8 = 1;
const NL80211_CMD_NEW_WIPHY: u8 = 3;
const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_NEW_INTERFACE: u8 = 7;
const NL80211_CMD_GET_SCAN: u8 = 32;
const NL80211_CMD_TRIGGER_SCAN: u8 = 33;
const NL80211_CMD_NEW_SCAN_RESULTS: u8 = 34;
const NL80211_CMD_SCAN_ABORTED: u8 = 35;

const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_WIPHY_NAME: u16 = 2;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_WIPHY_BANDS: u16 = 22;
const NL80211_ATTR_SUPPORTED_IFTYPES: u16 = 32;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_MAX_NUM_SCAN_SSIDS: u16 = 43;
const NL80211_ATTR_BSS: u16 = 47;
const NL80211_ATTR_SSID: u16 = 52;
const NL80211_ATTR_CIPHER_SUITES: u16 = 57;

const NL80211_BSS_BSSID: u16 = 1;
const NL80211_BSS_FREQUENCY: u16 = 2;
const NL80211_BSS_CAPABILITY: u16 = 5;
const NL80211_BSS_INFORMATION_ELEMENTS: u16 = 6;
const NL80211_BSS_SIGNAL_MBM: u16 = 7;
const NL80211_BSS_SIGNAL_UNSPEC: u16 = 8;
const NL80211_BSS_SEEN_MS_AGO: u16 = 10;
const NL80211_BSS_BEACON_IES: u16 = 11;

const NL80211_BAND_ATTR_FREQS: u16 = 1;
const NL80211_BAND_ATTR_HT_CAPA: u16 = 4;
const NL80211_BAND_ATTR_VHT_CAPA: u16 = 8;

const NL80211_FREQUENCY_ATTR_FREQ: u16 = 1;
const NL80211_FREQUENCY_ATTR_DISABLED: u16 = 2;

const IE_SSID: u8 = 0;
const IE_RSN: u8 = 48;
const IE_VENDOR: u8 = 221;
const WPA_OUI: [u8; 3] = [0x00, 0x50, 0xf2];
const WPA_OUI_TYPE: u8 = 1;

/// Privacy bit in the 802.11 capability field (indicates WEP when no
/// RSN/WPA information element is present).
const BSS_CAPABILITY_PRIVACY: u16 = 0x0010;
/// RSN capability bits for management frame protection.
const RSN_CAPABILITY_MFP: u16 = 0x00c0;

const IE_MAX_SSID_LEN: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
struct GenlHdr {
    cmd: u8,
    version: u8,
    reserved: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlAttr {
    nla_len: u16,
    nla_type: u16,
}

/// A decoded netlink attribute with an owned payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawAttr {
    pub typ: u16,
    pub nested: bool,
    pub payload: Vec<u8>,
}

/// A decoded generic netlink message with an owned payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawMsg {
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub cmd: Option<u8>,
    pub attrs: Vec<RawAttr>,
    /// Raw netlink payload after the message header.
    pub payload: Vec<u8>,
}

/// Resolved generic netlink family information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FamilyInfo {
    pub id: u16,
    pub mcast_groups: Vec<(String, u32)>,
}

/// A connected generic netlink socket for nl80211 operations.
pub struct Nl80211Connection {
    fd: OwnedFd,
    family_id: u16,
    buf: Vec<u8>,
}

impl Nl80211Connection {
    /// Opens a generic netlink socket, resolves the nl80211 family, and
    /// subscribes to the "scan" multicast group so scan events are received.
    pub fn open() -> Result<Self, NetlinkError> {
        let family = resolve_nl80211_family()?;
        let groups = family
            .mcast_groups
            .iter()
            .find(|(name, _)| name == "scan")
            .map(|(_, id)| *id)
            .unwrap_or(0);
        let fd = open_socket_with_groups(NETLINK_GENERIC, groups)?;
        Ok(Self {
            fd,
            family_id: family.id,
            buf: vec![0_u8; 65536],
        })
    }

    pub fn set_nonblocking(&self) -> Result<(), NetlinkError> {
        set_nonblocking(self.fd.as_raw_fd())
    }

    /// Dumps all nl80211 interfaces known to the kernel.
    pub fn dump_interfaces(&mut self) -> Result<Vec<WirelessInterface>, NetlinkError> {
        let mut out = Vec::new();
        for message in self.transact_dump(NL80211_CMD_GET_INTERFACE, &[])? {
            if message.cmd == Some(NL80211_CMD_GET_INTERFACE)
                || message.cmd == Some(NL80211_CMD_NEW_INTERFACE)
            {
                if let Some(interface) = interface_from_attrs(&message.attrs)? {
                    out.push(interface);
                }
            }
        }
        out.sort_by_key(|interface| interface.index);
        Ok(out)
    }

    /// Dumps all wiphys together with their capabilities.
    pub fn dump_wiphys(&mut self) -> Result<Vec<WiphyInfo>, NetlinkError> {
        let mut out = Vec::new();
        for message in self.transact_dump(NL80211_CMD_GET_WIPHY, &[])? {
            if message.cmd == Some(NL80211_CMD_GET_WIPHY)
                || message.cmd == Some(NL80211_CMD_NEW_WIPHY)
            {
                if let Some(wiphy) = wiphy_from_attrs(&message.attrs)? {
                    out.push(wiphy);
                }
            }
        }
        out.sort_by_key(|wiphy| wiphy.index);
        Ok(out)
    }

    /// Triggers an active scan on the given interface (read-only).
    pub fn trigger_scan(&mut self, ifindex: i32) -> Result<(), NetlinkError> {
        let attrs = [(
            NL80211_ATTR_IFINDEX,
            (ifindex as u32).to_ne_bytes().to_vec(),
        )];
        self.transact_ack(NL80211_CMD_TRIGGER_SCAN, &attrs)
    }

    /// Dumps the current scan results (cached BSSes) for an interface.
    pub fn dump_scan(&mut self, ifindex: i32) -> Result<Vec<AccessPoint>, NetlinkError> {
        let attrs = [(
            NL80211_ATTR_IFINDEX,
            (ifindex as u32).to_ne_bytes().to_vec(),
        )];
        let mut out = Vec::new();
        for message in self.transact_dump(NL80211_CMD_GET_SCAN, &attrs)? {
            if message.cmd == Some(NL80211_CMD_GET_SCAN)
                || message.cmd == Some(NL80211_CMD_NEW_SCAN_RESULTS)
            {
                if let Some(point) = bss_from_attrs(&message.attrs)? {
                    out.push(point);
                }
            }
        }
        Ok(out)
    }

    /// Reads a single buffer of pending scan events (non-blocking sockets
    /// surface `WouldBlock` through the returned I/O error).
    pub fn read_scan_events(&mut self) -> Result<Vec<WifiEvent>, NetlinkError> {
        let n = recv_into(self.fd.as_raw_fd(), &mut self.buf)?;
        parse_scan_events(&self.buf[..n])
    }

    fn transact_dump(
        &mut self,
        cmd: u8,
        attrs: &[(u16, Vec<u8>)],
    ) -> Result<Vec<RawMsg>, NetlinkError> {
        let request = build_message(self.family_id, cmd, NLM_F_REQUEST | NLM_F_DUMP, 1, attrs);
        send_all(self.fd.as_raw_fd(), &request)?;
        let mut messages = Vec::new();
        loop {
            let n = recv_into(self.fd.as_raw_fd(), &mut self.buf)?;
            for message in parse_genl_messages(&self.buf[..n])? {
                match message.nlmsg_type {
                    NLMSG_DONE => return Ok(messages),
                    NLMSG_ERROR => return Err(parse_kernel_error(&message.payload)),
                    _ => messages.push(message),
                }
            }
        }
    }

    fn transact_ack(&mut self, cmd: u8, attrs: &[(u16, Vec<u8>)]) -> Result<(), NetlinkError> {
        let request = build_message(self.family_id, cmd, NLM_F_REQUEST | NLM_F_ACK, 1, attrs);
        send_all(self.fd.as_raw_fd(), &request)?;
        loop {
            let n = recv_into(self.fd.as_raw_fd(), &mut self.buf)?;
            for message in parse_genl_messages(&self.buf[..n])? {
                if message.nlmsg_type == NLMSG_ERROR {
                    return parse_ack_error(&message.payload);
                }
            }
        }
    }
}

/// A wiphy together with the capabilities it advertises.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WiphyInfo {
    pub index: u32,
    pub name: String,
    pub capabilities: WifiCapabilities,
}

fn resolve_nl80211_family() -> Result<FamilyInfo, NetlinkError> {
    let fd = open_socket_with_groups(NETLINK_GENERIC, 0)?;
    let mut buf = vec![0_u8; 65536];
    let request = build_message(
        GENL_ID_CTRL,
        CTRL_CMD_GETFAMILY,
        NLM_F_REQUEST,
        1,
        &[(CTRL_ATTR_FAMILY_NAME, b"nl80211".to_vec())],
    );
    send_all(fd.as_raw_fd(), &request)?;
    loop {
        let n = recv_into(fd.as_raw_fd(), &mut buf)?;
        for message in parse_genl_messages(&buf[..n])? {
            if message.cmd.is_none() {
                continue;
            }
            if let Some(info) = family_info_from_attrs(&message.attrs)? {
                return Ok(info);
            }
        }
    }
}

fn build_message(
    family_id: u16,
    cmd: u8,
    flags: u16,
    seq: u32,
    attrs: &[(u16, Vec<u8>)],
) -> Vec<u8> {
    let attr_len: usize = attrs
        .iter()
        .map(|(_, payload)| align(size_of::<NlAttr>() + payload.len(), NLA_ALIGNTO))
        .sum();
    let len = size_of::<NlMsgHdr>() + GENL_HDRLEN + attr_len;
    let mut buf = Vec::with_capacity(len);
    buf.extend_from_slice(&(len as u32).to_ne_bytes());
    buf.extend_from_slice(&family_id.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0_u32.to_ne_bytes());
    buf.extend_from_slice(&[cmd, 1, 0, 0]);
    for (typ, payload) in attrs {
        buf.extend_from_slice(&((size_of::<NlAttr>() + payload.len()) as u16).to_ne_bytes());
        buf.extend_from_slice(&typ.to_ne_bytes());
        buf.extend_from_slice(payload);
        while buf.len() % NLA_ALIGNTO != 0 {
            buf.push(0);
        }
    }
    buf
}

/// Parses a sequence of netlink attributes out of a payload.
pub(crate) fn parse_attrs(payload: &[u8]) -> Result<Vec<RawAttr>, NetlinkError> {
    let mut attrs = Vec::new();
    let mut offset = 0;
    while offset + size_of::<NlAttr>() <= payload.len() {
        let header = read_unaligned::<NlAttr>(&payload[offset..])?;
        let len = header.nla_len as usize;
        if len < size_of::<NlAttr>() || offset + len > payload.len() {
            return Err(NetlinkError::MalformedMessage("invalid nlattr length"));
        }
        attrs.push(RawAttr {
            typ: header.nla_type & NLA_TYPE_MASK,
            nested: header.nla_type & NLA_F_NESTED != 0,
            payload: payload[offset + size_of::<NlAttr>()..offset + len].to_vec(),
        });
        offset += align(len, NLA_ALIGNTO);
    }
    Ok(attrs)
}

/// Parses all generic netlink messages in a receive buffer.
pub(crate) fn parse_genl_messages(buf: &[u8]) -> Result<Vec<RawMsg>, NetlinkError> {
    let mut messages = Vec::new();
    let mut offset = 0;
    while offset + size_of::<NlMsgHdr>() <= buf.len() {
        let header = read_unaligned::<NlMsgHdr>(&buf[offset..])?;
        let len = header.nlmsg_len as usize;
        if len < size_of::<NlMsgHdr>() || offset + len > buf.len() {
            return Err(NetlinkError::MalformedMessage("invalid nlmsghdr length"));
        }
        let payload = &buf[offset + size_of::<NlMsgHdr>()..offset + len];
        if matches!(header.nlmsg_type, NLMSG_DONE | NLMSG_ERROR) {
            messages.push(RawMsg {
                nlmsg_type: header.nlmsg_type,
                nlmsg_flags: header.nlmsg_flags,
                cmd: None,
                attrs: Vec::new(),
                payload: payload.to_vec(),
            });
        } else {
            if payload.len() < GENL_HDRLEN {
                return Err(NetlinkError::MalformedMessage("short genl header"));
            }
            let genl = read_unaligned::<GenlHdr>(payload)?;
            messages.push(RawMsg {
                nlmsg_type: header.nlmsg_type,
                nlmsg_flags: header.nlmsg_flags,
                cmd: Some(genl.cmd),
                attrs: parse_attrs(&payload[GENL_HDRLEN..])?,
                payload: payload.to_vec(),
            });
        }
        offset += align(len, 4);
    }
    if offset != buf.len() {
        return Err(NetlinkError::MalformedMessage("trailing partial nlmsghdr"));
    }
    Ok(messages)
}

fn parse_ack_error(payload: &[u8]) -> Result<(), NetlinkError> {
    if payload.len() < size_of::<i32>() {
        return Err(NetlinkError::MalformedMessage("short nlmsgerr"));
    }
    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(&payload[..4]);
    let code = i32::from_ne_bytes(bytes);
    if code == 0 {
        Ok(())
    } else {
        Err(NetlinkError::Kernel(code))
    }
}

fn family_info_from_attrs(attrs: &[RawAttr]) -> Result<Option<FamilyInfo>, NetlinkError> {
    let Some(id_attr) = attrs.iter().find(|attr| attr.typ == CTRL_ATTR_FAMILY_ID) else {
        return Ok(None);
    };
    if id_attr.payload.len() != size_of::<u16>() {
        return Err(NetlinkError::MalformedMessage("invalid family id length"));
    }
    let mut id_bytes = [0_u8; 2];
    id_bytes.copy_from_slice(&id_attr.payload);
    let id = u16::from_ne_bytes(id_bytes);
    let mut mcast_groups = Vec::new();
    if let Some(groups_attr) = attrs.iter().find(|attr| attr.typ == CTRL_ATTR_MCAST_GROUPS) {
        for group in parse_attrs(&groups_attr.payload)? {
            let inner = parse_attrs(&group.payload)?;
            let name = read_string(&inner, CTRL_ATTR_MCAST_GRP_NAME)?;
            let group_id = read_u32(&inner, CTRL_ATTR_MCAST_GRP_ID)?;
            if let (Some(name), Some(group_id)) = (name, group_id) {
                mcast_groups.push((name, group_id));
            }
        }
    }
    Ok(Some(FamilyInfo { id, mcast_groups }))
}

/// Parses an nl80211 interface dump buffer into typed interfaces.
#[cfg(test)]
pub(crate) fn parse_interface_messages(buf: &[u8]) -> Result<Vec<WirelessInterface>, NetlinkError> {
    let mut out = Vec::new();
    for message in parse_genl_messages(buf)? {
        if message.cmd == Some(NL80211_CMD_GET_INTERFACE)
            || message.cmd == Some(NL80211_CMD_NEW_INTERFACE)
        {
            if let Some(interface) = interface_from_attrs(&message.attrs)? {
                out.push(interface);
            }
        }
    }
    Ok(out)
}

/// Parses an nl80211 wiphy dump buffer into wiphys and capabilities.
#[cfg(test)]
pub(crate) fn parse_wiphy_messages(
    buf: &[u8],
) -> Result<Vec<(u32, String, WifiCapabilities)>, NetlinkError> {
    let mut out = Vec::new();
    for message in parse_genl_messages(buf)? {
        if message.cmd == Some(NL80211_CMD_GET_WIPHY) || message.cmd == Some(NL80211_CMD_NEW_WIPHY)
        {
            if let Some(wiphy) = wiphy_from_attrs(&message.attrs)? {
                out.push((wiphy.index, wiphy.name, wiphy.capabilities));
            }
        }
    }
    Ok(out)
}

/// Parses an nl80211 scan dump buffer into typed access points.
#[cfg(test)]
pub(crate) fn parse_scan_messages(buf: &[u8]) -> Result<Vec<AccessPoint>, NetlinkError> {
    let mut out = Vec::new();
    for message in parse_genl_messages(buf)? {
        if message.cmd == Some(NL80211_CMD_GET_SCAN)
            || message.cmd == Some(NL80211_CMD_NEW_SCAN_RESULTS)
        {
            if let Some(point) = bss_from_attrs(&message.attrs)? {
                out.push(point);
            }
        }
    }
    Ok(out)
}

/// Parses nl80211 scan notifications (new results / aborted) from a buffer.
pub(crate) fn parse_scan_events(buf: &[u8]) -> Result<Vec<WifiEvent>, NetlinkError> {
    let mut out = Vec::new();
    for message in parse_genl_messages(buf)? {
        let kind = match message.cmd {
            Some(NL80211_CMD_NEW_SCAN_RESULTS) => WifiEventKind::ScanResults,
            Some(NL80211_CMD_SCAN_ABORTED) => WifiEventKind::ScanAborted,
            _ => continue,
        };
        let Some(index) = read_u32(&message.attrs, NL80211_ATTR_IFINDEX)? else {
            continue;
        };
        let frequency =
            read_u32(&message.attrs, NL80211_ATTR_WIPHY_FREQ)?.filter(|freq| *freq != 0);
        out.push(WifiEvent {
            kind,
            interface_index: index as i32,
            interface_name: None,
            frequency,
        });
    }
    Ok(out)
}

fn interface_from_attrs(attrs: &[RawAttr]) -> Result<Option<WirelessInterface>, NetlinkError> {
    let Some(index) = read_u32(attrs, NL80211_ATTR_IFINDEX)? else {
        return Ok(None);
    };
    let name = read_string(attrs, NL80211_ATTR_IFNAME)?.unwrap_or_default();
    let wiphy_index = read_u32(attrs, NL80211_ATTR_WIPHY)?;
    let interface_type = match read_u8(attrs, NL80211_ATTR_IFTYPE)? {
        Some(value) => InterfaceType::from_u8(value),
        None => InterfaceType::Unspecified,
    };
    let mac = read_mac(attrs, NL80211_ATTR_MAC)?;
    Ok(Some(WirelessInterface {
        index: index as i32,
        name,
        wiphy_index,
        wiphy_name: None,
        interface_type,
        mac,
        up: false,
        capabilities: WifiCapabilities::default(),
    }))
}

fn wiphy_from_attrs(attrs: &[RawAttr]) -> Result<Option<WiphyInfo>, NetlinkError> {
    let Some(index) = read_u32(attrs, NL80211_ATTR_WIPHY)? else {
        return Ok(None);
    };
    let name = read_string(attrs, NL80211_ATTR_WIPHY_NAME)?.unwrap_or_default();
    let mut capabilities = WifiCapabilities::default();
    for supported in nested_attrs(attrs, NL80211_ATTR_SUPPORTED_IFTYPES)? {
        capabilities
            .supported_interfaces
            .push(InterfaceType::from_u8(supported.typ as u8));
    }
    if let Some(ciphers) = attrs
        .iter()
        .find(|attr| attr.typ == NL80211_ATTR_CIPHER_SUITES)
    {
        capabilities.cipher_suites = parse_cipher_suites(&ciphers.payload)?;
    }
    capabilities.max_scan_ssids = read_u8(attrs, NL80211_ATTR_MAX_NUM_SCAN_SSIDS)?.map(u32::from);
    capabilities.scan_supported = capabilities.max_scan_ssids.is_some();
    for band in nested_attrs(attrs, NL80211_ATTR_WIPHY_BANDS)? {
        if let Some(band) = band_from_attrs(band.typ as u8, &band.payload)? {
            capabilities.bands.push(band);
        }
    }
    Ok(Some(WiphyInfo {
        index,
        name,
        capabilities,
    }))
}

fn band_from_attrs(band_id: u8, payload: &[u8]) -> Result<Option<WifiBand>, NetlinkError> {
    let attrs = parse_attrs(payload)?;
    let mut band = WifiBand {
        id: WifiBandId::from_u8(band_id),
        channels: Vec::new(),
        frequencies: Vec::new(),
        ht_capabilities: None,
        vht_capabilities: None,
    };
    if let Some(freqs) = attrs
        .iter()
        .find(|attr| attr.typ == NL80211_BAND_ATTR_FREQS)
    {
        for entry in parse_attrs(&freqs.payload)? {
            let inner = parse_attrs(&entry.payload)?;
            if inner
                .iter()
                .any(|attr| attr.typ == NL80211_FREQUENCY_ATTR_DISABLED)
            {
                continue;
            }
            if let Some(frequency) = read_u32(&inner, NL80211_FREQUENCY_ATTR_FREQ)? {
                band.channels.push(entry.typ);
                band.frequencies.push(frequency);
            }
        }
    }
    band.ht_capabilities = read_u16(&attrs, NL80211_BAND_ATTR_HT_CAPA)?;
    band.vht_capabilities = read_u32(&attrs, NL80211_BAND_ATTR_VHT_CAPA)?;
    Ok(Some(band))
}

fn parse_cipher_suites(payload: &[u8]) -> Result<Vec<WifiCipher>, NetlinkError> {
    if !payload.len().is_multiple_of(size_of::<u32>()) {
        return Err(NetlinkError::MalformedMessage(
            "invalid cipher suite length",
        ));
    }
    Ok(payload
        .chunks_exact(size_of::<u32>())
        .map(|chunk| {
            let mut bytes = [0_u8; 4];
            bytes.copy_from_slice(chunk);
            WifiCipher::from_u32(u32::from_ne_bytes(bytes))
        })
        .collect())
}

fn bss_from_attrs(attrs: &[RawAttr]) -> Result<Option<AccessPoint>, NetlinkError> {
    let Some(bss_attr) = attrs.iter().find(|attr| attr.typ == NL80211_ATTR_BSS) else {
        return Ok(None);
    };
    let bss = parse_attrs(&bss_attr.payload)?;
    let bssid = read_mac(&bss, NL80211_BSS_BSSID)?.map(Bssid);
    let frequency = read_u32(&bss, NL80211_BSS_FREQUENCY)?;
    let channel = frequency.and_then(frequency_to_channel);
    let capability = read_u16(&bss, NL80211_BSS_CAPABILITY)?;
    let signal_dbm = read_i32(&bss, NL80211_BSS_SIGNAL_MBM)?.map(|mbm| mbm / 100);
    let signal_unspecified = read_u8(&bss, NL80211_BSS_SIGNAL_UNSPEC)?;
    let seen_millis_ago = read_u32(&bss, NL80211_BSS_SEEN_MS_AGO)?;
    let information_elements = read_bytes(&bss, NL80211_BSS_INFORMATION_ELEMENTS)
        .or_else(|| read_bytes(&bss, NL80211_BSS_BEACON_IES));
    let ssid = read_ssid(attrs, NL80211_ATTR_SSID)?.or_else(|| {
        information_elements
            .as_ref()
            .and_then(|ies| ssid_from_ies(ies))
    });
    let security = parse_security(information_elements.as_deref().unwrap_or(&[]), capability)?;
    Ok(Some(AccessPoint {
        bssid,
        ssid,
        frequency,
        channel,
        signal_dbm,
        signal_unspecified,
        capability,
        security,
        seen_millis_ago,
    }))
}

fn parse_security(
    ies: &[u8],
    capability: Option<u16>,
) -> Result<AccessPointSecurity, NetlinkError> {
    let mut security = AccessPointSecurity::default();
    let mut auth_suites = Vec::new();
    let mut rsn_seen = false;
    let mut wpa_seen = false;
    let mut offset = 0;
    while offset + 2 <= ies.len() {
        let id = ies[offset];
        let len = ies[offset + 1] as usize;
        if offset + 2 + len > ies.len() {
            return Err(NetlinkError::MalformedMessage(
                "malformed information element",
            ));
        }
        let data = &ies[offset + 2..offset + 2 + len];
        match id {
            IE_RSN => {
                rsn_seen = true;
                let (suites, mfp) = parse_rsn_ie(data)?;
                auth_suites.extend(suites);
                security.management_frame_protection |= mfp;
            }
            IE_VENDOR
                if data.len() >= 4 && data.starts_with(&WPA_OUI) && data[3] == WPA_OUI_TYPE =>
            {
                wpa_seen = true;
                auth_suites.extend(parse_wpa_ie(&data[4..])?);
            }
            _ => {}
        }
        offset += 2 + len;
    }
    security.auth_suites = auth_suites;
    security.wpa1 = wpa_seen;
    security.wpa3 = security.auth_suites.iter().any(|suite| {
        matches!(
            suite,
            WifiAuthSuite::RsnSae
                | WifiAuthSuite::RsnSaeFt
                | WifiAuthSuite::RsnOwe
                | WifiAuthSuite::RsnPskSha384
                | WifiAuthSuite::RsnFt8021xSha384
                | WifiAuthSuite::RsnFtPskSha384
                | WifiAuthSuite::RsnSuiteB192
                | WifiAuthSuite::RsnPasn
        )
    });
    security.wpa2 = rsn_seen
        && security.auth_suites.iter().any(|suite| {
            !matches!(
                suite,
                WifiAuthSuite::RsnSae
                    | WifiAuthSuite::RsnSaeFt
                    | WifiAuthSuite::RsnOwe
                    | WifiAuthSuite::RsnPasn
                    | WifiAuthSuite::Other(_)
            )
        });
    security.enterprise = security.auth_suites.iter().any(|suite| {
        matches!(
            suite,
            WifiAuthSuite::Wpa18021x
                | WifiAuthSuite::Rsn8021x
                | WifiAuthSuite::RsnFt8021x
                | WifiAuthSuite::Rsn8021xSha256
                | WifiAuthSuite::RsnFt8021xSha384
                | WifiAuthSuite::RsnSuiteB
                | WifiAuthSuite::RsnSuiteB192
        )
    });
    security.wep = capability
        .map(|cap| cap & BSS_CAPABILITY_PRIVACY != 0)
        .unwrap_or(false)
        && !rsn_seen
        && !wpa_seen;
    Ok(security)
}

/// Parses an RSN information element into auth suites and MFP support.
fn parse_rsn_ie(data: &[u8]) -> Result<(Vec<WifiAuthSuite>, bool), NetlinkError> {
    let mut offset = 0;
    read_ie_u16(data, &mut offset)?;
    skip_ie_bytes(data, &mut offset, 4)?;
    skip_ie_counted(data, &mut offset, 4)?;
    let akm_count = read_ie_u16(data, &mut offset)?;
    if offset + akm_count as usize * 4 > data.len() {
        return Err(NetlinkError::MalformedMessage("malformed rsn ie"));
    }
    let mut suites = Vec::with_capacity(akm_count as usize);
    for _ in 0..akm_count {
        if offset + 4 > data.len() {
            return Err(NetlinkError::MalformedMessage("malformed rsn ie"));
        }
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(&data[offset..offset + 4]);
        suites.push(WifiAuthSuite::from_rsn_akm(u32::from_le_bytes(bytes)));
        offset += 4;
    }
    let mfp = if offset + 2 <= data.len() {
        let capabilities = read_le_u16(&data[offset..offset + 2]);
        capabilities & RSN_CAPABILITY_MFP != 0
    } else {
        false
    };
    Ok((suites, mfp))
}

/// Parses a WPA vendor-specific information element into auth suites.
fn parse_wpa_ie(data: &[u8]) -> Result<Vec<WifiAuthSuite>, NetlinkError> {
    let mut offset = 0;
    skip_ie_bytes(data, &mut offset, 2)?;
    skip_ie_bytes(data, &mut offset, 4)?;
    skip_ie_counted(data, &mut offset, 4)?;
    let auth_count = read_ie_u16(data, &mut offset)?;
    if offset + auth_count as usize * 4 > data.len() {
        return Err(NetlinkError::MalformedMessage("malformed wpa ie"));
    }
    let mut suites = Vec::with_capacity(auth_count as usize);
    for _ in 0..auth_count {
        if offset + 4 > data.len() {
            return Err(NetlinkError::MalformedMessage("malformed wpa ie"));
        }
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(&data[offset..offset + 4]);
        let value = u32::from_le_bytes(bytes);
        suites.push(match value {
            1 => WifiAuthSuite::Wpa18021x,
            2 => WifiAuthSuite::Wpa1Psk,
            other => WifiAuthSuite::Other(other),
        });
        offset += 4;
    }
    Ok(suites)
}

fn read_ie_u16(data: &[u8], offset: &mut usize) -> Result<u16, NetlinkError> {
    if *offset + 2 > data.len() {
        return Err(NetlinkError::MalformedMessage(
            "malformed information element",
        ));
    }
    let value = read_le_u16(&data[*offset..*offset + 2]);
    *offset += 2;
    Ok(value)
}

fn skip_ie_bytes(data: &[u8], offset: &mut usize, count: usize) -> Result<(), NetlinkError> {
    if *offset + count > data.len() {
        return Err(NetlinkError::MalformedMessage(
            "malformed information element",
        ));
    }
    *offset += count;
    Ok(())
}

fn skip_ie_counted(
    data: &[u8],
    offset: &mut usize,
    element_size: usize,
) -> Result<(), NetlinkError> {
    let count = read_ie_u16(data, offset)?;
    skip_ie_bytes(data, offset, count as usize * element_size)
}

fn read_le_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn ssid_from_ies(ies: &[u8]) -> Option<Ssid> {
    let mut offset = 0;
    while offset + 2 <= ies.len() {
        let id = ies[offset];
        let len = ies[offset + 1] as usize;
        if offset + 2 + len > ies.len() {
            return None;
        }
        if id == IE_SSID {
            return Ssid::from_bytes(&ies[offset + 2..offset + 2 + len]);
        }
        offset += 2 + len;
    }
    None
}

fn nested_attrs(attrs: &[RawAttr], typ: u16) -> Result<Vec<RawAttr>, NetlinkError> {
    match attrs.iter().find(|attr| attr.typ == typ) {
        Some(attr) => parse_attrs(&attr.payload),
        None => Ok(Vec::new()),
    }
}

fn read_u8(attrs: &[RawAttr], typ: u16) -> Result<Option<u8>, NetlinkError> {
    let Some(attr) = attrs.iter().find(|attr| attr.typ == typ) else {
        return Ok(None);
    };
    if attr.payload.len() != size_of::<u8>() {
        return Err(NetlinkError::MalformedMessage(
            "invalid u8 attribute length",
        ));
    }
    Ok(Some(attr.payload[0]))
}

fn read_u16(attrs: &[RawAttr], typ: u16) -> Result<Option<u16>, NetlinkError> {
    let Some(attr) = attrs.iter().find(|attr| attr.typ == typ) else {
        return Ok(None);
    };
    if attr.payload.len() != size_of::<u16>() {
        return Err(NetlinkError::MalformedMessage(
            "invalid u16 attribute length",
        ));
    }
    let mut bytes = [0_u8; 2];
    bytes.copy_from_slice(&attr.payload);
    Ok(Some(u16::from_ne_bytes(bytes)))
}

fn read_u32(attrs: &[RawAttr], typ: u16) -> Result<Option<u32>, NetlinkError> {
    let Some(attr) = attrs.iter().find(|attr| attr.typ == typ) else {
        return Ok(None);
    };
    if attr.payload.len() != size_of::<u32>() {
        return Err(NetlinkError::MalformedMessage(
            "invalid u32 attribute length",
        ));
    }
    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(&attr.payload);
    Ok(Some(u32::from_ne_bytes(bytes)))
}

fn read_i32(attrs: &[RawAttr], typ: u16) -> Result<Option<i32>, NetlinkError> {
    let Some(attr) = attrs.iter().find(|attr| attr.typ == typ) else {
        return Ok(None);
    };
    if attr.payload.len() != size_of::<i32>() {
        return Err(NetlinkError::MalformedMessage(
            "invalid i32 attribute length",
        ));
    }
    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(&attr.payload);
    Ok(Some(i32::from_ne_bytes(bytes)))
}

fn read_mac(attrs: &[RawAttr], typ: u16) -> Result<Option<[u8; 6]>, NetlinkError> {
    let Some(attr) = attrs.iter().find(|attr| attr.typ == typ) else {
        return Ok(None);
    };
    if attr.payload.len() != 6 {
        return Err(NetlinkError::MalformedMessage(
            "invalid mac attribute length",
        ));
    }
    let mut mac = [0_u8; 6];
    mac.copy_from_slice(&attr.payload);
    Ok(Some(mac))
}

fn read_string(attrs: &[RawAttr], typ: u16) -> Result<Option<String>, NetlinkError> {
    let Some(attr) = attrs.iter().find(|attr| attr.typ == typ) else {
        return Ok(None);
    };
    let end = attr
        .payload
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(attr.payload.len());
    Ok(Some(
        String::from_utf8_lossy(&attr.payload[..end]).into_owned(),
    ))
}

fn read_ssid(attrs: &[RawAttr], typ: u16) -> Result<Option<Ssid>, NetlinkError> {
    let Some(attr) = attrs.iter().find(|attr| attr.typ == typ) else {
        return Ok(None);
    };
    if attr.payload.len() > IE_MAX_SSID_LEN {
        return Err(NetlinkError::MalformedMessage("invalid ssid length"));
    }
    Ok(Ssid::from_bytes(&attr.payload))
}

fn read_bytes(attrs: &[RawAttr], typ: u16) -> Option<Vec<u8>> {
    attrs
        .iter()
        .find(|attr| attr.typ == typ)
        .map(|attr| attr.payload.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAMILY_ID: u16 = 0x15;

    fn push_message(buf: &mut Vec<u8>, nlmsg_type: u16, cmd: u8, attrs: &[u8]) {
        let len = size_of::<NlMsgHdr>() + GENL_HDRLEN + attrs.len();
        buf.extend_from_slice(&(len as u32).to_ne_bytes());
        buf.extend_from_slice(&nlmsg_type.to_ne_bytes());
        buf.extend_from_slice(&0_u16.to_ne_bytes());
        buf.extend_from_slice(&1_u32.to_ne_bytes());
        buf.extend_from_slice(&0_u32.to_ne_bytes());
        buf.extend_from_slice(&[cmd, 1, 0, 0]);
        buf.extend_from_slice(attrs);
    }

    fn push_plain(buf: &mut Vec<u8>, nlmsg_type: u16, payload: &[u8]) {
        let len = size_of::<NlMsgHdr>() + payload.len();
        buf.extend_from_slice(&(len as u32).to_ne_bytes());
        buf.extend_from_slice(&nlmsg_type.to_ne_bytes());
        buf.extend_from_slice(&0_u16.to_ne_bytes());
        buf.extend_from_slice(&1_u32.to_ne_bytes());
        buf.extend_from_slice(&0_u32.to_ne_bytes());
        buf.extend_from_slice(payload);
    }

    fn push_done(buf: &mut Vec<u8>) {
        push_plain(buf, NLMSG_DONE, &[]);
    }

    fn attr_bytes(typ: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&((size_of::<NlAttr>() + payload.len()) as u16).to_ne_bytes());
        out.extend_from_slice(&typ.to_ne_bytes());
        out.extend_from_slice(payload);
        while out.len() % NLA_ALIGNTO != 0 {
            out.push(0);
        }
        out
    }

    fn nested_bytes(typ: u16, inner: &[u8]) -> Vec<u8> {
        attr_bytes(typ | NLA_F_NESTED, inner)
    }

    fn flag_attr(typ: u16) -> Vec<u8> {
        attr_bytes(typ, &[])
    }

    fn u8_attr(typ: u16, value: u8) -> Vec<u8> {
        attr_bytes(typ, &value.to_ne_bytes())
    }

    fn u16_attr(typ: u16, value: u16) -> Vec<u8> {
        attr_bytes(typ, &value.to_ne_bytes())
    }

    fn u32_attr(typ: u16, value: u32) -> Vec<u8> {
        attr_bytes(typ, &value.to_ne_bytes())
    }

    fn i32_attr(typ: u16, value: i32) -> Vec<u8> {
        attr_bytes(typ, &value.to_ne_bytes())
    }

    fn string_attr(typ: u16, value: &str) -> Vec<u8> {
        let mut payload = value.as_bytes().to_vec();
        payload.push(0);
        attr_bytes(typ, &payload)
    }

    fn mac_attr(typ: u16, value: [u8; 6]) -> Vec<u8> {
        attr_bytes(typ, &value)
    }

    fn frequency_entry(channel: u16, frequency: u32) -> Vec<u8> {
        nested_bytes(
            channel,
            &attr_bytes(NL80211_FREQUENCY_ATTR_FREQ, &frequency.to_ne_bytes()),
        )
    }

    fn ssid_ie(name: &[u8]) -> Vec<u8> {
        let mut ie = vec![IE_SSID, name.len() as u8];
        ie.extend_from_slice(name);
        ie
    }

    fn rsn_ie(akm_suites: &[u32], mfp_capable: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1_u16.to_le_bytes());
        body.extend_from_slice(&0x000FAC04_u32.to_le_bytes());
        body.extend_from_slice(&1_u16.to_le_bytes());
        body.extend_from_slice(&0x000FAC04_u32.to_le_bytes());
        body.extend_from_slice(&(akm_suites.len() as u16).to_le_bytes());
        for suite in akm_suites {
            body.extend_from_slice(&suite.to_le_bytes());
        }
        let capabilities = if mfp_capable { 0x0080_u16 } else { 0 };
        body.extend_from_slice(&capabilities.to_le_bytes());
        let mut ie = vec![IE_RSN, body.len() as u8];
        ie.extend_from_slice(&body);
        ie
    }

    fn wpa_ie(akm_values: &[u32]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1_u16.to_le_bytes());
        body.extend_from_slice(&0x000FAC02_u32.to_le_bytes());
        body.extend_from_slice(&1_u16.to_le_bytes());
        body.extend_from_slice(&0x000FAC02_u32.to_le_bytes());
        body.extend_from_slice(&(akm_values.len() as u16).to_le_bytes());
        for value in akm_values {
            body.extend_from_slice(&value.to_le_bytes());
        }
        let mut data = Vec::new();
        data.extend_from_slice(&WPA_OUI);
        data.push(WPA_OUI_TYPE);
        data.extend_from_slice(&body);
        let mut ie = vec![IE_VENDOR, data.len() as u8];
        ie.extend_from_slice(&data);
        ie
    }

    fn interface_message(ifindex: i32, name: &str, wiphy: u32, iftype: u8) -> Vec<u8> {
        let mut attrs = Vec::new();
        attrs.extend(u32_attr(NL80211_ATTR_IFINDEX, ifindex as u32));
        attrs.extend(string_attr(NL80211_ATTR_IFNAME, name));
        attrs.extend(u32_attr(NL80211_ATTR_WIPHY, wiphy));
        attrs.extend(u8_attr(NL80211_ATTR_IFTYPE, iftype));
        let mut message = Vec::new();
        push_message(&mut message, FAMILY_ID, NL80211_CMD_GET_INTERFACE, &attrs);
        message
    }

    fn bss_message(
        bssid: Option<[u8; 6]>,
        ssid: Option<&[u8]>,
        frequency: u32,
        signal_mbm: i32,
        capability: u16,
        ies: &[u8],
    ) -> Vec<u8> {
        let mut bss = Vec::new();
        if let Some(bssid) = bssid {
            bss.extend(mac_attr(NL80211_BSS_BSSID, bssid));
        }
        bss.extend(u32_attr(NL80211_BSS_FREQUENCY, frequency));
        bss.extend(u16_attr(NL80211_BSS_CAPABILITY, capability));
        bss.extend(i32_attr(NL80211_BSS_SIGNAL_MBM, signal_mbm));
        if !ies.is_empty() {
            bss.extend(attr_bytes(NL80211_BSS_INFORMATION_ELEMENTS, ies));
        }
        let mut attrs = Vec::new();
        attrs.extend(nested_bytes(NL80211_ATTR_BSS, &bss));
        if let Some(ssid) = ssid {
            attrs.extend(attr_bytes(NL80211_ATTR_SSID, ssid));
        }
        let mut message = Vec::new();
        push_message(&mut message, FAMILY_ID, NL80211_CMD_GET_SCAN, &attrs);
        message
    }

    fn scan_event_message(cmd: u8, ifindex: u32, frequency: u32) -> Vec<u8> {
        let mut attrs = Vec::new();
        attrs.extend(u32_attr(NL80211_ATTR_IFINDEX, ifindex));
        attrs.extend(u32_attr(NL80211_ATTR_WIPHY_FREQ, frequency));
        let mut message = Vec::new();
        push_message(&mut message, FAMILY_ID, cmd, &attrs);
        message
    }

    #[test]
    fn parses_interface_dump() {
        let mut buffer = Vec::new();
        buffer.extend(interface_message(3, "wlan0", 0, 2));
        buffer.extend(interface_message(5, "wlx01", 1, 6));
        push_done(&mut buffer);

        let interfaces = parse_interface_messages(&buffer).unwrap();
        assert_eq!(interfaces.len(), 2);
        assert_eq!(interfaces[0].index, 3);
        assert_eq!(interfaces[0].name, "wlan0");
        assert_eq!(interfaces[0].wiphy_index, Some(0));
        assert_eq!(interfaces[0].interface_type, InterfaceType::Station);
        assert_eq!(interfaces[1].interface_type, InterfaceType::Monitor);
    }

    #[test]
    fn parses_wiphy_capabilities() {
        let mut freq_2ghz = Vec::new();
        freq_2ghz.extend(frequency_entry(1, 2412));
        freq_2ghz.extend(frequency_entry(6, 2437));
        freq_2ghz.extend(frequency_entry(11, 2462));
        let mut band_2ghz = Vec::new();
        band_2ghz.extend(nested_bytes(NL80211_BAND_ATTR_FREQS, &freq_2ghz));
        band_2ghz.extend(u16_attr(NL80211_BAND_ATTR_HT_CAPA, 0x01ff));

        let mut freq_5ghz = Vec::new();
        freq_5ghz.extend(frequency_entry(36, 5180));
        freq_5ghz.extend(frequency_entry(149, 5745));
        let mut band_5ghz = Vec::new();
        band_5ghz.extend(nested_bytes(NL80211_BAND_ATTR_FREQS, &freq_5ghz));
        band_5ghz.extend(u32_attr(NL80211_BAND_ATTR_VHT_CAPA, 0x0e000000));

        let mut bands = Vec::new();
        bands.extend(nested_bytes(0, &band_2ghz));
        bands.extend(nested_bytes(1, &band_5ghz));

        let mut supported = Vec::new();
        supported.extend(flag_attr(2));
        supported.extend(flag_attr(3));
        supported.extend(flag_attr(6));

        let mut ciphers = Vec::new();
        ciphers.extend(0x000FAC04_u32.to_ne_bytes());
        ciphers.extend(0x000FAC02_u32.to_ne_bytes());
        ciphers.extend(0x000FAC01_u32.to_ne_bytes());

        let mut attrs = Vec::new();
        attrs.extend(u32_attr(NL80211_ATTR_WIPHY, 0));
        attrs.extend(string_attr(NL80211_ATTR_WIPHY_NAME, "phy0"));
        attrs.extend(nested_bytes(NL80211_ATTR_SUPPORTED_IFTYPES, &supported));
        attrs.extend(attr_bytes(NL80211_ATTR_CIPHER_SUITES, &ciphers));
        attrs.extend(u8_attr(NL80211_ATTR_MAX_NUM_SCAN_SSIDS, 8));
        attrs.extend(nested_bytes(NL80211_ATTR_WIPHY_BANDS, &bands));

        let mut buffer = Vec::new();
        push_message(&mut buffer, FAMILY_ID, NL80211_CMD_GET_WIPHY, &attrs);
        push_done(&mut buffer);

        let wiphys = parse_wiphy_messages(&buffer).unwrap();
        assert_eq!(wiphys.len(), 1);
        let (index, name, capabilities) = &wiphys[0];
        assert_eq!(*index, 0);
        assert_eq!(name, "phy0");
        assert_eq!(
            capabilities.supported_interfaces,
            vec![
                InterfaceType::Station,
                InterfaceType::Ap,
                InterfaceType::Monitor
            ]
        );
        assert_eq!(
            capabilities.cipher_suites,
            vec![WifiCipher::Ccmp, WifiCipher::Tkip, WifiCipher::Wep40]
        );
        assert_eq!(capabilities.max_scan_ssids, Some(8));
        assert!(capabilities.scan_supported);
        assert_eq!(capabilities.bands.len(), 2);
        assert_eq!(capabilities.bands[0].id, WifiBandId::Ghz2);
        assert_eq!(capabilities.bands[0].channels, vec![1, 6, 11]);
        assert_eq!(capabilities.bands[0].frequencies, vec![2412, 2437, 2462]);
        assert_eq!(capabilities.bands[0].ht_capabilities, Some(0x01ff));
        assert_eq!(capabilities.bands[1].id, WifiBandId::Ghz5);
        assert_eq!(capabilities.bands[1].channels, vec![36, 149]);
        assert_eq!(capabilities.bands[1].frequencies, vec![5180, 5745]);
        assert_eq!(capabilities.bands[1].vht_capabilities, Some(0x0e000000));
    }

    #[test]
    fn parses_open_access_point() {
        let mut ies = Vec::new();
        ies.extend(ssid_ie(b"OpenNet"));
        let mut buffer = Vec::new();
        buffer.extend(bss_message(
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Some(b"OpenNet"),
            2437,
            -4500,
            0x0001,
            &ies,
        ));
        push_done(&mut buffer);

        let points = parse_scan_messages(&buffer).unwrap();
        assert_eq!(points.len(), 1);
        let point = &points[0];
        assert_eq!(
            point.bssid,
            Some(Bssid([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
        );
        assert_eq!(point.ssid, Ssid::from_bytes(b"OpenNet"));
        assert_eq!(point.frequency, Some(2437));
        assert_eq!(point.channel, Some(6));
        assert_eq!(point.signal_dbm, Some(-45));
        assert!(!point.security.wep);
        assert!(!point.security.wpa1);
        assert!(!point.security.wpa2);
        assert!(!point.security.wpa3);
        assert!(!point.security.enterprise);
    }

    #[test]
    fn parses_wpa_wpa2_security() {
        let mut ies = Vec::new();
        ies.extend(wpa_ie(&[2]));
        ies.extend(rsn_ie(&[0x000FAC02], false));
        let mut buffer = Vec::new();
        buffer.extend(bss_message(
            Some([1, 2, 3, 4, 5, 6]),
            Some(b"SecureNet"),
            5180,
            -5200,
            0x0011,
            &ies,
        ));
        push_done(&mut buffer);

        let points = parse_scan_messages(&buffer).unwrap();
        let security = &points[0].security;
        assert!(!security.wep);
        assert!(security.wpa1);
        assert!(security.wpa2);
        assert!(!security.wpa3);
        assert!(!security.enterprise);
        assert_eq!(
            security.auth_suites,
            vec![WifiAuthSuite::Wpa1Psk, WifiAuthSuite::RsnPsk]
        );
    }

    #[test]
    fn parses_wpa2_wpa3_transition_security() {
        let mut ies = Vec::new();
        ies.extend(rsn_ie(&[0x000FAC08, 0x000FAC02], true));
        let mut buffer = Vec::new();
        buffer.extend(bss_message(
            Some([2, 3, 4, 5, 6, 7]),
            Some(b"Transition"),
            5500,
            -4300,
            0x0011,
            &ies,
        ));
        push_done(&mut buffer);

        let points = parse_scan_messages(&buffer).unwrap();
        let security = &points[0].security;
        assert!(security.wpa2);
        assert!(security.wpa3);
        assert!(security.management_frame_protection);
    }

    #[test]
    fn parses_wpa3_only_sae_security() {
        let mut ies = Vec::new();
        ies.extend(rsn_ie(&[0x000FAC08], true));
        let mut buffer = Vec::new();
        buffer.extend(bss_message(
            Some([3, 4, 5, 6, 7, 8]),
            Some(b"Wpa3Only"),
            5825,
            -6000,
            0x0011,
            &ies,
        ));
        push_done(&mut buffer);

        let points = parse_scan_messages(&buffer).unwrap();
        let security = &points[0].security;
        assert!(!security.wpa2);
        assert!(security.wpa3);
    }

    #[test]
    fn parses_enterprise_security() {
        let mut ies = Vec::new();
        ies.extend(wpa_ie(&[1]));
        let mut buffer = Vec::new();
        buffer.extend(bss_message(
            Some([4, 5, 6, 7, 8, 9]),
            Some(b"CorpNet"),
            2412,
            -4700,
            0x0011,
            &ies,
        ));
        push_done(&mut buffer);

        let points = parse_scan_messages(&buffer).unwrap();
        let security = &points[0].security;
        assert!(security.wpa1);
        assert!(security.enterprise);
        assert!(!security.wep);
    }

    #[test]
    fn parses_wep_security() {
        let mut ies = Vec::new();
        ies.extend(ssid_ie(b"WepNet"));
        let mut buffer = Vec::new();
        buffer.extend(bss_message(
            Some([5, 6, 7, 8, 9, 10]),
            Some(b"WepNet"),
            2462,
            -5500,
            0x0011,
            &ies,
        ));
        push_done(&mut buffer);

        let points = parse_scan_messages(&buffer).unwrap();
        assert!(points[0].security.wep);
        assert!(!points[0].security.wpa1);
        assert!(!points[0].security.wpa2);
    }

    #[test]
    fn derives_ssid_from_beacon_ie_when_attr_missing() {
        let mut ies = Vec::new();
        ies.extend(ssid_ie(b"BeaconSsid"));
        let mut buffer = Vec::new();
        buffer.extend(bss_message(
            Some([6, 7, 8, 9, 10, 11]),
            None,
            2437,
            -5000,
            0x0001,
            &ies,
        ));
        push_done(&mut buffer);

        let points = parse_scan_messages(&buffer).unwrap();
        assert_eq!(points[0].ssid, Ssid::from_bytes(b"BeaconSsid"));
    }

    #[test]
    fn parses_signal_strength_mbm_and_unspecified() {
        let mut ies = Vec::new();
        ies.extend(ssid_ie(b"Signal"));
        let mut bss = Vec::new();
        bss.extend(mac_attr(NL80211_BSS_BSSID, [7, 8, 9, 10, 11, 12]));
        bss.extend(u32_attr(NL80211_BSS_FREQUENCY, 5180));
        bss.extend(i32_attr(NL80211_BSS_SIGNAL_MBM, -3100));
        bss.extend(u8_attr(NL80211_BSS_SIGNAL_UNSPEC, 75));
        bss.extend(attr_bytes(NL80211_BSS_INFORMATION_ELEMENTS, &ies));
        let mut attrs = Vec::new();
        attrs.extend(nested_bytes(NL80211_ATTR_BSS, &bss));
        let mut buffer = Vec::new();
        push_message(&mut buffer, FAMILY_ID, NL80211_CMD_GET_SCAN, &attrs);
        push_done(&mut buffer);

        let points = parse_scan_messages(&buffer).unwrap();
        assert_eq!(points[0].signal_dbm, Some(-31));
        assert_eq!(points[0].signal_unspecified, Some(75));
        assert_eq!(points[0].channel, Some(36));
    }

    #[test]
    fn parses_multiple_messages_in_one_buffer() {
        let mut buffer = Vec::new();
        let mut ies_a = Vec::new();
        ies_a.extend(ssid_ie(b"NetA"));
        buffer.extend(bss_message(
            Some([0, 1, 2, 3, 4, 5]),
            Some(b"NetA"),
            2437,
            -5000,
            0x0011,
            &ies_a,
        ));
        let mut ies_b = Vec::new();
        ies_b.extend(ssid_ie(b"NetB"));
        buffer.extend(bss_message(
            Some([0, 1, 2, 3, 4, 6]),
            Some(b"NetB"),
            5180,
            -5100,
            0x0001,
            &ies_b,
        ));
        buffer.extend(scan_event_message(NL80211_CMD_NEW_SCAN_RESULTS, 3, 5180));
        buffer.extend(scan_event_message(NL80211_CMD_SCAN_ABORTED, 5, 2437));
        push_done(&mut buffer);

        let points = parse_scan_messages(&buffer).unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].ssid, Ssid::from_bytes(b"NetA"));
        assert_eq!(points[1].ssid, Ssid::from_bytes(b"NetB"));

        let events = parse_scan_events(&buffer).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, WifiEventKind::ScanResults);
        assert_eq!(events[0].interface_index, 3);
        assert_eq!(events[0].frequency, Some(5180));
        assert_eq!(events[1].kind, WifiEventKind::ScanAborted);
        assert_eq!(events[1].interface_index, 5);
    }

    #[test]
    fn parses_scan_events_without_frequency() {
        let mut buffer = Vec::new();
        buffer.extend(scan_event_message(NL80211_CMD_NEW_SCAN_RESULTS, 3, 0));
        push_done(&mut buffer);
        let events = parse_scan_events(&buffer).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, WifiEventKind::ScanResults);
        assert_eq!(events[0].frequency, None);
    }

    #[test]
    fn parses_family_info() {
        let mut groups = Vec::new();
        let mut scan_group = Vec::new();
        scan_group.extend(string_attr(CTRL_ATTR_MCAST_GRP_NAME, "scan"));
        scan_group.extend(u32_attr(CTRL_ATTR_MCAST_GRP_ID, 17));
        groups.extend(nested_bytes(0, &scan_group));
        let mut mlme_group = Vec::new();
        mlme_group.extend(string_attr(CTRL_ATTR_MCAST_GRP_NAME, "mlme"));
        mlme_group.extend(u32_attr(CTRL_ATTR_MCAST_GRP_ID, 21));
        groups.extend(nested_bytes(1, &mlme_group));

        let mut attrs = Vec::new();
        attrs.extend(u16_attr(CTRL_ATTR_FAMILY_ID, FAMILY_ID));
        attrs.extend(nested_bytes(CTRL_ATTR_MCAST_GROUPS, &groups));

        let mut buffer = Vec::new();
        push_message(&mut buffer, GENL_ID_CTRL, 2, &attrs);

        let messages = parse_genl_messages(&buffer).unwrap();
        let info = family_info_from_attrs(&messages[0].attrs).unwrap().unwrap();
        assert_eq!(info.id, FAMILY_ID);
        assert_eq!(
            info.mcast_groups,
            vec![("scan".to_string(), 17), ("mlme".to_string(), 21)]
        );
    }

    #[test]
    fn rejects_truncated_genl_message() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&16_u32.to_ne_bytes());
        buffer.extend_from_slice(&FAMILY_ID.to_ne_bytes());
        buffer.extend_from_slice(&0_u16.to_ne_bytes());
        buffer.extend_from_slice(&1_u32.to_ne_bytes());
        buffer.extend_from_slice(&0_u32.to_ne_bytes());
        assert!(matches!(
            parse_genl_messages(&buffer),
            Err(NetlinkError::MalformedMessage(_))
        ));
    }

    #[test]
    fn rejects_short_genl_header() {
        let mut buffer = Vec::new();
        let len = size_of::<NlMsgHdr>() + 2;
        buffer.extend_from_slice(&(len as u32).to_ne_bytes());
        buffer.extend_from_slice(&FAMILY_ID.to_ne_bytes());
        buffer.extend_from_slice(&0_u16.to_ne_bytes());
        buffer.extend_from_slice(&1_u32.to_ne_bytes());
        buffer.extend_from_slice(&0_u32.to_ne_bytes());
        buffer.extend_from_slice(&[0, 0]);
        assert!(matches!(
            parse_genl_messages(&buffer),
            Err(NetlinkError::MalformedMessage(_))
        ));
    }

    #[test]
    fn rejects_trailing_partial_message() {
        let mut buffer = Vec::new();
        buffer.extend(interface_message(3, "wlan0", 0, 2));
        buffer.extend_from_slice(&[0x01]);
        assert!(matches!(
            parse_genl_messages(&buffer),
            Err(NetlinkError::MalformedMessage(_))
        ));
    }

    #[test]
    fn rejects_malformed_attribute_length() {
        let mut buffer = Vec::new();
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&1_u16.to_ne_bytes());
        attrs.extend_from_slice(&NL80211_ATTR_IFINDEX.to_ne_bytes());
        push_message(&mut buffer, FAMILY_ID, NL80211_CMD_GET_INTERFACE, &attrs);
        assert!(matches!(
            parse_genl_messages(&buffer),
            Err(NetlinkError::MalformedMessage(_))
        ));
    }

    #[test]
    fn rejects_oversized_attribute() {
        let mut buffer = Vec::new();
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&100_u16.to_ne_bytes());
        attrs.extend_from_slice(&NL80211_ATTR_IFINDEX.to_ne_bytes());
        push_message(&mut buffer, FAMILY_ID, NL80211_CMD_GET_INTERFACE, &attrs);
        assert!(matches!(
            parse_genl_messages(&buffer),
            Err(NetlinkError::MalformedMessage(_))
        ));
    }

    #[test]
    fn rejects_wrong_sized_scalar_attribute() {
        let attrs = vec![RawAttr {
            typ: NL80211_ATTR_IFINDEX,
            nested: false,
            payload: vec![1, 2, 3],
        }];
        assert!(matches!(
            read_u32(&attrs, NL80211_ATTR_IFINDEX),
            Err(NetlinkError::MalformedMessage(_))
        ));
    }

    #[test]
    fn ignores_unsupported_attributes() {
        let mut raw = Vec::new();
        raw.extend(u32_attr(NL80211_ATTR_IFINDEX, 3));
        raw.extend(u8_attr(999, 1));
        raw.extend(string_attr(NL80211_ATTR_IFNAME, "wlan0"));
        let attrs = parse_attrs(&raw).unwrap();
        let interface = interface_from_attrs(&attrs).unwrap().unwrap();
        assert_eq!(interface.index, 3);
        assert_eq!(interface.name, "wlan0");
    }

    #[test]
    fn rejects_malformed_rsn_ie() {
        let mut ies = Vec::new();
        ies.extend_from_slice(&[IE_RSN, 20]);
        ies.extend_from_slice(&[0, 1, 0, 0]);
        let mut buffer = Vec::new();
        buffer.extend(bss_message(
            Some([9, 9, 9, 9, 9, 9]),
            Some(b"BadRsn"),
            2437,
            -5000,
            0x0011,
            &ies,
        ));
        push_done(&mut buffer);
        assert!(matches!(
            parse_scan_messages(&buffer),
            Err(NetlinkError::MalformedMessage(_))
        ));
    }

    #[test]
    fn rejects_truncated_information_element() {
        let mut ies = Vec::new();
        ies.extend_from_slice(&[IE_RSN, 30, 0, 1]);
        let mut buffer = Vec::new();
        buffer.extend(bss_message(
            Some([8, 8, 8, 8, 8, 8]),
            Some(b"TruncIe"),
            2437,
            -5000,
            0x0001,
            &ies,
        ));
        push_done(&mut buffer);
        assert!(matches!(
            parse_scan_messages(&buffer),
            Err(NetlinkError::MalformedMessage(_))
        ));
    }

    #[test]
    fn rejects_malformed_cipher_suite_list() {
        let mut raw = Vec::new();
        raw.extend(u32_attr(NL80211_ATTR_WIPHY, 0));
        raw.extend(attr_bytes(NL80211_ATTR_CIPHER_SUITES, &[1, 2, 3]));
        let attrs = parse_attrs(&raw).unwrap();
        let wiphy = wiphy_from_attrs(&attrs);
        assert!(matches!(wiphy, Err(NetlinkError::MalformedMessage(_))));
    }

    #[test]
    fn parses_ssid_with_binary_octets() {
        let mut ies = Vec::new();
        ies.extend(ssid_ie(&[0xde, 0xad, 0x01, 0x02]));
        let ssid = ssid_from_ies(&ies).unwrap();
        assert_eq!(ssid.display_string(), "\\xde\\xad\\x01\\x02");
        assert_eq!(
            Ssid::from_bytes(b"plain").unwrap().display_string(),
            "plain"
        );
        assert_eq!(Ssid::from_bytes(b"").unwrap().display_string(), "(hidden)");
    }

    #[test]
    fn formats_bssid_and_ssid() {
        assert_eq!(
            Bssid([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]).to_string(),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(Ssid::from_bytes(b"home").unwrap().to_string(), "home");
    }

    #[test]
    fn maps_frequency_to_channel() {
        assert_eq!(frequency_to_channel(2412), Some(1));
        assert_eq!(frequency_to_channel(2437), Some(6));
        assert_eq!(frequency_to_channel(2462), Some(11));
        assert_eq!(frequency_to_channel(2484), Some(14));
        assert_eq!(frequency_to_channel(5180), Some(36));
        assert_eq!(frequency_to_channel(5745), Some(149));
        assert_eq!(frequency_to_channel(5955), Some(1));
        assert_eq!(frequency_to_channel(6135), Some(37));
        assert_eq!(frequency_to_channel(100), None);
    }

    #[test]
    fn builds_well_formed_request() {
        let request = build_message(FAMILY_ID, NL80211_CMD_GET_INTERFACE, NLM_F_REQUEST, 7, &[]);
        assert_eq!(
            request.len() as u32,
            u32::from_ne_bytes(request[0..4].try_into().unwrap())
        );
        let header = read_unaligned::<NlMsgHdr>(&request).unwrap();
        assert_eq!(header.nlmsg_type, FAMILY_ID);
        assert_eq!(header.nlmsg_flags, NLM_F_REQUEST);
        assert_eq!(header.nlmsg_seq, 7);
        assert_eq!(request[16..20], [NL80211_CMD_GET_INTERFACE, 1, 0, 0]);
    }

    #[test]
    fn parses_ack_and_kernel_error() {
        let mut ok = vec![0_u8; 4];
        assert!(parse_ack_error(&ok).is_ok());
        ok[0] = 0xff;
        ok[1] = 0xff;
        ok[2] = 0xff;
        ok[3] = 0xff;
        assert!(matches!(
            parse_ack_error(&ok),
            Err(NetlinkError::Kernel(-1))
        ));
        let short = vec![0_u8; 2];
        assert!(matches!(
            parse_ack_error(&short),
            Err(NetlinkError::MalformedMessage(_))
        ));
    }

    #[test]
    fn parses_multiple_events_with_padding() {
        let mut buffer = Vec::new();
        buffer.extend(scan_event_message(NL80211_CMD_NEW_SCAN_RESULTS, 3, 2437));
        while buffer.len() % 4 != 0 {
            buffer.push(0);
        }
        buffer.extend(scan_event_message(NL80211_CMD_SCAN_ABORTED, 4, 5180));
        push_done(&mut buffer);
        let events = parse_scan_events(&buffer).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].interface_index, 3);
        assert_eq!(events[1].interface_index, 4);
    }
}
