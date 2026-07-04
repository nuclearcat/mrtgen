//! Builders for well-formed MRT records of every standard type/subtype.

use crate::bgp;
use crate::types::*;
use crate::writer::{Buf, MrtRecord};

/// A peer entry for the TABLE_DUMP_V2 PEER_INDEX_TABLE.
#[derive(Debug, Clone)]
pub struct Peer {
    pub bgp_id: [u8; 4],
    /// 4-byte (IPv4) or 16-byte (IPv6) address.
    pub ip: Vec<u8>,
    pub asn: u32,
    /// Encode the AS as 4 bytes (peer type bit 6).
    pub as4: bool,
}

impl Peer {
    fn peer_type(&self) -> u8 {
        let mut t = 0u8;
        if self.as4 {
            t |= 0x02;
        }
        if self.ip.len() == 16 {
            t |= 0x01;
        }
        t
    }

    fn encode(&self, b: &mut Buf) {
        b.u8(self.peer_type());
        b.bytes(&self.bgp_id);
        b.bytes(&self.ip);
        if self.as4 {
            b.u32(self.asn);
        } else {
            b.u16(self.asn as u16);
        }
    }
}

/// TABLE_DUMP_V2 PEER_INDEX_TABLE (RFC 6396 section 4.3.1).
pub fn peer_index_table(timestamp: u32, collector_id: [u8; 4], view_name: &str, peers: &[Peer]) -> MrtRecord {
    let mut b = Buf::new();
    b.bytes(&collector_id);
    b.u16(view_name.len() as u16).bytes(view_name.as_bytes());
    b.u16(peers.len() as u16);
    for p in peers {
        p.encode(&mut b);
    }
    MrtRecord::new(timestamp, TABLE_DUMP_V2, PEER_INDEX_TABLE, b.into_vec())
}

/// One RIB entry inside a TABLE_DUMP_V2 RIB record.
#[derive(Debug, Clone)]
pub struct RibEntry {
    pub peer_index: u16,
    pub originated_time: u32,
    /// Present only for the _ADDPATH RIB subtypes (RFC 8050 section 4.1).
    pub path_id: Option<u32>,
    /// Concatenated, pre-encoded BGP path attributes.
    pub attributes: Vec<u8>,
    /// Override for the Attribute Length field; `None` = correct value.
    pub declared_attr_len: Option<u16>,
}

impl RibEntry {
    pub fn new(peer_index: u16, originated_time: u32, attributes: Vec<u8>) -> Self {
        Self { peer_index, originated_time, path_id: None, attributes, declared_attr_len: None }
    }

    fn encode(&self, b: &mut Buf) {
        b.u16(self.peer_index);
        b.u32(self.originated_time);
        if let Some(id) = self.path_id {
            b.u32(id);
        }
        b.u16(self.declared_attr_len.unwrap_or(self.attributes.len() as u16));
        b.bytes(&self.attributes);
    }
}

/// AFI/SAFI-specific TABLE_DUMP_V2 RIB record (subtypes 2-5 and 8-11).
/// `nlri_prefix` is the NLRI-encoded prefix: length octet + truncated address.
pub fn rib_afi_safi(timestamp: u32, subtype: u16, sequence: u32, nlri_prefix: &[u8], entries: &[RibEntry]) -> MrtRecord {
    let mut b = Buf::new();
    b.u32(sequence);
    b.bytes(nlri_prefix);
    b.u16(entries.len() as u16);
    for e in entries {
        e.encode(&mut b);
    }
    MrtRecord::new(timestamp, TABLE_DUMP_V2, subtype, b.into_vec())
}

/// TABLE_DUMP_V2 RIB_GENERIC / RIB_GENERIC_ADDPATH (RFC 6396 section 4.3.3).
pub fn rib_generic(timestamp: u32, subtype: u16, sequence: u32, afi: u16, safi: u8, nlri: &[u8], entries: &[RibEntry]) -> MrtRecord {
    let mut b = Buf::new();
    b.u32(sequence);
    b.u16(afi).u8(safi);
    b.bytes(nlri);
    b.u16(entries.len() as u16);
    for e in entries {
        e.encode(&mut b);
    }
    MrtRecord::new(timestamp, TABLE_DUMP_V2, subtype, b.into_vec())
}

/// Legacy TABLE_DUMP record (RFC 6396 section 4.2). The prefix and peer IP
/// are full-width (4 or 16 bytes) as selected by the subtype.
#[allow(clippy::too_many_arguments)]
pub fn table_dump(
    timestamp: u32,
    subtype: u16,
    view: u16,
    sequence: u16,
    prefix: &[u8],
    prefix_len: u8,
    originated: u32,
    peer_ip: &[u8],
    peer_as: u16,
    attributes: &[u8],
) -> MrtRecord {
    let mut b = Buf::new();
    b.u16(view).u16(sequence);
    b.bytes(prefix);
    b.u8(prefix_len).u8(1); // status: always 1 per RFC 6396
    b.u32(originated);
    b.bytes(peer_ip);
    b.u16(peer_as);
    b.u16(attributes.len() as u16);
    b.bytes(attributes);
    MrtRecord::new(timestamp, TABLE_DUMP, subtype, b.into_vec())
}

/// Common prefix of every BGP4MP body: peer/local AS, ifindex, AFI, addresses.
fn bgp4mp_prelude(peer_as: u32, local_as: u32, as4: bool, ifindex: u16, peer_ip: &[u8], local_ip: &[u8]) -> Buf {
    debug_assert_eq!(peer_ip.len(), local_ip.len());
    let afi = if peer_ip.len() == 16 { BGP_AFI_IPV6 } else { BGP_AFI_IPV4 };
    let mut b = Buf::new();
    if as4 {
        b.u32(peer_as).u32(local_as);
    } else {
        b.u16(peer_as as u16).u16(local_as as u16);
    }
    b.u16(ifindex).u16(afi);
    b.bytes(peer_ip).bytes(local_ip);
    b
}

/// BGP4MP_MESSAGE and friends (subtypes 1, 4, 6, 7 and the _ADDPATH forms).
/// Whether AS numbers are 2 or 4 bytes is derived from the subtype.
#[allow(clippy::too_many_arguments)]
pub fn bgp4mp_message(
    timestamp: u32,
    mrt_type: u16,
    microsecond: Option<u32>,
    subtype: u16,
    peer_as: u32,
    local_as: u32,
    ifindex: u16,
    peer_ip: &[u8],
    local_ip: &[u8],
    bgp_message: &[u8],
) -> MrtRecord {
    let as4 = matches!(
        subtype,
        BGP4MP_MESSAGE_AS4
            | BGP4MP_MESSAGE_AS4_LOCAL
            | BGP4MP_MESSAGE_AS4_ADDPATH
            | BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH
            | BGP4MP_STATE_CHANGE_AS4
    );
    let mut b = bgp4mp_prelude(peer_as, local_as, as4, ifindex, peer_ip, local_ip);
    b.bytes(bgp_message);
    match microsecond {
        Some(us) => MrtRecord::new_et(timestamp, us, mrt_type, subtype, b.into_vec()),
        None => MrtRecord::new(timestamp, mrt_type, subtype, b.into_vec()),
    }
}

/// BGP4MP_STATE_CHANGE / BGP4MP_STATE_CHANGE_AS4 (RFC 6396 sections 4.4.1, 4.4.4).
#[allow(clippy::too_many_arguments)]
pub fn bgp4mp_state_change(
    timestamp: u32,
    subtype: u16,
    peer_as: u32,
    local_as: u32,
    ifindex: u16,
    peer_ip: &[u8],
    local_ip: &[u8],
    old_state: u16,
    new_state: u16,
) -> MrtRecord {
    let as4 = subtype == BGP4MP_STATE_CHANGE_AS4;
    let mut b = bgp4mp_prelude(peer_as, local_as, as4, ifindex, peer_ip, local_ip);
    b.u16(old_state).u16(new_state);
    MrtRecord::new(timestamp, BGP4MP, subtype, b.into_vec())
}

/// OSPFv2 record (RFC 6396 section 4.1). Subtype is 0.
pub fn ospfv2(timestamp: u32, remote: [u8; 4], local: [u8; 4], ospf_pdu: &[u8]) -> MrtRecord {
    let mut b = Buf::new();
    b.bytes(&remote).bytes(&local).bytes(ospf_pdu);
    MrtRecord::new(timestamp, OSPFV2, 0, b.into_vec())
}

/// OSPFv3 / OSPFv3_ET record (RFC 6396 section 4.6).
pub fn ospfv3(timestamp: u32, microsecond: Option<u32>, remote: [u8; 16], local: [u8; 16], ospf_pdu: &[u8]) -> MrtRecord {
    let mut b = Buf::new();
    b.u16(BGP_AFI_IPV6).bytes(&remote).bytes(&local).bytes(ospf_pdu);
    let (ty, body) = (if microsecond.is_some() { OSPFV3_ET } else { OSPFV3 }, b.into_vec());
    match microsecond {
        Some(us) => MrtRecord::new_et(timestamp, us, ty, 0, body),
        None => MrtRecord::new(timestamp, ty, 0, body),
    }
}

/// ISIS / ISIS_ET record (RFC 6396 section 4.5): raw PDU, subtype undefined (0).
pub fn isis(timestamp: u32, microsecond: Option<u32>, pdu: &[u8]) -> MrtRecord {
    match microsecond {
        Some(us) => MrtRecord::new_et(timestamp, us, ISIS_ET, 0, pdu.to_vec()),
        None => MrtRecord::new(timestamp, ISIS, 0, pdu.to_vec()),
    }
}

/// A representative, deterministic set of path attributes for RIB entries
/// (4-byte AS_PATH as TABLE_DUMP_V2 requires). `salt` varies the values.
pub fn standard_attrs_v4(salt: u32) -> Vec<u8> {
    let mut attrs = Vec::new();
    attrs.extend(bgp::attr_origin(0));
    attrs.extend(bgp::attr_as_path_4b(&[64500 + salt, 65000 + salt, 4200000000 + salt]));
    attrs.extend(bgp::attr_next_hop([192, 0, 2, (1 + salt) as u8]));
    attrs.extend(bgp::attr_med(100 + salt));
    attrs.extend(bgp::attr_local_pref(200 + salt));
    attrs.extend(bgp::attr_atomic_aggregate());
    attrs.extend(bgp::attr_aggregator_4b(64500 + salt, [192, 0, 2, 254]));
    attrs.extend(bgp::attr_communities(&[(64500u32 << 16) | (10 + salt), 0xFFFF_FF01]));
    attrs
}

/// Same but next-hop delivered via the abbreviated TABLE_DUMP_V2
/// MP_REACH_NLRI form, for IPv6 RIB entries.
pub fn standard_attrs_v6(salt: u32) -> Vec<u8> {
    let mut nh = [0u8; 16];
    nh[0] = 0x20;
    nh[1] = 0x01;
    nh[2] = 0x0d;
    nh[3] = 0xb8;
    nh[15] = (1 + salt) as u8;
    let mut attrs = Vec::new();
    attrs.extend(bgp::attr_origin(1));
    attrs.extend(bgp::attr_as_path_4b(&[64500 + salt, 4200000000 + salt]));
    attrs.extend(bgp::attr_mp_reach_td2(&nh));
    attrs.extend(bgp::attr_local_pref(300 + salt));
    attrs
}
