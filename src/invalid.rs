//! Builders for deliberately malformed records.
//!
//! Two damage classes exist, mirroring [`crate::manifest::Expect`]:
//!
//! * **Skip-class** — the MRT common header and its Length field are
//!   consistent with the bytes that follow, but the record content is
//!   broken (unknown type, wrong attribute TLV sizes, inner truncation).
//!   A parser must be able to skip such a record and keep loading.
//! * **Abort-class** — the framing itself lies (Length points past EOF,
//!   header cut short). There is no way to find the next record, so a
//!   parser must stop. These are emitted as raw byte tails, not records,
//!   and must be the last thing in a file.

use crate::bgp;
use crate::records::{self, RibEntry};
use crate::types::*;
use crate::writer::{Buf, MrtRecord};

// ---------------------------------------------------------------- skip class

/// A record with an MRT type nobody has defined. Body is benign filler.
pub fn unknown_mrt_type(timestamp: u32, mrt_type: u16) -> MrtRecord {
    MrtRecord::new(timestamp, mrt_type, 0, vec![0xDE, 0xAD, 0xBE, 0xEF])
}

/// A known MRT type with an undefined subtype.
pub fn unknown_subtype(timestamp: u32, mrt_type: u16, subtype: u16) -> MrtRecord {
    MrtRecord::new(timestamp, mrt_type, subtype, vec![0xCA, 0xFE, 0xBA, 0xBE])
}

/// BGP4MP_MESSAGE whose UPDATE carries one fixed-size attribute encoded with
/// the wrong length. `declared_len` both drives the TLV length field and the
/// actual number of value bytes, so all outer framing stays consistent —
/// only the attribute itself violates its type's required size (e.g. MED
/// must be 4 bytes; pass 2, 8 or 16 to break it).
pub fn bgp4mp_wrong_attr_size(timestamp: u32, attr_flags: u8, attr_code: u8, declared_len: u16) -> MrtRecord {
    let value = vec![0xAB; declared_len as usize];
    let mut attrs = bgp::attr_origin(0);
    attrs.extend(bgp::attribute_declared(attr_flags, attr_code, declared_len, &value));
    let update = bgp::bgp_update(&[], &attrs, &bgp::nlri_v4([198, 51, 100, 0], 24));
    records::bgp4mp_message(timestamp, BGP4MP, None, BGP4MP_MESSAGE, 64500, 64501, 1, &[192, 0, 2, 1], &[192, 0, 2, 2], &update)
}

/// BGP4MP_MESSAGE whose UPDATE has an attribute TLV whose declared length
/// overruns the attribute section: the TLV claims `declared_len` bytes but
/// only `actual_len` follow. Attribute iteration must fail.
pub fn bgp4mp_attr_overrun(timestamp: u32, declared_len: u16, actual_len: usize) -> MrtRecord {
    let value = vec![0x55; actual_len];
    let attrs = bgp::attribute_declared(FLAG_OPTIONAL, ATTR_MULTI_EXIT_DISC, declared_len, &value);
    // Total Path Attribute Length reflects the real byte count, so the
    // overrun is only discoverable while walking the TLVs.
    let update = bgp::bgp_update(&[], &attrs, &[]);
    records::bgp4mp_message(timestamp, BGP4MP, None, BGP4MP_MESSAGE, 64500, 64501, 1, &[192, 0, 2, 1], &[192, 0, 2, 2], &update)
}

/// BGP4MP_MESSAGE whose BGP marker is not all-ones (RFC 4271 section 4.1).
pub fn bgp4mp_bad_marker(timestamp: u32) -> MrtRecord {
    let mut marker = [0xFF; 16];
    marker[7] = 0x00;
    let msg = bgp::bgp_message_raw(marker, 19, BGP_KEEPALIVE, &[]);
    records::bgp4mp_message(timestamp, BGP4MP, None, BGP4MP_MESSAGE, 64500, 64501, 1, &[192, 0, 2, 1], &[192, 0, 2, 2], &msg)
}

/// BGP4MP_MESSAGE whose BGP header Length field is out of the legal
/// 19..=4096 range (RFC 4271) or disagrees with the record size.
pub fn bgp4mp_bad_bgp_length(timestamp: u32, declared: u16) -> MrtRecord {
    let msg = bgp::bgp_message_raw([0xFF; 16], declared, BGP_KEEPALIVE, &[]);
    records::bgp4mp_message(timestamp, BGP4MP, None, BGP4MP_MESSAGE, 64500, 64501, 1, &[192, 0, 2, 1], &[192, 0, 2, 2], &msg)
}

/// BGP4MP_MESSAGE whose body stops in the middle of the BGP header
/// (record framing consistent, inner message truncated).
pub fn bgp4mp_truncated_bgp(timestamp: u32) -> MrtRecord {
    let full = bgp::bgp_keepalive();
    let cut = &full[..10]; // ends inside the 16-byte marker
    records::bgp4mp_message(timestamp, BGP4MP, None, BGP4MP_MESSAGE, 64500, 64501, 1, &[192, 0, 2, 1], &[192, 0, 2, 2], cut)
}

/// A BGP4MP_MESSAGE record with a zero-length body: the header is valid
/// but the mandatory per-subtype fields are absent.
pub fn bgp4mp_empty_body(timestamp: u32) -> MrtRecord {
    MrtRecord::new(timestamp, BGP4MP, BGP4MP_MESSAGE, Vec::new())
}

/// TABLE_DUMP_V2 RIB record whose single entry declares more attribute
/// bytes than the record contains.
pub fn rib_attr_len_overrun(timestamp: u32, sequence: u32) -> MrtRecord {
    let mut entry = RibEntry::new(0, timestamp, records::standard_attrs_v4(0));
    let real = entry.attributes.len() as u16;
    entry.declared_attr_len = Some(real + 64);
    records::rib_afi_safi(timestamp, RIB_IPV4_UNICAST, sequence, &bgp::nlri_v4([203, 0, 113, 0], 24), &[entry])
}

/// TABLE_DUMP_V2 RIB record with an impossible NLRI prefix length
/// (e.g. 33 for IPv4, 129 for IPv6).
pub fn rib_bad_prefix_len(timestamp: u32, sequence: u32, ipv6: bool, bits: u8) -> MrtRecord {
    if ipv6 {
        let mut p = [0u8; 16];
        p[0] = 0x20;
        p[1] = 0x01;
        let mut nlri = vec![bits];
        nlri.extend_from_slice(&p); // full 16 bytes of address
        let entry = RibEntry::new(2, timestamp, records::standard_attrs_v6(0));
        records::rib_afi_safi(timestamp, RIB_IPV6_UNICAST, sequence, &nlri, &[entry])
    } else {
        let mut nlri = vec![bits];
        nlri.extend_from_slice(&[203, 0, 113, 0]);
        let entry = RibEntry::new(0, timestamp, records::standard_attrs_v4(0));
        records::rib_afi_safi(timestamp, RIB_IPV4_UNICAST, sequence, &nlri, &[entry])
    }
}

/// TABLE_DUMP_V2 RIB_GENERIC VPNv4 record (AFI 1 / SAFI 128) whose NLRI
/// length octet is impossible for the address family: fewer bits than the
/// mandatory label (24) + RD (64), or more than label + RD + a full IPv4
/// address (120). The encoded NLRI bytes honestly match the length octet,
/// so all framing stays consistent.
pub fn rib_generic_vpn_bad_prefix_len(timestamp: u32, sequence: u32, bits: u8) -> MrtRecord {
    let mut nlri = vec![bits];
    nlri.extend(vec![0xAA; (bits as usize).div_ceil(8)]);
    let entry = RibEntry::new(0, timestamp, records::standard_attrs_v4(0));
    records::rib_generic(timestamp, RIB_GENERIC, sequence, BGP_AFI_IPV4, SAFI_MPLS_VPN, &nlri, &[entry])
}

/// PEER_INDEX_TABLE whose Peer Count claims more entries than are encoded.
pub fn peer_index_count_mismatch(timestamp: u32, claimed: u16, actual: u16) -> MrtRecord {
    let mut b = Buf::new();
    b.bytes(&[192, 0, 2, 99]); // collector id
    b.u16(0); // empty view name
    b.u16(claimed);
    for i in 0..actual {
        b.u8(0); // IPv4, 2-byte AS
        b.bytes(&[192, 0, 2, i as u8]);
        b.bytes(&[10, 0, 0, i as u8]);
        b.u16(64500 + i);
    }
    MrtRecord::new(timestamp, TABLE_DUMP_V2, PEER_INDEX_TABLE, b.into_vec())
}

/// Legacy TABLE_DUMP record whose Attribute Length disagrees with the
/// record length (declares more attribute bytes than remain).
pub fn table_dump_attr_overrun(timestamp: u32) -> MrtRecord {
    let attrs = bgp::attr_origin(0);
    let mut b = Buf::new();
    b.u16(0).u16(7); // view, sequence
    b.bytes(&[203, 0, 113, 0]).u8(24).u8(1);
    b.u32(timestamp);
    b.bytes(&[192, 0, 2, 1]);
    b.u16(64500);
    b.u16(attrs.len() as u16 + 100); // lie
    b.bytes(&attrs);
    MrtRecord::new(timestamp, TABLE_DUMP, AFI_IPV4, b.into_vec())
}

// ------------------------------------------- skip class: attribute error handling
// These mirror RFC 7606 (Revised Error Handling for BGP UPDATE Messages): the
// MRT framing and BGP message framing are honest, but a single path attribute
// violates a per-attribute rule (bad length/flags, illegal zero length,
// unrecognised type, malformed AS_PATH segment, malformed MP_REACH/UNREACH).

/// Wrap crafted path attributes in a BGP4MP_MESSAGE UPDATE (2-byte AS transport).
fn bgp4mp_update(timestamp: u32, attrs: &[u8], nlri: &[u8]) -> MrtRecord {
    let update = bgp::bgp_update(&[], attrs, nlri);
    records::bgp4mp_message(timestamp, BGP4MP, None, BGP4MP_MESSAGE, 64500, 64501, 1, &[192, 0, 2, 1], &[192, 0, 2, 2], &update)
}

fn nlri24() -> Vec<u8> {
    bgp::nlri_v4([198, 51, 100, 0], 24)
}

/// BGP4MP UPDATE whose AS_PATH attribute value (the segment bytes) is crafted
/// by the caller. The TLV length is honest — the damage is inside the value,
/// so it is only discoverable while walking segments (RFC 7606: malformed if
/// segment type unrecognised, or the segments overrun/underrun the attribute,
/// or a segment has zero length).
pub fn bgp4mp_as_path_raw(timestamp: u32, segment: &[u8]) -> MrtRecord {
    let mut attrs = bgp::attr_origin(0);
    attrs.extend(bgp::attribute(FLAG_TRANSITIVE, ATTR_AS_PATH, segment));
    attrs.extend(bgp::attr_next_hop([192, 0, 2, 1]));
    bgp4mp_update(timestamp, &attrs, &nlri24())
}

/// BGP4MP UPDATE carrying an AS_PATH of a single AS_TRANS (23456) placeholder
/// plus an AS4_PATH that is *longer* than the AS_PATH. Per RFC 6793 the
/// AS4_PATH is then ignored (so the record is valid), but the mismatch has
/// historically panicked parsers that blindly merge the two.
pub fn bgp4mp_as4_path_longer(timestamp: u32) -> MrtRecord {
    let mut attrs = bgp::attr_origin(0);
    attrs.extend(bgp::attr_as_path_2b(&[23456]));
    attrs.extend(bgp::attr_next_hop([192, 0, 2, 1]));
    let mut seg = Buf::new();
    seg.u8(2).u8(3).u32(4_200_000_001).u32(4_200_000_002).u32(4_200_000_003);
    attrs.extend(bgp::attribute(FLAG_OPTIONAL | FLAG_TRANSITIVE, ATTR_AS4_PATH, &seg.into_vec()));
    bgp4mp_update(timestamp, &attrs, &nlri24())
}

/// BGP4MP UPDATE whose ORIGIN attribute carries the given flags — used to set
/// the Optional bit on a well-known attribute (RFC 7606 attribute-flags error).
pub fn bgp4mp_attr_bad_flags(timestamp: u32, flags: u8, code: u8, value: &[u8]) -> MrtRecord {
    let mut attrs = bgp::attr_as_path_2b(&[64500]);
    attrs.extend(bgp::attribute_declared(flags, code, value.len() as u16, value));
    attrs.extend(bgp::attr_next_hop([192, 0, 2, 1]));
    bgp4mp_update(timestamp, &attrs, &nlri24())
}

/// BGP4MP UPDATE with the Extended Length flag set on an attribute whose value
/// is ≤255 bytes (RFC 4271: ext-len may be used only for values > 255).
pub fn bgp4mp_spurious_ext_len(timestamp: u32) -> MrtRecord {
    let mut attrs = bgp::attr_origin(0);
    attrs.extend(bgp::attr_as_path_2b(&[64500]));
    attrs.extend(bgp::attr_next_hop([192, 0, 2, 1]));
    attrs.extend(bgp::attribute_declared(FLAG_OPTIONAL | FLAG_EXT_LEN, ATTR_MULTI_EXIT_DISC, 4, &100u32.to_be_bytes()));
    bgp4mp_update(timestamp, &attrs, &nlri24())
}

/// BGP4MP UPDATE with an MP_REACH_NLRI whose Next Hop Length field promises
/// more next-hop bytes than are present, so the NLRI cannot be located
/// (RFC 7606: session reset / AFI-SAFI disable).
pub fn bgp4mp_mp_reach_bad_nh_len(timestamp: u32) -> MrtRecord {
    let mut val = Buf::new();
    val.u16(BGP_AFI_IPV6).u8(SAFI_UNICAST).u8(32); // claims a 32-byte next hop...
    val.bytes(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]); // ...but only 16 follow
    val.u8(0); // reserved
    val.bytes(&[64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]); // NLRI 2001:db8::/64 (will be misread)
    let mut attrs = bgp::attr_origin(0);
    attrs.extend(bgp::attr_as_path_2b(&[64500]));
    attrs.extend(bgp::attribute(FLAG_OPTIONAL, ATTR_MP_REACH_NLRI, &val.into_vec()));
    bgp4mp_update(timestamp, &attrs, &[])
}

/// BGP4MP UPDATE with an MP_UNREACH_NLRI shorter than 3 bytes (cannot even
/// hold the AFI + SAFI). RFC 7606 treats length < 3 as malformed.
pub fn bgp4mp_mp_unreach_short(timestamp: u32) -> MrtRecord {
    let mut attrs = bgp::attr_origin(0);
    attrs.extend(bgp::attr_as_path_2b(&[64500]));
    attrs.extend(bgp::attribute(FLAG_OPTIONAL, ATTR_MP_UNREACH_NLRI, &[0x00, 0x02])); // AFI only
    bgp4mp_update(timestamp, &attrs, &[])
}

/// BGP4MP UPDATE with an attribute encoded at length 0. Illegal for every
/// attribute except AS_PATH and ATOMIC_AGGREGATE (RFC 7606).
pub fn bgp4mp_zero_len_attr(timestamp: u32, flags: u8, code: u8) -> MrtRecord {
    let mut attrs = bgp::attr_as_path_2b(&[64500]);
    attrs.extend(bgp::attribute_declared(flags, code, 0, &[]));
    bgp4mp_update(timestamp, &attrs, &nlri24())
}

/// BGP4MP UPDATE with an ATOMIC_AGGREGATE whose length is non-zero (must be 0).
pub fn bgp4mp_atomic_aggregate_nonzero(timestamp: u32) -> MrtRecord {
    let mut attrs = bgp::attr_origin(0);
    attrs.extend(bgp::attr_as_path_2b(&[64500]));
    attrs.extend(bgp::attr_next_hop([192, 0, 2, 1]));
    attrs.extend(bgp::attribute_declared(FLAG_TRANSITIVE, ATTR_ATOMIC_AGGREGATE, 4, &[0, 0, 0, 0]));
    bgp4mp_update(timestamp, &attrs, &nlri24())
}

/// BGP4MP UPDATE with an AGGREGATOR (code 7) whose length is neither 6
/// (2-byte AS) nor 8 (4-byte AS) — RFC 7606 malformed.
pub fn bgp4mp_aggregator_bad_len(timestamp: u32, declared: u16) -> MrtRecord {
    let value = vec![0xAB; declared as usize];
    let mut attrs = bgp::attr_origin(0);
    attrs.extend(bgp::attr_as_path_2b(&[64500]));
    attrs.extend(bgp::attr_next_hop([192, 0, 2, 1]));
    attrs.extend(bgp::attribute_declared(FLAG_OPTIONAL | FLAG_TRANSITIVE, ATTR_AGGREGATOR, declared, &value));
    bgp4mp_update(timestamp, &attrs, &nlri24())
}

/// BGP4MP UPDATE carrying an attribute of the given optional-transitive type
/// code with a small benign value. With an unassigned code a conforming parser
/// must retain it (as raw) and still load the record; with type 0 (reserved)
/// the attribute is invalid.
pub fn bgp4mp_extra_attr(timestamp: u32, code: u8) -> MrtRecord {
    let mut attrs = bgp::attr_origin(0);
    attrs.extend(bgp::attr_as_path_2b(&[64500]));
    attrs.extend(bgp::attr_next_hop([192, 0, 2, 1]));
    attrs.extend(bgp::attribute(FLAG_OPTIONAL | FLAG_TRANSITIVE, code, &[0xDE, 0xAD, 0xBE, 0xEF]));
    bgp4mp_update(timestamp, &attrs, &nlri24())
}

/// TABLE_DUMP_V2 RIB record whose entry references a peer index that does not
/// exist in the PEER_INDEX_TABLE (has historically panicked parsers).
pub fn rib_bad_peer_index(timestamp: u32, sequence: u32, peer_index: u16) -> MrtRecord {
    let entry = RibEntry::new(peer_index, timestamp, records::standard_attrs_v4(0));
    records::rib_afi_safi(timestamp, RIB_IPV4_UNICAST, sequence, &bgp::nlri_v4([203, 0, 113, 0], 24), &[entry])
}

/// A record typed BGP4MP_ET whose body is too short (2 bytes) to hold the
/// mandatory 4-byte Microsecond Timestamp. The MRT Length is honest.
pub fn bgp4mp_et_short(timestamp: u32) -> MrtRecord {
    MrtRecord::new(timestamp, BGP4MP_ET, BGP4MP_MESSAGE, vec![0x00, 0x00])
}

// --------------------------------------------------------------- abort class

/// Raw tail: a complete MRT header whose Length points far past end of
/// file, followed by fewer bytes than promised. Must terminate the file.
pub fn tail_length_overruns_eof(timestamp: u32, declared: u32, actual: usize) -> Vec<u8> {
    let mut rec = MrtRecord::new(timestamp, BGP4MP, BGP4MP_MESSAGE, vec![0x00; actual]);
    rec.declared_length = Some(declared);
    rec.encode()
}

/// Raw tail: a truncated MRT common header (fewer than 12 bytes at EOF).
pub fn tail_truncated_header(timestamp: u32, keep: usize) -> Vec<u8> {
    assert!(keep < 12);
    let rec = MrtRecord::new(timestamp, BGP4MP, BGP4MP_MESSAGE, Vec::new());
    let mut bytes = rec.encode();
    bytes.truncate(keep);
    bytes
}
