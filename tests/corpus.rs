//! Corpus-level guarantees: determinism, framing consistency, and the
//! skip/abort semantics the manifest promises.

use mrtgen::{generate, Expect, FatalKind, GeneratorConfig};

/// Minimal reference reader: walk records by trusting each header's
/// Length field. Returns (records_walked, clean_eof).
fn walk(bytes: &[u8]) -> (usize, bool) {
    let mut off = 0usize;
    let mut n = 0usize;
    while off < bytes.len() {
        if bytes.len() - off < 12 {
            return (n, false); // truncated header
        }
        let len = u32::from_be_bytes(bytes[off + 8..off + 12].try_into().unwrap()) as usize;
        let Some(end) = off.checked_add(12 + len) else {
            return (n, false);
        };
        if end > bytes.len() {
            return (n, false); // length overruns EOF
        }
        off = end;
        n += 1;
    }
    (n, true)
}

#[test]
fn generation_is_deterministic() {
    let a = generate(&GeneratorConfig::default());
    let b = generate(&GeneratorConfig::default());
    assert_eq!(a.bytes, b.bytes);
    assert_eq!(a.manifest.to_json(), b.manifest.to_json());
}

#[test]
fn manifest_offsets_match_file_layout() {
    let corpus = generate(&GeneratorConfig::default());
    let mut expected_offset = 0u64;
    for rec in &corpus.manifest.records {
        assert_eq!(rec.offset, expected_offset, "record {} ({})", rec.index, rec.kind);
        // Header fields at the recorded offset must match the manifest.
        let o = rec.offset as usize;
        let ts = u32::from_be_bytes(corpus.bytes[o..o + 4].try_into().unwrap());
        let ty = u16::from_be_bytes(corpus.bytes[o + 4..o + 6].try_into().unwrap());
        let st = u16::from_be_bytes(corpus.bytes[o + 6..o + 8].try_into().unwrap());
        assert_eq!(ts, rec.timestamp, "timestamp of {}", rec.kind);
        assert_eq!(ty, rec.mrt_type, "type of {}", rec.kind);
        assert_eq!(st, rec.subtype, "subtype of {}", rec.kind);
        expected_offset += rec.size;
    }
    assert_eq!(expected_offset, corpus.manifest.file_size);
    assert_eq!(corpus.bytes.len() as u64, corpus.manifest.file_size);
}

#[test]
fn valid_and_skip_records_are_walkable() {
    // Without a fatal tail, every record (valid or skip-class) must have an
    // honest Length field, so a dumb walker reaches EOF cleanly.
    let corpus = generate(&GeneratorConfig::default());
    let (n, clean) = walk(&corpus.bytes);
    assert!(clean, "file must end exactly on a record boundary");
    assert_eq!(n, corpus.manifest.records.len());
    assert!(corpus.manifest.counts.valid > 0);
    assert!(corpus.manifest.counts.skip > 0);
    assert_eq!(corpus.manifest.counts.abort, 0);
}

#[test]
fn fatal_tails_break_the_walk() {
    for kind in FatalKind::ALL {
        let corpus = generate(&GeneratorConfig { fatal: Some(kind), ..GeneratorConfig::default() });
        let (n, clean) = walk(&corpus.bytes);
        assert!(!clean, "{:?}: walker must NOT reach clean EOF", kind);
        // Everything before the tail is still walkable.
        assert_eq!(n, corpus.manifest.records.len() - 1, "{:?}", kind);
        assert_eq!(corpus.manifest.counts.abort, 1);
        let last = corpus.manifest.records.last().unwrap();
        assert_eq!(last.expect, Expect::Abort);
        assert_eq!(last.kind, kind.kind_name());
    }
}

#[test]
fn corpus_covers_all_standard_types_and_expectations() {
    use std::collections::BTreeSet;
    let corpus = generate(&GeneratorConfig::default());

    let types: BTreeSet<u16> = corpus.manifest.records.iter().filter(|r| r.expect == Expect::Valid).map(|r| r.mrt_type).collect();
    for want in [11u16, 12, 13, 16, 17, 32, 33, 48, 49] {
        assert!(types.contains(&want), "missing valid records of MRT type {want}");
    }

    let td2_subtypes: BTreeSet<u16> =
        corpus.manifest.records.iter().filter(|r| r.expect == Expect::Valid && r.mrt_type == 13).map(|r| r.subtype).collect();
    for want in [1u16, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12] {
        assert!(td2_subtypes.contains(&want), "missing TABLE_DUMP_V2 subtype {want}");
    }

    let bgp4mp_subtypes: BTreeSet<u16> =
        corpus.manifest.records.iter().filter(|r| r.expect == Expect::Valid && r.mrt_type == 16).map(|r| r.subtype).collect();
    for want in [0u16, 1, 4, 5, 6, 7, 8, 9, 10, 11] {
        assert!(bgp4mp_subtypes.contains(&want), "missing BGP4MP subtype {want}");
    }

    // Kinds are unique so CI can key on them.
    let mut kinds = BTreeSet::new();
    for r in &corpus.manifest.records {
        assert!(kinds.insert(r.kind.clone()), "duplicate kind {}", r.kind);
    }
}

#[test]
fn vpn_records_cover_safi_128() {
    let corpus = generate(&GeneratorConfig::default());
    let find = |kind: &str| {
        corpus.manifest.records.iter().find(|r| r.kind == kind).unwrap_or_else(|| panic!("missing {kind}"))
    };

    // Valid VPN routes exist for both address families, plus a BGP4MP carrier.
    let v4 = find("rib_generic_vpnv4");
    assert_eq!(v4.expect, Expect::Valid);
    assert_eq!(v4.details["afi"], 1);
    assert_eq!(v4.details["safi"], 128);
    // Length octet counts label (24) + RD (64) + prefix bits.
    assert_eq!(v4.details["nlri_bits"], 24 + 64 + 24);

    let v6 = find("rib_generic_vpnv6");
    assert_eq!(v6.expect, Expect::Valid);
    assert_eq!(v6.details["afi"], 2);
    assert_eq!(v6.details["safi"], 128);
    assert_eq!(v6.details["nlri_bits"], 24 + 64 + 48);

    assert_eq!(find("bgp4mp_message_vpnv4_update").expect, Expect::Valid);

    // Impossible VPN NLRI lengths are skip-class.
    assert_eq!(find("invalid_rib_vpn_prefix_len_too_short").expect, Expect::Skip);
    assert_eq!(find("invalid_rib_vpn_prefix_len_too_long").expect, Expect::Skip);
}

#[test]
fn skip_records_include_wrong_tlv_sizes() {
    let corpus = generate(&GeneratorConfig::default());
    for kind in [
        "invalid_attr_origin_len4",
        "invalid_attr_med_len2",
        "invalid_attr_med_len8",
        "invalid_attr_nexthop_len16",
        "invalid_attr_aggregator4_len4",
        "invalid_attr_aggregator4_len16",
        "invalid_attr_len_overrun",
        "invalid_rib_attr_len_overrun",
    ] {
        let rec = corpus.manifest.records.iter().find(|r| r.kind == kind).unwrap_or_else(|| panic!("missing {kind}"));
        assert_eq!(rec.expect, Expect::Skip, "{kind}");
    }
}

#[test]
fn combo_records_cross_communities_and_addpath() {
    let corpus = generate(&GeneratorConfig::default());
    let find = |kind: &str| {
        corpus.manifest.records.iter().find(|r| r.kind == kind).unwrap_or_else(|| panic!("missing {kind}"))
    };

    // Legal combinations parse as valid records.
    for kind in [
        "combo_rib_v4_addpath_std_comm",
        "combo_rib_v4_addpath_ext_comm",
        "combo_rib_v4_addpath_large_comm",
        "combo_rib_v6_addpath_all_comm",
        "combo_rib_generic_addpath_comm",
        "combo_bgp4mp_addpath_comm",
        "combo_rib_v4_addpath_pathid0_comm",
        "combo_rib_v4_addpath_many_comm",
    ] {
        assert_eq!(find(kind).expect, Expect::Valid, "{kind}");
    }

    // The large legal block really does carry ~1000 communities.
    assert_eq!(find("combo_rib_v4_addpath_many_comm").details["community_count"], 1000);

    // Deliberately illegal combinations are skip-class (honest framing).
    for kind in [
        "combo_rib_pathid_in_nonaddpath",
        "combo_rib_addpath_missing_pathid",
        "combo_std_comm_bad_len_addpath",
        "combo_ext_comm_bad_len_addpath",
        "combo_large_comm_bad_len_addpath",
        "combo_dup_community_addpath",
        "combo_bgp4mp_addpath_plain_nlri",
        "combo_bgp4mp_addpath_comm_over_4096",
    ] {
        assert_eq!(find(kind).expect, Expect::Skip, "{kind}");
    }

    // The over-limit message really does exceed the 4096-byte BGP maximum.
    assert!(find("combo_bgp4mp_addpath_comm_over_4096").details["bgp_message_len"].as_u64().unwrap() > 4096);

    // The combo section can be turned off independently.
    let without = generate(&GeneratorConfig { include_combo: false, ..GeneratorConfig::default() });
    assert!(without.manifest.records.iter().all(|r| !r.kind.starts_with("combo_")));
    assert!(corpus.manifest.records.len() > without.manifest.records.len());
}

#[test]
fn attr_error_records_cover_rfc7606_cases() {
    let corpus = generate(&GeneratorConfig::default());
    let find = |kind: &str| {
        corpus.manifest.records.iter().find(|r| r.kind == kind).unwrap_or_else(|| panic!("missing {kind}"))
    };

    // Malformed content that a parser must reject and skip.
    for kind in [
        "attr_as_path_zero_len_segment",
        "attr_as_path_unknown_segment_type",
        "attr_as_path_count_overrun",
        "attr_as_path_trailing_bytes",
        "attr_origin_optional_flag",
        "attr_spurious_extended_length",
        "attr_mp_reach_bad_nexthop_len",
        "attr_mp_unreach_too_short",
        "attr_zero_len_origin",
        "attr_zero_len_nexthop",
        "attr_zero_len_community",
        "attr_atomic_aggregate_nonzero",
        "attr_aggregator_bad_len",
        "attr_type_code_zero",
        "attr_rib_bad_peer_index",
        "attr_bgp4mp_et_short",
    ] {
        assert_eq!(find(kind).expect, Expect::Skip, "{kind}");
    }

    // Valid-but-tricky records a robust parser must load without choking.
    for kind in ["attr_as4_path_longer_than_as_path", "attr_unknown_optional_transitive"] {
        assert_eq!(find(kind).expect, Expect::Valid, "{kind}");
    }

    // The section can be toggled off independently of the others.
    let without = generate(&GeneratorConfig { include_attr_errors: false, ..GeneratorConfig::default() });
    assert!(without.manifest.records.iter().all(|r| !r.kind.starts_with("attr_")));
    assert!(corpus.manifest.records.len() > without.manifest.records.len());
}

#[test]
fn manifest_json_round_trips() {
    let corpus = generate(&GeneratorConfig::default());
    let json = corpus.manifest.to_json();
    let back = mrtgen::Manifest::from_json(&json).unwrap();
    assert_eq!(back.records.len(), corpus.manifest.records.len());
    assert_eq!(back.file_size, corpus.manifest.file_size);
}
