//! Low-level MRT record framing (RFC 6396 section 2).

/// A single MRT record ready to be framed with a common header.
///
/// The common header is: Timestamp (4), Type (2), Subtype (2), Length (4).
/// Types with the `_ET` suffix carry an extra Microsecond Timestamp field
/// which is part of the message body for length-accounting purposes
/// (RFC 6396 section 3: the microsecond field IS included in Length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MrtRecord {
    pub timestamp: u32,
    pub mrt_type: u16,
    pub subtype: u16,
    /// Microsecond timestamp for Extended Timestamp (_ET) types.
    pub microsecond: Option<u32>,
    pub body: Vec<u8>,
    /// Override for the header Length field. `None` means the correct
    /// length is computed. Used to produce deliberately broken records.
    pub declared_length: Option<u32>,
}

impl MrtRecord {
    pub fn new(timestamp: u32, mrt_type: u16, subtype: u16, body: Vec<u8>) -> Self {
        Self { timestamp, mrt_type, subtype, microsecond: None, body, declared_length: None }
    }

    pub fn new_et(timestamp: u32, microsecond: u32, mrt_type: u16, subtype: u16, body: Vec<u8>) -> Self {
        Self { timestamp, mrt_type, subtype, microsecond: Some(microsecond), body, declared_length: None }
    }

    /// The value the Length header field will carry.
    pub fn wire_length(&self) -> u32 {
        self.declared_length.unwrap_or_else(|| {
            self.body.len() as u32 + if self.microsecond.is_some() { 4 } else { 0 }
        })
    }

    /// Total encoded size of this record (header + microseconds + body).
    pub fn encoded_len(&self) -> usize {
        12 + if self.microsecond.is_some() { 4 } else { 0 } + self.body.len()
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.mrt_type.to_be_bytes());
        out.extend_from_slice(&self.subtype.to_be_bytes());
        out.extend_from_slice(&self.wire_length().to_be_bytes());
        if let Some(us) = self.microsecond {
            out.extend_from_slice(&us.to_be_bytes());
        }
        out.extend_from_slice(&self.body);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out);
        out
    }
}

/// Byte-writing helpers shared by the record builders.
#[derive(Debug, Default, Clone)]
pub struct Buf(pub Vec<u8>);

impl Buf {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}
