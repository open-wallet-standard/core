//! Minimal RLP encoding/decoding for EVM signed transaction construction.
//!
//! Only implements the subset needed to append v, r, s to an unsigned
//! EIP-1559/EIP-2930 transaction list.

/// Decode the length of an RLP item (string or list) at the start of `data`.
/// Returns `(payload_offset, payload_length)`.
fn decode_length(data: &[u8]) -> Result<(usize, usize), &'static str> {
    if data.is_empty() {
        return Err("empty input");
    }
    let prefix = data[0];
    match prefix {
        // Single byte
        0x00..=0x7f => Ok((0, 1)),
        // Short string (0-55 bytes)
        0x80..=0xb7 => {
            let len = (prefix - 0x80) as usize;
            Ok((1, len))
        }
        // Long string (>55 bytes)
        0xb8..=0xbf => {
            let len_bytes = (prefix - 0xb7) as usize;
            if data.len() < 1 + len_bytes {
                return Err("truncated length");
            }
            let len = read_be_uint(&data[1..1 + len_bytes]);
            Ok((1 + len_bytes, len))
        }
        // Short list (0-55 bytes total payload)
        0xc0..=0xf7 => {
            let len = (prefix - 0xc0) as usize;
            Ok((1, len))
        }
        // Long list (>55 bytes total payload)
        0xf8..=0xff => {
            let len_bytes = (prefix - 0xf7) as usize;
            if data.len() < 1 + len_bytes {
                return Err("truncated length");
            }
            let len = read_be_uint(&data[1..1 + len_bytes]);
            Ok((1 + len_bytes, len))
        }
    }
}

fn read_be_uint(bytes: &[u8]) -> usize {
    let mut val = 0usize;
    for &b in bytes {
        val = (val << 8) | b as usize;
    }
    val
}

/// RLP-encode a byte string.
pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    let mut out = encode_length(data.len(), 0x80);
    out.extend_from_slice(data);
    out
}

/// RLP-encode a list from already-encoded concatenated items.
pub fn encode_list(items: &[u8]) -> Vec<u8> {
    let mut out = encode_length(items.len(), 0xc0);
    out.extend_from_slice(items);
    out
}

fn encode_length(len: usize, offset: u8) -> Vec<u8> {
    if len < 56 {
        vec![offset + len as u8]
    } else {
        let len_bytes = be_bytes(len);
        let mut out = vec![offset + 55 + len_bytes.len() as u8];
        out.extend_from_slice(&len_bytes);
        out
    }
}

fn be_bytes(val: usize) -> Vec<u8> {
    if val == 0 {
        return vec![0];
    }
    let bytes = val.to_be_bytes();
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
}

/// Strip leading zeros from a 32-byte scalar for minimal RLP encoding.
fn strip_leading_zeros(data: &[u8]) -> &[u8] {
    let start = data.iter().position(|&b| b != 0).unwrap_or(data.len());
    &data[start..]
}

/// Given unsigned typed transaction bytes (e.g. `0x02 || RLP([...fields])`)
/// and a signature, produce the signed transaction bytes:
/// `type_byte || RLP([...fields, v, r, s])`.
///
/// For EIP-1559 (type 0x02) and EIP-2930 (type 0x01), v is the raw
/// recovery ID (0 or 1). r and s are 32-byte big-endian scalars.
pub fn encode_signed_typed_tx(
    unsigned_tx: &[u8],
    v: u8,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    if unsigned_tx.is_empty() {
        return Err("empty transaction");
    }

    let type_byte = unsigned_tx[0];
    if type_byte != 0x01 && type_byte != 0x02 {
        return Err("unsupported transaction type (expected 0x01 or 0x02)");
    }

    let rlp_data = &unsigned_tx[1..];
    let (payload_offset, payload_length) = decode_length(rlp_data)?;

    if rlp_data.len() < payload_offset + payload_length {
        return Err("truncated RLP payload");
    }

    // Extract the inner list items (raw concatenated RLP items)
    let items = &rlp_data[payload_offset..payload_offset + payload_length];

    // Append v, r, s as RLP-encoded items
    let v_encoded = encode_bytes(strip_leading_zeros(&[v]));
    let r_encoded = encode_bytes(strip_leading_zeros(r));
    let s_encoded = encode_bytes(strip_leading_zeros(s));

    let mut new_items = items.to_vec();
    new_items.extend_from_slice(&v_encoded);
    new_items.extend_from_slice(&r_encoded);
    new_items.extend_from_slice(&s_encoded);

    // Re-encode as list and prepend type byte
    let mut result = vec![type_byte];
    result.extend_from_slice(&encode_list(&new_items));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_bytes_single() {
        assert_eq!(encode_bytes(&[0x42]), vec![0x42]);
    }

    #[test]
    fn test_encode_bytes_short() {
        let data = vec![0x01, 0x02, 0x03];
        let encoded = encode_bytes(&data);
        assert_eq!(encoded[0], 0x83); // 0x80 + 3
        assert_eq!(&encoded[1..], &data[..]);
    }

    #[test]
    fn test_encode_bytes_empty() {
        assert_eq!(encode_bytes(&[]), vec![0x80]);
    }

    #[test]
    fn test_encode_list_empty() {
        assert_eq!(encode_list(&[]), vec![0xc0]);
    }

    #[test]
    fn test_roundtrip_signed_tx() {
        // Construct a minimal unsigned EIP-1559 tx:
        // 0x02 || RLP([chain_id=1, nonce=0, maxPriorityFee=0, maxFee=0, gas=0, to="", value=0, data="", accessList=[]])
        let items: Vec<u8> = [
            encode_bytes(&[1]), // chain_id = 1
            encode_bytes(&[]),  // nonce = 0
            encode_bytes(&[]),  // maxPriorityFeePerGas = 0
            encode_bytes(&[]),  // maxFeePerGas = 0
            encode_bytes(&[]),  // gasLimit = 0
            encode_bytes(&[]),  // to = empty (contract creation)
            encode_bytes(&[]),  // value = 0
            encode_bytes(&[]),  // data = empty
            encode_list(&[]),   // accessList = empty
        ]
        .concat();

        let mut unsigned_tx = vec![0x02];
        unsigned_tx.extend_from_slice(&encode_list(&items));

        let r = [0u8; 32];
        let s = [0u8; 32];
        let v = 1u8;

        let signed = encode_signed_typed_tx(&unsigned_tx, v, &r, &s).unwrap();

        // Signed tx should start with type byte
        assert_eq!(signed[0], 0x02);

        // Decode the signed list
        let (offset, length) = decode_length(&signed[1..]).unwrap();
        let signed_items = &signed[1 + offset..1 + offset + length];

        // It should be longer than the unsigned items (v + r + s appended)
        assert!(signed_items.len() > items.len());
    }

    #[test]
    fn test_strip_leading_zeros() {
        assert_eq!(strip_leading_zeros(&[0, 0, 1, 2]), &[1, 2]);
        assert_eq!(strip_leading_zeros(&[0, 0, 0, 0]), &[] as &[u8]);
        assert_eq!(strip_leading_zeros(&[1, 2, 3]), &[1, 2, 3]);
    }

    #[test]
    fn test_rejects_legacy_tx() {
        // Legacy tx starts with RLP list prefix (0xc0+), not a type byte
        let legacy = vec![0xc0];
        let r = [0u8; 32];
        let s = [0u8; 32];
        assert!(encode_signed_typed_tx(&legacy, 0, &r, &s).is_err());
    }

    #[test]
    fn test_v_zero_encoded_as_rlp_integer_zero() {
        // BUG TEST: In RLP, integer 0 is encoded as the empty byte string → [0x80].
        // encode_bytes(&[0]) returns [0x00] (the byte value 0), which is the RLP
        // encoding of a single-byte string containing 0x00 — NOT integer zero.
        // For EIP-1559/EIP-2930 transactions, yParity=0 must be encoded as integer 0.
        //
        // The correct encoding uses strip_leading_zeros:
        //   strip_leading_zeros(&[0]) → &[]
        //   encode_bytes(&[])         → [0x80]

        // First, verify the underlying primitives:
        assert_eq!(
            strip_leading_zeros(&[0]),
            &[] as &[u8],
            "strip_leading_zeros(&[0]) should yield empty slice"
        );
        assert_eq!(
            encode_bytes(&[]),
            vec![0x80],
            "encode_bytes of empty slice should be [0x80] (RLP integer 0)"
        );
        assert_eq!(
            encode_bytes(&[0]),
            vec![0x00],
            "encode_bytes(&[0]) is [0x00] — correct for a byte string, wrong for integer 0"
        );

        // Now verify the signed transaction encoding with v=0:
        let items: Vec<u8> = [
            encode_bytes(&[1]), // chain_id = 1
            encode_bytes(&[]),  // nonce = 0
            encode_bytes(&[]),  // maxPriorityFeePerGas = 0
            encode_bytes(&[]),  // maxFeePerGas = 0
            encode_bytes(&[]),  // gasLimit = 0
            encode_bytes(&[]),  // to = empty
            encode_bytes(&[]),  // value = 0
            encode_bytes(&[]),  // data = empty
            encode_list(&[]),   // accessList = empty
        ]
        .concat();

        let mut unsigned_tx = vec![0x02];
        unsigned_tx.extend_from_slice(&encode_list(&items));

        let r = [0u8; 32];
        let s = [0u8; 32];
        let v = 0u8; // recovery id 0

        let signed = encode_signed_typed_tx(&unsigned_tx, v, &r, &s).unwrap();

        // Decode the signed list to inspect the appended v field
        let (offset, length) = decode_length(&signed[1..]).unwrap();
        let signed_payload = &signed[1 + offset..1 + offset + length];

        // The original unsigned items occupy `items.len()` bytes.
        // After them come v, r, s as RLP-encoded items.
        let v_and_rs = &signed_payload[items.len()..];

        // The first byte of the appended data is the RLP-encoded v.
        // For v=0 (integer zero), it MUST be 0x80 (empty byte string).
        assert_eq!(
            v_and_rs[0], 0x80,
            "v=0 must be RLP-encoded as 0x80 (integer zero), not 0x00 (byte value zero)"
        );
    }

    #[test]
    fn test_v_one_encoded_correctly() {
        // v=1 should be encoded as [0x01] — a single byte < 0x80 is its own RLP encoding.
        let items: Vec<u8> = [
            encode_bytes(&[1]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_list(&[]),
        ]
        .concat();

        let mut unsigned_tx = vec![0x02];
        unsigned_tx.extend_from_slice(&encode_list(&items));

        let r = [0u8; 32];
        let s = [0u8; 32];
        let v = 1u8;

        let signed = encode_signed_typed_tx(&unsigned_tx, v, &r, &s).unwrap();

        let (offset, length) = decode_length(&signed[1..]).unwrap();
        let signed_payload = &signed[1 + offset..1 + offset + length];
        let v_and_rs = &signed_payload[items.len()..];

        assert_eq!(v_and_rs[0], 0x01, "v=1 must be RLP-encoded as 0x01");
    }
}
