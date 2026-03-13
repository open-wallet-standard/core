//! EIP-712 typed structured data hashing.
//!
//! Implements the full EIP-712 hashing algorithm for producing a 32-byte digest
//! that can be signed with secp256k1. No external chain SDKs — only `sha3` and
//! `serde_json`.

use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::collections::{BTreeSet, HashMap};

use crate::traits::SignerError;

/// Parsed EIP-712 typed data structure.
#[derive(Debug)]
pub struct TypedData {
    pub types: HashMap<String, Vec<Field>>,
    pub primary_type: String,
    pub domain: Value,
    pub message: Value,
}

/// A single field in a struct type definition.
#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub type_name: String,
}

/// Parse JSON string into TypedData.
pub fn parse_typed_data(json: &str) -> Result<TypedData, SignerError> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| SignerError::InvalidMessage(e.to_string()))?;

    let types_val = v
        .get("types")
        .ok_or_else(|| SignerError::InvalidMessage("missing 'types' field".into()))?;
    let primary_type = v
        .get("primaryType")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SignerError::InvalidMessage("missing 'primaryType' field".into()))?
        .to_string();
    let domain = v
        .get("domain")
        .ok_or_else(|| SignerError::InvalidMessage("missing 'domain' field".into()))?
        .clone();
    let message = v
        .get("message")
        .ok_or_else(|| SignerError::InvalidMessage("missing 'message' field".into()))?
        .clone();

    let types_obj = types_val
        .as_object()
        .ok_or_else(|| SignerError::InvalidMessage("'types' must be an object".into()))?;

    let mut types = HashMap::new();
    for (type_name, fields_val) in types_obj {
        let fields_arr = fields_val.as_array().ok_or_else(|| {
            SignerError::InvalidMessage(format!("type '{type_name}' must be an array"))
        })?;
        let mut fields = Vec::new();
        for f in fields_arr {
            let name = f
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SignerError::InvalidMessage("field missing 'name'".into()))?
                .to_string();
            let tn = f
                .get("type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SignerError::InvalidMessage("field missing 'type'".into()))?
                .to_string();
            fields.push(Field {
                name,
                type_name: tn,
            });
        }
        types.insert(type_name.clone(), fields);
    }

    Ok(TypedData {
        types,
        primary_type,
        domain,
        message,
    })
}

/// Compute the full EIP-712 hash: `keccak256("\x19\x01" || domainSeparator || structHash)`.
pub fn hash_typed_data(data: &TypedData) -> Result<[u8; 32], SignerError> {
    let domain_hash = hash_struct("EIP712Domain", &data.domain, &data.types)?;
    let message_hash = hash_struct(&data.primary_type, &data.message, &data.types)?;

    let mut buf = Vec::with_capacity(2 + 32 + 32);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(&domain_hash);
    buf.extend_from_slice(&message_hash);

    Ok(Keccak256::digest(&buf).into())
}

/// `hashStruct(typeName, data) = keccak256(typeHash || encodeData)`
fn hash_struct(
    type_name: &str,
    data: &Value,
    types: &HashMap<String, Vec<Field>>,
) -> Result<[u8; 32], SignerError> {
    let type_hash = type_hash(type_name, types)?;
    let encoded = encode_data(type_name, data, types)?;

    let mut buf = Vec::with_capacity(32 + encoded.len());
    buf.extend_from_slice(&type_hash);
    buf.extend_from_slice(&encoded);

    Ok(Keccak256::digest(&buf).into())
}

/// `typeHash(typeName) = keccak256(encodeType(typeName))`
fn type_hash(
    type_name: &str,
    types: &HashMap<String, Vec<Field>>,
) -> Result<[u8; 32], SignerError> {
    let encoded_type = encode_type(type_name, types)?;
    Ok(Keccak256::digest(encoded_type.as_bytes()).into())
}

/// Build the canonical type encoding string, including referenced types sorted alphabetically.
///
/// Example: `"Mail(Person from,Person to,string contents)Person(string name,address wallet)"`
fn encode_type(
    type_name: &str,
    types: &HashMap<String, Vec<Field>>,
) -> Result<String, SignerError> {
    let fields = types
        .get(type_name)
        .ok_or_else(|| SignerError::InvalidMessage(format!("unknown type: {type_name}")))?;

    // Collect all referenced struct types (transitive)
    let mut referenced = BTreeSet::new();
    collect_deps(type_name, types, &mut referenced);
    referenced.remove(type_name); // primary type comes first, not in sorted set

    let mut result = format_struct(type_name, fields);
    for dep in &referenced {
        if let Some(dep_fields) = types.get(dep.as_str()) {
            result.push_str(&format_struct(dep, dep_fields));
        }
    }

    Ok(result)
}

fn format_struct(name: &str, fields: &[Field]) -> String {
    let params: Vec<String> = fields
        .iter()
        .map(|f| format!("{} {}", f.type_name, f.name))
        .collect();
    format!("{name}({})", params.join(","))
}

fn collect_deps(type_name: &str, types: &HashMap<String, Vec<Field>>, out: &mut BTreeSet<String>) {
    if let Some(fields) = types.get(type_name) {
        for field in fields {
            let base = base_type(&field.type_name);
            if types.contains_key(base) && !out.contains(base) {
                out.insert(base.to_string());
                collect_deps(base, types, out);
            }
        }
    }
}

/// Strip array suffix to get base type name. `"uint256[]"` → `"uint256"`, `"Person"` → `"Person"`.
fn base_type(t: &str) -> &str {
    if let Some(idx) = t.find('[') {
        &t[..idx]
    } else {
        t
    }
}

/// ABI-encode all field values as 32-byte words.
fn encode_data(
    type_name: &str,
    data: &Value,
    types: &HashMap<String, Vec<Field>>,
) -> Result<Vec<u8>, SignerError> {
    let fields = types
        .get(type_name)
        .ok_or_else(|| SignerError::InvalidMessage(format!("unknown type: {type_name}")))?;

    let obj = data
        .as_object()
        .ok_or_else(|| SignerError::InvalidMessage(format!("expected object for {type_name}")))?;

    let mut encoded = Vec::new();

    for field in fields {
        let value = obj.get(&field.name).unwrap_or(&Value::Null);
        let word = encode_value(&field.type_name, value, types)?;
        encoded.extend_from_slice(&word);
    }

    Ok(encoded)
}

/// Encode a single value as one 32-byte word.
fn encode_value(
    type_name: &str,
    value: &Value,
    types: &HashMap<String, Vec<Field>>,
) -> Result<[u8; 32], SignerError> {
    // Array types
    if type_name.ends_with(']') {
        let base = base_type(type_name);
        let arr = value.as_array().ok_or_else(|| {
            SignerError::InvalidMessage(format!("expected array for {type_name}"))
        })?;
        let mut inner = Vec::new();
        for item in arr {
            let word = encode_value(base, item, types)?;
            inner.extend_from_slice(&word);
        }
        return Ok(Keccak256::digest(&inner).into());
    }

    // Struct types (referenced)
    if types.contains_key(type_name) {
        let h = hash_struct(type_name, value, types)?;
        return Ok(h);
    }

    // Atomic types
    encode_atomic(type_name, value)
}

/// Encode an atomic (non-struct, non-array) type to a 32-byte word.
fn encode_atomic(type_name: &str, value: &Value) -> Result<[u8; 32], SignerError> {
    let mut word = [0u8; 32];

    match type_name {
        "address" => {
            let s = value
                .as_str()
                .ok_or_else(|| SignerError::InvalidMessage("address must be a string".into()))?;
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(s)
                .map_err(|e| SignerError::InvalidMessage(format!("bad address hex: {e}")))?;
            if bytes.len() != 20 {
                return Err(SignerError::InvalidMessage(format!(
                    "address must be 20 bytes, got {}",
                    bytes.len()
                )));
            }
            word[12..32].copy_from_slice(&bytes);
            Ok(word)
        }

        "bool" => {
            let b = value.as_bool().ok_or_else(|| {
                SignerError::InvalidMessage("bool field must be a boolean".into())
            })?;
            if b {
                word[31] = 1;
            }
            Ok(word)
        }

        "string" => {
            let s = value
                .as_str()
                .ok_or_else(|| SignerError::InvalidMessage("string must be a string".into()))?;
            Ok(Keccak256::digest(s.as_bytes()).into())
        }

        "bytes" => {
            let s = value
                .as_str()
                .ok_or_else(|| SignerError::InvalidMessage("bytes must be a hex string".into()))?;
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(s)
                .map_err(|e| SignerError::InvalidMessage(format!("bad bytes hex: {e}")))?;
            Ok(Keccak256::digest(&bytes).into())
        }

        t if t.starts_with("bytes") => {
            // bytesN (1..=32)
            let n: usize = t[5..]
                .parse()
                .map_err(|_| SignerError::InvalidMessage(format!("invalid type: {t}")))?;
            if !(1..=32).contains(&n) {
                return Err(SignerError::InvalidMessage(format!(
                    "bytesN: N must be 1..32, got {n}"
                )));
            }
            let s = value
                .as_str()
                .ok_or_else(|| SignerError::InvalidMessage(format!("{t} must be a hex string")))?;
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(s)
                .map_err(|e| SignerError::InvalidMessage(format!("bad {t} hex: {e}")))?;
            if bytes.len() != n {
                return Err(SignerError::InvalidMessage(format!(
                    "{t} must be {n} bytes, got {}",
                    bytes.len()
                )));
            }
            // Left-aligned in 32-byte word
            word[..n].copy_from_slice(&bytes);
            Ok(word)
        }

        t if t.starts_with("uint") => {
            let bits: usize = t[4..]
                .parse()
                .map_err(|_| SignerError::InvalidMessage(format!("invalid type: {t}")))?;
            if bits == 0 || bits > 256 || !bits.is_multiple_of(8) {
                return Err(SignerError::InvalidMessage(format!(
                    "invalid uint width: {bits}"
                )));
            }
            let bytes = parse_uint_value(value)?;
            let len = bytes.len().min(32);
            word[32 - len..].copy_from_slice(&bytes[bytes.len() - len..]);
            Ok(word)
        }

        t if t.starts_with("int") => {
            let bits: usize = t[3..]
                .parse()
                .map_err(|_| SignerError::InvalidMessage(format!("invalid type: {t}")))?;
            if bits == 0 || bits > 256 || !bits.is_multiple_of(8) {
                return Err(SignerError::InvalidMessage(format!(
                    "invalid int width: {bits}"
                )));
            }
            // For signed ints, we parse the same way but interpret as two's complement.
            // JSON typically provides them as decimal strings.
            let bytes = parse_int_value(value, bits)?;
            word.copy_from_slice(&bytes);
            Ok(word)
        }

        _ => Err(SignerError::InvalidMessage(format!(
            "unsupported EIP-712 type: {type_name}"
        ))),
    }
}

/// Parse an unsigned integer value from JSON (number or decimal/hex string) to big-endian bytes.
fn parse_uint_value(value: &Value) -> Result<Vec<u8>, SignerError> {
    if let Some(n) = value.as_u64() {
        return Ok(n.to_be_bytes().to_vec());
    }
    if let Some(s) = value.as_str() {
        if let Some(hex_str) = s.strip_prefix("0x") {
            let bytes = hex::decode(hex_str)
                .map_err(|e| SignerError::InvalidMessage(format!("bad uint hex: {e}")))?;
            return Ok(bytes);
        }
        // Decimal string — u128 covers up to ~3.4e38; for larger uint256 values use hex
        let n: u128 = s.parse().map_err(|_| {
            SignerError::InvalidMessage(format!(
                "uint decimal value '{s}' exceeds u128 range; use hex encoding (0x...) for values > 2^128"
            ))
        })?;
        return Ok(n.to_be_bytes().to_vec());
    }
    Err(SignerError::InvalidMessage(
        "uint value must be a number or string".into(),
    ))
}

/// Parse a signed integer value. Negative values are stored as two's complement in 32 bytes.
fn parse_int_value(value: &Value, _bits: usize) -> Result<[u8; 32], SignerError> {
    let mut word = [0u8; 32];
    if let Some(n) = value.as_i64() {
        let be = n.to_be_bytes();
        let fill = if n < 0 { 0xff } else { 0x00 };
        word[..24].fill(fill);
        word[24..].copy_from_slice(&be);
        return Ok(word);
    }
    if let Some(s) = value.as_str() {
        if let Some(hex_str) = s.strip_prefix("0x") {
            let bytes = hex::decode(hex_str)
                .map_err(|e| SignerError::InvalidMessage(format!("bad int hex: {e}")))?;
            let start = 32 - bytes.len();
            word[start..].copy_from_slice(&bytes);
            return Ok(word);
        }
        // Decimal string
        if let Some(neg) = s.strip_prefix('-') {
            let n: u128 = neg
                .parse()
                .map_err(|e| SignerError::InvalidMessage(format!("bad int decimal: {e}")))?;
            // Two's complement: negate
            let pos_be = n.to_be_bytes();
            // Put positive value in low 16 bytes, then negate entire 32-byte word
            word[16..].copy_from_slice(&pos_be);
            negate_twos_complement(&mut word);
            return Ok(word);
        }
        let n: u128 = s
            .parse()
            .map_err(|e| SignerError::InvalidMessage(format!("bad int decimal: {e}")))?;
        let be = n.to_be_bytes();
        word[16..].copy_from_slice(&be);
        return Ok(word);
    }
    Err(SignerError::InvalidMessage(
        "int value must be a number or string".into(),
    ))
}

/// Negate a 32-byte big-endian integer in-place (two's complement).
fn negate_twos_complement(bytes: &mut [u8; 32]) {
    // Invert all bits
    for b in bytes.iter_mut() {
        *b = !*b;
    }
    // Add 1
    let mut carry = 1u16;
    for b in bytes.iter_mut().rev() {
        let sum = *b as u16 + carry;
        *b = sum as u8;
        carry = sum >> 8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// EIP-712 spec example: Mail(Person from, Person to, string contents)
    const EIP712_EXAMPLE: &str = r#"{
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"}
            ],
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"}
            ]
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
        },
        "message": {
            "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!"
        }
    }"#;

    #[test]
    fn test_encode_type_mail() {
        let td = parse_typed_data(EIP712_EXAMPLE).unwrap();
        let encoded = encode_type("Mail", &td.types).unwrap();
        assert_eq!(
            encoded,
            "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
        );
    }

    #[test]
    fn test_type_hash_mail() {
        let td = parse_typed_data(EIP712_EXAMPLE).unwrap();
        let hash = type_hash("Mail", &td.types).unwrap();
        assert_eq!(
            hex::encode(hash),
            "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2"
        );
    }

    #[test]
    fn test_eip712_full_hash() {
        // Known test vector from the EIP-712 specification
        let td = parse_typed_data(EIP712_EXAMPLE).unwrap();
        let hash = hash_typed_data(&td).unwrap();
        assert_eq!(
            hex::encode(hash),
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        );
    }

    #[test]
    fn test_domain_separator() {
        let td = parse_typed_data(EIP712_EXAMPLE).unwrap();
        let ds = hash_struct("EIP712Domain", &td.domain, &td.types).unwrap();
        assert_eq!(
            hex::encode(ds),
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
        );
    }

    #[test]
    fn test_encode_type_person() {
        let td = parse_typed_data(EIP712_EXAMPLE).unwrap();
        let encoded = encode_type("Person", &td.types).unwrap();
        assert_eq!(encoded, "Person(string name,address wallet)");
    }

    #[test]
    fn test_parse_invalid_json() {
        let result = parse_typed_data("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_types() {
        let result = parse_typed_data(r#"{"primaryType":"X","domain":{},"message":{}}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_bool_true() {
        let mut word = [0u8; 32];
        word[31] = 1;
        assert_eq!(encode_atomic("bool", &Value::Bool(true)).unwrap(), word);
    }

    #[test]
    fn test_encode_bool_false() {
        assert_eq!(
            encode_atomic("bool", &Value::Bool(false)).unwrap(),
            [0u8; 32]
        );
    }

    #[test]
    fn test_encode_address() {
        let val = Value::String("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC".into());
        let result = encode_atomic("address", &val).unwrap();
        // Address should be right-aligned in 32 bytes
        assert_eq!(&result[..12], &[0u8; 12]);
        assert_eq!(
            hex::encode(&result[12..]),
            "cccccccccccccccccccccccccccccccccccccccc"
        );
    }

    #[test]
    fn test_encode_uint256() {
        let val = Value::from(1u64);
        let result = encode_atomic("uint256", &val).unwrap();
        assert_eq!(result[31], 1);
        assert_eq!(&result[..31], &[0u8; 31]);
    }

    #[test]
    fn test_encode_string() {
        let val = Value::String("Hello, Bob!".into());
        let result = encode_atomic("string", &val).unwrap();
        let expected: [u8; 32] = Keccak256::digest(b"Hello, Bob!").into();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_encode_bytes32() {
        let hex_str = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let val = Value::String(hex_str.into());
        let result = encode_atomic("bytes32", &val).unwrap();
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_negate_twos_complement() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        negate_twos_complement(&mut bytes);
        // -1 in two's complement is all 0xff
        assert_eq!(bytes, [0xffu8; 32]);
    }
}
