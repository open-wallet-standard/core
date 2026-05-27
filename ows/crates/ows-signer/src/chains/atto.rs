use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use blake2::digest::{consts::U32, consts::U5, consts::U64, Digest};
use blake2::Blake2b;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ows_core::ChainType;
use serde_json::{json, Value};

const ATTO_COIN_TYPE: u32 = 1_869_902_945;
const ATTO_ADDRESS_ALGORITHM_V1: u8 = 0;
const ATTO_SIGNED_MESSAGE_DOMAIN: &[u8] = b"ATTO Signed Message v1";
const RFC4648_BASE32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encode bytes using RFC 4648 base32 without padding, lowercased.
fn encode_base32_lower_no_pad(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u16;
        bits += 8;
        while bits >= 5 {
            let shift = bits - 5;
            let index = ((buffer >> shift) & 0x1f) as usize;
            out.push(RFC4648_BASE32_LOWER[index] as char);
            bits -= 5;
            buffer &= (1 << bits) - 1;
        }
    }

    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(RFC4648_BASE32_LOWER[index] as char);
    }

    out
}

fn decode_base32_lower_no_pad(body: &str) -> Result<Vec<u8>, SignerError> {
    let mut out = Vec::with_capacity(body.len() * 5 / 8);
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;

    for (idx, byte) in body.bytes().enumerate() {
        let value = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            b'A'..=b'Z' => {
                return Err(SignerError::AddressDerivationFailed(format!(
                    "invalid Atto address alphabet: uppercase character at body index {idx}"
                )))
            }
            _ => {
                return Err(SignerError::AddressDerivationFailed(format!(
                    "invalid Atto address alphabet: character {:?} at body index {idx}",
                    byte as char
                )))
            }
        };

        buffer = (buffer << 5) | value as u16;
        bits += 5;
        while bits >= 8 {
            let shift = bits - 8;
            out.push(((buffer >> shift) & 0xff) as u8);
            bits -= 8;
            buffer &= (1 << bits) - 1;
        }
    }

    if bits > 0 && buffer != 0 {
        return Err(SignerError::AddressDerivationFailed(
            "invalid Atto address padding bits".into(),
        ));
    }

    Ok(out)
}

fn atto_checksum(payload: &[u8; 33]) -> [u8; 5] {
    let mut hasher = Blake2b::<U5>::new();
    hasher.update(payload);
    hasher.finalize().into()
}

pub fn atto_address(pubkey: &[u8; 32]) -> String {
    let mut bytes = [0u8; 38];
    bytes[0] = ATTO_ADDRESS_ALGORITHM_V1;
    bytes[1..33].copy_from_slice(pubkey);

    let payload: [u8; 33] = bytes[..33].try_into().expect("payload length is fixed");
    bytes[33..].copy_from_slice(&atto_checksum(&payload));

    format!("atto://{}", encode_base32_lower_no_pad(&bytes))
}

fn decode_atto_address_bytes(address: &str) -> Result<[u8; 38], SignerError> {
    let body = address.strip_prefix("atto://").ok_or_else(|| {
        SignerError::AddressDerivationFailed("invalid Atto address prefix: expected atto://".into())
    })?;

    if body.len() != 61 {
        return Err(SignerError::AddressDerivationFailed(format!(
            "invalid Atto address length: expected 61 base32 characters, got {}",
            body.len()
        )));
    }

    let decoded = decode_base32_lower_no_pad(body)?;
    let bytes: [u8; 38] = decoded.try_into().map_err(|decoded: Vec<u8>| {
        SignerError::AddressDerivationFailed(format!(
            "invalid Atto address payload length: expected 38 bytes, got {}",
            decoded.len()
        ))
    })?;

    Ok(bytes)
}

pub fn atto_pubkey_from_address(address: &str) -> Result<[u8; 32], SignerError> {
    let bytes = decode_atto_address_bytes(address)?;

    if bytes[0] != ATTO_ADDRESS_ALGORITHM_V1 {
        return Err(SignerError::AddressDerivationFailed(format!(
            "unsupported Atto address algorithm byte: expected {ATTO_ADDRESS_ALGORITHM_V1}, got {}",
            bytes[0]
        )));
    }

    let payload: [u8; 33] = bytes[..33].try_into().expect("payload length is fixed");
    let expected_checksum = atto_checksum(&payload);
    if bytes[33..] != expected_checksum {
        return Err(SignerError::AddressDerivationFailed(
            "invalid Atto address checksum".into(),
        ));
    }

    let public_key: [u8; 32] = bytes[1..33].try_into().expect("public key length is fixed");
    Ok(public_key)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttoNetwork {
    Live,
    Beta,
    Dev,
    Local,
}

impl AttoNetwork {
    fn code(self) -> u8 {
        match self {
            Self::Live => 0,
            Self::Beta => 1,
            Self::Dev => 2,
            Self::Local => 3,
        }
    }

    fn api_name(self) -> &'static str {
        match self {
            Self::Live => "LIVE",
            Self::Beta => "BETA",
            Self::Dev => "DEV",
            Self::Local => "LOCAL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttoSendBlock {
    pub network: AttoNetwork,
    pub version: u16,
    pub public_key: [u8; 32],
    pub height: u64,
    pub balance: u64,
    pub timestamp_ms: i64,
    pub previous: [u8; 32],
    pub receiver_public_key: [u8; 32],
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttoReceiveBlock {
    pub network: AttoNetwork,
    pub version: u16,
    pub public_key: [u8; 32],
    pub height: u64,
    pub balance: u64,
    pub timestamp_ms: i64,
    pub previous: [u8; 32],
    pub send_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttoOpenBlock {
    pub network: AttoNetwork,
    pub version: u16,
    pub public_key: [u8; 32],
    pub balance: u64,
    pub timestamp_ms: i64,
    pub send_hash: [u8; 32],
    pub representative_public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttoChangeBlock {
    pub network: AttoNetwork,
    pub version: u16,
    pub public_key: [u8; 32],
    pub height: u64,
    pub balance: u64,
    pub timestamp_ms: i64,
    pub previous: [u8; 32],
    pub representative_public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttoBlock {
    Open(AttoOpenBlock),
    Receive(AttoReceiveBlock),
    Send(AttoSendBlock),
    Change(AttoChangeBlock),
}

impl AttoBlock {
    pub const OPEN_SIZE: usize = 119;
    pub const RECEIVE_SIZE: usize = 126;
    pub const SEND_SIZE: usize = 134;
    pub const CHANGE_SIZE: usize = 126;
    const ALGORITHM_V1: u8 = 0;

    pub fn to_buffer(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.block_size());
        match self {
            Self::Open(block) => {
                Self::write_common(&mut out, 0, block.network, block.version, &block.public_key);
                Self::write_u64_le(&mut out, block.balance);
                Self::write_i64_le(&mut out, block.timestamp_ms);
                out.push(Self::ALGORITHM_V1);
                out.extend_from_slice(&block.send_hash);
                out.push(Self::ALGORITHM_V1);
                out.extend_from_slice(&block.representative_public_key);
            }
            Self::Receive(block) => {
                Self::write_common(&mut out, 1, block.network, block.version, &block.public_key);
                Self::write_u64_le(&mut out, block.height);
                Self::write_u64_le(&mut out, block.balance);
                Self::write_i64_le(&mut out, block.timestamp_ms);
                out.extend_from_slice(&block.previous);
                out.push(Self::ALGORITHM_V1);
                out.extend_from_slice(&block.send_hash);
            }
            Self::Send(block) => {
                Self::write_common(&mut out, 2, block.network, block.version, &block.public_key);
                Self::write_u64_le(&mut out, block.height);
                Self::write_u64_le(&mut out, block.balance);
                Self::write_i64_le(&mut out, block.timestamp_ms);
                out.extend_from_slice(&block.previous);
                out.push(Self::ALGORITHM_V1);
                out.extend_from_slice(&block.receiver_public_key);
                Self::write_u64_le(&mut out, block.amount);
            }
            Self::Change(block) => {
                Self::write_common(&mut out, 3, block.network, block.version, &block.public_key);
                Self::write_u64_le(&mut out, block.height);
                Self::write_u64_le(&mut out, block.balance);
                Self::write_i64_le(&mut out, block.timestamp_ms);
                out.extend_from_slice(&block.previous);
                out.push(Self::ALGORITHM_V1);
                out.extend_from_slice(&block.representative_public_key);
            }
        }
        debug_assert_eq!(out.len(), self.block_size());
        out
    }

    pub fn hash(&self) -> [u8; 32] {
        atto_block_hash(&self.to_buffer())
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::Open(_) => Self::OPEN_SIZE,
            Self::Receive(_) => Self::RECEIVE_SIZE,
            Self::Send(_) => Self::SEND_SIZE,
            Self::Change(_) => Self::CHANGE_SIZE,
        }
    }

    pub fn to_api_json_value(&self) -> Value {
        match self {
            Self::Open(block) => json!({
                "type": "OPEN",
                "network": block.network.api_name(),
                "version": block.version,
                "algorithm": "V1",
                "publicKey": hex::encode_upper(block.public_key),
                "balance": block.balance,
                "timestamp": block.timestamp_ms,
                "sendHashAlgorithm": "V1",
                "sendHash": hex::encode_upper(block.send_hash),
                "representativeAlgorithm": "V1",
                "representativePublicKey": hex::encode_upper(block.representative_public_key),
                "height": 1,
                "address": atto_address(&block.public_key),
                "representativeAddress": atto_address(&block.representative_public_key),
            }),
            Self::Receive(block) => json!({
                "type": "RECEIVE",
                "network": block.network.api_name(),
                "version": block.version,
                "algorithm": "V1",
                "publicKey": hex::encode_upper(block.public_key),
                "height": block.height,
                "balance": block.balance,
                "timestamp": block.timestamp_ms,
                "previous": hex::encode_upper(block.previous),
                "sendHashAlgorithm": "V1",
                "sendHash": hex::encode_upper(block.send_hash),
                "address": atto_address(&block.public_key),
            }),
            Self::Send(block) => json!({
                "type": "SEND",
                "network": block.network.api_name(),
                "version": block.version,
                "algorithm": "V1",
                "publicKey": hex::encode_upper(block.public_key),
                "height": block.height,
                "balance": block.balance,
                "timestamp": block.timestamp_ms,
                "previous": hex::encode_upper(block.previous),
                "receiverAlgorithm": "V1",
                "receiverPublicKey": hex::encode_upper(block.receiver_public_key),
                "amount": block.amount,
                "address": atto_address(&block.public_key),
                "receiverAddress": atto_address(&block.receiver_public_key),
            }),
            Self::Change(block) => json!({
                "type": "CHANGE",
                "network": block.network.api_name(),
                "version": block.version,
                "algorithm": "V1",
                "publicKey": hex::encode_upper(block.public_key),
                "height": block.height,
                "balance": block.balance,
                "timestamp": block.timestamp_ms,
                "previous": hex::encode_upper(block.previous),
                "representativeAlgorithm": "V1",
                "representativePublicKey": hex::encode_upper(block.representative_public_key),
                "address": atto_address(&block.public_key),
                "representativeAddress": atto_address(&block.representative_public_key),
            }),
        }
    }

    fn write_common(
        out: &mut Vec<u8>,
        block_type: u8,
        network: AttoNetwork,
        version: u16,
        public_key: &[u8; 32],
    ) {
        out.push(block_type);
        out.push(network.code());
        out.extend_from_slice(&version.to_le_bytes());
        out.push(Self::ALGORITHM_V1);
        out.extend_from_slice(public_key);
    }

    fn write_u64_le(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn write_i64_le(out: &mut Vec<u8>, value: i64) {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttoSignedTransaction {
    pub block: AttoBlock,
    pub signature: [u8; 64],
    pub work: [u8; 8],
}

impl AttoSignedTransaction {
    pub fn new(block: AttoBlock, signature: [u8; 64], work: [u8; 8]) -> Self {
        Self {
            block,
            signature,
            work,
        }
    }

    pub fn to_buffer(&self) -> Vec<u8> {
        let mut out = self.block.to_buffer();
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.work);
        out
    }

    pub fn to_api_json_value(&self) -> Value {
        let mut value = self.block.to_api_json_value();
        if let Value::Object(ref mut object) = value {
            object.insert(
                "signature".to_string(),
                Value::String(hex::encode_upper(self.signature)),
            );
            object.insert(
                "work".to_string(),
                Value::String(hex::encode_upper(self.work)),
            );
        }
        value
    }
}

pub fn atto_block_hash(block_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(block_bytes);
    hasher.finalize().into()
}

fn atto_block_size_from_prefix(tx_bytes: &[u8]) -> Result<usize, SignerError> {
    let block_type = tx_bytes.first().copied().ok_or_else(|| {
        SignerError::InvalidTransaction("empty Atto transaction/block payload".into())
    })?;
    match block_type {
        0 => Ok(AttoBlock::OPEN_SIZE),
        1 => Ok(AttoBlock::RECEIVE_SIZE),
        2 => Ok(AttoBlock::SEND_SIZE),
        3 => Ok(AttoBlock::CHANGE_SIZE),
        other => Err(SignerError::InvalidTransaction(format!(
            "unsupported Atto block type byte {other}; expected canonical block bytes or 32-byte canonical block hash"
        ))),
    }
}

fn atto_unsigned_parts(tx_bytes: &[u8]) -> Result<(&[u8], &[u8]), SignerError> {
    let block_size = atto_block_size_from_prefix(tx_bytes)?;
    if tx_bytes.len() == block_size {
        Ok((&tx_bytes[..block_size], &[]))
    } else if tx_bytes.len() == block_size + 8 {
        Ok((&tx_bytes[..block_size], &tx_bytes[block_size..]))
    } else if tx_bytes.len() == block_size + 64 + 8 {
        Err(SignerError::InvalidTransaction(
            "Atto payload is already signed; pass canonical block bytes plus optional 8-byte work"
                .into(),
        ))
    } else {
        Err(SignerError::InvalidTransaction(format!(
            "invalid Atto payload length: block type expects {block_size} block bytes, got {} bytes",
            tx_bytes.len()
        )))
    }
}

fn atto_network_from_code(code: u8) -> Result<AttoNetwork, SignerError> {
    match code {
        0 => Ok(AttoNetwork::Live),
        1 => Ok(AttoNetwork::Beta),
        2 => Ok(AttoNetwork::Dev),
        3 => Ok(AttoNetwork::Local),
        other => Err(SignerError::InvalidTransaction(format!(
            "unsupported Atto network byte {other}"
        ))),
    }
}

fn read_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], SignerError> {
    let end = *offset + N;
    let slice = bytes.get(*offset..end).ok_or_else(|| {
        SignerError::InvalidTransaction(format!(
            "truncated Atto payload while reading {N} bytes at offset {}",
            *offset
        ))
    })?;
    *offset = end;
    slice.try_into().map_err(|_| {
        SignerError::InvalidTransaction(format!("invalid Atto payload field length {N}"))
    })
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> Result<u8, SignerError> {
    Ok(read_array::<1>(bytes, offset)?[0])
}

fn read_u16_le(bytes: &[u8], offset: &mut usize) -> Result<u16, SignerError> {
    Ok(u16::from_le_bytes(read_array::<2>(bytes, offset)?))
}

fn read_u64_le(bytes: &[u8], offset: &mut usize) -> Result<u64, SignerError> {
    Ok(u64::from_le_bytes(read_array::<8>(bytes, offset)?))
}

fn read_i64_le(bytes: &[u8], offset: &mut usize) -> Result<i64, SignerError> {
    Ok(i64::from_le_bytes(read_array::<8>(bytes, offset)?))
}

fn read_algorithm_v1(bytes: &[u8], offset: &mut usize, label: &str) -> Result<(), SignerError> {
    let algorithm = read_u8(bytes, offset)?;
    if algorithm != AttoBlock::ALGORITHM_V1 {
        return Err(SignerError::InvalidTransaction(format!(
            "unsupported Atto {label} algorithm byte {algorithm}"
        )));
    }
    Ok(())
}

fn atto_block_from_bytes(block_bytes: &[u8]) -> Result<AttoBlock, SignerError> {
    let expected = atto_block_size_from_prefix(block_bytes)?;
    if block_bytes.len() != expected {
        return Err(SignerError::InvalidTransaction(format!(
            "invalid Atto block length: expected {expected} bytes, got {}",
            block_bytes.len()
        )));
    }

    let mut offset = 0;
    let block_type = read_u8(block_bytes, &mut offset)?;
    let network = atto_network_from_code(read_u8(block_bytes, &mut offset)?)?;
    let version = read_u16_le(block_bytes, &mut offset)?;
    read_algorithm_v1(block_bytes, &mut offset, "block")?;
    let public_key = read_array::<32>(block_bytes, &mut offset)?;

    match block_type {
        0 => {
            let balance = read_u64_le(block_bytes, &mut offset)?;
            let timestamp_ms = read_i64_le(block_bytes, &mut offset)?;
            read_algorithm_v1(block_bytes, &mut offset, "send hash")?;
            let send_hash = read_array::<32>(block_bytes, &mut offset)?;
            read_algorithm_v1(block_bytes, &mut offset, "representative")?;
            let representative_public_key = read_array::<32>(block_bytes, &mut offset)?;
            Ok(AttoBlock::Open(AttoOpenBlock {
                network,
                version,
                public_key,
                balance,
                timestamp_ms,
                send_hash,
                representative_public_key,
            }))
        }
        1 => {
            let height = read_u64_le(block_bytes, &mut offset)?;
            let balance = read_u64_le(block_bytes, &mut offset)?;
            let timestamp_ms = read_i64_le(block_bytes, &mut offset)?;
            let previous = read_array::<32>(block_bytes, &mut offset)?;
            read_algorithm_v1(block_bytes, &mut offset, "send hash")?;
            let send_hash = read_array::<32>(block_bytes, &mut offset)?;
            Ok(AttoBlock::Receive(AttoReceiveBlock {
                network,
                version,
                public_key,
                height,
                balance,
                timestamp_ms,
                previous,
                send_hash,
            }))
        }
        2 => {
            let height = read_u64_le(block_bytes, &mut offset)?;
            let balance = read_u64_le(block_bytes, &mut offset)?;
            let timestamp_ms = read_i64_le(block_bytes, &mut offset)?;
            let previous = read_array::<32>(block_bytes, &mut offset)?;
            read_algorithm_v1(block_bytes, &mut offset, "receiver")?;
            let receiver_public_key = read_array::<32>(block_bytes, &mut offset)?;
            let amount = read_u64_le(block_bytes, &mut offset)?;
            Ok(AttoBlock::Send(AttoSendBlock {
                network,
                version,
                public_key,
                height,
                balance,
                timestamp_ms,
                previous,
                receiver_public_key,
                amount,
            }))
        }
        3 => {
            let height = read_u64_le(block_bytes, &mut offset)?;
            let balance = read_u64_le(block_bytes, &mut offset)?;
            let timestamp_ms = read_i64_le(block_bytes, &mut offset)?;
            let previous = read_array::<32>(block_bytes, &mut offset)?;
            read_algorithm_v1(block_bytes, &mut offset, "representative")?;
            let representative_public_key = read_array::<32>(block_bytes, &mut offset)?;
            Ok(AttoBlock::Change(AttoChangeBlock {
                network,
                version,
                public_key,
                height,
                balance,
                timestamp_ms,
                previous,
                representative_public_key,
            }))
        }
        other => Err(SignerError::InvalidTransaction(format!(
            "unsupported Atto block type byte {other}"
        ))),
    }
}

pub fn atto_signed_transaction_to_api_json_value(
    signed_bytes: &[u8],
) -> Result<Value, SignerError> {
    let block_size = atto_block_size_from_prefix(signed_bytes)?;
    let expected = block_size + 64 + 8;
    if signed_bytes.len() != expected {
        return Err(SignerError::InvalidTransaction(format!(
            "Atto signed transaction must be {expected} bytes ({block_size} block + 64 signature + 8 work), got {}",
            signed_bytes.len()
        )));
    }
    let block = atto_block_from_bytes(&signed_bytes[..block_size])?;
    let signature = signed_bytes[block_size..block_size + 64]
        .try_into()
        .expect("signature slice length is fixed");
    let work = signed_bytes[block_size + 64..expected]
        .try_into()
        .expect("work slice length is fixed");
    Ok(AttoSignedTransaction::new(block, signature, work).to_api_json_value())
}

pub fn atto_signed_transaction_hash_hex(signed_bytes: &[u8]) -> Result<String, SignerError> {
    let block_size = atto_block_size_from_prefix(signed_bytes)?;
    if signed_bytes.len() < block_size {
        return Err(SignerError::InvalidTransaction(format!(
            "invalid Atto signed transaction length: expected at least {block_size} block bytes, got {}",
            signed_bytes.len()
        )));
    }
    Ok(hex::encode_upper(atto_block_hash(
        &signed_bytes[..block_size],
    )))
}

/// Atto chain signer metadata and local Ed25519 primitives.
///
/// Canonical block bytes follow Atto Commons `AttoBlock.toBuffer()`. The block
/// hash is BLAKE2b-256 over those bytes, and Ed25519 signs that 32-byte hash.
/// Full transaction bytes are `block || signature64 || work8`; work is encoded
/// for broadcast but deliberately excluded from the signature.
pub struct AttoSigner;

impl AttoSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let key_bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        Ok(SigningKey::from_bytes(&key_bytes))
    }

    fn signed_message_digest(public_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
        let mut hasher = Blake2b::<U64>::new();
        hasher.update(ATTO_SIGNED_MESSAGE_DOMAIN);
        hasher.update(public_key);
        hasher.update((message.len() as u64).to_le_bytes());
        hasher.update(message);
        hasher.finalize().into()
    }
}

impl ChainSigner for AttoSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Atto
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn coin_type(&self) -> u32 {
        ATTO_COIN_TYPE
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        Ok(atto_address(verifying_key.as_bytes()))
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let signature = signing_key.sign(message);
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(verifying_key.to_bytes().to_vec()),
        })
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        if tx_bytes.len() == 32 {
            return self.sign(private_key, tx_bytes);
        }
        let (block_bytes, _) = atto_unsigned_parts(tx_bytes)?;
        let hash = atto_block_hash(block_bytes);
        self.sign(private_key, &hash)
    }

    fn extract_signable_bytes<'a>(&self, tx_bytes: &'a [u8]) -> Result<&'a [u8], SignerError> {
        let (block_bytes, _) = atto_unsigned_parts(tx_bytes)?;
        Ok(block_bytes)
    }

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        if signature.signature.len() != 64 {
            return Err(SignerError::InvalidTransaction(format!(
                "Atto signatures must be 64 bytes, got {} bytes",
                signature.signature.len()
            )));
        }

        let (block_bytes, work) = atto_unsigned_parts(tx_bytes)?;
        let mut signed = Vec::with_capacity(block_bytes.len() + 64 + 8);
        signed.extend_from_slice(block_bytes);
        signed.extend_from_slice(&signature.signature);
        if work.is_empty() {
            signed.extend_from_slice(&[0u8; 8]);
        } else {
            signed.extend_from_slice(work);
        }
        Ok(signed)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let public_key = signing_key.verifying_key().to_bytes();
        let digest = Self::signed_message_digest(&public_key, message);
        let signature = signing_key.sign(&digest);
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(public_key.to_vec()),
        })
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/{ATTO_COIN_TYPE}'/{index}'")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::signer_for_chain;
    use crate::hd::HdDeriver;
    use crate::mnemonic::Mnemonic;
    use ed25519_dalek::Verifier;

    const ABANDON_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn derive_key(index: u32) -> Vec<u8> {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let signer = AttoSigner;
        let key = HdDeriver::derive_from_mnemonic(
            &mnemonic,
            "",
            &signer.default_derivation_path(index),
            Curve::Ed25519,
        )
        .unwrap();
        key.expose().to_vec()
    }

    #[test]
    fn chain_properties() {
        let signer = AttoSigner;
        assert_eq!(signer.chain_type(), ChainType::Atto);
        assert_eq!(signer.curve(), Curve::Ed25519);
        assert_eq!(signer.coin_type(), ATTO_COIN_TYPE);
        assert_eq!(signer.default_derivation_path(0), "m/44'/1869902945'/0'");
    }

    #[test]
    fn address_has_atto_uri_shape() {
        let key = derive_key(0);
        let signer = AttoSigner;
        let address = signer.derive_address(&key).unwrap();
        assert!(address.starts_with("atto://"));
        assert_eq!(address.len(), "atto://".len() + 61);
        assert!(address["atto://".len()..]
            .chars()
            .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)));
    }

    #[test]
    fn address_decodes_to_original_pubkey() {
        // Fixture generated from OWS' Atto codec contract: algorithm byte 0,
        // RFC 4648 lowercase base32 without padding, BLAKE2b-5 checksum.
        let pubkey = [0x42u8; 32];
        let address = atto_address(&pubkey);
        assert_eq!(
            address,
            "atto://abbeeqscijbeeqscijbeeqscijbeeqscijbeeqscijbeeqscijbefcvpqter6"
        );
        assert_eq!(atto_pubkey_from_address(&address).unwrap(), pubkey);
    }

    #[test]
    fn address_decoder_accepts_contract_example() {
        // Public Atto address example without source private key, so this only
        // verifies address decoding.
        let address = "atto://aaferyy3quqiyugpambc452bu2oqh7hrcazz4vnvem2meaa6thwf4vkiuiwyw";
        let pubkey = atto_pubkey_from_address(address).unwrap();
        assert_eq!(pubkey.len(), 32);
    }

    #[test]
    fn address_decoder_rejects_invalid_prefix_case_length_alphabet_algorithm_and_checksum() {
        let valid = atto_address(&[0x42u8; 32]);

        let uppercase_body = format!("atto://{}", valid["atto://".len()..].to_uppercase());
        for (address, expected_error) in [
            (valid.replacen("atto://", "nano://", 1), "prefix"),
            (valid.to_uppercase(), "prefix"),
            (uppercase_body, "alphabet"),
            (format!("{}a", valid), "61"),
            (valid.replacen('a', "0", 1), "prefix"),
            (valid.replacen('b', "0", 1), "alphabet"),
        ] {
            let err = atto_pubkey_from_address(&address).unwrap_err();
            assert!(
                err.to_string().contains(expected_error),
                "expected {expected_error:?} in {err} for {address}"
            );
        }

        let mut decoded = decode_atto_address_bytes(&valid).unwrap();
        decoded[0] = 1;
        let bad_algorithm = format!("atto://{}", encode_base32_lower_no_pad(&decoded));
        let err = atto_pubkey_from_address(&bad_algorithm).unwrap_err();
        assert!(err.to_string().contains("algorithm"));

        let mut bad_checksum = valid.clone();
        let last = bad_checksum.pop().unwrap();
        bad_checksum.push(if last == 'a' { 'b' } else { 'a' });
        let err = atto_pubkey_from_address(&bad_checksum).unwrap_err();
        assert!(err.to_string().contains("checksum"));
    }

    #[test]
    fn sign_transaction_requires_canonical_atto_block_payload() {
        let key = derive_key(0);
        let signer = AttoSigner;
        let err = signer.sign_transaction(&key, b"not a block").unwrap_err();
        assert!(err.to_string().contains("unsupported Atto block type"));

        let block = fixture_receive_block();
        let signature = signer.sign_transaction(&key, &block.to_buffer()).unwrap();
        assert_eq!(signature.signature.len(), 64);
    }

    #[test]
    fn sign_message_uses_atto_domain_separated_hash() {
        let key = derive_key(0);
        let signer = AttoSigner;
        let message = b"atto message";
        let output = signer.sign_message(&key, message).unwrap();
        let public_key =
            VerifyingKey::from_bytes(&output.public_key.unwrap().try_into().unwrap()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&output.signature.try_into().unwrap());

        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"ATTO Signed Message v1");
        preimage.extend_from_slice(public_key.as_bytes());
        preimage.extend_from_slice(&(message.len() as u64).to_le_bytes());
        preimage.extend_from_slice(message);
        let digest = Blake2b::<U64>::digest(&preimage);

        public_key.verify(&digest, &signature).unwrap();
        assert!(public_key.verify(message, &signature).is_err());
    }

    #[test]
    fn official_send_fixture_serializes_to_canonical_block_bytes_and_hash() {
        let block = fixture_send_block();
        assert_eq!(block.to_buffer().len(), 134);
        assert_eq!(
            hex::encode_upper(block.to_buffer()),
            concat!(
                "0203000000",
                "A5E7E4B3B93150314E1177D5B9DE0057626B16A4B3C3F1DB37DF67628A5EF457",
                "0200000000000000",
                "0100000000000000",
                "FB1D08E38C010000",
                "6CC2D3A7513723B1BA59DE784BA546BAF6447464D0BA3D80004752D6F9F4BA23",
                "00",
                "552254E101B51B22080D084C12C94BF7DFC5BE0D973025D62C0BC1FF4D9B145F",
                "0100000000000000"
            )
        );
        assert_eq!(
            hex::encode_upper(block.hash()),
            "15601F3C70D7D27F104A7076DB399BE9123241A3ECCE6E833B676720B4E1F43E"
        );
    }

    #[test]
    fn all_block_variants_have_canonical_lengths_and_api_json_fields() {
        let cases = [
            (fixture_open_block(), 119, "OPEN"),
            (fixture_receive_block(), 126, "RECEIVE"),
            (fixture_send_block(), 134, "SEND"),
            (fixture_change_block(), 126, "CHANGE"),
        ];
        for (block, expected_len, expected_type) in cases {
            assert_eq!(block.to_buffer().len(), expected_len, "{expected_type}");
            let json = block.to_api_json_value();
            assert_eq!(json["type"], expected_type);
            assert_eq!(json["network"], "LOCAL");
            assert_eq!(json["algorithm"], "V1");
            assert_eq!(json["version"], 0);
            assert!(json.get("address").is_some());
            assert!(json["balance"].is_number());
        }
    }

    #[test]
    fn signs_block_hash_and_encodes_transaction_without_signing_work() {
        let key = derive_key(0);
        let block = fixture_send_block();
        let mut unsigned = block.to_buffer();
        unsigned.extend_from_slice(&[0xA5; 8]);

        let signer = signer_for_chain(ChainType::Atto);
        let signable = signer.extract_signable_bytes(&unsigned).unwrap();
        assert_eq!(signable, block.to_buffer().as_slice());

        let output = signer.sign_transaction(&key, &unsigned).unwrap();
        assert_eq!(output.signature.len(), 64);
        let public_key =
            VerifyingKey::from_bytes(&output.public_key.clone().unwrap().try_into().unwrap())
                .unwrap();
        let signature =
            ed25519_dalek::Signature::from_bytes(&output.signature.clone().try_into().unwrap());
        public_key.verify(&block.hash(), &signature).unwrap();
        assert!(public_key.verify(&unsigned, &signature).is_err());

        let signed = signer
            .encode_signed_transaction(&unsigned, &output)
            .unwrap();
        assert_eq!(signed.len(), 134 + 64 + 8);
        assert_eq!(&signed[..134], block.to_buffer().as_slice());
        assert_eq!(&signed[134..198], output.signature.as_slice());
        assert_eq!(&signed[198..], &[0xA5; 8]);
    }

    #[test]
    fn signed_transaction_api_json_contains_signature_and_work_hex() {
        let block = fixture_receive_block();
        let signature = [0x11u8; 64];
        let work = [0x22u8; 8];
        let json = AttoSignedTransaction::new(block, signature, work).to_api_json_value();
        assert_eq!(json["type"], "RECEIVE");
        assert_eq!(json["signature"], "11".repeat(64));
        assert_eq!(json["work"], "22".repeat(8));
    }

    #[test]
    fn signed_transaction_bytes_convert_to_api_json_and_hash() {
        let block = fixture_receive_block();
        let signed = AttoSignedTransaction::new(block.clone(), [0x11; 64], [0x22; 8]);
        let bytes = signed.to_buffer();

        let json = atto_signed_transaction_to_api_json_value(&bytes).unwrap();
        let hash = atto_signed_transaction_hash_hex(&bytes).unwrap();

        assert_eq!(json["type"], "RECEIVE");
        assert_eq!(json["signature"], "11".repeat(64));
        assert_eq!(json["work"], "22".repeat(8));
        assert!(json["address"].as_str().unwrap().starts_with("atto://"));
        assert_eq!(hash, hex::encode_upper(block.hash()));
    }

    #[test]
    fn signed_transaction_api_json_rejects_missing_work_bytes() {
        let block = fixture_receive_block();
        let mut bytes = block.to_buffer();
        bytes.extend_from_slice(&[0x11; 64]);

        let err = atto_signed_transaction_to_api_json_value(&bytes).unwrap_err();

        assert!(err.to_string().contains("signature + 8 work"), "{err}");
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn fixture_send_block() -> AttoBlock {
        AttoBlock::Send(AttoSendBlock {
            network: AttoNetwork::Local,
            version: 0,
            public_key: hex32("A5E7E4B3B93150314E1177D5B9DE0057626B16A4B3C3F1DB37DF67628A5EF457"),
            height: 2,
            balance: 1,
            timestamp_ms: 1704616009211,
            previous: hex32("6CC2D3A7513723B1BA59DE784BA546BAF6447464D0BA3D80004752D6F9F4BA23"),
            receiver_public_key: hex32(
                "552254E101B51B22080D084C12C94BF7DFC5BE0D973025D62C0BC1FF4D9B145F",
            ),
            amount: 1,
        })
    }

    fn fixture_receive_block() -> AttoBlock {
        AttoBlock::Receive(AttoReceiveBlock {
            network: AttoNetwork::Local,
            version: 0,
            public_key: hex32("39B56483A0DE38D9578CAF7EA791C2FEC96B318C7BD9989207B575334C5D9F1B"),
            height: 2,
            balance: 18_000_000_000_000_000_000,
            timestamp_ms: 1704616009216,
            previous: hex32("03783A08F51486A66A602439D9164894F07F150B548911086DAE4E4F57A9C4DD"),
            send_hash: hex32("EE5FDA9A1ACEC7A09231792C345CDF5CD29F1059E5C413535D9FCA66A1FB2F49"),
        })
    }

    fn fixture_open_block() -> AttoBlock {
        AttoBlock::Open(AttoOpenBlock {
            network: AttoNetwork::Local,
            version: 0,
            public_key: hex32("15625A4831C8F1312F1DB41550D0FD6C730FCC259ACE0FF88B500EA96783A348"),
            balance: 18_000_000_000_000_000_000,
            timestamp_ms: 1704616008836,
            send_hash: hex32("4DC7257C0F492B8C7AC2D8DE4A6DC4078B060BB42FDB6F8032A839AAA9048DB0"),
            representative_public_key: hex32(
                "69C010A8A74924D083D1FC8234861B4B357530F42341484B4EBDA6B99F047105",
            ),
        })
    }

    fn fixture_change_block() -> AttoBlock {
        AttoBlock::Change(AttoChangeBlock {
            network: AttoNetwork::Local,
            version: 0,
            public_key: hex32("2415EE860847B3A1CE8B605267E83481D8426A4C42F8128EA72D72F0AD072DCC"),
            height: 2,
            balance: 18_000_000_000_000_000_000,
            timestamp_ms: 1704616009221,
            previous: hex32("AD675BD718F3D96F9B89C58A8BF80741D5EDB6741D235B070D56E84098894DD5"),
            representative_public_key: hex32(
                "69C010A8A74924D083D1FC8234861B4B357530F42341484B4EBDA6B99F047105",
            ),
        })
    }
}
