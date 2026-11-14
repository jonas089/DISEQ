//! Binary wire format for peer-to-peer traffic: bincode (varint integers) with a size limit,
//! so a peer cannot make us allocate more than `MAX_WIRE_BYTES` while decoding.
//!
//! A batch (`Vec<T>`) on the wire is the item count followed by the items, so items can be
//! encoded once and the same bytes concatenated into a batch for every peer.
use anyhow::Result;
use bincode::Options;
use bytes::{BufMut, Bytes, BytesMut};
use serde::{de::DeserializeOwned, Serialize};

/// Upper bound for one encoded request or response.
pub const MAX_WIRE_BYTES: u64 = 64 * 1024 * 1024;

/// Content type used for bincode request and response bodies.
pub const BINCODE: &str = "application/octet-stream";

fn options() -> impl Options {
    bincode::DefaultOptions::new().with_limit(MAX_WIRE_BYTES)
}

pub fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Bytes> {
    Ok(Bytes::from(options().serialize(value)?))
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(options().deserialize(bytes)?)
}

/// Encodes `Vec<T>` from items that were each encoded with [`encode`].
pub fn encode_batch(items: &[Bytes]) -> Result<Bytes> {
    let len = options().serialize(&(items.len() as u64))?;
    let total = len.len() + items.iter().map(Bytes::len).sum::<usize>();
    let mut out = BytesMut::with_capacity(total);
    out.put_slice(&len);
    for item in items {
        out.put_slice(item);
    }
    Ok(out.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;
    use diseq_consensus::types::Message;

    #[test]
    fn batch_of_encoded_items_decodes_as_vec() {
        let messages: Vec<Message> = (0..300u32)
            .map(|i| Message {
                data: i.to_le_bytes().to_vec(),
                timestamp: i,
            })
            .collect();
        let items: Vec<Bytes> = messages.iter().map(|m| encode(m).unwrap()).collect();
        let decoded: Vec<Message> = decode(&encode_batch(&items).unwrap()).unwrap();
        assert_eq!(decoded, messages);
        assert_eq!(encode_batch(&items).unwrap(), encode(&messages).unwrap());
    }

    #[test]
    fn oversized_length_prefix_is_rejected() {
        // claims 2^40 messages but carries none: must fail, not allocate
        let bogus = options().serialize(&(1u64 << 40)).unwrap();
        assert!(decode::<Vec<Message>>(&bogus).is_err());
    }
}
