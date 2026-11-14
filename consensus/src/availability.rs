//! Data availability of batches (the "quorum store" layer, as in Aptos / Narwhal).
//!
//! Validators do not put messages into blocks. Instead:
//!
//! 1. Each validator packs its clients' messages into a [`Batch`], signs it and broadcasts it.
//! 2. Every validator that receives a valid batch stores it and returns a signed
//!    [`Attestation`] to the author.
//! 3. Attestations from more than 2/3 of the weight form a [`BatchCert`]. Since at most 1/3
//!    is faulty, at least one honest validator holds the batch and will serve it.
//! 4. Blocks list certificates. Consensus only has to agree on a few hundred bytes per batch,
//!    and every validator disseminates data in parallel instead of one leader per block.
//!
//! This module holds the pure rules: what a valid batch, attestation and certificate is, and
//! how attestations combine into a certificate. Storage and networking live in the node.
use crate::crypto::{ecdsa::verify_signature, LocalValidator};
use crate::types::{Attestation, Batch, BatchCert, GenericPublicKey, Hash, Message};
use crate::validators::ValidatorSet;
use anyhow::{anyhow, ensure, Result};
use std::collections::HashSet;

/// Seals `messages` into a signed batch.
pub fn seal(identity: &LocalValidator, seq: u64, messages: Vec<Message>) -> Batch {
    let mut batch = Batch {
        author: identity.id(),
        seq,
        messages,
        signature: Vec::new(),
    };
    batch.signature = identity.sign(&Batch::signing_payload(&batch.digest()));
    batch
}

/// Checks a received batch: authored and signed by an active validator, sane sizes.
/// Returns its digest.
pub fn verify_batch(
    batch: &Batch,
    set: &ValidatorSet,
    max_messages: usize,
    max_message_bytes: usize,
) -> Result<Hash> {
    ensure!(
        !batch.messages.is_empty() && batch.messages.len() <= max_messages,
        "batch must hold 1 to {max_messages} messages"
    );
    ensure!(
        batch
            .messages
            .iter()
            .all(|m| !m.data.is_empty() && m.data.len() <= max_message_bytes),
        "invalid message size in batch"
    );
    let author = set
        .get(&batch.author)
        .ok_or_else(|| anyhow!("batch author is not an active validator"))?;
    let digest = batch.digest();
    verify_signature(
        &author.id,
        &Batch::signing_payload(&digest),
        &batch.signature,
    )?;
    Ok(digest)
}

/// Signs that this validator stores `batch`. Call only after the batch is persisted.
pub fn attest(identity: &LocalValidator, digest: Hash, messages: u32) -> Attestation {
    Attestation {
        digest,
        messages,
        validator: identity.id(),
        signature: identity.sign(&Attestation::signing_payload(&digest, messages)),
    }
}

/// Checks a certificate: attestations from distinct active validators, all valid, together
/// more than 2/3 of the weight.
pub fn verify_cert(cert: &BatchCert, set: &ValidatorSet) -> Result<()> {
    ensure!(cert.messages > 0, "empty batch");
    ensure!(
        set.get(&cert.author).is_some(),
        "batch author is not an active validator"
    );
    let payload = Attestation::signing_payload(&cert.digest, cert.messages);
    let mut seen = HashSet::new();
    let mut weight = 0u64;
    for (validator, signature) in &cert.attestations {
        ensure!(seen.insert(validator), "duplicate attestation");
        let v = set
            .get(validator)
            .ok_or_else(|| anyhow!("attestation from unknown validator"))?;
        verify_signature(&v.id, &payload, signature)?;
        weight += v.weight;
    }
    ensure!(
        set.is_quorum(weight),
        "certificate lacks a quorum of attestations"
    );
    Ok(())
}

/// Collects attestations for one of our own batches until they form a certificate.
pub struct CertBuilder {
    digest: Hash,
    author: GenericPublicKey,
    messages: u32,
    attestations: Vec<(GenericPublicKey, Vec<u8>)>,
    done: bool,
}

impl CertBuilder {
    pub fn new(digest: Hash, author: GenericPublicKey, messages: u32) -> Self {
        CertBuilder {
            digest,
            author,
            messages,
            attestations: Vec::new(),
            done: false,
        }
    }

    pub fn has_attested(&self, validator: &[u8]) -> bool {
        self.attestations.iter().any(|(v, _)| v == validator)
    }

    /// Adds a (verified here) attestation. Returns the certificate once the attestations
    /// reach a quorum, exactly once.
    pub fn add(&mut self, att: Attestation, set: &ValidatorSet) -> Result<Option<BatchCert>> {
        ensure!(
            att.digest == self.digest && att.messages == self.messages,
            "attestation for a different batch"
        );
        if self.done || self.has_attested(&att.validator) {
            return Ok(None);
        }
        let v = set
            .get(&att.validator)
            .ok_or_else(|| anyhow!("attestation from unknown validator"))?;
        verify_signature(
            &v.id,
            &Attestation::signing_payload(&att.digest, att.messages),
            &att.signature,
        )?;
        self.attestations.push((att.validator, att.signature));
        let weight: u64 = self
            .attestations
            .iter()
            .filter_map(|(id, _)| set.get(id))
            .map(|v| v.weight)
            .sum();
        if !set.is_quorum(weight) {
            return Ok(None);
        }
        self.done = true;
        Ok(Some(BatchCert {
            digest: self.digest,
            author: self.author.clone(),
            messages: self.messages,
            attestations: self.attestations.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{default_validator_set, test_signing_keys};

    fn validators() -> (Vec<LocalValidator>, ValidatorSet) {
        let keys = test_signing_keys()
            .into_iter()
            .map(LocalValidator::from_signing_key)
            .collect();
        let addrs: Vec<String> = (0..4).map(|i| format!("n{i}")).collect();
        (keys, default_validator_set(&addrs))
    }

    fn batch(author: &LocalValidator) -> Batch {
        let messages = vec![Message {
            data: b"hello".to_vec(),
            timestamp: 0,
        }];
        seal(author, 1, messages)
    }

    #[test]
    fn three_of_four_attestations_certify_a_batch() {
        let (keys, set) = validators();
        let b = batch(&keys[0]);
        let digest = verify_batch(&b, &set, 10, 100).unwrap();
        let mut builder = CertBuilder::new(digest, keys[0].id(), 1);
        assert!(builder
            .add(attest(&keys[0], digest, 1), &set)
            .unwrap()
            .is_none());
        // a repeated attestation does not count twice
        assert!(builder
            .add(attest(&keys[0], digest, 1), &set)
            .unwrap()
            .is_none());
        assert!(builder
            .add(attest(&keys[1], digest, 1), &set)
            .unwrap()
            .is_none());
        let cert = builder
            .add(attest(&keys[2], digest, 1), &set)
            .unwrap()
            .expect("quorum");
        verify_cert(&cert, &set).unwrap();
        // no second certificate
        assert!(builder
            .add(attest(&keys[3], digest, 1), &set)
            .unwrap()
            .is_none());
    }

    #[test]
    fn invalid_batches_and_certificates_are_rejected() {
        let (keys, set) = validators();
        let mut b = batch(&keys[0]);
        b.messages[0].data = b"tampered".to_vec();
        assert!(verify_batch(&b, &set, 10, 100).is_err());

        let digest = batch(&keys[0]).digest();
        let att = |k: &LocalValidator| (k.id(), attest(k, digest, 1).signature);
        let mut cert = BatchCert {
            digest,
            author: keys[0].id(),
            messages: 1,
            attestations: vec![att(&keys[0]), att(&keys[1])],
        };
        assert!(verify_cert(&cert, &set).is_err(), "2 of 4 is no quorum");
        cert.attestations.push(att(&keys[1]));
        assert!(verify_cert(&cert, &set).is_err(), "duplicate attester");
        cert.attestations.pop();
        cert.attestations.push(att(&keys[2]));
        verify_cert(&cert, &set).unwrap();
        cert.messages = 2;
        assert!(
            verify_cert(&cert, &set).is_err(),
            "count is covered by the signatures"
        );
    }
}
