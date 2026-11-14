//! Batch dissemination (the node side of [`diseq_consensus::availability`]).
//!
//! * **Own batches.** Client messages wait in `pending` until there are `max_batch_messages`
//!   of them or the oldest is `batch_interval_ms` old. They are then sealed into a signed
//!   batch, stored, attested by ourselves and broadcast. Peers' attestations are collected
//!   into a certificate, which goes to consensus and to all validators. Until the batch is
//!   committed it is retransmitted to validators that have not attested, and its certificate
//!   is re-sent, so lost messages only cost time.
//! * **Peers' batches.** A valid batch is stored, then attested back to its author. Full nodes
//!   store batches without attesting.
//!
//! Backpressure: at most `max_inflight_batches` own batches may be uncommitted. Beyond that
//! no new batches are sealed, `pending` fills up, and clients get "overloaded" errors.
//!
//! Accepting a message does not make it final: if this validator crashes before its batch
//! is certified, the message is lost and the client must resubmit (resubmitting is always
//! safe, duplicates are sequenced once). `GET /get/message/:id` tells when it is final.
use crate::network::{wire, DataMsg};
use crate::storage::Db;
use anyhow::{ensure, Result};
use bytes::Bytes;
use diseq_consensus::availability::{attest, seal, verify_batch, CertBuilder};
use diseq_consensus::types::{Attestation, Batch, BatchCert, Block, Hash, Message};
use diseq_consensus::validators::ValidatorSet;
use diseq_consensus::{LocalValidator, Received};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct BatchConfig {
    pub max_batch_messages: usize,
    pub batch_interval_ms: u64,
    pub max_message_bytes: usize,
    pub max_pending_messages: usize,
    pub max_inflight_batches: usize,
    pub retry_interval_ms: u64,
}

struct OwnBatch {
    /// the encoded `DataMsg::Batch`, sent as is on every retransmission
    encoded: Bytes,
    builder: CertBuilder,
    cert: Option<BatchCert>,
    next_retry_ms: u64,
}

/// What a retransmission should do.
pub enum Retry {
    /// re-send the batch to these validator addresses
    Batch(Bytes, Vec<String>),
    /// re-offer the certificate to consensus and re-broadcast it
    Cert(BatchCert),
}

pub struct Dissemination {
    identity: Option<LocalValidator>,
    db: Arc<Db>,
    config: BatchConfig,
    pending: Vec<Message>,
    pending_ids: HashSet<Hash>,
    oldest_ms: u64,
    seq: u64,
    own: HashMap<Hash, OwnBatch>,
}

impl Dissemination {
    pub fn new(
        identity: Option<LocalValidator>,
        db: Arc<Db>,
        config: BatchConfig,
        now_ms: u64,
    ) -> Self {
        Dissemination {
            identity,
            db,
            config,
            pending: Vec::new(),
            pending_ids: HashSet::new(),
            oldest_ms: 0,
            // unique across restarts without persisting a counter
            seq: now_ms * 1_000,
            own: HashMap::new(),
        }
    }

    pub fn is_validator(&self) -> bool {
        self.identity.is_some()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn inflight(&self) -> usize {
        self.own.len()
    }

    /// Admits client messages (ids computed by the caller). One verdict per message.
    pub fn submit(
        &mut self,
        messages: Vec<(Hash, Message)>,
        now_ms: u64,
    ) -> Vec<Result<Received, String>> {
        let ids: Vec<Hash> = messages.iter().map(|(id, _)| *id).collect();
        let sequenced = match self.db.sequenced(&ids) {
            Ok(flags) => flags,
            Err(e) => return messages.iter().map(|_| Err(format!("{e:#}"))).collect(),
        };
        messages
            .into_iter()
            .zip(sequenced)
            .map(|((id, message), sequenced)| {
                if message.data.is_empty() || message.data.len() > self.config.max_message_bytes {
                    Err(format!(
                        "message must hold 1 to {} bytes",
                        self.config.max_message_bytes
                    ))
                } else if sequenced || self.pending_ids.contains(&id) {
                    Ok(Received::Duplicate)
                } else if self.pending.len() >= self.config.max_pending_messages {
                    Err("node is overloaded, retry later".into())
                } else {
                    if self.pending.is_empty() {
                        self.oldest_ms = now_ms;
                    }
                    self.pending_ids.insert(id);
                    self.pending.push(message);
                    Ok(Received::New)
                }
            })
            .collect()
    }

    /// Seals pending messages into a batch if one is due. Returns the encoded batch to
    /// broadcast, and the certificate if our own attestation already completes it.
    pub fn seal_due(
        &mut self,
        now_ms: u64,
        set: &ValidatorSet,
    ) -> Result<Option<(Bytes, Option<BatchCert>)>> {
        let Some(identity) = &self.identity else {
            return Ok(None);
        };
        let full = self.pending.len() >= self.config.max_batch_messages;
        let old =
            !self.pending.is_empty() && now_ms >= self.oldest_ms + self.config.batch_interval_ms;
        if !(full || old) || self.own.len() >= self.config.max_inflight_batches {
            return Ok(None);
        }
        let take = self.pending.len().min(self.config.max_batch_messages);
        let messages: Vec<Message> = self.pending.drain(..take).collect();
        for m in &messages {
            self.pending_ids.remove(&m.id());
        }
        self.oldest_ms = now_ms;
        self.seq += 1;
        let batch = seal(identity, self.seq, messages);
        let digest = batch.digest();
        let count = batch.messages.len() as u32;
        self.db.put_batch(&digest, &batch)?;
        let encoded = wire::encode(&DataMsg::Batch(batch))?;
        let mut builder = CertBuilder::new(digest, identity.id(), count);
        let cert = builder.add(attest(identity, digest, count), set)?;
        self.own.insert(
            digest,
            OwnBatch {
                encoded: encoded.clone(),
                builder,
                cert: cert.clone(),
                next_retry_ms: now_ms + self.config.retry_interval_ms,
            },
        );
        Ok(Some((encoded, cert)))
    }

    /// Validates and stores a peer's batch; returns our attestation if we are a validator.
    pub fn on_batch(&mut self, batch: Batch, set: &ValidatorSet) -> Result<Option<Attestation>> {
        let digest = verify_batch(
            &batch,
            set,
            self.config.max_batch_messages,
            self.config.max_message_bytes,
        )?;
        if !self.db.has_batch(&digest)? {
            self.db.put_batch(&digest, &batch)?;
        }
        let count = batch.messages.len() as u32;
        Ok(self
            .identity
            .as_ref()
            .filter(|id| set.get(&id.id()).is_some())
            .map(|id| attest(id, digest, count)))
    }

    /// Adds an attestation for one of our batches; returns the certificate once complete.
    pub fn on_attestation(
        &mut self,
        att: Attestation,
        set: &ValidatorSet,
    ) -> Result<Option<BatchCert>> {
        let own = self.own.get_mut(&att.digest);
        ensure!(own.is_some(), "attestation for an unknown batch");
        let own = own.expect("checked");
        let cert = own.builder.add(att, set)?;
        if cert.is_some() {
            own.cert = cert.clone();
        }
        Ok(cert)
    }

    /// Retransmissions that are due for own batches that are not committed yet.
    pub fn retries(&mut self, now_ms: u64, set: &ValidatorSet) -> Vec<Retry> {
        let me = self.identity.as_ref().map(|i| i.id());
        let mut out = Vec::new();
        for own in self.own.values_mut() {
            if now_ms < own.next_retry_ms {
                continue;
            }
            own.next_retry_ms = now_ms + self.config.retry_interval_ms;
            match &own.cert {
                Some(cert) => out.push(Retry::Cert(cert.clone())),
                None => {
                    let missing: Vec<String> = set
                        .iter()
                        .filter(|v| {
                            Some(v.id_bytes()) != me && !own.builder.has_attested(&v.id_bytes())
                        })
                        .map(|v| v.address.clone())
                        .collect();
                    out.push(Retry::Batch(own.encoded.clone(), missing));
                }
            }
        }
        out
    }

    /// Forgets own batches that a committed block contains.
    pub fn on_committed(&mut self, block: &Block) {
        for cert in &block.batches {
            self.own.remove(&cert.digest);
        }
    }
}
