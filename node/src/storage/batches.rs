//! Batch payloads, by digest. A batch is stored before this node attests to it, and kept
//! after its block commits so peers can fetch it while syncing.
use super::{write_options, Db};
use anyhow::Result;
use diseq_consensus::types::{Batch, Hash};

impl Db {
    pub fn put_batch(&self, digest: &Hash, batch: &Batch) -> Result<()> {
        self.raw().put_cf_opt(
            self.cf("batches"),
            digest,
            bincode::serialize(batch)?,
            &write_options(false),
        )?;
        Ok(())
    }

    pub fn has_batch(&self, digest: &Hash) -> Result<bool> {
        Ok(self.get("batches", digest)?.is_some())
    }

    /// The stored batch for each digest, in order (`None` where missing).
    pub fn batches(&self, digests: &[Hash]) -> Result<Vec<Option<Batch>>> {
        let cf = self.cf("batches");
        self.raw()
            .multi_get_cf(digests.iter().map(|d| (cf, d.as_slice())))
            .into_iter()
            .map(|value| match value? {
                Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
                None => Ok(None),
            })
            .collect()
    }
}
