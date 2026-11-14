//! Signatures (secp256k1 ECDSA) and the VRF used for proposer election.
pub mod ecdsa;
pub mod vrf;

use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use vrf::VrfKeypair;

/// Keys of the validator a node runs as.
pub struct LocalValidator {
    pub signing_key: SigningKey,
    pub vrf: VrfKeypair,
}
impl LocalValidator {
    /// Uses the VRF key derived from the ECDSA key (matches the default validator set).
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let vrf = VrfKeypair::derive_from_ecdsa(&signing_key);
        LocalValidator { signing_key, vrf }
    }
    /// SEC1 encoded public key; identifies the validator everywhere.
    pub fn id(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_sec1_bytes().to_vec()
    }
    pub fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(payload);
        signature.to_bytes().to_vec()
    }
}
