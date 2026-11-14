//! Standard VRF (Schnorrkel / sr25519 VRF over Ristretto255, the construction used by
//! Polkadot's BABE). Each validator holds a VRF keypair; evaluating the VRF on a public input
//! yields an output that is unique for (key, input), unpredictable without the secret key, and
//! publicly verifiable from the attached proof.
use crate::types::{sha256, Hash, VrfClaim};
use anyhow::{anyhow, Result};
use k256::ecdsa::SigningKey;
use schnorrkel::{
    signing_context,
    vrf::{VRFPreOut, VRFProof},
    ExpansionMode, Keypair, MiniSecretKey, PublicKey,
};

const VRF_SIGNING_CONTEXT: &[u8] = b"DISEQ-leader-election-v1";
const VRF_OUTPUT_CONTEXT: &[u8] = b"DISEQ-vrf-output-v1";

pub struct VrfKeypair(Keypair);

impl VrfKeypair {
    pub fn from_seed(seed: &Hash) -> Self {
        let mini = MiniSecretKey::from_bytes(seed).expect("32 byte seed");
        VrfKeypair(mini.expand_to_keypair(ExpansionMode::Ed25519))
    }
    /// Deterministically derives a VRF key from a validator's ECDSA key, so the default
    /// setup needs a single secret per validator. Production deployments can instead
    /// generate and register an independent VRF key.
    pub fn derive_from_ecdsa(sk: &SigningKey) -> Self {
        Self::from_seed(&sha256(&[b"DISEQ_VRF_KEY_V1", &sk.to_bytes()]))
    }
    pub fn public_bytes(&self) -> Vec<u8> {
        self.0.public.to_bytes().to_vec()
    }
    /// Evaluates the VRF on `input`, returning the 32 byte output and the claim peers verify.
    pub fn prove(&self, input: &[u8]) -> (Hash, VrfClaim) {
        let ctx = signing_context(VRF_SIGNING_CONTEXT);
        let (inout, proof, _) = self.0.vrf_sign(ctx.bytes(input));
        let output: Hash = inout.make_bytes(VRF_OUTPUT_CONTEXT);
        let claim = VrfClaim {
            pre_output: inout.to_preout().to_bytes().to_vec(),
            proof: proof.to_bytes().to_vec(),
        };
        (output, claim)
    }
}

/// Verifies `claim` for `input` under `public_key`, returning the VRF output.
pub fn verify(public_key: &[u8], input: &[u8], claim: &VrfClaim) -> Result<Hash> {
    let pk = PublicKey::from_bytes(public_key).map_err(|e| anyhow!("invalid VRF key: {e}"))?;
    let pre_output = VRFPreOut::from_bytes(&claim.pre_output)
        .map_err(|e| anyhow!("invalid VRF pre-output: {e}"))?;
    let proof =
        VRFProof::from_bytes(&claim.proof).map_err(|e| anyhow!("invalid VRF proof: {e}"))?;
    let ctx = signing_context(VRF_SIGNING_CONTEXT);
    let (inout, _) = pk
        .vrf_verify(ctx.bytes(input), &pre_output, &proof)
        .map_err(|e| anyhow!("VRF verification failed: {e}"))?;
    Ok(inout.make_bytes(VRF_OUTPUT_CONTEXT))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_and_verify_roundtrip() {
        let kp = VrfKeypair::from_seed(&[7; 32]);
        let (out, claim) = kp.prove(b"input");
        assert_eq!(verify(&kp.public_bytes(), b"input", &claim).unwrap(), out);
    }

    #[test]
    fn output_is_unique_per_key_and_input() {
        // The prover has no free input: re-evaluating gives the same output, so it cannot
        // grind for a favourable result.
        let kp = VrfKeypair::from_seed(&[7; 32]);
        assert_eq!(kp.prove(b"input").0, kp.prove(b"input").0);
        assert_ne!(kp.prove(b"input").0, kp.prove(b"other").0);
    }

    #[test]
    fn rejects_wrong_input_or_key() {
        let kp = VrfKeypair::from_seed(&[7; 32]);
        let other = VrfKeypair::from_seed(&[8; 32]);
        let (_, claim) = kp.prove(b"input");
        assert!(verify(&kp.public_bytes(), b"other", &claim).is_err());
        assert!(verify(&other.public_bytes(), b"input", &claim).is_err());
    }
}
