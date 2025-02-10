use k256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;

pub struct Keypair {
    pub sk: SigningKey,
    pub vk: VerifyingKey,
}
impl Keypair {
    #[allow(unused)]
    pub fn new() -> Self {
        let sk = SigningKey::random(&mut OsRng);
        let vk = VerifyingKey::from(&sk);
        Keypair { sk, vk }
    }
    #[allow(unused)]
    pub fn sign_data(&self, data: &[u8]) -> Signature {
        self.sk.sign(data)
    }
    #[allow(unused)]
    pub fn serialize_sk(&self) -> Vec<u8> {
        self.sk.to_bytes().to_vec()
    }
    #[allow(unused)]
    pub fn serialize_vk(&self) -> Vec<u8> {
        self.vk.to_sec1_bytes().to_vec()
    }
}
impl Default for Keypair {
    fn default() -> Self {
        Self::new()
    }
}
pub fn deserialize_sk(sk_serialized: &[u8]) -> SigningKey {
    SigningKey::from_bytes(sk_serialized.into()).unwrap()
}
pub fn deserialize_vk(vk_serialized: &[u8]) -> VerifyingKey {
    VerifyingKey::from_sec1_bytes(vk_serialized).unwrap()
}
#[test]
fn test_serialize_and_deserialize_sk() {
    let keypair = Keypair::new();
    let sk_before = keypair.sk.clone();
    let sk_serialized = keypair.serialize_sk();
    let sk_deserialized = deserialize_sk(&sk_serialized);
    assert_eq!(sk_before, sk_deserialized);
}
#[test]
fn test_serialize_and_deserialize_vk() {
    let keypair = Keypair::new();
    let vk_before = keypair.vk;
    let vk_serialized = keypair.serialize_vk();
    let vk_deserialized = deserialize_vk(&vk_serialized);
    assert_eq!(vk_before, vk_deserialized);
}
#[test]
fn test_generate_and_verify_ecdsa_signature_using_secp256k1_curve() {
    use k256::ecdsa::signature::Verifier;
    let keypair = Keypair::new();
    let arbitrary_data: Vec<u8> = vec![0; 32];
    let signature = keypair.sign_data(&arbitrary_data);
    keypair
        .vk
        .verify(&arbitrary_data, &signature)
        .expect("Failed to verify signature");
}
#[test]
fn test_generate_validator_keys_for_basic_e2e_setup() {
    let v1_keypair = Keypair::new();
    let v2_keypair = Keypair::new();
    let v3_keypair = Keypair::new();
    let v4_keypair = Keypair::new();
    println!(
        "V1 sk: {:?}, V1 vk: {:?}",
        v1_keypair.serialize_sk(),
        v1_keypair.serialize_vk()
    );
    println!(
        "V2 sk: {:?}, V2 vk: {:?}",
        v2_keypair.serialize_sk(),
        v2_keypair.serialize_vk()
    );
    println!(
        "V3 sk: {:?}, V3 vk: {:?}",
        v3_keypair.serialize_sk(),
        v3_keypair.serialize_vk()
    );
    println!(
        "V4 sk: {:?}, V4 vk: {:?}",
        v4_keypair.serialize_sk(),
        v4_keypair.serialize_vk()
    );
}
