//! Public API from stealth discovery through SDK encryption and disclosure.

use rand_core::{TryCryptoRng, TryRng};
use solana_zk_sdk::{
    encryption::{
        auth_encryption::{AeCiphertext, AeKey},
        derivation::derive_confidential_keys_from_ikm,
    },
    zk_elgamal_proof_program::{VerifyZkProof, build_pubkey_validity_proof_data},
};
use stealth_keygen::{
    ConfidentialContext, ConfidentialKeyMaterial, RecipientSecretKeys, derive_payment,
    recover_payment,
};

// Fixed bytes for tests only. Never use this RNG with real keys.
struct TestRng(u8);

impl TryRng for TestRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from_le_bytes([self.0; 4]))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_le_bytes([self.0; 8]))
    }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
        out.fill(self.0);
        self.0 += 1;
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

#[test]
fn payer_recipient_and_disclosure_derive_the_same_usable_keys() {
    let recipient = RecipientSecretKeys::generate(&mut TestRng(1)).expect("recipient");
    let sent = derive_payment(&recipient.derive_public_keys(), &mut TestRng(3)).expect("payment");
    let recovered = recover_payment(&recipient, &sent.announcement)
        .expect("recovery")
        .expect("matching tag");
    let context = ConfidentialContext {
        chain_id: [1; 32],
        program_id: [2; 32],
        mint: [3; 32],
        token_account: [4; 32],
    };
    let material = sent.derive_ct_ikm(&context).expect("payer material");
    let received = recovered
        .derive_ct_ikm(&context)
        .expect("recipient material");
    let disclosed = ConfidentialKeyMaterial::from_bytes(*material.as_bytes());
    let (payer_eg, payer_ae) =
        derive_confidential_keys_from_ikm(material.as_bytes()).expect("payer keys");
    for input in [&received, &disclosed] {
        let (eg, ae) = derive_confidential_keys_from_ikm(input.as_bytes()).expect("derived keys");
        assert_eq!(eg, payer_eg);
        assert_eq!(ae, payer_ae);
        for amount in [0, 1, 42, 65_535] {
            assert_eq!(
                eg.secret()
                    .decrypt_u32(&payer_eg.pubkey().encrypt_u64(amount)),
                Some(amount)
            );
        }
        for amount in [0, 1, 42, u32::MAX as u64, u64::MAX] {
            assert_eq!(ae.decrypt(&payer_ae.encrypt(amount)), Some(amount));
        }
    }
    build_pubkey_validity_proof_data(&payer_eg)
        .expect("pubkey proof")
        .verify_proof()
        .expect("valid proof");

    // A receipt containing different material fails the public-key comparison.
    let mut forged = *disclosed.as_bytes();
    forged[0] ^= 1;
    let (forged_eg, _) = derive_confidential_keys_from_ikm(&forged).expect("forged keys");
    assert_ne!(forged_eg.pubkey(), payer_eg.pubkey());

    let changed = ConfidentialContext {
        token_account: [5; 32],
        ..context
    };
    let changed_material = recovered.derive_ct_ikm(&changed).expect("changed context");
    let (other_eg, other_ae) =
        derive_confidential_keys_from_ikm(changed_material.as_bytes()).expect("other keys");
    assert_ne!(other_eg.pubkey(), payer_eg.pubkey());
    assert_eq!(other_ae.decrypt(&payer_ae.encrypt(42)), None);
    let ciphertext = payer_ae.encrypt(42).to_bytes();
    for i in 0..ciphertext.len() {
        let mut corrupted = ciphertext;
        corrupted[i] ^= 1;
        let parsed = AeCiphertext::from_bytes(&corrupted).expect("ciphertext encoding");
        assert_eq!(payer_ae.decrypt(&parsed), None);
    }
}

fn vector<const N: usize>(key: &str) -> [u8; N] {
    let value = include_str!("fixtures/hkdf.txt")
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(name, _)| *name == key)
        .expect("fixture field")
        .1;
    assert_eq!(value.len(), N * 2);
    std::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).expect("hex fixture"))
}

#[test]
fn sdk_keys_match_independent_hkdf_sha512_vectors() {
    let material = ConfidentialKeyMaterial::from_bytes(vector("ct_ikm"));
    let (elgamal, ae) =
        derive_confidential_keys_from_ikm(material.as_bytes()).expect("SDK derivation");
    assert_eq!(elgamal.secret().as_bytes(), &vector::<32>("elgamal_scalar"));
    assert_eq!(ae, AeKey::from(vector::<16>("balance_key")));
    let (again, again_ae) =
        derive_confidential_keys_from_ikm(material.as_bytes()).expect("SDK derivation");
    assert_eq!(elgamal, again);
    assert_eq!(ae, again_ae);
}
