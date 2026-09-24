//! Ed25519 signing with a recovered payment scalar.
//!
//! The recovered private scalar is not an Ed25519 seed.
//! This module signs directly with that scalar.

use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::recipient::RecoveredPayment;

/// Domain tag for this scheme's deterministic nonce-prefix derivation.
const NONCE_TAG: &[u8] = b"stealth-keygen-v1-nonce";

impl RecoveredPayment {
    /// Sign the exact message bytes using the recovered payment key.
    /// Returns a standard 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let private_scalar = self.payment_private_key();

        // 1. Derive the public key from the actual signing scalar.
        let public_key = (private_scalar * ED25519_BASEPOINT_POINT).compress();

        // 2. Derive a secret nonce prefix from the payment scalar.
        let scalar_bytes = Zeroizing::new(private_scalar.to_bytes());

        let mut prefix_hasher = Sha512::new();
        prefix_hasher.update([NONCE_TAG.len() as u8]);
        prefix_hasher.update(NONCE_TAG);
        prefix_hasher.update(&scalar_bytes[..]);

        let prefix_digest: Zeroizing<[u8; 64]> = Zeroizing::new(prefix_hasher.finalize().into());

        // 3. Derive the message-specific nonce scalar.
        //    nonce = reduce(SHA512(secret_prefix || message))
        let mut nonce_hasher = Sha512::new();
        nonce_hasher.update(&prefix_digest[32..]);
        nonce_hasher.update(message);

        let nonce_digest: Zeroizing<[u8; 64]> = Zeroizing::new(nonce_hasher.finalize().into());

        let nonce = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&nonce_digest));

        // 4. Compute the public nonce commitment.
        let nonce_point = (*nonce * ED25519_BASEPOINT_POINT).compress();

        // 5. Compute the Ed25519 challenge.
        //    challenge = reduce(SHA512(R_sig || P || message))
        let mut challenge_hasher = Sha512::new();
        challenge_hasher.update(nonce_point.as_bytes());
        challenge_hasher.update(public_key.as_bytes());
        challenge_hasher.update(message);

        let challenge_digest: [u8; 64] = challenge_hasher.finalize().into();

        let challenge = Scalar::from_bytes_mod_order_wide(&challenge_digest);

        // 6. Compute the signature response.
        //    response = nonce + challenge * private_scalar mod l
        let response = *nonce + challenge * private_scalar;

        // 7. Encode signature = R_sig || response.
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(nonce_point.as_bytes());
        signature[32..].copy_from_slice(&response.to_bytes());

        signature
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        RecipientSecretKeys, derive_payment, recover_payment,
        test_support::{identity_rng, payment_rng, vector},
    };
    use curve25519_dalek::Scalar;

    #[test]
    fn signing_matches_independent_vector_and_response_is_canonical() {
        let recipient = RecipientSecretKeys::generate(&mut identity_rng()).unwrap();
        let sent = derive_payment(&recipient.derive_public_keys(), &mut payment_rng()).unwrap();
        let recovered = recover_payment(&recipient, &sent.announcement)
            .unwrap()
            .unwrap();
        let signature = recovered.sign(b"stealth-keygen test vector");
        assert_eq!(signature, vector::<64>("signature"));
        let response: [u8; 32] = signature[32..].try_into().unwrap();
        assert!(bool::from(Scalar::from_canonical_bytes(response).is_some()));
    }
}
