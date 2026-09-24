//! Shared cryptographic calculations for stealth payments.
//!
//! This module implements the Stealth Keygen v1 discovery-tag and tweak derivation.

use curve25519_dalek::{EdwardsPoint, Scalar, constants::ED25519_BASEPOINT_POINT};
use sha2::{Digest, Sha256};
use x25519_dalek::{
    PublicKey as X25519PublicKey, SharedSecret as X25519SharedSecret, StaticSecret as X25519Secret,
};
use zeroize::{Zeroize, Zeroizing};

/// Protocol constant. Do not change this during ordinary crate upgrades.
/// Note: changing this label changes the derived tags, tweaks, and addresses.
const TWEAK_TAG: &[u8] = b"stealth-keygen-v1-tweak";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveError {
    InvalidSharedSecret,
    InvalidSpendPublicKey,
    InvalidPaymentPublicKey,
}

/// A shared secret that has passed the X25519 contributory check.
///
/// The field is private so callers cannot construct an unchecked value.
/// Intentionally does not implement Debug, Clone, or Copy.
pub(crate) struct PaymentSharedSecret(X25519SharedSecret);

impl PaymentSharedSecret {
    /// Compute a shared secret and reject an all-zero result.
    ///
    /// Sender:
    ///     agree(ephemeral_secret, recipient_scan_public_key)
    /// Recipient:
    ///     agree(recipient_scan_secret, ephemeral_public_key)
    pub(crate) fn derive_secret(
        own_secret: &X25519Secret,
        peer_public: &X25519PublicKey,
    ) -> Result<Self, DeriveError> {
        let shared = own_secret.diffie_hellman(peer_public);

        if !shared.was_contributory() {
            return Err(DeriveError::InvalidSharedSecret);
        }

        Ok(Self(shared))
    }

    /// Derive the public one-byte discovery filter:
    ///
    /// discovery-tag = SHA256(len(tag) || tag || S)[0]
    pub(crate) fn discovery_tag(&self) -> u8 {
        let mut hasher = tweak_hasher();
        hasher.update(self.0.as_bytes());

        let mut digest = hasher.finalize();
        let discovery_tag = digest[0];

        digest[..].zeroize();

        discovery_tag
    }

    /// Derive the private scalar tweak:
    ///
    /// t = reduce_mod_l(
    ///     SHA256(len(tag) || tag || S || discovery_tag)
    /// )
    ///
    /// The digest is interpreted as a little-endian integer.
    pub(crate) fn tweak(&self) -> Zeroizing<Scalar> {
        let discovery_tag = self.discovery_tag();

        let mut hasher = tweak_hasher();
        hasher.update(self.0.as_bytes());
        hasher.update([discovery_tag]);

        let mut digest = hasher.finalize();

        let mut digest_bytes = Zeroizing::new([0u8; 32]);
        digest_bytes.copy_from_slice(&digest);

        digest[..].zeroize();

        Zeroizing::new(Scalar::from_bytes_mod_order(*digest_bytes))
    }
}

/// Initialize the hash with the scheme's length-prefixed domain tag.
///
/// The length occupies exactly one byte.
fn tweak_hasher() -> Sha256 {
    let mut hasher = Sha256::new();

    hasher.update([TWEAK_TAG.len() as u8]);
    hasher.update(TWEAK_TAG);

    hasher
}

/// Derive the one-time payment public key:
///
/// P = B + t·G
///
/// Rejects an invalid recipient spend point and an identity result.
pub(crate) fn payment_public_key(
    recipient_spend: &EdwardsPoint,
    tweak: &Scalar,
) -> Result<EdwardsPoint, DeriveError> {
    // Accept only nonidentity points in the prime-order subgroup.
    if recipient_spend.is_small_order() || !recipient_spend.is_torsion_free() {
        return Err(DeriveError::InvalidSpendPublicKey);
    }

    let payment = recipient_spend + (tweak * ED25519_BASEPOINT_POINT);

    // Both terms are in the prime-order subgroup. Their sum could
    // still be the identity if their scalars cancel.
    if payment.is_small_order() {
        return Err(DeriveError::InvalidPaymentPublicKey);
    }

    Ok(payment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{hex, vector};
    use curve25519_dalek::constants::EIGHT_TORSION;

    #[test]
    fn rfc7748_shared_secret_matches() {
        let a = X25519Secret::from(hex::<32>(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let b = X25519PublicKey::from(hex::<32>(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        ));
        let secret = PaymentSharedSecret::derive_secret(&a, &b).unwrap();
        assert_eq!(
            secret.0.to_bytes(),
            hex::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }

    #[test]
    fn shared_secret_tag_and_tweak_match_independent_vector() {
        let scan = X25519Secret::from(vector::<32>("scan_entropy"));
        let ephemeral = X25519Secret::from(vector::<32>("ephemeral_entropy"));
        let sender =
            PaymentSharedSecret::derive_secret(&ephemeral, &X25519PublicKey::from(&scan)).unwrap();
        let recipient =
            PaymentSharedSecret::derive_secret(&scan, &X25519PublicKey::from(&ephemeral)).unwrap();
        assert_eq!(sender.0.to_bytes(), vector::<32>("shared_secret"));
        assert_eq!(recipient.0.to_bytes(), vector::<32>("shared_secret"));
        assert_eq!(sender.discovery_tag(), vector::<1>("discovery_tag")[0]);
        assert_eq!(sender.tweak().to_bytes(), vector::<32>("tweak"));
        assert_eq!(recipient.tweak().to_bytes(), vector::<32>("tweak"));
    }

    #[test]
    fn low_order_x25519_inputs_are_rejected() {
        let secret = X25519Secret::from([9; 32]);
        for encoding in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let peer = X25519PublicKey::from(hex::<32>(encoding));
            assert!(matches!(
                PaymentSharedSecret::derive_secret(&secret, &peer),
                Err(DeriveError::InvalidSharedSecret)
            ));
        }
    }

    #[test]
    fn small_order_spend_points_are_rejected() {
        for point in EIGHT_TORSION {
            assert_eq!(
                payment_public_key(&point, &Scalar::ONE),
                Err(DeriveError::InvalidSpendPublicKey)
            );
        }
    }

    #[test]
    fn mixed_torsion_spend_points_are_rejected() {
        for torsion in EIGHT_TORSION.iter().skip(1) {
            assert_eq!(
                payment_public_key(&(ED25519_BASEPOINT_POINT + torsion), &Scalar::ONE),
                Err(DeriveError::InvalidSpendPublicKey)
            );
        }
    }

    #[test]
    fn cancellation_to_identity_is_rejected() {
        assert_eq!(
            payment_public_key(&ED25519_BASEPOINT_POINT, &(-Scalar::ONE)),
            Err(DeriveError::InvalidPaymentPublicKey)
        );
    }

    #[test]
    fn zero_tweak_preserves_valid_spend_point() {
        assert_eq!(
            payment_public_key(&ED25519_BASEPOINT_POINT, &Scalar::ZERO),
            Ok(ED25519_BASEPOINT_POINT)
        );
    }
}
