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
pub(crate) enum DeriveError {
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
