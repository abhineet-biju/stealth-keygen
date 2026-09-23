//! Recipient key generation, public-key derivation, and key representations.
//!
//! # Public and secret material
//!
//! `RecipientPublicKeys` contains information intended for publication.
//! `RecipientSecretKeys` contains material that must remain private.

use curve25519_dalek::{EdwardsPoint, Scalar, constants::ED25519_BASEPOINT_POINT};
use rand_core::TryCryptoRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

/// Recipient secrets.
/// Intentionally does not implement Clone, Debug, Copy.
pub struct RecipientSecretKeys {
    spend: Zeroizing<Scalar>,
    scan: X25519Secret,
}

/// Recipient public information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientPublicKeys {
    spend: EdwardsPoint,
    scan: X25519PublicKey,
}

impl RecipientSecretKeys {
    /// Generate a fresh recipient identity.
    pub fn generate<R>(rng: &mut R) -> Result<Self, R::Error>
    where
        R: TryCryptoRng + ?Sized,
    {
        // Reduce 64 bytes modulo the Ed25519 subgroup order.
        let spend = loop {
            let mut random_bytes = Zeroizing::new([0u8; 64]);
            rng.try_fill_bytes(&mut random_bytes[..])?;

            let candidate = Scalar::from_bytes_mod_order_wide(&random_bytes);

            if candidate != Scalar::ZERO {
                break candidate;
            }
        };

        let mut scan_bytes = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(&mut scan_bytes[..])?;

        let scan = X25519Secret::from(*scan_bytes);

        Ok(Self {
            spend: Zeroizing::new(spend),
            scan,
        })
    }
    /// Derive the recipient's public spend and scan keys.
    pub fn derive_public_keys(&self) -> RecipientPublicKeys {
        RecipientPublicKeys {
            spend: *self.spend * ED25519_BASEPOINT_POINT,
            scan: X25519PublicKey::from(&self.scan),
        }
    }

    /// Internal access API for secrets.
    pub(crate) fn spend_private_key(&self) -> &Scalar {
        &self.spend
    }
    pub(crate) fn scan_private_key(&self) -> &X25519Secret {
        &self.scan
    }
}

impl RecipientPublicKeys {
    /// Compressed Edwards encoding of B, exactly 32 bytes.
    pub fn spend_public_key_bytes(&self) -> [u8; 32] {
        self.spend.compress().to_bytes()
    }

    /// X25519 public-key encoding of A, exactly 32 bytes.
    pub fn scan_public_key_bytes(&self) -> [u8; 32] {
        self.scan.to_bytes()
    }

    /// Internal access API for public keys.
    pub(crate) fn spend_public_key(&self) -> &EdwardsPoint {
        &self.spend
    }
    pub(crate) fn scan_public_key(&self) -> &X25519PublicKey {
        &self.scan
    }
}
