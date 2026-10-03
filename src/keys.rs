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

/// Payer's ephemeral X25519 secret material for one payment.
/// Cleared on drop; intentionally does not implement Debug, Clone, or Copy.
pub struct EphemeralSecret(X25519Secret);

impl EphemeralSecret {
    /// Import 32 secret bytes, for example from a per-payment KDF.
    /// X25519 applies clamping when deriving public keys and shared secrets.
    /// Any copies made by the caller must be protected separately.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(X25519Secret::from(bytes))
    }

    /// Internal access for payer-side key agreement.
    pub(crate) fn private_key(&self) -> &X25519Secret {
        &self.0
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeriveError, SenderError,
        derivation::PaymentSharedSecret,
        derive_payment, derive_payment_with_ephemeral,
        test_support::{ScriptedRng, TestRngError, identity_rng, payment_rng, vector},
    };
    use curve25519_dalek::constants::EIGHT_TORSION;

    #[test]
    fn supplied_ephemeral_rejects_invalid_recipient_keys() {
        let public = RecipientSecretKeys::generate(&mut identity_rng())
            .unwrap()
            .derive_public_keys();
        let ephemeral = EphemeralSecret::from_bytes(vector::<32>("ephemeral_entropy"));
        for spend in EIGHT_TORSION.into_iter().chain(
            EIGHT_TORSION
                .iter()
                .skip(1)
                .map(|p| ED25519_BASEPOINT_POINT + p),
        ) {
            let invalid = RecipientPublicKeys {
                spend,
                scan: public.scan,
            };
            assert_eq!(
                derive_payment_with_ephemeral(&invalid, &ephemeral).err(),
                Some(DeriveError::InvalidSpendPublicKey)
            );
            assert!(matches!(
                derive_payment(&invalid, &mut payment_rng()),
                Err(SenderError::Derivation(DeriveError::InvalidSpendPublicKey))
            ));
        }
        let invalid = RecipientPublicKeys {
            scan: X25519PublicKey::from([0; 32]),
            ..public
        };
        assert_eq!(
            derive_payment_with_ephemeral(&invalid, &ephemeral).err(),
            Some(DeriveError::InvalidSharedSecret)
        );
        assert!(matches!(
            derive_payment(&invalid, &mut payment_rng()),
            Err(SenderError::Derivation(DeriveError::InvalidSharedSecret))
        ));
    }

    #[test]
    fn supplied_ephemeral_rejects_payment_identity() {
        let mut public = RecipientSecretKeys::generate(&mut identity_rng())
            .unwrap()
            .derive_public_keys();
        let ephemeral = EphemeralSecret::from_bytes(vector::<32>("ephemeral_entropy"));
        let r = X25519PublicKey::from(ephemeral.private_key()).to_bytes();
        let shared =
            PaymentSharedSecret::derive_secret(ephemeral.private_key(), &public.scan, &r).unwrap();
        public.spend = -(*shared.tweak().unwrap() * ED25519_BASEPOINT_POINT);
        assert_eq!(
            derive_payment_with_ephemeral(&public, &ephemeral).err(),
            Some(DeriveError::InvalidPaymentPublicKey)
        );
        assert!(matches!(
            derive_payment(&public, &mut payment_rng()),
            Err(SenderError::Derivation(
                DeriveError::InvalidPaymentPublicKey
            ))
        ));
    }

    #[test]
    fn public_keys_match_independent_vector() {
        let mut rng = identity_rng();
        let secret = RecipientSecretKeys::generate(&mut rng).unwrap();
        let public = secret.derive_public_keys();
        assert_eq!(
            public.spend_public_key_bytes(),
            vector::<32>("spend_public")
        );
        assert_eq!(public.scan_public_key_bytes(), vector::<32>("scan_public"));
        assert_eq!(public, secret.derive_public_keys());
        assert!(!public.spend.is_small_order());
        assert!(public.spend.is_torsion_free());
        assert_eq!(rng.calls, 2);
    }

    #[test]
    fn zero_scalar_candidate_is_retried() {
        let mut bytes = vec![0; 64];
        bytes.extend_from_slice(&vector::<64>("spend_entropy"));
        bytes.extend_from_slice(&vector::<32>("scan_entropy"));
        let mut rng = ScriptedRng::new(bytes);
        let public = RecipientSecretKeys::generate(&mut rng)
            .unwrap()
            .derive_public_keys();
        assert_eq!(
            public.spend_public_key_bytes(),
            vector::<32>("spend_public")
        );
        assert_eq!(public.scan_public_key_bytes(), vector::<32>("scan_public"));
        assert_eq!(rng.calls, 3);
    }

    #[test]
    fn randomness_errors_propagate_at_both_requests() {
        for call in [1, 2] {
            let mut rng = identity_rng().failing_on(call);
            assert!(matches!(
                RecipientSecretKeys::generate(&mut rng),
                Err(TestRngError::InjectedFailure)
            ));
            assert_eq!(rng.calls, call);
        }
    }

    #[test]
    fn zero_candidate_then_randomness_failure_returns_error() {
        let mut rng = ScriptedRng::new(vec![0; 64]).failing_on(2);
        assert!(matches!(
            RecipientSecretKeys::generate(&mut rng),
            Err(TestRngError::InjectedFailure)
        ));
    }
}
