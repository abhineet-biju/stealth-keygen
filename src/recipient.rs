//! Recipient-side recovery of one-time payment keys.
//!
//! Uses the recipient's secret keys and a public announcement.
//! A matching discovery tag identifies a candidate.

use curve25519_dalek::Scalar;
use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::Zeroizing;

use crate::{
    derivation::{DeriveError, PaymentSharedSecret, payment_public_key},
    keys::RecipientSecretKeys,
    spender::PaymentAnnouncement,
};

/// Recipient-side result for a candidate payment.
/// Intentionally does not implement Debug, Clone, or Copy.
pub struct RecoveredPayment {
    /// Compressed Ed25519 public key P.
    /// Check the destination authority against this key before accepting a payment.
    pub payment_public_key: [u8; 32],

    payment_scalar: Zeroizing<Scalar>,
    shared_secret: PaymentSharedSecret,
}

impl RecoveredPayment {
    /// Internal access for the future scalar-based signing module.
    pub(crate) fn payment_private_key(&self) -> &Scalar {
        &self.payment_scalar
    }

    /// Internal access for the future encryption module.
    pub(crate) fn shared_secret(&self) -> &PaymentSharedSecret {
        &self.shared_secret
    }
}

#[derive(Debug)]
pub enum RecipientError {
    Derivation(DeriveError),
}

/// Recover a candidate payment from an announcement.
/// Returns None when the discovery tag does not match.
pub fn recover_payment(
    recipient: &RecipientSecretKeys,
    announcement: &PaymentAnnouncement,
) -> Result<Option<RecoveredPayment>, RecipientError> {
    // 1. Read the sender's ephemeral public key R.
    let ephemeral_public = X25519PublicKey::from(announcement.ephemeral_public_key);

    // 2. Compute S = X25519(recipient_scan_secret, R).
    let shared_secret =
        PaymentSharedSecret::derive_secret(recipient.scan_private_key(), &ephemeral_public)
            .map_err(RecipientError::Derivation)?;

    // 3. Reject announcements whose discovery tag does not match.
    if shared_secret.discovery_tag() != announcement.discovery_tag {
        return Ok(None);
    }

    // 4. Derive the tweak and candidate public key P = B + t·G.
    let tweak = shared_secret.tweak();
    let public_keys = recipient.derive_public_keys();
    let payment = payment_public_key(public_keys.spend_public_key(), &tweak)
        .map_err(RecipientError::Derivation)?;

    // 5. Recover the private scalar p = b + t mod l.
    let payment_scalar = Zeroizing::new(*recipient.spend_private_key() + *tweak);

    // 6. Retain private material for signing and encryption.
    Ok(Some(RecoveredPayment {
        payment_public_key: payment.compress().to_bytes(),
        payment_scalar,
        shared_secret,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive_payment,
        test_support::{identity_rng, payment_rng, vector},
    };
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

    #[test]
    fn recovered_scalar_and_shared_material_match_independent_vector() {
        let recipient = RecipientSecretKeys::generate(&mut identity_rng()).unwrap();
        let sent = derive_payment(&recipient.derive_public_keys(), &mut payment_rng()).unwrap();
        let recovered = recover_payment(&recipient, &sent.announcement)
            .unwrap()
            .unwrap();
        assert_eq!(
            recovered.payment_private_key().to_bytes(),
            vector::<32>("payment_scalar")
        );
        assert_eq!(recovered.payment_public_key, vector::<32>("payment_public"));
        assert_eq!(
            (recovered.payment_private_key() * ED25519_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
            sent.payment_public_key
        );
        assert_eq!(
            recovered.shared_secret().tweak().to_bytes(),
            sent.shared_secret().tweak().to_bytes()
        );
    }
}
