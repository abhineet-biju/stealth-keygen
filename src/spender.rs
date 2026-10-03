//! Sender-side derivation of one-time payment destinations.
//!
//! Uses only the recipient's public keys.
//! The sender never obtains the recipient's payment signing key.

use rand_core::TryCryptoRng;
use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::Zeroizing;

use crate::{
    derivation::{
        ConfidentialContext, ConfidentialKeyMaterial, DeriveError, PaymentSharedSecret,
        payment_public_key,
    },
    keys::{EphemeralSecret, RecipientPublicKeys},
};

/// Public discovery information for one payment.
///
/// This is an in-memory representation. A versioned wire format
/// can be defined separately when announcements are serialized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentAnnouncement {
    pub ephemeral_public_key: [u8; 32],
    pub discovery_tag: u8,
}

/// Sender-side result for one payment.
/// Intentionally does not implement Debug, Clone, or Copy.
pub struct SenderPayment {
    /// Compressed Ed25519 public key P.
    /// These are the raw 32 bytes of the receiving authority.
    pub payment_public_key: [u8; 32],

    /// Public information needed for recipient discovery.
    pub announcement: PaymentAnnouncement,

    shared_secret: PaymentSharedSecret,
}

impl SenderPayment {
    /// Derive confidential-key material shared by the payer and recipient.
    /// Disclosure grants this account's full read access, not spending authority.
    pub fn derive_ct_ikm(
        &self,
        context: &ConfidentialContext,
    ) -> Result<ConfidentialKeyMaterial, DeriveError> {
        self.shared_secret().ct_ikm(context)
    }

    /// Internal access for account-scoped key derivation.
    pub(crate) fn shared_secret(&self) -> &PaymentSharedSecret {
        &self.shared_secret
    }
}

#[derive(Debug)]
pub enum SenderError<E> {
    Randomness(E),
    Derivation(DeriveError),
}

/// Derive a fresh payment destination using HKDF-SHA256.
/// Generates ephemeral secret material and calls [`derive_payment_with_ephemeral`].
pub fn derive_payment<R>(
    recipient: &RecipientPublicKeys,
    rng: &mut R,
) -> Result<SenderPayment, SenderError<R::Error>>
where
    R: TryCryptoRng + ?Sized,
{
    // Generate fresh ephemeral private material r.
    let mut ephemeral_bytes = Zeroizing::new([0u8; 32]);

    rng.try_fill_bytes(&mut ephemeral_bytes[..])
        .map_err(SenderError::Randomness)?;

    let ephemeral = EphemeralSecret::from_bytes(*ephemeral_bytes);
    derive_payment_with_ephemeral(recipient, &ephemeral).map_err(SenderError::Derivation)
}

/// Derive a payment destination from caller-supplied X25519 secret material r.
/// The same recipient and r reconstruct the same P, R and discovery tag, and
/// the same confidential context reconstructs the same ct_ikm.
/// Use a fresh ephemeral key for each distinct payment; reuse it only to rebuild
/// that payment. This function does not generate randomness or retain r.
///
/// R is returned in `announcement.ephemeral_public_key`. Derive the token-account
/// address from R before building the context for [`SenderPayment::derive_ct_ikm`].
///
/// ```
/// use stealth_keygen::{
///     DeriveError, EphemeralSecret, RecipientPublicKeys, SenderPayment,
///     derive_payment_with_ephemeral,
/// };
///
/// fn rebuild_payment(
///     recipient: &RecipientPublicKeys,
///     r: [u8; 32],
/// ) -> Result<SenderPayment, DeriveError> {
///     let ephemeral = EphemeralSecret::from_bytes(r);
///     derive_payment_with_ephemeral(recipient, &ephemeral)
/// }
/// ```
pub fn derive_payment_with_ephemeral(
    recipient: &RecipientPublicKeys,
    ephemeral: &EphemeralSecret,
) -> Result<SenderPayment, DeriveError> {
    let ephemeral_secret = ephemeral.private_key();

    // 1. Derive the public announcement key R.
    let ephemeral_public = X25519PublicKey::from(ephemeral_secret);

    // 2. Compute S = X25519(r, recipient_scan_public_key).
    //    derive_secret rejects an all-zero shared secret.
    let shared_secret = PaymentSharedSecret::derive_secret(
        ephemeral_secret,
        recipient.scan_public_key(),
        &ephemeral_public.to_bytes(),
    )?;

    // 3. Derive the public discovery tag and private tweak.
    let discovery_tag = shared_secret.discovery_tag()?;
    let tweak = shared_secret.tweak()?;

    // 4. Compute P = B + t·G.
    let payment = payment_public_key(recipient.spend_public_key(), &tweak)?;

    // 5. Return public payment information and retain S privately
    //    for account-scoped confidential-key derivation.
    Ok(SenderPayment {
        payment_public_key: payment.compress().to_bytes(),
        announcement: PaymentAnnouncement {
            ephemeral_public_key: ephemeral_public.to_bytes(),
            discovery_tag,
        },
        shared_secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RecipientSecretKeys,
        test_support::{TestRngError, identity_rng, payment_rng, vector},
    };

    #[test]
    fn sender_output_matches_independent_vector() {
        let recipient = RecipientSecretKeys::generate(&mut identity_rng()).unwrap();
        let payment = derive_payment(&recipient.derive_public_keys(), &mut payment_rng()).unwrap();
        assert_eq!(payment.payment_public_key, vector::<32>("payment_public"));
        assert_eq!(
            payment.announcement.ephemeral_public_key,
            vector::<32>("ephemeral_public")
        );
        assert_eq!(
            payment.announcement.discovery_tag,
            vector::<1>("discovery_tag")[0]
        );
        assert_eq!(
            payment.shared_secret().tweak().unwrap().to_bytes(),
            vector::<32>("tweak")
        );
    }

    #[test]
    fn sender_propagates_randomness_failure() {
        let public = RecipientSecretKeys::generate(&mut identity_rng())
            .unwrap()
            .derive_public_keys();
        let mut rng = payment_rng().failing_on(1);
        assert!(matches!(
            derive_payment(&public, &mut rng),
            Err(SenderError::Randomness(TestRngError::InjectedFailure))
        ));
        assert_eq!(rng.calls, 1);
    }
}
